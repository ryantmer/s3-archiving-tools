import boto3
import hashlib
import logging
import shutil
import sys
from _hashlib import HASH as Hash
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError
from glob import glob
from pathlib import Path
from tqdm import tqdm

def md5_update_from_file(filename: Path, hash: Hash):
	assert filename.is_file()
	with open(str(filename), 'rb') as f:
		for chunk in iter(lambda: f.read(4096), b''):
			hash.update(chunk)
	return hash

def md5_update_from_dir(directory: Path, hash: Hash):
	assert directory.is_dir()
	for path in sorted(directory.iterdir(), key=lambda p: str(p).lower()):
		hash.update(path.name.encode())
		if path.is_file():
			hash = md5_update_from_file(path, hash)
		elif path.is_dir():
			hash = md5_update_from_dir(path, hash)
	return hash

def md5_dir(directory: Path):
	return md5_update_from_dir(directory, hashlib.md5()).hexdigest()

def md5_file(file: Path):
	return md5_update_from_file(file, hashlib.md5()).hexdigest()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

if len(sys.argv) != 2:
	logger.critical("Usage: python.py <s3 bucket name> <s3 key prefix>")
	sys.exit(-1)
s3_bucket = sys.argv[1] or 'test-s3-bucket'

photos_root_path = Path('E:/Pictures')
year_folders = [Path(year_folder) for year_folder in glob(str(photos_root_path / '[0-9][0-9][0-9][0-9]'))]
zip_count = 0
total_folders = 0

logger.info('Archiving and uploading folders from "%s" to "s3://%s"', photos_root_path, s3_bucket)
s3_client = boto3.client('s3')

for year_folder_index, year_folder_path in enumerate(year_folders):
	logger.info('--- Processing photos from year %s', year_folder_path.stem)
	photo_folders = [Path(photo_folder) for photo_folder in glob(str(year_folder_path / '[0-9][0-9][0-9][0-9]-[0-9][0-9]*'))]
	total_folders += len(photo_folders)

	for photo_folder in photo_folders:
		logger.info('- Processing photos from folder "%s"', photo_folder.stem)

		archive_s3_key = f'photos/ryan/{year_folder_path.stem}/{photo_folder.stem}.zip'
		hash_s3_key = f'photos/ryan/{year_folder_path.stem}/{photo_folder.stem}.md5'
		
		logger.info('Hashing folder "%s" (this may take a while)', photo_folder.stem)
		folder_hash = md5_dir(photo_folder)

		logger.info('Looking for archive "%s" in S3...', archive_s3_key)
		existing_archive = None
		try:
			s3_client.get_object_attributes(Bucket=s3_bucket, Key=archive_s3_key, ObjectAttributes=['ETag'])
			logger.info('Archive "%s" found in S3.', archive_s3_key)
			existing_archive = True
		except ClientError as err:
			if err.response['Error']['Code'] == 'NoSuchKey':
				logger.info('Archive "%s" not found in S3.', archive_s3_key)
				existing_archive = False
			else:
				raise err

		logger.info('Looking for hash "%s" in S3...', hash_s3_key)
		try:
			hash_object = s3_client.get_object(Bucket=s3_bucket, Key=hash_s3_key)
			remote_hash = hash_object['Body'].read().decode('utf-8')
			logger.info('Hash "%s" found in S3.', hash_s3_key)
			if existing_archive is True:
				if remote_hash == folder_hash:
					logger.info('Archive and hash exist in S3, and hash matches local folder. Nothing more to do, moving to next folder.')
					continue
				else:
					logger.info('Archive and hash exist in S3, but hash does not match local folder. Updating archive and hash from local folder.')
			else:
				logger.warning('Found matching hash, but no matching archive - was it manually deleted?')
		except ClientError as err:
			if err.response['Error']['Code'] == 'NoSuchKey':
				logger.info('Hash "%s" not found in S3.', hash_s3_key)
			else:
				raise err

		logger.info('Creating archive for photo folder "%s" (this may take a while)', photo_folder.stem)
		archive_file_path = shutil.make_archive(f'{photos_root_path / photo_folder.stem}', 'zip', photo_folder)

		logger.info('Uploading archive "%s" to "s3://%s/%s"', archive_file_path, s3_bucket, archive_s3_key)
		# Credit to https://alexwlchan.net/2021/s3-progress-bars/ for the progress bar here
		with tqdm(total=Path(archive_file_path).stat().st_size, unit='B', unit_scale=True, desc=photo_folder.stem) as progress_bar:
			s3_client.upload_file(
				Filename=archive_file_path,
				Bucket=s3_bucket,
				Key=archive_s3_key,
				Callback=lambda bytes_transferred: progress_bar.update(bytes_transferred),
				ExtraArgs={ 'StorageClass': 'INTELLIGENT_TIERING' },
				# Config=TransferConfig(max_bandwidth=1000000)
			)

		logger.info('Uploading hash to "s3://%s/%s"', s3_bucket, hash_s3_key)
		s3_client.put_object(Bucket=s3_bucket, Key=hash_s3_key, Body=folder_hash)

		logger.info('Deleting local archive "%s"', archive_file_path)
		Path(archive_file_path).unlink()

		zip_count += 1

logger.info('Archiving complete. %d folders were zipped into new archives, and %d zip archives were already up to date.' % (zip_count, total_folders - zip_count))

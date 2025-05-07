#!/usr/bin/env python3
"""
X (Twitter) Daily Poster Script - Cron Version
------------------------------------------------
Script designed to be run once daily by cron at 12PM to post to X.
Looks for directories in YYYY-MM-DD format and posts content from post.md
with images attached.

Setup:
1. Install dependencies: pip install requests requests_oauthlib python-dotenv
2. Run once manually to set up authentication
3. Add to crontab: 0 12 * * * cd /path/to/script/dir && python3 twitter_poster.py
"""

import os
import sys
import json
import base64
import hashlib
import re
import time
import glob
import requests
import logging
from datetime import datetime
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("twitter_poster.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# API Endpoints and configuration
MEDIA_ENDPOINT_URL = 'https://api.x.com/2/media/upload'
POST_TO_X_URL = 'https://api.x.com/2/tweets'
TOKEN_FILE = 'token.json'

# OAuth configuration from environment variables
CLIENT_ID = os.getenv('TWITTER_CLIENT_ID')
CLIENT_SECRET = os.getenv('TWITTER_CLIENT_SECRET')
REDIRECT_URI = os.getenv('TWITTER_REDIRECT_URI', "https://example.com")
SCOPES = ["media.write", "users.read", "tweet.read", "tweet.write", "offline.access"]

# Validate required environment variables
if not CLIENT_ID or not CLIENT_SECRET:
    logger.error("Missing required environment variables. Please set TWITTER_CLIENT_ID and TWITTER_CLIENT_SECRET.")
    sys.exit(1)

def get_oauth_session():
    """
    Load the OAuth token from disk if available.
    Otherwise run the OAuth flow and save the token.
    """
    token = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            token = json.load(f)
            
        # Check if token is expired and needs refresh
        if 'expires_at' in token and token['expires_at'] < time.time():
            logger.info("Token has expired, refreshing...")
            oauth = OAuth2Session(CLIENT_ID, token=token)
            token = oauth.refresh_token(
                token_url="https://api.x.com/2/oauth2/token",
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET
            )
            with open(TOKEN_FILE, 'w') as f:
                json.dump(token, f)
                
    oauth = OAuth2Session(CLIENT_ID, token=token, redirect_uri=REDIRECT_URI, scope=SCOPES)
    
    if token is None:
        logger.info("No token found. Starting OAuth2 authorization flow...")
        # Create code verifier and challenge for PKCE
        code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode("utf-8").replace("=", "")
        
        # Build and print the auth URL
        auth_url = "https://x.com/i/oauth2/authorize"
        authorization_url, state = oauth.authorization_url(
            auth_url, code_challenge=code_challenge, code_challenge_method="S256"
        )
        logger.info("Visit this URL to authorize your App:")
        logger.info(authorization_url)
        print("\nVisit this URL to authorize your App:")
        print(authorization_url)
        authorization_response = input("\nPaste the full redirect URL here:\n")
        
        token_url = "https://api.x.com/2/oauth2/token"
        auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        token = oauth.fetch_token(
            token_url=token_url,
            authorization_response=authorization_response,
            auth=auth,
            client_id=CLIENT_ID,
            include_client_id=True,
            code_verifier=code_verifier,
        )
        with open(TOKEN_FILE, 'w') as f:
            json.dump(token, f)
        logger.info("Authentication successful. Token saved to token.json")
    
    return oauth, token

def upload_image(image_path, headers):
    """
    Upload a single image in three phases: INIT, APPEND (in chunks) and FINALIZE.
    Returns the media_id on success.
    """
    try:
        total_bytes = os.path.getsize(image_path)
        
        # Determine media type from extension
        if image_path.lower().endswith('.png'):
            media_type = 'image/png'
        elif image_path.lower().endswith(('.jpg', '.jpeg')):
            media_type = 'image/jpeg'
        else:
            media_type = 'image/jpeg'  # Default
        
        logger.info(f"Uploading image: {image_path} ({total_bytes} bytes, type: {media_type})")
        
        # INIT phase
        init_params = {
            'command': 'INIT',
            'media_type': media_type,
            'total_bytes': total_bytes,
            'media_category': 'tweet_image'
        }
        init_resp = requests.post(MEDIA_ENDPOINT_URL, params=init_params, headers=headers)
        
        if not (200 <= init_resp.status_code < 300):
            logger.error(f"INIT error for {image_path}: {init_resp.status_code} {init_resp.text}")
            return None
            
        media_id = init_resp.json()['data']['id']
        logger.info(f"Media ID {media_id} initialized successfully")
        
        # APPEND phase – reading in 4MB chunks
        segment_id = 0
        with open(image_path, 'rb') as f:
            while True:
                chunk = f.read(4 * 1024 * 1024)
                if not chunk:
                    break
                    
                files = {'media': ('chunk', chunk, 'application/octet-stream')}
                append_params = {
                    'command': 'APPEND',
                    'media_id': media_id,
                    'segment_index': segment_id
                }
                
                append_resp = requests.post(
                    MEDIA_ENDPOINT_URL, 
                    data=append_params, 
                    files=files, 
                    headers={
                        "Authorization": headers["Authorization"],
                        "User-Agent": headers.get("User-Agent", "MediaUploadCron")
                    }
                )
                
                if append_resp.status_code < 200 or append_resp.status_code > 299:
                    logger.error(f"APPEND error for {image_path}: {append_resp.status_code} {append_resp.text}")
                    return None
                    
                segment_id += 1
        
        logger.info(f"Uploaded {segment_id} segments, finalizing...")
        
        # FINALIZE phase
        finalize_params = {
            'command': 'FINALIZE',
            'media_id': media_id
        }
        finalize_resp = requests.post(MEDIA_ENDPOINT_URL, params=finalize_params, headers=headers)
        
        if finalize_resp.status_code < 200 or finalize_resp.status_code > 299:
            logger.error(f"FINALIZE error for {image_path}: {finalize_resp.status_code} {finalize_resp.text}")
            return None
            
        processing_info = finalize_resp.json()['data'].get('processing_info', None)
        
        # If processing is asynchronous, check until it succeeds (or fails)
        if processing_info:
            state = processing_info.get('state')
            while state not in ['succeeded', 'failed']:
                wait_secs = processing_info.get('check_after_secs', 5)
                logger.info(f"Processing... checking after {wait_secs} seconds.")
                time.sleep(wait_secs)
                
                status_params = {'command': 'STATUS', 'media_id': media_id}
                status_resp = requests.get(MEDIA_ENDPOINT_URL, params=status_params, headers=headers)
                
                if status_resp.status_code < 200 or status_resp.status_code > 299:
                    logger.error(f"STATUS error for {image_path}: {status_resp.status_code} {status_resp.text}")
                    return None
                    
                processing_info = status_resp.json()['data'].get('processing_info', None)
                if processing_info:
                    state = processing_info.get('state')
                    
            if state == 'failed':
                logger.error(f"Media processing failed for {image_path}.")
                return None
                
        logger.info(f"Image {image_path} uploaded successfully with ID: {media_id}")
        return media_id
        
    except Exception as e:
        logger.error(f"Error uploading image {image_path}: {str(e)}")
        return None

def post_tweet(text, headers, media_ids=None, reply_to_id=None):
    """
    Post a tweet with optional media attachments and optional reply_to field.
    Returns the tweet ID.
    """
    try:
        payload = {'text': text}
        
        if media_ids:
            payload['media'] = {'media_ids': media_ids}
            
        if reply_to_id:
            payload['reply'] = {'in_reply_to_tweet_id': reply_to_id}
        
        logger.info(f"Posting tweet: {text[:50]}{'...' if len(text) > 50 else ''}")
        if media_ids:
            logger.info(f"With media IDs: {media_ids}")
        if reply_to_id:
            logger.info(f"As reply to: {reply_to_id}")
            
        resp = requests.post(POST_TO_X_URL, json=payload, headers=headers)
        
        if resp.status_code < 200 or resp.status_code > 299:
            logger.error(f"Tweet post error: {resp.status_code} {resp.text}")
            return None
            
        tweet_data = resp.json()['data']
        tweet_id = tweet_data.get('id')
        logger.info(f"Tweet posted successfully with ID: {tweet_id}")
        return tweet_id
        
    except Exception as e:
        logger.error(f"Error posting tweet: {str(e)}")
        return None

def get_todays_directory():
    """
    Returns the folder name for today's post in format YYYY-MM-DD.
    """
    today = datetime.now()
    folder_name = today.strftime("%Y-%m-%d")
    return folder_name

def parse_post_file(post_file):
    """
    Parse the post.md file to extract main content and reply link.
    
    Returns:
        Tuple of (main_content, reply_link)
    """
    try:
        with open(post_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        # Split into lines and filter out empty lines
        lines = [line for line in content.split('\n') if line.strip()]
        
        if len(lines) < 2:
            logger.error(f"Post file has insufficient content: {post_file}")
            return None, None
        
        # Get the reply link (last line)
        reply_link = lines[-1]
        
        # Get the main content (everything except the last line)
        main_content = '\n'.join(lines[:-1])
        
        return main_content, reply_link
        
    except Exception as e:
        logger.error(f"Error parsing post file: {str(e)}")
        return None, None

def process_folder(folder_name=None):
    """
    Process a folder with the given name (or today's folder if not provided).
    Reads the post.md content, uploads images, and posts the main tweet and reply.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get today's directory if none provided
        if folder_name is None:
            folder_name = f"posts/{get_todays_directory()}"
        
        logger.info(f"Processing folder: {folder_name}")
        
        # Check if folder exists
        if not os.path.exists(f"{folder_name}"):
            logger.error(f"No folder found for: {folder_name}")
            return False
        
        # Check for post.md file
        post_file = os.path.join(folder_name, "post.md")
        if not os.path.exists(post_file):
            logger.error(f"No post.md file in folder {folder_name}")
            return False
        
        # Parse post.md content
        main_content, reply_link = parse_post_file(post_file)
        if not main_content or not reply_link:
            logger.error("Failed to parse post.md content")
            return False
        
        logger.info("Post content parsed successfully")
        logger.info(f"Main content: {main_content[:50]}{'...' if len(main_content) > 50 else ''}")
        logger.info(f"Reply link: {reply_link}")
        
        # Gather image files (.png, .jpeg, .jpg) from the folder
        image_files = []
        for ext in ('*.png', '*.jpeg', '*.jpg'):
            image_files.extend(glob.glob(os.path.join(folder_name, ext)))
        
        # Sort images by filename
        image_files.sort()
        logger.info(f"Found {len(image_files)} images: {[os.path.basename(f) for f in image_files]}")
        
        # Get OAuth session and headers
        _, token = get_oauth_session()
        headers = {
            "Authorization": f"Bearer {token['access_token']}",
            "Content-Type": "application/json",
            "User-Agent": "X-Daily-Poster-Cron"
        }
        
        # Upload images
        media_ids = []
        for image_path in image_files:
            media_id = upload_image(image_path, headers)
            if media_id:
                media_ids.append(media_id)
        
        if len(media_ids) != len(image_files):
            logger.warning(f"Some images failed to upload: {len(media_ids)}/{len(image_files)} successful")
        
        # Post main tweet
        main_tweet_id = post_tweet(main_content, headers, media_ids=media_ids)
        if not main_tweet_id:
            logger.error("Failed to post main tweet")
            return False
        
        # Post reply tweet with link
        reply_tweet_id = post_tweet(reply_link, headers, reply_to_id=main_tweet_id)
        if not reply_tweet_id:
            logger.error("Failed to post reply tweet")
            # Continue anyway since the main tweet was posted
        
        logger.info("Successfully posted to X")
        
        # Save tweet information to a file for reference
        with open(os.path.join(folder_name, "tweet_info.json"), "w") as f:
            json.dump({
                "date": datetime.now().isoformat(),
                "main_tweet_id": main_tweet_id,
                "reply_tweet_id": reply_tweet_id,
                "media_ids": media_ids
            }, f, indent=2)
        
        return True
        
    except Exception as e:
        logger.error(f"Error processing folder: {str(e)}")
        return False

def main():
    """
    Main function - processes today's folder and exits.
    Designed to be run by cron job at 12PM daily.
    """
    logger.info("Starting X daily poster cron script")
    
    # Process today's folder
    success = process_folder()
    
    if success:
        logger.info("Daily post completed successfully")
    else:
        logger.error("Daily post failed")
    
    logger.info("X daily poster cron script finished")

if __name__ == '__main__':
    # Check for debug mode
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "debug":
            folder_arg = sys.argv[2] if len(sys.argv) > 2 else None
            logger.info(f"Running in debug mode with folder: {folder_arg}")
            process_folder(folder_arg)
        else:
            # Treat the first argument as a folder name
            logger.info(f"Processing specific folder: {sys.argv[1]}")
            process_folder(sys.argv[1])
    else:
        # Normal execution - process today's folder
        main()

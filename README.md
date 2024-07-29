To install dependencies, run pip install -r requirements.txt

To ensure proper working of the app, you need to have an AWS account with an S3 tier, to which the encrypted files will be uploaded.
Open app.py using any text editor or python compiler and make the following changes:
1) In place of 'your_bucket_name' enter the name of your Amazon S3 bucket.
2) In place of 'aws_access_key' enter your AWS account access key
3) In place of 'aws_secret_key' enter your AWS account secret key
4) In place of 'aws_region' enter your configured AWS region

In the main app directory, store all the html files in a directory called \templates.

If necessary, set up a virtual environment using the command venv\Scripts\activate

Run python app.py to run the app.

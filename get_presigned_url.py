#!/usr/bin/env python2
# coding: utf-8
import boto3
from botocore.client import Config


config = Config(signature_version='s3v4-query')

cli = boto3.client(
    's3',
    region_name='us-east-1',
    aws_access_key_id='renzhi_access_key',
    aws_secret_access_key='renzhi_secret_key',
    endpoint_url='http://127.0.0.1:1313',
    config = config,
)


if __name__ == "__main__":
    import sys
    client_method = sys.argv[1]

    if client_method == 'list_buckets':

        url = cli.generate_presigned_url(
            ClientMethod='list_buckets',
            ExpiresIn=60000,
        )
        print url

    elif client_method == 'create_bucket':

        url = cli.generate_presigned_url(
            ClientMethod='create_bucket',
            Params={
                'Bucket': sys.argv[2],
            },
            ExpiresIn=60000,
        )
        print url

    elif client_method == 'put_object':

        url = cli.generate_presigned_url(
            ClientMethod='put_object',
            Params={
                'Bucket': sys.argv[2],
                'Key': sys.argv[3],
            },
            ExpiresIn=60000,
        )
        print url

    elif client_method == 'get_object':

        url = cli.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': sys.argv[2],
                'Key': sys.argv[3],
            },
            ExpiresIn=60000,
        )
        print url

    elif client_method == 'list_objects':
        url = cli.generate_presigned_url(
            ClientMethod='list_objects',
            Params={
                'Bucket': sys.argv[2],
            },
            ExpiresIn=6000,
        )
        print url

    elif client_method == 'delete_object':

        url = cli.generate_presigned_url(
            ClientMethod='delete_object',
            Params={
                'Bucket': sys.argv[2],
                'Key': sys.argv[3],
            },
            ExpiresIn=60000,
        )
        print url

    elif client_method == 'delete_bucket':

        url = cli.generate_presigned_url(
            ClientMethod='delete_bucket',
            Params={
                'Bucket': sys.argv[2],
            },
            ExpiresIn=60000,
        )
        print url

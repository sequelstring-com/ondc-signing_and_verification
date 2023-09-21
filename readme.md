The utility can be used by calling the function create_authorisation_header in which we pass requestBody, created, expires and the domain type based on which the utility will pick the appropriate id and keys for signing the request. 

You can update your id and keys for the respective relevant domains in the .env file.

To verify the signed header you can use the function verify_authorisation_header in which we pass requestBody, created, expires and the domain type based on which the utility will pick the appropriate id and keys for signing the request. 

Type of domains are bap, bpp or logistic. 
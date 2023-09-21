import dotenv from 'dotenv';

dotenv.config()

export const bpp_id = process.env["bpp_id"];

export const bpp_uri = process.env["bpp_uri"];

export const bap_id = process.env["bap_id"];

export const bap_uri = process.env["bap_uri"];

export const logistic_id = process.env["logistic_id"];

export const logistic_uri = process.env["logistic_uri"];

export const bap_public_key = process.env["bap_public_key"] || "";

export const bap_private_key = process.env["bap_private_key"] || ""

export const bap_unique_key_id = process.env["bap_unique_key_id"] || ""

export const bpp_public_key = process.env["bpp_public_key"] || "";

export const bpp_private_key = process.env["bpp_private_key"] || ""

export const bpp_unique_key_id = process.env["bpp_unique_key_id"] || ""

export const logistic_public_key = process.env["logistic_public_key"] || "";

export const logistic_private_key = process.env["logistic_private_key"] || ""

export const logistic_unique_key_id = process.env["logistic_unique_key_id"] || ""

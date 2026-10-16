export const IMAGE_MIME_TYPE = "image/jpeg";

export type ConnectorImage = {
	type: "image";
	mimeType: typeof IMAGE_MIME_TYPE;
	data: Uint8Array;
};

export function hasJpegSignature(bytes: Uint8Array) {
	return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
}

export function isConnectorImage(value: unknown): value is ConnectorImage {
	return typeof value === "object" && value !== null &&
		"type" in value && value.type === "image" &&
		"mimeType" in value && value.mimeType === IMAGE_MIME_TYPE &&
		"data" in value && value.data instanceof Uint8Array;
}

import { isImageMimeType, type ImageMimeType } from "./response-formats";
import { z } from "zod";

export type ConnectorImage = {
	type: "image";
	mimeType: ImageMimeType;
	data: Uint8Array;
};

type ImageReference = Omit<ConnectorImage, "data"> & { imageId: string; byteLength: number };

const imageIdentity = z.object({ type: z.literal("image"), mimeType: z.custom<ImageMimeType>(isImageMimeType) });
const imageReferenceSchema = imageIdentity.extend({ imageId: z.string(), byteLength: z.number() });
const connectorImageSchema = imageIdentity.extend({ data: z.instanceof(Uint8Array) });

/** Request-local bytes; Code Mode's durable history carries only execution-scoped references. */
export class ConnectorImages {
	private readonly executions = new Map<string, Map<string, ConnectorImage>>();

	capture(executionId: string, image: ConnectorImage): ImageReference {
		const images = this.executions.get(executionId) ?? new Map<string, ConnectorImage>();
		const totalBytes = [...images.values()].reduce((total, value) => total + value.data.byteLength, 0);

		if (images.size >= 4 || totalBytes + image.data.byteLength > 4 * 1024 * 1024) {
			throw new Error("Retrieve at most 4 images totaling 4 MiB per invocation. Earlier calls may have succeeded; do not replay writes.");
		}

		const imageId = crypto.randomUUID();
		images.set(imageId, image);
		this.executions.set(executionId, images);

		return { type: "image", mimeType: image.mimeType, imageId, byteLength: image.data.byteLength };
	}

	resolve(executionId: string, reference: ImageReference) {
		const image = this.executions.get(executionId)?.get(reference.imageId);

		if (!image || image.mimeType !== reference.mimeType || image.data.byteLength !== reference.byteLength) {
			throw new Error("Image references are valid only within their original invocation.");
		}

		return image;
	}

	clear(executionId: string) {
		this.executions.delete(executionId);
	}
}

export function isImageReference(value: unknown): value is ImageReference {
	return imageReferenceSchema.safeParse(value).success;
}

export function isConnectorImage(value: unknown): value is ConnectorImage {
	return connectorImageSchema.safeParse(value).success;
}

import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const posts = defineCollection({
  loader: glob({
    pattern: "**/*.md",
    base: "./src/content/posts",
  }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),

    categories: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),

    description: z.string().optional(),
    image: z.string().optional(),

    pin: z.boolean().optional(),
    math: z.boolean().optional(),
    mermaid: z.boolean().optional(),
  }),
});

export const collections = {
  posts,
};
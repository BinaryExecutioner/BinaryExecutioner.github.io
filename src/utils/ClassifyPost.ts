export function getWriteupSection(post: any) {
  const id = post.id.toLowerCase();
  const title = post.data.title.toLowerCase();

  const tags = (post.data.tags || []).map((tag: string) =>
    String(tag).toLowerCase()
  );

  const categories = (post.data.categories || []).map((cat: string) =>
    String(cat).toLowerCase()
  );

  const combined = [id, title, ...tags, ...categories].join(" ");

  if (
    combined.includes("cydef") ||
    combined.includes("cyberdefenders") ||
    combined.includes("forensics") ||
    combined.includes("malware-analysis") ||
    combined.includes("revil") ||
    combined.includes("blue-team") ||
    combined.includes("blueteam")
  ) {
    return "defense";
  }

  if (
    combined.includes("pl_") ||
    combined.includes("pwnedlabs") ||
    combined.includes("aws") ||
    combined.includes("azure") ||
    combined.includes("cloud") ||
    combined.includes("blob") ||
    combined.includes("entra") ||
    combined.includes("iam")
  ) {
    return "cloud";
  }

  return "attack";
}

export function getWriteupSectionLabel(section: string) {
  const labels: Record<string, string> = {
    attack: "Attack Labs",
    defense: "Defense Labs",
    cloud: "Cloud Labs",
  };

  return labels[section] || "Writeups";
}
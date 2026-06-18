import { describe, expect, it } from "vitest";

import { classifyPath, riskFor } from "./riskClass";

describe("classifyPath", () => {
  it("flags OS system dirs as os (red)", () => {
    expect(classifyPath("/etc/passwd")).toBe("os");
    expect(classifyPath("/usr/bin/python")).toBe("os");
    expect(classifyPath("/scan/root/boot/vmlinuz")).toBe("os"); // /scan alias stripped
    expect(classifyPath("/mnt/c/Windows/System32/cmd.exe", "cmd.exe")).toBe("os");
  });

  it("flags docker / service state as services (orange)", () => {
    expect(classifyPath("/mnt/docker_data/overlay2/abc/diff/x")).toBe("services");
    expect(classifyPath("/scan/docker_images/overlay2/layer")).toBe("services");
    expect(classifyPath("/var/lib/docker/volumes/db/_data/file")).toBe("services");
    expect(classifyPath("/mnt/pgdata/base/123")).toBe("services");
  });

  it("flags compose / env / conf files as config (yellow)", () => {
    expect(classifyPath("/mnt/apps/myapp/docker-compose.yml", "docker-compose.yml")).toBe("config");
    expect(classifyPath("/mnt/apps/myapp/.env", ".env")).toBe("config");
    expect(classifyPath("/mnt/apps/nginx.conf", "nginx.conf")).toBe("config");
  });

  it("treats ordinary user data as user (no badge)", () => {
    expect(classifyPath("/scan/tank/Media/TV/show.mkv", "show.mkv")).toBe("user");
    expect(classifyPath("/scan/nextcloud/photos/2024/img.jpg", "img.jpg")).toBe("user");
    expect(riskFor("/scan/nextcloud/photos/2024/img.jpg", "img.jpg")).toBeNull();
  });

  it("OS outranks a config file under an OS path (deleting /etc/* is dangerous)", () => {
    expect(classifyPath("/etc/nginx/nginx.conf", "nginx.conf")).toBe("os");
  });

  it("returns display metadata for risky paths", () => {
    expect(riskFor("/etc/passwd")?.label).toBe("OS");
    expect(riskFor("/mnt/docker_data/x")?.label).toBe("Service data");
  });
});

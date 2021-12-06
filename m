Return-Path: <kasan-dev+bncBAABBK4JXKGQMGQEGRBZQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CCA146AACB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:20 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id q64-20020a2e2a43000000b00218c94eab9bsf3845766ljq.18
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827179; cv=pass;
        d=google.com; s=arc-20160816;
        b=HrO1TP0SXGgHVqnh6RqQL+pkdOjUosGCs7dxLXX7dElfPmaJRL6wKhjfEjzqqSay51
         8HW4uAkX5YQKtX5llrEF33ON00x0SptYjcWlhSrt6N0ANOCvd8BWs35ntl4FaoG9SeLU
         iRqXOOn3NKtMpZ5solVdIKvxcsEnfN7sUznCKqdsbNQJufFUzKGxWhqPdrXsoIdHDQOW
         Yb422zBK6peDYJZAaS0FRR4RinK4cW3sJXxDqV3PZvXR1Z81NMz84dDpejo3HU5z3wqY
         slflz1rreGDSp13cY1N06Hf10kJzywhCjuTM94k7skuHEx6Bf8D6W+DiPadbzmsC0msW
         YiHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hb04glvF/yXWShGRnwBnVxAnKIDplgb//o3N8s8SE+0=;
        b=hF0QNJrsp0FJ4JvVQmdehX3nopOJnZ+1AB+8QQOStHsGrh1P3fXJuAF0QrB25bKty/
         mhAyy1IPSGF9syjtKqYA/8V2lyVjLTqDJi8BySEarF96uF9w3/Lrni6I4Cqcv+hXfG1J
         9H/O0mjY0a1DTDWhEGiiHOSMzX17MxWKPTxpNqBc+u24vfl7OT/85Qd29XB6eLkgOFxc
         y65VvYJGpng/58eAiMQkBtsNfNC57T90ZHlZ0G16tuHwzQDuh1lQxCq7CTvcGDuIjnTZ
         H9QA9FmbttFIudv/xROuyU67uZW8tAqUQMrLJA5E4gXYlsLXAnWneyWFzl8tl7dz2pwc
         Y8Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jpdwDylT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hb04glvF/yXWShGRnwBnVxAnKIDplgb//o3N8s8SE+0=;
        b=iWGOUMdsyixC9Rsvl2eGySqWIkDoo4OEzdcjkii4pgz+IxCMYaziYNyF9YyFpSKKaS
         ziF5NHd2/7HUedpV3lwZwfrvUYcBgyEzamEd91KjoN/lOJNYl0/I8F7xCQ22sRbEaKSo
         KGKYguZ9x4kZna8s68gyRviYZDZEbAozOKG3KOWQ02RCc9Lt48bjsRsM0h359jju2gF3
         AY3GycxMehFcyLIauvdmzQPDBjeLzVTGjGD8phiIPhG/1OFJ9JSspddcF/dBfHDiHWDE
         y0r9szn6LwWHr6fR1i7fOJCraHKq+dBDA4ntIvzGDM/150yTc6cXj1Qef+nFpKBcj+Bz
         e9eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hb04glvF/yXWShGRnwBnVxAnKIDplgb//o3N8s8SE+0=;
        b=0hhBCTVDgBgBbSS0bxvQHfTYKNlhpuQc3Lr9ifolJ/bl8AGiigSES4g5hWy5zyCGsj
         qYVOsVr0kd0tAk4FirW/zGvJIy9+1KFW/TQFx3+EqIUKcsonuS3kuLr680PH1zbr+DmQ
         ZxUxQ/UySUNSWhGxn+nwN38WtuxW7QNDJDWjK+GZgx8E7tZH6wzsX+lWZvs60scJdwvq
         6VaXxa/2FNpVxqQQLY+FzRhBky0pZtZJsnsdnnRLwgGLlh5MLgg9/bGDaA2CrMJ3beoH
         SaunM3tMwXuJB8kQnOShcH3y1FMT9ysDo8WbvyVEOVg08zOHO8HXfsRXT2QdFyIEn1Vs
         bHpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Mt7ar0TlNypvkQ1sjbEfn31US9dD+e4YZPw8Y6jwwXjq8MgSg
	AI6b9Hsksv8OYOH65xMxqHQ=
X-Google-Smtp-Source: ABdhPJxfpmzjOHw/9fOv+0vXeQFk+O/SJJHXO05hTyZsPI0R5/7ORynO41IKQXdaE/H/yLTukPD3Vw==
X-Received: by 2002:a05:6512:1506:: with SMTP id bq6mr38204190lfb.444.1638827179626;
        Mon, 06 Dec 2021 13:46:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1927060lfv.1.gmail; Mon,
 06 Dec 2021 13:46:19 -0800 (PST)
X-Received: by 2002:a19:c34a:: with SMTP id t71mr36888331lff.146.1638827178914;
        Mon, 06 Dec 2021 13:46:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827178; cv=none;
        d=google.com; s=arc-20160816;
        b=otOjmmZrYq0MEdQSaaW5s1+Xd4LBskFp0xDr2wAF5c+z5roR7oKvlQBS26zaJfsJ27
         W/RFbTsTTHYl/qrt7+e3svTNUa2otvt0ALM5qxyiTv34HhfhFj8PpKfGgPhI5NTss7Jh
         qM9YCAxJzflNUaEUe1qIFiGfS690aH10Ssd9p4gdM/l4Dj9LDK6vekqPQnxF9N7Tlc/d
         xHVCfRuFt7WI1INSB0JHIvODZkuLAnEY/YYH9L8W1jkTJJjE0Gshs/zpy+82cdlibm7E
         4fieflEMQdiqot3lYOhmv5krwKx/Cb8FF+63BgaG3n0PgxCS8AD980MFqf+846mOH+qy
         9nmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4ip+mfiCrUsqaU/ZPq/AUCt3O9J1b1z5H3QxOY+5r30=;
        b=x46G8BbNmd1iNcB0YgYG/IX1ye2JJSCgRF24woms6jkQDzR8VJVi9GV6baov9A57C6
         ol014g4oyBY7g33eaAB9ywAVHZ919ELiAM7BI4EuAetC9gRC57Hq6FQcERVO1QnXxN39
         5TctC2L5Zt3Fr6mZ0FhKSFhVnQ+NXhiwAPIz1MYHG+U+Uv3yqheqS25UBTZ4bbnb4ZgP
         f1jWlIYuiyZW+J6M4JPbDtnGoqaaRRoVEvUGFTgyjzYr/qg8UJ5Uxh1ZuBZC5AImJODN
         0msd/eS3uzOKzThw7ezEONcXWTO/B4pt8OL1dDMWrqHXdh6R/m49tdGSSNKeLzLmtFZ8
         HpcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jpdwDylT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id j13si745089lfu.5.2021.12.06.13.46.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 23/34] kasan, vmalloc: add vmalloc support to SW_TAGS
Date: Mon,  6 Dec 2021 22:44:00 +0100
Message-Id: <666b9e932dde24df6e1b02493a04530b99ace697.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jpdwDylT;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: Andrey Konovalov <andreyknvl@google.com>

This patch adds vmalloc tagging support to SW_TAGS KASAN.

The changes include:

- __kasan_unpoison_vmalloc() now assigns a random pointer tag, poisons
  the virtual mapping accordingly, and embeds the tag into the returned
  pointer.

- __get_vm_area_node() (used by vmalloc() and vmap()) and
  pcpu_get_vm_areas() save the tagged pointer into vm_struct->addr
  (note: not into vmap_area->addr). This requires putting
  kasan_unpoison_vmalloc() after setup_vmalloc_vm[_locked]();
  otherwise the latter will overwrite the tagged pointer.
  The tagged pointer then is naturally propagateed to vmalloc()
  and vmap().

- vm_map_ram() returns the tagged pointer directly.

- Allow enabling KASAN_VMALLOC with SW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Allow enabling KASAN_VMALLOC with SW_TAGS in this patch.
---
 include/linux/kasan.h | 17 +++++++++++------
 lib/Kconfig.kasan     |  2 +-
 mm/kasan/shadow.c     |  6 ++++--
 mm/vmalloc.c          | 14 ++++++++------
 4 files changed, 24 insertions(+), 15 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ad4798e77f60..6a2619759e93 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -423,12 +423,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
-static __always_inline void kasan_unpoison_vmalloc(const void *start,
-						   unsigned long size)
+void * __must_check __kasan_unpoison_vmalloc(const void *start,
+					     unsigned long size);
+static __always_inline void * __must_check kasan_unpoison_vmalloc(
+					const void *start, unsigned long size)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size);
+	return (void *)start;
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size);
@@ -453,8 +455,11 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) { }
 
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
+static inline void *kasan_unpoison_vmalloc(const void *start,
+					   unsigned long size, bool unique)
+{
+	return (void *)start;
+}
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cdc842d090db..3f144a87f8a3 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -179,7 +179,7 @@ config KASAN_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
+	depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index fa0c8a750d09..4ca280a96fbc 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,12 +475,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
-		return;
+		return (void *)start;
 
+	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
+	return (void *)start;
 }
 
 /*
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a059b3100c0a..7be18b292679 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2208,7 +2208,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2441,10 +2441,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3752,9 +3752,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3767,6 +3764,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
+	/* mark allocated areas as accessible */
+	for (area = 0; area < nr_vms; area++)
+		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
+							 vms[area]->size);
+
 	kfree(vas);
 	return vms;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/666b9e932dde24df6e1b02493a04530b99ace697.1638825394.git.andreyknvl%40google.com.

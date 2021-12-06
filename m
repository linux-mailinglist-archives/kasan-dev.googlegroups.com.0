Return-Path: <kasan-dev+bncBAABBN4JXKGQMGQEJBXTM5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B5646AACD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:32 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id f3-20020a5d50c3000000b00183ce1379fesf2355854wrt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827191; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGKan7rKdtL9E916E9qN22BzTEkx3kn8uJguUJ4CEr7S/ZkFGdpMlOuVPFlXiKNk/4
         uWLcZj6fEcFo/cQzPMrId1M9nU4zTR+lkaeu9FnWLJ/50g2i6XFvw5JvpXgwOXY4l/bc
         WQDIRJVoMlQ0IE+59dymMNeBMQXpNVvvTJTli2IRM6JJs73tU88JimVJwnOPfcd6mcbi
         r35CwQZ8CLUv1DWeZFdDYMJSOsBVOTiBzyJ9J9pEQRAQTIjGWFLrXw/yFLlj8qxioUXl
         9Eis2HWkoiVTHtGBBu53qOfq/JJ6kB/b2N/T+/4zLpU20+39TZZr4JbBOcDBoLBNtXuF
         XpYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m4e4vdixSwjit8z4BlYKY61LP6fkTGkYudOhJnoQbm0=;
        b=wjHW/hMxJTrONF2tXSmArKxQ5vYMn5xaP9eqa6RMB7usK011Gglr/WQPMZmwlkxR1W
         n10P9vhH1QBAEaHo9rhYnLL7Loail96WxlTzPgFep5IVNli0dU4vn6EjbicP5ETlWpKr
         2dDfu9T/8PDjLEqX6qx1BylDxJs8nobm11VMBjtlNpx0f7uYQK/6G9Brx2t7W5OCRmfW
         SN5lnkLfi6gHtgn9h6JbcbMlWtwrwmXcPSgO/dd/D66tqiF5RcZ48IpSkKEbdMOFdsk9
         ByxieYZv2nnBr0SnILqxYwMpxEUOHpwMuB6P3S6MRoWeFsVHMwYrTvRBIswU0E2xQblF
         uakA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=M9OKKoZe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m4e4vdixSwjit8z4BlYKY61LP6fkTGkYudOhJnoQbm0=;
        b=FiZTmm2xNrd7fhyfyLk+VzAUWm/d/JaWtOvNe88+SraDV4awVPzHOcI2VOCvBXPHkc
         16bS0bWJpXKHvWHc4GMkA9zq8Yb8Jorz4u74EZrXTHz/sOgL/+t88ffax/z8iaUyqECp
         RDK27XqIunJOHnC4+4NdF0zyhM2zWgdcvkv2rX9k57eD/foccVX7kFk4ypKvB7XbFVV5
         LomluSyeTvhc69bHVCVxa/4Ej0uZeb2Xd1xGbOPnEogTZ7QYq/Bp4JbFdNg3nf2jOYxw
         tyWDLPSfhJhDzeUxxlrnL/41d2AU7qRDoE+wTiPKvHTT5tT8tJ98K1REHnDzc7wYAU0F
         1v3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m4e4vdixSwjit8z4BlYKY61LP6fkTGkYudOhJnoQbm0=;
        b=m3+2voF3yw7uA6XpVYfQVcHJxpYDDEjH31Y9bNX/3h5PBnnriiHeakqtITj/xauDYR
         Rc3Z0hXdNChb/RJzRoI0IxmWAvaPkePt8Mb6vuHlOXpXrrV3D34VkA74OrU2cww8SQWG
         YK7N/LRhhPB5o1Lz8FovgZ3BoFpsLFe4+Kr/0zCY7pYpYKEOlYnBTxu1815BjZcgZ72o
         v6NSmc8Rm5ePQTZqZFMzIxOHr582Ye4HqeCzrE2OsMWziRO5HtivA3mpcG5JGUC5CBpb
         c90RnB2l1G8zAdJpveTbOJ+HGIHdGF2E6dJmazqrYzR+ZfqMgntAAARBiL4zmpcw8SWu
         CXeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NkXOyH7+mJk+Hz35AvfYuZC4YOicDFNxQr7vpUs7EZB+U6/fR
	jg6/2oyr0G7Za80hEJYkFd0=
X-Google-Smtp-Source: ABdhPJzWu5VFXJNyd+rL6nsgk0VqeTJuc8hvlmJtePOA28Kj/wWVSIRo26LqvgB3BrU+HrAsyQ4BAw==
X-Received: by 2002:a7b:c407:: with SMTP id k7mr1532724wmi.35.1638827191632;
        Mon, 06 Dec 2021 13:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls225507wmd.2.gmail; Mon, 06 Dec
 2021 13:46:31 -0800 (PST)
X-Received: by 2002:a1c:540c:: with SMTP id i12mr1524604wmb.33.1638827190910;
        Mon, 06 Dec 2021 13:46:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827190; cv=none;
        d=google.com; s=arc-20160816;
        b=1Iihic4BRRp8K73g6FoulVKDeOpz0ncTtHGhtuHjKxrJh6/uWXVlsBqeQgvdaK03rT
         ym0xlWSARdQwoObG0UB/F+whKKZfPWSUeBTieCQga8i55b12X/qCEUOb/hqn4aDvdt1k
         U/qUhIrzsAshuG0Rz2ad84VkwYtNuTMf1DOpyd3LOztdxwxbdAsKkw1eXNca+EXsa5RH
         eRt0UobLBNvE2RZzcaOfB6RQcBE7BJCfBTJxiX9oxXNnekfa7P6IutqMVDb+4Qj9swZy
         eUcKNV9Pqrh6lZCfCixYHi2/zMm3lp45DIimvRYq/QJLXs1K4qMe0Nt0jyApmreEMgJH
         gvzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CceoAuXc8ztt6c/41GK5sR1YQRKzgrFVIEpBFl753js=;
        b=rezdAQ2WRORou4p9T/DaxTW93AXr6Asse01hkJyyLcfttxWuF5k+FSHGiW4hgofOmH
         LjUJdmvToxYwrtNg2gTcu4czEUAkWMA3PiD0jyKuM0igqGpSi631TopCgXNSqwlKqQ49
         deXwB59SFdIZOf53Fkj29e23DuAdBmz7mjrKmolFGNFOgBflRNJVKjwRDBJslpYMc7kg
         LCJKST+/TRayrDisswRwItYwjOtcVxcX29Ks3wrr+QPkwSHDRPu/wS+2hXPUOmdD3Sox
         DMbHp1MMGDE6aOhppBjK69jI22UhFF9WAoaU47NCG9go+8VJmZtUG3l1uvsGpp6JwBty
         deXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=M9OKKoZe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id a1si771742wrv.4.2021.12.06.13.46.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH v2 25/34] kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
Date: Mon,  6 Dec 2021 22:44:02 +0100
Message-Id: <af074f0ed424b2530982cf41391dc6e8265b4a7e.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=M9OKKoZe;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

This patch makes KASAN unpoison vmalloc mappings after that have been
mapped in when it's possible: for vmalloc() (indentified via VM_ALLOC)
and vm_map_ram().

The reasons for this are:

- For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
  mapping them fails.
- For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
  kasan_unpoison_vmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/vmalloc.c | 26 ++++++++++++++++++++++----
 1 file changed, 22 insertions(+), 4 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index f37d0ed99bf9..82ef1e27e2e4 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2208,14 +2208,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	mem = kasan_unpoison_vmalloc(mem, size);
-
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
 	}
 
+	/* Mark the pages as accessible after they were mapped in. */
+	mem = kasan_unpoison_vmalloc(mem, size);
+
 	return mem;
 }
 EXPORT_SYMBOL(vm_map_ram);
@@ -2443,7 +2444,14 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
 	setup_vmalloc_vm(area, va, flags, caller);
 
-	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+	/*
+	 * For VM_ALLOC mappings, __vmalloc_node_range() mark the pages as
+	 * accessible after they are mapped in.
+	 * Otherwise, as the pages can be mapped outside of vmalloc code,
+	 * mark them now as a best-effort approach.
+	 */
+	if (!(flags & VM_ALLOC))
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
 
 	return area;
 }
@@ -3072,6 +3080,12 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		goto fail;
 
+	/*
+	 * Mark the pages for VM_ALLOC mappings as accessible after they were
+	 * mapped in.
+	 */
+	addr = kasan_unpoison_vmalloc(addr, real_size);
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3766,7 +3780,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
-	/* mark allocated areas as accessible */
+	/*
+	 * Mark allocated areas as accessible.
+	 * As the pages are mapped outside of vmalloc code,
+	 * mark them now as a best-effort approach.
+	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
 							 vms[area]->size);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af074f0ed424b2530982cf41391dc6e8265b4a7e.1638825394.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBAABBH6VXOHQMGQE4WQWN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A88914987C0
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:23 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id g13-20020a056512118d00b00436a446899fsf3718310lfr.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047583; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKvY/YwIhdQA2FtLzfsOQssVGJ3P1x3OuFZ1cvtC9FxozDM6bAK3kwOpQ7Og8GbFjp
         0MAEiOsMZTDQpAFEep1YpqYGXwVMqpSyk0/5vFg5yuNURkUqR7OyC632teCgWHVUPE7d
         n0jMCP3Qvhr8kBQ1RHgbuhTSKkF9bKFfRIupGsEAwI67WwC9Jd9CYATS7zQf5zaGQNmc
         dHDLM7Zo1JfXR9OTJhHsoNI00yB9oG793qqM3WOOxb9iFxRWe8Guc9N2T8NHndHrxaER
         q2oxLtnBVi6U7QkpJjpUXP4+68Tbg4PtCC9TVdiFZAohW3PCzbJJWMpXRhkblShV65Lx
         izbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RTRyRTohuJH7zfKpFIq6EumqH8nSDHcflMhQQcVeLqg=;
        b=uuZoIOGD3lDt1RlcTEeutTdTJ7xZ/7WEw5ZlNlo4ANi1W62P2ALPDHgDKvcKEyGtG6
         88kIo9p/sLQ9nJUKPisuMt7xhmLwVEejvifd7v19+LoH7mBdGRK7tsyTvHreOutDUf3M
         NOTJcKyeur9+p4LeTKXc12Dc9FuLS2n8C0fi8bVhlRIJpz/jlJqVgbAij72yYz2/SSj+
         glXZqX1zeO7VEJGNTefmMJYORPEZAxGloUfyZUhUTQ9hQ0FlOldwJBPbUDXJxTIuHz6p
         fQWTL9vqoWnv3oP7rYF1/pvrQa6EnEOtkSh49izwIQax6UkoaoZbpFw/vOsILxSA7QH0
         P/YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ngeRMLOE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RTRyRTohuJH7zfKpFIq6EumqH8nSDHcflMhQQcVeLqg=;
        b=Zh8lfirWXxqnWAFbYhNpcHxf9Kda/s8ACniZLXjTJF722IOOy8cIkJx2crh5l794yD
         n445G5gwAJIMNPMJdvPL26Ss+HHewCfRktK9PwgFpG/umGTwzdaAAWUb+g+OlJC3qElM
         48zxcpvcsut2FBv7IKaLrW7bv/uYTr31pcucDyZiDWXdfOX1crcRGe6utE8K2k4SYFCZ
         soBd5lGb+NpDBWSfxiubCsSPSGT6gRm+f8tB2LZ9yxUxnyAmG2hWWKWKpbUpLOVUg3Wf
         cMm4EgGenJ0oYYoTRbyp6TobH5rGgm1RhSAeVrCYp35wpBfqUr+i7Ka7F18zrPQcY7LY
         pH3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RTRyRTohuJH7zfKpFIq6EumqH8nSDHcflMhQQcVeLqg=;
        b=1chZfgKHQX26ELIiku9OpNFHtxn6dFLOznDhdP08AXbTSBw0ejKF9CrDcfKr3xt7Be
         48Zm4UnmG3L99gCVVd5d+3oo4F14TnxMfdLOzkmGxQnl4WuV6oUGkGi4cChVGv/awXnx
         1NWD2tS/b0KfJfPWF8Q9vylbIizARV5B2V2zTXniITw3e+275AvjrGYf4N/oTDbOftgu
         sLPPVzGrkiwoKyGo5E/1r+U5RsNQX2gZRJc5XbKNRFWcIYDVEEv5FVbFc5nf589aTPrJ
         7GPpIIekJQln/9xYZkC1rm/tgVan2iKUAcORPmsCJKNRCrWUPq+CrN1jjcS52PMN0haN
         XlKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oaYpa7qMkgYF32K09s3dMEIw3RyO9d7l+uMrzmr/XCrXwFeXa
	2nzBPSdAcBSxjEc7YTELq2Y=
X-Google-Smtp-Source: ABdhPJw3Mp+L++HWtHuFfwnztGisGDScPUIt0uEd9cPhLXQ7weoOajStvhKVwGzo+nPTuZtctV5YBA==
X-Received: by 2002:a05:6512:31d1:: with SMTP id j17mr2835237lfe.363.1643047583226;
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac9:: with SMTP id n9ls572522lfu.1.gmail; Mon, 24
 Jan 2022 10:06:22 -0800 (PST)
X-Received: by 2002:a19:f80f:: with SMTP id a15mr11057679lff.396.1643047582390;
        Mon, 24 Jan 2022 10:06:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047582; cv=none;
        d=google.com; s=arc-20160816;
        b=TFeP66C4WOR77Q2RobU7sK4N/9h1FoYvYLOlI6Z8z59PpKZ10Ilu6/tfXg3R1x6zMo
         Xl6d8o8/DLi2eYq6j80mO5BwwIvcAJusjo99idDef9Apn+wcLKiVX/ATEvYs2lsvjBRc
         X2PZkm0H56vzrRLiz+BZdE/bQPPLzS4y+bwjZSKA6BUoSTy2sL62mDoQSKDXlGc1ORfk
         AydcCqmTp5DcSZA+zzM7ddQyJFRqQld+az5FDTK+1CdHf+vsjw7LlqJbdlCJfMFlEr18
         nunkHrzxvwzHq4ioRsCTIXhwnOgKAzT06Qw5ZgDOJsgpLulm5wgwfWDkCX2EjAZjZQQN
         URJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TDVp0JL1APA56QEsnBAsRwmJ3v+N88UNoUAViR0TQ7w=;
        b=I8lrgNLXtseHtwRdeL2pa/DFibliiZ3KHjI3g42gwJqgk8X/wqbCZ1DLng1xKqykDt
         bnEfbZLVbk9zTp+LcSyiu72P2SwfUDlJQMreC4nFvOJMx8fRtWYVP2kV4ClQYbCmwPb4
         FtVixH1IbUVZA6jiAxfmY0tdY5cQFJfUhsRAocjkEtDFGFb7QjWmBkOtI7ELjWRPpFSI
         VkgTzSjxfOnDsv1g7EplJ52OqsNIIymN97XgOqSWclbYipCuUcSIxPyq5Ig1ctZjghLC
         136ThDza2NL/32pyRHHzfbS/Zbc+9IWcUxTfJ4RBgSOHa8JCvAWBqZEoLSGW9G0k18xw
         NoaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ngeRMLOE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e18si474080lji.4.2022.01.24.10.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 24/39] kasan, vmalloc: add vmalloc tagging for SW_TAGS
Date: Mon, 24 Jan 2022 19:04:58 +0100
Message-Id: <4a78f3c064ce905e9070c29733aca1dd254a74f1.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ngeRMLOE;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add vmalloc tagging support to SW_TAGS KASAN.

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

As a result of this change, vm_struct->addr is now tagged.

Enabling KASAN_VMALLOC with SW_TAGS is not yet allowed.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop accidentally added kasan_unpoison_vmalloc() argument for when
  KASAN is off.
- Drop __must_check for kasan_unpoison_vmalloc(), as its result is
  sometimes intentionally ignored.
- Move allowing enabling KASAN_VMALLOC with SW_TAGS into a separate
  patch.
- Update patch description.

Changes v1->v2:
- Allow enabling KASAN_VMALLOC with SW_TAGS in this patch.
---
 include/linux/kasan.h | 16 ++++++++++------
 mm/kasan/shadow.c     |  6 ++++--
 mm/vmalloc.c          | 14 ++++++++------
 3 files changed, 22 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index da320069e7cf..92c5dfa29a35 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,12 +424,13 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
-static __always_inline void kasan_unpoison_vmalloc(const void *start,
-						   unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void *kasan_unpoison_vmalloc(const void *start,
+						    unsigned long size)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size);
+	return (void *)start;
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size);
@@ -454,8 +455,11 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) { }
 
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
+static inline void *kasan_unpoison_vmalloc(const void *start,
+					   unsigned long size)
+{
+	return (void *)start;
+}
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 39d0b32ebf70..5a866f6663fc 100644
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
index 38bf3b418b81..15e1a4fdfe0b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2210,7 +2210,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2443,10 +2443,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3795,9 +3795,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3810,6 +3807,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a78f3c064ce905e9070c29733aca1dd254a74f1.1643047180.git.andreyknvl%40google.com.

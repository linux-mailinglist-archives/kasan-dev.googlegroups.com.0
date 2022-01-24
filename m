Return-Path: <kasan-dev+bncBAABBYGVXOHQMGQES5NLUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E6DF4987CF
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:28 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id r26-20020adfab5a000000b001d67d50a45csf2201062wrc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047648; cv=pass;
        d=google.com; s=arc-20160816;
        b=KSwt7JrNMOk9CA+K8aQS5L8WS+Ner641D6aPiRZn97pCk6n70lbS0lUcNkKS4PxrE9
         ine8cJisjA3olboTyWsPG2yjpPJcvqSEz+JMeOIEWNlGeO5B4KG5GdkXZRUy8C8mJY8F
         sJOaIoFtzSY7X/6Rw+d0xb49kDCx5tftWNf+qJ+hOA86BTtv9krTlAwf8aavwchpdLMu
         98FBLfi2wJtud9MAtV6jM/sEVATaTZWFZj4k2NQ+LO92k/fDZSnoSFsyLyLYgQa/msLn
         CaJzpcDs5VxFYbAhgz0IveU4d06nsI0EbvceW9q8RlphVl0E2qgFpGsFhnDUAnW3ABKC
         EGIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XATZwxuRsMAXwDMlSXksHo2sC9NQa9+lnf045ML/V+Y=;
        b=yTbchRIB+4Y8ywyINpKpnSU+1X6TlI2plptdXjeU7/SzFqazn0LPJ6ctaOmKiHm2kP
         uM2yNIH5DY48OsZQnlPgKidC2wtnZu+PKMZD3d6Kd50e0Md+eSDSfK8eOa2iabA4f0Sn
         Uy6SslhzVJSUbkm3YeI91rcEjq14Isv9qnsR2dPE1FDcAVvibYdgxKSRuVZifeng37Je
         QqzlmzdBsZGfgd6DlCoXSPbI6uFE3ISqCJIiFrlbMVI9aTmJlrAOxGJPkxz/8qUcYcMf
         6kSq5GRIpfqLr7GgYFD90qs0K+P6Rqwb79gBYvtW39xeICqdDiOKRQ7RmoUqZ8LAU9vJ
         Zp7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fR9nfxov;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XATZwxuRsMAXwDMlSXksHo2sC9NQa9+lnf045ML/V+Y=;
        b=I4TV/c9cLVeCGcVZznh6XVHD5PWi9fautmBspL6IipYF245xlExeB9TDeuVX0EzzfI
         Lrg0mvCSnX7iYFIdWXY2qDEtwNBNo/aUPTYhDmY4k1yuG+qot0uSFs8beeQ1w9QRmeFd
         4nQeBz36wMTNRxbdBPLliNvOCb8FdvymijTHYRUDnpjgS4RP+4UMvGNiDe3OcFDdB3lr
         QzDi/pIHYg3abzX8PiurbrOO53Ohq4p3CUJVPJCsuoKh7UUj0meJHpK9GbJaWU/DkAEf
         pzIVrrxrgZ72mEFPe/EfOhvaH5NcRv/o2sL3lUHu9yspuryV8l0st4n36l6R8Q/5J67w
         yDlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XATZwxuRsMAXwDMlSXksHo2sC9NQa9+lnf045ML/V+Y=;
        b=h+9UyXDeWmhLNqybGsH/GxJsw38cEriLf8mS7nwa35G6oIxEQ9mE7R5RglrJ96OCs9
         HpdpurIMPU6KZAfrqPCfv77ezUq1qFYb6RrP3zWDH2l3loe+VQ0NjX4EW5Qz6kdBEbUQ
         OuGbRy7Q7ZePDaY5q8FREjjdOof+gDDR5cf6pptKx9F7IQ5LVqfqPBBXvIU8UfvVb8xf
         IzE8lmEGuBCU2PcmbjzwDmT0UjgJRxeft8ifGDljZfGSh7BsfAUDxuXmHXxowVvdXi2f
         xa14iIrRLdKrLPbcfdZiPIobx1jopeMpCoCZdoFNXzvHcxNt38NzWX15I6MXZ8pG/WmE
         pb/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AHqQzZraicr4xSxP+gyaPvmcRD6CoLsj2p07deXBza1AKhQ7u
	kjfxV/KOPcUzGf3lFNUUwOQ=
X-Google-Smtp-Source: ABdhPJwhJAUul2DWPOFDeEMfyzecowJZNk1iS/+RCOveuuEn6Q/UPJzVC1jR9apNO+u6Fg9wsWm0Ug==
X-Received: by 2002:a05:6000:2c6:: with SMTP id o6mr4370046wry.601.1643047648285;
        Mon, 24 Jan 2022 10:07:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f80e:: with SMTP id s14ls303376wrp.2.gmail; Mon, 24 Jan
 2022 10:07:27 -0800 (PST)
X-Received: by 2002:a5d:6482:: with SMTP id o2mr13080767wri.109.1643047647617;
        Mon, 24 Jan 2022 10:07:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047647; cv=none;
        d=google.com; s=arc-20160816;
        b=HWQgzHFFcRFwiCtGMWZj3/PMAnFhLpIkQMSRwNAhQIBuBXaW7wN2d2KXOUQQEsiKDr
         XTyxo7+EPyFpnKP+kpqqEmEVaDv559Tpvs1+wxNW/HvZYA2FZhOjNNMRO9lQd4TpLS6C
         ZDbBAVxNv2DKf4bXLwZeKcARMqBsfFzCJF1go2QDC2rtGt1Z54C7I9bA8+iqh5pxwdFQ
         G//Wcw5yTpc2iUJq67fSrVIpogbGLOzEB+fviG1kHDJ+hzaL157TP/EwYueOdYAu8lL5
         9Hvgv6rjr2sJI2NtCevPZsZojk8mPGO9wM2cH7SDf7FLjShxUtSF5lKFLX6YdcPhUqY3
         N2TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5KUJZNJV1O4hNGiPaFWjJZ6YP4SR64jSFKwdeaC+81U=;
        b=LPHfa/X5k4k85UGsysfIJn1RMe0J5IbhYx7DiCKunyFefqT3aIrSOXg+dpFwEsVNG9
         L70I+n9CGotlJ72q+7pIz54J7Ya7jb3N0dzFRldXeUuGUrRiMNRU1ZmZXsnrJCRJUWo+
         YOuHoWa6IgGuoni75YpSD2hmDtjpNy0jZYibwRJwNGPRPaM5YtZyIHH//0G2ayPYoVSq
         VV6AeHuZ8RYSjUGmXpQuH1WJmW7datuU0PvdkjRCmQ2nQqF11bnU/NdRCA3iDS1olPOn
         tgPFQYcOSvXl2ZB7KjRjUytwTaGjIY1RrY1wZsT+8M8o16gXQJuNVkuLyn/DoE8wq4Ph
         7cfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fR9nfxov;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id p16si513406wru.0.2022.01.24.10.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:27 -0800 (PST)
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
Subject: [PATCH v6 31/39] kasan, vmalloc: only tag normal vmalloc allocations
Date: Mon, 24 Jan 2022 19:05:05 +0100
Message-Id: <fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fR9nfxov;       spf=pass
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

The kernel can use to allocate executable memory. The only supported way
to do that is via __vmalloc_node_range() with the executable bit set in
the prot argument. (vmap() resets the bit via pgprot_nx()).

Once tag-based KASAN modes start tagging vmalloc allocations, executing
code from such allocations will lead to the PC register getting a tag,
which is not tolerated by the kernel.

Only tag the allocations for normal kernel pages.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Rename KASAN_VMALLOC_NOEXEC to KASAN_VMALLOC_PROT_NORMAL.
- Compare with PAGE_KERNEL instead of using pgprot_nx().
- Update patch description.

Changes v2->v3:
- Add this patch.
---
 include/linux/kasan.h |  7 ++++---
 mm/kasan/hw_tags.c    |  7 +++++++
 mm/kasan/shadow.c     |  7 +++++++
 mm/vmalloc.c          | 49 +++++++++++++++++++++++++------------------
 4 files changed, 47 insertions(+), 23 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 499f1573dba4..3593c95d1fa5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -27,9 +27,10 @@ struct kunit_kasan_expectation {
 
 typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
-#define KASAN_VMALLOC_NONE	0x00u
-#define KASAN_VMALLOC_INIT	0x01u
-#define KASAN_VMALLOC_VM_ALLOC	0x02u
+#define KASAN_VMALLOC_NONE		0x00u
+#define KASAN_VMALLOC_INIT		0x01u
+#define KASAN_VMALLOC_VM_ALLOC		0x02u
+#define KASAN_VMALLOC_PROT_NORMAL	0x04u
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 21104fd51872..2e9378a4f07f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -247,6 +247,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!(flags & KASAN_VMALLOC_VM_ALLOC))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+		return (void *)start;
+
 	tag = kasan_random_tag();
 	start = set_tag(start, tag);
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index b958babc8fed..7272e248db87 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -488,6 +488,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+		return (void *)start;
+
 	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
 	return (void *)start;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6dcdf815576b..375b53fd939f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2221,7 +2221,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NONE);
+	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_PROT_NORMAL);
 
 	return mem;
 }
@@ -2460,7 +2460,7 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 	 */
 	if (!(flags & VM_ALLOC))
 		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
-							KASAN_VMALLOC_NONE);
+						    KASAN_VMALLOC_PROT_NORMAL);
 
 	return area;
 }
@@ -3071,7 +3071,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
-	kasan_vmalloc_flags_t kasan_flags;
+	kasan_vmalloc_flags_t kasan_flags = KASAN_VMALLOC_NONE;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3124,21 +3124,28 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		goto fail;
 	}
 
-	/* Prepare arguments for __vmalloc_area_node(). */
-	if (kasan_hw_tags_enabled() &&
-	    pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
-		/*
-		 * Modify protection bits to allow tagging.
-		 * This must be done before mapping in __vmalloc_area_node().
-		 */
-		prot = arch_vmap_pgprot_tagged(prot);
+	/*
+	 * Prepare arguments for __vmalloc_area_node() and
+	 * kasan_unpoison_vmalloc().
+	 */
+	if (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
+		if (kasan_hw_tags_enabled()) {
+			/*
+			 * Modify protection bits to allow tagging.
+			 * This must be done before mapping.
+			 */
+			prot = arch_vmap_pgprot_tagged(prot);
 
-		/*
-		 * Skip page_alloc poisoning and zeroing for physical pages
-		 * backing VM_ALLOC mapping. Memory is instead poisoned and
-		 * zeroed by kasan_unpoison_vmalloc().
-		 */
-		gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+			/*
+			 * Skip page_alloc poisoning and zeroing for physical
+			 * pages backing VM_ALLOC mapping. Memory is instead
+			 * poisoned and zeroed by kasan_unpoison_vmalloc().
+			 */
+			gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+		}
+
+		/* Take note that the mapping is PAGE_KERNEL. */
+		kasan_flags |= KASAN_VMALLOC_PROT_NORMAL;
 	}
 
 	/* Allocate physical pages and map them into vmalloc space. */
@@ -3152,10 +3159,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	 * (except for the should_skip_init() check) to make sure that memory
 	 * is initialized under the same conditions regardless of the enabled
 	 * KASAN mode.
+	 * Tag-based KASAN modes only assign tags to normal non-executable
+	 * allocations, see __kasan_unpoison_vmalloc().
 	 */
-	kasan_flags = KASAN_VMALLOC_VM_ALLOC;
+	kasan_flags |= KASAN_VMALLOC_VM_ALLOC;
 	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
 		kasan_flags |= KASAN_VMALLOC_INIT;
+	/* KASAN_VMALLOC_PROT_NORMAL already set if required. */
 	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);
 
 	/*
@@ -3861,8 +3871,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-							 vms[area]->size,
-							 KASAN_VMALLOC_NONE);
+				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBAABBA4LXCHAMGQECALZ2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D8E93481FB8
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:16:19 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id z3-20020a05640240c300b003f9154816ffsf8498459edb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:16:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891779; cv=pass;
        d=google.com; s=arc-20160816;
        b=YM1/lOvIZRIpjjF/Sa8BlBjRSkXEQmW/kLm1e3S2hqEq8iCbQ0xpIDWXiZt5LuKLFh
         ZDeOzuf+XdjdodviHDrepoWLliNGdA1LZP+vduRc5Y/NlFRPPSPlFNCt+P+BSTc5rKe/
         UmRkYMM7K45u18tl7xrKe20xQlKCCY4ET4eg1L0w/1vSjJkDGfZRpJyFuMtjgX6Cfe2L
         JD3BE/jfVr6+xgHnd4fs2l62bLtNZT53yPUHwEfqn0qWa1/N5u4LL10vt7MdCCwBSN+2
         kcKbDJUBajji/aY0Ck7PURIyS5COWqFL5PU/6At3tkjrWu7d4/qxerCcZGnjzSZpMa6H
         XR+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V6gX0B5tr3LBSAT3i9QSjUsVpK2upA7fTUeeiDL3VMg=;
        b=LmaGAVfjKMo84iZTGxY3bRnEMNo0ssTx+0lUbDD8lEDrBhKr/jQLkaPRcj8to8b53I
         53GBal7zMLT5oYKRtVszFkgymZUg/dYCvaVHLX4RBMSicwRQ/7khmiYbJkQVatvRHx/k
         oQeJuYUcX9JmlB7HGN+S3Tjcy8zP6A/NRRKmgaznrlwBMHONeg21+YfRkRySrpewskO7
         wKx5gEhHCJVd9+cn7oQb7spTURk3sxvvxiZPFqBVMhC+rssbv224pLfCvWWc8hF87pUh
         FKcW6g9D78SFpxZow3dhF0XWtg69VWQsqBrV6n7pdU5glSG+qc1ksCR4tDFEU1LLo53P
         Ep+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h8DXvs8Y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V6gX0B5tr3LBSAT3i9QSjUsVpK2upA7fTUeeiDL3VMg=;
        b=Cokn+6wdj0bQJMNjrqF/JH5H8IYhSPclGQGPqsQ8A7yMjIucM/PwCQSTI4UWCOLz0g
         uNy7xkFtMrDi/oSe/+X9iKa8CzGInjbXh1kPxCr/jVxe1p5qpxPH21Q5TdaCPTCLjQ2J
         cmKxLtSiEmchf/otQZJsHoLPST05ahN1DTtklumKggZGzuzxrt8UT+DV4ibLjYijyh5j
         A96tFBPFsxF82PgGxcI2AFRC9MdilaTqxS1TNHZr3NA1nMSPrxNyjRNDeQzDyT2M/ejG
         L/3TOTSM6LuV4pCuQiCmiSKlfoLgvlPF1vPhNGcuMFKu6JIqfZ4WJ7wgVpnHN7lgV2fP
         Xnsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V6gX0B5tr3LBSAT3i9QSjUsVpK2upA7fTUeeiDL3VMg=;
        b=fZst+mUz85AnWhLKocBcRr08/s+jZAQAo4KjoMCrn9Kx90LNXFm2A00HpPOSwcrtmk
         FA9hMmehW0SOE5ETpjkuSsiYVjCQyNTv63tCXoUdUoyU8UQvVjq/jttpv9n+rUSJ3ThC
         GZ20dISyVfUVfNwWBRfVs/f11BJaQKAx0SW3zQtk8M23RJRXoqUMgat6FtcRwqHDIGej
         CPHBRbmvFfW8n8fNI1sndDnwyIR8CiiNeOqXyfQP2sLKSctLxRpqENmXfvMSoOkB33DV
         06Ls0f+6KdtTJN8H+mYB+xvnNyKTPdwMvFstQKrK1AyAAVt4o1/XvIVfcb4B4CFDVF9t
         cc1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xOMyA1QY5zodq19LHaTVPk1DedPGLE8Jj7ZSOmlOq8b/QPsHP
	Wd5dAaf2dAYTUZ16nZPFWVQ=
X-Google-Smtp-Source: ABdhPJyJfn6XjWPVxlG2XfPgHocAO5HBpD6BPMzREb/pNL9+v85lzGDYTNHpP9PH+YZXJVxCURo+XQ==
X-Received: by 2002:a17:906:9258:: with SMTP id c24mr26717156ejx.473.1640891779665;
        Thu, 30 Dec 2021 11:16:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1ca6:: with SMTP id nb38ls6943596ejc.5.gmail; Thu,
 30 Dec 2021 11:16:18 -0800 (PST)
X-Received: by 2002:a17:907:9621:: with SMTP id gb33mr26076725ejc.394.1640891778861;
        Thu, 30 Dec 2021 11:16:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891778; cv=none;
        d=google.com; s=arc-20160816;
        b=WrPKuT2EQQFAURjAtc3xVmSWowd5Q1UUPB2WXhbHmvgASigIqxjy3AQm7wgdTMNjwL
         q7gFqgZw4hvdsTjqjBWYXw3yhdF7KRcCxnDIRKDwqhkNjrwKymqh1Bqyc6r/a+jlZLrM
         gATpzpIZRLMnrcOftR4G3C3Xp7eE9O+g+sUJxF7B66l4rsmIwIP0cy/4tr6ZaAHtYZ9q
         V2J/nvicqPJEys7cwdDeCzCWhfkBrHzyaORcwQgPVrClMEwvpLcaWXjwFpkEUv2cwUSE
         RYbzgIxsgihlYZzwrHvxJg2LGV0Jmclb8fLe2m/3Iu5OAs7MDqE1V35xSBzxLJBvDCkO
         rb2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mpbx3xQ9877agAPw9hxfd9/SjH16h8fCU/C+id44qD0=;
        b=JgDVi7nFuC7D230HRpjdwDzVrnODkU3Q3ugJPwc7lX25XVRG18Wf6GCUo69Q7fBSR3
         WiL8ACu1rtqtMKEmU+cOcPqs8TY0Oef7aKinCf9jJBMxyk8KXKz9iGGsF/q2V9KdhjYQ
         UUBeAShJmYD50Yw7GdFoQ+S/i34R3L6YBE7Op5hLtO2CJBmHFOYhEX4SKyNNJqJy9p0K
         GaZYD01Ok919LCldn2g547UIZQzLfTNUzXNjoABS0OFLRIbwtrc3dYXsOYnH/OjArzjU
         cLVlFoQfdIwuvPOj/pJtQuLxk8QyN6hzqAFl5tz15LFwt7jgL1nsVKUAdVjNIHL/rh2C
         DvmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h8DXvs8Y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id y11si760360eda.5.2021.12.30.11.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:16:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v5 31/39] kasan, vmalloc: only tag normal vmalloc allocations
Date: Thu, 30 Dec 2021 20:14:56 +0100
Message-Id: <220f632da9a7ea4014f13581b0ec7e66d323cb30.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h8DXvs8Y;       spf=pass
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
index 0f0c9a6a4b11..bfe171091bd7 100644
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
@@ -3070,7 +3070,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
-	kasan_vmalloc_flags_t kasan_flags;
+	kasan_vmalloc_flags_t kasan_flags = KASAN_VMALLOC_NONE;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3123,21 +3123,28 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3151,10 +3158,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3868,8 +3878,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/220f632da9a7ea4014f13581b0ec7e66d323cb30.1640891329.git.andreyknvl%40google.com.

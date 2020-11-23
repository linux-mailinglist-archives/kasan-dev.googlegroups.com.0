Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR5N6D6QKGQEXBNKW6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20F512C1540
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:40 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id c2sf6529451lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162119; cv=pass;
        d=google.com; s=arc-20160816;
        b=WA1UEmLBO8dChMRQUlC8JSR3Mkekt7YPA1sMAIlyOzjD/skMw7JaPwV3551tOLkO6l
         lMrAXMH7WYkXUzM3BrLNT4fZ7VZG98ZLG2APEdn4jrN82v0DF6rHfrEQEgVK2szBxzn4
         NV4QBy/SEDCAvoAlXVHi8EdhxSJeNjvFkknX1jyOtzoJ2hHQyH4/AwciWUdxQvK3LCYo
         ELJfj86Q2oiSH/S5Mt/vTQxVy1Mlbb4gYGfRecD72GnQFjEZ20gggcn57Mx6gt2ZAVli
         kO1tm/WwI3mzxo3ay+KIglkv6wNrab3kHC2ktmEi4uQDO/kudCedUl8C4M+m8MSiAwSc
         YLxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=I662AfQaiXT5rgI79BOxliLibly7Tf70mas9mztGd88=;
        b=kLyrJCstxfPKNepplSKsLmtHmkQldO7L7wq5fFcVn/kh3TFEEC1GZ5obTf8vXVob+e
         onOAb+Vz1pRw+4SItrXSJTBwA71zniqcEF9jFSTRG2HamvL9Nx8sisZx3XbYYIOdvjI5
         YBGvkjq3lQ6w0q11Asvt+Z0uUbFi/3UCu7s6Lqhlfc0kRFbsvh+GJqI2F/Qm0sUR5eoE
         KUuLVICSxIgJ31CoKt9SzT0ZdMrUVkmh8ODkNgGl0bKZ13mEUc7Cn3gkMrh7hUolRBji
         A+T3k8jvREo1rxjmV39biZmpC2MkdQw7LtjlK/mfev0qIQk/HzyHkBPGlCOSI5vSuUFt
         fjfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NJSLg8q2;
       spf=pass (google.com: domain of 3xha8xwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xha8XwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I662AfQaiXT5rgI79BOxliLibly7Tf70mas9mztGd88=;
        b=gR7i1cDJjBAc0uTZ9Vm49gAL7Myjs62XR1YSsnTJ6u3riqB/wYQz7IVng5nIx0Atql
         Oj8NY64cQPychjjxFzHybOBsSkK35ox1SXUPz87blnymKiPgyHMImAVw3fUGNuwjbSIs
         Y+cyQypFRhM69lI6ZI2Wvhu4ct0o/xNPj2zsasQ7DF5pT2Tq6/mPNSDnft74hIsQ0VRg
         wpkWEh676MB1wtX2BISStQsH5qyFprm0G2ojjcvy2DEwxq5zgKzh3CmaWrV/fDqmo6pq
         sB2g6bMokqbPdKwuzdDxTJ/2htbWVMrZxOrSJFjs1vwlKDLN4BzfeDYdYvlMee2xsOHt
         ejSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I662AfQaiXT5rgI79BOxliLibly7Tf70mas9mztGd88=;
        b=P5RkLltxbUlcyW43x3KA3TCFERfl4hVBkQpPcFoDaWezDr6tRfAw7jgoeXAFDTenHB
         B1IkyeiZjdV1WMDtWPxg958/TASii+n6rPUO0rdP24OntOfcsgGGCzq1x3jwRkmbnKL6
         GXK+UGW5hRM8Q2AccZ8tzoqV3VYzd1aoIIOqEp3miyf1XJkQ07LQfSfXg3c7ErfpdCSw
         mOkE8+R93m9mmatlOvpdy1j76Klo6FWyGY5kKspfB+YPEcGObOSsXuNXH8PWIjYPW17F
         39GleiXKMm4nJd5P0iTAxE5/EkKV6OSSZkQRgZSUf2+LaZeIK1yI3ecsgzNBOfkcFzpR
         13VA==
X-Gm-Message-State: AOAM530u7Gi5x6mytpr0RZd3lzJlNGBRdYr8FFol+/tSRqICa14tJQVa
	Q5R0UxloNE1Ri/xLqokR8Zk=
X-Google-Smtp-Source: ABdhPJwdjYWQuWE7pzWRf2uW0h2y6Vx8oYwX8KElm8F2WVvnlKlga9WhQfJUDXuzDQiz8SzGA1y53w==
X-Received: by 2002:a19:857:: with SMTP id 84mr303196lfi.235.1606162119585;
        Mon, 23 Nov 2020 12:08:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:914c:: with SMTP id q12ls2349093ljg.8.gmail; Mon, 23 Nov
 2020 12:08:38 -0800 (PST)
X-Received: by 2002:a2e:8788:: with SMTP id n8mr426070lji.35.1606162118515;
        Mon, 23 Nov 2020 12:08:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162118; cv=none;
        d=google.com; s=arc-20160816;
        b=jMMtsnh8vJy9Huusgayfrps/B1kXoE8/A6JkSMM2R9tJU6bY5MgJHzuYJIEjs6wjby
         7EeqfgU8yCViG8YEAvU6XNNGEkd/LLqZZNqnPsgNbPcr2Zvp2DedA9RjJGIr1D9AABOK
         WQkjPmG94coNsvjkwJzF1huAFsQGLoT2sQiroN6GhV0xzQlBps5J1ihUPKwJqWSQnXOl
         3kCRRscOLk/VyP3Jhb2uTgFIv/jBAkA4jRR1Ggh2PiyHTW27dFvhXIabnJncJswEJ3gj
         c3hi8uiQ6YgjCAZ3K4r9hMLuZH/JmNbPsLHxIKC3xJa9FTiJsrWYIFndch/9FHRVCXaA
         jRGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ziObOfvesqOzcCO46O3EewI6eBWHYo+xrV4aifZDsEg=;
        b=LGdMJgtkvV8e8wijSKRFrpnUXuLp2ske6VOdgJPo76SATeXVC2YCVEVO/f5J2KJje9
         sQZQeaUNlEmEOwJaH680WAA/2g+jDrqkyiGhcbXVp+hPKf2JsDpsEYhNCWkcmQkG82Mz
         cO1KenL1vHUmv/ieIQGGrwuU62+ehsez+t9War1zR/ld7xBflad4vrzEHXqOPjhwmAn8
         hgCgmBDd4X+F7N+lTNge8D4UISdL1y52hKEWPPXqiqN8VSI/O8nz5iZMN3QpnSmTLyPs
         Ep4IxjyZka8EAWyZYyB/H0DUm5CQ/RBB6Zlca4Zl7/3nFA9QWoOZOxuJO1NV3N04maYE
         FfZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NJSLg8q2;
       spf=pass (google.com: domain of 3xha8xwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xha8XwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v2si10415ljd.5.2020.11.23.12.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xha8xwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e6so2288440wrx.13
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a986:: with SMTP id
 s128mr601182wme.94.1606162118048; Mon, 23 Nov 2020 12:08:38 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:32 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <17d95cfa7d5cf9c4fcd9bf415f2a8dea911668df.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 08/42] kasan: split out shadow.c from common.c
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NJSLg8q2;       spf=pass
 (google.com: domain of 3xha8xwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xha8XwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory. Move all shadow-related code
to shadow.c, which is only enabled for software KASAN modes that use
shadow memory.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Ic1c32ce72d4649848e9e6a1f2c8dd269c77673f2
---
 mm/kasan/Makefile |   6 +-
 mm/kasan/common.c | 498 +-------------------------------------------
 mm/kasan/shadow.c | 518 ++++++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 523 insertions(+), 499 deletions(-)
 create mode 100644 mm/kasan/shadow.c

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7cf685bb51bd..7cc1031e1ef8 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -10,6 +10,7 @@ CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
@@ -26,9 +27,10 @@ CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 80dd71e88ef8..b3ebee6fcfca 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains common generic and tag-based KASAN code.
+ * This file contains common KASAN code.
  *
  * Copyright (c) 2014 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
@@ -14,7 +14,6 @@
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/kfence.h>
-#include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
 #include <linux/memory.h>
@@ -27,12 +26,8 @@
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <linux/types.h>
-#include <linux/vmalloc.h>
 #include <linux/bug.h>
 
-#include <asm/cacheflush.h>
-#include <asm/tlbflush.h>
-
 #include "kasan.h"
 #include "../slab.h"
 
@@ -62,105 +57,6 @@ void kasan_disable_current(void)
 	current->kasan_depth--;
 }
 
-bool __kasan_check_read(const volatile void *p, unsigned int size)
-{
-	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
-}
-EXPORT_SYMBOL(__kasan_check_read);
-
-bool __kasan_check_write(const volatile void *p, unsigned int size)
-{
-	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
-}
-EXPORT_SYMBOL(__kasan_check_write);
-
-#undef memset
-void *memset(void *addr, int c, size_t len)
-{
-	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
-		return NULL;
-
-	return __memset(addr, c, len);
-}
-
-#ifdef __HAVE_ARCH_MEMMOVE
-#undef memmove
-void *memmove(void *dest, const void *src, size_t len)
-{
-	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
-	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
-		return NULL;
-
-	return __memmove(dest, src, len);
-}
-#endif
-
-#undef memcpy
-void *memcpy(void *dest, const void *src, size_t len)
-{
-	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
-	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
-		return NULL;
-
-	return __memcpy(dest, src, len);
-}
-
-/*
- * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
- */
-void poison_range(const void *address, size_t size, u8 value)
-{
-	void *shadow_start, *shadow_end;
-
-	/*
-	 * Perform shadow offset calculation based on untagged address, as
-	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
-	 * addresses to this function.
-	 */
-	address = reset_tag(address);
-
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
-		return;
-
-	shadow_start = kasan_mem_to_shadow(address);
-	shadow_end = kasan_mem_to_shadow(address + size);
-
-	__memset(shadow_start, value, shadow_end - shadow_start);
-}
-
-void unpoison_range(const void *address, size_t size)
-{
-	u8 tag = get_tag(address);
-
-	/*
-	 * Perform shadow offset calculation based on untagged address, as
-	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
-	 * addresses to this function.
-	 */
-	address = reset_tag(address);
-
-	/*
-	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
-	 * that calls to ksize(), where size is not a multiple of machine-word
-	 * size, would otherwise poison the invalid portion of the word.
-	 */
-	if (is_kfence_address(address))
-		return;
-
-	poison_range(address, size, tag);
-
-	if (size & KASAN_GRANULE_MASK) {
-		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
-
-		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-			*shadow = tag;
-		else
-			*shadow = size & KASAN_GRANULE_MASK;
-	}
-}
-
 void kasan_unpoison_range(const void *address, size_t size)
 {
 	unpoison_range(address, size);
@@ -559,395 +455,3 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
 		kasan_report_invalid_free(ptr, ip);
 	/* The object will be poisoned by page_alloc. */
 }
-
-#ifdef CONFIG_MEMORY_HOTPLUG
-static bool shadow_mapped(unsigned long addr)
-{
-	pgd_t *pgd = pgd_offset_k(addr);
-	p4d_t *p4d;
-	pud_t *pud;
-	pmd_t *pmd;
-	pte_t *pte;
-
-	if (pgd_none(*pgd))
-		return false;
-	p4d = p4d_offset(pgd, addr);
-	if (p4d_none(*p4d))
-		return false;
-	pud = pud_offset(p4d, addr);
-	if (pud_none(*pud))
-		return false;
-
-	/*
-	 * We can't use pud_large() or pud_huge(), the first one is
-	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
-	 * pud_bad(), if pud is bad then it's bad because it's huge.
-	 */
-	if (pud_bad(*pud))
-		return true;
-	pmd = pmd_offset(pud, addr);
-	if (pmd_none(*pmd))
-		return false;
-
-	if (pmd_bad(*pmd))
-		return true;
-	pte = pte_offset_kernel(pmd, addr);
-	return !pte_none(*pte);
-}
-
-static int __meminit kasan_mem_notifier(struct notifier_block *nb,
-			unsigned long action, void *data)
-{
-	struct memory_notify *mem_data = data;
-	unsigned long nr_shadow_pages, start_kaddr, shadow_start;
-	unsigned long shadow_end, shadow_size;
-
-	nr_shadow_pages = mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIFT;
-	start_kaddr = (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
-	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)start_kaddr);
-	shadow_size = nr_shadow_pages << PAGE_SHIFT;
-	shadow_end = shadow_start + shadow_size;
-
-	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
-		return NOTIFY_BAD;
-
-	switch (action) {
-	case MEM_GOING_ONLINE: {
-		void *ret;
-
-		/*
-		 * If shadow is mapped already than it must have been mapped
-		 * during the boot. This could happen if we onlining previously
-		 * offlined memory.
-		 */
-		if (shadow_mapped(shadow_start))
-			return NOTIFY_OK;
-
-		ret = __vmalloc_node_range(shadow_size, PAGE_SIZE, shadow_start,
-					shadow_end, GFP_KERNEL,
-					PAGE_KERNEL, VM_NO_GUARD,
-					pfn_to_nid(mem_data->start_pfn),
-					__builtin_return_address(0));
-		if (!ret)
-			return NOTIFY_BAD;
-
-		kmemleak_ignore(ret);
-		return NOTIFY_OK;
-	}
-	case MEM_CANCEL_ONLINE:
-	case MEM_OFFLINE: {
-		struct vm_struct *vm;
-
-		/*
-		 * shadow_start was either mapped during boot by kasan_init()
-		 * or during memory online by __vmalloc_node_range().
-		 * In the latter case we can use vfree() to free shadow.
-		 * Non-NULL result of the find_vm_area() will tell us if
-		 * that was the second case.
-		 *
-		 * Currently it's not possible to free shadow mapped
-		 * during boot by kasan_init(). It's because the code
-		 * to do that hasn't been written yet. So we'll just
-		 * leak the memory.
-		 */
-		vm = find_vm_area((void *)shadow_start);
-		if (vm)
-			vfree((void *)shadow_start);
-	}
-	}
-
-	return NOTIFY_OK;
-}
-
-static int __init kasan_memhotplug_init(void)
-{
-	hotplug_memory_notifier(kasan_mem_notifier, 0);
-
-	return 0;
-}
-
-core_initcall(kasan_memhotplug_init);
-#endif
-
-#ifdef CONFIG_KASAN_VMALLOC
-
-static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-				      void *unused)
-{
-	unsigned long page;
-	pte_t pte;
-
-	if (likely(!pte_none(*ptep)))
-		return 0;
-
-	page = __get_free_page(GFP_KERNEL);
-	if (!page)
-		return -ENOMEM;
-
-	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
-	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
-
-	spin_lock(&init_mm.page_table_lock);
-	if (likely(pte_none(*ptep))) {
-		set_pte_at(&init_mm, addr, ptep, pte);
-		page = 0;
-	}
-	spin_unlock(&init_mm.page_table_lock);
-	if (page)
-		free_page(page);
-	return 0;
-}
-
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
-{
-	unsigned long shadow_start, shadow_end;
-	int ret;
-
-	if (!is_vmalloc_or_module_addr((void *)addr))
-		return 0;
-
-	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
-	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
-	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
-	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
-
-	ret = apply_to_page_range(&init_mm, shadow_start,
-				  shadow_end - shadow_start,
-				  kasan_populate_vmalloc_pte, NULL);
-	if (ret)
-		return ret;
-
-	flush_cache_vmap(shadow_start, shadow_end);
-
-	/*
-	 * We need to be careful about inter-cpu effects here. Consider:
-	 *
-	 *   CPU#0				  CPU#1
-	 * WRITE_ONCE(p, vmalloc(100));		while (x = READ_ONCE(p)) ;
-	 *					p[99] = 1;
-	 *
-	 * With compiler instrumentation, that ends up looking like this:
-	 *
-	 *   CPU#0				  CPU#1
-	 * // vmalloc() allocates memory
-	 * // let a = area->addr
-	 * // we reach kasan_populate_vmalloc
-	 * // and call unpoison_range:
-	 * STORE shadow(a), unpoison_val
-	 * ...
-	 * STORE shadow(a+99), unpoison_val	x = LOAD p
-	 * // rest of vmalloc process		<data dependency>
-	 * STORE p, a				LOAD shadow(x+99)
-	 *
-	 * If there is no barrier between the end of unpoisioning the shadow
-	 * and the store of the result to p, the stores could be committed
-	 * in a different order by CPU#0, and CPU#1 could erroneously observe
-	 * poison in the shadow.
-	 *
-	 * We need some sort of barrier between the stores.
-	 *
-	 * In the vmalloc() case, this is provided by a smp_wmb() in
-	 * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
-	 * get_vm_area() and friends, the caller gets shadow allocated but
-	 * doesn't have any pages mapped into the virtual address space that
-	 * has been reserved. Mapping those pages in will involve taking and
-	 * releasing a page-table lock, which will provide the barrier.
-	 */
-
-	return 0;
-}
-
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	poison_range(start, size, KASAN_VMALLOC_INVALID);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	unpoison_range(start, size);
-}
-
-static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-					void *unused)
-{
-	unsigned long page;
-
-	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
-
-	spin_lock(&init_mm.page_table_lock);
-
-	if (likely(!pte_none(*ptep))) {
-		pte_clear(&init_mm, addr, ptep);
-		free_page(page);
-	}
-	spin_unlock(&init_mm.page_table_lock);
-
-	return 0;
-}
-
-/*
- * Release the backing for the vmalloc region [start, end), which
- * lies within the free region [free_region_start, free_region_end).
- *
- * This can be run lazily, long after the region was freed. It runs
- * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
- * infrastructure.
- *
- * How does this work?
- * -------------------
- *
- * We have a region that is page aligned, labelled as A.
- * That might not map onto the shadow in a way that is page-aligned:
- *
- *                    start                     end
- *                    v                         v
- * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
- *  -------- -------- --------          -------- --------
- *      |        |       |                 |        |
- *      |        |       |         /-------/        |
- *      \-------\|/------/         |/---------------/
- *              |||                ||
- *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
- *                 (1)      (2)      (3)
- *
- * First we align the start upwards and the end downwards, so that the
- * shadow of the region aligns with shadow page boundaries. In the
- * example, this gives us the shadow page (2). This is the shadow entirely
- * covered by this allocation.
- *
- * Then we have the tricky bits. We want to know if we can free the
- * partially covered shadow pages - (1) and (3) in the example. For this,
- * we are given the start and end of the free region that contains this
- * allocation. Extending our previous example, we could have:
- *
- *  free_region_start                                    free_region_end
- *  |                 start                     end      |
- *  v                 v                         v        v
- * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
- *  -------- -------- --------          -------- --------
- *      |        |       |                 |        |
- *      |        |       |         /-------/        |
- *      \-------\|/------/         |/---------------/
- *              |||                ||
- *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
- *                 (1)      (2)      (3)
- *
- * Once again, we align the start of the free region up, and the end of
- * the free region down so that the shadow is page aligned. So we can free
- * page (1) - we know no allocation currently uses anything in that page,
- * because all of it is in the vmalloc free region. But we cannot free
- * page (3), because we can't be sure that the rest of it is unused.
- *
- * We only consider pages that contain part of the original region for
- * freeing: we don't try to free other pages from the free region or we'd
- * end up trying to free huge chunks of virtual address space.
- *
- * Concurrency
- * -----------
- *
- * How do we know that we're not freeing a page that is simultaneously
- * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
- *
- * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc running
- * at the same time. While we run under free_vmap_area_lock, the population
- * code does not.
- *
- * free_vmap_area_lock instead operates to ensure that the larger range
- * [free_region_start, free_region_end) is safe: because __alloc_vmap_area and
- * the per-cpu region-finding algorithm both run under free_vmap_area_lock,
- * no space identified as free will become used while we are running. This
- * means that so long as we are careful with alignment and only free shadow
- * pages entirely covered by the free region, we will not run in to any
- * trouble - any simultaneous allocations will be for disjoint regions.
- */
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
-			   unsigned long free_region_start,
-			   unsigned long free_region_end)
-{
-	void *shadow_start, *shadow_end;
-	unsigned long region_start, region_end;
-	unsigned long size;
-
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
-
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
-
-	if (start != region_start &&
-	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
-
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
-
-	if (end != region_end &&
-	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
-
-	shadow_start = kasan_mem_to_shadow((void *)region_start);
-	shadow_end = kasan_mem_to_shadow((void *)region_end);
-
-	if (shadow_end > shadow_start) {
-		size = shadow_end - shadow_start;
-		apply_to_existing_page_range(&init_mm,
-					     (unsigned long)shadow_start,
-					     size, kasan_depopulate_vmalloc_pte,
-					     NULL);
-		flush_tlb_kernel_range((unsigned long)shadow_start,
-				       (unsigned long)shadow_end);
-	}
-}
-
-#else /* CONFIG_KASAN_VMALLOC */
-
-int kasan_module_alloc(void *addr, size_t size)
-{
-	void *ret;
-	size_t scaled_size;
-	size_t shadow_size;
-	unsigned long shadow_start;
-
-	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
-				KASAN_SHADOW_SCALE_SHIFT;
-	shadow_size = round_up(scaled_size, PAGE_SIZE);
-
-	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
-		return -EINVAL;
-
-	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
-			shadow_start + shadow_size,
-			GFP_KERNEL,
-			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
-			__builtin_return_address(0));
-
-	if (ret) {
-		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
-		find_vm_area(addr)->flags |= VM_KASAN;
-		kmemleak_ignore(ret);
-		return 0;
-	}
-
-	return -ENOMEM;
-}
-
-void kasan_free_shadow(const struct vm_struct *vm)
-{
-	if (vm->flags & VM_KASAN)
-		vfree(kasan_mem_to_shadow(vm->addr));
-}
-
-#endif
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
new file mode 100644
index 000000000000..4264bfbdca1a
--- /dev/null
+++ b/mm/kasan/shadow.c
@@ -0,0 +1,518 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains KASAN runtime code that manages shadow memory for
+ * generic and software tag-based KASAN modes.
+ *
+ * Copyright (c) 2014 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ *
+ * Some code borrowed from https://github.com/xairy/kasan-prototype by
+ *        Andrey Konovalov <andreyknvl@gmail.com>
+ */
+
+#include <linux/init.h>
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/kfence.h>
+#include <linux/kmemleak.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/string.h>
+#include <linux/types.h>
+#include <linux/vmalloc.h>
+
+#include <asm/cacheflush.h>
+#include <asm/tlbflush.h>
+
+#include "kasan.h"
+
+bool __kasan_check_read(const volatile void *p, unsigned int size)
+{
+	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
+}
+EXPORT_SYMBOL(__kasan_check_read);
+
+bool __kasan_check_write(const volatile void *p, unsigned int size)
+{
+	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
+}
+EXPORT_SYMBOL(__kasan_check_write);
+
+#undef memset
+void *memset(void *addr, int c, size_t len)
+{
+	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
+
+	return __memset(addr, c, len);
+}
+
+#ifdef __HAVE_ARCH_MEMMOVE
+#undef memmove
+void *memmove(void *dest, const void *src, size_t len)
+{
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memmove(dest, src, len);
+}
+#endif
+
+#undef memcpy
+void *memcpy(void *dest, const void *src, size_t len)
+{
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memcpy(dest, src, len);
+}
+
+/*
+ * Poisons the shadow memory for 'size' bytes starting from 'addr'.
+ * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
+ */
+void poison_range(const void *address, size_t size, u8 value)
+{
+	void *shadow_start, *shadow_end;
+
+	/*
+	 * Perform shadow offset calculation based on untagged address, as
+	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
+	 * addresses to this function.
+	 */
+	address = reset_tag(address);
+
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	shadow_start = kasan_mem_to_shadow(address);
+	shadow_end = kasan_mem_to_shadow(address + size);
+
+	__memset(shadow_start, value, shadow_end - shadow_start);
+}
+
+void unpoison_range(const void *address, size_t size)
+{
+	u8 tag = get_tag(address);
+
+	/*
+	 * Perform shadow offset calculation based on untagged address, as
+	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
+	 * addresses to this function.
+	 */
+	address = reset_tag(address);
+
+	/*
+	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
+	 * that calls to ksize(), where size is not a multiple of machine-word
+	 * size, would otherwise poison the invalid portion of the word.
+	 */
+	if (is_kfence_address(address))
+		return;
+
+	poison_range(address, size, tag);
+
+	if (size & KASAN_GRANULE_MASK) {
+		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
+
+		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+			*shadow = tag;
+		else
+			*shadow = size & KASAN_GRANULE_MASK;
+	}
+}
+
+#ifdef CONFIG_MEMORY_HOTPLUG
+static bool shadow_mapped(unsigned long addr)
+{
+	pgd_t *pgd = pgd_offset_k(addr);
+	p4d_t *p4d;
+	pud_t *pud;
+	pmd_t *pmd;
+	pte_t *pte;
+
+	if (pgd_none(*pgd))
+		return false;
+	p4d = p4d_offset(pgd, addr);
+	if (p4d_none(*p4d))
+		return false;
+	pud = pud_offset(p4d, addr);
+	if (pud_none(*pud))
+		return false;
+
+	/*
+	 * We can't use pud_large() or pud_huge(), the first one is
+	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
+	 * pud_bad(), if pud is bad then it's bad because it's huge.
+	 */
+	if (pud_bad(*pud))
+		return true;
+	pmd = pmd_offset(pud, addr);
+	if (pmd_none(*pmd))
+		return false;
+
+	if (pmd_bad(*pmd))
+		return true;
+	pte = pte_offset_kernel(pmd, addr);
+	return !pte_none(*pte);
+}
+
+static int __meminit kasan_mem_notifier(struct notifier_block *nb,
+			unsigned long action, void *data)
+{
+	struct memory_notify *mem_data = data;
+	unsigned long nr_shadow_pages, start_kaddr, shadow_start;
+	unsigned long shadow_end, shadow_size;
+
+	nr_shadow_pages = mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIFT;
+	start_kaddr = (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
+	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)start_kaddr);
+	shadow_size = nr_shadow_pages << PAGE_SHIFT;
+	shadow_end = shadow_start + shadow_size;
+
+	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
+		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		return NOTIFY_BAD;
+
+	switch (action) {
+	case MEM_GOING_ONLINE: {
+		void *ret;
+
+		/*
+		 * If shadow is mapped already than it must have been mapped
+		 * during the boot. This could happen if we onlining previously
+		 * offlined memory.
+		 */
+		if (shadow_mapped(shadow_start))
+			return NOTIFY_OK;
+
+		ret = __vmalloc_node_range(shadow_size, PAGE_SIZE, shadow_start,
+					shadow_end, GFP_KERNEL,
+					PAGE_KERNEL, VM_NO_GUARD,
+					pfn_to_nid(mem_data->start_pfn),
+					__builtin_return_address(0));
+		if (!ret)
+			return NOTIFY_BAD;
+
+		kmemleak_ignore(ret);
+		return NOTIFY_OK;
+	}
+	case MEM_CANCEL_ONLINE:
+	case MEM_OFFLINE: {
+		struct vm_struct *vm;
+
+		/*
+		 * shadow_start was either mapped during boot by kasan_init()
+		 * or during memory online by __vmalloc_node_range().
+		 * In the latter case we can use vfree() to free shadow.
+		 * Non-NULL result of the find_vm_area() will tell us if
+		 * that was the second case.
+		 *
+		 * Currently it's not possible to free shadow mapped
+		 * during boot by kasan_init(). It's because the code
+		 * to do that hasn't been written yet. So we'll just
+		 * leak the memory.
+		 */
+		vm = find_vm_area((void *)shadow_start);
+		if (vm)
+			vfree((void *)shadow_start);
+	}
+	}
+
+	return NOTIFY_OK;
+}
+
+static int __init kasan_memhotplug_init(void)
+{
+	hotplug_memory_notifier(kasan_mem_notifier, 0);
+
+	return 0;
+}
+
+core_initcall(kasan_memhotplug_init);
+#endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+
+static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
+				      void *unused)
+{
+	unsigned long page;
+	pte_t pte;
+
+	if (likely(!pte_none(*ptep)))
+		return 0;
+
+	page = __get_free_page(GFP_KERNEL);
+	if (!page)
+		return -ENOMEM;
+
+	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+
+	spin_lock(&init_mm.page_table_lock);
+	if (likely(pte_none(*ptep))) {
+		set_pte_at(&init_mm, addr, ptep, pte);
+		page = 0;
+	}
+	spin_unlock(&init_mm.page_table_lock);
+	if (page)
+		free_page(page);
+	return 0;
+}
+
+int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
+{
+	unsigned long shadow_start, shadow_end;
+	int ret;
+
+	if (!is_vmalloc_or_module_addr((void *)addr))
+		return 0;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
+	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
+	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
+
+	ret = apply_to_page_range(&init_mm, shadow_start,
+				  shadow_end - shadow_start,
+				  kasan_populate_vmalloc_pte, NULL);
+	if (ret)
+		return ret;
+
+	flush_cache_vmap(shadow_start, shadow_end);
+
+	/*
+	 * We need to be careful about inter-cpu effects here. Consider:
+	 *
+	 *   CPU#0				  CPU#1
+	 * WRITE_ONCE(p, vmalloc(100));		while (x = READ_ONCE(p)) ;
+	 *					p[99] = 1;
+	 *
+	 * With compiler instrumentation, that ends up looking like this:
+	 *
+	 *   CPU#0				  CPU#1
+	 * // vmalloc() allocates memory
+	 * // let a = area->addr
+	 * // we reach kasan_populate_vmalloc
+	 * // and call unpoison_range:
+	 * STORE shadow(a), unpoison_val
+	 * ...
+	 * STORE shadow(a+99), unpoison_val	x = LOAD p
+	 * // rest of vmalloc process		<data dependency>
+	 * STORE p, a				LOAD shadow(x+99)
+	 *
+	 * If there is no barrier between the end of unpoisioning the shadow
+	 * and the store of the result to p, the stores could be committed
+	 * in a different order by CPU#0, and CPU#1 could erroneously observe
+	 * poison in the shadow.
+	 *
+	 * We need some sort of barrier between the stores.
+	 *
+	 * In the vmalloc() case, this is provided by a smp_wmb() in
+	 * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
+	 * get_vm_area() and friends, the caller gets shadow allocated but
+	 * doesn't have any pages mapped into the virtual address space that
+	 * has been reserved. Mapping those pages in will involve taking and
+	 * releasing a page-table lock, which will provide the barrier.
+	 */
+
+	return 0;
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	poison_range(start, size, KASAN_VMALLOC_INVALID);
+}
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	unpoison_range(start, size);
+}
+
+static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
+					void *unused)
+{
+	unsigned long page;
+
+	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
+
+	spin_lock(&init_mm.page_table_lock);
+
+	if (likely(!pte_none(*ptep))) {
+		pte_clear(&init_mm, addr, ptep);
+		free_page(page);
+	}
+	spin_unlock(&init_mm.page_table_lock);
+
+	return 0;
+}
+
+/*
+ * Release the backing for the vmalloc region [start, end), which
+ * lies within the free region [free_region_start, free_region_end).
+ *
+ * This can be run lazily, long after the region was freed. It runs
+ * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
+ * infrastructure.
+ *
+ * How does this work?
+ * -------------------
+ *
+ * We have a region that is page aligned, labelled as A.
+ * That might not map onto the shadow in a way that is page-aligned:
+ *
+ *                    start                     end
+ *                    v                         v
+ * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
+ *  -------- -------- --------          -------- --------
+ *      |        |       |                 |        |
+ *      |        |       |         /-------/        |
+ *      \-------\|/------/         |/---------------/
+ *              |||                ||
+ *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
+ *                 (1)      (2)      (3)
+ *
+ * First we align the start upwards and the end downwards, so that the
+ * shadow of the region aligns with shadow page boundaries. In the
+ * example, this gives us the shadow page (2). This is the shadow entirely
+ * covered by this allocation.
+ *
+ * Then we have the tricky bits. We want to know if we can free the
+ * partially covered shadow pages - (1) and (3) in the example. For this,
+ * we are given the start and end of the free region that contains this
+ * allocation. Extending our previous example, we could have:
+ *
+ *  free_region_start                                    free_region_end
+ *  |                 start                     end      |
+ *  v                 v                         v        v
+ * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
+ *  -------- -------- --------          -------- --------
+ *      |        |       |                 |        |
+ *      |        |       |         /-------/        |
+ *      \-------\|/------/         |/---------------/
+ *              |||                ||
+ *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
+ *                 (1)      (2)      (3)
+ *
+ * Once again, we align the start of the free region up, and the end of
+ * the free region down so that the shadow is page aligned. So we can free
+ * page (1) - we know no allocation currently uses anything in that page,
+ * because all of it is in the vmalloc free region. But we cannot free
+ * page (3), because we can't be sure that the rest of it is unused.
+ *
+ * We only consider pages that contain part of the original region for
+ * freeing: we don't try to free other pages from the free region or we'd
+ * end up trying to free huge chunks of virtual address space.
+ *
+ * Concurrency
+ * -----------
+ *
+ * How do we know that we're not freeing a page that is simultaneously
+ * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
+ *
+ * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc running
+ * at the same time. While we run under free_vmap_area_lock, the population
+ * code does not.
+ *
+ * free_vmap_area_lock instead operates to ensure that the larger range
+ * [free_region_start, free_region_end) is safe: because __alloc_vmap_area and
+ * the per-cpu region-finding algorithm both run under free_vmap_area_lock,
+ * no space identified as free will become used while we are running. This
+ * means that so long as we are careful with alignment and only free shadow
+ * pages entirely covered by the free region, we will not run in to any
+ * trouble - any simultaneous allocations will be for disjoint regions.
+ */
+void kasan_release_vmalloc(unsigned long start, unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end)
+{
+	void *shadow_start, *shadow_end;
+	unsigned long region_start, region_end;
+	unsigned long size;
+
+	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+
+	free_region_start = ALIGN(free_region_start,
+				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+
+	if (start != region_start &&
+	    free_region_start < region_start)
+		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+
+	free_region_end = ALIGN_DOWN(free_region_end,
+				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+
+	if (end != region_end &&
+	    free_region_end > region_end)
+		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+
+	shadow_start = kasan_mem_to_shadow((void *)region_start);
+	shadow_end = kasan_mem_to_shadow((void *)region_end);
+
+	if (shadow_end > shadow_start) {
+		size = shadow_end - shadow_start;
+		apply_to_existing_page_range(&init_mm,
+					     (unsigned long)shadow_start,
+					     size, kasan_depopulate_vmalloc_pte,
+					     NULL);
+		flush_tlb_kernel_range((unsigned long)shadow_start,
+				       (unsigned long)shadow_end);
+	}
+}
+
+#else /* CONFIG_KASAN_VMALLOC */
+
+int kasan_module_alloc(void *addr, size_t size)
+{
+	void *ret;
+	size_t scaled_size;
+	size_t shadow_size;
+	unsigned long shadow_start;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
+	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
+				KASAN_SHADOW_SCALE_SHIFT;
+	shadow_size = round_up(scaled_size, PAGE_SIZE);
+
+	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
+		return -EINVAL;
+
+	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
+			shadow_start + shadow_size,
+			GFP_KERNEL,
+			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
+			__builtin_return_address(0));
+
+	if (ret) {
+		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
+		find_vm_area(addr)->flags |= VM_KASAN;
+		kmemleak_ignore(ret);
+		return 0;
+	}
+
+	return -ENOMEM;
+}
+
+void kasan_free_shadow(const struct vm_struct *vm)
+{
+	if (vm->flags & VM_KASAN)
+		vfree(kasan_mem_to_shadow(vm->addr));
+}
+
+#endif
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17d95cfa7d5cf9c4fcd9bf415f2a8dea911668df.1606161801.git.andreyknvl%40google.com.

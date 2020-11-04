Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAHORT6QKGQEHWJKBXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id F39642A711C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:29 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id d202sf282597iof.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531969; cv=pass;
        d=google.com; s=arc-20160816;
        b=N/B1xUwS78MvU6Ta9vWK2Pl/9L9v8ULClXv4pCOShR1KOLT2Frx9DAjkH5IaWSPY+z
         /uLqEjnSlr4GnpOOoTpmUJGBO4SL+87IKAEWTRKg/oS3tH6GrWWe9RAkF4L8qcp76PbT
         u9YYfJTCaK+d9vtS0f/rbADsNxi4RM6/0h+/x1z5HqWJl2gg0dSbvM/MWM7hbNf20NPj
         dgoxWkGI1zLuBy344XqCHy6uuimFLhAZHxPytBYuqiibIKItaZacI4TfXn7qMDJm81gg
         bgJZP5d65EY4V2RpibRU68dbY2PYczvtmgiotueEXXrFS56qfy9djxjgUAadJNs5I+rT
         qpBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=g0MMe2m+jtviy51H3tVcLXSjcGYWKDhr9I1BP8dWSGE=;
        b=XeF+iAGC4ucH9ldQYEeK7NjtLSMgY5CdsC1+JW1ffcHKnop4LMKxd1CdQYk2K2iSSd
         UYQBKzMT4sJBYMtgpk3XdatIdvZdBvl4Fr4lcFxgUP7ewI7MR4XKVord3oXlK9vtFplQ
         0yBeovs7nyV8a7vbf7Ag5pGqDBEjCUroU2hNyGGW8Db9bJil9L0KNKpAXNtEoMFlWf+A
         vyFWsOqWZnOoKUixDrJ7JB0V6t17Gdw6Bz6XBD7vCTVjqWJUg0tFZ2TZP3rUXHZ37STc
         vq4hskVd/s0cCmN1tk8TKE+2zquHkMLgq2vLuTOKtZ8yo2MjnVsBGTSPjaGsWs7xg2lq
         yCVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dH+BMPhe;
       spf=pass (google.com: domain of 3_zajxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_zajXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g0MMe2m+jtviy51H3tVcLXSjcGYWKDhr9I1BP8dWSGE=;
        b=IAgc62uBEry1MZ8V1Fo6QoYvWsVXAxNu68V63TfEtxZadfQFobu6C9+AIF1qGKvOTi
         aHHUoGcM7m58hYWt8o/pBrtXlAuKXF8JuWaR0fubE9woYvh4MfhO/Rfnk0ehfFmysFXF
         HwNFnZP2+EK0JjM5syv7B1yuGsMjFvYZOSPb4aGAqrOYyoPqls7WPqmufr/OyoLVNl48
         SazemUqDy8b/AWXi2BzpLK6YS3Shco0SMw0I/O7ng1COs/Ed/KzfmPhQl8EE02jP8m8s
         qmoAZedAt0iharSlfsovTNhv81cLE46AWcAqJ9Lda04mFSXbPKawDBTdjPEqh+bo+uZj
         YvBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g0MMe2m+jtviy51H3tVcLXSjcGYWKDhr9I1BP8dWSGE=;
        b=mMAa9S/8wo0B1mzlKQw/1cvNcHTB3xMNWglTWYd/QFn97Swjwy3BmwXRhUjNoUkhmT
         sLoaEWb2sLvVJWQ2rr0dd5nZwi8hI9OAY1vkG1vuSDTzb6qtDLoe4BZogpcGPtdqzMd7
         4dJaI9+qxFcOCh9sLBXBqVYfMkuf4tEQNGdShOQXFihKlL3zpWh10gl/EcQXDvnxWvQZ
         0nahOJxm+Kr8vdnWjBtxCSPiwZyZWGfve6MxjUocRymP2WxSxDdYTQFj/BNqBpZx/tWA
         WedMgfqwyjTFS93kZSups3qBIThBzA3h6gn8BFnrMYCJMFZZwV1sOZ43128BOBtJaJkt
         dMEg==
X-Gm-Message-State: AOAM530FrPaM+ju5lemS0XX11dg/PjM7G8YKnPE98xWekk6sSRMGxdag
	Pp0oMenI+7XAG5rM1xgf1e0=
X-Google-Smtp-Source: ABdhPJwl51MQj9nFt0L5EA+VMZCeb/jNxdlh7I5Su9rCrytWEtMKrJyj61pcNfgNo2lloVIcyL+A8w==
X-Received: by 2002:a02:cc79:: with SMTP id j25mr407632jaq.104.1604531968996;
        Wed, 04 Nov 2020 15:19:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:d516:: with SMTP id e22ls569321iom.5.gmail; Wed, 04 Nov
 2020 15:19:28 -0800 (PST)
X-Received: by 2002:a6b:b807:: with SMTP id i7mr284260iof.49.1604531968541;
        Wed, 04 Nov 2020 15:19:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531968; cv=none;
        d=google.com; s=arc-20160816;
        b=ZxiRRp2s3lltbElurXkeTDLMzshmbuavO9VaLUPnMuNEVqAyl1dL2VYDz0fvxrlpWz
         g6beTTXDyj1rQ7nj09GYuOooGToqOmTLeVncLY9oMoXmR4APvsSN9KzT+Ekl9qItukw9
         LPKh1jmDH3PsH5DPKtvlQ6CaIi+FzdrUsoHE8k/uNzI8GvEYd8muWbo24nkuKicJ9TYH
         gSzBApHTV8tZvx3HsIyddXKDz7MSzXjnKh/rBpT2sToovSugPG6xfLbTMjzJ3T9nGrdZ
         XghX2lDTT5dpL4F54Fy97m+vy85Fab5cRkvDMLS8D0AAaqmFObqkymMfmhFHbl1sbggi
         HDlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JKR/Vyk0dE+gaWDMHhX5WcTwZcpnuIINGg9SojGy6kk=;
        b=OhhJATz9OUI/8PvLN9Zgw0DFTFjMHWjlNu3rqCEuhqg0WHz8AYcrm1U+3LYh7ZhUWW
         EfzSoMrdUb8tmkMX/TFzOuFUlmqVYjQFtD9wtnN+n8DwYljbifDiU7WQ0fQbCGShD+bq
         wDudeZSZOMf3w9xCG85I/Rg0GMZbkK+u8T4WQwnNAqd1oBs7d7s+Av0jn36Qj0pDXYXx
         b0hIux+gaqRqxSh9SDdxT++7gZJXQDg9Mk/1RaBkDsCzZw6iHse9QufpwYTjShNT8/lF
         WGaEpBMsCjyyeHLPbmvhFx6QH+ntvIbABu9Nm4H/fvyjI6lOSMs7ixjbmzRP8aMISW6M
         aRQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dH+BMPhe;
       spf=pass (google.com: domain of 3_zajxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_zajXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id p5si182906ilg.3.2020.11.04.15.19.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_zajxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id b13so6936qvz.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:192d:: with SMTP id
 es13mr229250qvb.27.1604531967876; Wed, 04 Nov 2020 15:19:27 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:24 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <35bd971b9e5b2575ad3ed7c93eeb6035df5dd775.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 09/43] kasan: split out shadow.c from common.c
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dH+BMPhe;       spf=pass
 (google.com: domain of 3_zajxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_zajXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: Ic1c32ce72d4649848e9e6a1f2c8dd269c77673f2
---
 mm/kasan/Makefile |   6 +-
 mm/kasan/common.c | 486 +-------------------------------------------
 mm/kasan/shadow.c | 505 ++++++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 510 insertions(+), 487 deletions(-)
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
index f65c9f792f8f..123abfb760d4 100644
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
@@ -13,7 +13,6 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
-#include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
 #include <linux/memory.h>
@@ -26,12 +25,8 @@
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
 
@@ -61,93 +56,6 @@ void kasan_disable_current(void)
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
-void kasan_poison_memory(const void *address, size_t size, u8 value)
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
-	shadow_start = kasan_mem_to_shadow(address);
-	shadow_end = kasan_mem_to_shadow(address + size);
-
-	__memset(shadow_start, value, shadow_end - shadow_start);
-}
-
-void kasan_unpoison_memory(const void *address, size_t size)
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
-	kasan_poison_memory(address, size, tag);
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
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
 	void *base = task_stack_page(task);
@@ -535,395 +443,3 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
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
-	 * // and call kasan_unpoison_memory:
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
-	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison_memory(start, size);
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
index 000000000000..ca0cc4c31454
--- /dev/null
+++ b/mm/kasan/shadow.c
@@ -0,0 +1,505 @@
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
+void kasan_poison_memory(const void *address, size_t size, u8 value)
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
+	shadow_start = kasan_mem_to_shadow(address);
+	shadow_end = kasan_mem_to_shadow(address + size);
+
+	__memset(shadow_start, value, shadow_end - shadow_start);
+}
+
+void kasan_unpoison_memory(const void *address, size_t size)
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
+	kasan_poison_memory(address, size, tag);
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
+	 * // and call kasan_unpoison_memory:
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
+	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
+}
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison_memory(start, size);
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35bd971b9e5b2575ad3ed7c93eeb6035df5dd775.1604531793.git.andreyknvl%40google.com.

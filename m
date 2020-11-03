Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FUQ36QKGQEVAETZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B2D8F2A4DA8
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:12 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id a130sf230162wmf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426352; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZM5L0iCVQCALbGFaxodHJpX798vy3NnMI+8OCIE4vQr0xIkLmUOb5f0dfc6L0HOFyZ
         lDoAg9oGelta3AglVrhyhax9RmvVL0DGUSdh7v1bwYE+rhytF2clD/uA34/ji+ASeEfM
         ZEObmnxeyKa0DAmhpjKhs2dADF9gd2NGeDGyHY/iXWwXkDwzZZvusUH3PEyf3JnCyitU
         oieuvKq9YdHzCfBTTE4z7awokih6miH0RspDLkvaIbagPKxMRW+xHT1e+U3VYJEp14kM
         7MugNgTTWs02mJyCTvfbjFj17j30lTU1NxwBnHNlfx9D7xwRndtNG/NVoTW9HBgxWi5N
         PeTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8qWNj5hVNji94a8EgxT8rcHlF9isD4dOLiYGSdcR4AE=;
        b=HLWdfOsxjITWiBBXu3xVwTJMUlDXfdXxm7yKe09rGCSR0vhfydU8tzEq7Dps3NGUgO
         Ig1ZBwff+DAYShroD3dK0HEWhysTbOpJYZrS7izl0TGeYX5CaPMgsIcjyZcoCujk1UJL
         wBBL4M7FMz7A4CjporWv6i/U3Tsy2l8DSSY9KZ7ghnNDP359mpe5nSOV0jQZrc9xyG/0
         5KSOdDk8bFplQDHYe4p/aObmLME9rgD4JooHcY3coXV94kIa4ZRZXVlb0VvDbNJNS6ZH
         qsGUmW6b/Sizr2uDl/okMxxQRJNJdDIQr19moParTmaDhooxIF75YLlsKrGXOXVilK2O
         f6Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hXt8NWmx;
       spf=pass (google.com: domain of 3b5qhxwukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3b5qhXwUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8qWNj5hVNji94a8EgxT8rcHlF9isD4dOLiYGSdcR4AE=;
        b=Qt03cUXOEXVojnebNCgM/pZzlQEsX3VHMaBxCqie222uBZIEkkiCCyEqnbv6hu4j94
         C8jAE4HALHX9NmWPa8lWJUbFv+lCZf5Ux8I8px8Px6vzhpIEXaahPskD1PKZY4pwa48b
         Ko1ZPgRfBGwTaL5excr0y8aiQzIz+C6Tr3dQSGbVOJCMCX+MOQAvohsCO7I7NnS0sa3t
         Nl+jn3MQBxuwgj1ZUJwCvU39nrRXRahtP72MfmfJVooWmrq5prSx77dx5lbiZud9Zlad
         wxFSVjgR7WjkmCu6mGKWqb5QpBirilVzDOOYL0O/lIz55aaufd+3/uZo0R8Tt4yyGIky
         TbTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8qWNj5hVNji94a8EgxT8rcHlF9isD4dOLiYGSdcR4AE=;
        b=g7PhjtDhzx3VzPzICsQl69Rle/3Njdc6OUx7dVknJLnWWFPuC0nT2TWmjuLzHn1Hrh
         sxgzSastRumb372xnpGgscbgppA+Zt80AaQTtII47Ov5HXY9BYz+/bzt6XCJOYlqzFHX
         uyUZWeqjU4SEwRKZc5oFuvkiOIihelmSGkk56aNkITrATAHDEZ6/xqoFQ27ALubS/fXO
         wvSjfHkbxGtO9Tp90KeGaeeUF1OLpqrQJrtbADsec1dEUMONXBFw8DQMWfMZbTdzkumj
         L981mUU4YQf6REg+h3/+Ui7F3JH7potHbDi0KMaYTkq/JAnijOHskfeqNuwkRia5lw5L
         QqJg==
X-Gm-Message-State: AOAM531j4yMMFgFyYUA18chookHenCqMuh6YlG1p6fatZfTEeta82DdG
	QHKtA1sOgoqUCH7C53IwxrU=
X-Google-Smtp-Source: ABdhPJyKz6OVJCeIZ8YXGhZhsW3eTWWhouh4KBUz/knqOpLv3SRqPnwuBfkVrMRVznT9jgNpJWOzWQ==
X-Received: by 2002:a1c:6302:: with SMTP id x2mr335160wmb.121.1604426352508;
        Tue, 03 Nov 2020 09:59:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls971750wro.2.gmail; Tue, 03 Nov
 2020 09:59:11 -0800 (PST)
X-Received: by 2002:a05:6000:1085:: with SMTP id y5mr27376846wrw.283.1604426351535;
        Tue, 03 Nov 2020 09:59:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426351; cv=none;
        d=google.com; s=arc-20160816;
        b=lmIhCie/kD2M3UM9VwSQ2a3TAm9+DHhkZeW5XhgZMFG0n69tCSxw/Wj4J2hN1wnfyH
         90LBBfOm82k24nbq99zrfrH42uq+vy8GHfgGN7TDmw5dnr/XnUG0AB+s62DbWeI9gfK+
         tciKUZ40M5BZhf+mxA8H/VzEC4MhCenYw2tHTqs8omUH86SSXkS4x6epdvkJ8yTU9vWC
         C4EZq1OiQ+lkl3m5iegh4fsEBbI0p865aFhClz0Zw6IX+fwDgb/yMKDvYTKrRc7ELmMt
         QFHwQ+OZCKwURQcKrcx30ML2NAYilqPDtj8WkKIMBQBJ2mE7uXoEj0SfzqFFWnw2rJFS
         fSkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=70mBaMGWcMxAe6qN8e5SHtOekmUUKIQfft9QsNU8who=;
        b=rKYT2G8XyROKkvp2YrDmLg76SZbUrtJH0IDwUCloD8mnZy9RSHF90hKbn7S8VvCFX4
         qvI2T8BIEtR0puxOP3miekMMT3ap0apVLCm2qGtMXTzdB6AhQznRliTvkkIp6g5EDI+d
         mi1SBAgdAj2sM4FcALSz8z7DAfJAveSqoeIgtdqmNIZxzAAoL1UosHN6I1ZbEK/oH0Ey
         JcmC+ifwZ/cg9LeqnX2snoJuE+6AXoXCQcPIvIY6GPvswq2dihyo8FrMFBJ/6FQMDvoZ
         RktLTLCjPEvnzxsQi4YYJ4MXkaQCmStxntporTuNyhJGQy8R/po1NXL8ON2v6500pY0b
         Ugkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hXt8NWmx;
       spf=pass (google.com: domain of 3b5qhxwukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3b5qhXwUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p4si185510wmc.4.2020.11.03.09.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3b5qhxwukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id b68so50448wme.5
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:11 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:b157:: with SMTP id a84mr381970wmf.34.1604426351021;
 Tue, 03 Nov 2020 09:59:11 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:38 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-7-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 6/9] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hXt8NWmx;       spf=pass
 (google.com: domain of 3b5qhxwukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3b5qhXwUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

Make KFENCE compatible with KASAN. Currently this helps test KFENCE
itself, where KASAN can catch potential corruptions to KFENCE state, or
other corruptions that may be a result of freepointer corruptions in the
main allocators.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Jann Horn <jannh@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v7:
* Remove EXPERT restriction for enabling KASAN+KFENCE. In future, MTE-based KASAN
  without stack traces will benefit from having KFENCE (which has stack
  traces). Removing EXPERT restriction allows this for production
  builds. The Kconfig help-text should still make it clear that in most
  cases KFENCE+KASAN does not make sense.
* Also skip kasan_poison_shadow() if KFENCE object. It turns out that
  kernel/scs.c is a user of kasan_{poison,unpoison}_object_data().
* Add Jann's Reviewed-by.

v5:
* Also guard kasan_unpoison_shadow with is_kfence_address(), as it may
  be called from SL*B internals, currently ksize().
* Make kasan_record_aux_stack() compatible with KFENCE, which may be
  called from outside KASAN runtime.
---
 lib/Kconfig.kfence |  2 +-
 mm/kasan/common.c  | 19 +++++++++++++++++++
 mm/kasan/generic.c |  3 ++-
 3 files changed, 22 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index b209cd02042b..d2e3c6724226 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -5,7 +5,7 @@ config HAVE_ARCH_KFENCE
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
 	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..de92da1b637a 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -18,6 +18,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -124,6 +125,10 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 	 */
 	address = reset_tag(address);
 
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
 
@@ -141,6 +146,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	 */
 	address = reset_tag(address);
 
+	/*
+	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
+	 * that calls to ksize(), where size is not a multiple of machine-word
+	 * size, would otherwise poison the invalid portion of the word.
+	 */
+	if (is_kfence_address(address))
+		return;
+
 	kasan_poison_shadow(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
@@ -396,6 +409,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = reset_tag(object);
 
+	if (is_kfence_address(object))
+		return false;
+
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
@@ -444,6 +460,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
+	if (is_kfence_address(object))
+		return (void *)object;
+
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..1069ecd1cd55 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -21,6 +21,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -332,7 +333,7 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_info;
 	void *object;
 
-	if (!(page && PageSlab(page)))
+	if (is_kfence_address(addr) || !(page && PageSlab(page)))
 		return;
 
 	cache = page->slab_cache;
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-7-elver%40google.com.

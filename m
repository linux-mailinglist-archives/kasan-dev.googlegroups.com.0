Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA4OY36AKGQEKKJVZXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2035E295FB9
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:04 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id t13sf650625ejf.13
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372804; cv=pass;
        d=google.com; s=arc-20160816;
        b=BEzH+dJXeoCLO9cttzotshDzy/0SYgUsVegmp2BByOuY4KFFE9ehlE7tgeeW92CZms
         zB+yY7JmIq6Rox+WDSlM+lq8NZ6Up2t1FKpbxB6W3urq+UY1TRTOVDwwzgZlw1enB/ua
         0G3zXdE5hPZPu9hyu1te3yQmauDbibeQUgk7aFj65eCthueEgO9tAXkz9jT3N5oaLKuX
         CyKiC6V6HiBoMMVKCt2knNA0YLQlsohkfu7RwFfYVL0gQgEetkjDWn7goxfQjEHbpbid
         LYj/bTzdhc4TrG+lriqz6jUky3P2koF9rZ1DqjPpDnn0ELO2py1dvtcwKJI1/Bo1smXI
         7pHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=iI/wfg9UYwZahTPO29s21pnJ65/JEemB09CneInrhU0=;
        b=Y6LKQ55e/Chr8kVUtfrzs2aCo1v0trLWLX7UoOJgjDFAJhEBzMonRoPMHN5j8Mm9wW
         n/DSXbNq/xFQmRTWmj3Any/UVCjy7x+ccR5N2irfyOyIFRio5NcqIqPjOGS3bAZjZvEm
         KEIFypgG7T24oad6NWl+vtXaplLRZk+GtbjgUg31cDDWuTvoXJ8oLlQ+XFCohbG7Rucz
         WrfBp2t5kx6fmsPNsyVb1OE+MswnLfCbF+UiSFS7GPeBxErahW04bhBb3Lto3WBI+hhv
         E2zzqfKjfY3pMoS/CV6SS1g/wTWFVXN3cTAPUrmDqRwU3ss6QpDTRNqPqGJnoSfzbL8L
         u5wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jSZdrkfY;
       spf=pass (google.com: domain of 3aoerxwokcvk1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3AoeRXwoKCVk1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iI/wfg9UYwZahTPO29s21pnJ65/JEemB09CneInrhU0=;
        b=BSBBhiLUWsAWQb9rssOrwKSJH4JbAvwzd8mA2E0qUWFwHAG3fGURQ0ftIbsH3cBID1
         aDuieo4PjUHycUC7iaqiGd92entSXg63dymeVrGZiTkbB7t3IzE0te1KSD+L3tpVumcv
         GPosEqgy1KhXLb8/VPelt3YtcMTHZ+QxY5LnBkuZGt4HwiiKAEJLHVi/MOOmpafM/yd8
         7wbdvCTXICKZRrC15zUf/oCQ6cnoIackaIfoLbV7gnVPmwYKL2w8et7A4fUrssWGppk8
         hp6dYI7Kar84vIN2G/Lds5zPMSpeHiimN+L78sMc2bTdRJSZ1nmOXQpr2lcVJJjeSECt
         Kmjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iI/wfg9UYwZahTPO29s21pnJ65/JEemB09CneInrhU0=;
        b=GcqRFM+4iltQn8VI0TtkonKwWCozrMkxGuJheQiIZ8i3Fu37xkatzChtBQhJ64THx9
         CUM+v05NpS6eXAfC2yF6lTw36RBhWELUN6tVJVco+m4ntvVz3t3CnoPKFRwP5nMw+nPo
         FQQIVZAvy7NFetRbNeoZM3aaf7vmBthI9LyU4FGH0sbpKvP22gZdbWmSpBi1er+IP/XW
         43DTOuXcHJDYlMfMqrGSbsRingsalntkFd0yxTnvmRq16VDU4gXXtS1IypoDxHiHtAQp
         wc45/wHDFiUMBWCDVUvCh4AmTrH59w2jtmqWniGtAsv1FYKvKoNGIU+/FWFWYXQxDAHW
         PKfw==
X-Gm-Message-State: AOAM532q4uK0MqgcF9o7R3WPh+n4uWhr6thgCn0dowmQEaXK1JZPKIVU
	PK4OIceUh5uyZGkXwLE58jM=
X-Google-Smtp-Source: ABdhPJydBzNh6UF4fxCpFmgj70D4A7HZS7Ounz06vltk/LHCj9AQV1kY14ryQTJYueF96yQOqkxfaw==
X-Received: by 2002:a50:ee19:: with SMTP id g25mr2287174eds.160.1603372803877;
        Thu, 22 Oct 2020 06:20:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls338437edt.3.gmail; Thu, 22 Oct
 2020 06:20:03 -0700 (PDT)
X-Received: by 2002:aa7:cb8f:: with SMTP id r15mr2263140edt.356.1603372803099;
        Thu, 22 Oct 2020 06:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372803; cv=none;
        d=google.com; s=arc-20160816;
        b=kXuanSMp6YhepD8cxhigY012aDE7c6+Ep7+IcED4+t0RKR5If1t8FxLz+qtGgsrPOt
         vfCObPUHq0GrR+3cj+P4E5eIJlvwgUjzDYPgnSGRY3RQFSUkJoa6n/WHGpS1n/s/XE1K
         VV/rrrqBS8scjpqzFeCXI3uxmKw9FI++XYjnv/dheksthaSEWy9OaGYdCOxTCwxV86Wa
         6eM7uWGFyE4rWnEjOnBkSBk01Ph5gC4YalC1G44vz5a+85Vl465kGnEFOD4drB/wijSC
         5Wn0kpI14TTPkh4uexfThX9N0REkEsmjQVUEHUhvXeK1aAH7URPsPS8Njfrh1Xt3luvt
         lXBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=OXY1Rszcej9Z+zHeV4E2RjMvc6KaNi19mvRQTnsPsy0=;
        b=AUUEY2QLXZmPbBQi/a+rx2gxZNiZYA+fDZjnxb5R3Sm1vpOtLBjsVzFRBzy9RuouL5
         G+f+hXg64t0urn34oHgEiTuwlSZkPqqZeSK70+MaiVTGvXnhkUC7ipC+p+ma0ToqvyCF
         7huU6BXubwVvuHe1YI0qva77ir5MwwuAkNmcbRclb4s8v0dcYWalI2x4HeGNa2v0sa/3
         JY1riTHpRxmKDpBqGaNWC9DiZU90YbBKUElKU4L3LM9FsEc+Rh3ktbu6W+z+fzyFpfu9
         Uqz/xMWQExcygC4pinN/RX5xohWPyks5KQf5U46DC/ME6i2Ea2NjTE65uRMjphdaxo4Q
         ts6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jSZdrkfY;
       spf=pass (google.com: domain of 3aoerxwokcvk1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3AoeRXwoKCVk1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n11si59612edi.1.2020.10.22.06.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aoerxwokcvk1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so627189wrq.2
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:03 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e88a:: with SMTP id
 d10mr2859147wrm.247.1603372802756; Thu, 22 Oct 2020 06:20:02 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:08 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <ce573435398f21d3e604f104c29ba65eca70d9e7.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 16/21] kasan: optimize poisoning in kmalloc and krealloc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jSZdrkfY;       spf=pass
 (google.com: domain of 3aoerxwokcvk1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3AoeRXwoKCVk1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

Since kasan_kmalloc() always follows kasan_slab_alloc(), there's no need
to reunpoison the object data, only to poison the redzone.

This requires changing kasan annotation for early SLUB cache to
kasan_slab_alloc(). Otherwise kasan_kmalloc() doesn't untag the object.
This doesn't do any functional changes, as kmem_cache_node->object_size
is equal to sizeof(struct kmem_cache_node).

Similarly for kasan_krealloc(), as it's called after ksize(), which
already unpoisoned the object, there's no need to do it again.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I4083d3b55605f70fef79bca9b90843c4390296f2
---
 mm/kasan/common.c | 31 +++++++++++++++++++++----------
 mm/slub.c         |  3 +--
 2 files changed, 22 insertions(+), 12 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c5ec60e1a4d2..a581937c2a44 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -360,8 +360,14 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
 
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
-	kasan_unpoison_memory(set_tag(object, tag), size);
+	/*
+	 * Don't unpoison the object when keeping the tag. Tag is kept for:
+	 * 1. krealloc(), and then the memory has already been unpoisoned via ksize();
+	 * 2. kmalloc(), and then the memory has already been unpoisoned by kasan_kmalloc().
+	 * Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS.
+	 */
+	if (!keep_tag)
+		kasan_unpoison_memory(set_tag(object, tag), size);
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
@@ -384,10 +390,9 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
-void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags)
+static void * __must_check ____kasan_kmalloc_large(struct page *page, const void *ptr,
+						size_t size, gfp_t flags, bool realloc)
 {
-	struct page *page;
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
@@ -397,18 +402,24 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 	if (unlikely(ptr == NULL))
 		return NULL;
 
-	page = virt_to_page(ptr);
-	redzone_start = round_up((unsigned long)(ptr + size),
-				KASAN_GRANULE_SIZE);
+	redzone_start = round_up((unsigned long)(ptr + size), KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
-	kasan_unpoison_memory(ptr, size);
+	/* ksize() in __do_krealloc() already unpoisoned the memory. */
+	if (!realloc)
+		kasan_unpoison_memory(ptr, size);
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_PAGE_REDZONE);
 
 	return (void *)ptr;
 }
 
+void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
+						gfp_t flags)
+{
+	return ____kasan_kmalloc_large(virt_to_page(ptr), ptr, size, flags, false);
+}
+
 void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
@@ -419,7 +430,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	page = virt_to_head_page(object);
 
 	if (unlikely(!PageSlab(page)))
-		return __kasan_kmalloc_large(object, size, flags);
+		return ____kasan_kmalloc_large(page, object, size, flags, true);
 	else
 		return ____kasan_kmalloc(page->slab_cache, object, size,
 						flags, true);
diff --git a/mm/slub.c b/mm/slub.c
index 1d3f2355df3b..afb035b0bf2d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3535,8 +3535,7 @@ static void early_kmem_cache_node_alloc(int node)
 	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
 	init_tracking(kmem_cache_node, n);
 #endif
-	n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
-		      GFP_KERNEL);
+	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
 	page->freelist = get_freepointer(kmem_cache_node, n);
 	page->inuse = 1;
 	page->frozen = 0;
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ce573435398f21d3e604f104c29ba65eca70d9e7.1603372719.git.andreyknvl%40google.com.

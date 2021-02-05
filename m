Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMWN6WAAMGQE3ZDGYAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E1CAA310D3E
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:30 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id bx12sf7005159ejc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539570; cv=pass;
        d=google.com; s=arc-20160816;
        b=D4A6xaXCxA5SWVXwCESivhrnTPfQLCGUpvHVegGSoLmPy73UV25ag51BkfVR+nalGz
         j2HceXupAdCrDeHceRiifG44y+tsr6BAugorSd8kYLHzaX6vaFSI9d/7bmBof7nRKyzj
         KCsAfe2cT12wx2iC6zusVvmA7MwL3WDmchC/1SZu9/VQ1PR2fu3sSPoZeUc/v3VVlh2E
         0rIlLdI74F98JUWVGgxeZk5NVHFR0Rr4H2YacqB6Xu5/oSVy/xHj09AzxjaHDcdMMsT9
         WO9UY+9z1EHXtBGoD9fsx1N9+wd4bATxX85RxDYhTFXotvjEA2r3bg/pv9uOFfP5cwPP
         zkIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jUaOUipL1Mfp5sTGI2HccBj8KEbYS7syFtlldcKcemI=;
        b=VtQsTgJ3+ubWQW0FfO03BCgUem+apbboJAUlYlLgdXqwUuw+++oCZwKBIKY+0TzHVF
         kRyAigt29IadGnmO1kJCEOPGOg25aLy8RGOW0ZtVZHJvtHauG+mu4NrPnVgbWhrdq/DV
         KJoJi842SAK9C7tIVnciVY6nSVdvdOoO9X46FKszUAf/vzq18/ieXpA4oqn5+DkshfGy
         wyEQ9K4BGXL4j9Z5A+D3nofLqhy9RgnxsU3gy8fMKJWsYW2LgT9I1xpBvttinKlvgbi1
         gLuwiC+Z6HalSFhXZkrD9coCKi+xtwmFx79/ailzxkLxouSkROTC7qf80q8WGsVI86zu
         7VIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LCEFnlDa;
       spf=pass (google.com: domain of 3swydyaokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sWYdYAoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jUaOUipL1Mfp5sTGI2HccBj8KEbYS7syFtlldcKcemI=;
        b=mm98rUTfunGJoevuTKDx1cYzcJnXYp5QxLVL2CcBAPx1/UntoBRMOrUShw07ZKHfxW
         UGThg7tScdia0KxcQ5ziBoKZZ3lM1AEmhRlI/7Y4aUqwCC7F68yofNq7BhRg2ovMixtS
         ZHYbKVss0eiCpj0kEAbbewL0cKF9zY2JgNB6h6ivKdRdWn9lIewOVCJrdIkMTZ4/EH8u
         FLDSMvsBAgUmJ+qmEwleDUraa09xETOCkylu27fvMdKq00xJ+LABY9hgocAhrQf6ScWv
         8mbS3M5aH3KoKPFBWugx4CH/GWMwh75w09W3OcQ2AJQr7mNDfLaa240GXNF2MHswejgc
         Rs5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jUaOUipL1Mfp5sTGI2HccBj8KEbYS7syFtlldcKcemI=;
        b=rM9fRTznptjErnCsyxhYhsvfHOftwgLMaRe6jLjpwQSdjSpJPppdufZnBUfUCEWDBl
         qTFgrJRgex0om1RWy5xU3hSaxwmFdBHNrIVf0KP3H1mabF6ngUO6G0U++Kk8Q5Boy3Bh
         ogSvPMwb/AHjQTk/8XZbi+KEqH11iIPXV0rRvCPVxaiF02ygleY9Z652rdqfB4MGfBgD
         I7QaI5yqX9Fvo2/SIUHtdZRSBqeKCDQ5ac+fvsBIaIT+NyewmDf4lbK6x2liZRDayjlu
         H3nnrQ45591WkyLl8OAY9iVdQ1MxMx3zqoPEScxMjTq7fY5SDwYYsXpqdvi10L3tAx6d
         4o9A==
X-Gm-Message-State: AOAM530JOZlnBQDz4G+5SJsmZr03XnyorE1Zs7OoDC3ll4jNR/VjODPi
	5jloFf1w7SfWFG4UDLzTbLk=
X-Google-Smtp-Source: ABdhPJy8+4GjtR/XJrq8aR9kL0VTjJf4vQ0CtrzeBuHXUX+Lemr34CrqNWgLb/TkOlr/O+UIBbSA0g==
X-Received: by 2002:a05:6402:3590:: with SMTP id y16mr4105849edc.21.1612539570689;
        Fri, 05 Feb 2021 07:39:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls334210edd.3.gmail; Fri, 05
 Feb 2021 07:39:29 -0800 (PST)
X-Received: by 2002:a50:fa93:: with SMTP id w19mr2390953edr.211.1612539569893;
        Fri, 05 Feb 2021 07:39:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539569; cv=none;
        d=google.com; s=arc-20160816;
        b=uW2+pbP4lt60t9JJLGMDaEInTgoBqV0ZMyLGw8yTt09NDn/n95/BVnyy/DrNtOIP8M
         4q13xYI+qcYRR6AUE2GVj5SZcPKIMqLogSlM2OiqVvkZovLnFKNhcGqTqXC2mWrTPq0d
         kWazwKcRvMJ/9dplhgX8QKsC4SiiXFrrPF9WhiyonROob4Wkb7TfV5w9MHXdSRnF6AHt
         WyLqA0atgVueIhcZ2AfIS2i9ZcyBx63fXeQ4kKo2vtT/aUlOX8LfkAm48r+gJyHFIoAe
         X6E1WbOelHSTbpY9kq9WM+UCxpRslu28XhnqaObcK3DMAQPtOR2Rs5iYeaujjW7cAPIU
         ivEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=kg30/g/LrsxD86gPJMTES5VW5Hgvjnk4vM4kmv21+Z4=;
        b=PwKkdneBBbCpdO1+ksLJlWFNiIH2A4OYiD/KTcvBQOhTD88Sx0knDTFFNOf2lFfNMC
         Ctt5P9nCS0a7ChpTzz2NBTYJpNkR0dGEkpQztt7mj+ViaMqfeBou/hmPSw8Om6LoUl0k
         XW8FAKiwjvdLKXW3LPQWtb0VNPVkFVmYczL0hgjT5PTi/NVA6RPL9tFKWp+7EMeElJvj
         +yPvJSWkU9jJczgQH2++fMuW83rADGOJU1K/qB9/Ul3B28fFxw2MxlN1AVZwEwVC5nzm
         Bw1DLKpgYBCBQeFL+e5fUtSdODitrFb2/nYFiVq2L8e4bB2cSpelv5PzctCabVOpdXLB
         gfoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LCEFnlDa;
       spf=pass (google.com: domain of 3swydyaokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sWYdYAoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id a15si526672edn.0.2021.02.05.07.39.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3swydyaokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l21so3131908wmj.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c2aa:: with SMTP id
 c10mr3901926wmk.101.1612539569588; Fri, 05 Feb 2021 07:39:29 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:06 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <492dcd5030419c5421a3762457c0ff1a7c91e628.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 05/12] kasan: unify large kfree checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LCEFnlDa;       spf=pass
 (google.com: domain of 3swydyaokcfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sWYdYAoKCfocpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

Unify checks in kasan_kfree_large() and in kasan_slab_free_mempool()
for large allocations as it's done for small kfree() allocations.

With this change, kasan_slab_free_mempool() starts checking that the
first byte of the memory that's being freed is accessible.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 36 ++++++++++++++++++++++++++----------
 2 files changed, 34 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 2d5de4092185..d53ea3c047bc 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -200,6 +200,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 	return false;
 }
 
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static __always_inline void kasan_kfree_large(void *ptr)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, _RET_IP_);
+}
+
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
 static __always_inline void kasan_slab_free_mempool(void *ptr)
 {
@@ -247,13 +254,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_kfree_large(void *ptr, unsigned long ip);
-static __always_inline void kasan_kfree_large(void *ptr)
-{
-	if (kasan_enabled())
-		__kasan_kfree_large(ptr, _RET_IP_);
-}
-
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -302,6 +302,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
+static inline void kasan_kfree_large(void *ptr) {}
 static inline void kasan_slab_free_mempool(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
@@ -322,7 +323,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_kfree_large(void *ptr) {}
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index da24b144d46c..7ea643f7e69c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -364,6 +364,31 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (ptr != page_address(virt_to_head_page(ptr))) {
+		kasan_report_invalid_free(ptr, ip);
+		return true;
+	}
+
+	if (!kasan_byte_accessible(ptr)) {
+		kasan_report_invalid_free(ptr, ip);
+		return true;
+	}
+
+	/*
+	 * The object will be poisoned by kasan_free_pages() or
+	 * kasan_slab_free_mempool().
+	 */
+
+	return false;
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	____kasan_kfree_large(ptr, ip);
+}
+
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 {
 	struct page *page;
@@ -377,10 +402,8 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
 	 */
 	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
+		if (____kasan_kfree_large(ptr, ip))
 			return;
-		}
 		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		____kasan_slab_free(page->slab_cache, ptr, ip, false);
@@ -539,13 +562,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
 }
 
-void __kasan_kfree_large(void *ptr, unsigned long ip)
-{
-	if (ptr != page_address(virt_to_head_page(ptr)))
-		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by kasan_free_pages(). */
-}
-
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/492dcd5030419c5421a3762457c0ff1a7c91e628.1612538932.git.andreyknvl%40google.com.

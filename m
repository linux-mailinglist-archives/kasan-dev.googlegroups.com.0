Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6NT4GAAMGQEXIGOUMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F87A30B09D
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:54 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id c22sf10010124ljk.18
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208633; cv=pass;
        d=google.com; s=arc-20160816;
        b=d81KdkRYo2x/ckylDf6hy9RKZsatac2hAbzyZqjPQQiL4KnekhyErWLLCTCE3VutR0
         BHAIxlao0KqUV4zXjETF3fVo/qpozHcHtP0tLi+RyM8wdOqywHNr/ysLnMioyYH/5Nfl
         xVvB/+NMF3Ybqmzl6mnmUWcRqvoaGVol7DwCcRpYD3nYaE3q6kDbHK6968pcgUlp6gIJ
         6YebcHpfa3+vToMe+2wrsGKkImkUXOXYLQR/J+9eDa4y3bm7wYqNn39WNfyI1eFXyGrk
         ZCvD/B0PYnIslRPAkaWPugTceGXLtTaR0E+/WGkkMJyLpucRivvfMph+6qIzkF05VpCs
         Q/ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=X/KBqG3BxJ+R4Q+Q8WsYKeHnJZIxJ6bZUmuqSVkguzg=;
        b=xAmGkinKf/huB5p3eDH78m51kRywWKJEbdmitvXb7S4oC7h2wHYO81syUaZhUGifGu
         n4qGzhig0WFfPRkGLvSAKH/Xxm8UqjNnBUx8txm+KxME3qJNa5K1hf//bvieh109IQcA
         dUQr8YtG6HzcPE+33jRNgf/3/OcrAYOUFSD7R4FzNIPj7FMAqsEAJMaxvAW4dc7JQ2SD
         2de260q0hb40Mr7xb9wHI/BFPhHiCQBzaBdkJrVeP4kgtUKFHaI4fDnZGTdqOI55Z18o
         ooGdw+dsj6neVgGyEWvQoHCCUl7DdJuBjHhOQSFZf38RDuQSFp7b/P8J0kOJufkYL999
         N56A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJiXwOEo;
       spf=pass (google.com: domain of 391kyyaokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=391kYYAoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X/KBqG3BxJ+R4Q+Q8WsYKeHnJZIxJ6bZUmuqSVkguzg=;
        b=e0zYuIM0N6ysPZM6BBSHxofSmTOPSs/oCV5xxuAzQDZzKcarsIcEfRa1USvw5OSS5a
         CIlMsdaqQLbfL2Z4j/qJknWUFTmNSaSEkadjO5p/eMr6pLcl9yNo4lOXJciVNduWb6+6
         Pv4vOCsHXwDRXT+/9rQlSujyo7tPLLhSamvE2HgfjqVuM5lJplEpdIHnh+1/UCyCJwBp
         ZnawUjrPOhc+iGK9Y35VNZ3vQ64sPEXmcuTDlfzLq44AWf1pC5lO5e2PsWYTVFrZj7Sq
         aVzwWbl4Z1Mk9JQwUnV+g/PgcLm1RFRxoAS3sXdELYOA366+WO6opUaoWjCoQKXiwnJb
         qdkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X/KBqG3BxJ+R4Q+Q8WsYKeHnJZIxJ6bZUmuqSVkguzg=;
        b=p0QRtgycn6OARdtXq3uPKRl4B9ARM6XSxVs3sH3icdTQ0W6LypztTjLZU6E6Bs/Rg7
         x4F5FMhM4Kw+cMMtOjsNC/qRPwgF5O0J8Tndsf4Xmp/qL1Am6TrGVpPzoyxjDL2xo3pw
         vC9jrpZpe4kgTAlDMijmhxRsfqxlF2Ccfod8VBsr8RrrEGk4vfdD8CzRM3neZvLz8QVu
         4nkNNQ90FtpNrDVqeAfSZdOF5YNQE/Q4x07Gs+Pm4BxP7UWsWsjk7mcc7B6Z6BBhJRDR
         AgOA40aEIl54qsasZKWMjcqPM6PhU/grIvrYofmvoP9g/XPuEs7jbre1S1UtoFcTO4fl
         m8lQ==
X-Gm-Message-State: AOAM530H6IBnYICm7HRyRCkVD9Rpp96DmeiRsgy3x6XmGtRUTQjHZnpm
	WeNoIh9HWVZuxMu6YCGpnhQ=
X-Google-Smtp-Source: ABdhPJy/obUzYCagz4b86veD78bw8XOXt+8TdOQlCE4lfqbpvZoS8JjKqXWdgFS1W309mVSr4eBMQQ==
X-Received: by 2002:a2e:b5ba:: with SMTP id f26mr10675517ljn.92.1612208633757;
        Mon, 01 Feb 2021 11:43:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls1493273lfp.0.gmail; Mon, 01 Feb
 2021 11:43:52 -0800 (PST)
X-Received: by 2002:a19:ad42:: with SMTP id s2mr9051549lfd.448.1612208632580;
        Mon, 01 Feb 2021 11:43:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208632; cv=none;
        d=google.com; s=arc-20160816;
        b=rWWIVBgSdLceNFxlB2Hg6F8gzfm9utJXP4jxLfM/1AwdcNfLOdlt5MzzV5a3+3ynvP
         iOrd+3WJpjzol+mL+FYL9VFFNdleB0NqEFD4NQjyuUAPXGe4qS9rUDH8oLgWiDZ7ile0
         rGGe/FgXVuqn/LPBh9bRVf81XQ5lieXhRlAbvWwAZ+TI82QEs4B+OdTYrmINgk+ijeUY
         WevQ8Bx28900VGSfBYBSybxJ6S0cDadnt6pUUx3o3zUjj4kdpM+AvsvWjqS/CIVpUY7k
         8hncRYxlpIrjWn5yhcslnCA0GtEoQmlXSuN1KoMWzgL1V0VO3YzHzY46XSDKH0S3hfyt
         5Shw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BaU4zsBnF6d3TSTU+6bwjMLYV3de6hEhX75uuk8b+O4=;
        b=mUWqs0xXHf9F+jNChqwPFKkwl47tg6sf4m/LJLfmZw9kd7pvOk6g4PcOhPQ9szs0mq
         NilRSxy1x2jFqOktqOKS85uB9TXKEQw/1kFE82qXQl4vCUoA4ndRQ1d+Zfb/YZKiShIi
         IN0H45RCGO/JAOqrR3XBxUeTJm9QbCZoVCWWnNY96tPdaspboTL1xuLAYaki3JyyhwpQ
         +K4DbswDZKE9iKvQFVk7UdRd32lnjc4qiOhNN6Uny4GKSDkMMYSgi84LEU4Vz3G919Xh
         zshQ7bGfDTdNP07QHJPEuREsuxBUUo9lkFgcezdd/Aqfzvu1qAYop18m2D/0TZ7ISAgk
         MAFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJiXwOEo;
       spf=pass (google.com: domain of 391kyyaokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=391kYYAoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a24si640337ljj.0.2021.02.01.11.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 391kyyaokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z9so11023321wro.11
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6a02:: with SMTP id
 f2mr447589wmc.36.1612208631997; Mon, 01 Feb 2021 11:43:51 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:29 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <dbef8131b70766f8d798d24bb1ab9ae75dadea61.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 05/12] kasan: unify large kfree checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nJiXwOEo;       spf=pass
 (google.com: domain of 391kyyaokcrqu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=391kYYAoKCRQu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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
index 086bb77292b6..9c64a00bbf9c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbef8131b70766f8d798d24bb1ab9ae75dadea61.1612208222.git.andreyknvl%40google.com.

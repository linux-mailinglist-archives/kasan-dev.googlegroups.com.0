Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXNQ6D6QKGQEHYO523Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B2772C1576
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:25 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id g1sf7116249edk.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162525; cv=pass;
        d=google.com; s=arc-20160816;
        b=TrpN58sFMrioQUA2fm5FHR5FXYfOSuAIFO/MFOQZkelv3KHvty1N0SMRexg41QAKf/
         MDz+zGiq7nbGPCqJpjWF2koz+mxl09Ik9axkVSj3smAfpqd4ql2qtUJDHM1SMcO00MJ6
         KfbeMxK4+5pcux2qn5Utpzu0ZIKwZrjDbxzupXWBUlw8PfhOFpIq7PFVM5oa1utJGo8Y
         nvUR5EgLpovIzRg6oluQyFVOJ9TQtbFL9+8+rHvQ5R1TCd2F8fYHDHCQ5YySUoxbOTzy
         2csZFcDjjGhM1Y8pYgTXPbm6Dr7lPZiHGrwzEhBHLzYRIVtSIQsXd8p0pI+F82X1DXLE
         S2Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fYFG0H5B9LkJZxXeav0e8JE/pbgHUhbBCSHWlxMowXA=;
        b=PB8e4At9POxqcVit89Jh3FAY2ed2goywC9tpYPchAUgUc1jE+kLjuw6A7GQlb7qUzm
         WWft6cxoL/0316vQXv4UzBorD+dh810L7bvev8coXiRJIl0QQniKQhyPQ5wKYOHSvAxa
         CObUyByYdZfJXHfZ9PuavHQFaD6KqpoENcqKNkfe2j9NiWQhloudUHi+c2iFtKCgzmIL
         zVIwwpnGwHzE8BxIjitaglXRRV42AO4LaADApj6OdcCowCyUCPfLMN9QJOA/xDOYn4K/
         wT+LEBXlWO5ICyHsXnadshb5wxIaEMbI0TSJH6bNvC/zKfAx070OFP+4ZmvWFowaOYHl
         6hig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A+kpGAdD;
       spf=pass (google.com: domain of 3xbi8xwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XBi8XwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fYFG0H5B9LkJZxXeav0e8JE/pbgHUhbBCSHWlxMowXA=;
        b=Ws+ObNUnnxSdwQi8CrFTvWVJCNk1OX6f1r8bX3hdg+e6wVDh3I+oNfcEhgNw4pYT0J
         fxDnE6eGCIZFQVZoifhywMx0yG6+wGd91oXBNSVSgwe+d+CTjeATQl4jgcKgw7yRAcFC
         BgwZ4A/0bH8R0WIsMuvffCEKHDyokvP/sNDrdZIT2/RuOshBHlGmXDcONuD8ZhhoNkol
         x9jSk8Qk0cDyD2tNRp+jpi1Zb2NoW86UPrdP4s1a0pLtpw6nvcA8k3w4o5vUirwJcPuF
         8MPAm1m6Y7T93CyLpWgP33MaESf7jShS8C0nGCd86vEiuAbRaYTA05/6WfHeCzJszfJc
         cY9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYFG0H5B9LkJZxXeav0e8JE/pbgHUhbBCSHWlxMowXA=;
        b=eAs/zMddox0xSBusKde80ozcN9VAVfPhJF0ufHAXjuCbWJA4SAEnaHqAwBul2SCaOV
         tKMJ5OzruRuB6tR3BhQW4Xh4MGemQziDw/Oih4FCRdUpQQ5yfWmBk39j2V8MpLfG5sR0
         p2JawllWWSwgpIJ+4oGLQ81r0WarWNVca9V3sx+lmW2WiiIHZCvsFvDCIR+uWKMRlqOB
         IXrFeGBrwF9Ipl2LefTqEpj7p2FNcsZjpA0D5kvk5NT3om8YQQ2KeghG9ToZlRGOpEAA
         knDMT+mRZA7xWDlhOStjy/7Pyo6bzbztKhJ9cmCkoj0XcU+Zg3xtBrxR1fKtenFBSRDs
         HG+Q==
X-Gm-Message-State: AOAM530YCbjHTlkzLXAcHVZTE67GT7cMM5qy2hf+leAiog5gk8HFN73m
	MVDewujaG2igewEAmQZnJ8s=
X-Google-Smtp-Source: ABdhPJyPtMtxbrgmxbmL/bLgEqHKr4QzPTiFRdifT7H3RHRUttWIV6caAhEvkHBYzIaD9Se5dslDZg==
X-Received: by 2002:a17:906:748:: with SMTP id z8mr563127ejb.546.1606162525311;
        Mon, 23 Nov 2020 12:15:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:931c:: with SMTP id m28ls7014811eda.2.gmail; Mon, 23 Nov
 2020 12:15:24 -0800 (PST)
X-Received: by 2002:a50:9f61:: with SMTP id b88mr917213edf.282.1606162524386;
        Mon, 23 Nov 2020 12:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162524; cv=none;
        d=google.com; s=arc-20160816;
        b=rTu2EiRqpNnt+mrGs2cee1YiAJT25L/e2Jjx/kE4N2++fUEXw94IZIy1GSkQwlD1m6
         EhpNoXEcLz0UUfASIY9qxPQ6AeFLMSkmZIQX7WCvjw0jhL8VsZAsIEhm47w9VPOdGEUt
         eyNyLnjmdQoFL+7AaYd1OzGevxtj52CfJVz4epCnQj5SVB5SrxUxO/DrVRvVTBLSWb4d
         3luZB+4tdSx9D4hL232zQGPumJfbQ6rX4Yym598x2s1QB/Wc4fyx8viX/Ue+8h0RT1Zn
         Kh279rjoP2i8SvW0vTVkQ+ClTX0YUB/yoQbB3Fq1lLklqnkCI+giZ12MEK8XFc0/oFNR
         MBaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vCPSdYhuISEPMca4NzZzu0kqKTeEYaaZfMxe3jMvD/s=;
        b=FaNoFxg4bEFTtHEne2JJDTGMdhCvreQhpjbvv8zvpZbPXz+hugLz13dmaOnljE2BGP
         4w9SwFrwMEYs0HB2EeRKECa4V1Q5AjkPZnC3NRvt7+UnB2UWeclaPC6jEDoxHw8WX2Tf
         YHUj+eNwF0eOs6CvZxkbd7T1IO8Ie/N0YwBRvqL+awQXLV9mvTXL2qpR+2nQRpdzvpbE
         9pGgsmwrHQASUsfGnszlF8OplEXPmer7UDwcLHQNi2e/YgfvL4IDlk7nNWEk29x4LbpL
         +MU1tn9gHvTzijv3SOvx5jl7JhjSIRQn/yq+F/nYHd1Cquw5zQOe5oX/+AvQ/aWYjNAD
         EoEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A+kpGAdD;
       spf=pass (google.com: domain of 3xbi8xwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XBi8XwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a11si256194edq.1.2020.11.23.12.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xbi8xwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id m2so2082683wro.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:c343:: with SMTP id
 t64mr639600wmf.140.1606162524075; Mon, 23 Nov 2020 12:15:24 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:43 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <141675fb493555e984c5dca555e9d9f768c7bbaa.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 13/19] kasan, mm: rename kasan_poison_kfree
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
 header.i=@google.com header.s=20161025 header.b=A+kpGAdD;       spf=pass
 (google.com: domain of 3xbi8xwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XBi8XwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
reflects what this annotation does. Also add a comment that explains the
PageSlab() check.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 40 +++++++++++++++++++++++-----------------
 mm/mempool.c          |  2 +-
 3 files changed, 32 insertions(+), 26 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f631f99aa4b4..2610438120ce 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -175,6 +175,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
+static __always_inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_slab_free_mempool(ptr, ip);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags);
 static __always_inline void * __must_check kasan_slab_alloc(
@@ -215,13 +222,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip);
-static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	if (kasan_enabled())
-		__kasan_poison_kfree(ptr, ip);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
 {
@@ -260,6 +260,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 {
 	return false;
 }
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -279,7 +280,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 17918bd20ed9..1205faac90bd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -335,6 +335,29 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	struct page *page;
+
+	page = virt_to_head_page(ptr);
+
+	/*
+	 * Even though this function is only called for kmem_cache_alloc and
+	 * kmalloc backed mempool allocations, those allocations can still be
+	 * !PageSlab() when the size provided to kmalloc is larger than
+	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
+	 */
+	if (unlikely(!PageSlab(page))) {
+		if (ptr != page_address(page)) {
+			kasan_report_invalid_free(ptr, ip);
+			return;
+		}
+		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
+	} else {
+		____kasan_slab_free(page->slab_cache, ptr, ip, false);
+	}
+}
+
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
@@ -429,23 +452,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 						flags, true);
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	struct page *page;
-
-	page = virt_to_head_page(ptr);
-
-	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
-			return;
-		}
-		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
-	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
-	}
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
diff --git a/mm/mempool.c b/mm/mempool.c
index 583a9865b181..624ed51b060f 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_poison_kfree(element, _RET_IP_);
+		kasan_slab_free_mempool(element, _RET_IP_);
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_free_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/141675fb493555e984c5dca555e9d9f768c7bbaa.1606162397.git.andreyknvl%40google.com.

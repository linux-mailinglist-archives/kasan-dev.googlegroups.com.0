Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ7736QQMGQEQE6DETI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 667AE6E0E34
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 15:12:36 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id l20-20020a05600c4f1400b003f0a04fe9b9sf2133534wmq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 06:12:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681391556; cv=pass;
        d=google.com; s=arc-20160816;
        b=dmXlQAK9FPjAhUXug5mdOmNeZYQVmHiWu4ANFeP5eGO+MOPTEmoGWTnapsVdB33fKg
         DcGystZ+pU+TUXT9CG13j27isa0Wb5u96sAtJxuniaJIukuN2/AQ75fcEwV12lnnryPX
         5X/vGAI+xW5+CSywKdBo4o4nbiokdYhQiScXZWxjCBf2HDKg7Yo1QZp7jGFgijrnwRW3
         fIwb4MEHk2lWxeU9ZruGYHNoEDDgBcX3KXwD8rr8o1G3E/UGZws2ltuzQGD7b6qnsU79
         Ex8/j0CfZJ7nhAVbKHHHPrmcQpGbwLCUgMnnd/Xpruntb4b5y/NKF7g9u3TpTtb3nMjf
         OkiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gs2o+FfkecZLCI0G8yg0ulYbCyw40Py1RV632vcdPJM=;
        b=rEHnG549dPuqDtn9QolZidYdMSxXBKGu7uGccIrmP7V0hjF0w2zgaJ9MKtJd+dypuT
         ij2drNNk5zwUJX6IY57lSYjKGWT+I7rdnx080MD9NtRe2FtKdafu55Ded1zhFGBcdMp/
         YzrQiQgcBQePPegZAXNizSsM6iY9RYcgT8esYMXXMhHxQmLQbnF5+dV/7phW2rK7PeRG
         xHMr1VVoMWSzJsQQ0NGR4KoY9hV4Zg7X7dJm69aClgO3UABeRu+GccxEFWpLOFnA73IV
         HCu/84NXMUyeII7REgkiYiMxBeHXtz/NOLACmk6KsAx+LVdGwdB2s7v/xvQh54SWVZZd
         z2PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=D1+Gxpsm;
       spf=pass (google.com: domain of 3wv83zaykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wv83ZAYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681391556; x=1683983556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gs2o+FfkecZLCI0G8yg0ulYbCyw40Py1RV632vcdPJM=;
        b=OkNpyUhAsUzBcl10KHMnscMDsPFXBnPItNROpJwYuZ3vmpSyk9i2xrpmGkZAS4Za6e
         FQdi1vGKZvlREMGGX8nB8ONcIOtHB1CZNe96ruvZGwiSI8BybRpNEa6dV1OrQTm39iXx
         9bEg30tcqILA7koKlRgqXrEOJKCfxqppTITNtzf7YLhXvKZpVJoxgTEuhJKO3Fcn8CUR
         MUWOz2MtIlZUsLezO8m2ZZxoc+D/D/zT8iUYpgAKnyQNn6F5NOhKxJptzf95B+tOebLR
         ufqQxDiXxo+3X5zFIjWCrV3tXjKB99/770Au5RJeC6Pk5wgOBdAdr3g03/Z+cXaEf4iE
         jiOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681391556; x=1683983556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gs2o+FfkecZLCI0G8yg0ulYbCyw40Py1RV632vcdPJM=;
        b=aud1TetIpX6oEPxRE84zeb86zhEkgx3wx/xWvQ+p5JHZp/XG3SQ/fSch4vvJrlYRob
         9AnZjhYPXBDdvzqJ9rEQU65Q2J2IeG4n24VyESOjm4EF+i40oMFmbZxvRncvRjqHdhnC
         yGMb6XT1+OcmwMe/qcpIGShEaZIhIYR5jpx0MsB4slHq1rSzxVXNi8VoS0mc+Z7ertyw
         Xgw8qu4DR11J7dX9JXdIjl2iDbc7T+uTL3rYNHsoR8MCJrjReH9bYe1ZXDwtwGY6OAv3
         xF+KByre4Nm6sTr2ekcDXvWoZ3EHOdpMEIS/i+PfY1ySrJA5DjCG/oQ1KO2O5uJ2QMbK
         IZEg==
X-Gm-Message-State: AAQBX9cCnreoce5iGPjHGNuNjXBcXu7nPFLC4PbhrILI+oc7g89Ft85a
	APnKNJep1J8RApTLAmm/uWU=
X-Google-Smtp-Source: AKy350bkrtnDdb9jBfc/JB6/DbiYVQsFGK2rb6Yyy1kUuzEWoXayPhHC6AW7VMNxAczhEHKShlJkNw==
X-Received: by 2002:a5d:6ac2:0:b0:2f2:5408:f160 with SMTP id u2-20020a5d6ac2000000b002f25408f160mr416549wrw.13.1681391555980;
        Thu, 13 Apr 2023 06:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6015:b0:3ef:df3:1695 with SMTP id
 az21-20020a05600c601500b003ef0df31695ls997046wmb.1.-pod-canary-gmail; Thu, 13
 Apr 2023 06:12:34 -0700 (PDT)
X-Received: by 2002:a05:600c:3786:b0:3f0:9ff4:d31b with SMTP id o6-20020a05600c378600b003f09ff4d31bmr1901691wmr.24.1681391554718;
        Thu, 13 Apr 2023 06:12:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681391554; cv=none;
        d=google.com; s=arc-20160816;
        b=f9XejZyFyIXE7d4no7GpIG9BDtHO0hvVt9Y7Rsz8nnTxPYZIbaRShQhfD8r5GYQyje
         Sw+K5dP7QOaywz/D0qvhqUrbres/IbavO5aqHOJJw49nfFl5yTkRQD0p5crbnDxx9p4f
         +uaE1AAmLYLrvb91RgNXLE10TIioo+nT1FWn47lKrQ65vLW50T+oAbMCVR00r5EW0mhW
         QCS/VjMiDRzriCEl78cDA4ZAo+fKx45poS05WyNUGr9os3bzmwQ5iKole0M3zrFNAkPi
         8RPXE38kipJe67jvdlk4RdF8J5RbIh6d/NsKAPj6qOxItkYCBx5rv4yUkkAD1BI1vzZ5
         AtOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BH4qKloTg3p5myDfS9qJ+XOa2IgLWTGcxSlYlXSqJNo=;
        b=V04GGx4QSx/onmVnaqFSyesFkLyL32m2GuO+KHbRzM7WU3TMufJlo08HTdJhQDQoen
         E7gCl64bxNtDSShsbGJuDLAd99aG4ZLTVnlK+n/W9U1juBAUGo1ZQV0zFnc+oXE0bG4g
         swKN+RTniCnCc1T2ZBLF+x26KVgCKpLGKHwqTopjKfgkXOgnfsreidDrlAX6yWeRoegK
         akMpm1zSEg5yaVl2tjZs4nbNKjgGoYLPlitnR5rxYu7Cp5wOrrPCml+0/FtEj6dsz1Kr
         QpMLM7iWp5vVt6n92gjfI8wEoKPB5Qu43aizWkuDWrQdSS4OtxntxYfC+5CYjJ/0g0OH
         T/6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=D1+Gxpsm;
       spf=pass (google.com: domain of 3wv83zaykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wv83ZAYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id bd14-20020a05600c1f0e00b003f07ed659f6si255598wmb.1.2023.04.13.06.12.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 06:12:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wv83zaykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5066c9c2ed6so460753a12.2
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 06:12:34 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:eb2b:4d7d:1d7f:9316])
 (user=glider job=sendgmr) by 2002:a50:9ee7:0:b0:505:842:37b0 with SMTP id
 a94-20020a509ee7000000b00505084237b0mr1236251edf.3.1681391554378; Thu, 13 Apr
 2023 06:12:34 -0700 (PDT)
Date: Thu, 13 Apr 2023 15:12:22 +0200
In-Reply-To: <20230413131223.4135168-1-glider@google.com>
Mime-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230413131223.4135168-3-glider@google.com>
Subject: [PATCH v2 3/4] mm: kmsan: apply __must_check to non-void functions
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=D1+Gxpsm;       spf=pass
 (google.com: domain of 3wv83zaykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wv83ZAYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Non-void KMSAN hooks may return error codes that indicate that KMSAN
failed to reflect the changed memory state in the metadata (e.g. it
could not create the necessary memory mappings). In such cases the
callers should handle the errors to prevent the tool from using the
inconsistent metadata in the future.

We mark non-void hooks with __must_check so that error handling is not
skipped.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kmsan.h | 43 ++++++++++++++++++++++---------------------
 1 file changed, 22 insertions(+), 21 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 30b17647ce3c7..e0c23a32cdf01 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -54,7 +54,8 @@ void __init kmsan_init_runtime(void);
  * Freed pages are either returned to buddy allocator or held back to be used
  * as metadata pages.
  */
-bool __init kmsan_memblock_free_pages(struct page *page, unsigned int order);
+bool __init __must_check kmsan_memblock_free_pages(struct page *page,
+						   unsigned int order);
 
 /**
  * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
@@ -137,9 +138,11 @@ void kmsan_kfree_large(const void *ptr);
  * vmalloc metadata address range. Returns 0 on success, callers must check
  * for non-zero return value.
  */
-int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
-				   pgprot_t prot, struct page **pages,
-				   unsigned int page_shift);
+int __must_check kmsan_vmap_pages_range_noflush(unsigned long start,
+						unsigned long end,
+						pgprot_t prot,
+						struct page **pages,
+						unsigned int page_shift);
 
 /**
  * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
@@ -163,9 +166,9 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
  * virtual memory. Returns 0 on success, callers must check for non-zero return
  * value.
  */
-int kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
-			     phys_addr_t phys_addr, pgprot_t prot,
-			     unsigned int page_shift);
+int __must_check kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
+					  phys_addr_t phys_addr, pgprot_t prot,
+					  unsigned int page_shift);
 
 /**
  * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
@@ -237,8 +240,8 @@ static inline void kmsan_init_runtime(void)
 {
 }
 
-static inline bool kmsan_memblock_free_pages(struct page *page,
-					     unsigned int order)
+static inline bool __must_check kmsan_memblock_free_pages(struct page *page,
+							  unsigned int order)
 {
 	return true;
 }
@@ -251,10 +254,9 @@ static inline void kmsan_task_exit(struct task_struct *task)
 {
 }
 
-static inline int kmsan_alloc_page(struct page *page, unsigned int order,
-				   gfp_t flags)
+static inline void kmsan_alloc_page(struct page *page, unsigned int order,
+				    gfp_t flags)
 {
-	return 0;
 }
 
 static inline void kmsan_free_page(struct page *page, unsigned int order)
@@ -283,11 +285,9 @@ static inline void kmsan_kfree_large(const void *ptr)
 {
 }
 
-static inline int kmsan_vmap_pages_range_noflush(unsigned long start,
-						 unsigned long end,
-						 pgprot_t prot,
-						 struct page **pages,
-						 unsigned int page_shift)
+static inline int __must_check kmsan_vmap_pages_range_noflush(
+	unsigned long start, unsigned long end, pgprot_t prot,
+	struct page **pages, unsigned int page_shift)
 {
 	return 0;
 }
@@ -297,10 +297,11 @@ static inline void kmsan_vunmap_range_noflush(unsigned long start,
 {
 }
 
-static inline int kmsan_ioremap_page_range(unsigned long start,
-					   unsigned long end,
-					   phys_addr_t phys_addr, pgprot_t prot,
-					   unsigned int page_shift)
+static inline int __must_check kmsan_ioremap_page_range(unsigned long start,
+							unsigned long end,
+							phys_addr_t phys_addr,
+							pgprot_t prot,
+							unsigned int page_shift)
 {
 	return 0;
 }
-- 
2.40.0.577.gac1e443424-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413131223.4135168-3-glider%40google.com.

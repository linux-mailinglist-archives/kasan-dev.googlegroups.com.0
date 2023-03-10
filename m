Return-Path: <kasan-dev+bncBD52JJ7JXILRBSHEVKQAMGQEJMTG3OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 678AD6B359C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 05:30:02 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id p9-20020a17090a930900b00237a7f862dfsf3710654pjo.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 20:30:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678422601; cv=pass;
        d=google.com; s=arc-20160816;
        b=OR/i1NAlKBLE35reRJKvgOVmKH9pOMeZ6puxepCcL4G4SNzj8RWf9+z2tZU98Y4TTz
         iJhqif6ET2OoHYuDdt9cRhZnxZ1+QCWC2aEiU9PCWqnCdE0l5pHwLYlRYuCvfCg9xfBN
         ZM+RvAD3nb5TpI8xpl5FNYwRxHiEU6n4+BbWRypnbLGnwdONuiPKvHvfFU7FtTpu/0NQ
         3uo4dYt2JtgQawCMfujVX7U+wzthhCnX91JboJTdIssC+P3nhov5AWaU1cgccXfustkf
         Q5352achfrmzjmthwlpY150sRG2MWKKAsHIZv2g0jZidQF8pE6mV62o69AxKaD04sP2j
         KT2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ok9ddsvImZQ8Nyk+dpfjSJzt9tWbAivA7YaUZCXmo2c=;
        b=zPFbALBM0E2po31l0yy8dEkWvrN1B9o1ZTw0YfLm+1f31bWPyraXJe7ajv4GN934bx
         /sZppyW/u2VpUpWzE9mHnuB49JwW+pV6ppooOVqXgyu7XVLC0PsZLEIYO04cKPCfcUSV
         OX1pYdjRGsee08vFOjHpV7+VFP2Et8HFlpGUjeHVzv5DkZ+gRNj1i3+05tYh81lRQSpC
         Q1Xp93kfyJUKFyMzDbg4a/tLzRf5FF3GkJp70BOHUjZ2HKfD22oxXZFdoch5ekmf84VR
         g8Ef/961HEnc28qez3vSDNrCk3fb2JawJlKR7NoL4uYHcvsAcsHvtv1lFJaCmWI+QCKw
         RLYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IUwzYC9Q;
       spf=pass (google.com: domain of 3r7ikzamkcfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R7IKZAMKCfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678422601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ok9ddsvImZQ8Nyk+dpfjSJzt9tWbAivA7YaUZCXmo2c=;
        b=pxd16PEWUjNne3eMMRBXWwcjGGl8VR119EgyLkBKMSi18bkA4rD33UXJ/+08tLkEjG
         X9qyxnO++r52m+U3/LmVAymPdVh6Ilo71MlghvjNOX8TsQaMn/y20p8opEuzng6k3r8L
         OEbZ+2IR71B6bR6RyNyunxn1trRBG00Y9HUb6Don1uyyQwgTJwclO2EejTSessrkC2FM
         zAiVJrm9CsHvrEpO3bqLqU+UhBTPpsKWnnNT6hSHpGcMnqi7Uxh5LV0ZhKzJ932nZHif
         AJwNX3qBogH3CEU4qJjXys2Ck+ffJWpyQb+CFCnJsA4o9P1PAEnCUmV8gPUTMS99Wpcc
         tWYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678422601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ok9ddsvImZQ8Nyk+dpfjSJzt9tWbAivA7YaUZCXmo2c=;
        b=auAcQUzzcspQr4Ca+IglCt2OBqRT7OooA5mKxQdOcq1rv4A7+3sE8lbXRrQ09Djuyi
         SaxTIfJTmxjURyOem2nwlGkhzbkmIwA3/habuM5tU4fgOA2/w2NAk8uMzlHCK2AgPloZ
         ODnFJXDcq/OyVUdh8ldUsTbGz1psyvtzA32bbH74h4/kWECe5gCNspB6T2UQR1fMlpWt
         lFhn/O3VuwW1Iejd4TJQtx5MV1KGbOVX4UK0Va9xjWOn6gk19S2ijMBjbPJh7XFm46JN
         tcBqN0uiI+EoCG6iRdgJJrKr/rMOEjobF1AcyqwkUFEll2B8ZWE75vyw+gAEauJD4bGM
         CdTA==
X-Gm-Message-State: AO0yUKWIVsU3kWv+JUpqYaFgYN237AfcglEFIKnIYAblRv/uanQZH4zA
	VhkRzrYyxWTqP3zSzQscR5dUiw==
X-Google-Smtp-Source: AK7set+IuKQSR+na0bZkPNiW/hcVKKydpTOx9Jj3dh+zQ64U+mPTpSOrTJdZNPln63CiCOfkS08p/g==
X-Received: by 2002:a17:90a:7c0d:b0:23a:8dcf:f5fd with SMTP id v13-20020a17090a7c0d00b0023a8dcff5fdmr7796318pjf.3.1678422600766;
        Thu, 09 Mar 2023 20:30:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4d0f:b0:23a:3333:a3ff with SMTP id
 mw15-20020a17090b4d0f00b0023a3333a3ffls5963002pjb.0.-pod-canary-gmail; Thu,
 09 Mar 2023 20:30:00 -0800 (PST)
X-Received: by 2002:a17:902:c94b:b0:19d:553:746b with SMTP id i11-20020a170902c94b00b0019d0553746bmr29646058pla.66.1678422600004;
        Thu, 09 Mar 2023 20:30:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678422599; cv=none;
        d=google.com; s=arc-20160816;
        b=T0N+7O2TiFzArUTTPk1zONIh5Fyc4e/jvBfxx2lgBMqu2Xxedi2TdDtJz6L1PAUAul
         EjA2bzv2BIc4okh+7Sv/jDfhULQTfQNUddn6dqc2yK4+rCrZunfceXdFhUpD6P/l0e4+
         vLt2+azyJtoPjn4Vy7rgHUfRlPcS6qr2HMBLzRuXU2I7G5zm8zxSyXQgSOW2vOMqD7XU
         u4r/WAlLqxQTxded2mCnxBRoBvz9MHSDRCZRyn5hbqmTKrAOj3vcngl5G/SnJ/rRdAFp
         CMSBlz9BbixjxY7lX8shyO8PXJtGtShicRvHSrnIQHXA6RxblrqeJkM9Da0Jowz1mgVF
         ZOsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QkRgpCrNH+soo+fiEkY3prqCJENxuAn2pQWgX5GFHYo=;
        b=Ial9fNUwd3sQdK9IVUbssJLj57Z+pX15fhqmhCc0cK6hylx01frL/S/GOkJOgn/8xI
         cXUflZtZoBBTZBV6BfvZwiOrkM2/WLcyfwERcBt0+K3yrzrUbjv6BaUtqjh3SKJWDImz
         dOasbQfMT588QYVBV9Puo2sNs/9MToBl/lLSw26MaQu0deAwYPzm89QJ9eVC8XdLO1wn
         AcBWqIn/TPcNcHylWLwYK/+TU5XGU91pRvqWXR715sgbVr7BJO9ouupt35Oty/d2BbAr
         Ul7WDMWTxlchNJ+6tb5J3SiupMqHov1T+xCRRapvH/LRP0EUpvmISVb80zjplSR3NQ/o
         C2Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IUwzYC9Q;
       spf=pass (google.com: domain of 3r7ikzamkcfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R7IKZAMKCfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id b11-20020a170902d88b00b0019cbe03d60csi57253plz.11.2023.03.09.20.29.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 20:29:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r7ikzamkcfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5376fa4106eso41790307b3.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 20:29:59 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:4760:7b08:a3d0:bc10])
 (user=pcc job=sendgmr) by 2002:a81:b289:0:b0:53c:7095:595a with SMTP id
 q131-20020a81b289000000b0053c7095595amr15950888ywh.7.1678422599352; Thu, 09
 Mar 2023 20:29:59 -0800 (PST)
Date: Thu,  9 Mar 2023 20:29:13 -0800
In-Reply-To: <20230310042914.3805818-1-pcc@google.com>
Message-Id: <20230310042914.3805818-2-pcc@google.com>
Mime-Version: 1.0
References: <20230310042914.3805818-1-pcc@google.com>
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Subject: [PATCH v4 1/2] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IUwzYC9Q;       spf=pass
 (google.com: domain of 3r7ikzamkcfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R7IKZAMKCfwtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.

The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
flag from page->flags. However, this line of code in free_pages_prepare():

page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;

clears most of page->flags, including PG_skip_kasan_poison, before calling
should_skip_kasan_poison(), which meant that it would never return true
as a result of the page flag being set. Therefore, fix the code to call
should_skip_kasan_poison() before clearing the flags, as we were doing
before the reverted patch.

This fixes a measurable performance regression introduced in the
reverted commit, where munmap() takes longer than intended if HW
tags KASAN is supported and enabled at runtime. Without this patch,
we see a single-digit percentage performance regression in a particular
mmap()-heavy benchmark when enabling HW tags KASAN, and with the patch,
there is no statistically significant performance impact when enabling
HW tags KASAN.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Fixes: 487a32ec24be ("kasan: drop skip_kasan_poison variable in free_pages_prepare")
Cc: <stable@vger.kernel.org> # 6.1
Link: https://linux-review.googlesource.com/id/Ic4f13affeebd20548758438bb9ed9ca40e312b79
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/page_alloc.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 1c54790c2d17..c58ebf21ce63 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1413,6 +1413,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1489,7 +1490,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!should_skip_kasan_poison(page, fpi_flags)) {
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230310042914.3805818-2-pcc%40google.com.

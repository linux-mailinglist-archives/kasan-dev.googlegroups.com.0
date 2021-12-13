Return-Path: <kasan-dev+bncBAABBKUB36GQMGQEZ3TKHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 452DB4736D0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:43 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id q26-20020ac2515a000000b0040adfeb8132sf8031260lfd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432362; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnTY9jikuxPTNxNYLAU58Bgj0dbDHuSM4ppsZQWkavuet1I3sJsrJS5v4rRx01Lu/q
         1+edkM416xZlUrzN2hF5wvtT6M0vKZ9g2mqf+uiK90wVTcPE7a/AX+jSn4alfIgdDPL6
         D1b5cl9sKbOrA2nJG3MH0sSG9uQWnS+RgUUiL7T5VZEyvXQSxTCPtksLsuv6crZEQj9W
         rpgK8Zav8/f/mMw5tYS1pPEnRfk681qnGgt47wujTey4QJ5Gy/NP1HSW2TcP7F5A8v4S
         psT4EYXMYhE6IIY2TOQrt0CTQ/70oN80Cwjt0nn7ZhptjC6ImDsL4IhohyNaXy41hLeC
         cykw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IwVF77b/d8rJDFGjHoyi+TDMcbD2Ihc4qyw8z0SQqOY=;
        b=qglYq8uzKQzWIek2GVCtVxGFyAG7ZRI4Bh9qRAbgJJmGMDGbFWZjuSTMjeBxTgtgs9
         IirWliD7WZ5o0mXr7YPkgo6KsIxN743HrCxnIWvcQFDZiC9Jx+ydRyUUrp1ahM768BO9
         fFQF5C9zFAnNBkvqfsMyNW2PwTiv/L2Nrvpx0BqVInW7z2M3iPgSGlI+rsgoPGH/u6VJ
         n1ZGIQVpANjVtCXJvurrLvV0ucmuCrxGShy8Ybjd4XkfMSVR+7tc9f5uK96s3Ap7fjWo
         +nSPBnIbEBBaDINGregcCD3uycMtLqyNK24ce1dYL+ThzN/ifwBLRJd9raTEzOEyJBfQ
         4JIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n4IarGd7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwVF77b/d8rJDFGjHoyi+TDMcbD2Ihc4qyw8z0SQqOY=;
        b=X4d6TkWVV8GfpWI80bnmcbFJldLNYcQAlrUlZjHTBknMXp8iXo4XVefvOBSwmQg3BC
         yE+1gKrPX6P4lHm8ycUxWM/L7NuoWR2uT091OVdRjrNgDyEfYDQnQarrypKQFLbeymjC
         WvqOrYQa9ovQOybLHrH+5Ickie2cvhIJGTzDN/jMsTH+Ccf9MGLRpx3Mgql6LQJZEhCg
         ctU2MTacJ9oMo4VhHw/rAcnk8ERewxsQk819CZCYTG/crpIU0x20EHpnaEkKAdTGapEF
         AZ8HoKYET8Jn04KZjAdc5y/Ry0Fva61m4DHdbY0/zHIfT0AAnWMHtjPW4vHHBAu30bs0
         UgWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwVF77b/d8rJDFGjHoyi+TDMcbD2Ihc4qyw8z0SQqOY=;
        b=XZKBXY1dvwTmN2p+jsydKDvNjtnzAUnhjlB1akUfpexbYC3mcT8F0Rjk1KOy75lYZX
         JAR1EIheXGAIUXgVElrAa6skrtS8/Gj7UR7GXYieo0/0gdzQEOekO6ev1M6wiMRFNCqd
         lhJm4cGLIDwy0G73g++T8csGLsT9Uk5e3d+pZFqfhyYz6DCPZUIsYUXmD9R0+pjhpX8o
         RKQyBeW85kUOH0ILf78EhTYb+cKMvu5VzQjNFItWVuL4qREBs8yRf/JJ6ErtODx7WrnQ
         AGiPuVxs7rYLIYT7FjgFgTfH0Z0cycKb9yqGJ2De2caOi28AvjVH1NRi3I3P4uVbX8KS
         2rmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PJqqdYpPX/9JZEPU7z76tOvh7KRtSDZNX99QL+A67IA0jxgZg
	yLToLHZ2KTvGQ+S/D6f7qdc=
X-Google-Smtp-Source: ABdhPJyhRGHq54s6ZB02BicZzBcNZklt0qum1nRLF6fP8xfSOQW5TIUKuPD8zlshXG+JqV2n/ZgaRg==
X-Received: by 2002:a19:c757:: with SMTP id x84mr918672lff.278.1639432362855;
        Mon, 13 Dec 2021 13:52:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1550497lfu.0.gmail; Mon,
 13 Dec 2021 13:52:42 -0800 (PST)
X-Received: by 2002:a05:6512:3b7:: with SMTP id v23mr957930lfp.406.1639432362023;
        Mon, 13 Dec 2021 13:52:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432362; cv=none;
        d=google.com; s=arc-20160816;
        b=HQP4fTbOEZP+Ujs2PmuMyD1jX5bThqs1x0tzfgAtRdJ1I3I/yixWCQ23ZuSTUTzFiQ
         HQ4EPjqhRh48aSrox13Mr6Rae+g3j1Yyyl7IFQsdH2urZDN6LkgUyDltSpMf3Q9LptjW
         8jxUMgShby6kh7/pSQOK70qoOt8ORF2qYOSywjCgRdtsSnUGZ52Z70tPj5hnCRMG3qGl
         sUbKET9EPMBYWNZNo9PMeBv+sWO0CH2T/6KnfIiQzgcmBA33xLZT5NZyU2U6Xo2udQen
         RfYTywmLdINJTLyiwbc1DkKtpPrl/g4/Q5KkSmnxvq7laLe/VVeAsO9CVx1oQpZCtqAR
         ilWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=W+nNbb3pTxbMZ8HlsYjmZQU7bd/tE4UK1EaMgljEPUA=;
        b=a60SwmDMIi1BAw8VyyDP8KDWQonhbP0vB4MewofHb8uvQGZsJXd8yFAOuqVb1kzoEX
         0OXF05LvueocH/ORJOcsO0kmJER+O7QIb2P5Biqmj/v4Pfd12R4CE3Ms/FEr20h10h7j
         zOgRnn2avbGyW0Q1OWb1c96qYEDJSZWzpX/dVirPxPFO+Bgz8wSuH4SCOYsNfwreWXno
         d9nczXjWI6B1b3SZ/DLntYW0WVEkTJ1H84o4eqCKChNXu0LK2BvuCas1Qt2vZ+LO9YQP
         7AkCOaxeOk1+HhTvA2bbMdW43nqwoNGfjBbI3YxXfZO+mqkC6d/36N4DpDFIyPYaklDN
         dB/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n4IarGd7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id j13si593547lfu.5.2021.12.13.13.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v3 10/38] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Mon, 13 Dec 2021 22:51:29 +0100
Message-Id: <d1543b79ed7771b0719600845a74fa72a29497ac.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n4IarGd7;       spf=pass
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

Currently, the code responsible for initializing and poisoning memory in
post_alloc_hook() is scattered across two locations: kasan_alloc_pages()
hook for HW_TAGS KASAN and post_alloc_hook() itself. This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches do a step-by-step restructure
the many performed checks to make them easier to follow.

Replace the only caller of kasan_alloc_pages() with its implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

Also move init and init_tags variables definitions out of
kasan_has_integrated_init() clause in post_alloc_hook(), as they have
the same values regardless of what the if condition evaluates to.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/kasan.h |  9 ---------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 22 ----------------------
 mm/page_alloc.c       | 20 +++++++++++++++-----
 4 files changed, 16 insertions(+), 37 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index a8bfe9f157c9..b88ca6b97ba3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -95,8 +95,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return kasan_enabled();
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
@@ -109,13 +107,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return false;
 }
 
-static __always_inline void kasan_alloc_pages(struct page *page,
-					      unsigned int order, gfp_t flags)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a0082fad48b1..d9079ec11f31 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -538,7 +538,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 		return NULL;
 
 	/*
-	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * The object has already been unpoisoned by kasan_unpoison_pages() for
 	 * alloc_pages() or by kasan_krealloc() for krealloc().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c643740b8599..76cf2b6229c7 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,28 +192,6 @@ void __init kasan_init_hw_tags(void)
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
-{
-	/*
-	 * This condition should match the one in post_alloc_hook() in
-	 * page_alloc.c.
-	 */
-	bool init = !want_init_on_free() && want_init_on_alloc(flags);
-	bool init_tags = init && (flags & __GFP_ZEROTAGS);
-
-	if (flags & __GFP_SKIP_KASAN_POISON)
-		SetPageSkipKASanPoison(page);
-
-	if (init_tags) {
-		int i;
-
-		for (i = 0; i != 1 << order; ++i)
-			tag_clear_highpage(page + i);
-	} else {
-		kasan_unpoison_pages(page, order, init);
-	}
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 9ecdf2124ac1..a2e32a8abd7f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2397,6 +2397,9 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
@@ -2412,15 +2415,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_alloc_pages and kernel_init_free_pages must be
+	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
 	if (kasan_has_integrated_init()) {
-		kasan_alloc_pages(page, order, gfp_flags);
-	} else {
-		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
-		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
+			SetPageSkipKASanPoison(page);
+
+		if (init_tags) {
+			int i;
 
+			for (i = 0; i != 1 << order; ++i)
+				tag_clear_highpage(page + i);
+		} else {
+			kasan_unpoison_pages(page, order, init);
+		}
+	} else {
 		kasan_unpoison_pages(page, order, init);
 
 		if (init_tags) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d1543b79ed7771b0719600845a74fa72a29497ac.1639432170.git.andreyknvl%40google.com.

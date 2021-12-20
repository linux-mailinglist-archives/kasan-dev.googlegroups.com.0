Return-Path: <kasan-dev+bncBAABBKXZQOHAMGQETF22QNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A430647B571
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:06 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id h17-20020a05651c125100b0021ba28cf54dsf1864441ljh.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037546; cv=pass;
        d=google.com; s=arc-20160816;
        b=BERm2F1O6oXMtKWEMM2iMjzvxV7aOpQRvKN+gB78iFxeKYg1U5DJhyCKcbceEKU8aI
         qwHnH7v4mrvmMX/1DzL7oJdAmAmxwMwPayxssyTxg/y664x3zmALuZ1oxgsCa93wwkES
         qwFv6D1rBXQg65ssuwNYxj06JF7lRg09SLg6kCVtTs3M05WE8OSTHbPzzSjUa8gYAPT+
         eJ3guuGTV1MDWnU5EUBojFJhy6tBtmw4DGjvVfXA220g1MO3W1XFBA5eXMtSqFlauYUc
         EItA5wDwX6kvMcg0QLjHGKLJ049e1EMoQiYvgWUJ+K0XJ3kGFttOpBxFucmocIKg2g4Z
         Kxnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=P4/e2omjmUBPRsM8+RGz06IxDSbw8vP9xSmT3DeKOOs=;
        b=WuAbjvs2yLjIE4uN3Tk6Wm0R43tuyGw9fLwNmDQj9yN3tYZU9H/2+Gr61rNfod8sX4
         WWUlDthdliDbuDKj06Xlzs+xXt866WrQgFzBQkcO8DvpHkdaJVfLwVWSo6tVAmhDCJfC
         UYCL393x2ZNNJd0m7SPB7oVtcQHol3QVUSbz7kNOa/nmvFXvPwl+QEigCnPvCF6UAXit
         QYPk4BI1jbZFYOD7oXa9mZBQ2QIiAL+yZ5BDqYVEpDQl6sZB0R8Erb8WMuY33OsSpIuh
         WguhHtFHE59mmSxMQ5MOutU/Ep9h8u6SgDIp2bD1qUeLClIpNwtBGVQ7IC8HoSNHi+Qb
         bqNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HjE3nU9F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P4/e2omjmUBPRsM8+RGz06IxDSbw8vP9xSmT3DeKOOs=;
        b=hKonllQ8YPoppJytoPrPNENv2Hlk2wjWIWABH528F6SsfDukhem5AaxXCW0vhaTomC
         5RByete2IwBT48IWrXzmuksQerVcKgoSh7V2FZ7RjUQlSLDdOud/PnIEtOfjdy4VdZ79
         sLh58cPF3PEUCWP3Ghiz0FbMkwLCZ1rTlm5zCEtuXJZlcqRgsUedsS964uzabign7jrp
         GphKeY+FqaylaHn4Za5xBQOii2IdvcGM2zeMYeB8cg7fW1IixVlaVOb/kadFV2XL6Dxi
         H40sV61yTm2e97M2kTwUVNo7oWdf/uh0rRlSD0r/YTVE9CyEpn9QZgc7f5P/bECXiZEd
         gqMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P4/e2omjmUBPRsM8+RGz06IxDSbw8vP9xSmT3DeKOOs=;
        b=WmoML1QcVUe1FKEmx7tEoaxnGWmBVQNS9B1N3elD/+5P36zBFjSD4VsOwu2ObKo6Q4
         2SHyCQTWDiS1PNfUEE6rhzuGNMmN/0OIUti1nAltCp57Tbido4jZ6bLs/1BNJDgTflgu
         9xQwU/G+lmoA/hus36ctUN19RCeqVFdgxwsryWU6D6T88DOvdwQnzL3fl2CgXSFuWBtA
         6yB6UY5mY0Xx/ODoDm3gEJUNttbppXlN/bv2i5ctwUJXY8GyecPZaCRHAcrkubr6Q5kC
         n00p080d7NoZf3SosTt3ibnVrs5xWu5csE24CJApastJnm3j0N4rAS/1duQxRtK1pGs8
         4ydA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318EAR/OOI5Ch0UI2zMHrdJfr38wjqbkMSLLjY9ixfP+tjpM5vd
	4wA/zHId97K1Nful1sOrS8E=
X-Google-Smtp-Source: ABdhPJzrF93IF9cSWIGYBPEKPx8it5ci9l0M0bP0Xdz/PCoSRKFgMyAin8RFAGkviB+gXunXfnAuKg==
X-Received: by 2002:a05:651c:90:: with SMTP id 16mr64070ljq.1.1640037546218;
        Mon, 20 Dec 2021 13:59:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1112:: with SMTP id l18ls796920lfg.1.gmail; Mon, 20
 Dec 2021 13:59:05 -0800 (PST)
X-Received: by 2002:ac2:5e68:: with SMTP id a8mr128562lfr.201.1640037545426;
        Mon, 20 Dec 2021 13:59:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037545; cv=none;
        d=google.com; s=arc-20160816;
        b=OaHG7ivq9YDqjuhPkIi1LaBmVUi/v4sXMBiaakALnkB2wLV+4VWITMzsuJJ/aCNJEC
         MEAlMa/6prsVPbDH6QAk9hRtHybhZYbD8gVNV5p4kgUOZtFO5K1lH59wk3g0Quc6Ze6k
         ZC4TEj5JbXV57zcysby2XNkprSKq4CeBGtTyUSmBfEeQByNprOX/1GwDa1YTgpVZ4K0W
         Mlz39+2wwLgGE8KaJKggi0xLDskjhXcGnub88oDw3HDgj5VFWBL/u1JHivsUDiz9T6X8
         jA6yR1eyNLGNohemk7UqleRQlXTFKnyaQRfFTRUsLw6+T5aqwM/mYgFiAkSTmx+XuN3z
         n3yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C/H8xEvLFjZpRKDTHcIRqvJZF1FN7N83kytVLUev48w=;
        b=EjUSJqUs23KeHeZTRhxwY1L75OFkUT+y07vR1i9y+PJj8wlUdaqZNv+wage0tZ3pCA
         /CEuugaiIffU2v+PR3RJ2mdicgGcodaXRfdtUemSw/7roSTkNiuiXB950juo8VTPXSnN
         BMeSNvS6FXcYSA8zblh73wPaXTYVdF27KXsrqCcIGd+B89njXKXcw7KoMyO5SL2sjDYS
         waujvVdLsgf/PchqxZZrR7EPRK/bMIzUIuNsCc19IcgHZlUnrTZGVKb5u9H3eft2G2aR
         bJZiLT5JyX0qvV8M6WZyHAPTvW+xaStfto6YoAKeJ2x/Qm8BJRbwz6e3TjuRe28RE8sV
         vW7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HjE3nU9F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id e15si1183546ljg.0.2021.12.20.13.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:05 -0800 (PST)
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
Subject: [PATCH mm v4 03/39] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Mon, 20 Dec 2021 22:58:18 +0100
Message-Id: <6d95dbfdc95fb5f0c60e96e3cc7bc9499ffbc337.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HjE3nU9F;       spf=pass
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

Currently, the code responsible for initializing and poisoning memory
in free_pages_prepare() is scattered across two locations:
kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches also simplify the performed
checks to make them easier to follow.

Replaces the only caller of kasan_free_pages() with its implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/kasan.h |  8 --------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 11 -----------
 mm/page_alloc.c       |  6 ++++--
 4 files changed, 5 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4a45562d8893..a8bfe9f157c9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,7 +96,6 @@ static inline bool kasan_hw_tags_enabled(void)
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-void kasan_free_pages(struct page *page, unsigned int order);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -117,13 +116,6 @@ static __always_inline void kasan_alloc_pages(struct page *page,
 	BUILD_BUG();
 }
 
-static __always_inline void kasan_free_pages(struct page *page,
-					     unsigned int order)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 92196562687b..a0082fad48b1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 	}
 
 	/*
-	 * The object will be poisoned by kasan_free_pages() or
+	 * The object will be poisoned by kasan_poison_pages() or
 	 * kasan_slab_free_mempool().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7355cb534e4f..0b8225add2e4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	}
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
-{
-	/*
-	 * This condition should match the one in free_pages_prepare() in
-	 * page_alloc.c.
-	 */
-	bool init = want_init_on_free();
-
-	kasan_poison_pages(page, order, init);
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 7c2b29483b53..740fb01a27ed 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1367,15 +1367,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_free_pages and kernel_init_free_pages must be
+	 * KASAN poisoning and memory initialization code must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
 	if (kasan_has_integrated_init()) {
+		bool init = want_init_on_free();
+
 		if (!skip_kasan_poison)
-			kasan_free_pages(page, order);
+			kasan_poison_pages(page, order, init);
 	} else {
 		bool init = want_init_on_free();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d95dbfdc95fb5f0c60e96e3cc7bc9499ffbc337.1640036051.git.andreyknvl%40google.com.

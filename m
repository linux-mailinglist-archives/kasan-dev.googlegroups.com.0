Return-Path: <kasan-dev+bncBAABBLOATKGQMGQECVLEDBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4974640EB
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:05:34 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf6595753wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:05:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638309934; cv=pass;
        d=google.com; s=arc-20160816;
        b=bCWrwiuPhN4RSwIa/QVrjcrHWNE3cI8RiO2IAgiii3erc7scL+7Kou6j94aKdT5R9m
         uHH4soM5GKfYbXvOQC99ryJFxFDET2HRLT6p9i7cAbmCYTXwynxOrkk0cev/i1EstBic
         gnfp1696yGehNMjd99rFq+9Jtf1iatzCHwjrsjdj8cFYJjXBjbhmc25qpW2Q/b+5nH6I
         IGuFKGrh38yUI4fk/3b9ziFUi0yDA7/F9/VAQMhAWxaNpQwbM7FYKZBcdUW3JOHZOpJK
         bojporwV2EbEL9hn4311CVqf8C1+5yJHEbqsJvuusSmlHFND98H3xZ/g3MzkEonsPiYd
         R49w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4j4SKMmvxWZDKVzYvApWw3GK2AYacN4ey70E9+F1b88=;
        b=NQctKSpxbXcV6FQ40N/t7XBU3Pro0ofsSNClbcS9nkq8ikF+ApVGoJq7Ul203NjApW
         OAoqkBCvcx4MNyect7C6SLgVog75JOrTlknt2fVHDvCnXhzdmB94ZrLl/Rkr8/rT8FJ/
         76kNL+R+q6vm9a9bxC2IxpZTyifgJEJzrrKykgZ2jW9CPTj1yYkyiIgIoXlYDcZt+Noc
         XpVOK7Fk0arqT7tIW81PZ6yQUGjOcPgw6tQJhpE5MWs1izCy1bQomfDyAlnT0j6gMvny
         kFdxF40i/AM6KZyZKuCoPYW0t8ZYcYkzq9YxL849g8UyC4nNG2Ua1M8Bfm4/QSlahh40
         Gy6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="kKuuQS7/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4j4SKMmvxWZDKVzYvApWw3GK2AYacN4ey70E9+F1b88=;
        b=pKgQUeCzCo4BVsKHUhfjfjW28A+M6cQEW2jZWwqcUi6h07fDJoqrEOH1dNWkeUU6HJ
         CK4rw0w0FKXZhdYy5uDfrFjSQ6zdkVGBGlx+CScoakZvV7ee/aso/2y3ZLhKpcVT6RzU
         6hZXsE1TflHVRjiYwx7hOFExruOolP/jAtPWDosIkgCbCc+rpXXjeTiDfphZ4hepslSG
         7JFeuuqFSnhWxzd9FlSMOngM5iybxY5r1OrShkzfq5RJxB4WWvR4YZ+0WjuhDA7Kpr1m
         DrRgb0zjUmMal50xf5LwTdtnckCGAjj+KaydYnmhqd0YDUNzoKfIukOnwP4VY1FmoJBZ
         TgKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4j4SKMmvxWZDKVzYvApWw3GK2AYacN4ey70E9+F1b88=;
        b=H0MfqbLXgSDbpfAdsalh+DkQM4tWXX/wA0mlhH9ZAubNEyofWyYzWtAM4haYZPs5Kb
         6ijtV3NcDo65kA3hT3muvsR6QC3G4078Zg25U+Hzihi0Vhy4C+r2aOvSvkKgt5w40d3y
         8gqU2E4ZhtKJ72kQcbUgqq2sjy0fKwfcJskwFe/wcoStLLoFGvKpAacG6kYa/EA9zGca
         Zzhn3jOtUzcHlj5Tswr9Dhdq8KCJxoqo0/rBwvpJGNv9r+6YX9Kc2k+4K36TG8ZtbGUJ
         cocoMBPD3f42HKzcFRSKQ4ovibpVd92qE5GCu8tBiEy3tgwOwqlRckW07NBV5A4AxOtV
         NbyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CNNhSHUFcQGmFaUNJEcSLQRM2Og+HwEbF3uyOyl/TzDqxzJPR
	SVG6paRN1eBCiC/+HMQkz2w=
X-Google-Smtp-Source: ABdhPJwhIZno0qmKTd71HL9NIM6ajNhuc5KoiECjojnIW6afxBaXECW8j7xyvvwrWOwcONg/D0ek/A==
X-Received: by 2002:a1c:1906:: with SMTP id 6mr1790710wmz.19.1638309933952;
        Tue, 30 Nov 2021 14:05:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls2133574wmc.2.canary-gmail; Tue,
 30 Nov 2021 14:05:33 -0800 (PST)
X-Received: by 2002:a7b:c2f7:: with SMTP id e23mr1816944wmk.92.1638309933211;
        Tue, 30 Nov 2021 14:05:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638309933; cv=none;
        d=google.com; s=arc-20160816;
        b=Bds1dsTaYsNXxkQPACDkER7M04VkVc+honmWlBHWo6Yh+QVcR9mrqv8Hz03uCJonp7
         kVz5wID58KVlSFZPhCstXTHSvySZPc4JcXplyUCwNOXrlF1VWShblheDoqmKv4d3M+aU
         11rqmTbStELpuCPmIto+mLGceQBkJWfjlTEKigjuQjs9DmdKUtLPvaKCi6qCRq7zbO60
         W8V+bBVU84bQhacgbTDaT7MnyFqQTUZ5RTZyc+KZrhlYObty+QtAfPFUu4EekWvyME7S
         IVx5Mm/ajIVAtyIYjH5wLjyWopNY97AsfwyILx7tYbjNrQuXyct8RPXwNdcIXKIHTHCp
         4YMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QgrHb09Vj6aJ0+9nbQZNm9kk14SqendbAdApMN1ty98=;
        b=ydDH0aSv09LFXHKZJQrpjVYe2kpM+vZjyrfbzYLsYmP2g+Y8a5u9Nl618iDEXaF+Un
         kVYCmCdh2L9eQnKV4BWAjDsFiTgCY18yvj65/xL5YIIH3Q4KUByP9jkVLyLbOwPRiO6z
         CQQGAm26PGb95fEyrmNt0/EqSRALPetNZiUcAts1fmm/a4320dJyKIbvafWiJKE8wtXm
         +7ZpghTrg2KrQqGTypWydfcLKgr/Ago/sQZ1sq9UW6hJRqcsjZ22QMits9BVnr2M6F6k
         GvlzzWDDFYCueJm+YwUDFHrDjFAAK+iYTbdg3gjvU7ueyDJMIDtXQrLIxdJD3RwXBQrG
         XvPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="kKuuQS7/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id 125si538749wmc.1.2021.11.30.14.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:05:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 13/31] kasan, page_alloc: simplify kasan_unpoison_pages call site
Date: Tue, 30 Nov 2021 23:05:30 +0100
Message-Id: <4e23fb3399fbc2bd59effeb89946a75c3c75b6a2.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="kKuuQS7/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Simplify the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the simplifications for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 17 ++++++++++-------
 1 file changed, 10 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index ba950889f5ea..4eb341351124 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2420,15 +2420,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (kasan_has_integrated_init()) {
-		if (!init_tags) {
-			kasan_unpoison_pages(page, order, init);
+	/*
+	 * If either a software KASAN mode is enabled, or,
+	 * in the case of hardware tag-based KASAN,
+	 * if memory tags have not been cleared via tag_clear_highpage().
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
+		/* Mark shadow memory or set memory tags. */
+		kasan_unpoison_pages(page, order, init);
 
-			/* Note that memory is already initialized by KASAN. */
+		/* Note that memory is already initialized by KASAN. */
+		if (kasan_has_integrated_init())
 			init = false;
-		}
-	} else {
-		kasan_unpoison_pages(page, order, init);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e23fb3399fbc2bd59effeb89946a75c3c75b6a2.1638308023.git.andreyknvl%40google.com.

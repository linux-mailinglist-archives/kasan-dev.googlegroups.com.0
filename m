Return-Path: <kasan-dev+bncBAABBWVUTKGQMGQEU3L2O7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 37C6746405F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:43 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id k7-20020aa7c387000000b003e7ed87fb31sf18280427edq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308443; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMjF52e3birqS/rkDBWGvYLqripRmkBua17KoHPhVmU4D9wYKASAuNptlUuLNfjyhf
         PFbYe8V6HZ8rMcptrJZ13LQhlhn0fpfIwh3ZV9ZnfaVi3vXJxELZrIo9GvEVv9I6xIxF
         EC40TU6M69x2+FB2WvY/EsztD5Ey3hMDgnEEcFPjbMX1AlTRnG1++Bxzvfpo4is2F6dG
         YIP1+YcTdBYHXAYV69jCJ39R1guRLfjnLOCa1C2BTs/9nokG0fE2nqHVwp89ekS4ERf5
         7NiKWvKODwwE2aozHJCkxERriaiFpXplcCnn2vL5mEb1bg/EKWQtp70jHaqVGuUkTg8a
         ZMsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qJ5snY3bnTIvTI+Mi7huEaYFi/UqQLxw9OKlpSRrPGo=;
        b=i57DDFtLUP8ceIhI3H31LTGr8RNlvA6wO7vZBD9+SgDS3q6YRPxQXda9pi3E0zRNZn
         JAza2ci/vFb2f/FsKiMtlYwSHl0BdoKMBLlAZs/vYaNmIOqJlQ7p4pPLI9f3vhoNsq+u
         IQOUqUmH4np/1gWn7qdiDtaye0DVoTiK2yITn/ZaroNh28MMuM+NBaQH+axkqGJkb4Nf
         zmmnRpdeEY5f4ssN9LbaW/ImKDekGScjeyr7xQTdILa5I05yJhBrl5pgskdJYrhVqPJ3
         TPAS6GojM1vfgCRKNKXh2iNfcK+fm0ytw6sopz8nBN5M3ld5S1UC0yBHb7Bzwg+JbZSt
         ZOyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJ5snY3bnTIvTI+Mi7huEaYFi/UqQLxw9OKlpSRrPGo=;
        b=IIssw/8j8fPI4pR+kMRH5RkPMngJwu6Fs27JH7nMX4sn9J4sS8vpZsoKIqhR2rONzv
         c6c7VRviv3nrAH/MAiLdqWcGdP4bY1S9Z35cNADsJxYqUHtyjpIp5bYIZDxchHgjuytB
         nhNY3TWKplsPeZwzBIcab1/pl0AJPW0ExrySzWeErXlw7lbZV+fLtQ6yB1PR/NZw4rTe
         LbsMB7FQbcMK1IFLwR6gWW+ZmHJoYFVo/TcNh5/WzFD3kC7vsZ9/2OC2jcVX7I3BMbsv
         eD68BBONBWqCV8DgTwii2JjD4uSLp7nFzAvrRSx3ExhDVmuuF2Qnw4OqSmdsX8zLC98c
         1wzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJ5snY3bnTIvTI+Mi7huEaYFi/UqQLxw9OKlpSRrPGo=;
        b=nefnmjrIHKqKTQCD7OO75Xs/c3eh74pS5J7rT333BBVj6WeveaYWRhgWccO9IudFqe
         XIDQiadSQoJ57Vjuyec53sb1j2HW9JObfy3ay2aXTzsdQ0CnvH4obO/sUG6Td0cQS5po
         005l/giUwJGJN2EypxMGiTVkNqVV4vnvSrpCQuw924hXsLVEGEQtLo/Qykd6rEwszoWg
         wlLg/ELSb1ewZW7p+YlN7EojjcECd6ivI9YtYyr8N2enQEO2pIA1nLtVlOEM8OL8mzES
         wQjPiAtah66WbnJTFf2jnLCcUZvZccwF+FbrmiDzpaRuY0VlyJVNx632/B5TPEcBEWA5
         75zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336hfeWD14ypVuviF+wvJSg1dwdmrDWvI3ruwo9+GGaRkEORZfZ
	gJx1zBpW96k0XELPo+9rrEs=
X-Google-Smtp-Source: ABdhPJxgggHqONFsN0WbyQbBWABwyrSZ8gd2YBQA5/rImXcKqSCdRAMISRrQCddUmaIoPCQ37+Kp/A==
X-Received: by 2002:a17:907:3f9d:: with SMTP id hr29mr1986527ejc.369.1638308442951;
        Tue, 30 Nov 2021 13:40:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c517:: with SMTP id o23ls182448edq.2.gmail; Tue, 30 Nov
 2021 13:40:42 -0800 (PST)
X-Received: by 2002:a05:6402:1d50:: with SMTP id dz16mr2271083edb.309.1638308442210;
        Tue, 30 Nov 2021 13:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308442; cv=none;
        d=google.com; s=arc-20160816;
        b=GW7YA7AkFOPzVb8M7ukKfyaU+MxSQ4eerEW40FfW7Rc2SGpNB9mEeM5I/QEhP+YUYJ
         rQnFOyJpst+h5iQ+Omzrcf2mrBNc5o0QA2ZjWWFo7i8yVkjR3hk+hDCq6+GEX0qv5ebc
         GSCVtZ8O8q+1S1ow8C22bX1JThVa0E7lsGTD0tq/J+Firwsq4JpFop52RhT6y+lct1BM
         urxwW3TNsU0mUD2TgYAVwO9v03L1WUqioWI5/hKQXlPiXHoYLTyyyVKyrccb30mTMPWE
         mWvDCHFhOWPwTmFckklrAl5594DDjl3wQJ51LWxDbYwGm+YL/+TtYQBE7TWO9aNjXnJ2
         /zYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7I9HcsQmkK3mD5Y0I4zfPlHF+PCd5E0HGcChO8p5mho=;
        b=Y/MfTAb6bAsvLV82YsWt/bQwLsrw9FvCQSUoX7jFaa0tPFDFAehV31OtWM4h3W4G/U
         01LzQdpq3jqQEFVGtD/jSwUZ8ZKQ9G4q/u6WHuNG7g6/TSW9ydVSWwdcU3RywoGOp8r5
         pblRk1JZExKyz02sAf/JJWODDhM0cnqK6840yEsSETq/ngxUc17BDsw0D54SoYCGzNLj
         /eElYQ5K4xa1gmbsQQmHehI73DC9SBQgzYGYK31SSMQUzHyRbQE+trQw4yydKaKE9Ga9
         J7/V7pU4s23uFUfpj1lYXzGWeFPIYN67VNTnprTmg08U2EF5gFLrO0eygWnzoDaqZmnj
         N4+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id i23si1084816edr.1.2021.11.30.13.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH 02/31] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Tue, 30 Nov 2021 22:39:08 +0100
Message-Id: <e64fc8cd8e08fac044368aaba27be9fc6f60ff9c.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Currently, kernel_init_free_pages() serves two purposes: either only
zeroes memory or zeroes both memory and memory tags via a different
code path. As this function has only two callers, each using only one
code path, this behaviour is confusing.

This patch pulls the code that zeroes both memory and tags out of
kernel_init_free_pages().

As a result of this change, the code in free_pages_prepare() starts to
look complicated, but this is improved in the few following patches.
Those improvements are not integrated into this patch to make diffs
easier to read.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c99566a3b67e..3589333b5b77 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1269,16 +1269,10 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
+static void kernel_init_free_pages(struct page *page, int numpages)
 {
 	int i;
 
-	if (zero_tags) {
-		for (i = 0; i < numpages; i++)
-			tag_clear_highpage(page + i);
-		return;
-	}
-
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++) {
@@ -1372,7 +1366,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		bool init = want_init_on_free();
 
 		if (init)
-			kernel_init_free_pages(page, 1 << order, false);
+			kernel_init_free_pages(page, 1 << order);
 		if (!skip_kasan_poison)
 			kasan_poison_pages(page, order, init);
 	}
@@ -2415,9 +2409,17 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
 
 		kasan_unpoison_pages(page, order, init);
-		if (init)
-			kernel_init_free_pages(page, 1 << order,
-					       gfp_flags & __GFP_ZEROTAGS);
+
+		if (init) {
+			if (gfp_flags & __GFP_ZEROTAGS) {
+				int i;
+
+				for (i = 0; i < 1 << order; i++)
+					tag_clear_highpage(page + i);
+			} else {
+				kernel_init_free_pages(page, 1 << order);
+			}
+		}
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e64fc8cd8e08fac044368aaba27be9fc6f60ff9c.1638308023.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBAABB27ZQOHAMGQEECWI2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 06C5447B585
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:12 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id p19-20020a19f113000000b00425930cf042sf3465972lfh.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037611; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9PVE5BQPmIxaU+OUA3cfDYN+XN3GXjjPjK+uW8wOAiqDCh9vGwFC4MNKNUkuO2IsQ
         oeJr53XrScMqjuesxjQ57FSRh6ji3cm+vftkZH7svi82OHbhJvMaZZqXrpzgL6fF/Ia9
         3bxVWFWX6Rp1JoyHE5/0FKPQJhj0IBmsx6ZqyuP8Wbbm6RDgFo8nkuyhOhQZRgjjVnlC
         j6Q35rl6bAEZ4uZoYklrVVV8zbEI1lr+ajZOmB3q4gbn+eL4X+9eT+UXbsj86Tm6Dh3r
         Ag5YabZL9c28H8BsgS44ZpTx1xcviz6CiO9DEjNa3kK0UOsFrnXGEAM43LlTy/W6L/F+
         YHJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yo0xsqCNnyqSNyObBFqidfkt769bTToO7pd/gsdcDc4=;
        b=NIw4ybklDz7HC0d4hDA13Ke9i68PhUdFc4PB5pmysI+VjaC8cPeupDKzTnF2x+4oou
         nt8w3Z2Fp526ihNIZV/R8YeTCMtpzAEiKfTCnigiHE2jtvGuUe+0m3JHaSaa3jFo955l
         6mRjpBCIXKvSlzcga5vY9+SGFlavJU4ZBbD3cxnAqMx4tEXXoly8pw/nMt4dXNECM7ud
         havjEEtw5gJpK/JAD+orPmVIvTbjykXhqX3LH2qgtj6VnO3N56R9V6YmcDxvD6/Yce4m
         Cb0fCZefQIdhIIIZSj9s46iNkFPv1wo8BxVt+ultEbvfdkbRPrHX2Q+swlbo+oojlE2r
         iVPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="WhLbP/3o";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yo0xsqCNnyqSNyObBFqidfkt769bTToO7pd/gsdcDc4=;
        b=RTQ8iZnNK3mOzmT3i1lhcOOGWqyZ/oCN+w7WU4m58+0KV0nvfOfLoQttIjcVj2M+5w
         Prt3UtNofESJyHAmDMUoyMFCiR6Z/ZLHlUjF5pt+1hP/GSLtsu0pBgJTw8DUZWTBir7/
         36hKpdKSzyGjfgRLVSxL6xXSOwyGC+VWyHnUwLbYLb2tfYkgsMP/hhPMMr0jUtHbUEsH
         jzYG+Tr5ug+RFs+QVIMexGGr45S6+TVcvuRr4CGPtz0R6lVdR/E9I/Eypsb/WV04lv0h
         C4SW/FKc8C56w8s9JAaUQ5/cJnQeCaEeEdO/KvYyqQKO/0JEqTx4D+ZCW6kpa/rWGCon
         2vxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yo0xsqCNnyqSNyObBFqidfkt769bTToO7pd/gsdcDc4=;
        b=Z2n3yXnisJIH2UTAhupMzUfqGJBn8fmJdtvlV3qm+T0yt1jegrg16Qoi8RRCXwaZDr
         tTa7aaO0cOlSt5UYrDPIAVm+oBwA3kKzurWMxeijcqlBmRuPhzKVvS34J1YIRBOzi6bn
         6IKDc2WLDWnoPcw+8EMbLCP6r8a4ogRfr34JKEs+ZI/alezKKRPtDIMjppZJKSk9J0gL
         NnNRolp12F7k1+HeWyJtRsbuHsoqNDNrWgPWkOeWRA66DJPeBEBes/PV3p+kfKOxjOh8
         9Js/g1tsDBXiL6/icRG7OTIS3pkS6s6nxYmz9fD3KufATNvc/Goeach9ot7iAGa/aHYt
         Y5lQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Q2B+E/nGfJFYryB+9R0zyWgvQH0n7c6MQcGjwXRHR9x2K7H1V
	qavjjsPbPt7eR7ra+0wcLjc=
X-Google-Smtp-Source: ABdhPJwWNjWdb/YJ7lDG6qbHv2Tcv7bTiH1ww3bBafLFE5pUl0sINxRFTPmqAvEP6nObpqy1Gnxdmw==
X-Received: by 2002:a2e:a913:: with SMTP id j19mr58785ljq.205.1640037611493;
        Mon, 20 Dec 2021 14:00:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls799498lfu.0.gmail; Mon, 20
 Dec 2021 14:00:10 -0800 (PST)
X-Received: by 2002:a05:6512:31c2:: with SMTP id j2mr137325lfe.95.1640037610709;
        Mon, 20 Dec 2021 14:00:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037610; cv=none;
        d=google.com; s=arc-20160816;
        b=a9wuTNN4lijgq1M5M7wIGu03Bl9eikt87GgyvCHPHVXoXo9rTWqFIqVGQ64d0jlhOH
         0PzY1Hb9VPoRICSXecVe57oriW3TABVPlJyXnkXq64AUBMOalL1fvty3jm7rp4t+VKWl
         DqwMUerVO4wBXhjQHQBBGHBV7cT2al/rtth3tnAt2D2O7z8LNg0Z2pYXprpZ6JyqSg17
         fzklfTXQGkzYzDoFq3b4SYCFHuovhXuLB5IS7xsxqNQnTyZzvFVfBul3OaLlZR93uSB7
         qTyErYNp3hvD9R4D7phSZDygK6KQYWzE/NYdt5d3S29IM+1G1anhA3cfB+lN4N4atoT1
         hk9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MBXf/nDIJH3lBRK2HYWbLL40X7GriSLmrG5CxAxbd1w=;
        b=Y2gpvePGzGAC45Xld3b4eCHRgIKysItVqGbpTIWvL9zpux2kVG5vjjE+E1+LVIZXiy
         f04oPzes/iMFIvM+QvZ+tmbbr139io9hemKDU5MtI+xF+5lBFUvUooy+JzU9pVCGvV1Q
         nze1LfibZvB4NEZv7mgT08KfZn2NPgtDbojCsT9UuMLtzbu1djPUt8NBfgxSpHE3DA7b
         /4PIe4lobu/QBIYamWFScd7mnG7bozfVuGZgOo69IVlNx/RKx7AToNmFljkRGwO5w1Xo
         wsrLSmzLdh4OhJ6g7W0QZdL4T3npq8iZG7VaV70uIbwKTl2NVrXY1ES1b4vZZtyrFr9m
         lF8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="WhLbP/3o";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id d18si882879lfg.3.2021.12.20.14.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v4 14/39] kasan, page_alloc: rework kasan_unpoison_pages call site
Date: Mon, 20 Dec 2021 22:59:29 +0100
Message-Id: <a33a9623f2d239ce0ed659f62fd9b9109e8433ca.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="WhLbP/3o";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Rework the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the changes for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Make the confition checks more explicit.
- Update patch description.
---
 mm/page_alloc.c | 19 ++++++++++++-------
 1 file changed, 12 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 205884e3520b..2ef0f531e881 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2433,15 +2433,20 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+	    kasan_hw_tags_enabled() && !init_tags) {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a33a9623f2d239ce0ed659f62fd9b9109e8433ca.1640036051.git.andreyknvl%40google.com.

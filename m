Return-Path: <kasan-dev+bncBAABBFOUXOHQMGQEF6DZEMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BCD324987A6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:04:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id w5-20020a1cf605000000b0034b8cb1f55esf15366658wmc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:04:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047445; cv=pass;
        d=google.com; s=arc-20160816;
        b=TYOhRYNz7E7LOST7VhjQs+s5uymvZj0oLOgMPk7HFLC8qFMvHcseEVy1mS2TktW2VV
         QPFqxEH/rIzXx/Up7lWePyGOwo+xZZb+AqcRnSYfacI0g5Aa0EcAxdBwgCrm/IS9g52f
         mHZzUh1om9M5b1cPSo+5RfW+cfRXbDRn8EqRwOP+Q07eBSBW/+nvz+K3ErvsuqXBQ1te
         Gv6TJ692vzwn8FXI+3LDxd1qqi8sz9gSEuHCHcx+ETFHqlOXQBEm2HFLHK/7zDj3VWIU
         wCe0UGmN4fhIf7r/N78j9CnROJtvNzWoyZ8nxq8q/8kqbuCJ1wQw1gSriZ1lBeGfM0To
         1SrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fQRjdLozYNHAQEzoTO8vTi81nXi/hJGN+vixi1IViAs=;
        b=Fmfm0SjUOyBkp5/jwGP3cPyA5MKHL9BWqrEhNRvyFLjfdON/0W2dj+rjhix35z6dQx
         A9uei96ipzKvN4U0gykU1bC342L/b0sK8f4ApCtr1vqaoC4owoXI0j8tPid1nRPNoxNn
         077h2WSDOZMSnsPcP6jbzF0ncPan9KkhwvcS3jbpMya6C472oBBo64KUmtAOwsEtFuJh
         tA45qBnJ7cbvTYemnqIy7M/um3QNivirbbfFs6gJ3xFns3NPd4n3o/xwOxID11ibtOeZ
         VDoQS+TE08rZdfZYBu3xAlDmOzMOrDWF9CwTP97Mc52oq9NnQ+dwWovKTovzJBJcSWft
         /syA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eV2kpwR8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQRjdLozYNHAQEzoTO8vTi81nXi/hJGN+vixi1IViAs=;
        b=i0fTWd20+F8Q0S7D13fz1f+pTmlUngJd7GAB6rkwJDGOXGLC2qd4+3xse/uQ52FXhj
         mlsyIP2iTbfLuA+RmKGCFxhzFKni30wN93m1OVhIpsN0XR9/9x2A+upCTiMvdavTZotp
         MPdFiO9DoifiDOKXxCkkLcoZDVJkYJV+kykNbvIpmJjiF+/z+EeJ7HenQ/mhEOTke037
         N0UPGeWf+1PTmdp4FLvplbjyP87LsMUWi9nD8wN17JT8tzKZd1eFlGf4Y5EgftktfFKA
         ZF7HUI5d9kgkVYBz8LlELtQ4uCzepySEudMeM+we3ZvumZEqybXg+B7S6pqY38v0DaHE
         nZ3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQRjdLozYNHAQEzoTO8vTi81nXi/hJGN+vixi1IViAs=;
        b=YYglAHyed0gI5EPTP+RLqJ0tPQxKrb9nsc+4G8kFgH56V7/eHZQFPSZ7J2+iZoBhgN
         W8bTQdqoR2eNchSAhzU3gK34Qmsxp2cYeoApRzy+PSfU4CxNPCI8YymHboo0QJ9zKT3m
         pV2eCLjBXcwqzOX0HyzsmGqfTscPzc8+I1cQ9QgVyG9y2BcPa+wa1WtnlHId9ZU/hpx/
         P0HMLya/yzcHLNF7TzLgudVLtJhkRgtr6NaL21rz0nH2LuEzekTzLtkSjnUAY9cIYTVK
         cAgnqfH5RKa5ch9vlKemLSg6p7ULg4dnR6+mcRpquq4WOx9qclQH1Txt+b0/MemtuRe/
         rfNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cTDrV5LasXza1bzc5gYAv4qtQFpKWRqgRIQT0b8xtitqjpUlt
	iWr5ivtPLwACH2aXhxU7tTY=
X-Google-Smtp-Source: ABdhPJyAqNoRnaJW8uC0NtpGjzTcs6R2LRCPNavO+ZUUvr/fY2rG1UNgJGkgjGNv+EXPhCDlDN2LGQ==
X-Received: by 2002:a7b:c76e:: with SMTP id x14mr2859784wmk.12.1643047445499;
        Mon, 24 Jan 2022 10:04:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e390:: with SMTP id e16ls291326wrm.0.gmail; Mon, 24 Jan
 2022 10:04:04 -0800 (PST)
X-Received: by 2002:a05:6000:18cb:: with SMTP id w11mr15284343wrq.292.1643047444824;
        Mon, 24 Jan 2022 10:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047444; cv=none;
        d=google.com; s=arc-20160816;
        b=Yng5ZJOFWZKFEil5aHk9orfk6ObgNTE1NxPUfnUyvOKRV0ur45I6MdOmOPFzX8gEsg
         CGwPS7yOfTr4LBxFoNxHUsWFYX4QLdw4Bet+oCWZTXStHyQHGiRYad9MtuYCvF+b4kqc
         FH7QxYVajyfuovTIjgm25OGlyHJvRUwlYSTxy4d1qHc5Dc5+ieYDJJFTSuxhCbN1o86G
         fLW/i9BNp7KAY2Z06RljG/cbFjguQpjUzRqLed1lqI9vosuUwpsGwEF5kY/FB2HrEVeX
         SIwdrDXkHkEtrxf+u63hLiPCQhnOSC6JNBEoCUG6BZypKnORzcjHoDPMsnj/kyG6Wbyc
         cNig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yIiooJ7Br0briWEQqZ6uPYrewTQt0yFaU3FLKd4NjuQ=;
        b=BMEBgAh4eq7bU6ibtQV6bd7YXvUsB1XAB1DQUAlbnmCiIKni9Ju6W4DOjzk8IVhtKn
         pyzSBjM/UFNkujs+bJMNcmzD4jng1TSdJpQTLhFRE6+WI2wU1oVPsgR0ljb5wp6duK+Z
         LgEW/r8v5jzFUbvhFB3Q4TgWIEycUMHpl1hXe2EW0cgoPYMe4b53YQf72WaIncOu/4Xu
         ElgVb3sSKa1CMR9UWS9dXqWcDx2i2LRZ6JKpULUsvegeQbc5JDNupj7CCk3IZ51qpCXv
         jVX7FkMzrsKlQBR+dQEEJ+G7F8WI3tOJ+jwel/CMmgumWRXQ0tXSebwQOX8x3Lcd3INH
         5eRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eV2kpwR8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id ay18si232239wrb.1.2022.01.24.10.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 13/39] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Mon, 24 Jan 2022 19:02:21 +0100
Message-Id: <a7a76456501eb37ddf9fca6529cee9555e59cdb1.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eV2kpwR8;       spf=pass
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

Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patch.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/page_alloc.c | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c51d637cdab3..2784bd478942 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2435,14 +2435,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (!init_tags)
+		if (!init_tags) {
 			kasan_unpoison_pages(page, order, init);
+
+			/* Note that memory is already initialized by KASAN. */
+			init = false;
+		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
 	}
+	/* If memory is still not initialized, do it now. */
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a7a76456501eb37ddf9fca6529cee9555e59cdb1.1643047180.git.andreyknvl%40google.com.

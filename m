Return-Path: <kasan-dev+bncBAABBQUCXKGQMGQEJMC6F7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B085346AA7D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:31:46 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id d26-20020ac244da000000b00417e1d212a2sf4377857lfm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:31:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638826306; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqQQBvzDAodSbSIr84YV1HI4us/ECPhAsgFcu+AF80bjh3LrMj9FYncMRLS64ai2KR
         G4+uJQ+iKONXY3rIS0V00eiP0FPpUZ7U1ILzl6mpcLVlffvm1eUWfsjl6LbHDMcR7jJX
         qoL/Jghs4xf0TUEwcY+Jb25Y1x7BDQiOjBR01FQXzCEN/7lM16nRvRTYuIT1Hn+et9Cn
         97BuDoXxre47k5AvA+OCUOYkzVCYTpxzIk/ZYJnA076CRwPDBDvF6NWATPA+DMD0SvPN
         NN9VmpudXqZFH91esbhEJVv+VzODK96KZ6R4xqs1U7H+jp6xZxUvYfTZ9imeI2AZ1EPe
         cH0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DNmwPzBawWSi3t8sX/eOqPF/bKBflE2cq5oS7qgiH8M=;
        b=Lpy3alolRhCpTMukBX4zvU+l1Su/75CWUNllEXCg5fgdIeAYhxZi4XLsxKU02guGlF
         z6HCgKvxCgiCPtGsh40awHdelEPqDHanl2i18fkw9I7vPsKc0HPwA/THPce9QE2KPrG+
         yf26ozoQn/xpyeDmipG760c73gSXPpisH7oUzRrH3E88YusgK4g6sietMH+oz3QkvQAp
         anXGzlkQtm4DC+pb/IB1jrsZ2LVMZmp8tCY6oVmuTqJ5i75Jk54jaAHnGYs+0m/gqYYY
         VlLzORr+Bi7+Jkp0klzRXtY5chxRMys5rjqjRi6ZII/EhGSvPyXM5M7bsiXrzvK0erKa
         HNfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G8KjRNXo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNmwPzBawWSi3t8sX/eOqPF/bKBflE2cq5oS7qgiH8M=;
        b=jLELNsD2LZ4AAveTbYVI3hcL8k749/1XJBFMJt5JfdHawezpWdAcyTSKIeVfd3/ED8
         12SWxq1DEJJJgY6I/zdiQZItPteytdWiI8s6L6NT85o44sweHF2V6vK+CblaTdQdqUdi
         AYCynWhoA7n1TXHvILhDgNgE+FAIDY22J4PWC6Qymhp4mVMFy+X6SQGar6ha01t8ZQZI
         O7Hzh7+2H/0pa14lYQUOsxqeONcWR7NHxnNfBjhNj5ehu69zCS8dzjNmgVna+DrYAgR7
         0z2GyQovPeFGrYYw8x+jKKGoDot3b5pCWHeJw8xSGd4D6FOll8EFKx1EUaactbYzVLT+
         vuVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNmwPzBawWSi3t8sX/eOqPF/bKBflE2cq5oS7qgiH8M=;
        b=4qXDFf3eneSDGP/mWhhDUYNts8hkpOS7SxqqqSjiJDcExJ5dd5Q7Xy/mSFAa/ncEzH
         HJo9+/iWUs5HyoRgs8mgeGaAlz+MPq4QNYKzNbc9VmzexV3I9tuPkAGXLZACD2KpbMl8
         4Ft8oJBqE55lnzL4fpGWR79cRJgIBNWFBPPW1yHPFjQukwDGvrWjxAzfCrWzT4TVCYG2
         NFPZa9zpX6wphcvKPmL+dTG4ruj7x1mBudDifwkU8a2WDU1XguE2/ZC5W8thLisqnM67
         GwBS6vENG7N5b1BnWIcudbv9ymE/jgK1Kdws7oDByROeEi0bPhYM4zt/MQpq/lbo0pMM
         ieig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SJg52qHDdVpccpDpPSuCjMqmNXDEeGgs8onzuSUA7UQVjr7XO
	ZyT03lXZEtXSF1L31TzcJ10=
X-Google-Smtp-Source: ABdhPJzlwVRjc95f8Y/s0OkH4uZnDptQntbkYnAHCyGsCzwUT95sUihVDuLRm4Brxts8wcko67W1Uw==
X-Received: by 2002:a05:6512:1682:: with SMTP id bu2mr36972955lfb.400.1638826306251;
        Mon, 06 Dec 2021 13:31:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c2:: with SMTP id p2ls2818747ljm.4.gmail; Mon, 06 Dec
 2021 13:31:45 -0800 (PST)
X-Received: by 2002:a2e:6e17:: with SMTP id j23mr36192719ljc.99.1638826305434;
        Mon, 06 Dec 2021 13:31:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638826305; cv=none;
        d=google.com; s=arc-20160816;
        b=0Z7UM6fcUWzUbxZxk31tzjyMXvdkBHKaILn8d9Fr3am9UTuLbfxxdQpTV6ZOLySfM6
         b9SP8ja/ZTkLiqjKh8i5/0lSavw4c+Sz3TRR1efckn7WK9HTPbwRDyfnwCFv8bE2XPdz
         jP7jjnvvDkcVSxTFkp3fdhAtVKUF0xp29rjlSNhz8jZ8LjUOwk7d9fJVo6/c1fwyIwHu
         vuZR5thJn+QTwvRGj9WhziaouZu7VQalsLK6JvZIqctsublCRv/YhdYntVuA5LJCAsws
         Zldoe6SyXMaZqdEM5khTUDVIEwxOXImYkwTxIqmPBQs+AH+1JdtStF2iJMwPEpheD9J9
         xXpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A+HW6k6OAcUIQ5pcvvYHE04liTPVazbrvXn/E55v5k4=;
        b=S8+DnS235yUMUpXFlUp2atBvLS5h9IiK/ZZP+q/eKBesukyMGf1Yk35Dbq0my64dib
         XDohKVp7HWksp9dUVM5t7QfHOGmbv0e/BmMNqaHihW54iZcHlYWp5xmSNn9tL20z2S4D
         oYdL/EqC5yH17ZqoHMWWhbpyFittKOXxq52TUIjTaOnphSFfTFM/ZFQdKh/hJCBD+7oj
         9ovZ0RVAhAGRu8PINpA8yW4k4kZ143BqGAvczItygMJ5OPrwO/L/qvqfIxaNKrfxK3xt
         FwneA/FBRqSKQiF+k3/wRkQDg69bmbE3MGYcaPWo+8xyXPpVgr7050w/TQEcQGfoaAYo
         ygEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G8KjRNXo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id c12si705064ljf.4.2021.12.06.13.31.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:31:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 02/34] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Mon,  6 Dec 2021 22:31:07 +0100
Message-Id: <2ace94811bd1ce8c87519bf55bcc163c2a78d3cd.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=G8KjRNXo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, kernel_init_free_pages() serves two purposes: it either only
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2ace94811bd1ce8c87519bf55bcc163c2a78d3cd.1638825394.git.andreyknvl%40google.com.

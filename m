Return-Path: <kasan-dev+bncBAABBK4C36GQMGQE65AOJNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 199C54736F3
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:52 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id n18-20020a0565120ad200b004036c43a0ddsf8031596lfu.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432491; cv=pass;
        d=google.com; s=arc-20160816;
        b=vymaKLPHgR63wRvm6Ma7wNB6vYoWB3zRAyxoIGTAq4jfux2we5M6+XPzRIHfd7ooDc
         64RShQf4sO6oLQ/b8qNgvulKWHANc7Dw2jXSlZwBUjFr58C7ELdKnOMjFVDrUPNUG0+j
         Dtq6p8JMWk+8HhEgzXAN46ifZr2m9ZSdN6N/YeXcTCnkqcnRrMMXZT0gsBeM0Qo5bBB/
         jL5RfRmMFggWmyLyi3MxmvWFiNVKDaLkKgozNEgK9OUD4g1HUDR+lXcJhBbOSWIJcKmQ
         MC6BeZu8l4kGlajaVn0LaOH1rSBMuyTXOuSx4/pJgCf9nkiEGkJnJ8tXxLesWryrmi/N
         TPag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kC6FpVqKjF9dpCiDBVoWBhUqrkJhThS9d+TSD3A1KV0=;
        b=o3lWJF/wGG48vU6KnfkXx+6YeqW+m3VvHt35RR1JlNNCkq7ZJ/hyXbUOOndvM5Nk5z
         xwreMdQ5er8k3SpPVgEfZeEhtt6I6HqkH9vgqs/xUUjkHzANltdgWlS8tDUv/kLZWr3N
         b9xi/dKKWxNGIDLJkxJQCgi/8RTBQq9+NafjDomVEl6GDMoSnIIUm/mamCSSW08n0xRp
         /DPK00iE1TjGlY3L6HCFgHi/+KwhWNK7CIw0VcgQ0wByMOIK0OGvUHOSFmwsSDvYRMh8
         adcdBLmD6jBl5n0mbTFyUiD+0cMIGYmA0POKbVUYkP3lC29Xjw3VakRK3x7qM2Xbj9Dm
         cjJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YvdW6wS8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kC6FpVqKjF9dpCiDBVoWBhUqrkJhThS9d+TSD3A1KV0=;
        b=pMSegio1wwOrw7HItF0PSEaL1H0GZWGOtZtztcSJw2STDYd/04N4ke0pS7rU3ixJSm
         rvMal8C7jnDpx3moRayXF9LP/t9QeDtK0oRerd1qeqdA49DIHdMzJnoIQCFYJKlajg4b
         elvP5eaJppKWDevhp0+8fxqJ0ChNNzLOzIs92RhFfFBgukYLkU58MrmTwY3lDlk7Egth
         MdduvP3JRKRx5LH9W1IpAwImW+jvHsa1RsSeNMt8Cccb/rXJ7I3imNFLVAz8Fc7UTrv8
         o4ksFvdd6wzRlXj41+ozdFreDV98/p266LVFnvjJAVy1BXhCg4xeNg8Gu+GO5+DjZIm2
         mIfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kC6FpVqKjF9dpCiDBVoWBhUqrkJhThS9d+TSD3A1KV0=;
        b=aO7EKZIy/GAPtqwL5+iBsIcnbt70AVBmqZV6Vl1fTXPOa5iO6Z1aa6AEUhWU9cEHTY
         QIHRpKL8t2Nw87y4w02mSk6ak7OXRZ/i26rQhIQBo6S+thp41ANlVIZRrRvi1kdvFvuh
         X60QIQGl50zq3Dy1dxTGz9nAZKD/oDNV/IrlT39mYqR19mXzWesGIVYM5EU4xHrPtaF1
         Qz8uax/0R879UZD7gAdmbTcnoy3XIFIYkQVYX2vUNTF7LAPQU71kAsUquwzGPIBRdjRk
         Ml+9svOcOQNwPmkz0o5MU53BLcYRw21lsa7n95nYKl7W0uhgnTN6imv+yyXij79Bu1OA
         yupA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vAGOS0L7yC7EJk1Jc9QWtWql3mPIjEa2pDtHHbMiutTlZm0v7
	c4AWkwa1LHsQ45iA05Nld1I=
X-Google-Smtp-Source: ABdhPJxwk+WcmH+OCn48AobH8NLIIYLXmpWG5C1CBK8ihGnq37Ajk6cbaTvOmaLs3qBCYOlSTLi0wg==
X-Received: by 2002:a05:6512:3f27:: with SMTP id y39mr914366lfa.675.1639432491687;
        Mon, 13 Dec 2021 13:54:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1552924lfu.0.gmail; Mon,
 13 Dec 2021 13:54:51 -0800 (PST)
X-Received: by 2002:a05:6512:b8c:: with SMTP id b12mr906850lfv.99.1639432490979;
        Mon, 13 Dec 2021 13:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432490; cv=none;
        d=google.com; s=arc-20160816;
        b=rhuk6McSy1m6UGBKG5sBWrZzalxZfrJLCW9ffjOgw1OTVHxFg/xXpfJz/inBK/YWGv
         QlWOF9Cu5WiHYy6K4QYz2gls0JNdRuDKXA373qZDnfcsCpKXcemHK5HP0RzYdR+lxq9Q
         Kxoc3yvyIJKo1KUl7evxISqr9cnY2ZPo+GiS/TV4gL8n11litt3GwUqZ1er3KICWq7lf
         fUX5Un2TiAjFHwZdu8vQ/NS/B52EtalqUlQH+E73caU2J5TaeHhM/M2UJZEyJSRvpiCd
         hYuStLh+HL4LJ/rD9bK0tw8ksxzaR9jB/F0W11DUVswExwO/cZjUvRMbmmEKp7GPLgFV
         ojsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=049z7ZWTue9UJQyuIOFEPdRayr1xnumxPN0uhYB9vCs=;
        b=yzWVRbWpS3+rvMFNXIdFrQVjXh3vapw6+jZ61WK5SMZi5sprpRO+wqpKyUdNnEcjgH
         8AkgTRGT5I1k06alE2Tn2PJ4PbFo97v1ASRplZZU9moslmVwLgBWTUeG5uKJ5OKz1VeW
         pEAkhtIC+YjzZDfTQhfxCFaHskJ31qXXKa36J3kgY/4uPs2DrGv3Ct0rrQPTbXK4nwUv
         50OSMV9gNvnMmlW7w+8MHVIpNHmta0+GuOS0p9DqDLOzJ/wV2gzfOFTiUU0iT2fVRYfh
         K0GC9oWZep+2LXyEp5wZ+JBfSwchLxDJnRdVe9kMYjWgCH9sR87YhLmD4Pdm38CxHuPj
         J7zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YvdW6wS8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e18si670461lji.3.2021.12.13.13.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 27/38] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Mon, 13 Dec 2021 22:54:23 +0100
Message-Id: <e9696ef1484c7057d1c048dda15819ac19dd4bea.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=YvdW6wS8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a new GFP flag __GFP_SKIP_KASAN_UNPOISON that allows skipping KASAN
poisoning for page_alloc allocations. The flag is only effective with
HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in a following patch. The reason to skip
KASAN poisoning for these pages in page_alloc is because vmalloc code
will be poisoning them instead.

Also reword the comment for __GFP_SKIP_KASAN_POISON.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/gfp.h | 18 +++++++++++-------
 mm/page_alloc.c     | 24 +++++++++++++++++-------
 2 files changed, 28 insertions(+), 14 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 42b845cdc131..6781f84345d1 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,9 +54,10 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
-#define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
+#define ___GFP_SKIP_KASAN_POISON	0x2000000u
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x2000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -231,21 +232,24 @@ struct vm_area_struct;
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
  * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
- * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
- * on deallocation. Typically used for userspace pages. Currently only has an
- * effect in HW tags mode.
+ * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
+ * Only effective in HW_TAGS mode.
+ *
+ * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
+ * Typically, used for userspace pages. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
-#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
+#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 497db24ed169..f1d5b80591c4 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2394,6 +2394,21 @@ static bool check_new_pages(struct page *page, unsigned int order)
 	return false;
 }
 
+static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		return false;
+
+	/*
+	 * For hardware tag-based KASAN, skip if either:
+	 *
+	 * 1. Memory tags have already been cleared via tag_clear_highpage().
+	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 */
+	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
@@ -2433,13 +2448,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	/*
-	 * If either a software KASAN mode is enabled, or,
-	 * in the case of hardware tag-based KASAN,
-	 * if memory tags have not been cleared via tag_clear_highpage().
-	 */
-	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
-		/* Mark shadow memory or set memory tags. */
+	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
 		/* Note that memory is already initialized by KASAN. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9696ef1484c7057d1c048dda15819ac19dd4bea.1639432170.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBAABBNMIXKGQMGQET7YW6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BFE046AAA3
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:21 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id f3-20020a5d50c3000000b00183ce1379fesf2354357wrt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827061; cv=pass;
        d=google.com; s=arc-20160816;
        b=OKzopZ7TXBC9GcxMsutLMe8JeQUimGGJ53uM3mz6MckAWwvaHePJvniIgcvrS+oPLo
         YcNOZnm6pYCJPMzUnjHcxlFITg/ZcwI+nvgQICgNbA+9hfZpRooZksUMFBSeRrdY4qht
         p3qd2L05cIPQiCmt+fh72/dtNj6tB1SFmZO/5qWSRe5cJiU/7c9/gTgyRG52RtqiYls8
         gPVqZBBbU8DXrWTGh/eFCkaNuy7nN5Z7/dvSaKMpDfgR3Vc5ca3WlYZSodX6YRJRGlEp
         HjWP84S9jkjc6/4baNSog/PDp8qZcreij3FtnsioDl7YDdq4qReLinoPR9tf9+TCKeD1
         47TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ryRcOO+cAsTaKRrmvIAAf5SqxCjMsU8S2p8KcNEmJmM=;
        b=nPxkIWFBhc/Hubp9QsX/BjbhHKRpJzd8hjyS++B41T9Kp3jMCp0UQVJZkEJ90g/Rd5
         bk7vxg87HtMkI0cSeRWrocsWmWKe9bKTc06nmU0jl9tP40LQbpccecGPiPfN9dZIfsOC
         MBBaRirp22QK8ycFFreMDs1rET7WyQzgojJMxWGi0cME9XXNpy6/g9fpEGJUqMUej5kT
         v1qezrF/hlSNrTgVlMsID9AOa8zuGeJrHuJWNbwzLyfsBogbRMSmxilxRkq2RcR+C/Te
         coPYty2TjcG+zmpwMAe8KR1k8lV4i1W5dfidN0YTQmo6c7i7QCEGeL3UXCPOG2lX8vwP
         XnUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gbVFChOr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ryRcOO+cAsTaKRrmvIAAf5SqxCjMsU8S2p8KcNEmJmM=;
        b=PcWUQsKfrihTxrgQO+e+GmJUpA8JDqIkshDZUFbeiIqEE3FuKvmrr8HKmMO2y3ncnx
         e+WI93+AFWhvCX/9Ykr830DsTtk5jslh8p8hUzx9n213JRMIdHAedYaJaxiO3hqPqubu
         Oee+WLvi3m24utgs6qXg8AhosGjgqC9GzIejznP7N+qUq0vYrcapVLC9f9DEqL4y1OVa
         Mwvfh372JYo+tM14fJA5J2dygI+eTkweuF60hQbhsHlKV/oYUlax35FiQO5pTbsG2FEG
         c5nXqvqKkqrn3Q1MDdwMUVs8Oc5fYeRzvt71H/vx7BX/CNpfLnSynQMpXxhNclBQE7Ly
         pedg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ryRcOO+cAsTaKRrmvIAAf5SqxCjMsU8S2p8KcNEmJmM=;
        b=7CqIHPnfWFS1lLy4taW7heNCIiZysJqXsvGuAsUkpacuY5KFkq6Uf4vc3N7V6wBwdN
         w77akSC9IyLnulppmdDsjtdkL0nInWZnQ4sBL/5Hc1n49Tha5D1ItGle+c5MHYT88SL+
         bnGr17UybGAwErsEwml/sP3O5BBfkKBKI/OPFHEsgXjVNxqLTthFIrrq6eguay3WCgMd
         NrIgzc4ntiS4x4lN+wpUGztat8eeAt57T0wuqGmFN+zik3mTF7Fp8pUT0yfmWDyzLXQq
         s6b+RY/EkkO7p8pQyTMKh+4rKb8znOiDzhE9f4u1M6OZ9/s8IyqnUrilVsaiV6PGW2X7
         vKLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309qLnyy+Iq20hKIaUbN5XXHvwIOM0c0e8ahGtc9E/QSWxfN5CC
	yuYBkEwtCWk/zI8KiU9J8BI=
X-Google-Smtp-Source: ABdhPJybk/IR2N2XoGZwYSen6PIF/8bK4JdjmpgVdAQYW07VxvDeYi4h41RvUIOyfT7MoXHc+lZilg==
X-Received: by 2002:adf:e286:: with SMTP id v6mr46642369wri.565.1638827061243;
        Mon, 06 Dec 2021 13:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls1146631wrp.1.gmail; Mon, 06 Dec
 2021 13:44:20 -0800 (PST)
X-Received: by 2002:a05:6000:128b:: with SMTP id f11mr45846732wrx.70.1638827060569;
        Mon, 06 Dec 2021 13:44:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827060; cv=none;
        d=google.com; s=arc-20160816;
        b=zdOSUHh1ry0ZQ3LoEI/OrbQzZyMgyFYfO8mwDVBv6ms2I/Cmi4TwEj5obnbYvD+Cr4
         dPmXnXFVLXvH57dEEFDWxNdBSt5X2P1DHj2OekevAEANvfCEqRKoSRFs7ITGVy6lz3HL
         X3RWm6xb/zEOGQ5hg2lcA4pU4bLSqoPi7ANy5Rei5jxXvgd/6trBJ3H22BsDAwZrjQWJ
         8SDOjGqRTJp+MbVooMA4aSdSSLbZxMlG49pslHhsfPRaZDHsSvVmbW8frpj+BEWgtEaJ
         t4+lZA6UVG8RuJ8uEKVcC82Tk1fqwmmn8+k/AF1qdt699wmG4GILWtG8c5kUCjTkYEq4
         fGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CDfDFpOAo922pZ0chQAMNz9tzdyiLXIp8K+CHBQuOYo=;
        b=JezChjtSIywhX7JGNSkob3JkVQepBwmEjfGtZKCuXJvLub9S74Ku9yXOm048oc29zS
         wnBrzkaxexAY4YLjds7vttxTQyynoIQwz323DpO6idk1Ay0ZUV9YKXPa3ocWkXBwoBwo
         5/VCctzNSbJ9qWJt9YlIOv/8AqOPh4DkOc1E8jWEVfpEgMFeUlUgGMIcAG5h6NqFORDA
         mQU03TANTdKp+szPe4I6eb2Fd8fi6XCOiifxydfEqLhYtt252TZzR/q1XEJPiWBmX0yK
         cCcgRyabFZI8wtMM0s+L7GroeGTnBjIF7b09Dj1rDUvAdnS6W8DQS+RAIZi+BCTCJBTl
         Mq7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gbVFChOr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id r6si821188wrj.2.2021.12.06.13.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v2 05/34] kasan, page_alloc: init memory of skipped pages on free
Date: Mon,  6 Dec 2021 22:43:42 +0100
Message-Id: <e5b3dc604bcd506a56c4f385ec6b2c9dc3e6ccb8.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gbVFChOr;       spf=pass
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

Since commit 7a3b83537188 ("kasan: use separate (un)poison implementation
for integrated init"), when all init, kasan_has_integrated_init(), and
skip_kasan_poison are true, free_pages_prepare() doesn't initialize
the page. This is wrong.

Fix it by remembering whether kasan_poison_pages() performed
initialization, and call kernel_init_free_pages() if it didn't.

Reordering kasan_poison_pages() and kernel_init_free_pages() is OK,
since kernel_init_free_pages() can handle poisoned memory.

Fixes: 7a3b83537188 ("kasan: use separate (un)poison implementation for integrated init")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Reorder kasan_poison_pages() and free_pages_prepare() in this patch
  instead of doing it in the previous one.
---
 mm/page_alloc.c | 11 ++++++++---
 1 file changed, 8 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 15f76bc1fa3e..2ada09a58e4b 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1360,11 +1360,16 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (init && !kasan_has_integrated_init())
-		kernel_init_free_pages(page, 1 << order);
-	if (!skip_kasan_poison)
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
+		/* Memory is already initialized if KASAN did it internally. */
+		if (kasan_has_integrated_init())
+			init = false;
+	}
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
+
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
 	 * does this.  So nothing which can access the page's contents should
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e5b3dc604bcd506a56c4f385ec6b2c9dc3e6ccb8.1638825394.git.andreyknvl%40google.com.

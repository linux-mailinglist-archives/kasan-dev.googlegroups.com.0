Return-Path: <kasan-dev+bncBAABBHPJTKPQMGQEW7WW7LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id BE30D69291E
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:18:21 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id v24-20020a2e7a18000000b0028ea2c1017fsf1883401ljc.14
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:18:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063901; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fzs+zSi6VagxhHHLoj2BXXIkHuGBKuNrVTAgobjimuIqt9/gNXH+P9W+3T/ag8RZlI
         3lHIg6d5a/xzfzYcwe6CPodrzHzk2uMDv0Qour6hoW+F2qEHcZM4m8Za4tc/xm89FHcz
         PvGJy0WWdrTwo12I+LyhuFg2BkuFiwFn9puRtKJMToKDLeS4UICtRNOuLCRUFUsQucJ1
         7C0kTUh8XLQWnQFawMR2CT8B4a/cO6ZOFWtyOECnZQ+TyyaIwoD0qnsZcYa7H+nAQetu
         xt0ITka2ly3+ipHhRAJb8eSQleSPXjb+ivTva8CRKZ8+JMm9QFIaHHqvjrS55V/M1PWH
         E1MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QG+CrncJPv0lVLo9adOq/GmCM0RRbMg3hhiRiaWa6AA=;
        b=jSpzCtqSRi7mLStklBXgnttb4je29pBDQ8DA6TC9B0vORHyWQUwbBWsZZUIRPDV3MH
         BImU//FPDtsunxY9t5VfKNJwcrAe1PFm2Lb9CI/SpJ9YshBjH3zQzC/9rbFZ22BVwEjP
         GwFeUHsxY6sRFXQ/bQXGC/WjBma5jh9L1t1ZdWeC2q07cfCu/vABH1bhAMNGYMmj2sEN
         XoXyR3MB6Odml8s4gohgPYOobbb459S2Ajdmv0Jdyhzn9JfsGG4nSv/KYRJG5994+Tmh
         rxo0syJQNAFuFtqLFtcgSMMBX6Nx3t0AjiwapqEunf5B7O5lo/GZ7tKxkxdxmcDG4q+z
         Btiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t7vDpQcZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QG+CrncJPv0lVLo9adOq/GmCM0RRbMg3hhiRiaWa6AA=;
        b=F+MSRPPHqk+Z7HUOtHW60dHuUeB7WV9pTcQOpktKdwBJ6fTLrX+lwpFLo+X0M40SF1
         eYEzgRX9/k6gN5QfLw2H2ziOBnwyVUmWXVrg4FxmW9HVkqe+EWESJB0k09CAwSfrsNPv
         66hGba4nn8/8u6rqocKPnlsE3HSP+UlekdUSzbpGAIUldIzYNom9RXBWOshfDOPBaNCT
         Vdox0XK3AdhUO7cZ30zv2Yc8mcjw7w+KrAPg8+YAd6T9/Bi+zA6yi0KaYxoVwsWBa8Mc
         bdBydxzI2tzP0O2ofqsu8hF2QYZwZ8V4loLRF+U/YR3r2d209h4H7eCeW/tn8VLatUgX
         gLHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QG+CrncJPv0lVLo9adOq/GmCM0RRbMg3hhiRiaWa6AA=;
        b=r4PR3+Pu1FprpqTI5WlfK5XFnBs0Tiu7X50vD0CrtDl84Dy3rSgjBvmrCwnDyDD6rI
         ZAkfjRDo2tSED7li9pmW/J8te8rErBLzTki2+QFMzFs+Irz1f29E5xpB0Vsrz1fmGOeH
         l+E5FGfcHV6fxypCNBGgNMDQSuVnDJa9wbJ/8IYnyxLbLZ+2RnhFrIv/qeYkDFisLiNB
         jwvjzNIKAGtK0vg/+CLixNmd8ndpYz/3iBxpQVjngFllJLFpv3Prb8AUiehzkx1hjaaa
         F2BriSztQ21ZvvQVadQuwDh8nBTwiKMqHmWafZ6F8jj35aMkdEZKGRzbwZ90O03i93l+
         V/oA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUqoXKR2RMp/wsEAvmHDYc4YKZPRawSHJPErwm8OgIvcQB1dDpB
	4k8rDzc2Ku1M0evJqdefz7w=
X-Google-Smtp-Source: AK7set/JembP465N9GIYx9H7tV18sbVHn79vOZuqHv7G6uVJ9X28XD44t0zaLGNfWvOJtFWIfJX5iA==
X-Received: by 2002:a2e:a168:0:b0:293:2c22:4f4f with SMTP id u8-20020a2ea168000000b002932c224f4fmr2571371ljl.157.1676063901345;
        Fri, 10 Feb 2023 13:18:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:239f:b0:4cf:ff9f:bbfd with SMTP id
 c31-20020a056512239f00b004cfff9fbbfdls4337655lfv.1.-pod-prod-gmail; Fri, 10
 Feb 2023 13:18:20 -0800 (PST)
X-Received: by 2002:a19:c515:0:b0:4da:f379:9f60 with SMTP id w21-20020a19c515000000b004daf3799f60mr2817011lfe.33.1676063900390;
        Fri, 10 Feb 2023 13:18:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063900; cv=none;
        d=google.com; s=arc-20160816;
        b=g9592MpfPWsjmEHO2AA8qe50Jx4+SF+hDFRPp7IbtzdVAMtFSDffKm3QXwu66pxcg0
         GIo/TVVtvqbaGaJq/WOsS5dhBT9Qe6x70MLlF0HlWDx7r+aN4hhTKHfeUEGw90dPNFrm
         L2g9oXANe8gFX0W15/2zRRkKfrOZLLqeD2WWcTsYfGD6aVVtXVYRDsy/JNNIZDFq2yeA
         l7DJrQ3fqyZ23CX+zIVTe5urfPct8C+NqF/57btXpyWU6VfddrMoqzktCiC4IGeEHwnY
         sXYD+Zl9BZXNinA+XRUY/vX35sTwTZdfa3ogk+5UU10tJq129nyaojK8XStrjpVtOZtd
         jC9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Qnr9u9smPMPXsKAXlYWG4fUkkGTB3Zxw4vbQvgaYcVg=;
        b=LD4qIW44MBYiV1E8TKcTyz3NMiTpMhUdlsqSJ+WkrXQiwS0Upni2WxqhsTlPqawOzu
         rrPlqg1OTVnym8POliDMKVFp+Ht7KF4qnA5jXg9ABqLMjIqayCc+u43poiXaW3muQDQF
         EjmRZc6b6zFlp0ThDnoQxFq/uh73qmZslpwL3Qo6m5xtu6RAubb0Zut+T/0i97+E6csz
         hFAsoxsbPMCvLj8mnVCGst9lAdaS2JlZsAfBS5qh+cUuHm8MkUtTMSzoApknNc3Ldgog
         E/xiEfTIgyzr0AeqrWVjLkzpmOXo8yVh2ZonmdDHz/cvMvsUgtuPT+iTqfjFAwOC/nNK
         baSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t7vDpQcZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id bp27-20020a056512159b00b004d57ca1c967si315945lfb.0.2023.02.10.13.18.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:18:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 16/18] lib/stackdepot: annotate racy pool_index accesses
Date: Fri, 10 Feb 2023 22:16:04 +0100
Message-Id: <359ac9c13cd0869c56740fb2029f505e41593830.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=t7vDpQcZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as
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

Accesses to pool_index are protected by pool_lock everywhere except
in a sanity check in stack_depot_fetch. The read access there can race
with the write access in depot_alloc_stack.

Use WRITE/READ_ONCE() to annotate the racy accesses.

As the sanity check is only used to print a warning in case of a
violation of the stack depot interface usage, it does not make a lot
of sense to use proper synchronization.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Improve comments as suggested by Marco.
---
 lib/stackdepot.c | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 8c6e4e9cb535..684c2168bed9 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -278,8 +278,12 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 			return NULL;
 		}
 
-		/* Move on to the next pool. */
-		pool_index++;
+		/*
+		 * Move on to the next pool.
+		 * WRITE_ONCE pairs with potential concurrent read in
+		 * stack_depot_fetch().
+		 */
+		WRITE_ONCE(pool_index, pool_index + 1);
 		pool_offset = 0;
 		/*
 		 * If the maximum number of pools is not reached, take note
@@ -502,6 +506,11 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	union handle_parts parts = { .handle = handle };
+	/*
+	 * READ_ONCE pairs with potential concurrent write in
+	 * depot_alloc_stack.
+	 */
+	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
@@ -510,7 +519,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle)
 		return 0;
 
-	if (parts.pool_index > pool_index) {
+	if (parts.pool_index > pool_index_cached) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
 			parts.pool_index, pool_index, handle);
 		return 0;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/359ac9c13cd0869c56740fb2029f505e41593830.1676063693.git.andreyknvl%40google.com.

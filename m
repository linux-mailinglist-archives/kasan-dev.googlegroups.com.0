Return-Path: <kasan-dev+bncBAABBPURUWVAMGQE4E7IIHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A75C17E2DDA
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:48 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-507d2e150c2sf5234737e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301568; cv=pass;
        d=google.com; s=arc-20160816;
        b=fa61lf6DQwIY1V91a3rm2clphnwC2BWmq4LMourgdTNjx1pWdzUjNUD7pOGmlz8dlX
         yKbl3Z57dKGURELpAIt72lmzL8vi5f05t9j4yxv0WnyP8ygp231eNDv/6j9y8p8cfg0k
         x/5PGhSzteSvJwleysD98NeHeOD2chc4qfyJljMijWioAOYUgMCm3dToqWRnTDgGh25P
         KrgH245mi0cZX4dHW/zk4TPVuB5SAclQDo1XeuOT2pruBA2Zl0uAvfLPzNOS4NPpzM7b
         s/qqk5Xv6El+5DGd0s9j5WtFFd2OIo+1PKQOQYAIhjT8ZKLgcaalSvmXwMe/0LBTzrFK
         nTCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z2D1ybOS1kWIYQEOWoXGuBmcjQrWGV0O7ccl2IzOyo4=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=iNMND9vi4kNMa2wjtMtMacPCwuqzXxR4fbS3+Zx0+0H2c52urJ8LYBdUTY9Voaedar
         6ER1MDna6wwO/Q8xTxGaQSYBA0XZTzzHaBJMAc9McNr/tqkJS9PHP61wyCQ6pEXnVflK
         s0YKmx8Hj/1SGTJSLKeZzN9an2UffnogXTlh72WF4k5uZPvuWYIa1HZqFCoo2++xI+4G
         Im2uIaF79tQ2dWsUpdUvsLcsYfBE42aM0DV4SX0f4s0M+sb4enU5OHiW3Bm4ixTUWV2j
         RE9CTtUpXodPUSis/H5u+ULtukYPWcOli9FljZHjqUZ/xeby0m4BpEBiUXN/UDGw6pp2
         cX2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t8CeOtDw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301568; x=1699906368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z2D1ybOS1kWIYQEOWoXGuBmcjQrWGV0O7ccl2IzOyo4=;
        b=XoREpb49Ln0Q/KR/ZWSKCcpBPltxuG79+X17JdwLfk/PKaKjbmkhq1H+rSjwT5wl2+
         +cLK3NliCMOoQjVEtCWl4l9kPWpoQff0mkOdswn9lDNF4imbNvugdeVOiZEPSOpfdM9e
         lKyEBBwu35HPiEuSyqSpQJBWeFtB0ZyJHvqPWlcplwUzAEwHnjCEIlPdENUrdNbb/PR8
         Itud4nUJ2Hm7owwywwqTX50q5m7Get8ksUKJQElckfC0PAVO+8gFeJK132qwJoTupoOT
         30ivy4TtbZxCCiJztGj4iGTWoAge7YO21oITr0xg8+RrCJbqt4Eacpjgdqt4ZNNJLeAD
         DpJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301568; x=1699906368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z2D1ybOS1kWIYQEOWoXGuBmcjQrWGV0O7ccl2IzOyo4=;
        b=iO3IiqlHeg2wkxBhCnriZJZgCs86hY5ElkdRvOFZ5TY2503PdAKxjXRR8N35FkTApr
         TxPy5XLeGVaCvZ4Eh/ZVZTTLCkJ9M1JG3iITFP8xeoEnfd6qtFI/n9R97J2cEIFdcTB4
         msjYOsYEiMI8kA8QU0PwWoYJ8wk0as3CnOq43rKOOiCBwm3FBs/Hn8mbBRPXNxZ6xwBH
         x1/oIOWm9wMyxcyjDMTCJvnI23FdwNVAxgEkFqiPzQacwi74ZQBt5JITwNPjyzA87Lc3
         R43nF8aDIvGQhvBvPNGzwlKIMWFtzes8/bNlWxArWFhEnyb6w51xg5cItPfeh/jOC/Kb
         DbKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwkjOJB+Vf3xLENc/LeXhknI54IEtBNCEXfxnDJnt43v1BbWPsF
	/v9g+yjcWQc6ltW5KnoyJmQ=
X-Google-Smtp-Source: AGHT+IFlJ22T5iTTpTk/4QNraK4BptGO3Nbq6d4qQBi06jQy8MKomc5xTpxIk59qHtzIsr68DCzCqA==
X-Received: by 2002:a05:6512:3b8c:b0:509:4ab2:3635 with SMTP id g12-20020a0565123b8c00b005094ab23635mr13410210lfv.59.1699301566914;
        Mon, 06 Nov 2023 12:12:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b1c:b0:409:3542:341d with SMTP id
 m28-20020a05600c3b1c00b004093542341dls2065317wms.1.-pod-prod-08-eu; Mon, 06
 Nov 2023 12:12:45 -0800 (PST)
X-Received: by 2002:a05:600c:35d1:b0:406:52e4:cd23 with SMTP id r17-20020a05600c35d100b0040652e4cd23mr652150wmq.0.1699301565256;
        Mon, 06 Nov 2023 12:12:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301565; cv=none;
        d=google.com; s=arc-20160816;
        b=VEoza2m0Ua81VL5eP1CIvjK2JKH/BJqXAUTuQrxiV1Bw94JVHeH8i9VGbR8lpQlr1c
         WzXTnZ+ByrXzxMlxJbCm0vAoQOnvIlRqyn/p2K24gO8MhJ7rY+NNCPrdMRGfkMjqDRVP
         FXunrFyTBTN73Ep4wqm3Z+Tvxm3Grr62oT5SBIEu94bj/dQF2ZLb0MNzZCvaIm/mk4pb
         nqXV3qzdJEAnGDsYmfwW52YguHPSzbfBCBmMTdqVVM8XJAISZBkXENsTOX8Mxseobxrl
         zGQOULX9GLfk4J7eol+P2GBw5aPUg6a51IGiijBEUSIcZ6dXsTEbHseO2p+wcEFp/JLH
         dJhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lOIDRjZO1avx1i6mH90OIJOQ1dfwcpWT2tH0Qop8VTU=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=nI+hGQydkMFFJRm4PhJjzRswNcY7IcMF5TLytW/wB5P8D+rm/qKUPvaW5sZkWALTbU
         9FNvOr0Py5qLCR3za+2+5a6d0jhsldfkhb5NvnHsLdZad3VvVjkcPUQS1SOV8j+UDYgt
         SjGlXAip2FNn6775cvfzchTXBQR5XrIe6/Os2J9EVGCZMW/h7e7tN6zTgNmI5J7cmbT2
         YlvBy22aWZ6F4goO+sqrD4Pi/2ksqJYpHzLL7IBOudeWE0VuFogm3ooT7L9VABkZg/ON
         u/IHs3ZTybQkNQOkbkIfosLedOsmB3W3MjSjt+VDHGTzzHizft2CtfSSuGymrVjvTO0j
         VgeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t8CeOtDw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [2001:41d0:203:375::b9])
        by gmr-mx.google.com with ESMTPS id n38-20020a05600c3ba600b004047a45b541si657283wms.0.2023.11.06.12.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) client-ip=2001:41d0:203:375::b9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 14/20] mempool: introduce mempool_use_prealloc_only
Date: Mon,  6 Nov 2023 21:10:23 +0100
Message-Id: <9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=t8CeOtDw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Introduce a new mempool_use_prealloc_only API that tells the mempool to
only use the elements preallocated during the mempool's creation and to
not attempt allocating new ones.

This API is required to test the KASAN poisoning/unpoisoning functinality
in KASAN tests, but it might be also useful on its own.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/mempool.h |  2 ++
 mm/mempool.c            | 27 ++++++++++++++++++++++++---
 2 files changed, 26 insertions(+), 3 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 4aae6c06c5f2..822adf1e7567 100644
--- a/include/linux/mempool.h
+++ b/include/linux/mempool.h
@@ -18,6 +18,7 @@ typedef struct mempool_s {
 	int min_nr;		/* nr of elements at *elements */
 	int curr_nr;		/* Current nr of elements at *elements */
 	void **elements;
+	bool use_prealloc_only;	/* Use only preallocated elements */
 
 	void *pool_data;
 	mempool_alloc_t *alloc;
@@ -48,6 +49,7 @@ extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data,
 			gfp_t gfp_mask, int nid);
 
+extern void mempool_use_prealloc_only(mempool_t *pool);
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
 extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
diff --git a/mm/mempool.c b/mm/mempool.c
index f67ca6753332..59f7fcd355b3 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -365,6 +365,20 @@ int mempool_resize(mempool_t *pool, int new_min_nr)
 }
 EXPORT_SYMBOL(mempool_resize);
 
+/**
+ * mempool_use_prealloc_only - mark a pool to only use preallocated elements
+ * @pool:      pointer to the memory pool that should be marked
+ *
+ * This function should only be called right after the pool creation via
+ * mempool_init() or mempool_create() and must not be called concurrently with
+ * mempool_alloc().
+ */
+void mempool_use_prealloc_only(mempool_t *pool)
+{
+	pool->use_prealloc_only = true;
+}
+EXPORT_SYMBOL(mempool_use_prealloc_only);
+
 /**
  * mempool_alloc - allocate an element from a specific memory pool
  * @pool:      pointer to the memory pool which was allocated via
@@ -397,9 +411,11 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 
 repeat_alloc:
 
-	element = pool->alloc(gfp_temp, pool->pool_data);
-	if (likely(element != NULL))
-		return element;
+	if (!pool->use_prealloc_only) {
+		element = pool->alloc(gfp_temp, pool->pool_data);
+		if (likely(element != NULL))
+			return element;
+	}
 
 	spin_lock_irqsave(&pool->lock, flags);
 	if (likely(pool->curr_nr)) {
@@ -415,6 +431,11 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 		return element;
 	}
 
+	if (pool->use_prealloc_only) {
+		spin_unlock_irqrestore(&pool->lock, flags);
+		return NULL;
+	}
+
 	/*
 	 * We use gfp mask w/o direct reclaim or IO for the first round.  If
 	 * alloc failed with that and @pool was empty, retry immediately.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl%40google.com.

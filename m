Return-Path: <kasan-dev+bncBAABBP5TRCWAMGQEFWVQ4RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 42510819397
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:28 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-50e38f63ae9sf1097e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025087; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTjy4RXp3Y7X1vR6ZKCaPkQMxAtJdmBnFYW+hPNr8F9HFiWksZtnMhnC2Q+LzWSK7n
         4sHa4WZtKXt69qReBlVZzFmD3DmncQjlOaD7nwYtNj2Ti3tIYlaKM4s4ShabMXO64fFf
         xJew6ZRpezODneoDgwlZQAbdx+euth9lmI+GpOi+iM0PXEJ+cG9R4CAUyqNM1jvfBlWn
         KOYxhAKhjSHi8wkdoZcm+Ci908OdSonjViY15UFVjNVBP3SXJxeYiLku+rx0mi//8kai
         LXqGTaC0EBMCH+c7evyXIM8EJ7H4w9z6vkJV59WEONGS1lQupDkmOFk6dC8s30oyPAAw
         2L8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZSEFmxWLj//mMLFEqyVH9HOZh1ARGxC4XTRMb7lLIrM=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=T4vqJ+TSZ6SRZcfCOK0UEdesaFFS6KWMPBHOvGszDC5XEgf4ZBx5x5YcMJjMt6qu6L
         sJ08hkDGReOAq9JrAyKlGUwZakMNn8InGc6//VGi+5CrI+CrOfvkken01Su011g/Nc0h
         VPZTe/7HOxocf2VCJw34BjejCLj4a9XmVo3VWURGHO8GBMDPW9OO7QgMJXUkIGI2/XZx
         Y+Cmy+L6ZSp79N1VXSOVyJc0FYN7SDAtRYdUzGT2lPwX4aBqp2KhzXFAoBWTPQdME3bJ
         cQzb7yn3l0R8I/BDdH7pBU3raSEXRayxmridd3/d/kkJbXZlMD9YzWkHH5AabZmvy7MY
         HKEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZpopGBZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025087; x=1703629887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZSEFmxWLj//mMLFEqyVH9HOZh1ARGxC4XTRMb7lLIrM=;
        b=iWW7rDHF2f8QILJpUCnyvbDTxzySul5MU7T0CypoFoY/BLT8SrZ8zHTqLu3v9l2O94
         PYyILQfHAAEDqwupC5en8QZkWmHRgvFhK0RCYNXAFKPZSlYb1hOa19zLbkXgKrYWoSzB
         SoYFg1NViAqxc5GF3l39uS51BjBCEIvO5+2MV88pSDUwv2SsFepFs4HQbeZcIozTk4on
         nQpLQJgl2zAnqDkWCuLCw0vW4IVVjTYRcbb3ONLY3YfvuwTVz1Ge+ppWHjtYbsYghpkR
         BPuzwSHd71wtSmsOEtEBEz6lsD3LCadWJDMp0ZUsT6qn95SL6BrKUWcHOZ1K2OrUSVI+
         t/IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025087; x=1703629887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZSEFmxWLj//mMLFEqyVH9HOZh1ARGxC4XTRMb7lLIrM=;
        b=B2ZZ1MyYbMGFxX2X16jauQ7j8eEhNFqbqswXfYMJOyOwgujs45UFRmWuXzOknuOx6H
         NhmoqtQWVROvc1h9P6tQce9tyG0H2zU4axkGfO8PuSGfLxSxAEWEvoAwPKA9t9lIgY/n
         vXzSw25B1Qz4Qv/TdgjpVv+vayRcdUNBBlp6FW9xyJeLYGS0gx9k0gg/Te4w0HEvggUO
         ZZ4uq0LkUojYC3ogDhBvscd9NqxX66Hxb6y/gLy9npnmDxMAsQGKXxVe9r3GEAHcymVA
         8vTvW1/kJUmUHZZwQnUzUniiVLP6ThCsEgjtVeeJNKQMjl+qI7ETgiRRj0pa+J4NK+nx
         6KnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy/jwZD4iVnGQbP/OFM24P0PpIDM31/ascg4WUrlcsDt31XDAkv
	JdEvRAQg56rgBworSc8eFmc=
X-Google-Smtp-Source: AGHT+IGbRxRSm+2CmdOBE9/i4v9FYTohYUuvqLQvSfPWtmd8ybToshcQGBf+QMsSr+l76aaKRN7GHQ==
X-Received: by 2002:a05:6512:1293:b0:50b:fe63:f06 with SMTP id u19-20020a056512129300b0050bfe630f06mr64005lfs.4.1703025087325;
        Tue, 19 Dec 2023 14:31:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:51c4:0:b0:336:4af7:a139 with SMTP id n4-20020a5d51c4000000b003364af7a139ls250905wrv.0.-pod-prod-04-eu;
 Tue, 19 Dec 2023 14:31:26 -0800 (PST)
X-Received: by 2002:adf:e611:0:b0:336:6e32:3fe1 with SMTP id p17-20020adfe611000000b003366e323fe1mr1904206wrm.57.1703025085697;
        Tue, 19 Dec 2023 14:31:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025085; cv=none;
        d=google.com; s=arc-20160816;
        b=mUUnKZwhUShXG9D9nznL5XiW9nlhutealCH4YyTGTVNWd1asv7mkw5ZAoe9kj5emCp
         SovnyV9IB/S0c+pYtHpEVmAvP7atKkf/eWf0/L5b595ReBM6xlpWyEaQUHckfLfiDelM
         ZpVr2TMc7kUKA5BgQ9FYbwgXgiPHciD4NOw516UVjXjNgui1qOXjwKXanJtm62NgsIih
         +uDqwsvgulUmR7/TrXW/s3B8VrMX+Z7FxSwXRMi8MNXqEWChE6j5AS0Ri0labdC+1Z2J
         g+KXk8Ky4j5T//K7/UIcqkNf+XPSCtbbGUM5bud2tOAe+J+Kk1T5Sa+vsgQmrVhnAAHM
         JDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Vw9Ju+XsuH7jTh0rV53QjnTfccLPGDaCnQHzua8vht8=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=BSYKgr5bS2VpuCpEHha+HoB3HhhVaUvo9nMDVpJyE7DL+49nSZSR+Ow1gLz2XBsVj7
         SW25s3+zhmb8FkjMiivnrj0S9y8elkIVl5G1/NC6NatKGsr+6mDn4L8KiSIWO1+XBWjz
         IUviorddT7EK6Qcfj2egH9k8DVGuMRm4L/dOros7ZDWpOK1T1Z5zFtLcbRr6GPThjN3E
         2/1mllioprlEiEv6m7L/mQxmi3ppdiu3X9BUu9u/7wgO9lACAkA9ecnc3G+uRt+JHN6W
         n9EfnHNPGXwKQRuELBFjW+IdjKiesOUvxOuk4RlDVbiHho04eVsHK2B+v6m+ceReDfAq
         TJOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZpopGBZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta0.migadu.com (out-187.mta0.migadu.com. [91.218.175.187])
        by gmr-mx.google.com with ESMTPS id m6-20020adfa3c6000000b00336740619c4si59930wrb.7.2023.12.19.14.31.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.187 as permitted sender) client-ip=91.218.175.187;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 15/21] mempool: introduce mempool_use_prealloc_only
Date: Tue, 19 Dec 2023 23:28:59 +0100
Message-Id: <a14d809dbdfd04cc33bcacc632fee2abd6b83c00.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CZpopGBZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.187
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

Introduce a new mempool_alloc_preallocated API that asks the mempool to
only use the elements preallocated during the mempool's creation when
allocating and to not attempt allocating new ones from the underlying
allocator.

This API is required to test the KASAN poisoning/unpoisoning
functionality in KASAN tests, but it might be also useful on its own.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes RFC->v1:
- Introduce a new mempool_alloc_preallocated API instead of adding a flag
  into mempool_t.
---
 include/linux/mempool.h |  1 +
 mm/mempool.c            | 37 +++++++++++++++++++++++++++++++++++++
 2 files changed, 38 insertions(+)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 4aae6c06c5f2..7be1e32e6d42 100644
--- a/include/linux/mempool.h
+++ b/include/linux/mempool.h
@@ -51,6 +51,7 @@ extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
 extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+extern void *mempool_alloc_preallocated(mempool_t *pool) __malloc;
 extern void mempool_free(void *element, mempool_t *pool);
 
 /*
diff --git a/mm/mempool.c b/mm/mempool.c
index 103dc4770cfb..cb7b4b56cec1 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -456,6 +456,43 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 }
 EXPORT_SYMBOL(mempool_alloc);
 
+/**
+ * mempool_alloc_preallocated - allocate an element from preallocated elements
+ *                              belonging to a specific memory pool
+ * @pool:      pointer to the memory pool which was allocated via
+ *             mempool_create().
+ *
+ * This function is similar to mempool_alloc, but it only attempts allocating
+ * an element from the preallocated elements. It does not sleep and immediately
+ * returns if no preallocated elements are available.
+ *
+ * Return: pointer to the allocated element or %NULL if no elements are
+ * available.
+ */
+void *mempool_alloc_preallocated(mempool_t *pool)
+{
+	void *element;
+	unsigned long flags;
+
+	spin_lock_irqsave(&pool->lock, flags);
+	if (likely(pool->curr_nr)) {
+		element = remove_element(pool);
+		spin_unlock_irqrestore(&pool->lock, flags);
+		/* paired with rmb in mempool_free(), read comment there */
+		smp_wmb();
+		/*
+		 * Update the allocation stack trace as this is more useful
+		 * for debugging.
+		 */
+		kmemleak_update_trace(element);
+		return element;
+	}
+	spin_unlock_irqrestore(&pool->lock, flags);
+
+	return NULL;
+}
+EXPORT_SYMBOL(mempool_alloc_preallocated);
+
 /**
  * mempool_free - return an element to the pool.
  * @element:   pool element pointer.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a14d809dbdfd04cc33bcacc632fee2abd6b83c00.1703024586.git.andreyknvl%40google.com.

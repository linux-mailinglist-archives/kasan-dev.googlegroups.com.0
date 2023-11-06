Return-Path: <kasan-dev+bncBAABBPURUWVAMGQE4E7IIHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E2657E2DD8
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:48 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5090f6a04e1sf5235981e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301567; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZ2tgirY1JNVzxnmStat7q5SE5m69N0LLXA4BC+4CljN4iBJjl4yt0O4HzzJw4On/a
         1ZOmQklBEMqi6ytCijB7V/fy1hxqL53GsVxKaJxBrC/nlZ19lyo43ZK5UridyrJJ0APQ
         270iBfDYd3HEuRkFZWLHwAEB9UKeGQk0kMEijOkLrENYYUZODm5E9CvXfYoU64oASHPl
         iti+6PEmUn5nAB4NXlMKSIWAPf6LX84IKlVkCwrcNaKagm303aVxuk9F9727HRAuJRFG
         IR0JwN0w9XQvhe9MszgA0J0ZpXKryPteNqWILgs3Lppv6LN3sujjmIC4CJ9bR6hULeEl
         XW7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vNv/5alIRGBVB2eNQxwXOApuqBznmDyiJqzpNbgcPeo=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=GsNHXmZ1roHXYd0d14UvnXrytw1dW+MmAs2Tcn+vtdcv0DjxjX1AQgOyj6t0LmKiYN
         QI9fXU97yTkvN5xe/p3VIuCr3le2c9H6Z+nc6By0HobaiGgGVhHKI9EGkd/BPWvgt5Na
         on1It7M9xi4uq/L3+1fRGYoqAEs6MkVsLvL4SvBSFvI90Zu8qnUrzbqE953+PwIlhdOZ
         mpKmQqaEaPXlJSGRLHpfGgXii4+UfPfjZQm5Twt8dwiuBGGBg0Bbk6t4fVB7fIWObMFz
         5PImGd1KbfrjMaQ6lF6A8LipnbFdBwF/BVvRXefN5yG9T+wNDj3hutcFwGbLW8IgGFxp
         vW8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Se8wvGtj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301567; x=1699906367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vNv/5alIRGBVB2eNQxwXOApuqBznmDyiJqzpNbgcPeo=;
        b=f5W8TBMSoSnWNvJD2VNCVF5T24pPxneYqGqkX/ANipuPtaBycgP1SOWUzXJ8N6giu+
         U0rDURqdfdeRkDAIBuyIfO6bsNw3sWAoSZ8gtygl+9lB5nDu1fRuNpdb0rsCN7wOIPGC
         fr0PobpBQVLKwE6KkQhq30ab7AtuYqWeF65JQ9ibEeQ6nrF4ZDQHX28GMVkdenlxk2fN
         1DxbzMO6/XjkjEt8fS5l3cZASuJpB8Y9/4J0hRaP4fE9BeKzRHNB/qQNW0h+MrKodc9U
         GQwtb5sDP5ry0UatGuK81UHdDf/spSMWsCYOgipEcYiFdRChfNPW5uIiK4+P91wzujvf
         Bwzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301567; x=1699906367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vNv/5alIRGBVB2eNQxwXOApuqBznmDyiJqzpNbgcPeo=;
        b=c/IyxkE+6Bx7kvFXsSjouHDHjEqwQKUDhAcsSwIF2vbgxDMyCcoiVUr0HqC9ig2fAS
         rHKARXYHa/hM9ZP2S3NjyrqQ9Wbg9WALmKMmZlXld80Yj+2I4l3iYZqFhBeQpZHSwaYC
         QHiwp5i/e3cKnOtxTT/4BIND6q7+h4x5U0G3+KI2q22ERexgikBRs+szeH9hVNDntAqW
         pEBEVeo8XBCzoJr6yV5FrTaqoYqhgw1H1sUlN11ufCudwTu0pojz+Egu3RBvoVoAHg19
         ZjI9T+sz+BjKKyGbtFUJN3CtCxdzCdK0JwHAYayxsTGdzqSKG1Gzs4z9NZ/15LZhUWhx
         hFJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzwu30mM+zzjMO0ceV/W2bdqUepF2z5k2+BVrpuYaNa4ZGDu63Z
	ecwKbWkfYFxWEfLpN2WF3Xw=
X-Google-Smtp-Source: AGHT+IHMbsYgI56gsILYmwKSLG2JSsEtZz6gLakQrdMKw4YrBLunyJljDSiABvP+FZCppFGfEEoL5A==
X-Received: by 2002:a05:6512:132a:b0:509:4559:27a9 with SMTP id x42-20020a056512132a00b00509455927a9mr12379318lfu.8.1699301566534;
        Mon, 06 Nov 2023 12:12:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cd96:0:b0:53d:b3c3:2126 with SMTP id x22-20020aa7cd96000000b0053db3c32126ls566449edv.1.-pod-prod-06-eu;
 Mon, 06 Nov 2023 12:12:45 -0800 (PST)
X-Received: by 2002:a17:907:ea1:b0:9dd:6664:1a3a with SMTP id ho33-20020a1709070ea100b009dd66641a3amr8623423ejc.51.1699301564694;
        Mon, 06 Nov 2023 12:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301564; cv=none;
        d=google.com; s=arc-20160816;
        b=KRfHUEY7B1wP8nhJkboD2FBhwM1tnWan86NxfdZQ/zjCF+8lzRA9YqZ3S4f0JeHJFw
         SMJRlgiQRZ49ZCyc65YyWbMln/pi7EjJfwZBb70w3Qz9nFXY6bEOAHgrIBk7VueSxw43
         vmvjXPDHtEnh9AWFJOQ179MdzrwEcViVcP2KDSpXtFV5q3zeg2frf/h9hDv1jelFoOqO
         qghmgJcPELF0Q7fLomx53WsDxi1Dqel5/f2L4SPVHN7GeZPeULHP8xG/q4LHLPPamlB+
         /20n617kuVxjcEDHOz5u9S5NAwZW7mq7v4dYTkskKmWEX5QWXO4mpFYwbbHYR3S9BSM4
         gY1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y7WYl7BvMbHXvuo0GG2Dw3ttgTpXyQGpBAxBpCO6Yug=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=rq4cfiQcUt08paUcdLItaAxnvAhqkjtXOVuM8QOlzcl3+m7eCyKaX9l3QMe/PXtrV0
         XPlvc5KtKs0LJ4a05lCzeFK0IayCRKS0bC3uxGVUVHj/MNCF+GuXxk0jJqPAhagvjDFl
         /5z1zeX9hTmD4meyD8MNANxBNga8KCuMlziw5zK/iIl3ArfyQFNUpm1UIm4kOiqsi0bn
         EsQnZKlzLODAqQ0+4tsLonPLAnE1FA61AVSao6IDQhzW6wi641Vbfdee5E4U9Mh5i9rj
         cqwnNH3cbQvckuW+g+rROsTzemuec8n0n1VCJnL2/TqPS3V2/0VEcVimbZCVsWhPcC+t
         Jcug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Se8wvGtj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [2001:41d0:203:375::af])
        by gmr-mx.google.com with ESMTPS id nb20-20020a1709071c9400b009adbab54deesi39247ejc.2.2023.11.06.12.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) client-ip=2001:41d0:203:375::af;
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
Subject: [PATCH RFC 13/20] mempool: use new mempool KASAN hooks
Date: Mon,  6 Nov 2023 21:10:22 +0100
Message-Id: <35771e9e5fc0fe2169c59f190fbd6bfc901b7c09.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Se8wvGtj;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Update the mempool code to use the new mempool KASAN hooks.

Rely on the return value of kasan_mempool_poison_object and
kasan_mempool_poison_pages to prevent double-free and invalid-free bugs.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/mempool.c | 22 ++++++++++++----------
 1 file changed, 12 insertions(+), 10 deletions(-)

diff --git a/mm/mempool.c b/mm/mempool.c
index 768cb39dc5e2..f67ca6753332 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -104,32 +104,34 @@ static inline void poison_element(mempool_t *pool, void *element)
 }
 #endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
 
-static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
+static __always_inline bool kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_mempool_poison_object(element);
+		return kasan_mempool_poison_object(element);
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_poison_pages(element, (unsigned long)pool->pool_data,
-				   false);
+		return kasan_mempool_poison_pages(element,
+						(unsigned long)pool->pool_data);
+	return true;
 }
 
 static void kasan_unpoison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_kmalloc)
-		kasan_unpoison_range(element, (size_t)pool->pool_data);
+		kasan_mempool_unpoison_object(element, (size_t)pool->pool_data);
 	else if (pool->alloc == mempool_alloc_slab)
-		kasan_unpoison_range(element, kmem_cache_size(pool->pool_data));
+		kasan_mempool_unpoison_object(element,
+					      kmem_cache_size(pool->pool_data));
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_unpoison_pages(element, (unsigned long)pool->pool_data,
-				     false);
+		kasan_mempool_unpoison_pages(element,
+					     (unsigned long)pool->pool_data);
 }
 
 static __always_inline void add_element(mempool_t *pool, void *element)
 {
 	BUG_ON(pool->curr_nr >= pool->min_nr);
 	poison_element(pool, element);
-	kasan_poison_element(pool, element);
-	pool->elements[pool->curr_nr++] = element;
+	if (kasan_poison_element(pool, element))
+		pool->elements[pool->curr_nr++] = element;
 }
 
 static void *remove_element(mempool_t *pool)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35771e9e5fc0fe2169c59f190fbd6bfc901b7c09.1699297309.git.andreyknvl%40google.com.

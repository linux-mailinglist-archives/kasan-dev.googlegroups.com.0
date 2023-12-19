Return-Path: <kasan-dev+bncBAABBPVTRCWAMGQEHD5BXFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 626B7819395
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:27 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40c49cb08fcsf39329775e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025087; cv=pass;
        d=google.com; s=arc-20160816;
        b=LGLNvRFg1Sz1OEPOASaYF8qws1qZqLORq/8CvymuI+DW7zhGlNukmuIJSlv1T5SGEb
         L7W14DprQbZDvlm71Hrlb2JPkX2/HKuyd5mk+Rzb+QddTlxx4+BXTUdh/H2XL5+QidCy
         UcRUpT1VisFDWvd/Y67gBkpt+Tu2S4Wo+bb1TVfMP2i4dFXAdZY+3mD0JH40GqDtwtIT
         qyyx03dkaX+9jAeZeOzQ15b5TjenyESFUYi6Zk8v2ssMob0/f0ii6Pum2QSPur3p8/3x
         ZKw79UkvBw1x703Tl1n4euxzb+hWHzYSPv0oYppaEPK3o6EeWXADUp8iOZMkCVRH0bZP
         njLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DqpyrJfVOLPr5rlyXWLNKeTzS+1XPL2rsE1lbcsOuF0=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=mv56d4OFLOxoblLZ6lLFLp3q1V8BwCoTGCI8bz4bX0FhfgTmLmGTWGJvRInNSCwNq1
         4ebzt1Os5EwrUwZsbH/7p4kK1YLASISZf4ttC+40EaDlxbdZR8lPwzIBGY4G1bSOQG+o
         +QvBD71RUcH2Uoknnn6AxxXvuj/2zoQpWIIzudw0jEN44vIrQSumW2l44DWuH4N6yWAX
         Lwl+BzRMWmYjaCGKbbujrSrJsaBrItEDH8w8Pq8pcHfPAevEeRSfeX0l5RPunSBGLoBX
         psX3ym/BUMTH6cJ+6ocLldQ1LGwgp+ZxnF0hJDSvOBQ7iDCuDeYBQQ2vUnSSSjObutBc
         r5qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fbafFq1j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025087; x=1703629887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DqpyrJfVOLPr5rlyXWLNKeTzS+1XPL2rsE1lbcsOuF0=;
        b=fRVddjtYdKuP1yMxEy1TajlxmeZil0UvxdIE8xa4ChBe7HmJbUTo92Q9+11gj9RSVB
         zcHK26utQjxIwtFy0STUhIdzkVpJ3vm6OsR+B5b1HOLIQyBQrhlOVnfhbW2Ar6nK9S9+
         h+ujoVH9fM2HQyxW8PF1Esp8zqFKUQzID2HoGTVaekROhOx9Oi1/fbmCcxDmHuKN7xYA
         ZOXzg+WcGfSL+5XL+E2xhnWGZAo7pJX0n88+PHUO75BKOMHHsV3unpAg9H5ewhKlHLYc
         o0hxqqghDBXPafoiRn3QtwIs1Ga42/Hdl8G0dakvLXUoYPVIER9r0wFX8o/Tx4kBHHa0
         kgFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025087; x=1703629887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DqpyrJfVOLPr5rlyXWLNKeTzS+1XPL2rsE1lbcsOuF0=;
        b=uizWbLYPO2Ti8JweVKdEpjz2SOUD77fTdNXQkmGRq9I6WuzeqVhEerbnklKQMRDcHE
         Wkhuy9V+2ShT5XcJttDuKs2E46Sw3Izs/cHu0q3eeaVjBE1j8iclP+/JF0L+Ef7t3Bkp
         BRJQ6RvrkKe4/WLU0lUTyjbiw62KGVSUo4PkDm26ffWH6OPD12ALA/ATgAbkLcqaI7+o
         0T1rzmd4p+tsaIOrzAo7YKNakR3CfjgFoyCRrKMBIRQhM2Old2tu8jkPhsh2Ptm9oNlT
         U/Rkf/cuSk/D2d0j6zsJ5XWqvQKw8e4LBhoP7reBj6Gm3CfdJdk330Db2VjWOkPTBBzj
         EDkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy9i1w+/7695bBRgq2zyk2fMb+ZJYn1/Nlp6ysNGaeyUDigAxtu
	/+T4JUH1LD1c6BnfJEt7w9Q=
X-Google-Smtp-Source: AGHT+IFrEguRzEEKr0BMTlkLemVH+ICtz8RW8inoGvaf4tzuBLQq0YbfijocN0edAm6wnMtpHWBLhQ==
X-Received: by 2002:a5d:420e:0:b0:333:49a8:73e3 with SMTP id n14-20020a5d420e000000b0033349a873e3mr8901033wrq.34.1703025086716;
        Tue, 19 Dec 2023 14:31:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:efc6:0:b0:336:6e21:d6c3 with SMTP id i6-20020adfefc6000000b003366e21d6c3ls251204wrp.2.-pod-prod-04-eu;
 Tue, 19 Dec 2023 14:31:25 -0800 (PST)
X-Received: by 2002:a05:600c:2d84:b0:40c:36ff:7507 with SMTP id i4-20020a05600c2d8400b0040c36ff7507mr10229819wmg.70.1703025084990;
        Tue, 19 Dec 2023 14:31:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025084; cv=none;
        d=google.com; s=arc-20160816;
        b=O9TAiDq2dg/ktoSev0UCj/yihvQPaPVPOaaCG1oEeHg1OrmjzBqjYP+nWtAlwh48E+
         xoA9s5gf/UOSWt4oS9l9LFbBlremkMbVQDR6EziCJXXsYaMfBo2O38W5owH782s+uPC3
         C4PaWXno5I/DD5QoRMrfIarwJxb5aJKbzIUBrZUZxeQ5zdqIkWCSTyV8pwObP+MT90Kc
         1R/3M0nxY/XAG7bpffhVG0X47gIe4xi2mZkvLZye7Im/9Bxu2nDE1T9BahTHiI/yA4Rx
         nyZ4UHmkzSonGgaop8Aurs+Ff3p5gZnW7bscF9S4ncEnoB/tQ3++gT+TIVV4XgOfjwBC
         75mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZKMuCi1Fs+yi8i1iMj8jEYKxpwLo+oL8GkzWTmOTGSI=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=LFN5yGmbXxtQIjzmhkLsgaR7fwh6fwboOElLHIBS0XfMEjlk/p0jlu2d7izATtba/V
         O0YyjPTa+dEb8Zn0tKnqDhhZ6eAwHhcAWXH4A1TTqM//8bQp/Tr9K02cONbzD3kJ0T4X
         aylpz0koIANLmLqROIV79GkOHhEJMzHxwMKjwPEhFXqPJWHm2VBylNRWTnT88i8LQzNq
         7xhbZTyeOKPjF7UkwXxfBkzojtB1GpDVbDeIuUCZ4XiN/MTm7k1fsZqjWDy6VBe8H0PS
         qDbnFJBCqsCBc7ouNO+ks8L5bUvDOrRtzxaAsXI2DbAIvVEbyt8B2HPnv6vgwe4rFAgN
         xBbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fbafFq1j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id e16-20020a05600c4e5000b0040b4055397csi278wmq.1.2023.12.19.14.31.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
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
Subject: [PATCH mm 14/21] mempool: use new mempool KASAN hooks
Date: Tue, 19 Dec 2023 23:28:58 +0100
Message-Id: <d36fc4a6865bdbd297cadb46b67641d436849f4c.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fbafFq1j;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 1fd39478c85e..103dc4770cfb 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -112,32 +112,34 @@ static inline void poison_element(mempool_t *pool, void *element)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d36fc4a6865bdbd297cadb46b67641d436849f4c.1703024586.git.andreyknvl%40google.com.

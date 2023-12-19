Return-Path: <kasan-dev+bncBAABBAFURCWAMGQEDKRO2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 276398193A2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:32:33 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50e2a3a1706sf2871649e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:32:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025152; cv=pass;
        d=google.com; s=arc-20160816;
        b=sAEQGSppSARTQ+l/peLfru5tTb7ZzvohR7lq7wnxgK7nCAIym4hjxOeRE1c2B6xDM+
         jp2g2rFpARSea6vvQw8WjLRCq5XAvymJvKMSwktJIlQSENxhzjVW7OPDR2CkCn/4wlSR
         8v49qaMKtl1jPzEm/wnobaer5suBUOQNIXUHJ4WOMZr13CSUUrdTShHhUTEXjAda4l3h
         cf4GbpIsm6HTLZHx56ZB9hKHUz/g4mAzP4yQ34Rp91B7SOj1r90x3VJdr5msKr9I9n9t
         627nbAEm493DMr4rPlEi5cbkup8+BRs4QAKhrtHbgmB6rbrQ+BtwLfYt9fCUQ+9aKoeI
         rEiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XXeAxXckZ12MNg1w0/lotMPwlIWPMVq4HW2zg5GX8Go=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=WUUxdOKYEbN7Mhlurx3raaG7E1yDCfh1vbmX9zjqGhp7L0KwGzSTtkUUTRT93CNvek
         LJ4nw96wbrJwa4HVxmjlb5DRaz/d0IzfBPD7XIidxeFYNzfSdGkxutHp1iLhrZwitGHV
         1LYm9lVt/B8k8PtobtGHW49Wj9CmkMmnYrjIjAh/RO2E5q3TuY30MgttrZUFXTJoepVR
         o/3ZmbSY/ci3tKUDf5aGZAQ83xd0HCwWWfbbKSuswb4b4WV+JWz4cku0D4BQG7oAPA23
         tTOJMi7roIAOPNCSdsaEZHWhUSgRzW+iOe+n5GcncvRGTDDtTvwHOYVIV1lTk2svzBG4
         H/FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="ljf0/KaK";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025152; x=1703629952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XXeAxXckZ12MNg1w0/lotMPwlIWPMVq4HW2zg5GX8Go=;
        b=ZMXR9nhdBMhQ/xO3ncoF4z0RtqK7zQH2CtNyyOx7HhuqcSmi2bKewJ0aCQpXaYy7UW
         CyAiV5AeZvzzC+tpuOokYzcBTxnYU9/1LXnleAaBjudvraf6x/z86Nqrm6V7PxTbok2P
         uue3Ll8M0jsf0F3tFao2oSKFbwFTOYx8hdg8xDCiLxxCIA/1dq7SfOvmPpsTSrUWVaW6
         ooGKm5xGF17j3OI+YBQhFGXpt/F0i39leQJ7wAdFn+FUc8nnwDITEHCdPU7uyjKaH10F
         8jRv/vZfvhzn/X6AY3u0bysRMXB4iwPxoorAEDvPQHw2VtAD8frst1Rk4g2hD4MbvHyN
         Zsfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025152; x=1703629952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XXeAxXckZ12MNg1w0/lotMPwlIWPMVq4HW2zg5GX8Go=;
        b=C0gNIpnM+Qt5hRb3VwLt9GknOKOoR45X7CVVSDoHvSGjL0qOjAUywwbaybNWxIouCG
         hgUj6hxw1phYJ7hh7l14XGO4l1ZS/3iMOQSYEEXS5w1L1D2gq6H1WxsqXRsEC3RXA7Vw
         l49uBDPIb5m6eMcOujHPB57m8s7ho3vhI4eaIktJi36C8O52PToG4muSH1Cx5F40xZaR
         W9RVZ/lZ+p2gAjlXqYqn8Snyf7g/6A0gZfjikiOYwXwR8yDJ8J8OskfShsr30AdLAP37
         hPQYrRwnJYRSddxTSy3e8HmBsLx36tUJCosr1ojQzqJG4LjsA7FqX3Xz6py7SHQ4c4RH
         oFKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YysJjeYzKmAUbmr+npkuQymRUE4HgUSZUpwxQopaNG2ZyB9U0o2
	q7nNoIiWSCJQuBC6MQFw2ek=
X-Google-Smtp-Source: AGHT+IEP1Fq77a1tRGMCs4pGxSPGpOXmaI7jyWNrb+Qyuv3BUjNz8a4uPX8JThixXjLVVqdUMsPYYA==
X-Received: by 2002:a19:6405:0:b0:50e:31b0:94f9 with SMTP id y5-20020a196405000000b0050e31b094f9mr2213377lfb.12.1703025152357;
        Tue, 19 Dec 2023 14:32:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d6:b0:50e:4018:274d with SMTP id
 k22-20020a05651210d600b0050e4018274dls509886lfg.0.-pod-prod-07-eu; Tue, 19
 Dec 2023 14:32:31 -0800 (PST)
X-Received: by 2002:a05:6512:3d08:b0:50b:f0de:621a with SMTP id d8-20020a0565123d0800b0050bf0de621amr10744006lfv.22.1703025150693;
        Tue, 19 Dec 2023 14:32:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025150; cv=none;
        d=google.com; s=arc-20160816;
        b=MfSsku0Q8JcvhNBzH86C2vweizczC7ZqCkIoEFyYqlEqj8nerjkyKlGUtQWpu1tL13
         RD13aq+6/BbfYKK9uJblxQEdS1gm3vHuUhUIcyhLS1mM3uxBJq9ztuqPrdcbs0UaI8S7
         XSIC+2OLiNMQ3hhP6zwzQj3c78+BY7bOu7JUak2+DIOuX8b9XPJFF4VjwceJYmW1F4No
         NLS9OdR+VXUdvDyXbaO5ZKlvLMzPZRuBxkpeivDDYuvNU/Q2PsijqNKXMON0dE1cIe5U
         QXOXWkJJ+DT3NL/yyz+3TsAoyg360FA7+/Tyktht2pdXWWT8H2273+2u7zDu6uifVwxW
         kN+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e29xpsueqsta+pB4dpMwNezQWpITpFZrOcR7dgpqXnM=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=HoAXbLAxyKo91IvPI/gXllxLZEwWwp4+MXhmL4gQeDQR00AnPJuHOIEMb3USOZ52c2
         e+5qeaccLu/ixB+BVS3fv7lrgavE/tQmog2Tz60NfNgBWMv4UnoyqouFdwEOWxIMNOx/
         h9wtOmDyx1mHS0+63s50X8EIWsMLbsmBBILmxnf1gg5VPHnBBBbCKPIn2AP0mATHv8RW
         qvGUk26ZD9PbrOs/UnIfHZm9x0RYbPeeWru1wjfkWuRYllJqnR04XO/45W2OJ5ZSW9vx
         +y5LC16B93tysv6RMKKzp8sG8vNqCZDH3hIHCKrvTGjUwztso+1TQsY3leonOkeGLq7T
         81Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="ljf0/KaK";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [95.215.58.185])
        by gmr-mx.google.com with ESMTPS id u21-20020ac258d5000000b0050e27f0ec11si401860lfo.4.2023.12.19.14.32.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:32:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) client-ip=95.215.58.185;
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
Subject: [PATCH mm 20/21] skbuff: use mempool KASAN hooks
Date: Tue, 19 Dec 2023 23:29:04 +0100
Message-Id: <a3482c41395c69baa80eb59dbb06beef213d2a14.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="ljf0/KaK";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as
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

Instead of using slab-internal KASAN hooks for poisoning and unpoisoning
cached objects, use the proper mempool KASAN hooks.

Also check the return value of kasan_mempool_poison_object to prevent
double-free and invali-free bugs.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 net/core/skbuff.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 63bb6526399d..bb75b4272992 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -337,7 +337,7 @@ static struct sk_buff *napi_skb_cache_get(void)
 	}
 
 	skb = nc->skb_cache[--nc->skb_count];
-	kasan_unpoison_new_object(skbuff_cache, skb);
+	kasan_mempool_unpoison_object(skb, kmem_cache_size(skbuff_cache));
 
 	return skb;
 }
@@ -1309,13 +1309,15 @@ static void napi_skb_cache_put(struct sk_buff *skb)
 	struct napi_alloc_cache *nc = this_cpu_ptr(&napi_alloc_cache);
 	u32 i;
 
-	kasan_poison_new_object(skbuff_cache, skb);
+	if (!kasan_mempool_poison_object(skb))
+		return;
+
 	nc->skb_cache[nc->skb_count++] = skb;
 
 	if (unlikely(nc->skb_count == NAPI_SKB_CACHE_SIZE)) {
 		for (i = NAPI_SKB_CACHE_HALF; i < NAPI_SKB_CACHE_SIZE; i++)
-			kasan_unpoison_new_object(skbuff_cache,
-						  nc->skb_cache[i]);
+			kasan_mempool_unpoison_object(nc->skb_cache[i],
+						kmem_cache_size(skbuff_cache));
 
 		kmem_cache_free_bulk(skbuff_cache, NAPI_SKB_CACHE_HALF,
 				     nc->skb_cache + NAPI_SKB_CACHE_HALF);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3482c41395c69baa80eb59dbb06beef213d2a14.1703024586.git.andreyknvl%40google.com.

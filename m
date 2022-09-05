Return-Path: <kasan-dev+bncBAABBNOK3GMAMGQELQXJNWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 75AEB5ADAA0
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:05 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id xh12-20020a170906da8c00b007413144e87fsf2630289ejb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412085; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rw6mfxJm+byfj6IxaVi8ZOV2QKXVnflmA6gjwoVKJQHAHw/760eguBQIIjAxltkTit
         uPeEwCtb+QissWxh14aUkNQxbJOOHOZSldBsyNq+ZcJRCTfdVuJ7iw6o0559niysgplY
         8WQvm9deXo4Q6PHBKxrWGJifkRV8O0h+ZLsKFOkYdHFnsSCTeCyzVbhZ3cKKMvPhMf3t
         pj5uJmNQcYzGAKmU7L7NwNu1ckEAX9WPcl5+5iJF9QnkF53C+9or4dKEwinQoZUPQ/mT
         nB6VR0ZOji0pDAuFPHc7hpXfQABXwQ4GnyRAou9dX7n/7weeRm/99fKM68lEIgMQY7tB
         V26g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6gi0KtIeGnIK/Peh7/zxfo6D4V92UsO+7pt7VlDfrfo=;
        b=vQ9CO1sAhoelq0MLMJQGjoHGEBiQ1BXtu8JFQ5rpvWCVmeF43yPkpyCRyuG3mTtk6x
         Cyze1nUcjWlteEX4RczEnXb9kQyuafR0dIJo8Nbxjq4WWFzGtLvFs9GwnY7MUhXLHmoT
         rLA8O723tMhRu/Lv4BGh0ZF0GvMUzKM/r+PKAX+rm9ukX77MP9RRWKIYdvrT+7ka3DyL
         DOi3gWFbKYQ5AGeq4qMwgbz080VU6FQEsEsflwy3pXnnqJA+0kM3OAtz28Dc4V5H44/F
         87HptRE0iduyCFFo10K3THKEE0ETprNCQgUSu1csIvbU942hsHVe1oycdlXjAhNupp/j
         J1vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k9Gvhrle;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=6gi0KtIeGnIK/Peh7/zxfo6D4V92UsO+7pt7VlDfrfo=;
        b=YzyJ8eAJBNiJbMkxx+X0t2yTG0NYUiq9DGlKDczNzrf26JMyldo8kb6kWxapQ2W9bM
         f0bcK9ZVIwoDBsTqMx+aaxIl7PHWV+Z/yN5gc63Vr4cZhIJP69MDnyqqVLXqqaCZtFgJ
         usvR/2AiGcHUn9BCjZ0MSos2aF+UHyIMPUevjs5fqit7D52Mg5ab1ErpqNMfeMxRkD5v
         eQDbMX59gBfd1NH+MVwVAHVR49Wi1RkycOa9mBwnnFbdeyzSm4crF/SnR/xeOLz3HydP
         WFGpZBc9kdMghRpBWDE1T1JWzq2gYyBSbJW+EN6bqW6iRqfI16XGY30ziVqFEsTu1cx5
         0hTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=6gi0KtIeGnIK/Peh7/zxfo6D4V92UsO+7pt7VlDfrfo=;
        b=dwMpfddL3yf9QIm1S7Wu1Xah5En+ZIfOiab8wGtM90U1xerSaGS05a7PqxZPY7Ilcl
         s50kI0xZfkKCyUTZNxYi/IMf8xsufYKxOCcWbqEvdpDTkGdPnh0OOS5XSr+BJeR+NBR0
         zFpXeitQ7stY/p3n0n9tCSWkC47PhAvTdfE+79Og/N3rFC8eNTVY6uzIk1EfQgcCUZHP
         2B5v7FUI1TwgdG5KwJNNPnNL7T7d8sQ64YE/LBgKiLtsNMx8fbnPMXJ5CNJZHyY6gTxm
         Ku1IDMGGTKSPnKS/GrckFpm4QK4Bftt/9EO8fTPQF1hg0PGWDFP2pmMuFkIsckidDaEL
         D6hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3qxGeKUz+LDwJCPp5pLHWTyohqgCIeHFnrhhJj4beXGcMZyP5b
	QrZ4GcMYdrq22282Z+B9fJk=
X-Google-Smtp-Source: AA6agR5C1O7DzjmygyH9okhl0Qcib4LXW+qdmEBIWB88s3MLpiPNBltKNdGf2YG/XpLO2udVCughbQ==
X-Received: by 2002:a05:6402:248a:b0:440:9709:df09 with SMTP id q10-20020a056402248a00b004409709df09mr45304387eda.42.1662412085219;
        Mon, 05 Sep 2022 14:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:274e:b0:44e:93b9:21c8 with SMTP id
 z14-20020a056402274e00b0044e93b921c8ls2840051edd.1.-pod-prod-gmail; Mon, 05
 Sep 2022 14:08:04 -0700 (PDT)
X-Received: by 2002:a05:6402:3546:b0:43e:466c:d4ed with SMTP id f6-20020a056402354600b0043e466cd4edmr45189301edd.48.1662412084439;
        Mon, 05 Sep 2022 14:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412084; cv=none;
        d=google.com; s=arc-20160816;
        b=bQPc+cCALx1OJYtSEdRf90PuMnHQ0Wq3JYErhsHoakyzjuVFO7kPVVcZmy55aofMuf
         puy7lNFnbPg62rt3kv1tHphZULUeMK/EeAHS2zNSVsOcwkCVpYl79uX/vcbjSu6F0NT3
         kIog2QkApf1HiqA4FI12gtMpCQ8MGNpJXopOuu8zFkWBCkCnIGU0hBujx3WdXEJ6Y6Mb
         A79+oN8eLhF66XVF7KnVBK4+kNJT2bANKJHRoaEQnu3a66Uwx2QrAfzwjCDrHeTu3pXn
         9yPl0OZvEDiujixQUgwZgnXgEnbYNaCl8MMzOI2sYpXMyjAF/8I5bC44TSB2OHEWDI8/
         zbyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3Ia3unTlaKp85Rb8pWqelG9+mYXrhoeUqospQVb1dz0=;
        b=Hb1lNysoyAtmJzi4nNJIwzoL4BTcuok4zUwl1pCsh0T2YIKVgSzgATw/4WVBKrY/+J
         nRO/KPiP99/6gVL4MiHm9TfYjU8borQhm2RpdSdlbJVt8wLa0W/8o6dHiz6M2Bf8B9d7
         qr+RWBUNFHH7ZWcrv8VFpPwvceVyee3GEK6c3b0d5fsr34+1lKl5BqhdXeL395d5xt3a
         lSeUi50Ekc49bb+cl8VVoJEJuf+4/Vf15PA+e16YMBHF6gz4NE8ZdOV88WGYzOUzWgE1
         CtpWcGMUN3b8ontELrYtlVLfucKJprKBwQ5fdsFmQIJB2Li/AAbExSUgLVNS/pS5Ad1e
         Iwtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k9Gvhrle;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id a20-20020a50ff14000000b0044608a57fbesi311877edu.4.2022.09.05.14.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 13/34] kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
Date: Mon,  5 Sep 2022 23:05:28 +0200
Message-Id: <211f8f2b213aa91e9148ca63342990b491c4917a.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=k9Gvhrle;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

As kasan_init_cache_meta() is only defined for the Generic mode, it does
not require the CONFIG_KASAN_GENERIC check.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 6 ------
 1 file changed, 6 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 73aea784040a..5125fad76f70 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -367,12 +367,6 @@ void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size)
 		/* Continue, since free meta might still fit. */
 	}
 
-	/* Only the generic mode uses free meta or flexible redzones. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-		return;
-	}
-
 	/*
 	 * Add free meta into redzone when it's not possible to store
 	 * it in the object. This is the case when:
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/211f8f2b213aa91e9148ca63342990b491c4917a.1662411799.git.andreyknvl%40google.com.

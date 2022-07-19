Return-Path: <kasan-dev+bncBAABB3XN26LAMGQEJ577UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D20578ED9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:30 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id v18-20020a05600c215200b003a2fea66b7csf4844507wml.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189550; cv=pass;
        d=google.com; s=arc-20160816;
        b=vTuXYOE13WAygwFRfffj95IN4YvmUXLpqetBsUFPnPBh4c3m55GR/Dn+w281PixVWD
         DODptMTKDyT/UbgDfHxCKfLB2dh5ctSiXNzMoGAe3BIQE20eQbAonHWaCElJCdTitu4c
         R6sivCTQVBczeO2MKSn6RKqAPlvUBKMmxdZeGISp6d+Bdkd31NjcUcCJ5GrzxIbMp1sy
         1TmiAK/FH2jHxOjFiKQFN1Oa5YvjUe7d6YkDv6IvbbmDufYvbxjGx8D5bKsT1AX+2Cwg
         N96GWjIaB8TqOLTE/ftj4c7h/zayCqjXWyw4p65aYa4YdSxyBYKe8mEM81XRmCdHbKi+
         yDyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D4zV2D76fTs1169XtQI5vSn+FeAsQ/WDTTJPv2vZTQY=;
        b=PQJ2ScFfl3voyH6ccJFNSgLpdooHt/8dUx8nxapL8QcCtAuIFYG4syCTJBOSnnU76D
         jatN4Z3j4yebFWIXhPJ0b+1oib2bXLgRUBgDGCxZ4Q9gTdc42UalPAql8uogLaOyIm/D
         E73RMANZaB9TU5LFfAQWfqXeXFKQ0sXZXCyAVbbXmrsAa0dSq2aLjyAEPiCLgTVu8dlf
         9RpdfShaGAR7y+wKWP+t24zLkLkF4Ve3IlhB8ytO/3nWJ2skNVZ3XYhIus2+9hMaTyg2
         g7hpyFxn1aoZ6wUIBhg2anvNUIWxzj3FWxZqHvEomYD5hZ6eGW/P+UkhuiWZY9WQoew0
         xJBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GGtCf53T;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4zV2D76fTs1169XtQI5vSn+FeAsQ/WDTTJPv2vZTQY=;
        b=b+ekDmZ9p2XyqHMBYsNvyXjfFuA6trMizQh+TWfTawtyXNqRczy0rJPvwpgVuS/m2b
         c4R1BsiHef80qH05teaWz0qChVgKVuLLdLSRi9F3QnOqmyGmqly4+rFl3gFkNqfSWgrL
         7Y/o0FqBaz77sNzj6JksL8GrRUX+ZlyLw8ZZWuI14WEllIaW8fIK3/anPxzFVIRHRz/6
         rdze4uUxTd9FdtKeqnSOA3dGlhrrY4zG0wnYz/dgoxCtYa14DW4FjMOEi45TCYBjzE49
         BKENolcQy/DIH0ZXkQtOt+ZqLyu0lE5pfDfn6gjR3V+wOPxU8hYiVIbfvKgaZ29u9re/
         Ub9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4zV2D76fTs1169XtQI5vSn+FeAsQ/WDTTJPv2vZTQY=;
        b=Zn+Y6c3sLxrlAOqtAZaRLFkOnnQaObvMaIO0tGl3T2YK0ZZMlI0PjNQ2t0M7wXyc0i
         gE6Lk6EHhrvcRlzXImRFwIUL3TXahprzunYygO+7E65nxrdFXSJISGh7AkMGADfpkAbS
         znjEmk8SG7jsZPKTt13L8eY7+H+PAvyuTXX+5SxZ+6BHgzSg0oh662tXq9Sy/8ij0QNU
         U3kn76P+aZOfaUTYq5UoCPeTTpq3gr6v0DjIh8lQDYOa4G3okZ2t1QeWTcyl1m5cyRIe
         UZEAGittKekbTrcr91hUbkQ10L1T1rv1ZdWIjbJaXoI/9oFawOjh9XnMcvpNhVWnUs/W
         WprQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora81QZ9rvehbY0e7Jb8/u2J9e55+RqoKGr+sYtB/1qTO0LjG3Mtt
	xQK2oI9C5clxPbeHAQ+r0So=
X-Google-Smtp-Source: AGRyM1uIiT7+xX4m3eONEKgSKSFGDI+cRT34lk48rvlfAo1vLC//CJVjB/Ly1qedUYa+flcTJRrQNw==
X-Received: by 2002:a05:6000:1681:b0:21d:85a7:4ed with SMTP id y1-20020a056000168100b0021d85a704edmr24414924wrd.345.1658189550518;
        Mon, 18 Jul 2022 17:12:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a42:b0:39c:5927:3fa0 with SMTP id
 c2-20020a05600c0a4200b0039c59273fa0ls41923wmq.2.-pod-canary-gmail; Mon, 18
 Jul 2022 17:12:29 -0700 (PDT)
X-Received: by 2002:a05:600c:4e4b:b0:3a3:19bf:35e1 with SMTP id e11-20020a05600c4e4b00b003a319bf35e1mr7862926wmq.74.1658189549810;
        Mon, 18 Jul 2022 17:12:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189549; cv=none;
        d=google.com; s=arc-20160816;
        b=xUXcDrHn8irxk5l5KN9bYcBmQqcFzOUtJuRrb8KdRfXrvFU1j6nLNXzJl8mvrXGT8i
         hq9EJs574LPU4eFnib0YD8wwRiReWBbUO9zNL0K/viz4GvrIvXhqVUlw6ea31SBBgCQc
         z8pif1DU55g+Zc6yaEYZeXeWwn47JpBG+MiG8pwd/WEv+51aZDHH9HB1fQcWZfISq878
         krffnNPLP0kP7dXoHxRlfC6A33kmmw5q7YFUYiDpJCuRUYrPCMjbes05BoZm+dM9ZRB4
         uMN6UYhu6njqW5+Zqo6CzP8CPgnLg+ucnrD/C9j1ThTPeYcJvuIN5BVJ90o/Wy0CibTP
         mKyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gFl1aLadfWJPQ+Xg4RcAPABChePIqsdWPpe8i7e+EqU=;
        b=iZcehjc5V3ruQHqoxW3Memi+YRx+PtGnE2YSLsMrcb8bn2DGtIr28aIRnMQO3GwCBr
         MSF6B4pP5W/hMi+q5qDK/tm9Lxf18JDQXIiI7ie5Vdu2elccEZopbiOnMJFDzjledwqh
         nTLvyT7pWg+7It9Cv4R3Pfpw2Nuc4eyLLPoe/5qx60zPShXZi5I5eQQfS5Nf91AWZU47
         oi0kIm0/+ETiXTL+Stg6hOsMgRyDnEXg9vq0Nn4Pcq7KWMdWwrXKLkp2p87xG+LHOCHp
         BBGy2hH6fWW3O+LF6HkH6UEV2UJcBlHdD00+dGGnPRTM7VyseU0a3MQ0CDzJ26ZIKIiJ
         ZxVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GGtCf53T;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id k7-20020a7bc407000000b003a31dd38c4esi105671wmi.2.2022.07.18.17.12.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 13/33] kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
Date: Tue, 19 Jul 2022 02:09:53 +0200
Message-Id: <b523760220958f50e3a04b281b635551cecd6c78.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GGtCf53T;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b523760220958f50e3a04b281b635551cecd6c78.1658189199.git.andreyknvl%40google.com.

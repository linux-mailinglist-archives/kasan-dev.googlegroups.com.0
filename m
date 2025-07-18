Return-Path: <kasan-dev+bncBCSL7B6LWYHBBQGX5HBQMGQEWUJRBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0382FB0A7D5
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 17:44:02 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3a4f7ebfd00sf1054905f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 08:44:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752853441; cv=pass;
        d=google.com; s=arc-20240605;
        b=ChlxhcrPR6els0If5J7CZfRSZh+NvCR9wYfrbEZZMDMYmheeRYXN/ED8amrhk0Fm4X
         jtCfPo97Y8mY44aMEnezyFCDjF24cYdlnRhz1unYY07c6nOqDkJR+vKtQoGv9jo5w667
         keUxp4C0m0bdzgYunewxcgYpgGYo67Ong0T5zpqYojCK6M+jbGvJ/1dTjy9OdduAFxA6
         9+YGyzKBKF9JzMKA3afjQXeosZwYHOkmG426OpCCGwIuPmi6dIoWsXoucHdNzoVG38Mg
         Dmb0eFGyNnT3Y31fYkjgArpV8iEfkt+n52NUq/qc2rFw5C2TpSac1F3Bo3N38xPNSM/L
         UTiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=Hhaecm2Er/TvCfjhhkk6qXdoF9tHiRw3JObCOGIQ9ok=;
        fh=uxALio2oSb59rS7fpsTfYjPolwM3VK+y4DmkyoBfQ1o=;
        b=fcaxCypwCoK8rYT2f59xqTdOWWmtbWLG92GU+MU9tiANiQ9yjNideFG1oG8+ANZr19
         UpTIHjlDY4F4h55QzZ8DieYIItDqEv+HAd3nBJAuRNuK9YzCI7Mvwjd3gGxlytqzVoWH
         9v6XWIa4zDHUTxTaBILjbYAfWNNhYPXXDnamU/yeqtSgJOcB07LMLl+Z2y+TFu3E6Ntv
         nkPbmL/VMeqhz0budFF5TyDgVj7Sz8T2vXHkAUUzI40j1yKD4AgZDo/LuvxAj//Qyw5H
         zrip7yBZQfC85kBJuNHD3cbD7qaLkfoQ6pFVjb6BM83ylRRecEsSRV/h4qwtY26gzfiV
         f7Rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D8bouPdg;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752853441; x=1753458241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Hhaecm2Er/TvCfjhhkk6qXdoF9tHiRw3JObCOGIQ9ok=;
        b=qvwUzBe8VmlTIAxFYsBLq2WSpm+M1/gNAkoTMQfX6fltN5RjnXN/GNnfY1T0rrV3hV
         TJy12binplcfL1508GTmWOc9IzCeNnVg2oXs8YvfjFsuCpbgoL3xGVm4L38MXWcFVqlW
         c3ulNHWrRHXk7GlenQlLLWO1xPZN19cAHgqST5luE7kMh65wVPGSLz8ZTFyumWTO1Ak6
         taojjJki/vLSZXwuTWQxNoMuDVEstttYv1OXaB3qz162LUn9KdXAUA3gapjHKaRGbwGO
         LP5KUzYqmQYq+V6Db9JcTO94BWD9Na1Saai9eBn1DvoBeOTk3zCREBglFVjhR+PmPgXO
         4y0A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752853441; x=1753458241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hhaecm2Er/TvCfjhhkk6qXdoF9tHiRw3JObCOGIQ9ok=;
        b=GvTwcnlOgzkoAPMvSsvria4fXmlY89KifXMuufIM4qsh/E9OT5lh4mZeOXYDEeAU0Q
         OCHTow9rIuzn9Yzg+xF3+X/LPaYRYJE2JtixSdT+wws4ItC4525UR/r8er3ggmwfqbJX
         xtQwsAevs3pN6zFJ+Chek1zwcWlfNkg9JcNhr52ywrGkoUD884CPZ4haOkXECBVjQcfx
         JgkPxVasMCb5EZaPyt0aYZIa8zYbs1xzEnNF3WzjiE6D7SEWsawToIh3oorFWXs6FnH5
         KZ4uPjsy7q7NykEn1jnFlnFfIneuB9miVgpZtgrMdtWwtMe8QKmtMu4oJEsTSSv0On8M
         qmFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752853441; x=1753458241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Hhaecm2Er/TvCfjhhkk6qXdoF9tHiRw3JObCOGIQ9ok=;
        b=fZxHQRUFeMKmipNfQP2oTYIe5LzmVY5AS2lV/moa69XCI1cZiPqxytLbpOYz5mG8J/
         eN110zkKZHL7PxH8f980GMG7OGUGmwnmEY63w8XRDc9NYoMegJNTPskr+RtjsvYWCUR4
         U6byH0gNIqrRq4X+2vysCK5vtPZ02mFJ22abeJybJmyZN7NJsV8AjE0TRwV+xGDt1N38
         iEQbUZdCHT62om3bw3IjDGHx+d3eHW6ZTz/03iEJblWWfSrOFpRlWe910dRUq1Gomgk9
         tpxiec7o0SjlZM9yqiOyvDEKVS9QG/pDx2UxBPhMXwPDp8JNhU/alr1h1YB1jDlPC65h
         6YVw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOg+iwjk9w7gXz2XP5KGwIVwm+TRcgXF/bevnd6+rQoMqtl/ji49ISvlSTsevmh5w2feHzEw==@lfdr.de
X-Gm-Message-State: AOJu0YwDNSkd3eiqcH00f+fOb1ljNsY7Me5pqxuz7WmTU4G5Vo4sRDF+
	TxJzjlVkZ/ziJEKU9dWTVk7NNnfl4vQkVdKje8RKIV2NIDmaD4RGZcyv
X-Google-Smtp-Source: AGHT+IEiratFeSfdxUSqBL12jyMe7AdFU8QpdWbtIC5shZoXcRxiZxhs6J3K9mEItHf4BJg88bVjKQ==
X-Received: by 2002:a05:6000:310b:b0:3a5:1f2:68f3 with SMTP id ffacd0b85a97d-3b613ea2b99mr6181778f8f.46.1752853440925;
        Fri, 18 Jul 2025 08:44:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf2eG61S3DEwMypBG/iDrLP0S9kDRJwkWaiIoOm13CZlA==
Received: by 2002:a05:600c:8208:b0:456:43c:dcde with SMTP id
 5b1f17b1804b1-456340ae986ls12339985e9.2.-pod-prod-03-eu; Fri, 18 Jul 2025
 08:43:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRbMsru8v0E+jpu/mYmv1MG+ET9dKHVGKcarcVA5m6G6s36A9B8Y9FBYWswky1DvagHHOJxqLCUCs=@googlegroups.com
X-Received: by 2002:a05:600c:3b11:b0:456:11db:2f0f with SMTP id 5b1f17b1804b1-4563532c395mr72537545e9.16.1752853438062;
        Fri, 18 Jul 2025 08:43:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752853438; cv=none;
        d=google.com; s=arc-20240605;
        b=j75DYOaVj3JWR5vw6dMAEjBYK0iyAJ1W5f4Ud7QKBxn7c3Tf90462ST4UtoJwI/MG4
         +ybUfUlWi0U3l8LqobV9bQHXbCobRZDlT8yLNrk+Zxuu++NpI47WV6ZBh6KfseUE2tY/
         +og2CPh5ekHTUoAPGdsheliWgnQVA03E9hqnKkyx9aGvAGsN9U8XnUIxStq5nwURD4TZ
         miOT10Wobx/wTb3KzHwrDbLzsWfrGhiR0FOmCbm0U38QuxyxBVh9J0ki7hBXRGYu4QcT
         wTKrBgP/NBf7HWfjmW731y/gvb4ToFmJvWlMJ53ya91BjKjqUbsELIMF0anCgrROuRhY
         h4xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=hJ3ROjwqD3CLXG2IiheiI0iDXPqsbWX3BCQXRvH9p54=;
        fh=j+hxJnyL0SnhTIvDG72UNayRoezZReEPeWYa/z6RLG0=;
        b=cSV4rwkw0i7KQhv+ahjmNKe7bJtxQxXW9HAm8XO1BlVKA4g8qtq2xQ0ABvi81kiTlW
         A/n/rXJE1j2BarRgOIiVKweMunkSzY60xUN4c81dhyIYPCrHRtcskphLjiM+Vzp+6M/V
         LSvavcvxyTWSpPQTw4XfVQRaSz4LNb4dOEwnY2eL8n1FUFF2AYwM8LiFkqcw8R4ejgsR
         kC0KiHfAbCaEaKvdaGTnItxSTUq2qja2SECAzYUONyl4ql+dyNe8ZB29U2TCBwIFjxMI
         3r98QM3pzkvLtdSa3nzhAxVRI+zLlyFcLJS0N8iXJDCl/R+l1wDdd9UQ9hupQZCBE4Fw
         BP4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D8bouPdg;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45626c7b1dbsi2882145e9.0.2025.07.18.08.43.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jul 2025 08:43:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-32f00cb318fso2787421fa.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 08:43:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV45+3cuzcvgV3YgZTGZP5R+ZesvpDdEwNNtWVTeMPdvG2vf+7TV1aamnKsASXEwmzXpqUzKU+8rBw=@googlegroups.com
X-Gm-Gg: ASbGncv+qzR8Uu737BqwDkex+CzcAPOww4FHekGJSIzWfUvr45VS6OTK5IQ2boDlx0q
	XapBlyBeHTToQtRF2IWMmob68T219y4C/LIgVKQ2Pg9P6Plor6FHac65Ju3/Ruuws+nmkLpl6hC
	cgAj2oq0XUCF2eGM97BqWvnIDye9CU4P/V9KoH2glM7DaUDPP25KwPAy1Xyzm/PwRk+4D5+kC1V
	nYW6vgpH4qsih9c9NebHUvntu8xLqObzWYkcig5NOg8fECmrwCAbmIdBbxnXmkdjuBd+0G2oFZk
	xLRmaM5v+IWz+Sxu/eRlKlKsmACnEwFU6ZKy/7XlnVrrsdYlFltx1G4ERFj10IHVHtgobrp6EEM
	yRTcMCxZcs60MimUuwQntx+eauIuK
X-Received: by 2002:a05:6512:128a:b0:545:ece:82d5 with SMTP id 2adb3069b0e04-55a233a28b1mr1360799e87.13.1752853436956;
        Fri, 18 Jul 2025 08:43:56 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55a31d7c777sm299394e87.116.2025.07.18.08.43.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jul 2025 08:43:55 -0700 (PDT)
Message-ID: <0004f2ed-ac2b-4d93-8a4d-d01cbede94a2@gmail.com>
Date: Fri, 18 Jul 2025 17:43:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: use vmalloc_dump_obj() for vmalloc error reports
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 Uladzislau Rezki <urezki@gmail.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Yeoreum Yun <yeoreum.yun@arm.com>, Yunseong Kim <ysk@kzalloc.com>,
 stable@vger.kernel.org
References: <20250716152448.3877201-1-elver@google.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250716152448.3877201-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=D8bouPdg;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/16/25 5:23 PM, Marco Elver wrote:
> Since 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent
> possible deadlock"), more detailed info about the vmalloc mapping and
> the origin was dropped due to potential deadlocks.
> 
> While fixing the deadlock is necessary, that patch was too quick in
> killing an otherwise useful feature, and did no due-diligence in
> understanding if an alternative option is available.
> 
> Restore printing more helpful vmalloc allocation info in KASAN reports
> with the help of vmalloc_dump_obj(). Example report:
> 
> | BUG: KASAN: vmalloc-out-of-bounds in vmalloc_oob+0x4c9/0x610
> | Read of size 1 at addr ffffc900002fd7f3 by task kunit_try_catch/493
> |
> | CPU: [...]
> | Call Trace:
> |  <TASK>
> |  dump_stack_lvl+0xa8/0xf0
> |  print_report+0x17e/0x810
> |  kasan_report+0x155/0x190
> |  vmalloc_oob+0x4c9/0x610
> |  [...]
> |
> | The buggy address belongs to a 1-page vmalloc region starting at 0xffffc900002fd000 allocated at vmalloc_oob+0x36/0x610
> | The buggy address belongs to the physical page:
> | page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x126364
> | flags: 0x200000000000000(node=0|zone=2)
> | raw: 0200000000000000 0000000000000000 dead000000000122 0000000000000000
> | raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
> | page dumped because: kasan: bad access detected
> |
> | [..]
> 
> Fixes: 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent possible deadlock")
> Suggested-by: Uladzislau Rezki <urezki@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: Yeoreum Yun <yeoreum.yun@arm.com>
> Cc: Yunseong Kim <ysk@kzalloc.com>
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>


Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0004f2ed-ac2b-4d93-8a4d-d01cbede94a2%40gmail.com.

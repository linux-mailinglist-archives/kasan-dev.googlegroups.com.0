Return-Path: <kasan-dev+bncBC5L5P75YUERBIUCRHUAKGQEVUIJOCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id BA9A0435E1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:27:14 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y3sf19233030edm.21
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:27:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560428834; cv=pass;
        d=google.com; s=arc-20160816;
        b=sH8I5mOciphxkJebblC2AP5ucVFsUoWrE8ADKTJTL1ImwAuWZGprRH/ObEaUk7JJPb
         1kgDfNHwEyB1Y0b+2L00EjoOnNmOeicT3lHMRSzzsA7gi5Lfk9tYLe7EKPUa+QekKx73
         hR7ab3yf6yGqsoS3qVQT9XEo4b9AgUDyKji0/OAknDwb01Tkaxz6A4WwdQAFBnEz3A/T
         I2NpeJsL+4Mzd8TObdWL2uCxEZ7SN6HfGEv4dXKzW7FqWdJ4QuSjdyRXDngdWJPWZmhZ
         VbdERbqF20uSRWZW2MJRYg8JZ2UGwZl6CTvw45lSU74M1csgoQftQnr3LFl5I+SFtrFy
         mXAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=vCp75hbu6DEgQYitjaf4joWxYtFzR5Bgr9zEZhdPb4Y=;
        b=ZB2aO4i+gDiXszdKCkxbzjJmnBPQtXvqeQV9CjCebhG+xVL1QeeGLpsAzClkcTZSqj
         aBOXNwKN98Pa3qjzXIgV28+qyg+bnfd0Lu2Dpm89fcjTNZZRBRFE+Ehe6LWrqh+KZWL9
         UM9khU5e5nhRxM0pyCOUTtJxRZ5Kp1u0QIcfgRGQV9PSDYrDRIT409bZAgZhr6UkDYa9
         LxogX28it5p7nN3hcezbxbYnXQ5XyK/C60Co02XPa75CZtYYPD8oXXOSVkujilpDDIQV
         9oTar8ux6LzfbQtxSuAsyoWaiLh27si/Fy8bHKf4ySsCEsQ79aKH4mYP+rpDz8Aqqpnr
         3FDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vCp75hbu6DEgQYitjaf4joWxYtFzR5Bgr9zEZhdPb4Y=;
        b=Kx0VwZ66EqMWLyorhv4tX6LYx7YPTPm1Ffn+aZJVlntVUI7NzSRlwAWJjttrDaLut6
         e3QSo6K3oBjxTdshQPIDkabtcHwmubaH/QsqjkZx3C5ivoJTdEXfoD5yI3e7qu7ozLSD
         4CC3geTlZy913j9ZsQnrO93wtw50Hw29EmG9mAeIIjBrzW60EIw0l0Oba2mnbPz53fsV
         EX3GVsu36C9sSfXxLyTeX6tZaetkC+eYwfKtaFeQzom/18D+8SJ9R+kGIIyedbJAJdi4
         WC3u7W59SOsb9tfU2pCdKxN3o4fNFzyE5+uoQgvdxVWW8crszRK9xPCpshs5WpRaDolO
         yY1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vCp75hbu6DEgQYitjaf4joWxYtFzR5Bgr9zEZhdPb4Y=;
        b=QkJXeflZfBLhdrQmt8VJ9VjJZ/+V0axzqd4iM5T6nq1KYckg8JTcrG6dFOxHQ1xcs/
         Dq0DLLVafLfqOG+PWVr8KDisbiI1MhVAHQGv1IP/wVNwU8YYJXTTkX7rsi63DIuDRAjv
         tKu3Y6x2r0+hp23z6UWwoJ8Kztf5llFe3sh50LL2+9Zwa6tXulCByre55V2hbJQTfPmF
         fdAv/SkSJzJ33p0/byZNBjH0u2Np4CppOqCCtBjLOI/4vZpJCF0h+XA2wkHI3+6YGLKf
         kmLUQ6LLUsqCbp6NKto9A5hlNGaHl66XKC6zSbhHab7RKqwKSd/FXuSPtrN0yIAQGn0q
         2txw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWd8Tot+75Ri5hE424wVmxTw0oorLOtwsHaNpbHmprS7QYQ/Mjq
	S5ntnsZdkYMI11EaJgI6o0w=
X-Google-Smtp-Source: APXvYqwyQ+RTeAYOQqPJVjRUF8ufyDeztsB92XTwttq65i7txeSwHVtf2XZ9wywa+F/IdAeEi+jYBA==
X-Received: by 2002:a17:906:85d4:: with SMTP id i20mr61885015ejy.256.1560428834506;
        Thu, 13 Jun 2019 05:27:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95a:: with SMTP id j26ls1310287ejd.5.gmail; Thu, 13
 Jun 2019 05:27:14 -0700 (PDT)
X-Received: by 2002:a17:906:30c4:: with SMTP id b4mr12984483ejb.276.1560428834132;
        Thu, 13 Jun 2019 05:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560428834; cv=none;
        d=google.com; s=arc-20160816;
        b=K6hHRTfc54r+zT9sB7oWDSVJJeyTr43rueunXH+caq8ZUcW6HHynkSWGo0DKYksj+c
         s3vDcX6qntUvVhMhBaCKcc7rjooCwijATc+SHMIDF8iCIVtCnXX1lBnR2ShEWZnTIopa
         fLsBJZIeR/GL2lld6BN+cKUUzD/11I1A82Lx8Ulp7w1sEyeXneWc/SQgcHzRjJEZERq0
         UP9BBfMvrzMp4nfJWqFa1IQTf+630jkb+KDHbQxXW1JA9o4ubqd+HUfJGbWSQkdu+Ccq
         8UMNX1RayUbK22/MH6JUarQ+8YKvFoetvH46sAcKqo2bvM9RAqGPWj9SYwtcuC15Wu+A
         k2Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=QyNWTj03afzaPDBn1iluZU89nDIXGRZJdacSCBorwio=;
        b=Wh56jtEUUVjURW9rM/6zU27NPxH+e0nAjqbrDC+JkCNU+vUz7sjq5BV4Kdj9rn/cy/
         urllSAOXJpDlwu0bTU7k0L/7pj3tHKedzs3UkvecKzgqe8QfnpKhLM7ccpQmiBTaL7bz
         AB4NnUzfjTripQy9R25lN/RTrEaxpVnicXvGQHUeMRZLKDhO8A2z4pSUEj3u3ItC/0cX
         UZtoA3WRwibRCerOi6pgaQ0MVBR4VPOerGJvtQg4XdQf8v0A+xV7AXvxPYa3FfOxPb8G
         o0+TAUBO+Fz7Lb94aDSXzPsm7fqEgAt2LtMbfqGC7l0Fv/5oHA5HweuDvOJCrfjHqCOo
         GwAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id h23si150666edb.2.2019.06.13.05.27.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:27:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbOol-000152-4t; Thu, 13 Jun 2019 15:26:59 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
Date: Thu, 13 Jun 2019 15:27:09 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 6/13/19 11:13 AM, Walter Wu wrote:
> This patch adds memory corruption identification at bug report for
> software tag-based mode, the report show whether it is "use-after-free"
> or "out-of-bound" error instead of "invalid-access" error.This will make
> it easier for programmers to see the memory corruption problem.
> 
> Now we extend the quarantine to support both generic and tag-based kasan.
> For tag-based kasan, the quarantine stores only freed object information
> to check if an object is freed recently. When tag-based kasan reports an
> error, we can check if the tagged addr is in the quarantine and make a
> good guess if the object is more like "use-after-free" or "out-of-bound".
> 


We already have all the information and don't need the quarantine to make such guess.
Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
otherwise it's use-after-free.

In pseudo-code it's something like this:

u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));

if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
	// out-of-bounds
else
	// use-after-free

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da7591c9-660d-d380-d59e-6d70b39eaa6b%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.

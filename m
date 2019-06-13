Return-Path: <kasan-dev+bncBC5L5P75YUERB5EMRHUAKGQEBQZEN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EDC5443609
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:49:56 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id l4sf661012lja.22
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:49:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430196; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwQcPc2Q6kwQRZ2wsbf4bSNsIzjzh7+LbIuuhzQFUbYM5/FDYQDDKk8hlLYXDLZ3RE
         aZKHSH3q6KUl9y6ipy+eKEU12h/Br0bqdn5ZurKXBOzg3aLEx4yMhnLPSywk8qVdbBCw
         HvJ4WnbEMhqjjNj/7/DU0p2FoUMsPY3LTNPBQTk0BDJrSRTs4W468zlFKCnBVc8E/Kc/
         QzLu2fkZ4vYqpRDfPH0HrYWHb+k7NlZmep4Egu0EbW/j8y9wvF+0ijpLqhiEo9Alvmy/
         FfspKAHH9ndC0hOQpopLmaPRF9I+b6oYXJQY+s1enFJSdVmOg2mjXu3zPbKm+RJMmf9D
         whqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BAKR0cxAnwuFAC1Xxg8PxiihgNbrQfBqq1IwE9buJy8=;
        b=R47FylmcmzmGK+tUoGXnADfPI6ix5oo0v2xvhnatAZ7gPIysycg3koA38CVJJqXp6H
         xrE0g6Ofo41PdQPgN2JjS9DM2JC/plLiBkv9sSAJaI9ZTglSgoeJ3D+FOM2iYXzhwXYk
         67X9JtY8/PzBteQLU0SMG8yyH49wPLN/u640qpXzr8ekwm+gKuE22OgezdfgvQlCrCFq
         DHCUN22NjgrwiVpcjHudoVnfMoQoI8cHvNAvliuITd1tEcf1QnwowywJcrEo0GyHs7B2
         Vv8w1BhVLj2L0H/7DroziWBWRnLdGrwCk7jB5a8Lc8/NOMB8d1vEvHHHdUknNqzQVAa3
         2M1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BAKR0cxAnwuFAC1Xxg8PxiihgNbrQfBqq1IwE9buJy8=;
        b=Ck7jIam7Rr/7N3poVW2S8UAKW8k5EaUOZCFeb8jvQ1vsVzN6+EPJ3ddzbnmuDkcfFL
         W6Y7uRHsxVk0u8a188BvrRCi7C3gxKBMfBqlSKrocqwHGPmztxIPQbh5Np/g6nYZxmyR
         PGhoMhWNzTOL47M0y5RGbq36SZblsc8HZAGpY0oIQGR4KdCxiiChC2NmT5qEgLOxBFwD
         VhaogPLHxunlHXGeANIv/xF4B7BVMqShNLeFBMAKtxG7nn8Fipg+wpsNlvBlLXLx10ko
         klcxuwJ3o7FxOtTzHourtw5fPsy10p5/V0gg41egZUOgHh5c386eYbG/LKgzGepjTuHI
         8xvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BAKR0cxAnwuFAC1Xxg8PxiihgNbrQfBqq1IwE9buJy8=;
        b=ttWY1hbWnkcQGNEp8Ux1lIDZih/dh0Zkp4jiovqvC3JoExAY3MHyp7QfEHGpBMO/ER
         MlVaY33KUYK2bzVgTio7mIJ6xlY6bQw1LRWrnwREdq0V3RK67w58hWCvZsd5XnGpwMww
         KV7uegy46k0VZh3XxLdfvriI+LGIjWKaUikw1Zrh+ya/VRf/VUt7UwASrQfJsfEJ+jor
         iqx7e4rxkbgyYLdsIL3FExJLa1wDql2yibjrg95KKaYVl1rXAWFESyEpvcVLj62jV6/C
         o+7FzUk4LgxMZ0o4r5pgv2Wfvcw1r1YxmeL93P5+v/SQj+W0p0hm2aT9ozVt42vaabhR
         lVcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU0aP22399mkvOLlB9FQLb62/jWp11KHKruWXXXndg5bV9IiCcD
	icLkJCKb/ZJ4NgJGQ3CLqUY=
X-Google-Smtp-Source: APXvYqyT+TYRXH0WY+oir/EIeHAYQUFb/Skoe1CoEsGXtsNXSB8NXyF2kIiuIR8vhlggmTdbbeJ67g==
X-Received: by 2002:a2e:9692:: with SMTP id q18mr49099119lji.89.1560430196462;
        Thu, 13 Jun 2019 05:49:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7f09:: with SMTP id a9ls624351ljd.16.gmail; Thu, 13 Jun
 2019 05:49:55 -0700 (PDT)
X-Received: by 2002:a2e:9951:: with SMTP id r17mr22828334ljj.125.1560430195970;
        Thu, 13 Jun 2019 05:49:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430195; cv=none;
        d=google.com; s=arc-20160816;
        b=BAQTSNd5sJDRXw/zrn4IVB+uozcsq8CCuI1ma6813t53fNS2mwGfg+JL9YOLMozh1s
         iML9YwbO0MoWg4WEKxG3/G54Y2Q8LxPFwWMg/GsQjj4hXaUTIIOU0qB5BpHZQGt/1k98
         zXIyiG3fKqSFghJha7qWzLlciVsUjGsTfZhdYNU6MvZ0WW4F9C5ituP627it5EoM+zBy
         +69ieSakEW0hrOW/6GY2enzTLY3nxxuBrQLAj4d+hd36TAOLzt5CP6Xqvrmofb77a87w
         wli762J+fPaq2GxNNffxIiXVA+6Zt+D8OKbI9/Zf8GJddSD06ek+vqYxhqhp7dD/jgpS
         GE+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=E0qsmcrJYos/k4iFhlJL0+yumW9401K1TzKguzdQ+Q8=;
        b=l9c6X9RHTZNv5bLMNCKHwjvck7OjC6GO1NgNweBZ3Qce4O/T8QqKInehW3OhSfiPqQ
         MTnD6hmPguFhqRgkFAj5y3fh5XdtSNOyhY8XL6BGIpeKKSCe2YRDPunVLPJZXggssLLz
         H+s64dsFSRteTTJRJhQ3U3DtEGnH/IHhhKLlVuuYqcMH5HaAaRKb06B16HIye4cmIK13
         zT57xe36JVWUOmxrol+H449qUfPMHpzEnNeT41XgVzmw/t8+0sXWsN17kwzCeon0HlA9
         vDS9+olm7FM/d+WuPJyEWYIPwaVffCJQ3qTxRdFzIBN1M7wBt612e7xWyP5Sx0SgQGSJ
         QqHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id z18si169718lfh.1.2019.06.13.05.49.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:49:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbPAv-0001HQ-RP; Thu, 13 Jun 2019 15:49:53 +0300
Subject: Re: [PATCH v4 1/3] lib/test_kasan: Add bitops tests
To: Marco Elver <elver@google.com>, peterz@infradead.org, dvyukov@google.com,
 glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
References: <20190613123028.179447-1-elver@google.com>
 <20190613123028.179447-2-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <6cc5e12d-1492-d9b7-3ea7-6381407439d7@virtuozzo.com>
Date: Thu, 13 Jun 2019 15:50:06 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190613123028.179447-2-elver@google.com>
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



On 6/13/19 3:30 PM, Marco Elver wrote:
> This adds bitops tests to the test_kasan module. In a follow-up patch,
> support for bitops instrumentation will be added.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Mark Rutland <mark.rutland@arm.com>
> ---

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>




> +static noinline void __init kasan_bitops(void)
> +{
> +	/*
> +	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> +	 * this way we do not actually corrupt other memory, in case
> +	 * instrumentation is not working as intended.

This sound like working instrumentation somehow save us from corrupting memory. In fact it doesn't,
it only reports corruption.

> +	 */
> +	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> +	if (!bits)
> +		return;
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6cc5e12d-1492-d9b7-3ea7-6381407439d7%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.

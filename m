Return-Path: <kasan-dev+bncBC5L5P75YUERBLWURDUAKGQEDGFSBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 75AEA4354E
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 12:49:18 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id b4sf6977823wrw.4
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 03:49:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560422958; cv=pass;
        d=google.com; s=arc-20160816;
        b=urX8AtSxMX4csX+dzmcPlW7kC5MQCBe82gwZYrhCne2MkBiIUUZA++6teI5cyxivfg
         /HThjeGhEsEeFuwt1oxA5s4OgQgV94shlkWslY4TA2FNVYl2EmHgmWyFL6Uwp4NdPZLM
         VCr8vIUHTTZAXSt3lZIZePcxILLaipDhGLMJLoWlTIA7uKMzPXB8P1TuqItmn29Z5f3S
         X+dDFbajly3RMoSyx/j/3MPs2+gmhJ8ixkVRnC04P3tCKG7o8QoRqHTrZxorTFUwT89r
         nR9IHRMOKNBbuJWx/nkEhZDp0EJT/q72JEwGlaGCmyXVKcOP/x0Lg03p2BceQm+sDBWd
         95kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Fa/IE/PLonx+UQa8DJ2r3bLDTNuJF8PtiLkAmXuun3o=;
        b=u20nfkBc1ZpkzaOUpaTFcQgD0ORZO5tPQzOmlIgId7TxVOkKU8MEkXVFj3qR+bo6P2
         tlWWBaIcVfCjYY+RS/+hj0qWVVMmNeTpyVO0xFY/6ZY1blkeCAfkGdQRKskkwb2cKivO
         gTh5hKolFcelRx49ZqqxAZDORJyEugC5/oZ+9SWO0WuwqC8DCTsOhdD6J8MfFaJ6/hYg
         hKfiGpdG13Jkfgy+/eq76kAJ1gUyLx56niwNoIMY3tkBAaoi3QKVbSQbiK86+Zxan40O
         eFo9NFH2VmIgi193oK51oC7jcB+CaN5l+2ro1tYXxvtp43WUj94RLrMSDuIwDkHH7kkR
         kLaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fa/IE/PLonx+UQa8DJ2r3bLDTNuJF8PtiLkAmXuun3o=;
        b=Yq1gfn3FNu7k7BDvG7VROGFOzeKg4DhTryTQtdX3ZxWXrQw1mlQnT16CtEgB/CaIW3
         2z0I10pyHTgUwFopJSd25tN0HIjVkz2PZMr12cI8HtokQDbi6xsJhBYXoEW4lonbRNC+
         m5SnlCXALfeW/0TMjHQ5Vxlkuh6PNuY8aDDi5+zsNYghzPpPSrisp5D5Z6mTm/fxM0oR
         EDyP1EJWsIg0UrRl4sy2aypbBAepnPeryzF+b+bQMZJXA8tznc0rYJ6lmIh4MOUKJXZR
         zHqkzSC9n9B9+2V7w5nvCxTmeDDjdXlGjt5bI6Enk+xI11LH2zfXC7kAfwLYwUd+tqup
         LbOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fa/IE/PLonx+UQa8DJ2r3bLDTNuJF8PtiLkAmXuun3o=;
        b=TgtmCfBLYe7Fk7vyI/fdrNPmwcvHaz53oKppoedbEJcNMVQjEVigOcediknTfXqiWB
         oF6Tl51gOsvZyRPjixhp/rpWiJOFv9nA6GvUFxZFdbq0xK1cmCPVo1zx50U7mI2z8FQd
         /q6MAFzlJ+agXRndBiFUK3f0R9hVY/hEFF+DlHSdbf1mlP210teOUAiTmeS4mMfoGiTt
         jqe2N9CVn43/Jz/wet94vRaMdqMcIPJsSSLkxPJOeosnKUyrcxWT2Ubh/HiZIetOehuL
         DKrZYSsT90W4/uNsoiXlrfKauwMYdvO4Srn5QokN4y2IY4znrQ+FhHaLBMREQZ9HXRAr
         73Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9zIFpoxUWoDJpOnB4eN2iD1l6MjGfUUChc4oodjxlf3fNBziK
	suD5dLM0lY/ZAvo1ij2gpFk=
X-Google-Smtp-Source: APXvYqyZ/cGWeESQjT79BNjlHJjO7nrnLvQRFYXm+VcQJYDfC5RxD5Qdyuvu6mk2xWjIyRcIWUk8lA==
X-Received: by 2002:a5d:53d2:: with SMTP id a18mr9524801wrw.98.1560422958089;
        Thu, 13 Jun 2019 03:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d11:: with SMTP id t17ls1614231wmt.0.gmail; Thu, 13 Jun
 2019 03:49:17 -0700 (PDT)
X-Received: by 2002:a1c:f712:: with SMTP id v18mr3503996wmh.0.1560422957647;
        Thu, 13 Jun 2019 03:49:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560422957; cv=none;
        d=google.com; s=arc-20160816;
        b=M5k7Z7Ors87ul1ji9lwJ2rXDMNyG6KgGwTks4Dvh9H2HDbSLGXpQsPGPUtetsG7gwM
         lJYIhJDWsH1L8vpS2ARyZ9bULglvaXdq+sKYUAX+/QTjWDKvQ0Ye0P6EL3X3wLednBxV
         E0reJutL3UVtJFCCN8dF5juKYBnoDb87pppJzfk9JSeBGzqCUnD4KrLwkrp0X2IsSuuT
         WtRc0YvXFU+iDlpetYXqZ/4ruymvKXX7phFITgK1JVsjQnjzK4zT63Kuj4YKtGt4uaQq
         cByTwVyTzFnZx4qEj8kQc9mB7lYi0nL4dUeORdlKHiRXgfWSaSbglRgXxA1sSAMMZj9B
         mCRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=a6Gh3I2YeGZuFCvmgk6STQ7mUGuO1wt1FSU+nPj3SAw=;
        b=jVYSDtuSoGY4IvMssVdIT8YtjDp4pgzSSjBPiOfpDDiUkURqbg5+sKBKX0PCuGhAAS
         EGLYjAW6eJt4vIItWf2dVsnatD4fB3+0mR/SmKscITyL4XJ9RhVkEiq6GwXpU9lFpKN5
         kjpToZ4YSEnAJP+LKLVupvnS6XHZ9sRwuQ6flRqZtHgHfJ0xsvoolW0PpKNUU6QJJ02A
         Sx0sWJxUAI0yYRrYHJPGJN2CDy0DIFUnlk/I85R3YCizRU+1wYOV4e5+YuG9t9b4FPp4
         xw1XNh82q+95ngHnfKfIvqbVmkXgwIO9blbC5a/l2N1cj8joxFh+PcvfjJrga9JwSJa0
         gt8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id h10si140108wrv.3.2019.06.13.03.49.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 03:49:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbNI7-0000bh-9J; Thu, 13 Jun 2019 13:49:11 +0300
Subject: Re: [PATCH v3 1/3] lib/test_kasan: Add bitops tests
To: Marco Elver <elver@google.com>, peterz@infradead.org, dvyukov@google.com,
 glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-2-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <5c35bc08-749f-dbc4-09d0-fcf14b1da1b3@virtuozzo.com>
Date: Thu, 13 Jun 2019 13:49:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190531150828.157832-2-elver@google.com>
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



On 5/31/19 6:08 PM, Marco Elver wrote:
> This adds bitops tests to the test_kasan module. In a follow-up patch,
> support for bitops instrumentation will be added.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Changes in v3:
> * Use kzalloc instead of kmalloc.
> * Use sizeof(*bits).
> 
> Changes in v2:
> * Use BITS_PER_LONG.
> * Use heap allocated memory for test, as newer compilers (correctly)
>   warn on OOB stack access.
> ---
>  lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 72 insertions(+), 3 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7de2702621dc..1ef9702327d2 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -11,16 +11,17 @@
>  
>  #define pr_fmt(fmt) "kasan test: %s " fmt, __func__
>  
> +#include <linux/bitops.h>
>  #include <linux/delay.h>
> +#include <linux/kasan.h>
>  #include <linux/kernel.h>
> -#include <linux/mman.h>
>  #include <linux/mm.h>
> +#include <linux/mman.h>
> +#include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> -#include <linux/module.h>
> -#include <linux/kasan.h>
>  
>  /*
>   * Note: test functions are marked noinline so that their names appear in
> @@ -623,6 +624,73 @@ static noinline void __init kasan_strings(void)
>  	strnlen(ptr, 1);
>  }
>  
> +static noinline void __init kasan_bitops(void)
> +{
> +	long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);

It would be safer to do kzalloc(sizeof(*bits) + 1, GFP_KERNEL) and change tests accordingly to: set_bit(BITS_PER_LONG + 1, bits) ...
kmalloc will internally round up allocation to 16-bytes, so we won't be actually corrupting someone elses memory.


> +	if (!bits)
> +		return;
> +
> +	pr_info("within-bounds in set_bit");
> +	set_bit(0, bits);
> +
> +	pr_info("within-bounds in set_bit");
> +	set_bit(BITS_PER_LONG - 1, bits);


I'd remove these two. There are plenty of within bounds set_bit() in the kernel so they are well tested already.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c35bc08-749f-dbc4-09d0-fcf14b1da1b3%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.

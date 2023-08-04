Return-Path: <kasan-dev+bncBD7I3CGX5IPRBEULWOTAMGQE4JEBWTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E46B476FD53
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 11:32:03 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fbe4ebfe73sf116105e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 02:32:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691141523; cv=pass;
        d=google.com; s=arc-20160816;
        b=hrLDtyHo9EqRdzqpPtbVsDIiqbxd1q+lEvseMxHHvFn3dxIw2axHlCvuxmEzuJpQDJ
         UTHEpc8iUVG6dvKN4Yc8SrWxw4ekuKjRXvCSoOfNIhxR1zJ4WDDoXn3hkkq5Gzp0TwAb
         5qT4Ny9QEaCW3DVMBK21zY6WYF1NKyXfrALEX/IMUbSZfaERcIz29GTxzwvUSSHkG3DQ
         boSoMpDjtZhtVvtlk0uNpX/ocrRZBhaTWoTpq3IeH0TTiClTRCwYVW9x2meD3DjPlOUk
         JPRgdkRfRHfmvPdVPNRC0dOxsd/YUc6+shAxcvDP7bhBuYepHMKvv3jL4juuYqNMXN4S
         pR9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=oF/VBpkLOTFe4LPmWsBbxFzQcPzZ72PHNd9Vz7vXvTk=;
        fh=Al7vh/+j54dCP9T4Q/KoT2/pH0X7zpBvlgRVzT1f1/0=;
        b=mKBF1pYcxi1ZOrgaXNgzOAKY+oVIIdNgy4YmxI9eNoB+szNM4QtEVQAFeAG/I8G958
         sly01lzi1ug1EqnrWJ/pVqmX1PhLeP2Ii7e8ZVNxHaSKy3H1Vix5s5lb7RTAQ8nfpw0e
         ueQM1j/oGVEDtpA7fNU2nph0T/eQuxUusHL9niYMm62jP0DAh0WppPyZoIn1MUKQ23YT
         YB1Hdi4gTwgFTeOYrkNa3MM6pabSZdQeknZ+7I2qu8JB/PiudDKCnkgpiHlFG9yV9BOO
         8/AMdrS0fR6AzySgenEDILDvT7biSbnteya2IfAImxBjyoBtUu8FHlZ7reNZ1T3f9anp
         ycTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=cCylAwlh;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691141523; x=1691746323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oF/VBpkLOTFe4LPmWsBbxFzQcPzZ72PHNd9Vz7vXvTk=;
        b=V2TJVumw86s+LighBOkKGTooSn4iqsYSQH/JJkCmGGwRwQ8w7zeuTvkVcj8UAqOws/
         JbupCpAQBCk4/Lob3N1Y3dxSVIfon6pLjhIygJzExYqOedF0Kw0fLEN2ZttKbjr2Z26h
         aNLkuISc4u0M54ccwsPo91Oim53wxBOdg8RKaYW6qHON1kNM7yXLyiK11SwJf3k6BViY
         7HzhmCTrx/LtUZELrk9f/V/T1NUPHEfMgGuthJLWkd8PCv2pl0L29mB/FTxvKIA+6Cqe
         eHhr/48V2NyLnGtCrr1RJ/nhlXiyNQuoQxJnbnkF7BPLkUvCw0TxyaA/i7O1qIH5ZMnR
         pUJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691141523; x=1691746323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oF/VBpkLOTFe4LPmWsBbxFzQcPzZ72PHNd9Vz7vXvTk=;
        b=GuoIdjhZcsOOVI7Azm4aw/2ljV1uJO55dqrgyAbmiRPDsPxjgIP4N7MwNSA5a+TDhi
         MO7+D4det7Spv+NK7e0c9qM7DmeG3QQqXWoj82vcs7C2yk3Oo7+oaQbMeEY7UuY4LQU5
         LefSfw1qI262QLgaAT50lWxNBrZU11x61+1tveBPErXJyo4b+t8BxgF4SZXVmSyLXiSr
         iEFNMLzhYmhq9YgqppCXzIC53xoXy7HYiviuATU2HNPg8fdF81vEzKOicA2+11JjRSOR
         /kU3Z57tRfxrUN/Eb8iqk5YYFuo61j8mTGJL4wj0LvWjm4v4XSu/cYNkFaVqS4eRBvSl
         EGdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx9TJUfISxytAD/OV2EQRKfdt0k3yDNfGItca3MHzjsG3R7ejYE
	9OF3GCq8jxsR6UQ6QGqUYhE=
X-Google-Smtp-Source: AGHT+IEme2zTItWr9VNTICGokFG0SyHQy8nQn38Q7vuVG0xVkJkdo2z3C0TLYJUzCS5TNZEoLacm+A==
X-Received: by 2002:a05:600c:4583:b0:3f1:6fe9:4a95 with SMTP id r3-20020a05600c458300b003f16fe94a95mr31878wmo.4.1691141522946;
        Fri, 04 Aug 2023 02:32:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3caa:b0:3fb:422d:4ff8 with SMTP id
 bg42-20020a05600c3caa00b003fb422d4ff8ls2003592wmb.1.-pod-prod-02-eu; Fri, 04
 Aug 2023 02:32:01 -0700 (PDT)
X-Received: by 2002:adf:ee11:0:b0:317:6513:da7c with SMTP id y17-20020adfee11000000b003176513da7cmr1079424wrn.18.1691141521392;
        Fri, 04 Aug 2023 02:32:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691141521; cv=none;
        d=google.com; s=arc-20160816;
        b=d4PZ5ExGHLVmsoX4OPMIjk4tylhqXbLEN3N0NWUSgpV+/5XbR0jnXCVdiARqF2AFsX
         mxcsNLbBwPPX9+Zv+F4CF8SfcXJHabtFEKOtgwbWaqWWIEZV4+25iSgy0DXnt8D+7NKK
         NT6fJM66HRGhg/fHxeP+3oBcGKsKuQCz0E+m0Si4SbIYMDGFNAoqArGVk2GushlOLnsR
         0KjDPzVHGuoZDZRwJNMT10ZKOQ1904U4AjwV3H++iWOtXcglf+2QvsRO/J68waAAkAYA
         hMyscR2XwiyQx/ObFNsOov+jcdZUAAAAlq2ExI5mcnWFSq8jWaWDG8h8KoEcTItE+BMW
         SAGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=YJcUmqfH4he3+bj4rk9cnVccev5fkfdS9FI/A70DRUM=;
        fh=Al7vh/+j54dCP9T4Q/KoT2/pH0X7zpBvlgRVzT1f1/0=;
        b=xxu/l9CH/y5aqWQX9ewW8Qp5zdoWwGdSGdHdN55IGDiEUNDC9VM+YvkaS52pWwZR/R
         2aji0AHY2h5BUscW4Ry7P1Gr5V19LV+ERyCs/aGxc44tsF4Fji6eL3AUsccji1hV8+3t
         PTgb+hU87zVSb7C15c83lneP6EUvYxqX4dvV4qjxvM6ilOoOAqBT6P/z5GI0rUB54gF7
         lJFHOhK0dQQYjBp5zyje8b0jHT/28BSWe9kXUdRnOkI0GcL3zeGMz4yZnydMTEuHQUpR
         LDLgLky9Ti5bApF0yKK7yuj81YaMfZ1Hq5pHfrDms6G9XyMAbFbkAg0w7jUsc4rokqSW
         7TkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=cCylAwlh;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id bt7-20020a056000080700b00317b3b0a31bsi150880wrb.5.2023.08.04.02.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:32:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-4fe0c566788so3210271e87.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 02:32:01 -0700 (PDT)
X-Received: by 2002:a05:6512:158f:b0:4f8:67f0:7253 with SMTP id bp15-20020a056512158f00b004f867f07253mr1071071lfb.49.1691141520453;
        Fri, 04 Aug 2023 02:32:00 -0700 (PDT)
Received: from [172.16.11.116] ([81.216.59.226])
        by smtp.gmail.com with ESMTPSA id t4-20020ac24c04000000b004fe09920fe5sm304024lfq.47.2023.08.04.02.31.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:31:59 -0700 (PDT)
Message-ID: <71ce8516-21cb-32c6-84d3-b3f9bb3d625b@rasmusvillemoes.dk>
Date: Fri, 4 Aug 2023 11:31:58 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH v1 4/4] lib/vsprintf: Split out sprintf() and friends
Content-Language: en-US, da
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
 <20230804082619.61833-5-andriy.shevchenko@linux.intel.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <20230804082619.61833-5-andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=cCylAwlh;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 04/08/2023 10.26, Andy Shevchenko wrote:
> kernel.h is being used as a dump for all kinds of stuff for a long time.
> sprintf() and friends are used in many drivers without need of the full
> kernel.h dependency train with it.
> 
> Here is the attempt on cleaning it up by splitting out sprintf() and
> friends.
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  include/linux/kernel.h  | 30 +-----------------------------
>  include/linux/sprintf.h | 24 ++++++++++++++++++++++++
>  lib/vsprintf.c          |  1 +
>  3 files changed, 26 insertions(+), 29 deletions(-)
>  create mode 100644 include/linux/sprintf.h
> 
> diff --git a/include/linux/kernel.h b/include/linux/kernel.h
> index b9e76f717a7e..cee8fe87e9f4 100644
> --- a/include/linux/kernel.h
> +++ b/include/linux/kernel.h
> @@ -29,6 +29,7 @@
>  #include <linux/panic.h>
>  #include <linux/printk.h>
>  #include <linux/build_bug.h>
> +#include <linux/sprintf.h>
>  #include <linux/static_call_types.h>
>  #include <linux/instruction_pointer.h>
>  #include <asm/byteorder.h>
> @@ -203,35 +204,6 @@ static inline void might_fault(void) { }
>  
>  void do_exit(long error_code) __noreturn;
>  
> -extern int num_to_str(char *buf, int size,
> -		      unsigned long long num, unsigned int width);
> -
> -/* lib/printf utilities */
> -
> -extern __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
> -extern __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
> -extern __printf(3, 4)
> -int snprintf(char *buf, size_t size, const char *fmt, ...);
> -extern __printf(3, 0)
> -int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
> -extern __printf(3, 4)
> -int scnprintf(char *buf, size_t size, const char *fmt, ...);
> -extern __printf(3, 0)
> -int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
> -extern __printf(2, 3) __malloc
> -char *kasprintf(gfp_t gfp, const char *fmt, ...);
> -extern __printf(2, 0) __malloc
> -char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
> -extern __printf(2, 0)
> -const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
> -
> -extern __scanf(2, 3)
> -int sscanf(const char *, const char *, ...);
> -extern __scanf(2, 0)
> -int vsscanf(const char *, const char *, va_list);
> -
> -extern int no_hash_pointers_enable(char *str);
> -
>  extern int get_option(char **str, int *pint);
>  extern char *get_options(const char *str, int nints, int *ints);
>  extern unsigned long long memparse(const char *ptr, char **retptr);
> diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
> new file mode 100644
> index 000000000000..00d1fdc70a3e
> --- /dev/null
> +++ b/include/linux/sprintf.h
> @@ -0,0 +1,24 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_KERNEL_SPRINTF_H_
> +#define _LINUX_KERNEL_SPRINTF_H_
> +
> +#include <linux/types.h>
> +

Shouldn't this at least also include compiler_attributes.h, to make it
self-contained?

As Marco said, please just declare no_hash_pointers in this file as
well. Perhaps with a comment about not accessing it unless one has good
reason, but I suppose that's true in general for all kernel global
variables, so maybe not worth it for this one.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71ce8516-21cb-32c6-84d3-b3f9bb3d625b%40rasmusvillemoes.dk.

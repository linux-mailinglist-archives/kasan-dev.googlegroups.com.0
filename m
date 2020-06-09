Return-Path: <kasan-dev+bncBCCZL45QXABBB3W5773AKGQELJPRS2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6671F47FA
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 22:19:59 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id n64sf3395415vsd.10
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 13:19:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591733998; cv=pass;
        d=google.com; s=arc-20160816;
        b=psPq5GC0ZmvS2a0N6evacIY3eDFY2Q2Gx9YcHVZD96FsAz2woaHpOEV/ZMI/i8nQ5h
         VY7wj4Tm7d/gsGbFki++2qLfdu6oKqLMlRp7OvUUSJBiJgtrIXzhehT1I7SwI0JKOHhb
         hFllzntlhm1hfksGtGbzWl5n8pwPueDA2nJ3c3YeeBer85gZdhNwm+m3U7NsCQLzLEHL
         AluPGWyTY+8lcdRhfX4HmkkDKnxM5Wb8w0yfWPQ31CsLDzRrra58jUwW5kWKjxEz7wO7
         UCMtbHb0kN7Kk0itl+eXXuMrHde3CkZ8dysmyZpoeXDnCvUCjMaYIhn2JStfOloeIqmP
         1r2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=y3eKMnVFr2nTACPyEpgcPo5HSlMPjTuFAoybG48hWdE=;
        b=DHg+0CJzFV3bqKgLFsriEmWDzGkavBg3ML6XeaOGtsbH40ShYIzD7ilsrOiHnSxD4u
         X07cwcVn8wrZVqVqyUfBxYSEpy0GQfrpjkLinw3z5LCcCY15yJ53z7NtfrsISmrfP4UB
         6q9eFYlK8ymRulEUAWg4mpXF/0x4uDT+K1hLIcx8P4u3tbA1bmCQDKvaIS1j+Tk8oCYO
         JZRhhctl6bFWhuXp22QjqkPD2CPVa4P1IJLU9gWK8pYssHG4Fpi45+0XI63TFROgeSeO
         vxCktrc4KbQW51XOd5m7Q/TJ0WOr7vi4Afcg+7rMbAi6kv/H+guPNeMUJy5xZJjOYHwS
         ad8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=JO2PjvGy;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y3eKMnVFr2nTACPyEpgcPo5HSlMPjTuFAoybG48hWdE=;
        b=m6K0rm7JFL1oC42lVisx8rsKvlMfzK78KRmPvfIEf2KrziYnm/OSR0ezVIaP05tWGP
         NLPEXNU5RqKOy0uU7mE080yyjaifVhJOjqxlj9PlSUm4O3TigSA4eG2HZLNBvzm9+TvQ
         gOZkKd8X+gnyGePiPO8Nzjz3JD8zCZWeTsynCDnSYD5lelNL+nE7vtUx032utuYVpSj0
         6pqFIf6tY/+I337n9c9RmvSweES3ZOq7mQX3SsWHCe5KzZ52wQC4zyOzCgUXSP77tT8N
         ZEC5HB6qTCBndMD043g8u5m3e7uf621LHRa77bSASt2K4umlmsjFDn1G45rdeBSUh/uI
         pnLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y3eKMnVFr2nTACPyEpgcPo5HSlMPjTuFAoybG48hWdE=;
        b=Qv5+3kMm9vJC+ztLvAYTkOakWtUNu8Nx1+YyqpspTwCUvoq8vQ+URdSGb3RzpmPHmS
         MjUXTkuDeJsj6AqTw0nH0uAggTMqTTGYozVseC0gYioxH4Ki+3Yazm4MgyAMJkr2NUX7
         TF1xBq026IlQyHEDgNirac96ZDnqeKiSi/amaCWyFs/Q1ERX2PzjE1CXhYsH2ZVo5Wdf
         0XIX7L8eAJXihK36s7CcyGLDzU7WEKxCAu4XHd5jAjA55BHVzOEYUwXlzQz4AdGpbJwP
         2ZdInCH9FqSN/iBiWhDxsCn4b9hZODYPYUat50B27j+YZmTbQizhF18RnEHIdMoGt2bP
         eSEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533P7URCc59W55ABT8Hgjyw6BwDXyDq5W1e4oZklyU/wzC0P8eUM
	ULb25KaPT3Gs+1uasqErLyc=
X-Google-Smtp-Source: ABdhPJz50wnb0SJ1kg0OAUjoL2mLmzimD9wmx74Ogy4V34+dtVgLOmlowXqkiDyJj5yyJeqpeQVMpQ==
X-Received: by 2002:a67:318d:: with SMTP id x135mr78988vsx.10.1591733998293;
        Tue, 09 Jun 2020 13:19:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:6e47:: with SMTP id j68ls2586139vsc.1.gmail; Tue, 09 Jun
 2020 13:19:57 -0700 (PDT)
X-Received: by 2002:a67:e041:: with SMTP id n1mr78638vsl.36.1591733997832;
        Tue, 09 Jun 2020 13:19:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591733997; cv=none;
        d=google.com; s=arc-20160816;
        b=l7SeXeu6+AhBufmgiWlkjeoEIBV/PA+O9kQgBIamgOzUaORxykCtAonQKXHFUiu6X+
         3eff2Zx7j9KCAji2Zt0Rrze3AHuKQr3zzZcwDfw4vDx4YQSuIYIFIoM1G6vuK2ybjjdm
         KFEDR2DEuTvS7ENU8dNzDZhSCTM9x/8ckuk4ceLA8qxZuwZ3vwJqXRSejS4qBPv//XJc
         neIemyEoZ18VhYygd3pJaqQJEdLUv6HzwNve7kcFSUlGHOuV6WG5iQqLKXxOm3N0mMDk
         ujwKOt/oKgWoxn6Sxf5x5L5zuIjjg0RVsk/fMKUKViuSRaRUMXWNPnHUXkiScS72j8Uf
         EHOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=cl0NnKl1Uu8CMgdsMDawpvRIt5rueRAfYk/i656FKFw=;
        b=gAFANrMsXVJaefiAhW0E3wp0J79TGymL8rj17MdjVDYtyvawFHkFSr1kpn1RG+rFsb
         MHaEWRkf3o72qlAl8N6UzWrKAz78vkRedUFis56UmSN2t9SNVI81G0OYMNzp+23iqxAB
         3j4+l0KgEW2rIEvxFyGv3TZBQk1vkUqXjx3QCu9IrfY/cAU+uF13cjB/K9bFYHwZEbZR
         e2MvPl5fmSmrEpB9Ed9yaOhqu91ZB1YDUgWTmXR3ZbWrcYDqwsSR1XTIen8NXCx5r0Pc
         WxdyYhcpwM8PV2XjmQg3JVvPtTjOgQh7/IlH+H3He1MNF7PypVsK1AhV/x4bIYwHnTas
         i86g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=JO2PjvGy;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id i11si262575vkk.2.2020.06.09.13.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 13:19:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id j189so19976331oih.10
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 13:19:57 -0700 (PDT)
X-Received: by 2002:aca:54d8:: with SMTP id i207mr10057oib.127.1591733997212;
        Tue, 09 Jun 2020 13:19:57 -0700 (PDT)
Received: from [192.168.1.112] (c-24-9-64-241.hsd1.co.comcast.net. [24.9.64.241])
        by smtp.gmail.com with ESMTPSA id f109sm2406819otf.39.2020.06.09.13.19.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 13:19:56 -0700 (PDT)
Subject: Re: [PATCH v8 1/5] Add KUnit Struct to Current Task
To: David Gow <davidgow@google.com>, trishalfonso@google.com,
 brendanhiggins@google.com, aryabinin@virtuozzo.com, dvyukov@google.com,
 mingo@redhat.com, peterz@infradead.org, juri.lelli@redhat.com,
 vincent.guittot@linaro.org, andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org,
 Shuah Khan <skhan@linuxfoundation.org>
References: <20200606040349.246780-1-davidgow@google.com>
 <20200606040349.246780-2-davidgow@google.com>
From: Shuah Khan <skhan@linuxfoundation.org>
Message-ID: <9a0cc68d-a7e5-a72c-7e47-3357a64f5aca@linuxfoundation.org>
Date: Tue, 9 Jun 2020 14:19:55 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200606040349.246780-2-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=JO2PjvGy;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
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

On 6/5/20 10:03 PM, David Gow wrote:
> From: Patricia Alfonso <trishalfonso@google.com>
> 
> In order to integrate debugging tools like KASAN into the KUnit
> framework, add KUnit struct to the current task to keep track of the
> current KUnit test.
> 
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>   include/linux/sched.h | 4 ++++
>   1 file changed, 4 insertions(+)
> 
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 4418f5cb8324..e50c568a8dc7 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1188,6 +1188,10 @@ struct task_struct {
>   	unsigned int			kasan_depth;
>   #endif
>   
> +#if IS_ENABLED(CONFIG_KUNIT)
> +	struct kunit			*kunit_test;
> +#endif
> +
>   #ifdef CONFIG_FUNCTION_GRAPH_TRACER
>   	/* Index of current stored address in ret_stack: */
>   	int				curr_ret_stack;
> 

Peter, Ingo, Juri,

Okay for this patch to go through Kselftest tree?


thanks,
-- Shuah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a0cc68d-a7e5-a72c-7e47-3357a64f5aca%40linuxfoundation.org.

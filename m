Return-Path: <kasan-dev+bncBDHMVDGV54LBBFP57GGAMGQEDIDPIUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E6C6645CBC3
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 19:04:06 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf1794742lfh.14
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 10:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637777046; cv=pass;
        d=google.com; s=arc-20160816;
        b=mVAtTktGYD+hXnnT3urHcWGSTxKtNpubRtQSGlZoWMNdzZ4Mj7g3J+0EaKsrwVzRUu
         mGLMLlXkRH3GZLGcgXAT3n40JF69pxdTP4OIzt1nqbieFzbIQ8C2jZZkGzd1gtajlrZE
         RLjYU3bNnL4xlDF8FfXXXcejVKoB+McVb86iGUQ6HA9Zt8qT6ujLZ1ApY452pOweggSE
         wAZqSSVxVzzUAAQG9JOtP2vYQGgofyFhN9qHFYIanDfmjWUY9lIVS8U3+SemxEeUaAb+
         BQLEkKRO1r4OSUPDXSClqjFkJtMrFHizq4VJcfUcYLlc9UG0TvN9qNbTMNj/NHeFMUFr
         j/Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+xxRAQmlLBMmfHY4EbFIWRxL0ATzuX+zIqQOjWmPgdI=;
        b=m0Y2J+t4yt6+rD32Yt/FajeLAtMH6H3/Dnwbt2KWuD6tEhU5Dm20GFGFk3rCIPEqBu
         L9c3phKJcaY7Li7oNhk1D0rkRkziTkxkHLGW6x3mCyD3eqW6SVVVlVN8pGPBSHrojHjx
         8ErR+kIJTzkKDzKzOXZj8RIyZYJo6c+bo9LsRiXe2LVtMV48m3dkO29oAx1Wh7B6tEKX
         q9f8fa3NJMmnADxdHzP/kO4Bf29d5TBE1T6A2pOEKJqqi/wgv6TMB9/EsX5G3iuOC8m9
         I3ret9hismnTTb9x/RO8qtVRFUJjjXqI5oiZyRSxSinyS9ZfnoY8hsKvZKhz1C7Wcuc5
         W/eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jirislaby@gmail.com designates 209.85.128.49 as permitted sender) smtp.mailfrom=jirislaby@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+xxRAQmlLBMmfHY4EbFIWRxL0ATzuX+zIqQOjWmPgdI=;
        b=klpm815NsTuZrjMc8pNgVBeL3V62jpJX9HmEEkR5oX3o8hb/iGncTuNhPuBRgMLjxv
         2Ny7HZW7DS9IC4l+W81SlKduAWmVtnkIVoKrZImIZo1pm8RL8icSmaA43eRdKP/p6IfE
         64CKsJXmozCbnGK7zE9P5WMi11S9sGgOHFfXn52gmiHdORihtazDEY1gzIfbFjOxBj7H
         XUAl2b6SHRNSgXVsanH4XRvKbiUgbsa8v21mKO0oLwD4tosk9N1ISX5rrT0CbTlk+tc3
         yfOy5ad5UgxA49n7fE7TngEkHl+BV95tY7PKxmEiZaDqQIKgLygCPMf2P84EazZRYOpK
         BV2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+xxRAQmlLBMmfHY4EbFIWRxL0ATzuX+zIqQOjWmPgdI=;
        b=AY6aM5AQNoeHByi7ifafxDzMwGkzlvu0u5SkXq+lRJiSPyiMCCL3oATcmXLVniFD33
         CxIy07395EpSJcM0aS7yNfvRnu3exySGYCW39N7D8cDpO+Dp19+F8N1vUropxg9b2aeF
         d6CuvyryhmoKfnC0gT+rE06+4qFdyLngAw/Y3ziKhp+xII+1oDayYW5GWkXe7AXKYiLL
         pQlOMxHbJHBxDcb4TmvUGHFP1ZibifjXds4YePk2STjbJ9qC3ZpL4hNohm6qpDUkZbOK
         OL/CdImY0zi/R9xEchLZtCTWqSEA88LDh3SCKs5WbZAif/Pr07W8kX3o3Kvy/PPSYhwC
         2LsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Rc1lslc9pVfQt2AZhFcaEKeYkHaZwVwh+J2en53y3Xtc2/wq1
	l3fwTtIvE657dVosw+I6nrU=
X-Google-Smtp-Source: ABdhPJxsHfqnv8pQ0M+6iZ478Cen9lYf9Ipzohr3imrdUsEV16EJt36+EXOexqUOKrl/kG3LfALrKg==
X-Received: by 2002:a2e:b6ce:: with SMTP id m14mr18351714ljo.128.1637777045999;
        Wed, 24 Nov 2021 10:04:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls470047lfr.0.gmail; Wed, 24
 Nov 2021 10:04:04 -0800 (PST)
X-Received: by 2002:ac2:55a6:: with SMTP id y6mr16799492lfg.406.1637777044877;
        Wed, 24 Nov 2021 10:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637777044; cv=none;
        d=google.com; s=arc-20160816;
        b=CwwGZI8S8BTznvO96IDZ0U+EpkRYrbpKfiLVHTUA8CfOEm+jN0LXndZ2PbsgI9yJ8Q
         Y3EAqFaJZDRcpnKk0n7/EZWmR++SUQjAnrC8aad4kiI2WPdoZbxIjAT2fDTFokGebw6V
         K4xxUqfYJsA+uVKgIyUozZbPrfWqssXGvV7rwxBkn7LSa8GVJijCwquAH2fsuJ1dFiOf
         UfAQ9MFf4Nb8jIXOyCxc7rwQlJxa2hbTqP5alXDMG/OSsQtnc4pYtCEjNi6zITGc26Uj
         UVP+S4Ipg7wgUAaJEakzjbRtS57ORoYaOCCV54okUnW6l1wSlK7ob8ICaRBFDF6cunPJ
         2hsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=12nEyDPdQY104trlboJVHkikF9Dqv57os2czAFrCZIo=;
        b=rCLD/ekVhIB3p+AANoFzNFjU6Jn6QW3EJL1wdN5KpAbFDB3VgJPwnOrgZJ1S8DGQO/
         o6XNC4QJgWpO5DQ7R/E0STs5N3e9hNO3/DnFdNBiWFwrWl69CinmlWtdJKGStleH2VsI
         QQj1atpoB4JHPnXn+yQ6Kw2H7JeSMyAkDo4KD8dr0bn0yaMCmnfoQQ3spSxEJtFMf9RK
         Qjd+Wxh/F/P2VWnIc7g1x9c1iSq6GsN0OqfaHjj/mw3Aep2BQslvSJi4xEgug6tIIONz
         beyPioqaXj8P7f4NFAJFgH1wGceJRorOkfzr732XFJCBkFzfamTZz/jWsTw3qO9aLt9s
         Yfwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jirislaby@gmail.com designates 209.85.128.49 as permitted sender) smtp.mailfrom=jirislaby@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-f49.google.com (mail-wm1-f49.google.com. [209.85.128.49])
        by gmr-mx.google.com with ESMTPS id j13si50788lfu.5.2021.11.24.10.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 10:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of jirislaby@gmail.com designates 209.85.128.49 as permitted sender) client-ip=209.85.128.49;
Received: by mail-wm1-f49.google.com with SMTP id i8-20020a7bc948000000b0030db7b70b6bso6225290wml.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Nov 2021 10:04:04 -0800 (PST)
X-Received: by 2002:a05:600c:202:: with SMTP id 2mr18093671wmi.134.1637777044293;
        Wed, 24 Nov 2021 10:04:04 -0800 (PST)
Received: from ?IPV6:2a0b:e7c0:0:107::49? ([2a0b:e7c0:0:107::49])
        by smtp.gmail.com with ESMTPSA id y7sm472211wrw.55.2021.11.24.10.04.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 10:04:03 -0800 (PST)
Message-ID: <d42117da-f6a4-053b-c498-5686cc06aca4@kernel.org>
Date: Wed, 24 Nov 2021 19:04:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.0
Subject: Re: [PATCH] kasan: distinguish kasan report from generic BUG()
Content-Language: en-US
To: Jiri Kosina <jikos@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm>
From: Jiri Slaby <jirislaby@kernel.org>
In-Reply-To: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: jirislaby@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jirislaby@gmail.com designates 209.85.128.49 as
 permitted sender) smtp.mailfrom=jirislaby@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 24. 11. 21, 18:41, Jiri Kosina wrote:
> From: Jiri Kosina <jkosina@suse.cz>
> 
> The typical KASAN report always begins with
> 
> 	BUG: KASAN: ....
> 
> in kernel log. That 'BUG:' prefix creates a false impression that it's an
> actual BUG() codepath being executed, and as such things like
> 'panic_on_oops' etc. would work on it as expected; but that's obviously
> not the case.
> 
> Switch the order of prefixes to make this distinction clear and avoid
> confusion.

Thinking about it more in the scope of panic_on_oops above: wouldn't it 
make more sense to emit "KASAN: WARNING:" instead? All that provided the 
fact the code explicitly does "if (panic_on_warn) { panic(); }"?

> Signed-off-by: Jiri Kosina <jkosina@suse.cz>
> ---
>   mm/kasan/report.c | 6 +++---
>   1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0bc10f452f7e..ead714c844e9 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -86,7 +86,7 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
>   
>   static void print_error_description(struct kasan_access_info *info)
>   {
> -	pr_err("BUG: KASAN: %s in %pS\n",
> +	pr_err("KASAN: BUG: %s in %pS\n",
>   		kasan_get_bug_type(info), (void *)info->ip);
>   	if (info->access_size)
>   		pr_err("%s of size %zu at addr %px by task %s/%d\n",
> @@ -366,7 +366,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>   #endif /* IS_ENABLED(CONFIG_KUNIT) */
>   
>   	start_report(&flags);
> -	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> +	pr_err("KASAN: BUG: double-free or invalid-free in %pS\n", (void *)ip);
>   	kasan_print_tags(tag, object);
>   	pr_err("\n");
>   	print_address_description(object, tag);
> @@ -386,7 +386,7 @@ void kasan_report_async(void)
>   #endif /* IS_ENABLED(CONFIG_KUNIT) */
>   
>   	start_report(&flags);
> -	pr_err("BUG: KASAN: invalid-access\n");
> +	pr_err("KASAN: BUG: invalid-access\n");
>   	pr_err("Asynchronous mode enabled: no access details available\n");
>   	pr_err("\n");
>   	dump_stack_lvl(KERN_ERR);
> 
> 


-- 
js
suse labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d42117da-f6a4-053b-c498-5686cc06aca4%40kernel.org.

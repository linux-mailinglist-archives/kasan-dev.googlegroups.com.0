Return-Path: <kasan-dev+bncBC7M5BFO7YCRBTXVZ6NAMGQEYAGBGGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93E07608DA0
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Oct 2022 16:14:39 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id v1-20020a05620a440100b006eee30cb799sf5683639qkp.23
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Oct 2022 07:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666448078; cv=pass;
        d=google.com; s=arc-20160816;
        b=BT8BcfAxiUVoAbFxo6ki3eeVyZWVYOoAKXATtRpTaSDgjXtjEJWzcwYLa7ZA3bOMWs
         CKKXT3aU6SOYEMTUdVAAtKLrWcPvYl6xk/hJyh0KoZEEYF7SW+ijPVMLhpd0fJcBRJ8T
         D/X6Fo4QyGGoOWbu+SumsSo2LBaZSxukFKMNh3Wrl3hSo0YsdZ6SFC0uzy0HMZ+8lEYv
         B7zYqG/djOSVhwzE1AFJ0lC3lmQUykTs53b4yM2ktZnJztaiFCRbOLR8FfjQBMYl+vCe
         pU2G/AENd5/IUZX5qjTasOXnXSuiC61WFVGuLv+Ws2crWd2V0yGWDPEBGfocbtelViWD
         1blA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=smhfgb7HB8hlFn34k4dT8q35lboF4fHdDv51VSBZlq0=;
        b=dwnvwv32haVc4xImTxql3la0PPqFZlMCtYTEwYnsfucLIYOuEAbRyl/6bys7NO8AHQ
         vuOP5oUltl7D6zt6yCnmEdqWk32x5znzOa/3ydyMAWCRQ6CuxUlVq1Fsl1XUfe6Pspdk
         PZzEP12TmL7O5EVJPKA3wmkXiF8sUYhMIXWMNWCyYhOPkMB24GbKIAAlCn+dG7tNWH94
         NUw6/THo7EgNtZSf1Gbio7oxSnqPcIXLzAt7XI+4M2ABNu2mRbmPFxW/Jr8eVoaLO1hH
         7qWuV6IgUkTsRutyZLgDVTbKPj4XTR5n6XNTsKzMIJuWaWy5F+sAJPcqxST1GvO1vzrZ
         Wn0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oJzxJp9s;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=smhfgb7HB8hlFn34k4dT8q35lboF4fHdDv51VSBZlq0=;
        b=md0or6/8omRuBmsWb09ZI6BmfZftWEHguJA31JXbiY8CGNAvpCjcz9SY241rnRdR3G
         fCBq2OKW5EOr+Dj+N2ukEKRzu7II+5nDyjmJDRtrdp2xqYzJD9BKryUmmRZEXDravOrK
         y37uMopq9u6IPJ9gRmRoAcWv2OBLAKeDzzalAsOulFY7TBwBJ3fF03NaconZ/8kIw8OM
         N670t0PGOJ2PkyOilbXO/DiaHs/ajeXKkYMncECWf+ISAnfA1zfbRaHWpRbYv6mHA3yv
         SDfnGdINPhlApYRV2yyj4TvKWVwpSxQpBDFoDVAH78XPzUu9zfDe556VnCXsrieZVTMT
         A83Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=smhfgb7HB8hlFn34k4dT8q35lboF4fHdDv51VSBZlq0=;
        b=NjYPv0v7Ijwxea/VPXnekY4q6X+/lB6S6dwdRulSrHhT9Ag44L/qkJhJGtjlUlDtba
         i9eNJyG1itO3gllhA+fSdP2F5d2K6twdzyR+PMpX/6MSiESQVE93pfgDm6QJMlZjBkyZ
         VfV9WOr/EI/lSs+l1OSnXpn84wAURIoHDAkIIposnSZvXr0Tede7p/f0g4b7Ro7Ka5KX
         jrEO0llCA+LQvd3ZcZa7H26UKDsczafgl6wnksKqIsx/B2Fm91/3sXxSuki8dptXWJVb
         KsDx0GZOqdnqo2x3BagiM3P9Och5nZ8FKtddQlJkaWH9IvI6QzhGQgYGzPqXrAQo4uNc
         WsTg==
X-Gm-Message-State: ACrzQf0vy+j/GZpqnjvRWzMAALfuzifoTS2nI0opsQl1/d2wtrMMjxeN
	sptBnLuqgcRb3gbff0W7+ws=
X-Google-Smtp-Source: AMsMyM5LDFjOFcfRgoHsaNq7AZAlgjTXmKpz5bnfYll785TLzXtaVJytwtvU3uqeEuPnBsnJyRKvqQ==
X-Received: by 2002:a37:bbc1:0:b0:6ee:a199:6f02 with SMTP id l184-20020a37bbc1000000b006eea1996f02mr17019280qkf.203.1666448078447;
        Sat, 22 Oct 2022 07:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8e44:0:b0:4b1:d9f8:1b13 with SMTP id w4-20020a0c8e44000000b004b1d9f81b13ls2549943qvb.9.-pod-prod-gmail;
 Sat, 22 Oct 2022 07:14:37 -0700 (PDT)
X-Received: by 2002:a05:6214:5296:b0:4bb:5ed2:d55d with SMTP id kj22-20020a056214529600b004bb5ed2d55dmr2479734qvb.62.1666448077750;
        Sat, 22 Oct 2022 07:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666448077; cv=none;
        d=google.com; s=arc-20160816;
        b=GiCvp0t+z+KqASfHmlj6hUFPDCJqv4Cv3vN0lT222EaeNqi1C8kHNT7U9x3G2aDMSG
         e0AEMOXujNxJXP9TeUv2MN6sXS3HphSaReR1p473Xi1pc5RqhWKVsGP/YRkhuwdUYPyJ
         tY7kqBYfRasORfHg329Vh77R5C6Fsf8+XaIjcEVirRPnG4UnRFtwX7ZRxzpXn+sx+TT8
         M9C6kmUHmk6akhzKybSo4KUGQWFDKz1gJ12aXdxWsr9UNd2sG5fZ+5K7PlFZBucvPgZr
         INezBH9eP7t3185hMY5sd5BQIii7dTM59nP6qk0FG2p41JD/Xvt+YSM4HwWyFisYn4oQ
         i02g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=V/pXnGpUP+A5cZvVHRAANC1TElzt+71d+M4GSsUDRR8=;
        b=k9wpdrMT1ufC0oPY1kDZgLk64AScqNd3a6AQG778q8qV+6Mbb6QK3WoNbfhDByAIxx
         ul0irT2CMz/lCsrBe+mO0nt/u/IOX6X31T7gDKm1Dx/rGaKRYTs8p1EYFkcudK2rHNZW
         4LqMWCRaAz2jcIMUs9GGmY1VVNQEd1dOY9TqqwOciRbZygb/mGqD1Q2CTyTBZPfHDPLq
         JFcw3O4WWSfpIpo8GHU+w6jrfGduQ7ufW1h+k8524O3fzgjb4RmfmeW+mJe4UKmFalge
         GdwF+6RBmlWaYrsJAbJkVVTd2axANzRISmuFaP+aAjDzNPoZUQbpjydoE++Q+p/OQFsO
         wkDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oJzxJp9s;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id l16-20020ac84cd0000000b0039f2f4aca88si57794qtv.0.2022.10.22.07.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Oct 2022 07:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id g10so6319937oif.10
        for <kasan-dev@googlegroups.com>; Sat, 22 Oct 2022 07:14:37 -0700 (PDT)
X-Received: by 2002:a54:4e99:0:b0:355:2239:2465 with SMTP id c25-20020a544e99000000b0035522392465mr12133089oiy.111.1666448077400;
        Sat, 22 Oct 2022 07:14:37 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id x5-20020a4a8d45000000b0047f94999318sm9731205ook.29.2022.10.22.07.14.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Oct 2022 07:14:36 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <e3c012aa-92ff-0b3f-6ea4-81b906c6f1c4@roeck-us.net>
Date: Sat, 22 Oct 2022 07:14:34 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: Warning backtraces when enabling KFENCE on arm
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20221015134144.GA1333703@roeck-us.net>
 <CANpmjNOVvriYmF1c7Rg31Yu2Tmu5JMJM-odhVnQF-xabMizjcQ@mail.gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
In-Reply-To: <CANpmjNOVvriYmF1c7Rg31Yu2Tmu5JMJM-odhVnQF-xabMizjcQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oJzxJp9s;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::236 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On 10/17/22 13:56, Marco Elver wrote:
> On Sat, 15 Oct 2022 at 06:41, Guenter Roeck <linux@roeck-us.net> wrote:
>>
>> Hi,
>>
>> I keep seeing the following backtrace when enabling KFENCE on arm
>> systems.
>>
>> [    9.736342] ------------[ cut here ]------------
>> [    9.736521] WARNING: CPU: 0 PID: 210 at kernel/smp.c:904 smp_call_function_many_cond+0x288/0x584
>> [    9.736638] Modules linked in:
>> [    9.736707] CPU: 0 PID: 210 Comm: S02sysctl Tainted: G        W        N 6.0.0-12189-g19d17ab7c68b #1
>> [    9.736806] Hardware name: Generic DT based system
>> [    9.736871]  unwind_backtrace from show_stack+0x10/0x14
>> [    9.736948]  show_stack from dump_stack_lvl+0x68/0x90
>> [    9.737021]  dump_stack_lvl from __warn+0xc8/0x1e8
>> [    9.737091]  __warn from warn_slowpath_fmt+0x5c/0xb8
>> [    9.737162]  warn_slowpath_fmt from smp_call_function_many_cond+0x288/0x584
>> [    9.737247]  smp_call_function_many_cond from smp_call_function+0x3c/0x50
>> [    9.737329]  smp_call_function from set_memory_valid+0x74/0x94
>> [    9.737407]  set_memory_valid from kfence_guarded_free+0x280/0x4bc
> 
> This comes from arm's implementation of set_memory_valid, which does a
> flush_tlb_kernel_range, which does on_each_cpu().
> 
> That in turn should probably not be called when interrupts are
> disabled. However, kfence alloc/free can occur in any context where
> kmalloc/kfree are valid.
> 
> [...]
>>
>> This is an example seen when running the 'virt' emulation in qemu
>> with a configuration based on multi_v7_defconfig and KFENCE enabled.
>>
>> The warning suggests that interrupts are disabled. Another KFENCE
>> related warning is
> [...]
>> [   11.381507]  smp_call_function from set_memory_valid+0x74/0x94
>> [   11.381657]  set_memory_valid from kfence_guarded_free+0x280/0x4bc
>> [   11.381800]  kfence_guarded_free from kmem_cache_free+0x338/0x390
> [...]
>> This is also seen with the same emulation. It suggests that the call is
>> made from outside task context, which presumably can also result in a
>> deadlock.
>>
>> I see those warnings only with arm emulations. The warnings are not new;
>> they are seen since kfence support for arm has been added.
>>
>> Is this a real problem ? Either case, is there a way to address the
>> warnings ?
> 
> The problem is real, but is a consequence of arm's implementation of
> set_memory_valid(), which arch/arm/include/asm/kfence.h relies on.
> Other architectures seem to implement set_memory_valid() without the
> IPI so the issue doesn't surface there.
> 
> I don't see a way to address it within kfence itself, since page
> protection is essential to how kfence operates. So my question would
> be if arm can improve set_memory_valid() somehow, but have absolutely
> no background how feasible this is:
> 
> Is there a way to implement a "lazy" version of set_memory_valid() for
> arm? I.e. let page fault handler recover on spurious faults, and
> possibly provide an optional explicitly lazy set_memory_valid, where a
> missed fault is acceptable. We need 2 things:
> 
> 1. On allocations, we need to eagerly mark a page accessible (however,
> a lazy implementation that recovers from spurious faults would work;
> afaik x86 does something like this).
> 
> 2. On frees, we can lazily mark a page inaccessible, with the only
> downside being that there's a time window where a use-after-free on
> another CPU might not be detected (assuming local CPU TLB flushes can
> always be done eagerly).
> 
> Thoughts?


Hmm, that doesn't look like an easy fix. I'll disable KFENCE in my arm
boot tests for the time being. That is less risky than missing other
warnings.

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e3c012aa-92ff-0b3f-6ea4-81b906c6f1c4%40roeck-us.net.

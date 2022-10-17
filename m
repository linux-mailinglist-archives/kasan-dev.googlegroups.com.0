Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHUDW6NAMGQE3I4URMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BABBE601ACD
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 22:57:03 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id m9-20020a056e021c2900b002fadb905ddcsf10256894ilh.18
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 13:57:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666040222; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fn3xeUnP+FhIeCGtpgvfyqnYURWGzgkMhImPKnmUOQ4brIWvu1CIC51NTt5IDAvelO
         luAtCDwVcvCsekkBbgkmMEpytoF4MUxR04myXOVop8zaeV8Rc2sV8nH61uoZGTtj45ol
         ZKXeIUd/qv/PtxVUKD1lnfgk4HO7qGsZ+Tc2XpesKjbvVWRoZT4YkVCM9G6Hkit2YZts
         DnEFW1yP2q1OlkZ5aMtBZNdnuzYXTKXG7QFRWgDWVBeFMMnKlCY9IMFwwUK3iFrQUcus
         qS0459fk2E8deZxqUEB885IsQpJxt/iYkyKobAS4dWFVaA6c8NPi/+0tu3goFY7W+mBG
         K7PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+qsm2vmv6PqXzHHq4ExIjX4pV/fhIgNpqPOtXhw9tf8=;
        b=P+6GC6GXMdPgyNya1ry9ptEjF5ojj3gPnB+3ztng9h/bVDKbDRW6UgXCvk2coMSxYm
         aRCDubPC47uVMqow6xvhWCt2yHd360WBHkYVDINrJsLbH+5IsWSpI0dvqlGN43moY9o6
         nHBEPGYOVD4EJRv2gu0TTRhw/L38N2TDUQbZ/d8zgLKY7QcCkmegVWjsEr1Nqch5tqE1
         1lIaqhzdGZqdj74Q7xWLgk694nbJC2jsrK8kvuDQy5YWLlDJAMobp7Tv8iyeE/L9cKpQ
         a4UtafKfXG6m8oqRYzt0ihSHqf/2SbpvPNzNGWvlQ3ZqXuKRgBkNCVEkiPHG4czb9F1d
         MtYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rebvhRch;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+qsm2vmv6PqXzHHq4ExIjX4pV/fhIgNpqPOtXhw9tf8=;
        b=cLniNfXpuWN0tt8CRFj+nIPNfGKnTx398GQvP4candnjBzzbqW+zp/YhfOcz6qHLGe
         BrDm6tkchxZrUpTBPiMyPF+hnnnx7w8b1yEZsezE4tyB7OP/HamjJQBF6zwX1QfCmWWM
         2td8ACkA9KLqGk/c7ku94fxNZjCibpifd6uGimeSliISWTjJrgd0g/LoQiTD354PjyGT
         IPIr4aLM0NTHz9RS/OY/K8Krmd/sUpNZr7afTTsE3WpTU9UHHc0ElFdUAMhAEj9Sti4+
         0imTe7LGhApxRrUHI2iMjI0QA+lr40/LYdf1oSA92SkETA9xu0u6GU34g9HnIvJNiQiD
         8jIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+qsm2vmv6PqXzHHq4ExIjX4pV/fhIgNpqPOtXhw9tf8=;
        b=6SPpmTTtmjuB/CZq77HX+uvTyfK5oS0eQiJ5n7AtTlOU6h+7iekH2j4q5lRfCrnBkt
         bXEWlRoHFSQ4wYDp5wT3m4iY52ctwcM8S/YsxWgJSYwnKcY+Vj56KuI/AlttMev3934T
         7Wd5GFI0RIQZDmrLEyZ9dxqGPI3KTIO+Dvoy64AyPgjehZ9loCD4rqO0QX4DzNDtjxqJ
         N/rcCcgWkpfbGzpIzAFd89XHOABsKyEn7LEeD3n3W1wkzkciqAmvqpNF1YbcqOp/n6wC
         ChZDqgtgc0tdmIX5bmMkePtRTl4W7xpEYqjxjOM+T+2lKCQmPmlEUFjUmnpNYUlpRrJT
         w3uw==
X-Gm-Message-State: ACrzQf2fUAVdUeSFYyA3u+UaUsshLT5f3OKpUdvjaVyG/pJgrnA3TBZ+
	SN44sdu3MAsqGjmohaq8bVM=
X-Google-Smtp-Source: AMsMyM4mK6ryIKeHvTh4ZS/cQDSxStZUD0s768dD6Mq2zU6+2ZFeT0h6Wjlx4KFy7ubumWH7fuecgw==
X-Received: by 2002:a05:6638:1613:b0:364:d83:b3de with SMTP id x19-20020a056638161300b003640d83b3demr6575721jas.299.1666040222424;
        Mon, 17 Oct 2022 13:57:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9427:0:b0:35a:2b9e:e336 with SMTP id a36-20020a029427000000b0035a2b9ee336ls3016450jai.4.-pod-prod-gmail;
 Mon, 17 Oct 2022 13:57:02 -0700 (PDT)
X-Received: by 2002:a05:6638:380f:b0:363:cb7f:4fb8 with SMTP id i15-20020a056638380f00b00363cb7f4fb8mr6442564jav.227.1666040221941;
        Mon, 17 Oct 2022 13:57:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666040221; cv=none;
        d=google.com; s=arc-20160816;
        b=IdhcZ2XwWWaBPMhYK9XJt/aej5LjD4dGjVEesOHhud2et6zF05WKiVnF7ZYuSsE/NP
         kOt3bIi+hEkC3CckDq4dBZ710npwsq0CmtG/uALm7dCSOgEJ4+5i2WxISatoAhKuiruw
         hUx4VsVqAl6alC2qXfxfQ2r0jmC/zK7x/lbID3avIOQHQ5ZiufDO8GVQQ1lNj4roMGsd
         BNZO7E6nkH0NJI0PvUraqkM4j4dHfnFo50HDOreKw992/gZ9Ee8dDB7ZLdEE8mK6aYA/
         +IukdVO9GIQURYVp0jv+j1MhLaeUG+8JYypS6DBzdKfk3GunOsDGcXnFHVL4LqKlk3+n
         pwiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hpkrNRfhOGOx24ap7YjRCixSfP97FOLJcWttTyPR4uA=;
        b=hWNT1MTR4MqD5uZfPcZoYsxPfNwv+GvuA5aqaKy7ECOs8L788JHpPKUoRs6j8QFMH/
         wQM8zbHgMozdyKglzJkAKUeZHzVZpwqtawIlA0RZoLbZ0TbKLUMtKvyGWZq7RzVkGSri
         Ndy1n/Ka2BShF3GV1RXsmpPXOwt5fmXoQ1olsP3dsOfl6oNHZipOyrveISwW3Da4c681
         PjqZAcQrhMd/VSk8PHtxceWsEcoF1aGyZyUO/cHMLLxkkn7zpT/NuSwukAYpHK5x1lYL
         Udw+0VTu0k6ZGgliQUSFi6Vdk8VfucAHzcKujbCCLg05H2MJC0q3LH3H+wMkTshja74p
         wxzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rebvhRch;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id k4-20020a02a704000000b00363dfd95c79si545393jam.1.2022.10.17.13.57.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Oct 2022 13:57:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id e62so14721171yba.6
        for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 13:57:01 -0700 (PDT)
X-Received: by 2002:a25:c012:0:b0:6c4:1762:db40 with SMTP id
 c18-20020a25c012000000b006c41762db40mr2881017ybf.584.1666040221335; Mon, 17
 Oct 2022 13:57:01 -0700 (PDT)
MIME-Version: 1.0
References: <20221015134144.GA1333703@roeck-us.net>
In-Reply-To: <20221015134144.GA1333703@roeck-us.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Oct 2022 13:56:25 -0700
Message-ID: <CANpmjNOVvriYmF1c7Rg31Yu2Tmu5JMJM-odhVnQF-xabMizjcQ@mail.gmail.com>
Subject: Re: Warning backtraces when enabling KFENCE on arm
To: Guenter Roeck <linux@roeck-us.net>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rebvhRch;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, 15 Oct 2022 at 06:41, Guenter Roeck <linux@roeck-us.net> wrote:
>
> Hi,
>
> I keep seeing the following backtrace when enabling KFENCE on arm
> systems.
>
> [    9.736342] ------------[ cut here ]------------
> [    9.736521] WARNING: CPU: 0 PID: 210 at kernel/smp.c:904 smp_call_function_many_cond+0x288/0x584
> [    9.736638] Modules linked in:
> [    9.736707] CPU: 0 PID: 210 Comm: S02sysctl Tainted: G        W        N 6.0.0-12189-g19d17ab7c68b #1
> [    9.736806] Hardware name: Generic DT based system
> [    9.736871]  unwind_backtrace from show_stack+0x10/0x14
> [    9.736948]  show_stack from dump_stack_lvl+0x68/0x90
> [    9.737021]  dump_stack_lvl from __warn+0xc8/0x1e8
> [    9.737091]  __warn from warn_slowpath_fmt+0x5c/0xb8
> [    9.737162]  warn_slowpath_fmt from smp_call_function_many_cond+0x288/0x584
> [    9.737247]  smp_call_function_many_cond from smp_call_function+0x3c/0x50
> [    9.737329]  smp_call_function from set_memory_valid+0x74/0x94
> [    9.737407]  set_memory_valid from kfence_guarded_free+0x280/0x4bc

This comes from arm's implementation of set_memory_valid, which does a
flush_tlb_kernel_range, which does on_each_cpu().

That in turn should probably not be called when interrupts are
disabled. However, kfence alloc/free can occur in any context where
kmalloc/kfree are valid.

[...]
>
> This is an example seen when running the 'virt' emulation in qemu
> with a configuration based on multi_v7_defconfig and KFENCE enabled.
>
> The warning suggests that interrupts are disabled. Another KFENCE
> related warning is
[...]
> [   11.381507]  smp_call_function from set_memory_valid+0x74/0x94
> [   11.381657]  set_memory_valid from kfence_guarded_free+0x280/0x4bc
> [   11.381800]  kfence_guarded_free from kmem_cache_free+0x338/0x390
[...]
> This is also seen with the same emulation. It suggests that the call is
> made from outside task context, which presumably can also result in a
> deadlock.
>
> I see those warnings only with arm emulations. The warnings are not new;
> they are seen since kfence support for arm has been added.
>
> Is this a real problem ? Either case, is there a way to address the
> warnings ?

The problem is real, but is a consequence of arm's implementation of
set_memory_valid(), which arch/arm/include/asm/kfence.h relies on.
Other architectures seem to implement set_memory_valid() without the
IPI so the issue doesn't surface there.

I don't see a way to address it within kfence itself, since page
protection is essential to how kfence operates. So my question would
be if arm can improve set_memory_valid() somehow, but have absolutely
no background how feasible this is:

Is there a way to implement a "lazy" version of set_memory_valid() for
arm? I.e. let page fault handler recover on spurious faults, and
possibly provide an optional explicitly lazy set_memory_valid, where a
missed fault is acceptable. We need 2 things:

1. On allocations, we need to eagerly mark a page accessible (however,
a lazy implementation that recovers from spurious faults would work;
afaik x86 does something like this).

2. On frees, we can lazily mark a page inaccessible, with the only
downside being that there's a time window where a use-after-free on
another CPU might not be detected (assuming local CPU TLB flushes can
always be done eagerly).

Thoughts?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOVvriYmF1c7Rg31Yu2Tmu5JMJM-odhVnQF-xabMizjcQ%40mail.gmail.com.

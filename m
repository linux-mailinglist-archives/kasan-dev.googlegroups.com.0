Return-Path: <kasan-dev+bncBCCZL45QXABBBFEM36EQMGQEEIVLRVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D0C402F60
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 22:05:42 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id h10-20020a17090a470a00b00196ead30459sf175751pjg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 13:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631045141; cv=pass;
        d=google.com; s=arc-20160816;
        b=GtbFYmH/obFaR0HT4Dht0KX4equI0lTGMXA80rE9bliYAaiDjC2e+PoqKD5ON1K9Tw
         ZjnKR876Zckbt5fZ2RupVqNCQ8TCy5fEqlnHebUM573MQ8OqBjUzm5JU0Ldq/Tl7B4Nv
         AVoqikNwSK0tkratdoYZtSOereaF+QAxZRyMiFfk+G80ztcKTiyWOmGo4dgaCMpKK7g9
         joPKGH+6XjX/qCnYJTev5q/if9y29blVX6Z6IF+2RtxEfr6JiKRMItR31DQRc7k3ecdZ
         3mkolGN4Tm+UtDS3+vpLFFmhJFgLMs/9826YJQR2v0jfIQBZ3fuAOsI2NRtxL0W6ExWt
         7+3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jdV8agkzfWq/qdPvrNt0kSJSbgqJa4vSIoKikkW0/GY=;
        b=ibI8Y5MRo8kZkwbDaxiNzFUVtHkDehOTjDTUjI9lCmT2m+dBmhlAS8USCaffwQJpb4
         CjBwBJmCxjAaGrBFoGtuMbolxC8bPUunePs4hpyyn0rrCGOULbpufK7bJ6+SEufRJ5AB
         QIWFto0J8dBb1n0b9KIKkeIh2EEoVPvQMIMwYKcZ1LBFVCbHlMxhbM/my85m08JbBwtu
         NINkkWvBBGrfOsyT/c2I5tsznBwLN5XYfWQ0KKTBaZe6IfTRzMVAZmIHonIM0tJApSr8
         COcJ3T7vr6vWSr2hRZrSQ4bViVG2Jo3NnGT695iOfPjf0lvb3MzXY12Xr5f74hThqgts
         QmAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=V3OZERQ7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jdV8agkzfWq/qdPvrNt0kSJSbgqJa4vSIoKikkW0/GY=;
        b=WyyT5Ss1G1BcT6b109fsVPyvR/v2zx9+ro9gSVhVruGLhWldlAlc2BBghw+vuFCnz2
         I0snplio9BN8bc9s8glZX32XZzRdefyq4XTitEsVhwLANbikwJ1AEvLKupU8+HHOBlbs
         x/n0IETPvgADkjlm8XhDufkUE31jMSHmvCSr8t3q9pN0AGyjeOEcg2twOpcDNbmggdMB
         5HbivOjQgq/ErNXDsO3jTXcknLaSzIFjFt7J4tcHsHm1WEBPWBaKEaZA6cMoY94myV9L
         hVcdaFmxGyvneZ9U5QlSTYKy+viztiJoaoihIdRafP2G7H63vboKwAGgoDnfqXL1/zOJ
         uPkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jdV8agkzfWq/qdPvrNt0kSJSbgqJa4vSIoKikkW0/GY=;
        b=lQUvOcE96mgnQjiDp869H4zfgfuOXP+n7TSa3X1DNJtNWL8+3l5bMET7A+DkZeo9jw
         nVswnFXkTYFxceVG5MBfPJRDkp5xhot/F3dRvMxthx/MJFDS0xxQ9R0taB4j7lQpSxFj
         O86JMb5lkOLWCo+y64anI9lttLh5bCUt1OH5xkGxvsCuvACAzdMVwVDxZU+MqFDOEWKR
         N6rVzPC7dZXXOUszn/BJdEH+INiuDYUg5l17lGyyGIimNZZdp4EB/Nvio9sZJeN43+Od
         a8SeLgTePacdYMzNtDdTAh0JLyh7xoiK7TO0V5nSqBnVVfH3dQGm2hYMgM0AOwbocUEG
         Ep3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532X36PYuXvO5gv+kbX5o8Lp9h1OIxZdAGFpbjul8ocMmUv9rB22
	21CKtvIucNac1yzwNGgd8q4=
X-Google-Smtp-Source: ABdhPJxSYCiAexmodg0ysspj98OeDKsET3lI5/5FXLlNenCtukQFio9tbja4EdLUYkkzr20ofaWx+Q==
X-Received: by 2002:a62:4ece:0:b0:3ef:88d5:ba51 with SMTP id c197-20020a624ece000000b003ef88d5ba51mr146280pfb.3.1631045140998;
        Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:19ca:: with SMTP id nm10ls54030pjb.0.canary-gmail;
 Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
X-Received: by 2002:a17:90a:bb13:: with SMTP id u19mr183632pjr.42.1631045140478;
        Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631045140; cv=none;
        d=google.com; s=arc-20160816;
        b=rPqZZUMKt3bEWsFHCmum9ypHLAjSiGeJoGLoLRu1YHiUxH4Ju5jH9+MyU9tMMli9rQ
         FMp0Ovo2w7RC4JUHPpfZhKdbsNfj2VdWDcrfDdLvL7uDPEz/FqyGMeBGgya/bCtGNved
         M9VoBLr7VFs7VxiIEMLEgnGjMEhje0Ey/WMB1Gbyj1/p9GmRXBvs0+PZ4z4eGmMndjMN
         QkEdBTSADMZ3BB9J5+MutOItT/jCVLnF7lGxS08nsM3OHu7/2ptU5sg07Q9ezU4vZP7m
         zCRBuTUiyS8YyjADwaYVka4p7WLzpyaRwXtZXTo2WYs3FCOkF4jhfeuRIsBEvF8RyO1+
         VE4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=qBeV/3OVpeBGqoC50W6WyV/Bm/mvFYoJ4MmFvZCO8nQ=;
        b=llG0Mok3SJC3W0D24nRZLI76VABpNym9XjLfXsCTkgI7vguTB1oUN5rIum5dyTsQc4
         lsSQVMJ+bM2BZc5r/KDUXh/61EhZrVm3HhX2MXpieuifdrx8YK35ET2cpLEtpmlUQReG
         iDRJk70SxLmIEz9MqsyP0z7ZBvrFi3slVIXW6pSXx2gKfo2ew/rF39GtDOQqnjMr5umM
         rx0TLcN+Ref0wwNYRp54wkMi/WLpMinqH7mRIEanW4P28BSBaDTKS47B1Th9jD3Uzg16
         WrGoBQ4KKhuf0bAth1xHwaptSn+cRDHFcuf2tW/aMXAGZIJhkZiNmsCO9o5WBljHPI6M
         7L6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=V3OZERQ7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id 136si2403pfz.2.2021.09.07.13.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id a20so6468ilq.7
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
X-Received: by 2002:a05:6e02:f03:: with SMTP id x3mr13623361ilj.315.1631045140169;
        Tue, 07 Sep 2021 13:05:40 -0700 (PDT)
Received: from [192.168.1.112] (c-24-9-64-241.hsd1.co.comcast.net. [24.9.64.241])
        by smtp.gmail.com with ESMTPSA id g14sm63699ila.28.2021.09.07.13.05.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 13:05:38 -0700 (PDT)
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 Vinayak Menon <vinmenon@codeaurora.org>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>,
 Shuah Khan <skhan@linuxfoundation.org>
References: <20210907141307.1437816-1-elver@google.com>
From: Shuah Khan <skhan@linuxfoundation.org>
Message-ID: <69f98dbd-e754-c34a-72cf-a62c858bcd2f@linuxfoundation.org>
Date: Tue, 7 Sep 2021 14:05:37 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=V3OZERQ7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On 9/7/21 8:13 AM, Marco Elver wrote:
> Shuah Khan reported [1]:
> 
>   | When CONFIG_PROVE_RAW_LOCK_NESTING=y and CONFIG_KASAN are enabled,
>   | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
>   | it tries to allocate memory attempting to acquire spinlock in page
>   | allocation code while holding workqueue pool raw_spinlock.
>   |
>   | There are several instances of this problem when block layer tries
>   | to __queue_work(). Call trace from one of these instances is below:
>   |
>   |     kblockd_mod_delayed_work_on()
>   |       mod_delayed_work_on()
>   |         __queue_delayed_work()
>   |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
>   |             insert_work()
>   |               kasan_record_aux_stack()
>   |                 kasan_save_stack()
>   |                   stack_depot_save()
>   |                     alloc_pages()
>   |                       __alloc_pages()
>   |                         get_page_from_freelist()
>   |                           rm_queue()
>   |                             rm_queue_pcplist()
>   |                               local_lock_irqsave(&pagesets.lock, flags);
>   |                               [ BUG: Invalid wait context triggered ]
> 
> [1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
> 
> PROVE_RAW_LOCK_NESTING is pointing out that (on RT kernels) the locking
> rules are being violated. More generally, memory is being allocated from
> a non-preemptive context (raw_spin_lock'd c-s) where it is not allowed.
> 
> To properly fix this, we must prevent stackdepot from replenishing its
> "stack slab" pool if memory allocations cannot be done in the current
> context: it's a bug to use either GFP_ATOMIC nor GFP_NOWAIT in certain
> non-preemptive contexts, including raw_spin_locks (see gfp.h and
> ab00db216c9c7).
> 
> The only downside is that saving a stack trace may fail if: stackdepot
> runs out of space AND the same stack trace has not been recorded before.
> I expect this to be unlikely, and a simple experiment (boot the kernel)
> didn't result in any failure to record stack trace from insert_work().
> 
> The series includes a few minor fixes to stackdepot that I noticed in
> preparing the series. It then introduces __stack_depot_save(), which
> exposes the option to force stackdepot to not allocate any memory.
> Finally, KASAN is changed to use the new stackdepot interface and
> provide kasan_record_aux_stack_noalloc(), which is then used by
> workqueue code.
> 
> Marco Elver (6):
>    lib/stackdepot: include gfp.h
>    lib/stackdepot: remove unused function argument
>    lib/stackdepot: introduce __stack_depot_save()
>    kasan: common: provide can_alloc in kasan_save_stack()
>    kasan: generic: introduce kasan_record_aux_stack_noalloc()
>    workqueue, kasan: avoid alloc_pages() when recording stack
> 
>   include/linux/kasan.h      |  2 ++
>   include/linux/stackdepot.h |  6 +++++
>   kernel/workqueue.c         |  2 +-
>   lib/stackdepot.c           | 51 ++++++++++++++++++++++++++++++--------
>   mm/kasan/common.c          |  6 ++---
>   mm/kasan/generic.c         | 14 +++++++++--
>   mm/kasan/kasan.h           |  2 +-
>   7 files changed, 65 insertions(+), 18 deletions(-)
> 

Thank you. Tested all the 6 patches in this series on Linux 5.14. This problem
exists in 5.13 and needs to be marked for both 5.14 and 5.13 stable releases.

Here is my

Tested-by: Shuah Khan <skhan@linuxfoundation.org>

thanks,
-- Shuah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69f98dbd-e754-c34a-72cf-a62c858bcd2f%40linuxfoundation.org.

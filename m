Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBDW73X5AKGQE2J46SQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C35B32610EE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 13:48:30 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m125sf4636108wmm.7
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 04:48:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599565710; cv=pass;
        d=google.com; s=arc-20160816;
        b=MXOWfrV569C/na1oYqUKGRsGLkknZOhaxkqh8U5uXsKHQkUpmMZ3IarETJAc6Vrf8r
         VmrytphlLQqOFBtXxzk1H5c6QET/pzQjxUShN9hiPt1ZCmxShT25x/552cZjYhP85Icd
         KE9v1ozfc1pdLPtDyhaDebVc6VExwJtOow15oruZMgEer6B421PTtiR+X4VXO8vfCxno
         5AxMz22+JPXn2Y4Jbo8Nv1QI1QwTSjyQltxDvvvwA+u4aTxM8+tkbmEXTtPpi9J0QtRx
         SKjzTxWqADjJn0FKtr7rQN/y4Z2nVnLNn0WMhW9n6BQAwobAC5gu9q8BX8dafDdF4f27
         VpfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=B/U8msQcw6SlWZdV1MFGMoSr6Uay/uOJQzBMmQPkKcU=;
        b=KQYWPP9gmCu2r5+T4D1pHg+DwQm6VmFk3BCn5+xkSnbzCvnjf1dd4wLfX+gAysvpuH
         tJ5glPKrDP+A1wR3GUxuOD1JHdCaix8FlJSJSQ3BUSdypTcP7hlQTRWKSltZkoqCfaM4
         nztsIsidDxV+1eUTVbf5Maz1WcTWwud6tmqPw+sCraShdFjwO7ZcJn55cgslpJvg0lBO
         n5G0rxOLG9vuZ7yjawwXkM+Wb8bJ0BgKGDhov2GBabaGciWZZ27ObuxL36FXpwDkm8lq
         +nk8aW+v34mv+Oa18Zz2DETDv63pSDWX7qXAkgM4IBg8RqO03/POO+4C3+H937vQdjlu
         hrRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B/U8msQcw6SlWZdV1MFGMoSr6Uay/uOJQzBMmQPkKcU=;
        b=MLuLTTp5TWNHFEm9IYEBcryr01ZsMF6AucjArkuKRxFjFUDNLV/tHkIMktVVcbbYVc
         TCZyGMgL6p8myu9419G6NxLv6vUFKOIZkgi4FAANMdk10RHWUPl403w4JTlnWahz98ea
         POvJfxJM1PBbgx/3q/ZMW/xlyZrAO5dy1/pH79z0UGYCf+t9th3tw5u7Zq2gEDXzE3IN
         ke3K7kuqNbZqsxJGF3ci9tfdbnkwTW0dtQg+imTr3b61bA4O06KUlJP4kRB0jZh64GPO
         QVeVrsK07DfGrjt5CmE0VjO+47mZcTFeZjaFhh6DpfHN5CDj8SGeUuOGGK1Ie8krhF1A
         mU8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=B/U8msQcw6SlWZdV1MFGMoSr6Uay/uOJQzBMmQPkKcU=;
        b=LjdBI+y4PRGupEhax0/hBUjIjpWd8T/iBLdZ88c43eIpk2bwHlQNZKykobNcWuQwhD
         9U1wXK5kBF8WGrsBWvEATO+3AnTF/6trKvdXTScyNAQ9UbwsliidA+65ZQz3uytI1ymm
         q4at6t/y+XYviyuUGFibJBCQjuxW0BPs3rMIMbxStaq6s39wLXMZReZ+oGMd290i35HX
         89LKZGiXnTwR66O2r7yZD8kL5TOH7jXBmPXFcK23ytx1UVok+KRHOerqIQKgIy6Cfc/t
         ewAI9WPx+4QbX1286uaVfb4z/MlgmWKAW4yDZUxzVD+txviE43VU+zWB1pKYihgK+Sl9
         fTCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IEKtneCBlGe+r0vv/eGT6uKSkWexh3h4edt0haW2XySlGJekd
	BFFkKkmxABlHELMFfgNMMlw=
X-Google-Smtp-Source: ABdhPJy4FokzYScD6HdmD/Vm0mkMVB4NQLR7zBtSAu9nO4vtprLOxG/gzlE2iPXSxAhSMI7speipLg==
X-Received: by 2002:adf:f843:: with SMTP id d3mr28501366wrq.226.1599565710397;
        Tue, 08 Sep 2020 04:48:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b86:: with SMTP id b128ls1215330wmb.3.canary-gmail;
 Tue, 08 Sep 2020 04:48:29 -0700 (PDT)
X-Received: by 2002:a1c:c90d:: with SMTP id f13mr4086194wmb.25.1599565709693;
        Tue, 08 Sep 2020 04:48:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599565709; cv=none;
        d=google.com; s=arc-20160816;
        b=It2FkGkC3JC5TWDLih7VQzC7vj9R7oSo4zu3JCCZSoIzoyCEvhyW4uWL8SydvKdZMg
         tcCYKgEG60esyDb/Zt5FOlJ4vWosE2FuAmq0ljWG55mCBz0EgypF1z+v21WowmYjv5N3
         JLpJ2ptIINQMJg9vvny/RP+6X20r6sFP7yUqHt5j+oBwWHV+tTy58ulhXys3lcVXKm8N
         34tk6u9YXTNDSO22KU8UAHDsgOfjFWWcYqbBPtyZLZumuL6Jr5ma59MDvmovTHLaaWgz
         e9Za5Rh1vIWEinYUhkUk5sEbkqzQqA57+j1etOgJVCaiMKa3BhPI+v8ClLkLfI6923OM
         j5ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=v2gzKazHGgdyOUtRKTfsp3zmxTtbtrziB66dkEwUiYE=;
        b=QzC0jqiDA5kHpepT6gPmU+ss/7Lir6qKTFfaDpnlxjT3q2V7H7hjOqQvTgkX9Fy3mv
         s0sc3jh8Q9G/WR4+X0wNC7IvhLhLDvCN36343qPzkabKAz80p03K6zy/CkgZ5jxVuNWz
         qA5aDh0RyoSSq2SMAkZ0OVJ+VMWI0RCpwyPFpr7RmP0zPqhOFkHjBvvZB48sEbxeQ6/L
         kEki2kJsqRpa/rOurMQt5ur715qie6xlzyHrjzYk4EujF2I9QcXm9DxNpVzBilPu6ZeV
         ae8OeUglWtJOlaQ0L1Taj1VOTcbCVCZwJO24dwaxQxgm5ZrdJLdtgfPvGx2MipDQfdNc
         LIUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id g5si1070696wmi.3.2020.09.08.04.48.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 04:48:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id DF95EAC6E;
	Tue,  8 Sep 2020 11:48:29 +0000 (UTC)
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>, glider@google.com,
 akpm@linux-foundation.org, catalin.marinas@arm.com, cl@linux.com,
 rientjes@google.com, iamjoonsoo.kim@lge.com, mark.rutland@arm.com,
 penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com,
 aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de,
 dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com,
 gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com,
 corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw,
 tglx@linutronix.de, will@kernel.org, x86@kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
References: <20200907134055.2878499-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <4dc8852a-120d-0835-1dc4-1a91f8391c8a@suse.cz>
Date: Tue, 8 Sep 2020 13:48:27 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/7/20 3:40 PM, Marco Elver wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.

Looks nice!

> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error.
> 
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval, a
> guarded allocation from the KFENCE object pool is returned to the main
> allocator (SLAB or SLUB). At this point, the timer is reset, and the
> next allocation is set up after the expiration of the interval.
> 
> To enable/disable a KFENCE allocation through the main allocator's
> fast-path without overhead, KFENCE relies on static branches via the
> static keys infrastructure. The static branch is toggled to redirect the
> allocation to KFENCE.

Toggling a static branch is AFAIK quite disruptive (PeterZ will probably tell
you better), and with the default 100ms sample interval, I'd think it's not good
to toggle it so often? Did you measure what performance would you get, if the
static key was only for long-term toggling the whole feature on and off (boot
time or even runtime), but the decisions "am I in a sample interval right now?"
would be normal tests behind this static key? Thanks.

> We have verified by running synthetic benchmarks (sysbench I/O,
> hackbench) that a kernel with KFENCE is performance-neutral compared to
> a non-KFENCE baseline kernel.
> 
> KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
> properties. The name "KFENCE" is a homage to the Electric Fence Malloc
> Debugger [2].
> 
> For more details, see Documentation/dev-tools/kfence.rst added in the
> series -- also viewable here:
> 
> 	https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst
> 
> [1] http://llvm.org/docs/GwpAsan.html
> [2] https://linux.die.net/man/3/efence
> 
> Alexander Potapenko (6):
>   mm: add Kernel Electric-Fence infrastructure
>   x86, kfence: enable KFENCE for x86
>   mm, kfence: insert KFENCE hooks for SLAB
>   mm, kfence: insert KFENCE hooks for SLUB
>   kfence, kasan: make KFENCE compatible with KASAN
>   kfence, kmemleak: make KFENCE compatible with KMEMLEAK
> 
> Marco Elver (4):
>   arm64, kfence: enable KFENCE for ARM64
>   kfence, lockdep: make KFENCE compatible with lockdep
>   kfence, Documentation: add KFENCE documentation
>   kfence: add test suite
> 
>  Documentation/dev-tools/index.rst  |   1 +
>  Documentation/dev-tools/kfence.rst | 285 +++++++++++
>  MAINTAINERS                        |  11 +
>  arch/arm64/Kconfig                 |   1 +
>  arch/arm64/include/asm/kfence.h    |  39 ++
>  arch/arm64/mm/fault.c              |   4 +
>  arch/x86/Kconfig                   |   2 +
>  arch/x86/include/asm/kfence.h      |  60 +++
>  arch/x86/mm/fault.c                |   4 +
>  include/linux/kfence.h             | 174 +++++++
>  init/main.c                        |   2 +
>  kernel/locking/lockdep.c           |   8 +
>  lib/Kconfig.debug                  |   1 +
>  lib/Kconfig.kfence                 |  70 +++
>  mm/Makefile                        |   1 +
>  mm/kasan/common.c                  |   7 +
>  mm/kfence/Makefile                 |   6 +
>  mm/kfence/core.c                   | 730 +++++++++++++++++++++++++++
>  mm/kfence/kfence-test.c            | 777 +++++++++++++++++++++++++++++
>  mm/kfence/kfence.h                 | 104 ++++
>  mm/kfence/report.c                 | 201 ++++++++
>  mm/kmemleak.c                      |  11 +
>  mm/slab.c                          |  46 +-
>  mm/slab_common.c                   |   6 +-
>  mm/slub.c                          |  72 ++-
>  25 files changed, 2591 insertions(+), 32 deletions(-)
>  create mode 100644 Documentation/dev-tools/kfence.rst
>  create mode 100644 arch/arm64/include/asm/kfence.h
>  create mode 100644 arch/x86/include/asm/kfence.h
>  create mode 100644 include/linux/kfence.h
>  create mode 100644 lib/Kconfig.kfence
>  create mode 100644 mm/kfence/Makefile
>  create mode 100644 mm/kfence/core.c
>  create mode 100644 mm/kfence/kfence-test.c
>  create mode 100644 mm/kfence/kfence.h
>  create mode 100644 mm/kfence/report.c
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4dc8852a-120d-0835-1dc4-1a91f8391c8a%40suse.cz.

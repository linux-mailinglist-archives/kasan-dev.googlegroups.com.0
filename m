Return-Path: <kasan-dev+bncBDH7RNXZVMORBGXE76VAMGQEGO6TNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B6F7F69E8
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Nov 2023 01:45:16 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-35ba0b303bdsf663445ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 16:45:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700786714; cv=pass;
        d=google.com; s=arc-20160816;
        b=pyxTTfVtg0m8+Y0vksG5FNnSlkse1z/kad2/hLOFv6opfDiUBJRfzWEYXwAINLB8Za
         POYvRJYklIzr8jncYEPqfHJhpF+BU1rhpzmObeWveGH8bppIJH4UofWRMfblaDxRoPy6
         3x0vQOAQxgGsZiB3ihmQo1Z3zOHSzf7xGySbay1y5cmZPBhr9/Hv3zJXHNZ2JF+a+u3k
         ps9FEHaSMver7oTLxTQyviEO1AUzim6zGAoYHsPfwDNmhIof5s8jBrjvIalVitsEEtmf
         wJ1gNISeouZk//Hid9JaW+U4407M1M0VnTC1wkY3amF/wykhT79z4zJ+FOerYgiW4Rbu
         ENsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=vA1fF4G+MYaTfDXu33M6/P9elq5NbBhCag+U1egig4g=;
        fh=znRC6ertM1NN7yUqvRad/Q+ykfaWJVc1H+onLpZ+Buo=;
        b=d8SBt+o8tg1F4raX9P9BVgaYMNSuyg+3m+CjJKEJF5+MLxc6xdDDbcZEqLRiZj8Zsq
         Td6FQNYNERoroH45cwukzxzjyIhm6dKoz4gXLOAPVh8278rHLEhdiL18XaFD297cH5ay
         VCOFg9KZWVElejnCswLxFPh0dyASnvK2MjRFJDIz2HBJj5im9JDBOtmuyVd0fVRw88i4
         ZFlzORwqoockVRA1c2z0JVZUW+pvKA5TLmxw8rjlQ3pvA6PWGVvjzwd66MopIn65U/bX
         PwYxXLAeGHbUx799Ze/q82uWRd6a08alt4vD8kLj1nlKAfTLFlyp5hGQ+qQZh7zBNhMR
         ibaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A1i0ErEi;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700786714; x=1701391514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vA1fF4G+MYaTfDXu33M6/P9elq5NbBhCag+U1egig4g=;
        b=AcS3uQyLZYRtXNFwXHm3eWNdJLt6m+tyoSUr6ACohCoCsSs5/zdJh8oVN6DfLEUMmG
         cpgRlMEq9m2cFVgosJ0i2DnNaCYdjaXy55TucPOED8R6QxkHjTTNA6UVL7NSw6k6Kxwm
         nQaliX/64livKmE1veb3Ks53wFNA20XG625WUBosWiEbfUbEwgTR52FIuGLGv39BsYzQ
         y4elKdmXPTZ1plaDvHGrBZUpCAaAxxUJIJ4+lD1vKNpjvnR1nORbvyZCPvvSiZhaboDB
         5XsUFvFdFytYUL7aTOP+Ptu4BblGotVKfI2F6Kr9NQ19MGMHwjjp2zSt5OzN8Jqk/Sp1
         bQag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700786714; x=1701391514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vA1fF4G+MYaTfDXu33M6/P9elq5NbBhCag+U1egig4g=;
        b=mkBZgngLKdgXTiPzClYKW6nKq/OtL/XQ1vRZUml9vTIcuxhC+lmDzI8Js0Lm4vP412
         QE/BPWffqSCkDof0hp+AQWyZdMpE0cVjqKtkl1XyzpeNHG7BYv45tv55VU9r5OYsJxRJ
         EjEr2hozkKpfeYGyEN2OHly/EHAWGEj5MLyDJg8E7gfUOtO8o+AVMtYDjQg80XboYNWE
         AlqIRH46WxDV3l8On9bbuc1QL/yrtxCob3VkIpXX0Xk5fnVPUZxX2oMtE9x6JEYzkUig
         g9HGBdcjyHTrcocsduzDYy6IPITk7CE7AU05PDSoLQ0vWq68NQWnIE1pTnr0jFFs9N3W
         h2Sg==
X-Gm-Message-State: AOJu0Yx9tSKWgw1+59X5K8RCh/GZR8ENDOY7cPCzPAsEFH2qaE8A0KrN
	X3BjqPOGUUrux00s9aXvXno=
X-Google-Smtp-Source: AGHT+IGphpASQHz48UIL+odMhzN4blIUnCbPHAcBoA/vs9AomTaE7sNKowp/xls4EJAK9EsnTzRjOA==
X-Received: by 2002:a05:6e02:214d:b0:357:ccd6:a347 with SMTP id d13-20020a056e02214d00b00357ccd6a347mr335178ilv.19.1700786714643;
        Thu, 23 Nov 2023 16:45:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:22a2:b0:589:f693:e94a with SMTP id
 ck34-20020a05682022a200b00589f693e94als1136281oob.2.-pod-prod-08-us; Thu, 23
 Nov 2023 16:45:14 -0800 (PST)
X-Received: by 2002:a9d:4f02:0:b0:6c0:9498:7a77 with SMTP id d2-20020a9d4f02000000b006c094987a77mr1191255otl.32.1700786713806;
        Thu, 23 Nov 2023 16:45:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700786713; cv=none;
        d=google.com; s=arc-20160816;
        b=03SIgp5TdXB11egFc+KRmpgz2ssPKcqHa+Lk9K7YHYtg9d7toFqPdrSOahrQsOMJvb
         cqbkW822guSKo+zbcENf+ZVftjsYlpF+ATBFcbNNb4LTou2QVl58mQXYqteui+h23Lw2
         I6TlM+zz1/BPXq5oh9n5uaq+1jYM0Xus4Ay2ZAT5EMjVyBaeAPmBvUz7Od2wJaz7zf6J
         JJHN0oCRXGbboCGjnpT7RTKrSZzCeHi2QmhnZcP+7U1HoFDAgOKfcdlGHbV0yySFh/Ev
         hHhKgIupDGX1eEGIaIhnIED0KoebSYIu8jMgjI1Mi0LpznDwMjY99sN8dcIB430HJRqq
         LYCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=RjvlNJZCYVj3BK/c/qbMtW/UyhsFITEp4fF0Uz8Mao8=;
        fh=znRC6ertM1NN7yUqvRad/Q+ykfaWJVc1H+onLpZ+Buo=;
        b=Vo0Q5b7kkg6p6fCZo+X/FCaGMzUjyR8WjuMqWNpX4NLlxJ+/CNW9Inz2+URQNO/l45
         0nOsuoSJdHk3GMZmXzKEhp8U2l5qKq78Qe8ZSUVkDh1Xu4uz0sVnevVdrXKSsGKTLbCd
         iug1YRiNgB0EuSKyt61gahJsydEjOVyNXzlRRS+lLETMfyo3C1TNj6AlA+vqwd69F2Dw
         NxNim49qpElXqLyHoK9yvO9xszUZ/uR8vkILpyvMEVmZpA7bd9zgdm+JFKWn+Q9/QU15
         aPL16UYQlYjJh/eHXwFCrOg+G7IXbcIPvK8i6NGkqo30zZFkdlXhLZbZQx2FawttWN0C
         u4Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A1i0ErEi;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id n21-20020a635915000000b00569ee9c848fsi122875pgb.0.2023.11.23.16.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 16:45:13 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id e9e14a558f8ab-35938a7d050so134975ab.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 16:45:13 -0800 (PST)
X-Received: by 2002:a05:6e02:1687:b0:357:4335:77fe with SMTP id f7-20020a056e02168700b00357433577femr452960ila.27.1700786713087;
        Thu, 23 Nov 2023 16:45:13 -0800 (PST)
Received: from [2620:0:1008:15:ab09:50a5:ec6d:7b5c] ([2620:0:1008:15:ab09:50a5:ec6d:7b5c])
        by smtp.gmail.com with ESMTPSA id q4-20020a631f44000000b005acd5d7e11bsm1919194pgm.35.2023.11.23.16.45.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Nov 2023 16:45:11 -0800 (PST)
Date: Thu, 23 Nov 2023 16:45:06 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, 
    Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
    Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
    Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
    linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
    kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
    linux-hardening@vger.kernel.org, Michal Hocko <mhocko@suse.com>
Subject: Re: [PATCH v2 00/21] remove the SLAB allocator
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
Message-ID: <b4d53ec4-482d-23ec-b73f-dfbc58ccc149@google.com>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=A1i0ErEi;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::136
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Mon, 20 Nov 2023, Vlastimil Babka wrote:

> Changes from v1:
> - Added new Patch 01 to fix up kernel docs build (thanks Marco Elver)
> - Additional changes to Kconfig user visible texts in Patch 02 (thanks Kees
>   Cook)
> - Whitespace fixes and other fixups (thanks Kees)
> 
> The SLAB allocator has been deprecated since 6.5 and nobody has objected
> so far. As we agreed at LSF/MM, we should wait with the removal until
> the next LTS kernel is released. This is now determined to be 6.6, and
> we just missed 6.7, so now we can aim for 6.8 and start exposing the
> removal to linux-next during the 6.7 cycle. If nothing substantial pops
> up, will start including this in slab-next later this week.
> 

I agree with the decision to remove the SLAB allocator, same as at LSF/MM.  
Thanks for doing this, Vlastimil!

And thanks for deferring this until the next LTS kernel, it will give any 
last minute hold outs a full year to raise any issues in their switch to 
SLUB if they only only upgrade to LTS kernels at which point we'll have 
done our due diligence to make people aware of SLAB's deprecation in 6.6.

I've completed testing on v1 of the series, so feel free to add

Acked-by: David Rientjes <rientjes@google.com>
Tested-by: David Rientjes <rientjes@google.com>

to each patch so I don't spam the list unnecessarily.  I'll respond to 
individual changes that were not in v1.

Thanks again!

> To keep the series reasonably sized and not pull in people from other
> subsystems than mm and closely related ones, I didn't attempt to remove
> every trace of unnecessary reference to dead config options in external
> areas, nor in the defconfigs. Such cleanups can be sent to and handled
> by respective maintainers after this is merged.
> 
> Instead I have added some patches aimed to reap some immediate benefits
> of the removal, mainly by not having to split some fastpath code between
> slab_common.c and slub.c anymore. But that is also not an exhaustive
> effort and I expect more cleanups and optimizations will follow later.
> 
> Patch 09 updates CREDITS for the removed mm/slab.c. Please point out if
> I missed someone not yet credited.
> 
> Git version: https://git.kernel.org/vbabka/l/slab-remove-slab-v2r1
> 
> ---
> Vlastimil Babka (21):
>       mm/slab, docs: switch mm-api docs generation from slab.c to slub.c
>       mm/slab: remove CONFIG_SLAB from all Kconfig and Makefile
>       KASAN: remove code paths guarded by CONFIG_SLAB
>       KFENCE: cleanup kfence_guarded_alloc() after CONFIG_SLAB removal
>       mm/memcontrol: remove CONFIG_SLAB #ifdef guards
>       cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
>       mm/slab: remove CONFIG_SLAB code from slab common code
>       mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB ifdefs
>       mm/slab: remove mm/slab.c and slab_def.h
>       mm/slab: move struct kmem_cache_cpu declaration to slub.c
>       mm/slab: move the rest of slub_def.h to mm/slab.h
>       mm/slab: consolidate includes in the internal mm/slab.h
>       mm/slab: move pre/post-alloc hooks from slab.h to slub.c
>       mm/slab: move memcg related functions from slab.h to slub.c
>       mm/slab: move struct kmem_cache_node from slab.h to slub.c
>       mm/slab: move kfree() from slab_common.c to slub.c
>       mm/slab: move kmalloc_slab() to mm/slab.h
>       mm/slab: move kmalloc() functions from slab_common.c to slub.c
>       mm/slub: remove slab_alloc() and __kmem_cache_alloc_lru() wrappers
>       mm/slub: optimize alloc fastpath code layout
>       mm/slub: optimize free fast path code layout
> 
>  CREDITS                           |   12 +-
>  Documentation/core-api/mm-api.rst |    2 +-
>  arch/arm64/Kconfig                |    2 +-
>  arch/s390/Kconfig                 |    2 +-
>  arch/x86/Kconfig                  |    2 +-
>  include/linux/cpuhotplug.h        |    1 -
>  include/linux/slab.h              |   22 +-
>  include/linux/slab_def.h          |  124 --
>  include/linux/slub_def.h          |  204 --
>  kernel/cpu.c                      |    5 -
>  lib/Kconfig.debug                 |    1 -
>  lib/Kconfig.kasan                 |   11 +-
>  lib/Kconfig.kfence                |    2 +-
>  lib/Kconfig.kmsan                 |    2 +-
>  mm/Kconfig                        |   68 +-
>  mm/Kconfig.debug                  |   16 +-
>  mm/Makefile                       |    6 +-
>  mm/dmapool.c                      |    2 +-
>  mm/kasan/common.c                 |   13 +-
>  mm/kasan/kasan.h                  |    3 +-
>  mm/kasan/quarantine.c             |    7 -
>  mm/kasan/report.c                 |    1 +
>  mm/kfence/core.c                  |    4 -
>  mm/memcontrol.c                   |    6 +-
>  mm/mempool.c                      |    6 +-
>  mm/slab.c                         | 4026 -------------------------------------
>  mm/slab.h                         |  551 ++---
>  mm/slab_common.c                  |  231 +--
>  mm/slub.c                         |  617 +++++-
>  29 files changed, 815 insertions(+), 5134 deletions(-)
> ---
> base-commit: b85ea95d086471afb4ad062012a4d73cd328fa86
> change-id: 20231120-slab-remove-slab-a76ec668d8c6
> 
> Best regards,
> -- 
> Vlastimil Babka <vbabka@suse.cz>
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4d53ec4-482d-23ec-b73f-dfbc58ccc149%40google.com.

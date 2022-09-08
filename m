Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUM42MAMGQEUUNF3BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FA665B1461
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 08:05:56 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id n6-20020a4a6106000000b0044b2434319esf6826363ooc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 23:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662617155; cv=pass;
        d=google.com; s=arc-20160816;
        b=O2DRyOZODnY2iJUYTmCx8hotJ1pB7jAgCbd3hXj6H7xlaHc1X1GO4xIvlBM6AWvX8i
         1bo72Hqza0T0PIsRIpq1GFqxoT4y5cQP4BhofabyBKGNMBxgESOZyyjd3L6/T2zcgso5
         Pgl35UqGl7++TxuKnAL36Q6AgqO2HZM6NipGjoXrepih9nea2hnZMvegsz1fqLzDUjyB
         u3rWKcm1fLLwYpsAt06YyUGDz+fVolRX6W9AJw4wpRQ2O31PLRKb9L6W9d5ZhQcVEOlm
         Xf5hZ0TWZvcxxYeaH49Hdx/FzL2O1Rprmfu8Ln10ctxsEmujosvOMtRsGTIUkQSbvQDX
         Oc8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uPuxvJf2Nn1gAeEyN3AOji4mMrhskrYKdxorNS82VbY=;
        b=rq5cvxS2L7EnzAdktvIQQ7xq4sg2WrA1WGdTEw5b+6YTbyVTg7j/NogB4RqdngP6M1
         F796TPv11RdjJ9gyIhbTCnj1YqrsYb98jNdKc5uWFyPdoSGT5F/hbllaZZlbI99rZHC/
         TtHdBnfmRlKFCZ7FL0ed8ezRrTFlBUiS9ydaKGfCTgKWby9zfyFXY2vCCwhatcBBeDaL
         3W5ZtTmSD4SXjWyMWgox/JltjT0igZDhoUyXf6OcjrZg+koH5I8TgEisCBf8LD3uSqDC
         SSJsTNqAuDxDwCYz/o1HuqWDsABj9B7SoYKPL5+y3oED48G3jXxPkuaImXbmNN6FkVtv
         RebA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dxgOW659;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=uPuxvJf2Nn1gAeEyN3AOji4mMrhskrYKdxorNS82VbY=;
        b=M8Oc0QL0BzCtwgiFoy5ijdxqGRuewM5jBmFzviaxmuzDYAtIby+j5oBDCq5AnSWPpu
         DyioclLK6N+mX/H2P6e7HoWWAKUnu/cpOWKO56DQfetFxJqdYBHVEzQrbtv0saOns71g
         vy2JL1lOkL1GI3U6OHY5kqn3Aw2YUAwloiwlCgZcFdZ4Ii9LFLE9KteUFDIK+q875dXf
         8iDqHS19fS1PACXqCF6q9c/sote+sK7iYY1xLbUM/dTLaKq6qeOO2EFuhA3i1ZVdtl6i
         EYBZAxwPfp2FtiPm+lZeB5LiNO4nSshdgeuxn07e9E1zxLceZc9PqUHkrPC6UTv8eAIS
         KikA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=uPuxvJf2Nn1gAeEyN3AOji4mMrhskrYKdxorNS82VbY=;
        b=Kd8F1cnYfrSAVyqnXS/PaWUGK2AzlzIauANYN6gYNjF9k/ovYzMSPiKYd7UxGOrp50
         53o+Sl5uaOuhZibWWI/i+ghqNjX+iPKHGh9c92iZRZyZ9ngB4odane91jMALHd7zkw8q
         y2vjPawx59whryO82IuOxNxR+XLJFMoqJ0vyXLRQg2oDv1YIQCdLo6rvKdXnLn2X/MSk
         12MTa1VGgizbyxVcq4MxP1elph4aFux3XyIbQzfjKrdHeAyuwSv1SccjaELyipyBPyqP
         6ab2ZfBS2vexnpisYfSCVccCuSits6Z40SogQf2mzVkXj+thNktbIinLErXhLeLzm6ys
         qyJA==
X-Gm-Message-State: ACgBeo1uYxye7NIK7F1KNNU1wZq6Lqi4+/72wpsnBwE8uhqMWXcy0auU
	dUIVch5UK3+dEHjIVZIjfFE=
X-Google-Smtp-Source: AA6agR6/e/4LAxTjSSrZ5AcGuOFeYCKuVy+Zs7JG2gvimgMEi/VjWAyjczpKoPx8hhiUzkrWuaBL3g==
X-Received: by 2002:a05:6808:1528:b0:343:2b03:95bb with SMTP id u40-20020a056808152800b003432b0395bbmr755448oiw.34.1662617154792;
        Wed, 07 Sep 2022 23:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2c56:0:b0:445:84e8:1342 with SMTP id o83-20020a4a2c56000000b0044584e81342ls41099ooo.8.-pod-prod-gmail;
 Wed, 07 Sep 2022 23:05:54 -0700 (PDT)
X-Received: by 2002:a4a:d41:0:b0:44a:8081:733c with SMTP id 62-20020a4a0d41000000b0044a8081733cmr2471832oob.71.1662617154197;
        Wed, 07 Sep 2022 23:05:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662617154; cv=none;
        d=google.com; s=arc-20160816;
        b=Ym0VC6A0LJPoKaBComlhg0zKqEegIoV5I0eXujNDeRD9fR362ix94qInvFGn4Y9+ZD
         G/BbIuxem5yo0PIehxyhaghxLxZ7WeUDfXZnq9THX8769oov0Y5+c8XSXtem+qMuLlt3
         aBaBqom0fuIfCmeN/uQNPNi/WTVKLXeSinjq1eRfF+4z0tlt8zPfXCTApawaVj83NG0B
         gOFwMBvFW6fwvNPYDCzpSz5NXCEx9FIMX+A8Zy1/vg2b0/gb0xkA5+owTIXNqF9dEUJb
         n8zp4u0rviBXfyUmLJX4Gc/lMwjj19zLY20ye17cARIVxxZe87kdXmRl2RQ+PZTxTxA0
         HL+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lJYRFzwH4JLePemhbCSx0zq48/URDmByv8p7ogaW1eM=;
        b=t3GQrFDcKaP7SMi4uTcpMNQjfVGLgxo9PQ4oAmVqF/UGSjkoSukb0ZNQmxKVpL62LY
         KpKYEGynCzBJAL1SRUao3EOxaTTIEmMxU9C1dIlmFUMpBwq4zqTOob9Q3ybEQUWVuUYc
         o+yhIUN3SfIXD0qPW5NgIalXChFLk0kgrkkB/jwWRp7+KGqhP74hlNdxRHJu56mIV2nL
         z3bFEkMXX/FtwcDCyjGpoG8pfE8yGqFoNsKMjrCnyor1SHuTrjXqptT7587IfyyVT89c
         m3yyzVv5VmNEULa2ZuBg24KjrHCX8Mgg5yLi11xu02smd4RKRidpfIRJ8KfY6UB4tJFQ
         spQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dxgOW659;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id y9-20020a056870418900b00108c292109esi3225781oac.2.2022.09.07.23.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 23:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-3454e58fe53so95987007b3.2
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 23:05:54 -0700 (PDT)
X-Received: by 2002:a81:bb41:0:b0:328:fd1b:5713 with SMTP id
 a1-20020a81bb41000000b00328fd1b5713mr6423586ywl.238.1662617153642; Wed, 07
 Sep 2022 23:05:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com>
In-Reply-To: <20220907173903.2268161-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Sep 2022 08:05:17 +0200
Message-ID: <CANpmjNMH4_H75Z_aQ63C52TDma7PnjWWjmyv+MtXt2W522UAQQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Instrument memcpy/memset/memmove with newer Clang
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dxgOW659;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Wed, 7 Sept 2022 at 19:39, Marco Elver <elver@google.com> wrote:
>
> With Clang version 16+, -fsanitize=thread will turn
> memcpy/memset/memmove calls in instrumented functions into
> __tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.
>
> Add these functions to the core KCSAN runtime, so that we (a) catch data
> races with mem* functions, and (b) won't run into linker errors with
> such newer compilers.
>
> Cc: stable@vger.kernel.org # v5.10+
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/core.c | 27 +++++++++++++++++++++++++++
>  1 file changed, 27 insertions(+)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index fe12dfe254ec..66ef48aa86e0 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -18,6 +18,7 @@
>  #include <linux/percpu.h>
>  #include <linux/preempt.h>
>  #include <linux/sched.h>
> +#include <linux/string.h>
>  #include <linux/uaccess.h>
>
>  #include "encoding.h"
> @@ -1308,3 +1309,29 @@ noinline void __tsan_atomic_signal_fence(int memorder)
>         }
>  }
>  EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> +
> +void *__tsan_memset(void *s, int c, size_t count);
> +noinline void *__tsan_memset(void *s, int c, size_t count)
> +{
> +       check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);
> +       return __memset(s, c, count);
> +}
> +EXPORT_SYMBOL(__tsan_memset);
> +
> +void *__tsan_memmove(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
> +{
> +       check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +       check_access(src, len, 0, _RET_IP_);
> +       return __memmove(dst, src, len);
> +}
> +EXPORT_SYMBOL(__tsan_memmove);
> +
> +void *__tsan_memcpy(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
> +{
> +       check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +       check_access(src, len, 0, _RET_IP_);
> +       return __memcpy(dst, src, len);
> +}
> +EXPORT_SYMBOL(__tsan_memcpy);

I missed that s390 doesn't have arch memcpy variants, so this fails:

>> kernel/kcsan/core.c:1316:16: error: implicit declaration of function '__memset'; did you mean '__memset64'? [-Werror=implicit-function-declaration]

I'll send a v2 where __tsan_mem* is aliased to generic versions if the
arch doesn't have mem*() functions.




> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMH4_H75Z_aQ63C52TDma7PnjWWjmyv%2BMtXt2W522UAQQ%40mail.gmail.com.

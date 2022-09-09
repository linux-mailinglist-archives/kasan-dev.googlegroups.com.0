Return-Path: <kasan-dev+bncBCMIZB7QWENRB6XW5OMAMGQEHCVY2MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EF825B31DF
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:38:19 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id h35-20020a0565123ca300b0049465e679a1sf359994lfv.16
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:38:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662712698; cv=pass;
        d=google.com; s=arc-20160816;
        b=D4fWXj2//i8VRiNAwksPVuwZqGY3MYdU2kN2coXWfXv1KNEr5uqEa/gOefOuB/rcW2
         SoKpyHdvzMCAtwlpxTWwEwXMKc5o4d5mP73NUFMVGXTATcRahaVm5JnKmV8Qe2pNDkEr
         Ax9F7IgX9a+pTqyhTezITtcNHuXrTT4+yus6ZU7qE1maby6sSp/MSGli4Bl5NUwTxBbg
         SH/jMk5XHB5gObgKOArpmg2nRuUnVll76fh0fqkqqmZ1PI82ILGJagV8F9Yu/Np08kA4
         TJ3pd+WKFmFMC8KlTUT8rwebzg3q5poHEc0cGZYwSaN3vg6QOuei7BxSzNi8hlPdHFvF
         BYxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0nPYELfbAPe9YJpSsZJ7rEkYm/xJmXzyZKc//cjV+eI=;
        b=WUU6RUjXqMmP80Hh4kcmI/co440vVLmiDjmf+2KFW4pUJqoI2OW1OpF9+GYAP242Ta
         3p36Tv/0ip7VsZDa/8/Fvpc8EwTsTAFq/wGCobYC79qyWoKfsjXrFjYxV+bhDtbDtNsY
         G9ydIFfdEYkV9wqMiig73TQFO+W7mOq+Ourc3gPDM9CXABxkSKTTvwPcEVxWCY9Ynl3f
         euM4vhj8DAhsBv4vgaoDLvQ/noGJlMgOYppWpgaU+Yq35nKIgz/kmU/dUd7lG09lwpVJ
         bX/yovzlDLXSJUJMIT/DWvtCoHyuXh4C+EMKZxBWtCuzhPZFwKW97wXQDH2XegSCiMqb
         qfTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j09QxsNs;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=0nPYELfbAPe9YJpSsZJ7rEkYm/xJmXzyZKc//cjV+eI=;
        b=JufDBRqwwFL9dVv/IrVVpbjRlsowWcMCFseuVK57ZOc1QZ+28IySg3W/gybnfG0PSM
         BTr4WHNDXQZWWB84YIl3JzdyhA4GRTjCoxHmMaFYynVxS5HXzzO1+EPEJelefOjZiouI
         C/exgzug8fzOFbYr02rb54XfifVKEXbz+NuGOFJlZ9xP9zdiF1IU1dZLlwyBEzzfJJnT
         S3vdBJ2HCCcjmeIyPfeOi+VAjzH5eMTYKWGknnTrvAwdCzPoXO4HtKhoUFXX8hQCw8UC
         5n6EX2vFTV+fCaGSHCTnhH613eZ1QZLbqJt54mS3bntyVfL/7SvhlVh+K6OialeRWzWH
         ni8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=0nPYELfbAPe9YJpSsZJ7rEkYm/xJmXzyZKc//cjV+eI=;
        b=1bwjrcZJiOOrYsdVFMttfDpLW+uT37dIRQ1KqStGD8b7T1F3y0zWz1V1nVLkyPVK6c
         1ku8FeQOi/E05OWQf+eGe4ZVw/acKJrjOSaSl0jI+wd343Xtyx+t3we6hlQgKjBB+1aH
         2kbYFTflpUWFeLCJuSDl165bw9CqJkOS7ue6/vh89JWYpQYUr4/0AZa91Vq8aYsKbGEN
         0ARogfqs3hMWtzpolf7ziW+wszFQCvFWZmoNPTUOQeQRV1wlvGkC2K0Fv7K7hB4B4R7b
         sJRQtgRlkLkrFJyAcoRxQX0Q+WIVz+JCJqT/ZZNXt5lk7TIEa4HzM71MUNIGZ3tlu/0j
         e30A==
X-Gm-Message-State: ACgBeo1x2P0Gq5vfwjs/I7ssBVAP0HDZmapqHB0tIhxhllhVDDhfZWvu
	XCjtV5LSJ9P7w/vDVZfqSFE=
X-Google-Smtp-Source: AA6agR7xNCIY/yZNIknNZJdq+kA/C1gLEDwqPm8jh9hEfPkUA3uv5SF4CGO0pZXtxUrmOUbdNikKnQ==
X-Received: by 2002:a05:6512:33c5:b0:48b:9c2f:938a with SMTP id d5-20020a05651233c500b0048b9c2f938amr4116410lfg.557.1662712698281;
        Fri, 09 Sep 2022 01:38:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a87:0:b0:26b:a653:ec79 with SMTP id p7-20020a2e9a87000000b0026ba653ec79ls624339lji.1.-pod-prod-gmail;
 Fri, 09 Sep 2022 01:38:17 -0700 (PDT)
X-Received: by 2002:a2e:391b:0:b0:26a:c75c:ff6e with SMTP id g27-20020a2e391b000000b0026ac75cff6emr3437459lja.99.1662712697094;
        Fri, 09 Sep 2022 01:38:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662712697; cv=none;
        d=google.com; s=arc-20160816;
        b=Wzi3/8kO5S1adVD3429G8zqrXGgwqdmy6bygr08HReij0gQNIppV1WX81UPGDV+SlW
         GwypAVGYZnezvHCwiIaF2pxptwCUgbPoj9F+0cbY433VkIfsSK+KgeLY8guYnAxMyof+
         c4nUs+nlVyUxcHGvD8WPLYRboF9HWtjtGmM3ETRoe7B++DKk1d0d4cHC7zrhK9gvJPmF
         +MbCXKg7ghsyTbiObwlGix4WqIW/b9Z7ZiBSKaVd/aOfXwefS+p6lcZQDQ3jEoksJal1
         Y23sxZsiZfA4JneOowF1E8pDDtiBs+7iBlIFTU6C/05qVQEJx0svWe+dwgAeA3g6CmRi
         elBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BQBhZcEfl6T9p1U34zgQ/JzWRYaK36lx1DLrHB7PYZQ=;
        b=0xuqH08q/gI5ie7tX988+PVkASbRSqRsOQtMYGm/FOTvlFW5xjIqbcTS7NBpH0q1oZ
         hublZD3BVlcUlYR2z29KN+G+GZ0Pda7agYA9jrB6FX6jW+4QZuPERIp3g+P++IuMXW+S
         cMhYDKAHFu3ao897ZDJgaPLGdy8LI39tdRolZX5TMeUWoWTqovUjKjeEtQBE6yrIg2fr
         N2AvkX6bo69/d9StZJE3cyir3b5crv76s94O4XX3PaHXzX2nCzoY4luVFq6XxOnRkfAb
         KjY1wmVPHksFdTTwq8sIE9rvEyaGvebJbda9X0e1TUAGwWQqWpnQMYYr4w5K+eaRopAV
         Vzkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j09QxsNs;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id q3-20020a056512210300b0049495f5689asi49244lfr.6.2022.09.09.01.38.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:38:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 9so71260ljr.2
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:38:17 -0700 (PDT)
X-Received: by 2002:a2e:bf07:0:b0:261:cafb:d4a8 with SMTP id
 c7-20020a2ebf07000000b00261cafbd4a8mr3459885ljr.268.1662712696564; Fri, 09
 Sep 2022 01:38:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220909073840.45349-1-elver@google.com> <20220909073840.45349-2-elver@google.com>
In-Reply-To: <20220909073840.45349-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Sep 2022 10:38:04 +0200
Message-ID: <CACT4Y+Zuf+ynzSbboTAN0_VLedeVErO6qm49H4YzuR1e8EgJUQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kcsan: Instrument memcpy/memset/memmove with newer Clang
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=j09QxsNs;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 9 Sept 2022 at 09:38, Marco Elver <elver@google.com> wrote:
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
> v2:
> * Fix for architectures which do not provide their own
>   memcpy/memset/memmove and instead use the generic versions in
>   lib/string. In this case we'll just alias the __tsan_ variants.
> ---
>  kernel/kcsan/core.c | 39 +++++++++++++++++++++++++++++++++++++++
>  1 file changed, 39 insertions(+)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index fe12dfe254ec..4015f2a3e7f6 100644
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
> @@ -1308,3 +1309,41 @@ noinline void __tsan_atomic_signal_fence(int memorder)
>         }
>  }
>  EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> +
> +#ifdef __HAVE_ARCH_MEMSET
> +void *__tsan_memset(void *s, int c, size_t count);
> +noinline void *__tsan_memset(void *s, int c, size_t count)
> +{
> +       check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);

These can use large sizes, does it make sense to truncate it to
MAX_ENCODABLE_SIZE?


> +       return __memset(s, c, count);
> +}
> +#else
> +void *__tsan_memset(void *s, int c, size_t count) __alias(memset);
> +#endif
> +EXPORT_SYMBOL(__tsan_memset);
> +
> +#ifdef __HAVE_ARCH_MEMMOVE
> +void *__tsan_memmove(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
> +{
> +       check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +       check_access(src, len, 0, _RET_IP_);
> +       return __memmove(dst, src, len);
> +}
> +#else
> +void *__tsan_memmove(void *dst, const void *src, size_t len) __alias(memmove);
> +#endif
> +EXPORT_SYMBOL(__tsan_memmove);
> +
> +#ifdef __HAVE_ARCH_MEMCPY
> +void *__tsan_memcpy(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
> +{
> +       check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +       check_access(src, len, 0, _RET_IP_);
> +       return __memcpy(dst, src, len);
> +}
> +#else
> +void *__tsan_memcpy(void *dst, const void *src, size_t len) __alias(memcpy);
> +#endif
> +EXPORT_SYMBOL(__tsan_memcpy);
> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZuf%2BynzSbboTAN0_VLedeVErO6qm49H4YzuR1e8EgJUQ%40mail.gmail.com.

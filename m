Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75R3D5QKGQEIS6R4RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A4D7280613
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:59:27 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id j7sf2375980wro.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:59:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575167; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZFEDXeYTrxkdOhq6z2gEBSEEcwW2T2pbaZFIHQ+Rw1h7aNLHuTrwW4rB43QmnTYDb
         ws3hlSRr/9GplpL83QawG5sRXN4XcTWYAFQjIVasuv25K+JJTQLIq00rDC5KHgavRQ3l
         PKeotTI39/xUVTFOfJ+kqMCSWcbCxTwqsaoWNH4Z1iUX+ycZQtOgD4+jq8TqDs/Lvkpz
         gpotmhEn3ePPp5/EcEyhma0fFdKNDcrODVAIOojJn9+nfZf6WmoDDWcvC3BMXn2+ciwZ
         pkXkdF1psv6imK6d/VbzmtNTV4qgXQlOyIKN0+ekCGWRoLakA9DHK3fP0IzXFvvGY4OP
         mjhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YeYWD3jkZVf4aC9tS+arBkqUCu+JIKiLQm1gzzFxces=;
        b=OWotx8btKZgGSwHEGKznI/9q0+8LsGk4Om0poJLtrF99MKoLSFxUvzNCSgTBwhBKO9
         t7VLzqrj9wRzfxyeDUI0GWXGfu3puHXH4LcPld5p0OFxW2EL37nt9scvmr/FKb9Br0LF
         5mO53hKvCZfz394I1YzB34uRikydmSWOdzTT9PhgB+3UPxycOxJDDkNoOJXv99Ee0FnT
         XV/01eosZ7GP4f+93C+kTy0kWAwOD4OApNx81haiLLo/txw3cSbKyM48+FU88/i6meAP
         /GxPbaVcUNN1vFwcbBcKpvuRobxu80VktBFcg2SSzOoJwfUaZ6tCNlXC7VL84cJNVjqs
         JxyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="L/shRT1p";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YeYWD3jkZVf4aC9tS+arBkqUCu+JIKiLQm1gzzFxces=;
        b=nexENBzauZxj+aHkDwbszbmecqxWi5rh3wnhEp3LrtY33iM2XGRYCb1RBpC3ixkOff
         1caJvGDm+/fjh1knTnaLp9TJPR1+UiGdVY4T+qgPDP353vw1W/Eb6duIFfYo51NVSsnt
         3mAxe4LqOk5uUK1yUNIpEAv0fbs61jezCa1bpEN4VMjddQQeCO3bwsg/ObpurbAeGLFR
         zPNO7yzeZeZmTWh/KIujbaKuKjbBA8aMrmzzZ2ags1znNCm0j4vU4E+tVLiVzu9C+gxq
         078suIxOiazJVkX3SAfYE9j/6+7akRTnoWAuTJox0ogTcFgH42/V99broUWdwGJQiznk
         6l6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YeYWD3jkZVf4aC9tS+arBkqUCu+JIKiLQm1gzzFxces=;
        b=Xer+d6qgyF1dAyuPjIUFoplqp49xc3FOGhAYgqdWRkdzvvirAEQPYqngCEvWuwR98J
         PkIdnG0frkmkurUhJPa4DMsUtCJPgqJqkFgz/9SfEjiVYXWVXv6ZyL3fSBngfTdec+sX
         bKgNKYqtN+5ARPAC+T5qXSuZR/wZFUEfc+VaBWuJQup4snLO5ZBPnKYRP7pHpV3LsJmB
         D76uKEO4MkrCS/KGHXoAhSPxBHdBoRgBYBknmtBh9N+6AKxYsTUTBo4JCtbtpqz1J+Ec
         m1D2tQocWBAM1pLIoXKQUhHvgBYCFHVVU+qqDWfCEyQvXPebEevPxZ8cpQ5IjMlG9X00
         qyhQ==
X-Gm-Message-State: AOAM533rlVGCp4SBdQzWoIzc62sTJuBxRyQB9unmj4O0VhW/x9wYJR6T
	InCvvCDYG86ck0D6PLUFs58=
X-Google-Smtp-Source: ABdhPJyEc9IOh0sUOYUXlTfZCco30AEjLHfe86XvBEtTIoX2Wwfx3hI7/Z49/hFhrZ4UAjliJJ6Q1A==
X-Received: by 2002:adf:ef4f:: with SMTP id c15mr11024741wrp.390.1601575167269;
        Thu, 01 Oct 2020 10:59:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls2011337wrq.0.gmail; Thu, 01 Oct
 2020 10:59:26 -0700 (PDT)
X-Received: by 2002:a5d:6404:: with SMTP id z4mr10903562wru.423.1601575166342;
        Thu, 01 Oct 2020 10:59:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575166; cv=none;
        d=google.com; s=arc-20160816;
        b=BwJxwkK6WqBjwEHDqFpON1X6+cGrYbJefG3LWW9rnoFiTSXWLEPaC/TmOZiEB2wvOq
         ysrbmtyA3FloC/O7NvHye4wsHUxrp1/AHNBUxgmzRIePAwpltH3iChvDsIkFfzlFnWTV
         IKevEskTqzQ1S5RC4VAJsZojI+IfZ8BVo/Fb7gRcdxGovgJITlocifWny4hvffFDNzHX
         6ks+DwRmAqmru4nLPV+M0K5J9K4VDXBskWlXQNYEN8eLBt8Rnd6I/pvIwMTylq30qGPH
         e0UKhtTt4spbYl6t3TdfyI5TgVlAkojZQAecFJHrmFIjq2sdCOzzNuPSdyHvZcN/NmTF
         utSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=TLkPGKpJtl4arwZwTjWF8S+it5AeziayXNp4OPYQ4v0=;
        b=Dr9DeHDmqmBW6HysuVdFyPozepsoTwUJeYFrnGdbWDf0KdQGCKQm7/FrWsL/Iln7qo
         d1nHLysEVjaRbDdnNHTc2PRyJhCwfj0jWCcem9vxzq1EyGueC+1AxDLIHr0hyL7L7LEY
         DYSEfYttb6A7EzqtT+WmsTTupdrwgrcQP3T6LNjq+PiFGh3mOgwA4CIJoFGdGvw15Jwr
         1H4hAGPgkjFY/fiV0lBTgT+p78gg11de4rlTa1u41/sOtCl9wbL90JHrXyNay1Ny6wC8
         qcdklJCueLcEiipXW/Kqx+X4Tob/uZ2nU1bfYax4DsJu4b87zCYjdMRCCL5Byt3pRZbK
         FUaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="L/shRT1p";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y84si25996wmc.0.2020.10.01.10.59.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:59:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id j136so2792202wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:59:26 -0700 (PDT)
X-Received: by 2002:a7b:cf30:: with SMTP id m16mr1235811wmg.0.1601575165850;
        Thu, 01 Oct 2020 10:59:25 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id d23sm965442wmb.6.2020.10.01.10.59.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:59:24 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:59:19 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 33/39] kasan, x86, s390: update undef CONFIG_KASAN
Message-ID: <20201001175919.GT4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <78ebf3bed0458172fec9e1e32f2d29d7c8c37341.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78ebf3bed0458172fec9e1e32f2d29d7c8c37341.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="L/shRT1p";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> With the intoduction of hardware tag-based KASAN some kernel checks of
> this kind:
> 
>   ifdef CONFIG_KASAN
> 
> will be updated to:
> 
>   if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> 
> x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
> that isn't linked with KASAN runtime and shouldn't have any KASAN
> annotations.
> 
> Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
> ---
>  arch/s390/boot/string.c         | 1 +
>  arch/x86/boot/compressed/misc.h | 1 +
>  2 files changed, 2 insertions(+)
> 
> diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> index b11e8108773a..faccb33b462c 100644
> --- a/arch/s390/boot/string.c
> +++ b/arch/s390/boot/string.c
> @@ -3,6 +3,7 @@
>  #include <linux/kernel.h>
>  #include <linux/errno.h>
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>  #include "../lib/string.c"
>  
>  int strncmp(const char *cs, const char *ct, size_t count)
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
> index 726e264410ff..2ac973983a8e 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -12,6 +12,7 @@
>  #undef CONFIG_PARAVIRT_XXL
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>  
>  /* cpu_feature_enabled() cannot be used this early */
>  #define USE_EARLY_PGTABLE_L5
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175919.GT4162920%40elver.google.com.

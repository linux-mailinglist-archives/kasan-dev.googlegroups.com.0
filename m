Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXVCSL5QKGQEOSOIKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id AE0FE26FAF7
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 12:52:14 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id p3sf1931008ljc.7
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 03:52:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600426334; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqmk5a47n0Fkn5NMijC2oo6HQok5QZuEWLuzT8RQFSU5Gq2tFR+hXGcPjFoSxyBY7+
         f/GTE6GmaOQhHjauab+m8jHUotW0/Wr3MkxNGb33xxuardqO0852gUjmZAAKjZlZ527c
         IqSH03E62aFxLf/4Fv6S/VcQyUOtw2yTZjFY8KAApMr9+TTuiNoyuI3VY7pVlKeuZiLf
         Y9cVij1tuH6G/EwCpTxq96CdC0v85geu+E5uvwx8m1lDSNyR/u6oNejo+u76Mj0z9JP5
         Pv2stv7i49fc0URLizNtwMoUBLT8L7Fbd7D3+KFpKUPJbtGo5y+u7ePnopnYT9HA8pRT
         Iwvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Q8ePC7F5t1jnWlyZiWth14xmGgafB1gxhV+fibuafXY=;
        b=dBB2UWDjFO1ijN6fhOlFE4FCK31vcRtkWe7Vb6XasTW9BgWw/7yghYl+Z2hIlBkqeF
         eAs51zGuIRjBC8i7CnVQMR9LM1zUHwJIf1veWN0rEkhtI7W9jJe0TmsNnFOvX/a4gwdK
         KbkziHSl38l/SsyGhduVqKZQQ1/Qqgs4oVd4wLUfS4a/rhPUn5ZCT66kUqIEIgsGxTz3
         auPP3m1SaDGGBiJqASEWPTJksFafn+hj/ZZVccVERmcD1WYno0JRZEKx5X7BiExny3/R
         Fp+eEdc0VozX18ANKt6h+g4F6MO4jtPl4eLbAzAy99vbWltXHFISZdVC8eA5Bxsa12vT
         zHqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sw1eIJfE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Q8ePC7F5t1jnWlyZiWth14xmGgafB1gxhV+fibuafXY=;
        b=FpyGeTCxYxHrPkGL6QepVVpfyq5XQErxcACRsJk2Spb/Ml3+r93W5PDDGFjD7kxFRc
         d8OroX0k27J6n6ZtaD08y9bxx5B6/2REvBQElqDCyxjaLl2epucun5pSC6sI4WFmO7nG
         b79qmz4OwTgJOUZSYzWWRYvfFJvsMY+GK6vCTBoqdhwBdHd66igkLMdbskRWmBEpdIhd
         uVMjyB6YIJNIEfRGCGqm+B8X4l2XVPJauvtLQXatC5+nFVQyfUw8IxDV48APCZeuAoYB
         qlppv7gA02aPjx4oN4QK1RjDSA+NnVEHTVtFtSqJ71dWovavzBFYx9xTUJ4Qbpm+/uum
         SRuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q8ePC7F5t1jnWlyZiWth14xmGgafB1gxhV+fibuafXY=;
        b=U2Wa+JdeXISjIO2wD4JHNpqlpevNOsc3vujD6JzQL5yTLy6VLiznq+b0SpKPDJoSYI
         GudWHoI61NHSxUh+T4qxRofV5wbpJ68cAO+cE6WueIi7bdRLF3TPuFxyzggHoFenwpcz
         eaSHsV9P0WNzEjzVwXNGBiqu9Wj1wm5SFKn4DbNDH06hkxKmk6Smnc9D4YBpkcPtnAjt
         wNgWvB7ZQStmZA+WznvTMmuxY0ICOKMK3LUqYXuM8b7mq+P7si3+r1sNXejgt7KUIAMB
         8tQI95bkuj52rSZ1LnZjNzBNqR6/NygsokshYXKfq4a+p6e7yX5/3AX2cnRoimOG4iBl
         8PNw==
X-Gm-Message-State: AOAM532bzt+B5kk1YtaWizhG8rSx1LlAe5jRY01Bs8acCUs/AkjsXOiQ
	ivS2lim5kcE+zRCiiGd95vY=
X-Google-Smtp-Source: ABdhPJzRWAEQIeFhyIdlc9aAP+ZaWsZmCfZ7Sf0fR54sXcbd2p+BUaEmzs02vQtnynutosflefqZVQ==
X-Received: by 2002:a19:610a:: with SMTP id v10mr11583017lfb.414.1600426334252;
        Fri, 18 Sep 2020 03:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:555:: with SMTP id q21ls764422ljp.3.gmail; Fri, 18
 Sep 2020 03:52:13 -0700 (PDT)
X-Received: by 2002:a2e:a587:: with SMTP id m7mr11769935ljp.133.1600426333116;
        Fri, 18 Sep 2020 03:52:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600426333; cv=none;
        d=google.com; s=arc-20160816;
        b=Fac0GmpN1vcx8SoQ6n0iJajw7lVeYnGkvZIEwapoA0MBkBA7KqIqEV4rtIpAfBdrex
         2PpCGVbihsfbiR9oW3U/RBHIxKNRzy9+7JnJIBtG1CTL1xQrYOqqC5nKAG9ZO6PYBklb
         n8Yyvj5pNi8NS3bRaOBxSfL6tAFsd6hSAMHmc5H5ZWQR4lPX/8nTr6zRsVYzX6bP7OyY
         gD6cHmu1RhzslkxPCZ0vaaDyG0esxEE8KRj6A2AslbyjkOQ/oHCHiFpVd4W3OfXSkxKS
         E5MgIfRKbrHmOkRgQjAkwJDS4d4RmQk8c9tsleQzCrLW0CenFz+3LJg3kr2288wCuQP1
         gbsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QRQC3uLJVX16XzkVHd3z/hv57pExgyhDAmcqkPNt84U=;
        b=IVySDqqJZlrgBk0ayDccZczAwzw4wctY5kgG+Oqqv5PL11+isiOROLoSzOwK7XnJ3K
         v4QktFXqUO8qXFURyAxTslPjT3+osMVSUtF6h+O710rD3ekejA2zDuGx0nmScep1+oQS
         lfU86TFoOKr+qhsT5GNVCknOkIKhbmbQ5CdcT7OqmRbDSv98UlTkKuF0rD5M8+r0qtlW
         rhrCciQt0hig5EL5KXa+QDTCF9IUEQiKO5ENfEvAGhqtbMmSMa8GrXN437xjwspgzFDt
         xB6AYUmAE+4mb/2b1PFCndZRoGL6vT5kmKlofgxtN/5+1zZiIZBpBIscKhLFbfIh4PR1
         cqGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sw1eIJfE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 21si50787ljq.5.2020.09.18.03.52.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 03:52:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id x14so5127631wrl.12
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 03:52:13 -0700 (PDT)
X-Received: by 2002:adf:b306:: with SMTP id j6mr35571156wrd.279.1600426332508;
        Fri, 18 Sep 2020 03:52:12 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id a10sm4228229wmj.38.2020.09.18.03.52.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 03:52:11 -0700 (PDT)
Date: Fri, 18 Sep 2020 12:52:06 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
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
Subject: Re: [PATCH v2 31/37] kasan, x86, s390: update undef CONFIG_KASAN
Message-ID: <20200918105206.GB2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Sw1eIJfE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
[...]
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

Is CONFIG_KASAN still used to guard instrumented versions of functions?

It looks like #undef CONFIG_KASAN is no longer needed -- at least
<linux/string.h> no longer mentions it.

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

Similar here; although it seems a little harder to check if CONFIG_KASAN
is still needed. (Maybe could check the preprocessed output diffs?)

>  
>  /* cpu_feature_enabled() cannot be used this early */
>  #define USE_EARLY_PGTABLE_L5
> -- 
> 2.28.0.618.gf4bc123cb7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918105206.GB2384246%40elver.google.com.

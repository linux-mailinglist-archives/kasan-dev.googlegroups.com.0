Return-Path: <kasan-dev+bncBDW2JDUY5AORB5N326DAMGQE4NUH3PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id D5D7D3B44B3
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 15:45:25 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id w13-20020a170906384db02903d9ad6b26d8sf3147754ejc.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 06:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624628725; cv=pass;
        d=google.com; s=arc-20160816;
        b=y9SVg8rR+AeXDpFPBQhck6YPjXjKkA3C1h0X2hUcN6OP4nTiURars02NKNlM9lJZT3
         SeNsebVLIwkrdDl4jUUZ3PMM9d6UOxq+ifE1S07uFnhWDk+4/WGcALAGbgTNwt/Mwh7U
         ovX1m4F0y+esmc2Hc6k/wpBi/Fw+WZ0WQzitFNK2Z5VpTxDNbcNenmATZ96bnf4vhRnR
         0MD1Hi/kNnaqujJ4NXR7bQyedtEuje/SpFaS1IAbySdZsCRtpgOuBGm4tFuPjw8ylI0x
         +lrdlrYAS47FcAEthHXo/Az6XTG97AgIxE++Qpw/S/jffX2P4XtyBWnG46BFai3v/ypc
         4ltw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+3pWeAzPD/AQxVi5ewYo8EQNETO2Kw+OBRER8sAkpQI=;
        b=LouLdE1SKFKVXHxkiqlK2lqQ8Elwy3TEnMoTzaZTBUw7TIaXgmWVoW+zgDixi+8iIv
         5T/BgMtxhDWkr6QcLljdehD7GDVe8oEu3pZv32FZsd8fbVvCsRoTYPVrzVXPXNMIYTNJ
         t504PLxmUWImJfuN1cctJBcVims/eeqKHzfQf52uXSzx2t88rFxdehV+8SKCysLrjAJu
         UFLJviQYX/0s3gxWaPVkybrcjgLZILPz1vYPfLvLIv8zD7ocFiDnreDmcSTcC7Nqbn4+
         pX215FZP5QuZiFr8fnDmnToye8z199P4edZIQsfGck2Xm/cfvVTmueObgR2Oi/oKIgBR
         y26w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kiJfd8p4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+3pWeAzPD/AQxVi5ewYo8EQNETO2Kw+OBRER8sAkpQI=;
        b=rCyQPICi7bbolCAVO4OYmqVL8lYf51cJ5pzG1PcWO7VCU5n+qhCekVQHSYVZoJc6ZH
         uiRvQwe5b7YsEhebPEDy46JzzDeSVCw1bBDeEus8iPKggdheqyD1go0Ly2p1+vs87Erh
         O4E2RsZEVS+q0DJxm5wcuonOdws+/+JoNmlw1GmQyCa/17EaczzhTx8cBW8n4aYZhoBK
         /NlXxEBrX83eI9LQxfovnIakBUCyze54rpdUU1J1FaMxswmca72lO9jywW3ueC0gcpOo
         rQyeV2GSh/i0ttuJWQi/hRjzjCLqXMod8YSVxyreLfqQ7B7FMcvGfnnbCdISCOU//DWX
         Cotw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+3pWeAzPD/AQxVi5ewYo8EQNETO2Kw+OBRER8sAkpQI=;
        b=Msd+XgAMKgtRYITPr7v0447jMLNPT9+hK/rR0m8GPGfEYJR4KAdrGox0GsgLcpMnq4
         Rerq0MKqmxT+TEZPPBGx/gBkhefgy0dcVaupD7LV8bmR7B1/IVl7SlmqF68oKhhjYpgT
         PdM82FNTWrAXKKxRXjP20Ro6XFXOn/xn2swRX6ER631aHaQUsLlWaF1EOFuUJ80RA386
         B1aI+tfPmx4X6jauqtvnGggiU1BUShsSTFEdVWCxq+f3Sz6yyXqc7FFhnhXwMtPhNssX
         FwLvrrbOuneDr55WRZArbVlmJaMADrdP+cHktyv6WLUcumDWa2VcseQNX0FGL+GZ1+cp
         ltoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+3pWeAzPD/AQxVi5ewYo8EQNETO2Kw+OBRER8sAkpQI=;
        b=AORMAkA73NhAts9p8+vMyiBTRCuVfitOJS8LFjRdn/NzYPzjWXGqc8UE0CptqIrNnS
         qR3TnWWkno/Kay5Yjd0PuPOCx7J1tysvbjIV9ckMg304rGhaSILziBCGq0gQmyfihmmU
         4ImTwIzbcAgyIsENGGfsJLxbiw6eAVI5ijczff4qint6fJdIbmjJB5Ljw6ewx4AdWye3
         yAJRIOegkBSOXXnOqvGsPqs6qhZHZUuBut3ycNVV6NwyniXuErJox+bV0KhRUC/QrP0w
         7SgxZpb/DFikcouqSF+apmPMvtcTa4MQ0ruoPRCzrZZ1Jo09WOk2yVhC7FpSmTXC/yWp
         f7ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EATE5omRcJatLArxCjjZl6evBI2ZOan79fQ1c6s0FUtZ6oDNg
	1mK7ZqeFOrSpat10Ils5pAY=
X-Google-Smtp-Source: ABdhPJwlz0PopdBNeojCSetVl4oyBILsOUWWBAtftePTCNHzOWeyB/948P/sd64MqG4PacR2l13Q6w==
X-Received: by 2002:a50:b2c5:: with SMTP id p63mr14579564edd.5.1624628725660;
        Fri, 25 Jun 2021 06:45:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:365a:: with SMTP id r26ls3797012ejb.3.gmail; Fri, 25
 Jun 2021 06:45:24 -0700 (PDT)
X-Received: by 2002:a17:907:6e9:: with SMTP id yh9mr11222046ejb.86.1624628724785;
        Fri, 25 Jun 2021 06:45:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624628724; cv=none;
        d=google.com; s=arc-20160816;
        b=S+aP5peTeoDoqHpJmtkgucoWAC6FpwGlVOCXClW8srBySKWZ1YyKirA9nJEpJRZPxT
         R/UPEs2Rw4iX+7G5Ait3ZoW2a1m/h5yLvSkyCPBi+g7OKEObrI3u2FPN9LXVV0QayL/8
         6O6OCL+5pSMacpMPs3UXk5qHaMYHcZCrKVG5IhCujKMCjLT6g6KtaEWtplMHgJ2bGzG+
         YXFQAJBcN18Zi2f3vxMbDVLSqShJEVg0pgaiL2CUM7o0z0Qk27TzyNnUjs31KrRCVBVU
         y7/SlxDvquzkKYCsJCKEYcVerl7trccBh8vatgXO/w6HAXchNia2MjeNwKruKdb1ZU0Y
         mdig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iL+ONoFlGB91h/2MUDT1aNEjicjs7hNRvFGJskZUmDk=;
        b=XgQ00oClUwtAyCfi3m/qRf6lqGtgBdT5EOW/QYDDZAIs8PbCvpY5cvPzUaripWVc9J
         3ryTeS7xQEkYCFJGpEsh3rotPla0HpBEjzGyAE37GAx1u81NRUSTYNoPqmD5ZVLQ6+xH
         hCAUyhZyr0hm+87tposciUWxSKWffmAdZslb/qBK6E1FR4BqeeUxHH2znrt0JHZG+eEk
         2RVKgt5DRVKWdRdHY9IzfAQbWqnEVSkKOujODUXm2Yb7iCN4ZjHI7fSdv+bAU/2OqPJV
         97PuEZQdN4LeJxFPSKfwEMBkb4Hhr3iF4t22FyToPwYJs5Gi4AmH0QAqoCTVA6qzCcu7
         4pFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kiJfd8p4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id c16si140685edj.3.2021.06.25.06.45.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jun 2021 06:45:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id q14so13471290eds.5
        for <kasan-dev@googlegroups.com>; Fri, 25 Jun 2021 06:45:24 -0700 (PDT)
X-Received: by 2002:a05:6402:4408:: with SMTP id y8mr14915135eda.55.1624628724627;
 Fri, 25 Jun 2021 06:45:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210624034050.511391-1-dja@axtens.net> <20210624034050.511391-2-dja@axtens.net>
In-Reply-To: <20210624034050.511391-2-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 25 Jun 2021 16:45:02 +0300
Message-ID: <CA+fCnZeLFoqm6_bxVgwG3teP6688rvQ1vBJyor1dCfj6F7kLUQ@mail.gmail.com>
Subject: Re: [PATCH v16 1/4] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kiJfd8p4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 24, 2021 at 6:41 AM Daniel Axtens <dja@axtens.net> wrote:
>
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.*
>
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
>
> * on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
> real mode. However, before we turn on virtual memory, we parse the device
> tree to determine which platform and MMU we're running under. That calls
> generic DT code, which is instrumented. Inline instrumentation in DT would
> unconditionally attempt to touch the shadow region, which we won't have
> set up yet, and would crash. We can make outline mode wait for the arch to
> be ready, but we can't change what the compiler inserts for inline mode.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/Kconfig.kasan | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..c3b228828a80 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,13 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
> +config ARCH_DISABLE_KASAN_INLINE
> +       bool
> +       help
> +         An architecture might not support inline instrumentation.
> +         When this option is selected, inline and stack instrumentation are
> +         disabled.
> +
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=kernel-address)
>
> @@ -130,6 +137,7 @@ config KASAN_OUTLINE
>
>  config KASAN_INLINE
>         bool "Inline instrumentation"
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         help
>           Compiler directly inserts code checking shadow memory before
>           memory accesses. This is faster than outline (in some workloads
> @@ -141,6 +149,7 @@ endchoice
>  config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
> @@ -154,6 +163,9 @@ config KASAN_STACK
>           but clang users can still enable it for builds without
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
> +         If the architecture disables inline instrumentation, stack
> +         instrumentation is also disabled as it adds inline-style
> +         instrumentation that is run unconditionally.
>
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> --
> 2.30.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks, Daniel!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeLFoqm6_bxVgwG3teP6688rvQ1vBJyor1dCfj6F7kLUQ%40mail.gmail.com.

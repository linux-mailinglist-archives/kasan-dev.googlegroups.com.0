Return-Path: <kasan-dev+bncBDDL3KWR4EBRBREWW75QKGQE7PUMVJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E01C9278562
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 12:49:41 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id k9sf1876655pgq.19
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 03:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601030980; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hw+f1x/MMOhIgYq+K0cN+Ofk+F9oJ0XSWWrKvbV2ZprcV55lJUz+rrs1O9jooqFg8i
         RZGj1ENUWMWfcO0t9vOy4xdp540CkZKjIAKxg1Ybck6bnm18GY1hrQjXDCTnN6QRoAjF
         M5yqy1gM2z3Hc7Q7BnXDnNe1euBpaN3mKn7nVxztKpmTCbAM8ZH9mpFd4W7okRkHaV7m
         /DWM7qAfYSereXqCoDnaOG98k37/WWnIyPdEeaSQmeGoPRHWdVjdHECtLjIYgU0/CJXB
         YocciAwJVrt9dhDMzVb/du8ZaVS+R/+7a7f+xlGHG8mn+vhfhEYdFXOUY2rOwiOK0V+K
         3fkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lE2BQr7CTjoB6jC89ymx3Lk8rWQH+AocUHA1Tccym5E=;
        b=RJ+2AjV9s7GziGrNKos5fS+45OX1UyvBxkFJJUeuNwMx3TYs1br57zOSPN4/1j+Lyh
         mw+Y7W3EcnMo0/nFCI3rc5otNerO2CV6ceQms3GxxgQFrg9mig6z3DrqrYe6X749Ubx3
         6HbNaLYJ9RaDayZrUg4OjHWe3ZlpTRHwK8339u9Lb+oWNy3ygE57ZcOtiqWTeLK+nYRd
         ITvzaeWlycg8Y99Hd/WndNuPLEvLiJ8JuwWsKjV1eGNmCPLW8/Gz4zY2J8isSRw/eICy
         3W39x7n8hlgHpJ0LpkL+v3o9kolCeWYQbhtk+iN1RHoAVQpvtybq2bjCjGE3DEAgZCYk
         YE2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lE2BQr7CTjoB6jC89ymx3Lk8rWQH+AocUHA1Tccym5E=;
        b=TkrHRa596Aqe/9JeX0pEpfI5YOx96x+0SV1ZaD85NzOW17D+uVOF/G1kq5ep/md1ID
         33LV8Dn8GUWCuJhKb/MQTNZor07LkdjTSNZvUuBksUt6gJM7+miaAxZbFmxLcbQgyFIt
         SK6gbkID5c/nDRLcTT56qsgM04SiFxXOAEok7XCkBtdR7MNpAyjMwEkLxH+RaQiSZFhl
         enkIPnsvV/uDtfKnKn5c3/NONfv81WHP24EZXrwDjJkq2UKpKgPoGbmgevQVAXpVtPkf
         fvabHJRJb53CyOmUGyBcdYSDCZMS8FE9u4u5ayJmMKdSy8SzBx6zFW5SqDO1/AJVQFbP
         EcGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lE2BQr7CTjoB6jC89ymx3Lk8rWQH+AocUHA1Tccym5E=;
        b=I8SbdmLcldhGntmdH5UKAqYlwXq3DSppIIcsCRnyP3TJ/HOBWB6khReM/FyIbgrs/8
         vZ6aXBq5g8mnPmnRh1UTCr4/5VJLMjvM5VD9tuJzM6v+WuM6dN1EpKiS65LunhK53xGf
         gXXHhW6tBlXWBI3DtmqQrfoD465TXXdWyM7Mie/uJ8ND3S8KnP2BWtPzoVWJvNNNWM3Q
         T8vcTiAn9KLfyUc5BHl7sxbUNsppNlGaCwrAb5e4b+TSUhpbnJCXnk9m7ga608j/Jyoz
         EmqXNult1FJxsaaQnpjGymVs5sHbo8qdKZWM/Q9YZCyR1ui/nZ3q7BV7iD9la4z7gyXH
         XJfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Dp2yivEjrKRBk9Bm3SsuFae9xCr0Ww5/F+p5WGt/YccB1Mges
	nhpqklUMQMPymaHgdOvJYsY=
X-Google-Smtp-Source: ABdhPJzcy0xQm/ExE6wDHviYmQFkzTxiffySI77jzijkRnk1skIrLg6N6ZFTPOdCOMD0K39jI9TBPg==
X-Received: by 2002:a17:902:ee83:b029:d0:cb2d:f271 with SMTP id a3-20020a170902ee83b02900d0cb2df271mr3884877pld.10.1601030980230;
        Fri, 25 Sep 2020 03:49:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:551b:: with SMTP id j27ls940756pgb.2.gmail; Fri, 25 Sep
 2020 03:49:39 -0700 (PDT)
X-Received: by 2002:a63:4a0e:: with SMTP id x14mr3077636pga.222.1601030979492;
        Fri, 25 Sep 2020 03:49:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601030979; cv=none;
        d=google.com; s=arc-20160816;
        b=uy5tM0XueSyl9QtScOUli+XUZk4Dt5BqtNDvoratzqRSezZcD5angCrorHxhr+ykFh
         c2n6eJIxQ4H2MVcTiul4GxZC11OIxTM4R5U+tdGVtvHRhL7hZGpyneVr7JZpyKy5V/hW
         w/XnDRqoQCedaKlzG+yKEUI64xTzWOw/XCy42Q2b0bsCpGFTfnNBEJ1NIhHBUwCrmDYc
         SwsPIOurY/3l7OEDrBeiLgTeYJEsIZs65ZmXyHJD8U2TJqw6l94/UCaaVng/KkOvMlYP
         6gXBexJcrU/TXKpLZNI/AtL7uPOZJprlMm4rsC4A+E6yBd+Z52yi9JEsSFPUn1v010Tt
         TS0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=RwMEWS9MKtNcuU+UKA+HKgpNEtdB/Wj3LQo+DhzT2po=;
        b=GNcTLBsjq/6LkUz32joJHgfyxOgJnk4x9CTD2RxNcyoHdYpBAcR3XV+8PhsyMHHGXP
         uuhRM6f7SS4hHGgFH1Eyi/y/pyQ4uyDiAmVt4KEg6vVhLDoIxya3/l++Xa5l3azR2yPp
         3WIoJpvVHnvZp3IrWNlqjkdzML2tzQeUYZbnN+n8NdryYeyjzd9NUkUpCGjqSx6cNygZ
         uklRwISOdpFSmgs52hffbX42MV8boSFSukfBrspyO1vH7GfDFTPgiuTrNP/G/Sx47sal
         TF+CmbFDiA0uxCkCOWA+UTTv5e5IUHJql7iX2aoOWFESX/LhjqxlPTbKltKJyGpmOiO4
         Mt/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y1si131526pjv.0.2020.09.25.03.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 03:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5020421D91;
	Fri, 25 Sep 2020 10:49:36 +0000 (UTC)
Date: Fri, 25 Sep 2020 11:49:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200925104933.GD4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:50:33AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 991dd5f031e4..c7fff8daf2a7 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -200,13 +200,36 @@ do {									\
>  				CONFIG_ARM64_PAN));			\
>  } while (0)
>  
> +/*
> + * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
> + * affects EL0 and TCF affects EL1 irrespective of which TTBR is
> + * used.
> + * The kernel accesses TTBR0 usually with LDTR/STTR instructions
> + * when UAO is available, so these would act as EL0 accesses using
> + * TCF0.
> + * However futex.h code uses exclusives which would be executed as
> + * EL1, this can potentially cause a tag check fault even if the
> + * user disables TCF0.
> + *
> + * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
> + * and reset it in uaccess_disable().
> + *
> + * The Tag check override (TCO) bit disables temporarily the tag checking
> + * preventing the issue.
> + */
>  static inline void uaccess_disable(void)
>  {
> +	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
> +				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
> +
>  	__uaccess_disable(ARM64_HAS_PAN);
>  }
>  
>  static inline void uaccess_enable(void)
>  {
> +	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
> +				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
> +
>  	__uaccess_enable(ARM64_HAS_PAN);
>  }

This look fine.

> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index a3bd189602df..d110f382dacf 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -33,6 +33,7 @@
>  #include <asm/debug-monitors.h>
>  #include <asm/esr.h>
>  #include <asm/kprobes.h>
> +#include <asm/mte.h>
>  #include <asm/processor.h>
>  #include <asm/sysreg.h>
>  #include <asm/system_misc.h>
> @@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>  	do_exit(SIGKILL);
>  }
>  
> +static void report_tag_fault(unsigned long addr, unsigned int esr,
> +			     struct pt_regs *regs)
> +{
> +}

Do we need to introduce report_tag_fault() in this patch? It's fine but
add a note in the commit log that it will be populated in a subsequent
patch.

> +
>  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>  			      struct pt_regs *regs)
>  {
> @@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
>  	return 0;
>  }
>  
> +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> +			   struct pt_regs *regs)
> +{
> +	static bool reported = false;
> +
> +	if (!READ_ONCE(reported)) {
> +		report_tag_fault(addr, esr, regs);
> +		WRITE_ONCE(reported, true);
> +	}

I don't mind the READ_ONCE/WRITE_ONCE here but not sure what they help
with.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925104933.GD4846%40gaia.

Return-Path: <kasan-dev+bncBDDL3KWR4EBRB25BVOAAMGQEP2R2XII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id C44DA3003FD
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 14:19:40 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id 98sf3067423pla.12
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 05:19:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611321579; cv=pass;
        d=google.com; s=arc-20160816;
        b=MEi86GCNlNob+apeURgXmASakZiYgYfzE6gE3LBajbpnHsm8mRKUGUihloI7oqLioD
         XH4qpeooXhGCi1kMbIzw4/QdlY+s616kddCj0KDqDGOxrEF+ykBXMxP6BuPN93biloMB
         14GyP5lZW+uzc4FJLpJypxy8lqXxdo901eU7KUAf8tlRbgnf6qIMWDTRgswHIFimhutV
         OhcEoV+c1mK1fcQVxlZvVnxLcrU5CNgTZyNy+esUO2sUk4AdyOiOGc8/t7ud54BbW6ly
         jquAdvBEryR6kgWjktx97tuT9VsSOxJnaDfiJxZxY3WEo9La85jlOoz4ghdnqVytGZZO
         Qxsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=n2UL9gySajpRC8GEPVeSOe7nOtfySJkILRffeEsCVfo=;
        b=qcured5rHi9JapYLDubpOYkw5tJqG1mqVcaQxgjX/Oz9r8LMns57ZdF/HePmrNxJXU
         SV6wHVDd8L8EiV+JD2o3Evzw1YhyrRhA5MN5nZxhLwyENfmWEUhHS/SviYKDPDOoQveL
         vijBiCjUiBbrnaYobfjptORZeul9frK8YpNFArJBFztZ5SQFjia6GSDwSZCObmHQUsFW
         e4p8oH1Hr1d91bwAsaAO8AWU+7dyiXbU3mJAQtY7ECJx4L4ibNvU81Om9+rF2mnYR995
         L3XrD1DpA7fqVIVzRr0fxrScO7lPAAKuAYha+a9O1eBQ81DTmlUviL/bpL2hZix2B2x1
         g/Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n2UL9gySajpRC8GEPVeSOe7nOtfySJkILRffeEsCVfo=;
        b=QMpt1guOafxtS5qElJ8NBY8J3BgKAMJCWhn/Dh9aLl2vM9V7xg+094Bnow51uMH7vT
         5o8LJjiknkfx/HB0xwdzNYSk+GP3uXv1LVdEs0h0VhwhGYYWS6gwfkJkXy9m6kDxAj7L
         ynl5Qg4oMJJAK7Dn+6qJ11Akfocpiwlp63r/EVI5416UoHkn4K4bBDQLu4IwR57bEMc8
         btp1JZ/jiIXdp3JiqT5lc2U9y9qNfQeJKxPrjMnn9t8EzwFqZf5Ganqz8qmL4pkWu9k3
         riqOAfDJqwVhUObn3NRXgMF8xMb4OnDe6hW0cLM8Nz1kkVqKhoovMGQ1+5SAy0puAtpD
         h7zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=n2UL9gySajpRC8GEPVeSOe7nOtfySJkILRffeEsCVfo=;
        b=Cl9qyC/BJXjnDpb+OwsliXSHh6HhA0ZItcqWjPXeBz3F+c8uVSKKYovPdSz4mJRFVn
         +ZWyyRSsSNHUBHdDJWAoucZiPVx7g58E3+4BxEIV2vMnv4y4y9JE/zhPhMFfM8j6SQxf
         KiiixYRPMR6RRMxigJQeyKDnJdM2qn7WjY3stsSRq294B+HaoetV/b1IO5xNzcIskipn
         KtSACaAqQKbO7HajqG9TdiCg4aVmrq0QPFOz5zCdaRjs6atDebPHjBvp3sKXFdQazI6B
         d8EHVzTZxL1NRfltSn61Gdb5heO3F+Fc3uOPWdgp7BI4Cemo0zxeLQprcb/URJaRtSN8
         FW2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DjvX7gB5Ea0ZHmH18tsnJSauEWTsjJep++usqZzT3L/ruG4zt
	w/DB5xCn+kUND+qUkoMKM4I=
X-Google-Smtp-Source: ABdhPJyYk0+uMi5KYhYSsugJrREIr9RpsJ6mAYd3NDT2rcRju64sQNuv18xHkFJrwRkJibp62us9bQ==
X-Received: by 2002:a65:488d:: with SMTP id n13mr4421840pgs.315.1611321579569;
        Fri, 22 Jan 2021 05:19:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d2:: with SMTP id y18ls2730097plg.6.gmail; Fri, 22
 Jan 2021 05:19:39 -0800 (PST)
X-Received: by 2002:a17:902:b717:b029:dc:3e69:6dd5 with SMTP id d23-20020a170902b717b02900dc3e696dd5mr4582580pls.70.1611321578901;
        Fri, 22 Jan 2021 05:19:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611321578; cv=none;
        d=google.com; s=arc-20160816;
        b=lkzqcZ26A4a7PguRFvq/BQo6tR8q2JIfA9etDaGvZpf9Y5SUx6eVeprO5DRxUVhZCr
         Ni4NPKkMvvW9Nu2pWJi+Ni7o+p1UMP6VZX1KlAOc/VTAfQ4GOKUAAdLkZNS88u4zBVnF
         2KGSs9hVkUInu4hceokWRRN5fuwe5ec3/eKI6oorL0LmN7kDCmyf97twMxHH1BZrU8yt
         0x+1iaE/Rsy82BY/LnGhtD4Ia0uIqykjZ+S0edEmn7FkGPui0pnvgN/ttDnSZJRprsyc
         qvKYLxJDFcK15FjIzgrbriCUsImpi0Tul5JdskpPGsVugv+EShh2f024Nos8I6aZa+2l
         l6TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IXN1F71GlF++ClXIAv9ATmsQoJ8BiddfgTlYnkHCKMI=;
        b=QEUHXSmnA+wETY2Jnkl0zZUI+nKa9szDGAMNDeOUsUmsujwmxucZXC5wV7aiHQbh6f
         IPAy2JFJaYZ4xDBSIQfGsFS09EQLSIt05sQMVkHG9OLbOKpMFRBCKoyrDkSav/GFqcJJ
         /+bXJMx8mA6WAMjosr2lXh/vYQbkmFhAa+/8Dr8cLxHVtmMx0tJtrX+aoFK9platuJ3D
         v5qH4zW3BmlTiW34DEeVNkTjJtQ4pTcVOIQ28AYa3S0TQ3eVOmNQBGyHpC7kRQ3Rq+VW
         HcNkMAqSfUjrQRbpFX42r0sFCLUjtNbncaCSzVUUWCtZkEES2fIwdCevVMzRFwKWcZQ6
         LLHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b189si536695pfg.5.2021.01.22.05.19.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jan 2021 05:19:38 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BC1AB23428;
	Fri, 22 Jan 2021 13:19:36 +0000 (UTC)
Date: Fri, 22 Jan 2021 13:19:34 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v5 3/6] kasan: Add report for async mode
Message-ID: <20210122131933.GD8567@gaia>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210121163943.9889-4-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 21, 2021 at 04:39:40PM +0000, Vincenzo Frascino wrote:
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bb862d1f0e15..b0a1d9dfa85c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  
> +void kasan_report_async(void);
> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>  
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 234f35a84f19..2fd6845a95e9 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -358,6 +358,17 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>  	end_report(&flags);
>  }
>  
> +void kasan_report_async(void)
> +{
> +	unsigned long flags;
> +
> +	start_report(&flags);
> +	pr_err("BUG: KASAN: invalid-access\n");
> +	pr_err("Asynchronous mode enabled: no access details available\n");
> +	dump_stack();
> +	end_report(&flags);
> +}

I think the kernel test robot complains that with KASAN_SW_TAGS and
HW_TAGS disabled, the kasan_report_async() prototype is no longer
visible but you still have the non-static function definition here. So
either move kasan_report_async() out of this #ifdef or add the #ifdef
around the function definition.

It looks like the original kasan_report() prototype is declared in two
places (second one in mm/kasan/kasan.h). I'd remove the latter and try
to have a consistent approach for kasan_report() and
kasan_report_async().

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122131933.GD8567%40gaia.

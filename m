Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4M3T35AKGQECNBEGTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDD5E2543EE
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:41:54 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id n1sf3847660pgi.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:41:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598524913; cv=pass;
        d=google.com; s=arc-20160816;
        b=r3iMNpA+VpNgDmoFXDkoKN09KU3zWytxyzCPqbWGYFz1tYIXEdzl1KC2FlX3V0iZdd
         yS/IB6pxY3dm4Zq8jEh47C9AEftJllkkfY5RvIinijK30oCBIMNKXCYeiT4OlEhDlyPj
         oT9inEHEN8dqk80lO04i8gAcaL7M/eQm/HRIpjzjbpKTp9Oef3KUhcLXwxGrx4WTEIBE
         MumkfSIxMibxiYvkWhtlELbtXDRxNT+PvoOG8kDo/afoeWsDYrnbDBvseqiuyZ4nVzTI
         DlTPwgnqfIB+bp8qa+WX8zz3BjE3EtNTUOeGF4nLCn21D55WdF7hpNGBQQqhBCUZLbyb
         wU6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=hWhz8x7z5KdBn5Ivi82ar/DK6ixdGyLb7iUHi8PH87Y=;
        b=iAoNkuidRjpZ5sKD2TBPk8Szatw80im/MlZ5jU8GMxk3vVQtIj3dvistSYeiKiqtQe
         ZdayCCa8D1/M5JkNhk7bnXG9gwwfQnHCL09zy00/MpX2Zs6vmIr+DUcbm4VYpxI9aDjM
         lqgREDFXdzh/yJKHl0Py1qSGFei3NcFj7C6gttOmoIa1A3L/E3CzmMs4p+Z9g3i4vmlH
         8RiGcAKuK471zPRGIqwLopkkfJHnpWEjVaYOdjLCDPN7gfRBEMfefH6E2xhYajnJBdZn
         Swrj4cVy6fvpMxwWv8n9J9QN52Axb5gyNSrPnhrc4JJVVwZv0u1mjgA8HOiMTW4A/9PH
         t1fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hWhz8x7z5KdBn5Ivi82ar/DK6ixdGyLb7iUHi8PH87Y=;
        b=h4eMyaSpKw8pKMmWwRuF1XcXFgHDoH7ExuN4KQfZ86HL1lTM3NAvSVHdLC1Ds6M7LG
         t1sXtv5YmZMTgmxT/tXKLlGbS66UseiVVi4xU3fyVMtGbnOshz71MgBnBUuhL7VbEMGQ
         ZD2IS937l2YqFXYEreDYwU+Cya42IgvrT+pfo+Eu3ckwdFEqho8UQiy2qP48CwgGJ5Cu
         URHmU5H5jBw3qJJXw7iU9W8wAM71Ba6+lrwIRXeBJ8iWTxahsG4D6ZP4TrMdmsS8acmZ
         9atSYFye4EAU92qs9ZB/WcsfLDDfhA0Fnwk4BrB130amLWnHPid8pheGSBlUGC/cD7MC
         HeSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hWhz8x7z5KdBn5Ivi82ar/DK6ixdGyLb7iUHi8PH87Y=;
        b=qnTg6g4Gq4PSJchwFPPBu5E2tB3mKA/kpaqKjcsPtNNQ/XWQOfuyxTzBu6gsQ0xp1s
         5pxH25pss7TSRjJKioaVhKGl2DVxdxA1utUsrVQRBatyhANuqDN7cDglZOCg0AgHaUE6
         k3js2Kkgmy7saeL+jVnniCcDyD7W3lxoz+VK0+Rc+Zp31P+P8RO2Iof1KFdp8bGQZQ20
         eY64fBzZ8wGI8YQBaGG5zYUiRjt0EAGicBi7nur7CQOkGuelynCZM+4W7fau6dftB35R
         tSE/I+hth8lQhJP5gFQMq6pyRkBfC71zXkwfHjn+yZmIssdI3UD9a8dORxUo69hsQGwQ
         igdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ps2OMbC2lIq8wXjidrlYaPoBuimIlxhl7lum5kp6Q4s9nJquN
	7UWyrcQ43JwDQVen+PRCiCY=
X-Google-Smtp-Source: ABdhPJywB8oeh5lz6pCDnHoRuVFTTXtuysjutv67sqiuzzAskadVAMRu6q8EzLO+TWzYvenNpgRtfA==
X-Received: by 2002:a63:4503:: with SMTP id s3mr14255739pga.119.1598524913598;
        Thu, 27 Aug 2020 03:41:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:82c5:: with SMTP id u5ls1037985plz.2.gmail; Thu, 27
 Aug 2020 03:41:53 -0700 (PDT)
X-Received: by 2002:a17:90b:148b:: with SMTP id js11mr10053248pjb.62.1598524913185;
        Thu, 27 Aug 2020 03:41:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598524913; cv=none;
        d=google.com; s=arc-20160816;
        b=jBseVUMkw/3kBLeLxLJxxk4mH5jnMNEJb3sOGvnEfm4+zAd2jIPa2RGLwYYC5c/dGn
         koknfx3hjkxq5atVMyqv3p6zY/BXQuWpy8wKqsxktHVSFfEEu7JLN2yNqhED+mMcPQse
         To1dwb5BpYjtCdZ7lj5FLzjH1+AZbsPjr4gZIpISfNTF/mf848lnLwmaymDziJ1mhGuG
         /1mDrloIWzDt4/3aEHs1MAXO3BiIPNzNvnwL/BlMQJirN/pkrYV8b/1JLXGj7v5RMefd
         Kkr5D1W31eTPNi1QJsXSGGIAzfagXhG/aQvyb1/H7gldjREREpGEfRDv69KVSiqDoCW4
         VagA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=gAoxXMxUOvuG7xKYY6sjXFko9WnSoDjz0acW2O84VA4=;
        b=FJ78O8NgWZ3o99vYx1k4ERLU68cA8O+v5JUtaNFQMQRm/FEBsrhRFYfbnpl0+LnsZy
         IOkPQC3Vas9766WAXPKxmQ4PdjxsmHSANbSXuntVJGxuuc93qYmyhMEseVHh6xj2auZ1
         aiubxwgrs0sTH9URW9OEwsa6fvHTmqBpSuQuXLS3nVaaBHPVylAKDM1C4Nk/tJXc/izI
         DMve18JuOTLecAl8qFlUo5/pWSjqchEKv/TI8Tbe6b1tgXtxAJicwSBgPz5FTCvXCbie
         M4plFbgZHY40D4sOgN5z8ltvt7FQFKlQWV/bIIdlVEyubYJqfTsHTWW+vAnwBhTKWMHC
         cdqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j4si136807pjd.0.2020.08.27.03.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:41:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4F7DE22B40;
	Thu, 27 Aug 2020 10:41:50 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:41:47 +0100
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
Subject: Re: [PATCH 28/35] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
Message-ID: <20200827104147.GG29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl@google.com>
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

On Fri, Aug 14, 2020 at 07:27:10PM +0200, Andrey Konovalov wrote:
> Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
> KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/kasan.h | 6 ++++++
>  1 file changed, 6 insertions(+)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 1d3c7c6ce771..4d8e229f8e01 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,7 +5,13 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>  
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
> +#else
> +#include <asm/mte.h>

You could only include the new asm/mte-def.h file (currently mte_asm.h).

> +#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)
> +#endif
> +
>  #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
>  
>  #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
> -- 
> 2.28.0.220.ged08abb693-goog
> 

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827104147.GG29264%40gaia.

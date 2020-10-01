Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHNM3D5QKGQEBUVUM7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 521E82805C7
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:47:10 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id n24sf1354910ljc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:47:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574430; cv=pass;
        d=google.com; s=arc-20160816;
        b=V5H/iaERm+QqSQDDVPkSXJHDjxZR7igQ/GWvrFI8YgUTMXufj4Sqxi8nfir7k5pUDg
         dDngFBIwPjcR9Z1ykjK4ly3p7rijuHY+r0CEPBISY88n/3WWl0l7xFb67ltjaEjJ5rSU
         B4P6WN/AUcG85gSDphcyNkR00oun+mJe40mjHpyp1j2bK+jg3abll6T4DywMm2pdnBsK
         Zjt7WwmmmUiOxJr5XyJ6NpVvW4uJaZU2PpqQifh6YiQYIMKwz6nFpDvKeO6qc0SuaVFA
         WU2XguU+ml4/0iKCCYkruH3b2j8e+hK1TnzKcM8BxucJgN/GrHmGZ8kFsj4Mt0q6yNMl
         2Ylw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CZ4OGD5F0mmFi/RBXMS1+99qAr/rzyzNH+7hroK6OpU=;
        b=OXKYw2JdmrdKM6NRrCXWL7cGxmRmAequgS9KTT7MbHdmw9WQoy+5goEREvrqU0RUfz
         EIEcWYPFa+11FtSeFCorZSsV8uqbcJ5XkI9Hgkcv5y7G1qRWHeihqDMut1nGVPg0vv6I
         ncvtKrpfg7TKr0hj1NmlNc11aRnUGgHgFH7hNGtHRzeL0AWoC4UCaqV8PRKtcQdgzSK+
         6oYEz2Mhy7jfgyddKqmP+sa3bW012C//45HXiO65bQ2TlF+YnyUsP8o7GkkNtv4Gr0hU
         qA7Wvz9crTGXnVG9Jh/mnoMP4MCRn1lMb7CL1Tl3zxBwv+qUFWV2ZgA9x/J9Ww8IPll0
         foUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IT5todeM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CZ4OGD5F0mmFi/RBXMS1+99qAr/rzyzNH+7hroK6OpU=;
        b=hsqURIIWavP2R+/O85x8NnpUe/HqFFhfXOqWKQtnHxeeSgP2NURMuDXMW+iPJISSG3
         IldSldlt97VXW7sUDprYJ+1i7GkpdITNeVS9uPlsVRECbpwYow+cgAXxh3/xi8eRmq8q
         lSbtx/qoMyFB7hz+nvHZ0E6nqhXac5jQFPv2XXU2FzVz6HZ6Mr4nyHSePJRI57Isibhi
         ASNnhDzPhXXzWnl2XPGuRD4CHLV+1Q4OVxZjVoPjZ9p6DAo/ZSMaTP1WmMsRdQfxTGN0
         oBMIwjD+f4rjCIRB5SIzgVtSLxoJ3/otbXKhW+pm+zMFx/+DYq4JuUaXr5ej5C/Tgft8
         Xz/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CZ4OGD5F0mmFi/RBXMS1+99qAr/rzyzNH+7hroK6OpU=;
        b=XtP/GNVmIgR8lxttjAIfbmSkJYVscHbCvDSShXRRgQrDvzpIy8C+L4k5r1YbYgrm6O
         ENLbTeXOhoh8folDkXm/Mzbf+0Nj3tnJkr/vZstkeLg44OH8WUAbg1NK93cK6tjVW1kJ
         LrD1jbTYXUiklAIP1KGqWewE9OikGOU8QQj42P4tw/iPSM+MegvDRp9yzeju93R98PPS
         ctj+7vqUxPnk+oQWC4Q2o/s+y9Gr39DsKENLVLxtaF+c9hgyGMYn/uwDSui+fCxUQnYU
         4N/35LmN2oZgaU7DkIy2F3S0L9/osLaHm1+DwYpPL9PCn+HIdDwWXXegw9s5NaMncW1b
         AqOA==
X-Gm-Message-State: AOAM531ShyfAJ+JRgAqZeVX6948eVd/nbgn7q3Q4Zs1kEeh71e3SJJvX
	ADwceDvlC6lDhpgoBgWzkcw=
X-Google-Smtp-Source: ABdhPJwDW6RKnj+vbM8RttPeXiM53B2IpHEAIhXmXsD50DLJ04BbZmZGfHGUxpP2+eGiIgDE6DpaGQ==
X-Received: by 2002:a2e:3c11:: with SMTP id j17mr2842886lja.357.1601574429848;
        Thu, 01 Oct 2020 10:47:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc6:: with SMTP id w6ls974624ljj.0.gmail; Thu, 01 Oct
 2020 10:47:08 -0700 (PDT)
X-Received: by 2002:a05:651c:514:: with SMTP id o20mr2953077ljp.312.1601574428668;
        Thu, 01 Oct 2020 10:47:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574428; cv=none;
        d=google.com; s=arc-20160816;
        b=lVPbVuAmRVV5Z0ylUkfOHtemrw0Icamu1kr9zQbC3wLaqarQVANWUmL8KqHt1OgNWX
         zvwculdB08wv6aTfnwtsjsu+Ny8n0G9ErU0RSR8thi35qHVwO0j9MiOy7DPS0iQ/u5DG
         ZZVR6Uz0WfJJQbSfTlbaxcUCEnxzMr7SFqec6BSBhcGqW5Z2lHo/3rgZRgyc59T/kaQk
         L36ykAAQwn85ldAbWW+nsV/o0zJ3UChtiojaiPeRahL0AaydV8LXflZGdEkmZqAiDhWD
         Ohb4b21kJcTOXibfr9Gwu/esuBMBkjVUndXMKjWTeB7BPSM8kvzaMyM5bk22LwXG+UEv
         uHpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7E5ey4NET4LMVLLkb7YG6DyEEKXE4OLZrVX+Ejvtxuk=;
        b=DP1cxmGF+JCsYwxvb5JRbt/VCRmil6J9kjRppHv4isAszApY7GPxwh+6GfMKecgTsS
         EYs1CJk85dhVjQlpH4DZ6YPPtMnESPaL9KDu0rmzHqP8u6J8vaabVuar1waItZ+cdyOV
         yfMo2a3hmgftDa3/0vmFCz+lL44O16gYisXv53obegIBKPfo9FNZfClN5Sx36J+NJ5as
         r7ymB/1sHlpk9LbBbVk2IE0RzGBM2wDp7jO50ePpH21OsKJxXydUAdGhyHkcoPmIEcE8
         Tu5zCsZw6MbafVEMEINwcm+zfFvzhOnLUnKYkH194bZBMZaFEsWedNiE8FuImMtpolrQ
         IWiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IT5todeM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id b5si164825lfa.0.2020.10.01.10.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:47:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id j2so6802457wrx.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:47:08 -0700 (PDT)
X-Received: by 2002:adf:f10a:: with SMTP id r10mr9953039wro.86.1601574427998;
        Thu, 01 Oct 2020 10:47:07 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id m13sm10484423wrr.74.2020.10.01.10.47.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:47:07 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:47:01 +0200
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
Subject: Re: [PATCH v3 18/39] kasan: kasan_non_canonical_hook only for
 software modes
Message-ID: <20201001174701.GN4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <ff0f9a3bab9d2b99580f436121812d1eee560b44.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ff0f9a3bab9d2b99580f436121812d1eee560b44.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IT5todeM;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> kasan_non_canonical_hook() is only applicable to KASAN modes that use
> shadow memory, and won't be needed for hardware tag-based KASAN.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
> ---
>  mm/kasan/report.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 9e4d539d62f4..67aa30b45805 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -371,7 +371,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>  	return ret;
>  }
>  
> -#ifdef CONFIG_KASAN_INLINE
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> +	defined(CONFIG_KASAN_INLINE)
>  /*
>   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
>   * canonical half of the address space) cause out-of-bounds shadow memory reads
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174701.GN4162920%40elver.google.com.

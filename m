Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3VRTOAAMGQEG7FIJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B92C72FB635
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 14:04:47 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id 21sf7675446pfx.15
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 05:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611061486; cv=pass;
        d=google.com; s=arc-20160816;
        b=yVIKHi0SGcWXwph1TK6lZ+xk8jnrdMsq5nrsNe/u4yDYKLSowFZy0ugeB6+6vkP+qZ
         b9zobF8iREMXN650LZLtusczjj1IK9lytKYGWYkHzrbwkml8RGNPl5JzhF1xFP+I/Fm/
         UcyWYMOAjfzw5VG9iJ7AFeGR63MhR3TjHnH58qObQkAB70Rf9A/Mly9WmZQQ5unTxdVw
         uL3e8HduANrBiF+0zVBA46TyZzGJyTp6XC8fOhZjV5Y/F34+Ml9dTiET9OrpzDXQmEWR
         4hBFceU19pmHBk77hMWAII7SXNP4Je/UIKhh7MD3Dw2xnjURLLNrGYnIvlTRmxOD4XDn
         j6Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pntC83xAyQmiCobN62JYyiy0u4cJDGjumVrHlDThrrI=;
        b=OuY3LvjYXXPynC2yUZWS8fWM0Kp6SZ2VHZU4F4FJGImgkvetjkuawfFEKHDu258vO8
         Sx2jV6BxIz/ocqgp6XzCvrJyItT+J/yCjAI3NCkE+RMtpKgYWsHLtckiD0W+YMSUj7B+
         UbjOnOXPypAZrxoVPWh49tbpz32HvlHZdhm1Xhjg8xkVwCiqH0/zegsdV93LEVewR36i
         4SOlf6hAeVgfRUScP6ea/ThvIKkMok2VQP8dHY54jQMq0bjWe8nmz5NpCZUUAmPQyIe2
         sYUuTKjmMR4V4Q3h4V1V2zQfpQ5UseIfTfKu+3Pk2sen/LMH9hJQBk0nMAYT71aTogX6
         HFgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pntC83xAyQmiCobN62JYyiy0u4cJDGjumVrHlDThrrI=;
        b=Mi6fY5ppZJAW9rk/RKU8RbXor6ZIq5+CNlObAEvWUOS+aKBKCBoS+f6iCT3BccR5r+
         gwh9mssndoHNwfYnNulFp9ZIudKnhc9fBYGrcuCD2/PAV1+e35Xm+fH6ylhL5bObF2Hy
         yW9x4GDTdAQ5uBPSvgKwfxr1GB25GpPtMVv04kcUXp8B3eMffgm40x3Fz5Qi/xtjxzvu
         w/Tah7Bf8ozP2XRDIMlAGvAUBWmgAItN6Ny/9rQwOyi2sm9qqROfddPbQdJMZqjFF1Eu
         f0VvxpuUpHu16cyLjvXqIC/M365sr80ONjqfMhm1JzcUKsqladtdF9c9MtT+yYVQVe7q
         6GRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pntC83xAyQmiCobN62JYyiy0u4cJDGjumVrHlDThrrI=;
        b=LsUh4yXJQyDTkYvzlctKZcKGLQVb4mLbTpNDwMooSfk+B/zolIa8WvN4qOv0EVqP5l
         9blrytcwdSDV7vHCzggIRNyexK4koQwZyw/SV9GyXaziA8MzsTTiIGDhe7oCc53jV+El
         cnVsUJfc3sMTPOdJiZHmnISHvDFjrj6hQ5g/+heaXWjKYE0VClBJIk0WYy9Bn74PQh/B
         0TYZvu6lWR5cdUDnaI8YqNC0gw0Szk52UTqGKpwIMw4SSCBeSQRMDzzIU7r4YOgZgPSP
         x2DLXqhnwjYn78K2x9sl/jlVVYdkqiEGPorXxS2M7/Nt+csdpdLSW5svr+F8VsS1Cx8Z
         yTqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uUMaGeRBxMmVOFVmwdM0dWJ/4BiTmsIwNv3n2jh5LewggvZ2b
	FgRgjL/e5siGqdiVvlPg7b8=
X-Google-Smtp-Source: ABdhPJykktc61KVSTeX17RXFsx1hrtUAZGSLNorU8H3XuubyWeuc+xz4QUc2gNKby8LzCeFI1u1jVA==
X-Received: by 2002:a17:90a:d305:: with SMTP id p5mr5584538pju.33.1611061486530;
        Tue, 19 Jan 2021 05:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d2:: with SMTP id y18ls9857089plg.6.gmail; Tue, 19
 Jan 2021 05:04:45 -0800 (PST)
X-Received: by 2002:a17:902:6ac9:b029:dc:2fe7:d949 with SMTP id i9-20020a1709026ac9b02900dc2fe7d949mr4831494plt.2.1611061485876;
        Tue, 19 Jan 2021 05:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611061485; cv=none;
        d=google.com; s=arc-20160816;
        b=XZvTPeGCsBkyu1JXdkL5ykqE1/kXhxgk27HRsDtUyM85KhJVKne5Y/IWGP3i9xqeaz
         cz52Deu8MHv/QrH0Xck7Oq+UH5aYHQXz2Bf2pqQzyi8USVoj1d9MwMiIolWmSmZzZtcr
         phMxd/xFc1UfMnNWvG3/VbOITbWlM5Y7mYRANPv1LjhU66MITCIrUj6H6xsnlKrCZ40W
         Wm8wJnUUmI4bJkboSY43gn7Q8emGbiL/GNvUqZj0+k2TmRkS1Ja6jQycT6D75lB19LL+
         sTEf8vLbJIA6tMUEPlhTUq7GWfHF//ISgVN8mJ2+Bba1P/6aIqAi3mARr/Wtv/u2+m2x
         AdTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=bSbkjrlVSch7T61YiDkLG5Wv/M40uLpKKoFYxebo8d8=;
        b=zYRVHslImrY0zSpvQloJH7TT0JBER+4UL6NefP48UMN3RuDTNY1wvfgGjUezchzp6m
         2AlLA6jYVGK6bzprfh08SZK+/mD7J9frkN30PnnCUchZ0ec70G9m7O4WK1bL9xNJxxKv
         CadM+o2UMsUtZ4wBhZwwLioG6ZymSld+7p3VTi9jq8xl/Jm4raLvaoDYXFJD1dOBeOn+
         22HNmiOq5T6iP8QhfBOuX2nbB/FG6he8R6l/1lHdvdYhxQaN1kDCm71z7gMXVxLUqyRW
         FGRCUdizO5rdraHzp6fLnVQtlumLM2wWtFPIhFFU2/KEwTKLNd2QAbC8auSenF7gX4MU
         S51w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t22si310652pjg.2.2021.01.19.05.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 05:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5026F22227;
	Tue, 19 Jan 2021 13:04:43 +0000 (UTC)
Date: Tue, 19 Jan 2021 13:04:40 +0000
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
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
Message-ID: <20210119130440.GC17369@gaia>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210118183033.41764-4-vincenzo.frascino@arm.com>
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

On Mon, Jan 18, 2021 at 06:30:31PM +0000, Vincenzo Frascino wrote:
> KASAN provides an asynchronous mode of execution.
> 
> Add reporting functionality for this mode.
> 
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h |  3 +++
>  mm/kasan/report.c     | 16 ++++++++++++++--
>  2 files changed, 17 insertions(+), 2 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index fe1ae73ff8b5..8f43836ccdac 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -336,6 +336,9 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  
> +bool kasan_report_async(unsigned long addr, size_t size,
> +			bool is_write, unsigned long ip);

We have no address, no size and no is_write information. Do we have a
reason to pass all these arguments here? Not sure what SPARC ADI does
but they may not have all this information either. We can pass ip as the
point where we checked the TFSR reg but that's about it.

> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>  
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c0fb21797550..946016ead6a9 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -388,11 +388,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  	start_report(&flags);
>  
>  	print_error_description(&info);
> -	if (addr_has_metadata(untagged_addr))
> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0))
>  		print_tags(get_tag(tagged_addr), info.first_bad_addr);
>  	pr_err("\n");
>  
> -	if (addr_has_metadata(untagged_addr)) {
> +	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0)) {
>  		print_address_description(untagged_addr, get_tag(tagged_addr));
>  		pr_err("\n");
>  		print_memory_metadata(info.first_bad_addr);
> @@ -419,6 +419,18 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>  	return ret;
>  }
>  
> +bool kasan_report_async(unsigned long addr, size_t size,
> +			bool is_write, unsigned long ip)
> +{
> +	pr_info("==================================================================\n");
> +	pr_info("KASAN: set in asynchronous mode\n");
> +	pr_info("KASAN: some information might not be accurate\n");
> +	pr_info("KASAN: fault address is ignored\n");
> +	pr_info("KASAN: write/read distinction is ignored\n");
> +
> +	return kasan_report(addr, size, is_write, ip);

So just call kasan_report (0, 0, 0, ip) here.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119130440.GC17369%40gaia.

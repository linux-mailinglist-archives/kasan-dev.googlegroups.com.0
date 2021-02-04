Return-Path: <kasan-dev+bncBDAZZCVNSYPBB5HK6CAAMGQEGBVCNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D78D630FA59
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 18:57:09 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id d68sf1166745vkg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 09:57:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612461429; cv=pass;
        d=google.com; s=arc-20160816;
        b=PvypTXIkTtNjLQCfz4zDz4bPe7pJuB1nzo5QetxKmSANh/2T7XyXtjmInqVIvHMRqo
         QS6+kEZcTNvaXtuv2IFJbU9lzXkVkHxFwfzMwXQKzVn8h7D1fYcqeYb9dNVLRCDARHRQ
         XDjAf4coTYXbC3S1eBaM6gLE91wGW3ej9L2QT2KcdrOTm2xf64QkNRa/Wu30p79qU2vc
         kQPB0Ys8sUe4MnMppYPKMJhSVbd68o5F7bBn4v7lQmUVwD61HFBVtI+GaM/JpkVWAcwP
         5YVJGaO2LmrtRdIzWS0TkMaAd+SM+nbTHf2S7AsjOBLNplRji5GPk/gutPvwVe7r2T0I
         uTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=RfvF8FuFSlGrpq5IJ1awz2ErH0LUF9EjFje1pxbPJu4=;
        b=Nyi6NDCes25zHlTGIi1hPa8Xe1iCx9c1Pn9MRraquGwgDOGmvXPloKs0R1B7AHDbIz
         xxW2rHwtc1ILBVw9IcF8GKUEgJlrVkCO1STWTh1mhzOaMmGN29Z7BcPtbzEg6R7OqLmH
         gu+WH4RzZIteirCVd2kMfL0ilxotDa1BhlWODN+OsmvFWNNByRCw6YpBy9lgRDIafgcx
         RtUZwTamZMPheRKSqQWkwWaaEAc1Q02wtHb0DvAzFhL0kd3XZsv7TVC9AY6c40+EOejq
         rzP8D+V6CTbq9Kql1k9QbdtHhJLTkGN067Cu98aFoOfP7G/29LyCxkZUjnmEQOnLCX/g
         Ocmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fvZC0GgA;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RfvF8FuFSlGrpq5IJ1awz2ErH0LUF9EjFje1pxbPJu4=;
        b=sEdZAH6XDhCZ4nFb8Od7VUlRdxsn+77b+fB+5Or4qTBaBK5DfjFs5/z+4S0sleYeh/
         jXG7wRaW/0KVp51/lpEOe/O3XzTBtXLFFTtKof0hfoY8bIyelQI06KLUU/ATb4/mo2JA
         Rwu0YXBCmyJ29BRszlE+ON4zEZ6MKfLt3VOQXG7Hee0M7iOh1VeHoR+182yNYECXab1V
         r5glFpR5V7binSAoJi1vwiHscmc/kX2Y6ZC8pbXwyE+cDf+vMNYxqtHTHETqRHsd0YEd
         NMlDX+R3qF7pQKUBIC2mUk6ZIYnTiIluQhTXAu6mGjQgKkCMIIHK6AB3X2sO31A7ZhaP
         3rfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RfvF8FuFSlGrpq5IJ1awz2ErH0LUF9EjFje1pxbPJu4=;
        b=e+jkgK4VO/krynmCWOpg53JnBjtqr/iKEw9d7DeVYreYBsR1UsBV++30DbgzirAxo+
         QCYIJ5Drofq/q7+GvZY54ZO//L8OOec8LtMQuq92rcUtw8RxS0jgsE2sTAPCCjmvsICf
         1GGwe8XVbYVLD5tBBFaIV0r2MkFPAIL6tM1zu6SyvPuls3MH5xKU/vF0XyZEJkYKY/3j
         E1vx/AjUBSu5WS42cs9kPgLeN82JO8byGBm9IyzCjn0KfiloPf1iKw4/gNaC4Sem6PKU
         /mir0OObbTFE6eVgHP9JxBOO0J0ttTwiTL9nFq4K0t3ENvj8WIYTgVIhXsU2w+2FoCEm
         qBtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CMauM/Y9JrrdHnqQ9ZMgiQzn04t5i/RXsBcPBJcNMz5NJ41AC
	ivRCXTJDxkw5GDGxYGCLPXg=
X-Google-Smtp-Source: ABdhPJy8181OZl8Iv7GjANBRfbTy3KB9PdwnGIOYG9ayjcV11PvgqVP3wY1jH7FEnDXcbLOCqpSg+A==
X-Received: by 2002:ab0:14ea:: with SMTP id f39mr394986uae.25.1612461428857;
        Thu, 04 Feb 2021 09:57:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f898:: with SMTP id h24ls818308vso.5.gmail; Thu, 04 Feb
 2021 09:57:08 -0800 (PST)
X-Received: by 2002:a67:fc8b:: with SMTP id x11mr479222vsp.19.1612461428441;
        Thu, 04 Feb 2021 09:57:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612461428; cv=none;
        d=google.com; s=arc-20160816;
        b=ZImsF7r7TPByTI5od9tJvb2vJHrq6yWig854MzSqxl698qeiAbAb45VNfKeolgX+9h
         pZtxfjmarmFr8e/u6cJVMIf2/InLUIG3olIklNnzl1d5DXJSPHRyoHwiodu4IuQ162aM
         5fQ82EAQ3C/2KrPNtG0A26+2WUQ+fYSy1218YRf/4ehMy3tel4GggAMA1etYASZdoKfd
         hRdzv+2Tqou9NTsxIiuTVLnUfcE9FP59nfWDA5SUe/+boRGi55cKTmx/c7HFZcIBGUwY
         pRKnkoJ1oSKpDJ3KF3BCxhDrhiyIVEBiJV80yUZoGysp790LURxPBgByAHgcLpaYy8XD
         yCkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LjHrDkrJTDukK7VxV/5qmN3cZP95FVPFATjY0dS8F7I=;
        b=IoRZMZ+0aK4QfBQ6ZAxrR1vseTcgLu9ZXZdHcmMEGnnIrEwOmbYaRxlz4/F40dk1AL
         EK8A8k32Cr0HsIQ9H4CZZ7EZAGswNbrLAR7bLfppLDLqR5zru1B2q4MeFNUimay68kyr
         4jN1syWXyaUCYOCbDxV0HEuVFSb7CnRYVjxKw8NCCSxfMfhTOorajp761fZh8Nqx/KGB
         Dc1wyYXCAcYWIgJM/4y03Hc2wUKzmjnJB7CNmQ5A4IAvPzTherz6gjzIsis/VOJHU6V4
         8fk/uUeLRTKVJlWXCE5LfpnlX9ftkpOt+GKz1H370GxjyrWaq9X2bTvQSyJvSxigOT0v
         mwMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fvZC0GgA;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c4si348884vkh.1.2021.02.04.09.57.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 09:57:08 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6061964E16;
	Thu,  4 Feb 2021 17:57:03 +0000 (UTC)
Date: Thu, 4 Feb 2021 17:57:00 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@google.com, ardb@kernel.org,
	aryabinin@virtuozzo.com, broonie@kernel.org,
	catalin.marinas@arm.com, dan.j.williams@intel.com,
	dvyukov@google.com, glider@google.com, gustavoars@kernel.org,
	kasan-dev@googlegroups.com, lecopzer.chen@mediatek.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org,
	linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org,
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <20210204175659.GC21303@willie-the-truck>
References: <20210204124914.GC20468@willie-the-truck>
 <20210204155346.88028-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210204155346.88028-1-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fvZC0GgA;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Feb 04, 2021 at 11:53:46PM +0800, Lecopzer Chen wrote:
> > On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:
> > > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > ("kasan: support backing vmalloc space with real shadow memory")
> > > 
> > > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > > by not to populate the vmalloc area except for kimg address.
> > 
> > The one thing I've failed to grok from your series is how you deal with
> > vmalloc allocations where the shadow overlaps with the shadow which has
> > already been allocated for the kernel image. Please can you explain?
> 
> 
> The most key point is we don't map anything in the vmalloc shadow address.
> So we don't care where the kernel image locate inside vmalloc area.
> 
>   kasan_map_populate(kimg_shadow_start, kimg_shadow_end,...)
> 
> Kernel image was populated with real mapping in its shadow address.
> I `bypass' the whole shadow of vmalloc area, the only place you can find
> about vmalloc_shadow is
> 	kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> 			(void *)KASAN_SHADOW_END);
> 
> 	-----------  vmalloc_shadow_start
>  |           |
>  |           | 
>  |           | <= non-mapping
>  |           |
>  |           |
>  |-----------|
>  |///////////|<- kimage shadow with page table mapping.
>  |-----------|
>  |           |
>  |           | <= non-mapping
>  |           |
>  ------------- vmalloc_shadow_end
>  |00000000000|
>  |00000000000| <= Zero shadow
>  |00000000000|
>  ------------- KASAN_SHADOW_END
> 
> vmalloc shadow will be mapped 'ondemend', see kasan_populate_vmalloc()
> in mm/vmalloc.c in detail.
> So the shadow of vmalloc will be allocated later if anyone use its va.

Indeed, but the question I'm asking is what happens when an on-demand shadow
allocation from vmalloc overlaps with the shadow that we allocated early for
the kernel image?

Sounds like I have to go and read the code...

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204175659.GC21303%40willie-the-truck.

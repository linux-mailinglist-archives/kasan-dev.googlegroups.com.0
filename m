Return-Path: <kasan-dev+bncBDDL3KWR4EBRBA7I3T5QKGQEYBD7IWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id B9FEB2814A4
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 16:07:00 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id z85sf99609vkd.19
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 07:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601647619; cv=pass;
        d=google.com; s=arc-20160816;
        b=XQrbVri1dKtRFdb7wuenVzgtGvFzn4YAIFWpbPowzDpFZ6VweG+x8HlHbzlL6On7u5
         EP2UYNhsU2WQJ+FcvAT5G2zYRS84Rksgrgtto3EldKm7yRrQfQIKl+QdECKYij8dKfc7
         hVz82vWJSa1A2FMdNdWbqUmC/hkLGXtYQZaQ0Gn0jYk4MLaqmnQabLX9FMtMEEAUAZOU
         wW+RRJoxrObknTeBajgc2B0BH8UqMgZm2BkwUtuEppIRS5dl6aQ4MGluc9DPHkwFiAHB
         nvJ5VLTtKs5B0NMvmylXdcz2HQUXDD/KInlFiJ1173LMK7R/syB2bY9fu92nTyLlsXre
         JcxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bahjdouw1rFpXNlhTavDVqDDxuAXbHqv9icWM8z4Reg=;
        b=cH3adE/SgbsRCQBA572L4eZkNrxpcD7kHk42nWgEQ9VyoevDEH65RoFg+clw1Cq8qL
         l02fezp9VUATd9myBm1Zoc4IimevysHwNc+ohVrK1CaaYomw36Jwi/jRPs9b5CsilSjX
         Ug9IwRDrhLPjWCXz2Lk6KojZgpONcQ/wA71DFpFMdsaxqlBv3dSYaf/mD1bviL2lop7g
         b0s47zHBKm2q8Qdqgb9Dd7Ip9IJzfuOjslcIdUGP7OGX85H7htgRpKGWGQ4VBjpRFhZF
         rVhRXjqmP5/45r5mG49MhWrlefL/J9EWLRy6RlL0EAE/3i1Ob0KyiztJ4+Y4eNox7Ek6
         Rr2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bahjdouw1rFpXNlhTavDVqDDxuAXbHqv9icWM8z4Reg=;
        b=m8tk6/DnIpEANiL/5x4FMuoQFkEkyd7gYtKRh7FjK6hc1MN/6Mb9kcW7Mk/0gSl0Yq
         R00OBAySdtvkxba8YGwHqQwLz+ORwDRS7einEXYiUp1mJxYlcCQL77wrkKOM4pERUwgN
         M7FAtoL32b11unVmiJj0FqJdbmoPE6UOPua22Mg6Hmx92cuCiIgIxOulhbk8Zdk6GEQ9
         1YB8JRjOv2O2MHLLFRftsTWV5S+GugaW08EwqnREfDHRwaTZp0ZUz3GZMprLi9vzaAbI
         OuJH1j/DINKNkvEPXDu60AbIW0o2xQBU2Rb66/HvR2aVu4iUlLNluLhCko3gCUTZ0Jh+
         SXAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bahjdouw1rFpXNlhTavDVqDDxuAXbHqv9icWM8z4Reg=;
        b=j9Oxn/cvxUUan9bp9v7x6t+lggiNGms/Yf9HNoavv3s1G4dXoNIBogEokC+Ud1Lj88
         ihj8w9hfT/L6r5w3f0RvXc//Jp+e4fJDwhcLy+QtJSpIpN3+vXJZKmGbMlJ5MrhEkBBo
         8T2nZBCk8LfNcaXi2/NTYsp1aMA+HDz0+IWxkl58ER0OymxraFxk3afFPADpGoqLCLIe
         ZgJoSgNW9w4zS2bXyVWqS0TduVAABwKDPlL60TZ8TEJRaB36kPW4PdtdBRlp9+mSsZkD
         veDzAnrESVHgHLDw0MYLKoNVZKGS6UvFpvsAf/KKQzZBJRpmsTpxCHZgjt7/sEy4gzgu
         cyHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zxqM0CuKZNOfYid/DyuzTOCBkkHw+ciNbLjOg57y6SKwOOKEe
	gQzt8/Ui1Vi193cvqBKY/zs=
X-Google-Smtp-Source: ABdhPJzC/5YHUEFtB+xOUYKoWCgJrbeEbK8PW39nZARqAhGRkozmg9g6TL04EBIL/LL6lc5CnNdySQ==
X-Received: by 2002:a67:c887:: with SMTP id v7mr1151160vsk.49.1601647619617;
        Fri, 02 Oct 2020 07:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f7c4:: with SMTP id a4ls173849vsp.10.gmail; Fri, 02 Oct
 2020 07:06:59 -0700 (PDT)
X-Received: by 2002:a05:6102:30b2:: with SMTP id y18mr514312vsd.51.1601647618703;
        Fri, 02 Oct 2020 07:06:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601647618; cv=none;
        d=google.com; s=arc-20160816;
        b=wLe6hE8D8LYvOkTbumUWq8UZuvtv0RvQ8+GPPf85mFz3Q23pYPOM6geP37aGCAQT8m
         NwmWSijGrzUWBFBqaACfuDiigGneXb+DUBzvEWxsO6pcEZejqWa459dzoX+ve9F/Q2R7
         XDC04hQvI2TzbZ4qgynvrhKKDChujyyDMqLlUQMcbeJMM3xXUFX7NLCO/b3tBcrk8M1B
         3tNlzKrsR8IRPUc7X/02tPTb/gSxk9XV79ENBRIYi06SPGD9aJZPIj7Jo8Ftig4qX1EN
         TWOF3b5Oa4FKovSNUwP/z1NN/sqXF8rluY51xGDeG4Whvk5JhCWDms2T1U550nUAD31W
         yi1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=0XCH5x9gWUMt6MBQFRZEJ0q6pv3Nq/O9c0XZP3SgM/U=;
        b=NCvBb4DKjksfDHMBOjvqAYOFgl6dGzD+6PWiFGVqegd8y44fx6y1bn7U81Z9xXljq7
         6eRShHaS7iWAxfMZoT5RbUEeGL7+3wYW0qhdFWZYYqGaVR2zkBQnbaebfMEmDXfmKi4j
         QdGawULfWUEKjFxEEmgRD/ef3PUqHLC68HZG2cLi2gNOy9sqSDwk7rYntSL/BGFeTvdR
         6UHo8mnZzy8zf+ysgXZPNc/KbLBmahmzO2JC24FECa+UJ03tFtv5atUP+x4oZHQQa+WE
         URVN+Up/G5Deh2fwYTyhnSLNHVbZqMNl/VyWtRayMyAR4Y2fdWwfRiW18jN8orzlwIH4
         aISA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u25si118267vkl.5.2020.10.02.07.06.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Oct 2020 07:06:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1458C206DB;
	Fri,  2 Oct 2020 14:06:54 +0000 (UTC)
Date: Fri, 2 Oct 2020 15:06:52 +0100
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
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201002140652.GG7034@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
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

On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 7c67ac6f08df..d1847f29f59b 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -23,6 +23,8 @@
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>  
> +u64 gcr_kernel_excl __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_init_tags(u64 max_tag)
> +{
> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);

Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).

Otherwise it looks fine.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002140652.GG7034%40gaia.

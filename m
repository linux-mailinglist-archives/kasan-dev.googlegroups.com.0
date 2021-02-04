Return-Path: <kasan-dev+bncBDAZZCVNSYPBB64V6CAAMGQE43SGOHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EBE730F570
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 15:55:57 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id s4sf3166816ilv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 06:55:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612450556; cv=pass;
        d=google.com; s=arc-20160816;
        b=QZQkZ3LGktx0hfoS9WnVEZPISSGawCm1sRC4hC634Tp7tpovNoRz42821yc5SQgIIS
         PzZP6cK6l7UY90bsdezw1rlh41tZgEzE/u5wUebealiY3/b5D0+PAdohFAfEnDjIQG4h
         tTQ0rLnLT/uMHKa+4iNlmYsJaauQKN+3FSToT7CI5KUCdu7MU5JxxaBfuj7jx/0Cs3/i
         wk96MLGVLblTvLq54tHn/0UJY56meBLk+UqaT11iKiYUJIs5ztb/sGyLpcQWCtW5g5XB
         vWolIcwxjMs9k4Du3lpUQd8quU4Rj/4ZdqhWA2EC6hWjpyOZVUhIj3iQTezsBBrZZdGB
         2t8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9oD0uQ7tx85YOMKkWnCj/ihDOwZKjntZhBwTF9SMq9g=;
        b=U24wD0CuoymaIfAtapSyOk0xyB7O+8m87EXFfYNi0glq+Lxe9OjrI+Ahs6AS6HQCjV
         32p2SnysQcH1d9TsEAWwiucX0iiy++7xv1lH9mpslP3QF0mmYl+UDOIBjpHteFMO2qb+
         /s459/3CIhzumDgA5cUCb7ZFNng4NWTQbfSlaJK1ZlRhSPqR35Vq5qHC4v1c04jwM2jV
         m0ljsLtWFdl60ScgZS/zeYKr5I48DRQDVFqwixnFHTGN3YCTflpsA7NGD1lQz6EJ+buF
         FwI68JPI6IYxwTX5hWup2cK/TeEwIoib0edLPO6pCXwiPee/Zku79mjQd0M+qdia/YN/
         ic4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7nY5mV5;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9oD0uQ7tx85YOMKkWnCj/ihDOwZKjntZhBwTF9SMq9g=;
        b=dfH7wQz/+9Qtdib6YkWwYmBhP7C73guTwhfmvT7iGS/qQlJON7yjgHkMyfhJRn0Opt
         Yu+amrfsHCjL9l7RqmoJGZ1geMce1zAaixnubX85ezdjCfaDGxKnK3mbUBrz+nx0dlOw
         ESdSTky8HE3tL4hejXTJVfTtekJ9eprnWnF2pdf7zhR6ZaBawtmQm/aoCDS2AzpadV4P
         c5UcxcnZi1B8vS/myTFmICWWvfO+SPs1IggCTz52SgVFbPEOesf3rVM1q6rkmIO8t7rx
         /aDlpaxS27uoeg+gRzEqv5bWs1Fhkjxinp7HJJOMVWDeYwbdiyQ7JLuqJ32VsNdgQbw3
         bn4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9oD0uQ7tx85YOMKkWnCj/ihDOwZKjntZhBwTF9SMq9g=;
        b=ULMwUYH2hyz1VZwj9TkDFLFrnwm28+VaaODAGh3Cl62NB8TckADm63eSonHoGclL4+
         WMGgcnggdJZpNj/rpadDRGaXqBfxapoVApoMbTQVc5Nkwdoe3SNRzJlBBJ0DTvVLAj+j
         sdzofTxbbUzowEBtZHvRBGogTntNLXls3ym3q8zwr9BIDe3GM5+zSXZ9UlUbTw7W8y9H
         hA+PSEsOky+XtP7O0gc8EQHTzdkNK7TnJTM576b+kNVEtaOw4FF7Yu1anlLYfGuVnZPo
         GbR+nvt1ednnTguje4qJ1Sx3PpOMoqUTSUuAcvBdiLiVzyZtIH0fdwN2o9EaJudsoZkp
         SzSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532I6H0KNwiunfhFb1zt03ji3OlDSRzARvrX06zoO5Nk3Oo3knJo
	3FeaEIEbqOvkDKUDvVjTZ3I=
X-Google-Smtp-Source: ABdhPJzhjQ/q6OMJoAAvHfw9kiDiN5xuaJI5rpnBLT4Mn9CqpZeq1M5mage183G1aJ6xtES9FPyn9A==
X-Received: by 2002:a05:6e02:1564:: with SMTP id k4mr7392101ilu.282.1612450556079;
        Thu, 04 Feb 2021 06:55:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:14c7:: with SMTP id b7ls948987iow.5.gmail; Thu, 04
 Feb 2021 06:55:55 -0800 (PST)
X-Received: by 2002:a5d:9f15:: with SMTP id q21mr7253345iot.132.1612450555511;
        Thu, 04 Feb 2021 06:55:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612450555; cv=none;
        d=google.com; s=arc-20160816;
        b=n7EgZw1TSxZ68S5066LLbcpEJ3Y5AdiiKAGyWhmOUaLkVPYco9wxA/2Knt41D5sbnT
         ZtTVoiFfZpwvEHSucfyN6njNCqlmKZREANOU7XnzHqv38d41o8C5+ip2NSkHl3AaSqb9
         +riAg0x1Vmay2VpUvK93p2dWswYnwP54NihEmmvXtOXEUw6UNVW9E9qars+rVqBf1mfH
         fKkHY98UEQ8yB1ho+3A60VsKZtx8GhHRAXbmKFtD0eM5KOu7SuXXxKBfmaoOw6StdK2u
         XTZq0u7Kd9qZQisRNQ7XkdhKijJwQkGaFGB5n9pZvXiAUvaUds1PrXEDj2qM+d4AeRXW
         XFOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JjE2EYqkcoPUXawvfRMc8bkeB6OwrIaeFnybOSqdw9Y=;
        b=bEohtbrrLC63KCI4P8YUiYzsd8y4FedGzu0CacXIca8kbVo1YPFH6Go+fVOXE8VJqW
         Srt53LzvkpQX0Oa7Nqi/SAxSf4soyKNc0hxqmkkpiHLr3utPtNTOhL6EcuHmNFYso2hu
         oI43chBDlgMwjdDhPOr7TXoBwMqRaJZkvMPRxNrXY95bc7VPp//tB/nJwdkgMieCiuaX
         N6Vfmgyb0ElF7+k5hZwP6e0rgaUmLYt4tdBZLAWzcQpClzPG3d7nStuBvV64pVnAPft6
         J2jA0QCDn9j6JbT/QYVu+lWBiWAjoEIgnh6TYc8p5+kHpMaZeWI+rwmX/99ODa4gDfoR
         13qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7nY5mV5;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 207si254156ioc.2.2021.02.04.06.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 06:55:55 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0D40264DBA;
	Thu,  4 Feb 2021 14:55:50 +0000 (UTC)
Date: Thu, 4 Feb 2021 14:55:48 +0000
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
Subject: Re: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to
 KERNEL_START/END
Message-ID: <20210204145547.GD20815@willie-the-truck>
References: <20210204124658.GB20468@willie-the-truck>
 <20210204145127.75856-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210204145127.75856-1-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a7nY5mV5;       spf=pass
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

On Thu, Feb 04, 2021 at 10:51:27PM +0800, Lecopzer Chen wrote:
> > On Sat, Jan 09, 2021 at 06:32:50PM +0800, Lecopzer Chen wrote:
> > > Arm64 provide defined macro for KERNEL_START and KERNEL_END,
> > > thus replace them by the abstration instead of using _text and _end.
> > > 
> > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > ---
> > >  arch/arm64/mm/kasan_init.c | 6 +++---
> > >  1 file changed, 3 insertions(+), 3 deletions(-)
> > > 
> > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > index 39b218a64279..fa8d7ece895d 100644
> > > --- a/arch/arm64/mm/kasan_init.c
> > > +++ b/arch/arm64/mm/kasan_init.c
> > > @@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
> > >  	phys_addr_t pa_start, pa_end;
> > >  	u64 i;
> > >  
> > > -	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
> > > -	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
> > > +	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
> > > +	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
> > >  
> > >  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> > >  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > > @@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
> > >  	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> > >  
> > >  	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
> > > -			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
> > > +			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));
> > 
> > To be honest, I think this whole line is pointless. We should be able to
> > pass NUMA_NO_NODE now that we're not abusing the vmemmap() allocator to
> > populate the shadow.
> 
> Do we need to fix this in this series? it seems another topic.
> If not, should this patch be removed in this series?

Since you're reposting anyway, you may as well include a patch doing that.
If you don't, then I will.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204145547.GD20815%40willie-the-truck.

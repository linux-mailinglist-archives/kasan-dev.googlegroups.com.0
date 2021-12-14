Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPVA4OGQMGQEFJCNIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 015BD4748F4
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 18:11:27 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id m12-20020adff38c000000b001a0cb286eacsf679370wro.9
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 09:11:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639501886; cv=pass;
        d=google.com; s=arc-20160816;
        b=E/+Ij6XxHAII1bjJZSO4da/CbVrMBTPvgaOU+5AlLFfSh1Vj4kJl4M2mICR/nZizi4
         Cqp3PJK/NTdyYqmCdU8lhLYjV3saMi7TkXSNCJI/QVywN0Li4tie86PM1FvMPv+RCUZd
         oyMIg4IxaL+5EFekrGhDjgDOCJJVvxPmw9BMIBuEJotcKCCa1nJEUkSf55J29SbCFIyB
         uUVFNd2aRa6gwR5t4Ga9ssW7zQZU29ts/BhSiyOHwSFenKvj6L1Vr9+VHYCuR9tsPWbY
         I4cm8NS/mrUnInnJj6q28yDNawlQ6/dMErfzfYr8cJXtumFvx/9sTVKBycn6FFmlSS/R
         +vYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hN4t9TgJRvqE5I+dcbk3dUtwUSlkg1+BYXtC5tEhfEw=;
        b=yyKmOVWgijPF0pS8pr3YQvbkYESEqkiolVN9Xo0nR977Bo1yFwqp7wUTL9h75dnowP
         MYcSKScNWAfi595/pPaNSt9AwtaImNZsTEsBJYYRa1mhByOdbQyGumW6NkeDFMMUe92B
         E/7hIU96MFAe4N0ctuxq+I2lt/+ttcNyoGMsphoUqr9xJBsuBp19RRB0ohIwiWtFbmqB
         xtzi5VKIup15zLTx/sfWVXgNP4VCfZGqDxu1ht4H5QBiHZwzWpPzM3QD2B/SqP1SXfK1
         NnqYKuL//fEEHB3dyHHa7HC9aoirapMX382qVLxU1/Ot02I3MzUtmW27g51iRA3XEBwx
         2R0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hN4t9TgJRvqE5I+dcbk3dUtwUSlkg1+BYXtC5tEhfEw=;
        b=lqFlfb7puxHCy+Gm2vVJrfUqVkT0NzCDYFofIRWvEQryb0l1oI7gKZUIodthbmOBoU
         KkG2AUKpUDRYYOLglHNZ4wbOQDjbJaG45ZmbVvEnQ9NX+GBcaO0qaX3PJYaNLIkh7094
         I+AvaHF5TzkJvaK+WAjmg8leFe9uG/MmM22XTskHBIcC5RSTy60MR3XqGD8U9iHpoVAa
         CpB5OWCmpGGfDK0kGDVigeDqYZUviRIN3rkmBBh/d8X5u9xkMQ1xx6odT/q7MUWdMV+q
         Kfm9woODqziQ7wJWMJD7xPeoJYzH1hig5Q/aJuVs7814edcqITHAWrhC/n1dDoLFm59G
         /2uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hN4t9TgJRvqE5I+dcbk3dUtwUSlkg1+BYXtC5tEhfEw=;
        b=gBrdKaOkxJTtZx77gM6zKxTw5XUhXcq3SPB+7lxEYF9gPvaq3vMNE5Ss/m6gn7jtaQ
         BUiUiOHUgVE0BDqmpsty7bxplEuWJ/waNrg2qTjIyGkjwNUq4kYMS/j+8Tisg2acgv1U
         l3l4zfLQVIsjul82+0n6YfbXzg7HgvClrtTUWNxWQp+ar3GK8Z3cvPOclgNIBfwDgCHb
         e3DlRSckVF3MaP9YS5WCXrMZhB4Sqs1C+lzzESQU1Wk+uwLnjfaQqdWXDWvBsS7C+kiY
         ZNWTkNv4K/VVb6583rY27666j48cvN5OR3U72BbO2dn528HQpNTUAZFYzYjLXnHcRKPZ
         3leg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nMpkiN/PK/DvslgjBO6h+VZiUxV3Af6svojT05on489vrcl2b
	tExnlF50/ye38g/LBwAEaTc=
X-Google-Smtp-Source: ABdhPJw0+3zSqnqxufvtMx4gm38uWggyiujECwYmDNUTBtsXWs3pt/AbhCLFOfzp42OHXtjZ2MBZig==
X-Received: by 2002:a5d:634c:: with SMTP id b12mr295468wrw.460.1639501886642;
        Tue, 14 Dec 2021 09:11:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls1699511wrp.1.gmail; Tue, 14 Dec
 2021 09:11:25 -0800 (PST)
X-Received: by 2002:adf:f18c:: with SMTP id h12mr291458wro.484.1639501885665;
        Tue, 14 Dec 2021 09:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639501885; cv=none;
        d=google.com; s=arc-20160816;
        b=SHEpSy3brj4Z2NCzNB8VMXrflAs5Ws+dp3+0KzF34RXlvEa98eNcW4WniBolE9tVSx
         tjhvi4Rp7ob+5CTenxVi9l3uubrAy4fk/hV4lA68h3jFu1KIj70VsL1FNN10Da2k4uTV
         alBX85vBknR2UbY67lYcKstkGTpc/infO91Lk5RTXxXe4JvDPmc50NgYLtNtbD82/Al1
         j4GdW7s0/qsLkM1x97jwLa/btzrR59NGrcvARZNgoav6gw9YMVIHaZarKs0XGR5vnGlt
         aPTr5Ks2dLRtcVs0AIcJFRBgpmmPSlxs3h+RBAgn6YG0nakH9yV+rtq2Opf8lWBjGx0z
         +30A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=OnNetwAcuArMlogYplRedsNrXDulXQYUW4U/u0Dtyi0=;
        b=IkgHtG79sByry/psS9mS+Iv/KE9rOkkmtatFe9HINiRpq4m4o3wahBnsHbCAdyShvH
         Nnk/1Ozhi8+RrT3fN5CcGjika46bfx/s6jzopvfEiDY0QYOxNYiT5Bl3dIP1LFzszF7u
         zuIHXIIPdz182X0edBIQniqBtLhv0GYstDtaARzI6KY701SsrDknjC+wAQ8sVnV0FEHB
         zWdl3YowwIKMXNOdHrFeBuT8IqTKgFoxUsKU+nykRRppvExPXWG/7+pwV89tcNFU9V5J
         rWvu1+BzP7weNRDW6uAYMsfgo9qSuOM/FX7q2tAkgW7uotrwsoDuL73sCmvUw1TX8lez
         rWqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id 138si21778wme.0.2021.12.14.09.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 09:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 441D7B81B9D;
	Tue, 14 Dec 2021 17:11:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E0FD9C34604;
	Tue, 14 Dec 2021 17:11:20 +0000 (UTC)
Date: Tue, 14 Dec 2021 17:11:17 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 25/38] kasan, vmalloc, arm64: mark vmalloc mappings
 as pgprot_tagged
Message-ID: <YbjQNdst07JqbG0j@arm.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 13, 2021 at 10:54:21PM +0100, andrey.konovalov@linux.dev wrote:
> diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> index b9185503feae..3d35adf365bf 100644
> --- a/arch/arm64/include/asm/vmalloc.h
> +++ b/arch/arm64/include/asm/vmalloc.h
> @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
>  
>  #endif
>  
> +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> +			(pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> +		prot = pgprot_tagged(prot);
> +
> +	return prot;
> +}
> +
>  #endif /* _ASM_ARM64_VMALLOC_H */
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index 28becb10d013..760caeedd749 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
>  }
>  #endif
>  
> +#ifndef arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +	return prot;
> +}
> +#endif
> +
>  /*
>   *	Highlevel APIs for driver use
>   */
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 837ed355bfc6..58bd2f7f86d7 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3060,6 +3060,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  		return NULL;
>  	}
>  
> +	prot = arch_vmalloc_pgprot_modify(prot);
> +
>  	if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
>  		unsigned long size_per_node;

I wonder whether we could fix the prot bits in the caller instead and we
won't need to worry about the exec or the module_alloc() case. Something
like:

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d2a00ad4e1dd..4e8c61255b92 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3112,7 +3112,7 @@ void *__vmalloc_node(unsigned long size, unsigned long align,
 			    gfp_t gfp_mask, int node, const void *caller)
 {
 	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
-				gfp_mask, PAGE_KERNEL, 0, node, caller);
+			gfp_mask, pgprot_hwasan(PAGE_KERNEL), 0, node, caller);
 }
 /*
  * This is only for performance analysis of vmalloc and stress purpose.
@@ -3161,7 +3161,7 @@ EXPORT_SYMBOL(vmalloc);
 void *vmalloc_no_huge(unsigned long size)
 {
 	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
-				    GFP_KERNEL, PAGE_KERNEL, VM_NO_HUGE_VMAP,
+				    GFP_KERNEL, pgprot_hwasan(PAGE_KERNEL), VM_NO_HUGE_VMAP,
 				    NUMA_NO_NODE, __builtin_return_address(0));
 }
 EXPORT_SYMBOL(vmalloc_no_huge);

with pgprot_hwasan() defined to pgprot_tagged() only if KASAN_HW_TAGS is
enabled.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbjQNdst07JqbG0j%40arm.com.

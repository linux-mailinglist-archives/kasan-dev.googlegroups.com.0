Return-Path: <kasan-dev+bncBDZMFEH3WYFBBHU263CAMGQEN6C2T3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 564AAB25CD9
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 09:15:49 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32326e2506asf671594a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 00:15:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755155743; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZcI+BhOTBuzJyp8SiXXLM49Dm0ySNWO6bUK+q+OBSeA8ALyrpSNNRXUTmbg2EdvUJd
         tnE9e76pNv2DBPcJHZ1ld3wI3wjrFK6bSScYxTSS5n+JNBp+xsBHUZPAOniUUevRKlD6
         mw9GQKulGn5X5T261dJSGsw27yZMWcmFuAVeko7HpK5+E3NEXawQ6aFPIuHfcDkl4E3B
         MqbDM3CosihiV5eJTfuEmMnQYSaYA1kQBN+8loWUICjzQ/SddstOPk51b0z02GR866Hf
         0PmuWLB1u9XEedZnHVCX13QkPCpt+kbdvjJ/utX0tI9U9HzsfMCDBg70FZidfO4C4zBV
         UFSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yn6oOdEWBY3H+70CY2Dc8WI5EAbOoKt2bqRfBprGJI8=;
        fh=3qlhKJTArBxs12sbQK1uJ5fkFbafpKSK1TWV61EVNqo=;
        b=iVYypwpXJnxSGU3pYAFS9eJ6vytu/nSd21jVQn0Ac92KXZh/d7KN/HPdl9t/6zYh9F
         AwGVpqz9ajAlViY2O93kO2SUhQQW5Ece4nXNGzcw/fhBZOvD2TEydKmFkqXRlnE0oVRc
         QFxxHNJn3eFppUVWoPPa2r02NT0FB82iAmnEMdAceTvb/pXKlbo1kyteeqA4XWZgw3fF
         Ff+duaoZ60YGm200ckQgf4LM4nDomSdnNw23PDecbikKNFNYCsuQCve2nEKfpqAsloGt
         xnXOGSa1zwb/vJ+jqHymhVVo1EzzZqAuRlaxlQVnVXHvR3ALLnzoHshYWiDX+I7ozJf1
         9rBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1IKT2zw;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755155743; x=1755760543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yn6oOdEWBY3H+70CY2Dc8WI5EAbOoKt2bqRfBprGJI8=;
        b=ucZSa0hcatrg1qJK87uO/krFoj0Z20mkxskQVbCGgLBGnX+yPfjgjSpRr5+SZaP38D
         63wQgnbbEkNqJnb9v+Sau2Es4wYy1IZT4nxjA5RayvDM53Q5JWjBw5cqypQHVVnxEcmz
         rRxAleXEcYuEnzHYAJs3oDut78o5bPAIoFjmxK4TON03KAASqMDX9koCO4SCULncOJ3+
         dp5fxDw0hH7LC8g52QugYR2EJuknhy16ZBB/V0ATvUrcacs0GtZnJgmhUMQnquFA2zhR
         tlvoS6OQLjtAyVJDC00y1gdeWwyccRcJ1do0CcEmWA5itccWSeEYKlDFO09i0nX2zlNp
         k5AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755155743; x=1755760543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yn6oOdEWBY3H+70CY2Dc8WI5EAbOoKt2bqRfBprGJI8=;
        b=n/cnijtR80BIS645UfHz/knaGf82IhQf68KEgiYYhs29eFuEFDTnDU/+2u0G2s8W6j
         udd3vN9ANDcNY6AXaqzuSc4A8LHA5AvkIDmjRdOEulxySvD+Rlzi9Rmz+GEmhvB8Xk+6
         N9kCXMjje6qpa4Okflw4jgmCHLM9ZMZHgQrakRXBEjW8HTOZbrejENks/livwVuzCBjU
         jiiEingIGFK2Np8HBoiQVttSWEIpHnpSNRGMP9wlDCW0euaDTYFiSCEpUcMD3SGFL8XU
         Aw7tUvygddP1jobCzLHsdb3EmV9eutWkHkNoTHjYoa/iK32/rbW78NC5Uph0EddvthgR
         0H6g==
X-Forwarded-Encrypted: i=2; AJvYcCVs4uquNAr6W5Y3gD9+d4tvoeCJSTAr8lLohSvNmnHPPNpCt898hwybBCjg19pyjzsk90RDyw==@lfdr.de
X-Gm-Message-State: AOJu0YxZxsECca9q9tYUGStNBbJSkHO9cM8j4wjeIWLM7x3VdbuPMI8o
	LrCshkiEnyllCPCX/ohPS4hsIV6g6xhv1upP752S/gRrI6Q6dY1NMf0x
X-Google-Smtp-Source: AGHT+IGptWXDkzIp5sPem4K6aaZWu05HSXGPEwYLYMMd66C01CU4sGXIaDDsWrGhqQDkX9BcyJWOrw==
X-Received: by 2002:a17:90b:2248:b0:311:f99e:7f57 with SMTP id 98e67ed59e1d1-32327a6ad49mr3184277a91.23.1755155742665;
        Thu, 14 Aug 2025 00:15:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdlrqey9bN9CpE+t/8+dsxd7MnK7Spc9bdayCF75VKlxA==
Received: by 2002:a17:90a:1050:b0:31e:cf05:e731 with SMTP id
 98e67ed59e1d1-323265d1a8els504912a91.0.-pod-prod-07-us; Thu, 14 Aug 2025
 00:15:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3ZoMRTOf5EOeYpmKEduZnvLUaV2un0CSWGmEJQ7ahkesqNVrWq/T2rDgwtMvRe9C4mY39Q7p/9IE=@googlegroups.com
X-Received: by 2002:a17:90b:4b8e:b0:321:157a:ee73 with SMTP id 98e67ed59e1d1-3232795b36emr3206943a91.6.1755155741231;
        Thu, 14 Aug 2025 00:15:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755155741; cv=none;
        d=google.com; s=arc-20240605;
        b=JbiFzylSTA+ljSwXQTrgrXoMRcJoPM9+Z973tW0zVPzBmB6evGbA0zDjEAtvZoJW7B
         JeQx86j3NZCoNdLVEss9XtB6b/dhUHR2FRH7O4u58F/7hjXd5mLQj8UtO14F4YMLiRSm
         QgC1v1v8cU28IbImjyABaa/y49Bu5aa4UgayUqFZUcmWsmoylOZjaa3I0GNK4zAYIpqN
         L40ZH881Le2d+132x0fxDdz+7OhSFnbNhfSexBdqRmb1DVe3ETvQPaERrH3XyHqGIPZ6
         20X8YqTwVB9tS6pahqlq01z/Vp0OYsHBRIUliZ8k/6KQ1wMWXYkHQtFQdUZ1TCO8sz+N
         kRaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6l0i4NfoPjd3dy49dR5GfraE/UtvtCZLrPT1jjwn6yI=;
        fh=An29kc1fWHUbq+trOJowZZoCiDy+Kj7isCjoanY75Zw=;
        b=HL6CrWt+tvHtPsytNOX0LRJ7MtmGUg6NXmZEx32EW/tKenqD4iv3bwD0ik8CHga47C
         es/A53l4EzX+Ih1IgKkCoj7jvlzO+acuIsZXAeu31htqNQ5NtfMKPUTQsx5bFW5nZghu
         BFxgcVEF03Zc4TWTZBKUYim3/D78V9xXVkPM+oKe42odnXPjBmWgTOXsm0fIK7W9Y2uV
         P4uE4VOi/0H2BOVuBVSK5TQSFYjGsv7Xz88PfhBVD9aETnPaw5dkJ7I9pS6JRgc89TYm
         aYGjxOaz8GDmc/9piXetrDN8sPh5PB+04b6B5GmAydA2eQfpqNlE4uZM9UMOnHxqwLHd
         HuVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1IKT2zw;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32330da89a7si36369a91.0.2025.08.14.00.15.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 00:15:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 680755C6209;
	Thu, 14 Aug 2025 07:15:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D0A94C4CEEF;
	Thu, 14 Aug 2025 07:15:13 +0000 (UTC)
Date: Thu, 14 Aug 2025 10:15:09 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
	Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
	kaleshsingh@google.com, leitao@debian.org, coxu@redhat.com,
	surenb@google.com, akpm@linux-foundation.org, luto@kernel.org,
	jpoimboe@kernel.org, changyuanl@google.com, hpa@zytor.com,
	dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
	vincenzo.frascino@arm.com, smostafa@google.com,
	nick.desaulniers+lkml@gmail.com, morbo@google.com,
	andreyknvl@gmail.com, alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org, catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com, jan.kiszka@siemens.com, jbohac@suse.cz,
	dan.j.williams@intel.com, joel.granados@kernel.org,
	baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
	pcc@google.com, andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org, bp@alien8.de, ada.coupriediaz@arm.com,
	xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
	glider@google.com, jgross@suse.com, kees@kernel.org,
	jhubbard@nvidia.com, joey.gouly@arm.com, ardb@kernel.org,
	thuth@redhat.com, pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de,
	lorenzo.stoakes@oracle.com, jason.andryuk@amd.com, david@redhat.com,
	graf@amazon.com, wangkefeng.wang@huawei.com, ziy@nvidia.com,
	mark.rutland@arm.com, dave.hansen@linux.intel.com,
	samuel.holland@sifive.com, kbingham@kernel.org,
	trintaeoitogc@gmail.com, scott@os.amperecomputing.com,
	justinstitt@google.com, kuan-ying.lee@canonical.com, maz@kernel.org,
	tglx@linutronix.de, samitolvanen@google.com, mhocko@suse.com,
	nunodasneves@linux.microsoft.com, brgerst@gmail.com,
	willy@infradead.org, ubizjak@gmail.com, peterz@infradead.org,
	mingo@redhat.com, sohil.mehta@intel.com, linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	x86@kernel.org, llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 06/18] x86: Reset tag for virtual to physical address
 conversions
Message-ID: <aJ2M_eKPvBluyLKJ@kernel.org>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <01e62233dcc39aeb8d640eb3ee794f5da533f2a3.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <01e62233dcc39aeb8d640eb3ee794f5da533f2a3.1755004923.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i1IKT2zw;       spf=pass
 (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Tue, Aug 12, 2025 at 03:23:42PM +0200, Maciej Wieczor-Retman wrote:
> Any place where pointer arithmetic is used to convert a virtual address
> into a physical one can raise errors if the virtual address is tagged.
> 
> Reset the pointer's tag by sign extending the tag bits in macros that do
> pointer arithmetic in address conversions. There will be no change in
> compiled code with KASAN disabled since the compiler will optimize the
> __tag_reset() out.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Simplify page_to_virt() by removing pointless casts.
> - Remove change in __is_canonical_address() because it's taken care of
>   in a later patch due to a LAM compatible definition of canonical.
> 
>  arch/x86/include/asm/page.h    | 14 +++++++++++---
>  arch/x86/include/asm/page_64.h |  2 +-
>  arch/x86/mm/physaddr.c         |  1 +
>  3 files changed, 13 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
> index 9265f2fca99a..15c95e96fd15 100644
> --- a/arch/x86/include/asm/page.h
> +++ b/arch/x86/include/asm/page.h
> @@ -7,6 +7,7 @@
>  #ifdef __KERNEL__
>  
>  #include <asm/page_types.h>
> +#include <asm/kasan.h>
>  
>  #ifdef CONFIG_X86_64
>  #include <asm/page_64.h>
> @@ -41,7 +42,7 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
>  #define __pa(x)		__phys_addr((unsigned long)(x))
>  #endif
>  
> -#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
> +#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(__tag_reset(x)))

Why not reset the tag inside __phys_addr_nodebug() and __phys_addr()?

>  /* __pa_symbol should be used for C visible symbols.
>     This seems to be the official gcc blessed way to do such arithmetic. */
>  /*
> @@ -65,9 +66,16 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
>   * virt_to_page(kaddr) returns a valid pointer if and only if
>   * virt_addr_valid(kaddr) returns true.
>   */
> -#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define page_to_virt(x) ({							\
> +	void *__addr = __va(page_to_pfn((struct page *)x) << PAGE_SHIFT);	\
> +	__tag_set(__addr, page_kasan_tag(x));					\
> +})
> +#endif
> +#define virt_to_page(kaddr)	pfn_to_page(__pa((void *)__tag_reset(kaddr)) >> PAGE_SHIFT)

then virt_to_page() will remain the same, no?

>  extern bool __virt_addr_valid(unsigned long kaddr);
> -#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
> +#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long)(__tag_reset(kaddr)))

The same here, I think tag_reset() should be inside __virt_addr_valid()
  
>  static __always_inline void *pfn_to_kaddr(unsigned long pfn)
>  {
> diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
> index 015d23f3e01f..de68ac40dba2 100644
> --- a/arch/x86/include/asm/page_64.h
> +++ b/arch/x86/include/asm/page_64.h
> @@ -33,7 +33,7 @@ static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
>  extern unsigned long __phys_addr(unsigned long);
>  extern unsigned long __phys_addr_symbol(unsigned long);
>  #else
> -#define __phys_addr(x)		__phys_addr_nodebug(x)
> +#define __phys_addr(x)		__phys_addr_nodebug(__tag_reset(x))
>  #define __phys_addr_symbol(x) \
>  	((unsigned long)(x) - __START_KERNEL_map + phys_base)
>  #endif
> diff --git a/arch/x86/mm/physaddr.c b/arch/x86/mm/physaddr.c
> index fc3f3d3e2ef2..7f2b11308245 100644
> --- a/arch/x86/mm/physaddr.c
> +++ b/arch/x86/mm/physaddr.c
> @@ -14,6 +14,7 @@
>  #ifdef CONFIG_DEBUG_VIRTUAL
>  unsigned long __phys_addr(unsigned long x)
>  {
> +	x = __tag_reset(x);
>  	unsigned long y = x - __START_KERNEL_map;
>  
>  	/* use the carry flag to determine if x was < __START_KERNEL_map */
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ2M_eKPvBluyLKJ%40kernel.org.

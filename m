Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPGS5HBAMGQE4OT2Z4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id AE425AE601B
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 11:00:46 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-87632a0283dsf262140039f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 02:00:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750755645; cv=pass;
        d=google.com; s=arc-20240605;
        b=fZ0YLzQBWUSE6wmnn58rJSBLH9ihYy23xei7dDXp4grspWUJlzMMEpxjUlz+IpNmu/
         5IL/RoSij1+JcvSnKGot6ifokJfPPHUUzXOKMhOmDOB4rTb9FlzeidzrzX4Pe0wlfK+v
         kqvh+VoBimPBT1lENjyP4u0RzNYy2yaYk5gwY5ol27M4+2D3CrQR7f3huMz/+sMNVR1J
         Eya/ZOibtIO3mo8sM8roRJAFvHf2VV325mZR87TGIHX6UvcyneZFovM+p7PkRK/t+d/i
         Wv9k7AwrA/ZSsrrK9R2+UEfqqp/sYRuiGcyAciiHtc/E3/9RPvXxgSc3LSaKQMkbDKmv
         Ai8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kc1B1KDuk4+FfySK9Mdd5PLhbDSLycWShqOH8IMtosM=;
        fh=13lhzLFWeSWsSL46qzXxZ2JxWhzZPYfSF6zS6/qdpmk=;
        b=iiMlmWKdfG5zbNTLJy0WyhjPFwLQ/Smgwb92BFr4Oovm4aMWMTv6iqVL2+4G2XgWv1
         wN5agZFDtpFB5AFoGVHsC8v4YF9u6bSln3QpvSP/9+CdyB9X2LQ/WvMGHJycPOgnZk8w
         BSBNC8FL/A10YgV5DI5ulCClDOHux/KqzzvVmTADVA0giAy7VF0Xs64PTaLJctspSdeb
         M9iKJFWzRGUC29cTF3ba4jzaDD2vY35v7LRp3sOwnVnLMTjWJnv/0iFTlBgRLLF84kAR
         UXPPvyQqT3LBrGOaBrIpiA7CubeSoW/+UiscHK45Y8pknE9UKY+TSCoZhAFrpF/4iaGM
         Dy3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750755645; x=1751360445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Kc1B1KDuk4+FfySK9Mdd5PLhbDSLycWShqOH8IMtosM=;
        b=LOKbxgN0ii3I5RR7fU4hsdWu2CP3JgUekxZL9HDDlPoYZrQNNmQMdhEeOK//+x9CXX
         lDnxN2FBtd/CJNWNkzsdVz0FiVwDujz++ENmhmG4dAAWcPT18op9eiaoa8bsXmqNCTq6
         j9rmoKpenak7AYL6Ay8l1IFr6dpNZaZe2q6AL/aBDsZRKK9jCYXbr1SFyWI973+y1Z7w
         8B8XYVGNysotAzm0SXQaWkh/g74uppBTM5Am87Mu9POR7YFaczHvjz3KDD1Z+hrFdvRd
         vDTLYrNWdmcN0yX3CQ8smOTh7hhGHV+nD+axyT7L7Rcj/6N+RgB0FlrXayRH9iiYiBRd
         7gdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750755645; x=1751360445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Kc1B1KDuk4+FfySK9Mdd5PLhbDSLycWShqOH8IMtosM=;
        b=uE/MwfJINjNM67Z6/QQprgHbL0cw8eA7JzT2iOxV+ExGZ0ppIUA+vHn1LGwpRGRj5e
         /TXp+ZQn73pSbWyGdiVV9hzwDgdJa0pJEnnYcRsS6UtQcNNnxcBFC9jXPDsfoOoJhKqD
         V+aVn0HbIyabxaXk9mOhHvI81C8FJlZQZ/GMRdS6LdUNYCyleOxxm1LIxyZ1Br9GtOi7
         37awHzqK4aqErEGoL0g5PPeHDRmK96DOPJPWVtNX8DlkFQ0HFLXk09Tb0vXRcmDz6XZ3
         XOfYhLpbyq/ELogoisfiXn/6DNvFPojeuefjZyw6+d3A7mYzFYAFd3C2QKEIpOBEv6Z8
         kYdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX790JZ6aoua5mPNt60L5fH9ClBrOAG88q+LcVjEqH233Vd7HFbxxmndGed5Oe1ovhjpQ6sAw==@lfdr.de
X-Gm-Message-State: AOJu0YwC+vDpTf9C4HXR4VT4sLgqEsCQwTa64ZLBerQxLdfDX3yMtvt1
	a5c0x8UpgUYMMZIRoWME1gEEy4XDLPw2E/QbxUt3QWJ9bJDua/bUijf3
X-Google-Smtp-Source: AGHT+IE9bfvpx/3ujEdM1dCCvtGO4Xs8lRiFyNjL1Mz/svy/wiTN5lyZPgcwt1LWIkF7qfNB4eKCJw==
X-Received: by 2002:a05:6e02:744:b0:3dd:bb7e:ca89 with SMTP id e9e14a558f8ab-3df289a121amr33009615ab.10.1750755644913;
        Tue, 24 Jun 2025 02:00:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1mnKv6axXOilvMxjqfOHXRJ+vptKMEYc4pbGvEQ1Ucg==
Received: by 2002:a05:6e02:2781:b0:3de:f0e:a80d with SMTP id
 e9e14a558f8ab-3de30a8e30bls33228375ab.1.-pod-prod-00-us; Tue, 24 Jun 2025
 02:00:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqHSGOA89qvJ8BwwYCaxzb7a7YymQ6MBx3Z/QztTCghy++xRY8DvNUNRKcElILY58yTUhldu1ah+k=@googlegroups.com
X-Received: by 2002:a05:6602:3686:b0:867:8bb:4d8 with SMTP id ca18e2360f4ac-8765d2d9d55mr323469839f.0.1750755643694;
        Tue, 24 Jun 2025 02:00:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750755643; cv=none;
        d=google.com; s=arc-20240605;
        b=XWJltZ6QdNyvjylyZaSTcp22eEs6InGJgWSqpMGT9W5TJkOd2OPn7mo4XBP2DM4XuC
         HM1yEiPzuRWzYnqrBXvi2yu9lDxyXFpLod3eAVcm8tDymDdnXQ+TK/VyyQvwSajvQvxI
         0uyM3jSzQqkzMBaVRxaPZU/RoUpeAZvjP0pRc2Op2PTe9B5IfleNw/zz7/dq79+t/M2O
         XEjSTMlYcVjDNuSY15Rw0kj57o2KOgThn+3gRTtc6+vi5ecrbMQWTK2V/Law1SPpleAs
         ECQuh3eLJocT4/5gCCwe5OawpCHx61M/SOcuWHJSORVvhH+/aiaYcqmliqN739DBt+o9
         /T6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Yp5jO+3XqshE99v9cEk3EOttPZ9/nyT0f5i7VRcI51Q=;
        fh=5l2jr7w/NLBEKXHfO6iKMMWjDp0RPHvZqE8MNo299/s=;
        b=l0vfTRVEp1yqnHXgImUrh+Wt0w5CZH6qluXBfAg8UhDmsbmQ6qWXMGgeKw9vSSrM4N
         zXz9lzicYT7EOVzMbd5XpB5QPFyvZ93u8TnfsEoOVCPxqm+TIjDPLicENWYNJduqG1s5
         Slh640D7UxyzMR9ob6UFy72dj3hxlYz2H50TI1DE9UWWN1DJDHCYAF1yF/D0qEqfh1N3
         lRdNr0TTKUhPBn2ofst4uF3xoooNJC3ewZ7UDW9z5Gvxk3NiK5j2KjZXh1dp5Pz8IBII
         P4Rt51LSNGvqE9RJ6VVehcDwy2X8AF+bG73704+HnXnAOwsUdvIsgaO9EevS7NBFS3th
         yMkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8762b65da6esi37745439f.3.2025.06.24.02.00.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jun 2025 02:00:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id F1F61629C9;
	Tue, 24 Jun 2025 09:00:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C9639C4CEE3;
	Tue, 24 Jun 2025 09:00:40 +0000 (UTC)
Date: Tue, 24 Jun 2025 10:00:38 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Breno Leitao <leitao@debian.org>
Cc: andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, will@kernel.org,
	song@kernel.org, mark.rutland@arm.com, usamaarif642@gmail.com,
	Ard Biesheuvel <ardb@kernel.org>, rmikey@meta.com
Subject: Re: arm64: BUG: KASAN: invalid-access in arch_stack_walk
Message-ID: <aFppNmkSrdsbwhed@arm.com>
References: <aFVVEgD0236LdrL6@gmail.com>
 <CA+fCnZfzHOFjVo43UZK8H6h3j=OHjfF13oFJvT0P-SM84Oc4qQ@mail.gmail.com>
 <aFlA1tXXUEBZP1NH@arm.com>
 <aFmHQbpwX4WnR/5p@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aFmHQbpwX4WnR/5p@gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as
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

On Mon, Jun 23, 2025 at 09:56:33AM -0700, Breno Leitao wrote:
> arm64: Use arch_alloc_vmap_stack for EFI runtime stack allocation
> 
> Refactor vmap stack allocation by moving the CONFIG_VMAP_STACK check
> from BUILD_BUG_ON to a runtime return of NULL if the config is not set.
> The side effect of this is that _init_sdei_stack() might NOT fail in
> build time if _VMAP_STACK, but in runtime. It shifts error
> detection from compile-time to runtime

_init_sdei_stack() is only called from init_sdei_stacks() if
CONFIG_VMAP_STACK is enabled.

> Then, reuse arch_alloc_vmap_stack() to allocate the ACPI stack
> memory in the arm64_efi_rt_init().
> 
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Breno Leitao <leitao@debian.org>
> 
> diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/vmap_stack.h
> index 20873099c035c..8380af4507d01 100644
> --- a/arch/arm64/include/asm/vmap_stack.h
> +++ b/arch/arm64/include/asm/vmap_stack.h
> @@ -19,7 +19,8 @@ static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
> {
> 	void *p;
> 
> -	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
> +	if (!IS_ENABLED(CONFIG_VMAP_STACK))
> +		return NULL;
> 
> 	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
> 			__builtin_return_address(0));

We can leave this unchanged to catch possible misuses in the future.

> diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
> index 3857fd7ee8d46..6c371b158b99f 100644
> --- a/arch/arm64/kernel/efi.c
> +++ b/arch/arm64/kernel/efi.c
> @@ -15,6 +15,7 @@
> 
> #include <asm/efi.h>
> #include <asm/stacktrace.h>
> +#include <asm/vmap_stack.h>
> 
> static bool region_is_misaligned(const efi_memory_desc_t *md)
> {
> @@ -214,9 +215,8 @@ static int __init arm64_efi_rt_init(void)
> 	if (!efi_enabled(EFI_RUNTIME_SERVICES))
> 		return 0;
> 
> -	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> -			   NUMA_NO_NODE, &&l);
> -l:	if (!p) {
> +	p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);

and bail out earlier here similar to init_sdei_stacks():

	if (!IS_ENABLED(CONFIG_VMAP_STACK))
		return -ENOMEM;

> +	if (!p) {
> 		pr_warn("Failed to allocate EFI runtime stack\n");
> 		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
> 		return -ENOMEM;

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aFppNmkSrdsbwhed%40arm.com.

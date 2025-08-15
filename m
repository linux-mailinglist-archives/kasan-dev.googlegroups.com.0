Return-Path: <kasan-dev+bncBDDL3KWR4EBRBV5M7TCAMGQEWWH5SJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 91C32B27EEB
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 13:13:29 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce58018esf3647753fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 04:13:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755256408; cv=pass;
        d=google.com; s=arc-20240605;
        b=ctd88FsD24xGoJYbDKqEBNYGW9Ul6urghcyGtvTiZHJLwr7k2m1pXxfF8TSq6fVWu/
         1xVlVi5/8wwwLnl8ruBWus3kCWVH5N1zkJXK/FXa7rxuY0Ao3Phm2fR8uhz+IaDz0SBL
         A6IzgmTKP3Y3464nySGw/Ck6w2X7re5jE9TUb9wmRXjtEBmtK38gSTbKkh29tvmL7vb8
         6jIyHkZJgM0maR6sqZoAqSP/9tp8zVzBw91p5z6xz7+mtCN1apgOeFNMKtgjSQrLgmmd
         at+Y2JD8GCZOdpKs0m9Mv1hjKZNatWmYVhsxrU/+V5HlMFi2H7oJInJITRRa9hr1NdLL
         XyYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=p20UKAeUWtXl1qX3IzVwoctF/tvDJ/1rAx3OaRSE19c=;
        fh=EWKnWCqWKj+ZGk/Zt+hZXXUsiiN+1SBTzP9TtEvJV90=;
        b=kBcg9aD3CFDqMq4c3etRtKNymUcUuLweakv81j2U507ePQ4cIy6rjYNHF6sQbdxSah
         LmtSyD1jMRUVhGg9cR9H+whtZqWmFWAoASBtDye95FxJaCDOm9N5LHNL3y+fXQAqjPrq
         qSx7TSeIhCl65MweIf5K8BDYUpbXiIZMrwV6KBWDcZQf59mEcJnTe0pbg8o6uwktkZ8r
         pOYNLKdLD/tAaDt/mySOqnpAylgNUBeDjRB4QDACmIKCFbdvA3IWAzzCiEi23QK8qacQ
         FWCImIfr5tzfxoAI686HKpNvqO+eSXfmJaSznckSJHSsgaCiEAX72xnOATNvq3N/spCc
         btiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755256408; x=1755861208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p20UKAeUWtXl1qX3IzVwoctF/tvDJ/1rAx3OaRSE19c=;
        b=Kl8MzQFPiwfLnFSQVp3NspBbBaNvbTbCoBI7YqOWoK6GLPsTpUsl70wvXT2Z1yT8oy
         PiYazfs1sbxNP/GIVO6Cw5tdxCs0LvLaSIPnPhv93LksegM/vW8gkJSJ91hn98jNRkId
         TVPLHBivmnKCYNqJ7jlZekeBHzcyFoFrXE7XPtxCSj4LQoSFNFUlyXDPNVbuMOxSVPTb
         +Jrgo489yh8IoLhKuJ5nZKCTTBMNa5w0ISFHY8agaUUi1HGN5CCgX/rMwIq7MUWhFd3B
         Qry+uDrKegSdTxWoi9QBsSqMVmBC7sOyK4rofsppMUPkKRItC1aciOdQz9CLE6Ws5w3V
         P8/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755256408; x=1755861208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p20UKAeUWtXl1qX3IzVwoctF/tvDJ/1rAx3OaRSE19c=;
        b=puf3KOitgMNbos78fV/ee8nq3AYHHB9zFTG9+6GkX4RgLODyevlSv9fuEf6yaDOor3
         I5LTFJAgYeXHcXxanwNjmYns6MOUpFoTqzcU2aM0hKO1IB0KE/2Ha77LnTx05Sc2P2eB
         ovhsUyQ+hXahUDmgCypwRWlVrJjRwE4v51SQ/Oh1FdMqG6HIMPY6AR57p8iSWDyI9BdZ
         YDJjnlKWi1ug8btF3k0oP2vyX6+cxSrNU5c1soH8XOrYRgzZo/2gQ/Zq38u8EhPDyU5e
         YJ7F+/PlwcwhZnz3b3MLp1mUw1FqpH4eFerkdwyxPfPY5omUUcUszQLBEk+OlBIiQU8R
         tycQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkrAHbr9+HQ6y3bWRc532Xn2gly5yeXmh9sugXKM8CE3w2R3XLtJzfPNMBrgOLyZ96sCHwHA==@lfdr.de
X-Gm-Message-State: AOJu0YxK84QznbYjzmKM7DHoMP760YF6iX+Hf+dsIZVZoV0C14Qcyg96
	pvFlCiKVCgRqZepZuwMTCQFPEIvT7uXq/jjFN6rOcXRlYy3N1R2Br+AZ
X-Google-Smtp-Source: AGHT+IHcaRifAIWOL3UDf0NRRYRwmWXfKWmejG/7g3veXjKTBd6QNmDmmahQzRt2Tnjylmvg3kAC9A==
X-Received: by 2002:a05:6870:231e:b0:30b:75a2:a45e with SMTP id 586e51a60fabf-310aaedf112mr863797fac.33.1755256407987;
        Fri, 15 Aug 2025 04:13:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf180BBKc+fE8Cu/BxEWsetV3VhpNr5L0iG7gh5zN6nOA==
Received: by 2002:a05:6871:a311:b0:30b:8494:7c37 with SMTP id
 586e51a60fabf-30cce767909ls716174fac.0.-pod-prod-05-us; Fri, 15 Aug 2025
 04:13:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWHVjSxN6qSMutQhe9n0Xp47xPoQiCCCd+IsrLVDyj8A7OQ54gkrrEZa6V7uqN7BJUsIuibs50OwY=@googlegroups.com
X-Received: by 2002:a05:6808:3a1a:b0:433:ff53:1b7b with SMTP id 5614622812f47-435ec42d44bmr711229b6e.24.1755256406996;
        Fri, 15 Aug 2025 04:13:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755256406; cv=none;
        d=google.com; s=arc-20240605;
        b=kHaXu6Cnw6GhODCnykFgrIOb9XUF0oFHBIQuPctW0zrgUOoGicjN4zP1E/csYr9+O/
         7+1+CDqa/d6gYVK/DbLn0zOG0u8+a1ac2+Dl5xucw7tc9HjoHgju4NrMObRQaL8qHEsd
         C0Ttktu0j6l5xRIN/PqVxSafuXa5U2vjjUtP4l1aOXFoXkINTMpBPF7IwCyDCNwKCx3G
         rMwL7LswNQE2nPItNNRd6P7maJadzKgE61u0+5wqsUG+649RdPbmnL5UV1U+sxBH9INX
         Y0WL6ysJ8aYrDVKk9DXw1sC5TezcC/ddG9/5Cb77HvzGWZ1M1XXLCaokl/mkIgUCxmRe
         AS0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=gbUJHuak2u5MhS/qm2dIicmSf5kMrLrrJoF5h7UvVAU=;
        fh=EzR/B+1KMqNd9XTm1o6Oe7qwChDN7wGXNwHOALRhjRs=;
        b=cVsjfNO+gq63yDflfJLh1M0RdAY3ILyCyPkAqRbv8Ti9B46W8HlY8qfMtPhBnTOOUf
         ae4wG6UDXg+7L4u4O022U3oVtTqNbYNF+9PYLTcY/x57BZzmgkyP/OHlR6Oztuev/Ix9
         tavF3DoJnl20pFLuuKV7fTQR0Ftr5uYdTAOL5qephvnfcmkCmQ2BQv54ngplPrE0hza3
         KsPjLLwkuRR38GRgmfarmvyMs2oqwrWayImDRyXyj7ngLTpNn/IVuVZVFuAOQTG0jkyN
         Bxze3/fjCEh3tinwf1pUbR2gwssWHQX7qwpjRct4dPGkVnzLO9rkqxSYI+uOMfFX8V6s
         Kteg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed264809si28836b6e.5.2025.08.15.04.13.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 04:13:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2547F43A44;
	Fri, 15 Aug 2025 11:13:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 85B8BC4CEEB;
	Fri, 15 Aug 2025 11:13:21 +0000 (UTC)
Date: Fri, 15 Aug 2025 12:13:19 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ8WTyRJVznC9v4K@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250813175335.3980268-2-yeoreum.yun@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as
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

On Wed, Aug 13, 2025 at 06:53:34PM +0100, Yeoreum Yun wrote:
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 2e98028c1965..3e1cc341d47a 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
>  void mte_enable_kernel_asymm(void);
> +int mte_enable_kernel_store_only(void);
>  
>  #else /* CONFIG_ARM64_MTE */
>  
> @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
>  {
>  }
>  
> +static inline int mte_enable_kenrel_store_only(void)
				^^^^^^
This won't build with MTE disabled (check spelling).

> +{
> +	return -EINVAL;
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>  
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index 9ad065f15f1d..7b724fcf20a7 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>  
>  	kasan_init_hw_tags_cpu();
>  }
> +
> +static void cpu_enable_mte_store_only(struct arm64_cpu_capabilities const *cap)
> +{
> +	kasan_late_init_hw_tags_cpu();
> +}
>  #endif /* CONFIG_ARM64_MTE */
>  
>  static void user_feature_fixup(void)
> @@ -2922,6 +2927,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
>  		.capability = ARM64_MTE_STORE_ONLY,
>  		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
>  		.matches = has_cpuid_feature,
> +		.cpu_enable = cpu_enable_mte_store_only,

I don't think we should add this, see below.

>  		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>  	},
>  #endif /* CONFIG_ARM64_MTE */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e773844889..8eb1f66f2ccd 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
>  		mte_enable_kernel_sync();
>  	}
>  }
> +
> +int mte_enable_kernel_store_only(void)
> +{
> +	if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
> +		return -EINVAL;
> +
> +	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
> +			 SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
> +	isb();
> +
> +	pr_info_once("MTE: enabled stonly mode at EL1\n");
> +
> +	return 0;
> +}
>  #endif

If we do something like mte_enable_kernel_asymm(), that one doesn't
return any error, just fall back to the default mode.

> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..c2f90c06076e 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -219,6 +246,20 @@ void kasan_init_hw_tags_cpu(void)
>  	kasan_enable_hw_tags();
>  }
>  
> +/*
> + * kasan_late_init_hw_tags_cpu_post() is called for each CPU after
> + * all cpus are bring-up at boot.

Nit: s/bring-up/brought up/

> + * Not marked as __init as a CPU can be hot-plugged after boot.
> + */
> +void kasan_late_init_hw_tags_cpu(void)
> +{
> +	/*
> +	 * Enable stonly mode only when explicitly requested through the command line.
> +	 * If system doesn't support, kasan checks all operation.
> +	 */
> +	kasan_enable_store_only();
> +}

There's nothing late about this. We have kasan_init_hw_tags_cpu()
already and I'd rather have it all handled via this function. It's not
that different from how we added asymmetric support, though store-only
is complementary to the sync vs async checking.

Like we do in mte_enable_kernel_asymm(), if the feature is not available
just fall back to checking both reads and writes in the chosen
async/sync/asymm way. You can add some pr_info() to inform the user of
the chosen kasan mode. It's really mostly an performance choice.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ8WTyRJVznC9v4K%40arm.com.

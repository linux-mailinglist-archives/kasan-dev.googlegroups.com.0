Return-Path: <kasan-dev+bncBDDL3KWR4EBRBI5CW75QKGQEKBQKYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 34F42278594
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:14:44 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id i1sf1112634ood.9
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601032483; cv=pass;
        d=google.com; s=arc-20160816;
        b=mj91kbYfHv0u9EpiU5Hot88shsmgDlSn37+WyDbqquSRQ6g8NzA5bPDKEqTmCoFQ/T
         MkGqcJT+9Ik1arXDPEd2S3n8mdeLdlWELBSwFX3HW2qaCBATd38C1rmZysg21qEYYvIj
         T9pXaQFeVahnfTm7oyAtSE7c5yGqIPBpf0pR44mbUu2SmNbmadwqlB+rpF6TnSfFk5sv
         NiAiXM7T2C+JiJU2fkElFqAT0209AfViTlxVcENMSHla86UxRWi/WaiAgq2zbvW/R63u
         MrNjbYvfi7pOOzvJR9tX2mZI1KV6sWUDkB2PffAABwKlof5wlDqAdFq51s7vkwWO8xOg
         CtSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kPdfAdyfDNeJxyWt4Vs9dApXR5Jg/SmwPAYEsWiJcQ4=;
        b=OCSQVCqk5OrY2idlyvmmihb296JmwEIMWjxlYM2TlhYKluYjzbnHlN78t7vkVIfdvD
         kXGlzu7XlLiIePcg8rPiAqm3Xw0wRO8DN/OsSeDZGwRDqk3tf7hmR4F55Wuxx8MVPyYK
         jxcSdFbs40sx8I/lhJQKRb6/hbUHVSc2xOLSUUEeCG+oZmCaIuTlSyeibDgOJTYTWtSQ
         effPDmujArRaM5ENqqQsd9CgHHNCHK3CBpoKiKdThCDfEyCLIsU50qaWVroFByU2iwSI
         heNrXktiU2Dvb0DIDyZHOswH5zt8Qa25wLz6jIWl2/PDBUMcVVfEMjzOvn+b8s6onMc+
         fJaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kPdfAdyfDNeJxyWt4Vs9dApXR5Jg/SmwPAYEsWiJcQ4=;
        b=XovX0jxdeF00qHDJo7YnL58jURjO9K33h50uSY/EFlQ7wb4SvGxpKA4SKZartRuW8M
         4f82MEOjIMCdLMr5LZmyrTUP3zKzq5vaB0kehwSVHRMx0V8s5VSmCMt2sc5nIl1yugJ9
         gI6U2axDCTb73TIYBmSIxk9mozKzk8nXlU892B4qdM1ocuavcPIzmhlcUor+8i6QBB0Y
         vz1wYvdCYVR4Kc7NEyPBcjyMESgnV52hnJFS7R1OU7krUeYlgm38eCyHhKdkHkNKU0Jh
         RdJmVp1N9IqOi9J47VXFcmfZZ1JzWwQ0TBTuf2zPOB0170uIRrfK3HikLCQCP9ENHvIv
         yGVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kPdfAdyfDNeJxyWt4Vs9dApXR5Jg/SmwPAYEsWiJcQ4=;
        b=peEts/hPX2d1zrD1PU9JvNbdTLo1uR3MNkYjxZPCJdI7kGjfgPfTyOV+HwSUpscUAp
         NIWjPNUdiyiM/6mLHU9b+qDiJnSma6Nhw150+IH8QaI6hR0EA0CoE0lesUPRwHkAY7ua
         Zvd3xhfcnZa94mzQmLoOXQdB/CVqHHI4pI6tjhaRWzghVaJauHM6Eaer5I+cYQUKfmeF
         oLbUX/eiR9cKmliS4kZo4MlnOb/BxXz5l3sNsDBye0GzgbL3FE1FxniIUnqSi1bZRtXV
         WQ8U49/hZc90eJrVk8kyYMBpT3GIm4VvmelRrOCu9XJ5jXSZQAq4KVos/3F98eOIP+YA
         o9ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532K/05X0GIohZNOj1dq8c/Su1bqPibpQIhmNSJ2l3ZryUslwLnJ
	Rd8G+pJVUbnpV6eStTTSfaI=
X-Google-Smtp-Source: ABdhPJxRsfNcpH9sjbQCnltvOnUticWKTqsG5CDZAZ+H0BcJJuAki4+KDExYvwhRTR+WD9KmoXLdKA==
X-Received: by 2002:aca:d493:: with SMTP id l141mr1265092oig.142.1601032483208;
        Fri, 25 Sep 2020 04:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3a07:: with SMTP id h7ls488470oia.1.gmail; Fri, 25 Sep
 2020 04:14:42 -0700 (PDT)
X-Received: by 2002:aca:4c09:: with SMTP id z9mr1241465oia.175.1601032482844;
        Fri, 25 Sep 2020 04:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601032482; cv=none;
        d=google.com; s=arc-20160816;
        b=BzA/l6s4rcnN30Ol7SbgPbzZ3GgpKkh3+CL0N8odDLcUcwHk32Q82h9URQvw9m+JZf
         owl5BayeS5ZN4R2QXBmDdM/X8/IqLYb/6pJRncx5GGjsaTK/GgXO5hFl83Qanfd3WtvE
         BryvkKPMrS12J2pAcA/m//R7MvRCUBIw9oNQQUFuzN3X1KZRMf+3T041oxM2NdG+SyvS
         ej8halBw2PWslnZnDNENt6sO3MAzzoUAHWJ+dL5BhUDENK6AMky5bMPc/wbpKJVGi8V9
         z5oLAk/VdkvJ/mTZC4WlOFZ9QLK1nXiw1EgaWmT0OH/AyWdD5jdll/2/lU2KqTjapkCl
         AXHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=DEwl8OYpz/PnZ87H0aBOfMmULtQZA1DTF2Apzm/N0G0=;
        b=cIdf3hdQ4aJuNjZDqv/CnYcPXRBIW2o3NPd4hBPNjuFTOY6/SvD4gvVSbYZ9SELaur
         2rRKWA16Dh62LdBCLwuJUq/UUqc/7BZIk+KBXy4Ec0kIadqaufNjWG55tcFtObw9NSra
         UOW2a4W5jsNef1dQ8je4GP9lvpySqmh67c/T52TXCe1w/Hk+eXOSP1r3hNvg5yxPvjp1
         vgyly6tjWwDEGuAGQXMYSWcbomwA8++H24JxMw3Yk4AzPRDdiMcuIz0gwKcFXfhPnEuK
         n86FCtROGZcW92zXOM+BZ/TL50E+83LpPDqguogpkFYXG78sjtmryIjisOD5rKLh4B2e
         acAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l18si116918otj.1.2020.09.25.04.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8777E208B6;
	Fri, 25 Sep 2020 11:14:39 +0000 (UTC)
Date: Fri, 25 Sep 2020 12:14:37 +0100
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
Subject: Re: [PATCH v3 27/39] arm64: kasan: Enable in-kernel MTE
Message-ID: <20200925111435.GE4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <20326c060cd1535b15a0df43d1b9627a329f2277.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20326c060cd1535b15a0df43d1b9627a329f2277.1600987622.git.andreyknvl@google.com>
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

On Fri, Sep 25, 2020 at 12:50:34AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 23c326a06b2d..12ba98bc3b3f 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -427,6 +427,10 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x5, MAIR_EL1_SET
>  #ifdef CONFIG_ARM64_MTE
> +	mte_tcr	.req	x20
> +
> +	mov	mte_tcr, #0
> +
>  	/*
>  	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
>  	 * (ID_AA64PFR1_EL1[11:8] > 1).
> @@ -447,6 +451,9 @@ SYM_FUNC_START(__cpu_setup)
>  	/* clear any pending tag check faults in TFSR*_EL1 */
>  	msr_s	SYS_TFSR_EL1, xzr
>  	msr_s	SYS_TFSRE0_EL1, xzr
> +
> +	/* set the TCR_EL1 bits */
> +	orr	mte_tcr, mte_tcr, #SYS_TCR_EL1_TCMA1
>  1:
>  #endif
>  	msr	mair_el1, x5
> @@ -457,6 +464,10 @@ SYM_FUNC_START(__cpu_setup)
>  	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
>  			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
>  			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
> +#ifdef CONFIG_ARM64_MTE
> +	orr	x10, x10, mte_tcr
> +	.unreq	mte_tcr
> +#endif
>  	tcr_clear_errata_bits x10, x9, x5

I had a slightly different preference (see the previous version) to
avoid the #ifdef altogether but this works as well.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925111435.GE4846%40gaia.

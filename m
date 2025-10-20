Return-Path: <kasan-dev+bncBDE45GUIXYNRBGO33HDQMGQED2YXMXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3308EBF2A30
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 19:13:02 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-430da49fb0asf39853895ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 10:13:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760980378; cv=pass;
        d=google.com; s=arc-20240605;
        b=BT2NQQo7mBRDFB5fXMZ76COJ9BpjFZKAOLSm5NUxWMcfpujn/WOoc8Cqo8TbDuoqqY
         /VLwZfHQOip+TYaP6pOJTQdrBNm8aoBYKSJNWiitotlCebQkXiu4plVCDckRg3RV1tgI
         bI5jIcT7UWHBBosdGmcZtUyPisSTZTmZ9xAAqrvyFH0GFCyX10Ehgg+CYjUMZrZVKCkb
         UOmxyWTXwWC5nPMKUypWXKsaa7HB86AcIJtk/LU0whiS0OdA3Y2DWuL9NgIciQDnotfx
         RtLMVOrSvDvSyjnFPrd0p4Zp+eEKja7OmmZxSuYLP22U1IOYvnWKxq39Nxv7isG1Hj8F
         w0QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=L/PguSWZtHJa/Sw/ehF0w1GqHssoWn7DBO+zy5J2Xdw=;
        fh=y4hnFTr419HfF3QOZhzWaCRcefM8CEwwx5L5m3o4kBs=;
        b=e/+vyuNY1Yh0xWqECwXKnBtsRsxS312kn0huY79KBOy+s87ujRpzbK93v/WFYbl70Z
         pgg2OvdPl2gLZvxOZNdNlxzzCbQCjkMdL72pThl9eNzK9c4wEnvznHmGW2AcD+mtJVPu
         LpfAxgh4WMWcRE4Apot5dWzepW9utjy+SEBXym3Inaf0SDk0HOtQDFxZkA+rInN8vmcC
         UnuK5kBzr8TXj3USamjfxH25NfQhido9/amHcufYBWKGjOkie2LqEVvwxdy5oHpgEgnM
         65PkqP37eoTg75Q71jH58rhQGW1DNe3KJWwtU5y0a8g85QUziekj4PtBHNhiIayYJhHr
         rkWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oaX3Cypq;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760980378; x=1761585178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=L/PguSWZtHJa/Sw/ehF0w1GqHssoWn7DBO+zy5J2Xdw=;
        b=ai5QG4rVfLVlmLCaD8+aZ+8rdk3fffyChiBnk6BhzDtSaW9d6YnSAMiooALzl3yxcR
         IeU7neOTndpONstFbEL/sH8JaEuuJiMEHXVSx9uqeT78LybjZhwUwFRyRDwsdal46e99
         yJlGgGWr6/GaxrFcxyV/td8VkDkb9xjrrU2ULyTMa6rBcIxL5ABhJ+e6MzKbVc8fVd6E
         9ZgzjNkJhjplYUXgSuCaDfO9fK15QQtKpEMfCh0hC/mEKohhjIpovc5L5svH49kJ17wi
         Io/Ll0wJJQhVPww8SvNz7YNl1Z9dRojIvGGc8Io2KV+KMlMV66MosAzCQAX2HptXj9/0
         UInA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760980378; x=1761585178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L/PguSWZtHJa/Sw/ehF0w1GqHssoWn7DBO+zy5J2Xdw=;
        b=wQkE9A7redoKWh+lYGH7wd7juiD4obMFTuJ/Bvb7HcnbEdWUpQCsNqSLfoMQ8IfPii
         o0edsnB/pM+XNaVPxrbrXc56cTVLbB8Ok73WOpEggbP4PkPur97SLTZU4WmYqyzC24+E
         iA1a0qTqWQGnbbhB4jC/lCDekeVADQW19PMn9eGAEMjIKVD+IrtlLXI+xT4jSR6Nuugt
         fuvm4BFaJDWuyCOeAUkGxvW3TRSADBBhEtMVgbwGy/eSE19EedkX+d00TSOqSX8fRVno
         loT2T8dlcoFPpqNtGtFy062ohV3Vh6WyuiS6bJZyNDvynbWJLgzP+8AkhU8tSHMWFjmT
         77NA==
X-Forwarded-Encrypted: i=2; AJvYcCXbZHCm7cNI9vzsN0sOlDE8Vko6E4+N8uHtnYuBEygkeREERZKJiAjHxCf1D2ML4dVJX2XYHw==@lfdr.de
X-Gm-Message-State: AOJu0YwLHrh/bwTTXtjWBP4yHYax+FRMTIBXkqBytcHMYKWCvYE+iYsC
	jbf7CXdSiEcG8qVFTBbAR2AHoJ4UrxbB+zxE0FckKUaRluqZgP0tMvwU
X-Google-Smtp-Source: AGHT+IEIjN5hOSWiXrVQ3hRVgYCeuaLyb9t4uqQUy42IXabOanoaHknqhXyIPt9M/tkqxMMfY2ASGg==
X-Received: by 2002:a05:6e02:1a0c:b0:430:cad8:4610 with SMTP id e9e14a558f8ab-430cad847ebmr180073995ab.23.1760980377807;
        Mon, 20 Oct 2025 10:12:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4tUKcP5Bxe4MLM1krW0Ew8ZBfsVonnzol87PwP0PE6iw=="
Received: by 2002:a05:6e02:1564:b0:42f:2c8d:eb0a with SMTP id
 e9e14a558f8ab-430b7619b17ls44953405ab.0.-pod-prod-01-us; Mon, 20 Oct 2025
 10:12:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcElFtBrXrB9qevwNw9qPH1ysvsvU28URCUB1IW4StC458poLST0RsoDLLjb0RbSCKzVQ2Pdb/a6c=@googlegroups.com
X-Received: by 2002:a05:6e02:188f:b0:430:c7fa:50a1 with SMTP id e9e14a558f8ab-430c7fa535cmr186309895ab.30.1760980376820;
        Mon, 20 Oct 2025 10:12:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760980376; cv=none;
        d=google.com; s=arc-20240605;
        b=H7Gbh54gudTINupm/Lhor1dFuH5Jor69bEGVJjPKNeyloqVE1LjbcdvKNwNlofWEEL
         vdl9nZHjoBjfaoEYENJQudLL2gWGSTgNirtgPG1IJDJkCb9vAUl8pw+j4CTF/imQOV2E
         4zxBAhFSenBicWYofuN75VkQiBErgx+rDCZl/L3jwXceLzXoispd5A1I52c8+JEgqP8g
         lfMrK1BwVXYkLzcrOPcKqfD/GYXoG60jm+FbX/nzyF1HDwnST9SY5YuId8nd0T4SagD5
         e0jduFzF5wTCRD/r0Q8GVFVm+Y07aYnpbiS4hvERkXfA0Lk5HbdHSdf5HIa38YXVU+xD
         zbLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=q/66rxPnbpYQFlS+dv6XaKdv0wxHBu0ZyFSkv14gaLg=;
        fh=2I6TuXMYcRNNrCjn1jRpbuD9zai3uxO6fbJLk4U/BhY=;
        b=Sh/htV//vkGait+PNqjiePz36EolDoidPjHyKnbdsD3miaM4r1dSxI3J3kX2tXGyNS
         9SxcBNjimzJ4hYNfSE8p3PfCIe00I1jLPWShWjAKmfYArpxss7hI5Q+nEwFT+uW4rQBm
         8ntxvrn+EwQWGCil5m6S27K2dyAbnZNEubjF8Fz10ayWJeAJe1xa911FLR5ZJtIQ/l7V
         7deA3UuyWWZ4zdvCtKLM6fL8yZ/Gg1RIVo0zWi+9SdnndcoLbhFiSASgjgdkqaT1qH0a
         ST1Ze1RYQd5LqYbgcyDVQSxiSCXzNkiNY0rC0vCZQiArFugUhTxJ3/ioMIXAbbQFCBzl
         irYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oaX3Cypq;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-430d07bb12bsi6448575ab.3.2025.10.20.10.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 10:12:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 04451602AE;
	Mon, 20 Oct 2025 17:12:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9F140C4CEF9;
	Mon, 20 Oct 2025 17:12:55 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.98.2)
	(envelope-from <maz@kernel.org>)
	id 1vAtRF-0000000FaSv-2Qhv;
	Mon, 20 Oct 2025 17:12:53 +0000
Date: Mon, 20 Oct 2025 18:12:53 +0100
Message-ID: <86h5vtwl7u.wl-maz@kernel.org>
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>
Subject: Re: [RFC PATCH 14/16] arm64/insn: always inline aarch64_insn_encode_ldst_size()
In-Reply-To: <20250923174903.76283-15-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
	<20250923174903.76283-15-ada.coupriediaz@arm.com>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) SEMI-EPG/1.14.7 (Harue)
 FLIM-LB/1.14.9 (=?UTF-8?B?R29qxY0=?=) APEL-LB/10.8 EasyPG/1.0.0 Emacs/30.1
 (aarch64-unknown-linux-gnu) MULE/6.0 (HANACHIRUSATO)
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: ada.coupriediaz@arm.com, linux-arm-kernel@lists.infradead.org, catalin.marinas@arm.com, will@kernel.org, oliver.upton@linux.dev, ardb@kernel.org, joey.gouly@arm.com, suzuki.poulose@arm.com, yuzenghui@huawei.com, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, linux-kernel@vger.kernel.org, kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, mark.rutland@arm.com
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oaX3Cypq;       spf=pass
 (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

On Tue, 23 Sep 2025 18:49:01 +0100,
Ada Couprie Diaz <ada.coupriediaz@arm.com> wrote:
> 
> The type and instruction checks cannot be made at compile time,
> as they are dynamically created. However, we can remove the error print
> as it should never appear in normal operation and will still lead to
> a fault BRK.
> 
> This makes `aarch64_insn_encode_ldst_size()` safe for inlining
> and usage from patching callbacks.
> 
> This is a change of visiblity, as previously the function was private to
> lib/insn.c.
> However, in order to inline more `aarch64_insn_` functions and make
> patching callbacks safe, it needs to be accessible by those functions.
> As it is more accessible than before, add a check so that only loads
> or stores can be affected by the size encoding.
> 
> Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
> ---
>  arch/arm64/include/asm/insn.h | 24 ++++++++++++++++++++++++
>  arch/arm64/lib/insn.c         | 19 +------------------
>  2 files changed, 25 insertions(+), 18 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
> index 44435eede1f3..46d4d452e2e2 100644
> --- a/arch/arm64/include/asm/insn.h
> +++ b/arch/arm64/include/asm/insn.h
> @@ -717,6 +717,30 @@ static __always_inline u32 aarch64_insn_encode_immediate(
>  
>  	return insn;
>  }
> +
> +extern const u32 aarch64_insn_ldst_size[];
> +static __always_inline u32 aarch64_insn_encode_ldst_size(
> +					 enum aarch64_insn_size_type type,
> +					 u32 insn)
> +{
> +	u32 size;
> +
> +	if (type < AARCH64_INSN_SIZE_8 || type > AARCH64_INSN_SIZE_64) {
> +		return AARCH64_BREAK_FAULT;
> +	}
> +
> +	/* Don't corrput the top bits of other instructions which aren't a size. */
> +	if (!aarch64_insn_is_ldst(insn)) {
> +		return AARCH64_BREAK_FAULT;
> +	}
> +
> +	size = aarch64_insn_ldst_size[type];

Given that we have this:

	enum aarch64_insn_size_type {
		AARCH64_INSN_SIZE_8,
		AARCH64_INSN_SIZE_16,
		AARCH64_INSN_SIZE_32,
		AARCH64_INSN_SIZE_64,
	};

[...]

> +	insn &= ~GENMASK(31, 30);
> +	insn |= size << 30;
> +
> +	return insn;
> +}
> +
>  static __always_inline u32 aarch64_insn_encode_register(
>  				 enum aarch64_insn_register_type type,
>  				 u32 insn,
> diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
> index 71df4d72ac81..63564d236235 100644
> --- a/arch/arm64/lib/insn.c
> +++ b/arch/arm64/lib/insn.c
> @@ -42,30 +42,13 @@ u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
>  	return (insn >> shift) & mask;
>  }
>  
> -static const u32 aarch64_insn_ldst_size[] = {
> +const u32 aarch64_insn_ldst_size[] = {
>  	[AARCH64_INSN_SIZE_8] = 0,
>  	[AARCH64_INSN_SIZE_16] = 1,
>  	[AARCH64_INSN_SIZE_32] = 2,
>  	[AARCH64_INSN_SIZE_64] = 3,
>  };

[...] this array is completely superfluous, and

	size = aarch64_insn_ldst_size[type];

could be replaced by

	size = type;

But that's only a very minor improvement. On the plus side, your
approach definitely makes it impossible to add a patching callback
using aarch64_insn_encode_ldst_size() in a module!

Thanks,

	M.

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86h5vtwl7u.wl-maz%40kernel.org.

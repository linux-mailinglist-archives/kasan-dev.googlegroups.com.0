Return-Path: <kasan-dev+bncBDE45GUIXYNRB4OP3HDQMGQEEIU2I2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 974FABF2829
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 18:48:51 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-78117fbda6esf3914356b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 09:48:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760978930; cv=pass;
        d=google.com; s=arc-20240605;
        b=bmvo42Xa2NZDL2GC81l2533Cbf9JPgxGUPbQr8cheYHFhJZ+yGmtWnsc+S7XApOphi
         YQRLGNFluUquPBR/UQWRRgj/7GIcUo7Yuib4KLzfwP2lEuqF0HcJlSaTetHE9dhWs0EG
         wme4bnLkCw32oel7Ay3FeIYZyJvMRyHeckcgERsC9mWASqKbmgZdlEGEPw6IXCbko492
         rTSHPR48moDKYDQ5xXMw/R4T7AgGFksOMtwg4MjdZFdgKc+E+cUMPv4K7eu75Q31D9OM
         j+jV4cfbU0x/Rg7xKRbT/V8i71gCkUJ+7UTUbjK7FKkHyRkyT/Zcz8W4cNCUSMTxkBH/
         pT9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=QdsXO3SP6M1/rNMdFIXLKHSLDisiiaDE4gyX4eRiC/w=;
        fh=F2+qr+GXGemCn4wac9TvJlVjVE4GXreCseNfiInG0Xc=;
        b=K+Yqua4II7mau1xl1p5uATm8t2Ni6rdwM2it5riXXG02D99VTpTBZa/7fPU+J3OVXU
         /EEhqY80hzID9/8Zv77i6GbP39e4DwCk/scA36tecrfSg/4VHdLggsJS3OT89arAcKUa
         UTW8lHBSRpdkoU2mxa5bi/IQqmsrIbEv35X4c5c+lgtbULkX9IqCQ9GHAvvAtf7SPqyH
         /dFnS1BMd7F1ymEWVGT9Grds5IAPJtrDL1z4aeQsU16xm0e+uH8WrvuGizTGYjDCoMAV
         KjwTLYeimM94HpkutwCw3R6z+wr5hbn4+60VLRRIZfz+ATmlP3upoab+n47/tCWQRuUB
         l6Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dYg53VZA;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760978930; x=1761583730; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=QdsXO3SP6M1/rNMdFIXLKHSLDisiiaDE4gyX4eRiC/w=;
        b=C9ZMv9knwfaXz6o+PFSomMhdDQW+Mh2FvmhldJYbYurD9i1zgDaKiPzQtK3dzvjBt5
         Uk0QV63dRPCBAFWHWO6MBuY3Q9aR83h8tdH8P4ZmnWId1YTLGL+yGue97bTdEfun4Wg4
         RtTYVNI+CmttyCZyemif+zRtFyu6i6tgVX/ajaZrfkih6GxwkFDlGEK0Jr21CEnt/kO/
         wv/ceO62PNFj+0xf5jb2K9JnhGYtLtYR9WnITPVdHXV96XrvYTf62yrErYQg1r2gKQVM
         G7hOVO/wrLojkt44e9zLIKwCetL8cMk7cUtds8cEmTuldTRJ/ZpO4c8/zwFRdtuwLrSK
         vYVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760978930; x=1761583730;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QdsXO3SP6M1/rNMdFIXLKHSLDisiiaDE4gyX4eRiC/w=;
        b=ehVm9ZzSfyS5XIfj6LPEBU3XLXhAZnhf4JzV2T7XrN7L6Y+yjt4WeG8cu3NY86Q/go
         EJNdFaq1bX/fiUgrgaZUyptR37hnlnDmQ+M+MaEUKMCxZv9jhT/RdeAP+9a3eM527/Q/
         FYPttehVSz/ClsTZOm/rx81fs/CqeeVzzTFJqfrueG8pzDNdwF+4KbYtxqXZuGAUfv2J
         0ytj5FJFejXZwPXyxl2nLqTn6pGcnjggUh952BjlJ5pyU5l0Mq7onA+HAOa9LikEP150
         4nlK4oYdBE6jZcE4M4nVummcD4sUChENcAkLYoaikUGyG/umNCcMgqOqNMIOfLDfPOqL
         1plQ==
X-Forwarded-Encrypted: i=2; AJvYcCUQW5CbB67+d09FPmwKd2L/7k7NODrFfE2iejybR7O9YZZ8MewfZ/a0BiOeA1foZZbeK0zfKQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTAzVb8qWtpe6qb/GLZg5DUtZqvNHV6AxdPU8uAOSwkT9Vm2Sx
	dSDX3UvHaBh5r9TUFvJBrF6TvtEdJr7xyEm7JhLR2LfpcdP/JCNoLS2q
X-Google-Smtp-Source: AGHT+IEQpFTpm5xezfzPZdG3xnA1QU8R4zYOtnicpNVBbNvyQhjIWtUR9GdomeYxA+Bb5amyQu6YCA==
X-Received: by 2002:a05:6a00:188b:b0:781:2757:1b4f with SMTP id d2e1a72fcca58-7a2206eb750mr14944654b3a.7.1760978929919;
        Mon, 20 Oct 2025 09:48:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd56f6D3JWBGHLTXI406Xv6yCJQdfxN9sIXFrBGzV6LOQg=="
Received: by 2002:a05:6a00:999:b0:772:445b:19ee with SMTP id
 d2e1a72fcca58-7a2154faec9ls5701276b3a.2.-pod-prod-04-us; Mon, 20 Oct 2025
 09:48:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXx2GM/mYH9FpJyc2geqG8vTweunjkA1YgTW2wXvT2sz4lZXfaj3lQZB3+EqN3jFkOhZMchNv3/Xnw=@googlegroups.com
X-Received: by 2002:a05:6a20:9144:b0:2e4:9004:530c with SMTP id adf61e73a8af0-334a85244a8mr18330404637.17.1760978927114;
        Mon, 20 Oct 2025 09:48:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760978927; cv=none;
        d=google.com; s=arc-20240605;
        b=Nzmg/Bqc6DtRCD4jXhq0dZLdnOR8xGgUKQYBvUhz4vS0tAJcE7lTY2xgIDh1eFrxeG
         kSL3wVHnO0Jq3GeSnomcuxTwaQysS2SiM8gDW0BaiTBYcN9Zs/SAhb0t6RjLKoRtPVdn
         pZbdaPKo/UB7pFa+m0JIeX4CI0hqCpX5dvII05yCjOeYurzf9JNjcj3/PIouhRkLr66Y
         xeaRqyEFPhaGmdPhTpNaY3u4A+1HRJ0T28BR0DvmpZ+wQddTOHpy7nkAnVrtfawkpGNs
         m12cBFrOxex4h4tyQ6QbGHINCnngpFCrGRmaT5uJJTQHNeofzt3flKURY6H+mjl5UcJL
         Z1Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=d6IPdS54ifgnZZpZCpTxK7GYvPHyc0glLc5M14AzolM=;
        fh=2I6TuXMYcRNNrCjn1jRpbuD9zai3uxO6fbJLk4U/BhY=;
        b=WZ6wZXjyyCsVFVKvSQX2uPl55CAWp89Ijf6t7GKK26zvptY9kfjDvDzGs56WRryZg1
         KCPvNYw9JI8MRsM0PRFT+58AFwpykl6WldHH7O0cN5MPPWYGL49A4z0npyK3ylLmSiQp
         z9yZnMWPu/kYn5McLDgymFbTonHjpllIdTsBuCOPnHKUJUIZvUduRKgH1mIJK60d4fyL
         /fQCIUbA7aod6jeVcliDed94FvbzKKfFtfpnqY0zXgrALWmKgydprC9gMjmXZRXBSJT2
         G3X2u1QW6taeOMZ3EXH38NzN6r8XwwNX5/Zzbiz10jVG+92uT4I0XVffrlYk3TgqC11y
         EtKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dYg53VZA;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b6a7644f4cbsi653813a12.0.2025.10.20.09.48.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 09:48:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DD052434E0;
	Mon, 20 Oct 2025 16:48:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B245AC4CEF9;
	Mon, 20 Oct 2025 16:48:46 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.98.2)
	(envelope-from <maz@kernel.org>)
	id 1vAt3s-0000000Fa00-1car;
	Mon, 20 Oct 2025 16:48:44 +0000
Date: Mon, 20 Oct 2025 17:48:43 +0100
Message-ID: <86jz0pwmc4.wl-maz@kernel.org>
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
Subject: Re: [RFC PATCH 06/16] arm64/insn: always inline aarch64_insn_gen_movewide()
In-Reply-To: <20250923174903.76283-7-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
	<20250923174903.76283-7-ada.coupriediaz@arm.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=dYg53VZA;       spf=pass
 (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

On Tue, 23 Sep 2025 18:48:53 +0100,
Ada Couprie Diaz <ada.coupriediaz@arm.com> wrote:
> 
> As it is always called with an explicit movewide type, we can
> check for its validity at compile time and remove the runtime error print.
> 
> The other error prints cannot be verified at compile time, but should not
> occur in practice and will still lead to a fault BRK, so remove them.
> 
> This makes `aarch64_insn_gen_movewide()` safe for inlining
> and usage from patching callbacks, as both
> `aarch64_insn_encode_register()` and `aarch64_insn_encode_immediate()`
> have been made safe in previous commits.
> 
> Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
> ---
>  arch/arm64/include/asm/insn.h | 58 ++++++++++++++++++++++++++++++++---
>  arch/arm64/lib/insn.c         | 56 ---------------------------------
>  2 files changed, 54 insertions(+), 60 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
> index 5f5f6a125b4e..5a25e311717f 100644
> --- a/arch/arm64/include/asm/insn.h
> +++ b/arch/arm64/include/asm/insn.h
> @@ -624,6 +624,8 @@ static __always_inline bool aarch64_get_imm_shift_mask(
>  #define ADR_IMM_LOSHIFT		29
>  #define ADR_IMM_HISHIFT		5
>  
> +#define AARCH64_INSN_SF_BIT	BIT(31)
> +
>  enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
>  u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
>  
> @@ -796,10 +798,58 @@ u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
>  			      int immr, int imms,
>  			      enum aarch64_insn_variant variant,
>  			      enum aarch64_insn_bitfield_type type);
> -u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
> -			      int imm, int shift,
> -			      enum aarch64_insn_variant variant,
> -			      enum aarch64_insn_movewide_type type);
> +
> +static __always_inline u32 aarch64_insn_gen_movewide(
> +				 enum aarch64_insn_register dst,
> +				 int imm, int shift,
> +				 enum aarch64_insn_variant variant,
> +				 enum aarch64_insn_movewide_type type)

nit: I personally find this definition style pretty unreadable, and
would rather see the "static __always_inline" stuff put on a line of
its own:

static __always_inline
u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
			      int imm, int shift,
			      enum aarch64_insn_variant variant,
			      enum aarch64_insn_movewide_type type)

But again, that's a personal preference, nothing else.

> +{
> +	compiletime_assert(type >=  AARCH64_INSN_MOVEWIDE_ZERO &&
> +		type <= AARCH64_INSN_MOVEWIDE_INVERSE, "unknown movewide encoding");
> +	u32 insn;
> +
> +	switch (type) {
> +	case AARCH64_INSN_MOVEWIDE_ZERO:
> +		insn = aarch64_insn_get_movz_value();
> +		break;
> +	case AARCH64_INSN_MOVEWIDE_KEEP:
> +		insn = aarch64_insn_get_movk_value();
> +		break;
> +	case AARCH64_INSN_MOVEWIDE_INVERSE:
> +		insn = aarch64_insn_get_movn_value();
> +		break;
> +	default:
> +		return AARCH64_BREAK_FAULT;

Similar request to one of the previous patches: since you can check
the validity at compile time, place it in the default: case, and drop
the return statement.

> +	}
> +
> +	if (imm & ~(SZ_64K - 1)) {
> +		return AARCH64_BREAK_FAULT;
> +	}
> +
> +	switch (variant) {
> +	case AARCH64_INSN_VARIANT_32BIT:
> +		if (shift != 0 && shift != 16) {
> +			return AARCH64_BREAK_FAULT;
> +		}
> +		break;
> +	case AARCH64_INSN_VARIANT_64BIT:
> +		insn |= AARCH64_INSN_SF_BIT;
> +		if (shift != 0 && shift != 16 && shift != 32 && shift != 48) {
> +			return AARCH64_BREAK_FAULT;
> +		}
> +		break;
> +	default:
> +		return AARCH64_BREAK_FAULT;

You could also check the variant.

Thanks,

	M.

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86jz0pwmc4.wl-maz%40kernel.org.

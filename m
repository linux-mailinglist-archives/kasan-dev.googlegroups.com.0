Return-Path: <kasan-dev+bncBDE45GUIXYNRBNOL3HDQMGQEARYH4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D64A7BF27A6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 18:39:19 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-430c523ce49sf42707575ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 09:39:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760978358; cv=pass;
        d=google.com; s=arc-20240605;
        b=YQkLHKBBnM/P1CNR4vV0vqCLdTo0UQFqPyAKGn/77zxRI9XLrnQpwTJMXwbeMGNWQw
         vColorOFIYCoIU3TTUPZJ1OheiQTaizY+n0gEp2QxeOyLWN4FWHlmGndfLkURE2zcq6F
         Fd3Um8EauAHBJGjpHwv12W5ZG8bcahmIDMULuW43C1BsNKp+SK+yHYnhOMKKprYTm4Bb
         X5tn2SBps254jaz+a37wf7Fg3IVxo1CImqUYxlnGY/Kby8a00h3DJyHapcpOwYWig50U
         thz06zer1zFHUJLbrqRpVbFCkdEdeAJssbA7AztbxmA7LAETK8LKz4vYRS+lgAu3elk+
         BN/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=5Mu+j97D/bci+q3GjODPGlS6UEKRr2I8Wth/96tcyPY=;
        fh=UgzfNJq5pavJDesJeKI7Okvx6eJ//ui7eIBv7oc2G4c=;
        b=lSuVj/PiIUOik839jocZVmHLg1thnplBBv3E7neJYiAOE3y77LEJNMJacM6Ams8IMz
         8rUqOiGPeRR7m2uxNwiMN9UXVxcCOAg1XDn832OAIwEPi/SE6H2NobfFUDvTEQvY9zxC
         cpLnyn/4auUB8iuRw6wCroCEaha+RaqspWDQBPuBgB5K7+C9s/2OxpJIWaO1hD6FgbsA
         aIopGolLmUfsVi8JGwgqUCvcF9kvE4FyJ1f7cBpZO+W00jlPm/jllaeiGeZCOZwYb/zc
         cbEb4Slh3t9XCYmgLYuPtbkFOq+xGPBoWGjqv3KAIpJbGryL300dvCWfDvHJwq5hnKFq
         hNHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQsMR9Ok;
       spf=pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760978358; x=1761583158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=5Mu+j97D/bci+q3GjODPGlS6UEKRr2I8Wth/96tcyPY=;
        b=fvmnCJ/LgX9qAN7CXU/s9JaGIUS7aLK+SALwgcqm5tEbHtOohD6k4CIM1cAAjWFOcj
         E5nzYE4slVpMWoTjmj5olYBs8kH8bfA68+x5zIM/xDyaYyGlAD2tNwZQ1+ZZmDBKT7+U
         OKXPjM7erojRq9Ty3oClv1pHfzNoE59NKdwp0kpZmNCERHEfsUVbZnUMJ88ePWL66Sh/
         fZ2wk7B2kBaGf9V/2Bs/Lx9mRYf8o6HelHmN0zjvMufdt6nnjtsC9BjLqupJYWJQuf+6
         X96Ma0TLz2ESYfRd3UpJYNAyqBwvFmeP6tjG9YEetBdihD32xYvzgVTJp+S28yUDlO9f
         3gJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760978358; x=1761583158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Mu+j97D/bci+q3GjODPGlS6UEKRr2I8Wth/96tcyPY=;
        b=tiH/5MICiKg/VosEbOBtiVlAywAlh1jWkOVb/dd/RWfWfDU+JDNXD1w3rVytM/WVRs
         hqEVSYdQ4Cd/LNJ5an5dn0AcyzJn/eVVjeRwkH0pJij8mPcVgnE5ERusaWkU76iF4EId
         osZy+y7A+9wHMbynDuGRWeNFUSCFRDJWHDJ+JdniGQqtvVll0BjK3a3s0htDGBhVInbf
         nWNqb88p4Hbod8M2n1tnO8qpfjr2pWRU/ImpQjUA01/BLjt1KTzK7mBCbPgfmN3xfFMA
         Uk69uwIAkhkH6W0aLivnLtw3xb0v2nLn0U1gK8Lm/ShDba59zY4zqdllS1vPkrAK7+q+
         GfAQ==
X-Forwarded-Encrypted: i=2; AJvYcCW3J9FLOasrS/QiXzdXgB6WQHYC8Aj6HQzGFd+7Eszblo1ScqPIT1AVxIPGxKggmG0WPZhqkw==@lfdr.de
X-Gm-Message-State: AOJu0YxLLoT4ipw2T9oKLwssvRSabNuvtbRBQaAngNNuQOESn5uNut6Q
	mNk0/gPWAWEBdVQ75gzrMLCaw6incBK2rbkUObcZE80+nGnrsp0kFmcf
X-Google-Smtp-Source: AGHT+IEoIV8rmmgtg66cHbkchzFMlys7z5l4ORNkZm2t7k+q1/nmya4k59HCc3znBBXjmva/uV2IOg==
X-Received: by 2002:a05:6e02:3787:b0:42d:8b25:47ed with SMTP id e9e14a558f8ab-430c51eb7d1mr212691495ab.6.1760978358244;
        Mon, 20 Oct 2025 09:39:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd591awJjqZNBiRRpx0AJeDqliUHK5WLMEMeWWB6y5p6tA=="
Received: by 2002:a92:c704:0:b0:430:b5ef:868d with SMTP id e9e14a558f8ab-430b76faaafls36441645ab.2.-pod-prod-03-us;
 Mon, 20 Oct 2025 09:39:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQejroc7rVMjCZbue/lZDo6nj1RQaI3KrN49/y0HDkDdKj28/PbHXerpXyiv5IkMOTzWfR3qqTVQ8=@googlegroups.com
X-Received: by 2002:a05:6e02:1745:b0:42f:91aa:510b with SMTP id e9e14a558f8ab-430c51eac3dmr182553955ab.4.1760978357080;
        Mon, 20 Oct 2025 09:39:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760978357; cv=none;
        d=google.com; s=arc-20240605;
        b=Sx+xRjIQH3nhMQ6N/S44gUMRm9/CEJCAYDynk5MD8CsRT4GdPCGT/ktwIjmNEoSGgn
         T655TKRkqjuf8Ww9AL4ce0Y/jLyPTdc1QqId5nau5awvXhlDxNXzNTMsb2FG50dl51p6
         inqs9RQU9U0wczDIIK1nh1nuSRNMt6vCPvlDn4e33W/dm18kEOrty7T7xR1Z+17dm0ve
         Dyurm5Fsb8JO0/u63JJGSvqEJIueTDf2l5EhUCXtAnP26ikidNjsqWJernlgOxx+ZVUh
         1C9SVBPKzmhoB4kll4VHbT3SnUCXsNLWORZnqD/iXuTkO6VfRRAkVC3tgRV4jOF29y4W
         m/rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=ljgwGTyHDyNrzUm2wfSApTtDIUOkOST1fBvM18Ofiu4=;
        fh=2I6TuXMYcRNNrCjn1jRpbuD9zai3uxO6fbJLk4U/BhY=;
        b=h4sf02TBkHd62d7kq/iLICkbU731jLYr2KA1+2RL98/xhJwpWTADyGeksy7i/tZiTw
         arRDyBbjoYhasmEiBFyvE+t0DOxQkMTw1UuAF88BR8X0stqZUHmFoGVse6g39SYsMN2E
         VirF33sA4STq+HMl+z0jzswY8hO0HhwONm1nYpKcMt/keO8IfQMHjvv64WeDfdKqufhz
         hEL6akSk1LvgGi91IJBKeSIq5J0wz+Mvj8QwPqdQTD3ykVXmKta7OVNcCEy7eCIhEv54
         OYWSu/uV4dnBWnNzgiO1LOdAW0PPPWxrUDiaNE8iS2VUaHd8NVIC+yRmoTAygYmxd3WD
         aYpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQsMR9Ok;
       spf=pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5a8a96e1150si340294173.4.2025.10.20.09.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 09:39:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 560754182C;
	Mon, 20 Oct 2025 16:39:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 280ECC4CEF9;
	Mon, 20 Oct 2025 16:39:16 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.98.2)
	(envelope-from <maz@kernel.org>)
	id 1vAsuf-0000000FZt9-3Yhi;
	Mon, 20 Oct 2025 16:39:13 +0000
Date: Mon, 20 Oct 2025 17:39:13 +0100
Message-ID: <86ldl5wmry.wl-maz@kernel.org>
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
Subject: Re: [RFC PATCH 03/16] arm64/insn: always inline aarch64_insn_decode_register()
In-Reply-To: <20250923174903.76283-4-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
	<20250923174903.76283-4-ada.coupriediaz@arm.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=CQsMR9Ok;       spf=pass
 (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Tue, 23 Sep 2025 18:48:50 +0100,
Ada Couprie Diaz <ada.coupriediaz@arm.com> wrote:
> 
> As it is always called with an explicit register type, we can
> check for its validity at compile time and remove the runtime error print.
> 
> This makes `aarch64_insn_decode_register()` self-contained and safe
> for inlining and usage from patching callbacks.
> 
> Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
> ---
>  arch/arm64/include/asm/insn.h | 32 ++++++++++++++++++++++++++++++--
>  arch/arm64/lib/insn.c         | 29 -----------------------------
>  2 files changed, 30 insertions(+), 31 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
> index 18c7811774d3..f6bce1a62dda 100644
> --- a/arch/arm64/include/asm/insn.h
> +++ b/arch/arm64/include/asm/insn.h
> @@ -7,6 +7,7 @@
>   */
>  #ifndef	__ASM_INSN_H
>  #define	__ASM_INSN_H
> +#include <linux/bits.h>
>  #include <linux/build_bug.h>
>  #include <linux/types.h>
>  
> @@ -558,8 +559,35 @@ enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
>  u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
>  u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
>  				  u32 insn, u64 imm);
> -u32 aarch64_insn_decode_register(enum aarch64_insn_register_type type,
> -					 u32 insn);
> +static __always_inline u32 aarch64_insn_decode_register(
> +				 enum aarch64_insn_register_type type, u32 insn)
> +{
> +	compiletime_assert(type >= AARCH64_INSN_REGTYPE_RT &&
> +		type <= AARCH64_INSN_REGTYPE_RS, "unknown register type encoding");
> +	int shift;
> +
> +	switch (type) {
> +	case AARCH64_INSN_REGTYPE_RT:
> +	case AARCH64_INSN_REGTYPE_RD:
> +		shift = 0;
> +		break;
> +	case AARCH64_INSN_REGTYPE_RN:
> +		shift = 5;
> +		break;
> +	case AARCH64_INSN_REGTYPE_RT2:
> +	case AARCH64_INSN_REGTYPE_RA:
> +		shift = 10;
> +		break;
> +	case AARCH64_INSN_REGTYPE_RM:
> +	case AARCH64_INSN_REGTYPE_RS:
> +		shift = 16;
> +		break;
> +	default:
> +		return 0;

Could you replace the above compiletime_assert() with something in the
default: case instead (BUILD_BUG_ON() or otherwise)?

I'm a bit concerned that if we add an enum entry in the middle of the
current lot, this code becomes broken without us noticing. It would
also rid us of this "return 0" case, which is pretty brittle.

Thanks,

	M.

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86ldl5wmry.wl-maz%40kernel.org.

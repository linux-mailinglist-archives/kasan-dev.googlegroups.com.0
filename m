Return-Path: <kasan-dev+bncBDCPL7WX3MKBB4MVQDAAMGQEWDIDM3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7888FA90C9A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 21:54:27 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e8f4367446sf1109156d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 12:54:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744833266; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sk3H1Y7nP64wJ7I/4JmXkUKsGXEcsQSvoVB7be1e8G0PnXGRXwqfNcsdE7huf3Dwnw
         ZMBLgn8XjQFGR3Ft/zkRp4T/7pQnjQJ6hw3Cd/LubZkW2XF6hdDTnrsxNFrISL1DWkqh
         YbJf4ufHKeAYuhwGdxpJoi2S2KK0x48aEIIO2VDp+Jcd0BoyP6MfiZsAF/tcS7tA5dk2
         CnP7mmVCHLT0DRyvLpvSjMogydoHC7QQWpCrxf+NfEq25vtq7wZ3zRM5R9oYspKS03MX
         xZAoIGH/Glo+609lK2Jw6SEjhcuy0at4cgs+gs4Yb2+Qa60yl+EX5+I9me+e8B50aDjf
         +plQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YNncmrIEyzhuODx+i/vT6FQNigpGACH3Tql+BDl3VRk=;
        fh=YZRsKRDnstlYdX90PlVnk00+X7eLbz7/fkIISfE9Xd0=;
        b=a5El9OG8Vgq1405zSCfFuXX+1ffboXvPgxop/bZmCIhq/WhScfFYj+iueN+YcgnrSd
         MQzgB7oY+bf6MIrhB+QFjdcYuQRdqC7geTwDzq3/sFsdAAYRnEJVopIyOw04/J8fZx66
         L+0K/+zUi48m4ZTrt0H6M5A6cdImgT/tqjuFNDe+Z4FRgHEqZWcpCHRS1Ob3JQB+NJvq
         DcNgYaOoADM2AtIeXdru3ajDSGDxhsaOONHZOof15RZ4T6ERBueMr+h8Nv/pXGJuaqGX
         dg/F38JASxav6re/c788eSJcebIeX73n7A5sbWAH3gfJZetDkNKyJdX5TXN/QEqMXdGl
         ILfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lz8rnA0B;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744833266; x=1745438066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YNncmrIEyzhuODx+i/vT6FQNigpGACH3Tql+BDl3VRk=;
        b=tF5vlnZ9Nm4SnYTxbl0AbQdlbBiC0mWvlCBe5EJ29Trli1vvMgrgt1dIvHxo6zrSb4
         BNqK0G7Ji3Ps1/kLjXHLz6G5kOWu1TzVObFlotYOCYRoc/0hhofiVCKuX+mo8o/a5ey5
         YdARIZ+xMiCYZIgwdEGfRR2n7xhhvqQ7zqEGteGR0/UIFSxX60VNlrO1oFoMD9lu3Fox
         Dr9DjFW3PUiTkEyQ3uKluJRaHiZNlQLwisRRXV4eiGVSVfCuC9EUB3d9rsIq+SkQgVF5
         ERspKzXKq0HypfCtaf1w5j4ydl9fBMfLyMAMZpjomuCrSVda4TjeG+xm2pWBqrwBGNxy
         SCbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744833266; x=1745438066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YNncmrIEyzhuODx+i/vT6FQNigpGACH3Tql+BDl3VRk=;
        b=kRMzkDuUhPn7y7y1XOTYU+ViTTy2xCvvLad552vpHtZfDsMhxYBGdINwFwsKLaASI0
         M9/EjiPky8h46ARZMyl8Oe2rJTk12cCNPTQBvd0Gmrn/khwR+eO4EfyAPGyGP1VFlSEM
         OxGqmH6vNDRHzwZWjRF2J/brOB7m0L6lGlb9k2KooWGIn2sFmql5FrxcpxVwe1ByqAkK
         ql1jHMwYy+Xn1EFp5rN8MTfftnkVhfFSpUJA6XGDaQErncEPYD/iHN/S1IC3LnNA8Ff4
         gxODiHUoigyKUA+SRR25qMqyLaKrDRjnCTh4ESSMZSgcelLrsXKSYjvWDy80KyPoCT2Y
         AlUQ==
X-Forwarded-Encrypted: i=2; AJvYcCUPHQFz3fnOh69nQQivp02NwMQkTLuNHZLk6H5Y/iaMgjmjcqq79eRxaXG7fLIi/LyRzC5AuQ==@lfdr.de
X-Gm-Message-State: AOJu0YyucB9kR4hYfsoCVR6EiNJ2c2/LQ4QSUcxs1G+kXxvASQzhCtIo
	q/LWt2Y0+hlzO52mMvajXAZftwh1h5KqSDD1w6NwCcM6Dy2UZ4n9
X-Google-Smtp-Source: AGHT+IHtk8lTyCEAsTMBexs4nsjK4CJ+lcYTVQa5eXdUof/E5M/P5GFvNKUnbELWA1CX7BYnRmGBQw==
X-Received: by 2002:a05:6214:1cce:b0:6e4:4288:61a3 with SMTP id 6a1803df08f44-6f2b2f30abfmr42448696d6.18.1744833265934;
        Wed, 16 Apr 2025 12:54:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJSwUTbkIDNstGeGYGeHeDg6RGeCOQfJtFm73X8lYbFZA==
Received: by 2002:a05:6214:601a:b0:6e8:f2bd:66b1 with SMTP id
 6a1803df08f44-6f2b9a9c608ls3984606d6.2.-pod-prod-08-us; Wed, 16 Apr 2025
 12:54:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVG5fus5twVtDrZEDsO0qZXD3c0FhfdakKZwyr8Imd0coBAsuR/CaZMaRPMDaJlUYRTuuGcsgSi2rg=@googlegroups.com
X-Received: by 2002:a05:6214:5292:b0:6e8:f88f:b96b with SMTP id 6a1803df08f44-6f2b2ef9f1fmr51166406d6.9.1744833265141;
        Wed, 16 Apr 2025 12:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744833265; cv=none;
        d=google.com; s=arc-20240605;
        b=DfXOqnl7Xk2NIxNCwEsnO+uY2A+DMiGTX4qAAgNApDA0MCdyLpGscTLZtO+kgCK3to
         sJ+6TCI1f2NJZim9JTOZkSkfcPlf5bM49J0bljU+iaoSj081mHCBFpY9jLrXia8bfKlK
         v2t6z2+Uv3IsrtjXNOvk9A1TrsuvY4nSRyS8KCGv8ERVgF2ckV1Akk0Q7r3bdmCqZ8CM
         xgoxbAYNihlO/HMiIzvynCpiLzlmqG9IwqY9HxHdBNqRjcmRhNC9zxG4ugPpmI9xaKXy
         5c152qp3oAWin6I1xiDmeVB91efWzhQhYnNoR+NeYH/eG/qGx4vuEBT4LwAF5Y5Yjoh+
         nUIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zw1RTUf9P1O8DE2gBZDfX57XQ6qwlxNFLSDVWnPqgU8=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=hisGPmmuQ9noP2w62sNtEvAdQ+lGdB7yzNd5DeLK+nVdrnDbDcRPNZRo/sqgGVrij/
         F5mV19pTdB88TeVdoo+9yUtmrL6ZQg739rRtk0Doy0u2sbkCvnEK5Wkx+0uUbeAFZPgO
         qqmnNuwDwLNlWCZraeDikkvaBFIPnjrLcl4yzeYCXc3pT1da+z5YJvqFUpaDkl3p1wTG
         1RW4cBZPDTG8FrtQal2H4+umiTMHtJDDOi2oDoNzZSNn4NLD3GGmOhSWZJfF6L1xnSOK
         vyvJnM9Yr9U6ZKryHAheQJgRtbe7Ht8/bvWWDCqtLvcqAuo25u0Qcv7sE9NaEib4cZv2
         6jYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lz8rnA0B;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de839103si1886406d6.0.2025.04.16.12.54.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Apr 2025 12:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 75DC9A4A52D;
	Wed, 16 Apr 2025 19:48:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66A95C4CEE2;
	Wed, 16 Apr 2025 19:54:24 +0000 (UTC)
Date: Wed, 16 Apr 2025 12:54:21 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, maz@kernel.org, oliver.upton@linux.dev,
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com,
	x86@kernel.org, hpa@zytor.com, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH 3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
Message-ID: <202504161250.CC5C277A@keescook>
References: <20250416180440.231949-1-smostafa@google.com>
 <20250416180440.231949-4-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250416180440.231949-4-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lz8rnA0B;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, Apr 16, 2025 at 06:04:33PM +0000, Mostafa Saleh wrote:
> Add a new Kconfig CONFIG_UBSAN_KVM_EL2 for KVM which enables
> UBSAN for EL2 code (in protected/nvhe/hvhe) modes.
> This will re-use the same checks enabled for the kernel for
> the hypervisor. The only difference is that for EL2 it always
> emits a "brk" instead of implementing hooks as the hypervisor
> can't print reports.
> 
> The KVM code will re-use the same code for the kernel
> "report_ubsan_failure()" so #ifdefs are changed to also have this
> code for CONFIG_UBSAN_KVM_EL2
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>
> ---
>  arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
>  include/linux/ubsan.h            | 2 +-
>  lib/Kconfig.ubsan                | 9 +++++++++
>  lib/ubsan.c                      | 6 ++++--
>  scripts/Makefile.ubsan           | 5 ++++-
>  5 files changed, 24 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
> index b43426a493df..cbe7e12752bc 100644
> --- a/arch/arm64/kvm/hyp/nvhe/Makefile
> +++ b/arch/arm64/kvm/hyp/nvhe/Makefile
> @@ -99,3 +99,9 @@ KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS), $(KBUILD_CFLAG
>  # causes a build failure. Remove profile optimization flags.
>  KBUILD_CFLAGS := $(filter-out -fprofile-sample-use=% -fprofile-use=%, $(KBUILD_CFLAGS))
>  KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> +
> +ifeq ($(CONFIG_UBSAN_KVM_EL2),y)
> +UBSAN_SANITIZE := y
> +# Always use brk and not hooks
> +ccflags-y += $(CFLAGS_UBSAN_FOR_TRAP)
> +endif
> diff --git a/include/linux/ubsan.h b/include/linux/ubsan.h
> index c843816f5f68..3ab8d38aedb8 100644
> --- a/include/linux/ubsan.h
> +++ b/include/linux/ubsan.h
> @@ -2,7 +2,7 @@
>  #ifndef _LINUX_UBSAN_H
>  #define _LINUX_UBSAN_H
>  
> -#ifdef CONFIG_UBSAN_TRAP
> +#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
>  const char *report_ubsan_failure(u32 check_type);
>  #else
>  static inline const char *report_ubsan_failure(u32 check_type)
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 4216b3a4ff21..3878858eb473 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -166,4 +166,13 @@ config TEST_UBSAN
>  	  This is a test module for UBSAN.
>  	  It triggers various undefined behavior, and detect it.
>  
> +config UBSAN_KVM_EL2
> +	bool "UBSAN for KVM code at EL2"
> +	depends on ARM64
> +	help
> +	  Enable UBSAN when running on ARM64 with KVM in a split mode
> +	  (nvhe/hvhe/protected) for the hypervisor code running in EL2.
> +	  In this mode, any UBSAN violation in EL2 would panic the kernel
> +	  and information similar to UBSAN_TRAP would be printed.
> +
>  endif	# if UBSAN
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 17993727fc96..a6ca235dd714 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -19,7 +19,7 @@
>  
>  #include "ubsan.h"
>  
> -#ifdef CONFIG_UBSAN_TRAP
> +#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
>  /*
>   * Only include matches for UBSAN checks that are actually compiled in.
>   * The mappings of struct SanitizerKind (the -fsanitize=xxx args) to
> @@ -97,7 +97,9 @@ const char *report_ubsan_failure(u32 check_type)
>  	}
>  }
>  
> -#else
> +#endif
> +
> +#ifndef CONFIG_UBSAN_TRAP
>  static const char * const type_check_kinds[] = {
>  	"load of",
>  	"store to",
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 9e35198edbf0..68af6830af0f 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -1,5 +1,8 @@
>  # SPDX-License-Identifier: GPL-2.0
>  
> +#Shared with KVM/arm64

Nitpick: Please add a space between "#" and "Shared", and end the line
with "."

> +export CFLAGS_UBSAN_FOR_TRAP := $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
> +
>  # Enable available and selected UBSAN features.
>  ubsan-cflags-$(CONFIG_UBSAN_ALIGNMENT)		+= -fsanitize=alignment
>  ubsan-cflags-$(CONFIG_UBSAN_BOUNDS_STRICT)	+= -fsanitize=bounds-strict
> @@ -10,7 +13,7 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
>  ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
>  ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
>  ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
> -ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
> +ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(CFLAGS_UBSAN_FOR_TRAP)

Another minor style request: please name this "CFLAGS_UBSAN_TRAP"
(nothing else in Kconfig uses "FOR" like this, and leaving it off sounds
more declarative).

>  
>  export CFLAGS_UBSAN := $(ubsan-cflags-y)

Otherwise, yes, looks good.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504161250.CC5C277A%40keescook.

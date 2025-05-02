Return-Path: <kasan-dev+bncBD4NDKWHQYDRBYG52PAAMGQEEQMPBKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D3E4CAA76CE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 18:12:17 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3f9cbcfbb7asf2671179b6e.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 09:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746202336; cv=pass;
        d=google.com; s=arc-20240605;
        b=cCwu65TMF2vSaXCn3B0j76I+7zeYF4rTh5gdLl3XO+wWSAe8iyY/pcIAi4xQBRIfeE
         k8C8Tr6tnEyhzt9EkPrYeQYqctbXK32r8tAfa+YXyLJXqndDByHjJI9Qx7QBp5zCCsIY
         qN2fDctWlH9toE0zXjs3TnEdgFO+Jg5iiaIvfTDHiQQsgkkYbIChY9JB2Z0VJiXVkDtd
         /SfFh1QRSiXSkb2mkcyuTBZqnoh+VFt1w7agZMNXC0yp09khawNIsfcNEp3UWSM8XE5J
         WWXpFRj9L9OLvc1rAMvtXE9N7xcI+1VQ5Szca8h+9uosd8L688fdevTwILAMrz1HYVuB
         q9RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=l/qsLNUi2qinupEhPaFg4ICg+7QMnraEy4XU01DLXJM=;
        fh=zPStLqnY5WlO9ReKSyBuOWMldku4u0ySG4CBG25kC2k=;
        b=HDtRBnr4Cs0RGIpSHhK01j/2iuNqPgGdRjyV/2nKnlqps8KVPVNiLAvRoHr8wmlGQT
         ZIS1xZYZxQP1I5uefiSVr6hp5Tf4ye2Hb0D+qNjuy/fmSxBfgxIZxJ7BxhFSK5gwy+6j
         i6BCYgX1ViPKK7ZrtMSl6qp7uv3/QKg1glsevozJJDUbVX8tYUmu6+aUROxkXE1xa2z/
         MRlZvRCNxscn4+421Km39Cceh5yBQ1AouY/Pk9HHKlZCayxp1os8o5GmP5IjOp13+sMK
         UXZpBPOfUdFW4marSWuy9U+f2DtbOBFv/UZ0XTv2HxOaDOqtninu2s40AaMWu7EGA0+y
         vtDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ilrraeZl;
       spf=pass (google.com: domain of nathan@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746202336; x=1746807136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l/qsLNUi2qinupEhPaFg4ICg+7QMnraEy4XU01DLXJM=;
        b=hlLmTd6ioeKHb22PGnpQuCZam00Qlq5uo9FQUlOG6tzbloIt3gSs78/IMbpv3PH3V3
         xg3sKgKOie84qOJ4KCYv5OVrXjadagNtqNnyLmUWAZwXwAazIZn39yzdIcIOcbFFJYPh
         junl0E/rE/w5aD2DbpPknBSX0ihNH3xaaK+Crvzh5N0vW3kcurcALde75b+8w/2QjahT
         wkf9il+t13NRhXAo31+5vLV2X15bwHKHQ8atnAh2ybwT3zhU1Yw2BwZZA1HlzqJFNNCc
         DdxYwr9dxU7FHYFDNRPHrEYC2vZfcxDfqTA5cmPha7ZgU02PMqrRCh54ktkLI87VcrjW
         qSLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746202336; x=1746807136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l/qsLNUi2qinupEhPaFg4ICg+7QMnraEy4XU01DLXJM=;
        b=HgQj3SwRuGyw2LeZFS4WaSV9gBPSpoZUjYxU9NoHbBmeoFTcVj+GxG8O3gmZveIZOh
         zt3NL0ylBl3Dy9ksVOc4afDwbd9d/ahc6cmIDZlqEIm23ebzO43krrNTq+a+un/wAYNr
         F+pMkRVh6rfPJnui4eSRCi/P5SLVBeN97BcsfZT36DeuvF2WggT0MB8K+jiSQWGTDtel
         KAapWtP5COf+9bU5jUKnvlGS5DQs2AcfXhHTbNfVR+7aUT58nRFJQqskuWo87W99pg8L
         n1bcq5cFSHUkJR8juoGk3/atmKrqj7PKDmIUaEoXogsdCuDLNCk/vNu1tsH62Du30jjc
         zOPw==
X-Forwarded-Encrypted: i=2; AJvYcCU0dTEG8VxtmR7KRnxF1qmcoYSqeQpLVpVciF8XJwlj/kCj31WmHxyRZp7t4WFUAWeBnJfDYg==@lfdr.de
X-Gm-Message-State: AOJu0YziXCwpIBg4YVFHZz60S8u4T8NcGzDTKA17yJqs2IVeQRgATri4
	aFoA0bxH86KONmzFahbFkNJhBTIJ4Ke6c/YFDUD3gmlGznR7Bxzd
X-Google-Smtp-Source: AGHT+IEoegvctGfbUpwxeqmwmJDdZgv8Ut4z83CBmpqzNaiZ2yBKriMjjmd/1HOWo/xoehEmbHwq3w==
X-Received: by 2002:a05:6808:10c7:b0:3f3:d699:e1a8 with SMTP id 5614622812f47-403360a6574mr4297006b6e.13.1746202336241;
        Fri, 02 May 2025 09:12:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGGpadyyH8j8JNEqtrKZh3Eg771gQR5dFk3ZEBVgeeWEg==
Received: by 2002:a4a:cb0d:0:b0:602:a14b:beba with SMTP id 006d021491bc7-607df23e8f2ls569378eaf.0.-pod-prod-00-us;
 Fri, 02 May 2025 09:12:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmw3dWPSQjzpbFwudXQFJhiOInlw6DQ/nMvzKbUsCNpaPlzmlIXcwxwtP4x1kNelGICbjejkuQWRE=@googlegroups.com
X-Received: by 2002:a4a:ea81:0:b0:5fe:b3c2:29e2 with SMTP id 006d021491bc7-607e1f95db1mr3728774eaf.2.1746202335391;
        Fri, 02 May 2025 09:12:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746202335; cv=none;
        d=google.com; s=arc-20240605;
        b=MMt6nAr8zvUFywLFnW1TXu3OJCN0sUP+zea3hS/gtP9iod0mIJrpeRTsRMPwE0w6FN
         wwK6TJAQQPaELiM0owNNXO5M3DZDEGYv1jGYjUg3NHehQiIZxgGb2qAgRSWdI45XCvER
         ZHvo4Qi2/HSQRLD7EYfol477eEwsD4xw4mioozDtbLcRXsuzIrPdDfGXl4lG/wfYcxTF
         uhp0B00WX2Zm8cnM0Q6ibRxIq2zb7b2zeTBdSQIQ2muJrfd6z9ELh2n4CNFRv6CHgQmA
         vrjH8Q5aZtluslKdgJsdvMOY5xOV1L1rdPIZlrUGpypVT4+7aqMWv+WhcMDk9t7lpm+2
         h4dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jYf/FUoHfzPFcs6MLCHQ/W9DYfD9IFIohV9WFap2Qvg=;
        fh=E4FvMKhUzi8EMpZDzdpViYiJLL+s12y0D44VdsGEdY0=;
        b=j5K6+PRYHaJx4B65csczGnHO5HppGPsoyElNEXRY3wm3jiXCNDH8AqiIlo87ZUjz6F
         WHMJu/Dk9btXS+D3s1pC2MF/9g3YSdQfOquG3YCpKZTmR2RuZyW5YsM+ccmZA7ox0XoG
         MtWJGg0VR8pUpxChCRo6+LtZXZ2f7NcyKxQX81JyzhSlti813V73HRHRl9gM9L3GfWyx
         lXhqKDYwxrbPCEXify3p4F+n8Pabjec8KbY+KbiAEQsiDsXUEl5X9GiRYO2nky2/2InV
         YLr5ymGOWvggcoenzrEL512V5EyvELSCaJ6rrFcMlpm/aERTgYgWMjTbI4aoXaqGwPo6
         d1lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ilrraeZl;
       spf=pass (google.com: domain of nathan@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-607e7681c00si125010eaf.0.2025.05.02.09.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 09:12:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 119FCA4C3D7;
	Fri,  2 May 2025 16:06:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0A9ACC4CEE4;
	Fri,  2 May 2025 16:12:11 +0000 (UTC)
Date: Fri, 2 May 2025 09:12:09 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kbuild@vger.kernel.org, Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/3] randstruct: Force full rebuild when seed changes
Message-ID: <20250502161209.GA2850065@ax162>
References: <20250501193839.work.525-kees@kernel.org>
 <20250501194826.2947101-2-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250501194826.2947101-2-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ilrraeZl;       spf=pass
 (google.com: domain of nathan@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Hi Kees,

On Thu, May 01, 2025 at 12:48:17PM -0700, Kees Cook wrote:
> While the randstruct GCC plugin was being rebuilt if the randstruct
> seed changed, Clangs build did not notice the change. Include the hash
> header directly so that it becomes a universal build dependency and full
> rebuilds will happen if it changes.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Petr Pavlu <petr.pavlu@suse.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  include/linux/vermagic.h    |  1 -
>  scripts/Makefile.randstruct |  3 ++-
>  scripts/basic/Makefile      | 11 ++++++-----
>  3 files changed, 8 insertions(+), 7 deletions(-)
> 
> diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
> index 939ceabcaf06..335c360d4f9b 100644
> --- a/include/linux/vermagic.h
> +++ b/include/linux/vermagic.h
> @@ -33,7 +33,6 @@
>  #define MODULE_VERMAGIC_MODVERSIONS ""
>  #endif
>  #ifdef RANDSTRUCT
> -#include <generated/randstruct_hash.h>
>  #define MODULE_RANDSTRUCT "RANDSTRUCT_" RANDSTRUCT_HASHED_SEED
>  #else
>  #define MODULE_RANDSTRUCT
> diff --git a/scripts/Makefile.randstruct b/scripts/Makefile.randstruct
> index 24e283e89893..ab87219c6149 100644
> --- a/scripts/Makefile.randstruct
> +++ b/scripts/Makefile.randstruct
> @@ -12,6 +12,7 @@ randstruct-cflags-y	\
>  	+= -frandomize-layout-seed-file=$(objtree)/scripts/basic/randstruct.seed
>  endif
>  
> -export RANDSTRUCT_CFLAGS := $(randstruct-cflags-y)
> +export RANDSTRUCT_CFLAGS := $(randstruct-cflags-y) \
> +			    -include $(objtree)/scripts/basic/randstruct_hash.h

As the kernel test robot points out (on a report that you weren't
included on for some reason...), this breaks the build in several
places on next-20250502.

https://lore.kernel.org/202505021409.yC9C70lH-lkp@intel.com/

  $ make -skj"$(nproc)" ARCH=arm LLVM=1 clean allmodconfig arch/arm/vdso/vgettimeofday.o
  clang: error: cannot specify -o when generating multiple output files

There are places in the kernel that filter out RANDSTRUCT_CFLAGS and
this appears to cause other '-include' flags to be filtered out as well,
such as the one in the efistub that includes hidden.h.

>  KBUILD_CFLAGS	+= $(RANDSTRUCT_CFLAGS)
> diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
> index dd289a6725ac..31637ce4dc5c 100644
> --- a/scripts/basic/Makefile
> +++ b/scripts/basic/Makefile
> @@ -8,9 +8,10 @@ hostprogs-always-y	+= fixdep
>  # before running a Clang kernel build.
>  gen-randstruct-seed	:= $(srctree)/scripts/gen-randstruct-seed.sh
>  quiet_cmd_create_randstruct_seed = GENSEED $@
> -cmd_create_randstruct_seed = \
> -	$(CONFIG_SHELL) $(gen-randstruct-seed) \
> -		$@ $(objtree)/include/generated/randstruct_hash.h
> -$(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
> +      cmd_create_randstruct_seed = $(CONFIG_SHELL) $(gen-randstruct-seed) \
> +		$(obj)/randstruct.seed $(obj)/randstruct_hash.h
> +
> +$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
>  	$(call if_changed,create_randstruct_seed)
> -always-$(CONFIG_RANDSTRUCT) += randstruct.seed
> +
> +always-$(CONFIG_RANDSTRUCT) += randstruct.seed randstruct_hash.h
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502161209.GA2850065%40ax162.

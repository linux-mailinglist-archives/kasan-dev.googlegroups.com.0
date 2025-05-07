Return-Path: <kasan-dev+bncBAABBYVA5XAAMGQEA44B7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FFA1AADEED
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:21:56 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-54b190d6027sf3521451e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:21:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746620515; cv=pass;
        d=google.com; s=arc-20240605;
        b=MDpKCYQGc/LWKtQQpgo9Yrfk23uWoczHlulWmZa3NzmOn145R8S044CKzHjS1kNs3v
         LA/5fVBiGT5HUYAjqigL64lPv09Gn1e19Tc0Ur4dqUfYx9fJ3TZO44UmEGvQNJUBGtyv
         DVm6vhnbvqFmsedDCHsnYP4nsOOtwP2toOnRfwpAv95xUHLzGBXnqwYukA2fHN2OMFko
         ucbivnBBpHAq6hHI/OaQ1eCS3p8ib2HX6oYPHJdhnjjtrjw6xDjWu33WA9RnLKPSofSY
         4aQUF3IMwZcWB5dWh/vdA5LPMY3lNwmhfo/kd/eOL86q4ivR71QCzEGOHNCOUC4BCtv2
         CbDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2bPThxibhfPC4h3JHh/08TGRQCY0aJPuLbFAkXxP7cc=;
        fh=vLYdO1+p2UgidsOmdsEmVRPfEZxP8pzdDBK0aefVIpU=;
        b=IA7txASPv72OkmpWUkFaWbEzpl8LaQk9HaYUQwg5mB86z8B3JQn8MAJtBrsLa7FjIx
         cgvAgk3wkm8p3PtbbWFJuUIXv6svutdHLsDwLYd2fA0dcWk1clbFG5DNbjuuQDJ67SA5
         jIgia/FNRR2XhzB+xgkFgfjrjm8UWFcES7TthTpsrY6VI6YCLEinJ7e+9OJlNCd7tWRh
         DdBzHrs/52ez9M6u8qDTm730rCzZSOwavxuHhCcUstItRJx+oFPBgvogk2JUo94Zyg7B
         lpDviY15dXcNtWIrrI9rFEWa8hpWP7RKal/M6/usGhEMqmZHGpyhVnKjgnPF5vwlxTng
         TujA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=miau027A;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746620515; x=1747225315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2bPThxibhfPC4h3JHh/08TGRQCY0aJPuLbFAkXxP7cc=;
        b=jaliO7GMwcQTo7u/lmuV5ouXqP62ewMyOAKVyPtT9U5WzPGZBUoiS23lNOOtmKpn6w
         QXHXqajXIB5ggyF/vBK1e/SOhunC3umK0m8shm4bhkR6FZgCNSTJxr84tzVZdiifHct1
         2HiGngCcs21N5/5PNyuR8oyKjKNaMeMH2HilpfzYI5E2xCbE4vgfR4vEScHgq5WjlJIE
         9+J7jJ1uBU+0GC6D4BwckvP9lUWgNd3Pa7rBYgMpe1micUfxMUmAUOLdm+7qFaeUFPVu
         iunuDpPDROtLSZXZdNXxltowiFGsL5IOqLvHvAv6HukMfgWQX45q5LDI7xd8Ff8Tr517
         tOQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746620515; x=1747225315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=2bPThxibhfPC4h3JHh/08TGRQCY0aJPuLbFAkXxP7cc=;
        b=r8JoEuGXF++H9t4ceUh3Uy6epG9FYmL3ZqWsqaR2/ZAprABxudmW1WIfM1AadtssYn
         M2nkbMhCPDVPgw3smIMJUsfqOj3WcmbpN2CcyKOSN+yu7x8hMB0a4KrCio6PH0lpStmh
         cIu6V/d0uoYGcuzyis8UzcvtOaHtKaPAMyFcFAQHuUViTizTtIWFNW2OcBiTOFOesAmo
         pl04eWdAm6ZnvqfHZlGaEOzwzdVXAaGpLGtP5187PbU5qUG6pJHCtV2G3tKuLPlvaNLC
         DZxMxPibrfmI3LjN+R+SYhMQ58fX6lhl1QRy9OG0Nm6dPGF9f08Qwa7WuD+Nux4GAruC
         ydFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRMb/p/hGGl46QrmctbOcD/EtwNrwmB3b+U3yaL4JKxiHAoCrhMa8J5IG4cInhq1xAaGa3YA==@lfdr.de
X-Gm-Message-State: AOJu0Ywjm3BotPW1tNSiGkcPVzt4xNYGqKmKmU23sNuOKEMGny0yfZYe
	eDt/jQ3sD8Gjwnu+Y+u2ypxNpEmsrIu7EdUD6BcGrcK/+QEeuH/G
X-Google-Smtp-Source: AGHT+IGKW8ZG+os16AZzExcSeuYEoUHzFht1c2x4u2prS655OfK2Y20jNfYxi9FvY8lK5fmMT7gHeg==
X-Received: by 2002:a05:6512:3404:b0:549:6759:3982 with SMTP id 2adb3069b0e04-54fb93afa5bmr1148265e87.37.1746620515201;
        Wed, 07 May 2025 05:21:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEWSB8iMcfRWfZMcfwNWyHNYkmETSKeSA9bewqCt0tfFw==
Received: by 2002:a05:6512:3f02:b0:54a:f77d:8332 with SMTP id
 2adb3069b0e04-54ea675f5c1ls267228e87.2.-pod-prod-03-eu; Wed, 07 May 2025
 05:21:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQvklB/A0GkgrvD9tSKVWpc7Nn5t0qmEYqcOeNvZHPldGpnPEdRUU8Og5xibZk7x6vIex+97XiVJY=@googlegroups.com
X-Received: by 2002:a05:6512:1324:b0:549:7c13:e88a with SMTP id 2adb3069b0e04-54fb9293556mr1219140e87.17.1746620513289;
        Wed, 07 May 2025 05:21:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746620513; cv=none;
        d=google.com; s=arc-20240605;
        b=gk6OkcQrnYnq9d9zxcoQ4pQedg+nnhVSBQyyt8q5rE697R9acVKPulbFFcsdx89MzO
         Wad0wP4nNJSz3b+CLIJL0reBpEdfeSs47D9/Y7W9wU9t6a+0wEvcKU9OprfQ+bYD8mwk
         qvef8++eFYxvH53nbcOjmGSDBO9kHnbD5FDfqwYWFuu+kv6RMbpIInYBtJJb4Qi+A84i
         Qi9EkdeTvY054pZI0KQigJlhCRofbKNzpPxMX8EPDNRBcUx44LBMpdeJMScgLmw5jJ4t
         yAkupJx5FTFtRwaajr2wwmdF+hl1UkU+YToSCjPt0MBe1PQRwX8lkMGI1sGJHyQp/pxW
         1xjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:dkim-signature:date;
        bh=DpPHSAGatCtkUGCaP/yd2Qyr3LuW/jp4fovDif5/S4M=;
        fh=hThWGRiJcfhX0IV6ZpbFG8GsRK4vHchA7BWP6I195kw=;
        b=c9eokehwhVjKJ/xq8yiz7CpBAgoC5wibXn2aM5igKnoOoT2Kk4Ca6teArVKbscZx4I
         mvkJO5OBIbaCvbb4M0apJnR75bLzMzHBnZBYdr3tyw6L8Rxjpu6NTeHVb/7/035v7QPR
         pqBdPPaDFipxDXwOSbSlOlNWggGcqCj4TFqdGZnB52NZvavNz/x/ESIJ+LOtXOawt8AY
         cwor3xNRi+YNjR2i+Ty7TqSAJXTVAjCn9tBTYsFdjIZj70lI+562AzdNXa0q49oBEaEN
         8+VkdO4cTr1Or4rPuIrWm/uD8gSiKpuAwasA7l/0IGzdSaEDUf6XzebZgTg5yxAW4fLm
         utHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=miau027A;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [95.215.58.186])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54fbc9a67dasi668e87.4.2025.05.07.05.21.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 05:21:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 95.215.58.186 as permitted sender) client-ip=95.215.58.186;
Date: Wed, 7 May 2025 14:21:45 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 3/3] integer-wrap: Force full rebuild when .scl file
 changes
Message-ID: <20250507-piquant-fascinating-pug-7ce4cd@l-nschier-aarch64>
References: <20250503184001.make.594-kees@kernel.org>
 <20250503184623.2572355-3-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250503184623.2572355-3-kees@kernel.org>
Organization: AVM GmbH
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=miau027A;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates 95.215.58.186 as
 permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Sat, 03 May 2025, Kees Cook wrote:

> Since the integer wrapping sanitizer's behavior depends on its associated
> .scl file, we must force a full rebuild if the file changes. If not,
> instrumentation may differ between targets based on when they were built.
> 
> Generate a new header file, integer-wrap.h, any time the Clang .scl
> file changes. Include the header file in compiler-version.h when its
> associated feature name, INTEGER_WRAP, is defined. This will be picked
> up by fixdep and force rebuilds where needed.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: <linux-kbuild@vger.kernel.org>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <linux-hardening@vger.kernel.org>
> ---
>  include/linux/compiler-version.h | 3 +++
>  scripts/Makefile.ubsan           | 1 +
>  scripts/basic/Makefile           | 5 +++++
>  3 files changed, 9 insertions(+)
> 
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
> index 69b29b400ce2..187e749f9e79 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -19,3 +19,6 @@
>  #ifdef RANDSTRUCT
>  #include <generated/randstruct_hash.h>
>  #endif
> +#ifdef INTEGER_WRAP
> +#include <generated/integer-wrap.h>
> +#endif
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 9e35198edbf0..653f7117819c 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
>  export CFLAGS_UBSAN := $(ubsan-cflags-y)
>  
>  ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
> +	-DINTEGER_WRAP						\
>  	-fsanitize-undefined-ignore-overflow-pattern=all	\
>  	-fsanitize=signed-integer-overflow			\
>  	-fsanitize=unsigned-integer-overflow			\
> diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
> index dd289a6725ac..fb8e2c38fbc7 100644
> --- a/scripts/basic/Makefile
> +++ b/scripts/basic/Makefile
> @@ -14,3 +14,8 @@ cmd_create_randstruct_seed = \
>  $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
>  	$(call if_changed,create_randstruct_seed)
>  always-$(CONFIG_RANDSTRUCT) += randstruct.seed
> +
> +# integer-wrap: if the .scl file changes, we need to do a full rebuild.
> +$(obj)/../../include/generated/integer-wrap.h: $(srctree)/scripts/integer-wrap-ignore.scl FORCE
> +	$(call if_changed,touch)
> +always-$(CONFIG_UBSAN_INTEGER_WRAP) += ../../include/generated/integer-wrap.h
> -- 
> 2.34.1
> 

Reviewed-by: Nicolas Schier <n.schier@avm.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507-piquant-fascinating-pug-7ce4cd%40l-nschier-aarch64.

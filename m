Return-Path: <kasan-dev+bncBAABBFUX5XAAMGQENPXVHJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id AC624AADDEF
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:01:28 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43e9b0fd00csf4703385e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746619288; cv=pass;
        d=google.com; s=arc-20240605;
        b=P9Cdhlmleqsbgd0UEMf6qO/N8qeYXIGvSf6McA5C52rkrFESReqSnGMxtTYYbWtg/5
         l2U31a32FfZhDitTMZ8EkXFuNTBFoAm8YM1GOrJIh/xze9nSR+NNvxwIov8g55cMkkou
         T1Yfp2MjWh6VJUaMCA2qH9m9jwr6A6kq3oTjET33lAC/5VSinHJi9HQ1MbIrQAWOH9bh
         efDMvIX499OWlOmouVIbEIyIHiwTY4QmOr5WKV6AtffkZd3CfQFNnQiOEbvOF4Sommk+
         WL5aAZFJggaYChTA71scGxIid78mPVaiQtn4mhlrIiUOG9o2x3FhOCxJ+6WzQtiF9B5G
         7GGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bGYfPEwGMpXLFOxCORSoGi6+gMmFiQm1+/uxaEw94kw=;
        fh=yq3rSS3stKXucP5zWtn1qdOjvyBG5NoVZlvqgA6Y1i8=;
        b=DJ3taaY1qf/9oKQJdAFbhYpDF+CujShO0B3h54uxFDEzZ75EClyGr+DPrnTNleYnM2
         DF1E9HaDFxO86ATXe5z3XeKNYSQ8lS+Yn2OkKYE3Gyn56uy93tesQObYZxxtuDqfAtPo
         2Fmocl4tXy5Ht+AHxI5kpnf11YrdGGh/UbUNXUduHUCHgST2W1ZFIZsLIKSaD3LhCLN7
         zVZhP6xGX3iodYGCuP6lKsClMbgVpeOw6GyrNsu7rijM9cfZ8WnHi0SUrqUG33oMU+tv
         Dk87f4sRW/+MPR/XguWvBdcZiJkv5l72/xktZjgXPrVfgIFViFJkdrE+7OamxiE5Dbtm
         AFBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KqvLLeaW;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746619288; x=1747224088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bGYfPEwGMpXLFOxCORSoGi6+gMmFiQm1+/uxaEw94kw=;
        b=Fg8NX5P5j+S/mTM3Nzw2G9nOBYBTua+mt+pzgFeuaSGLDXaKgQdQyJ0fFQJ/NqmwVP
         oi0GaWyUy/xN+DD2IlUKvxkoCxl9jQDVDPXoz7xieyj33Y/EzJPshQ3PfoAVo6/GQAW6
         WSdtExZOLmCrBRjaUGdeXyRQuF2IuscwkvNbJvCiFatcIGvlM+1bgYZIwfkpLYVTx2op
         +Du5+TT28OqYI0OMZXy7A7nn4dFUuI3KZRD0qem5T23NqWxaeUMvdrTiNKc/sGgmvere
         r3Rqkb8AJkPNX7uMEagKcKvpsgf9cXdwgEIkvJ8xAkOu+/Zk2+LHQaHrFSEeebC4oBFG
         PLRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746619288; x=1747224088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bGYfPEwGMpXLFOxCORSoGi6+gMmFiQm1+/uxaEw94kw=;
        b=GDQEug92lbMW8icGJiMjmtOSygQUSMd/s/UhSrIVvAVig72ga5WzdaRavhJNiF/zJO
         mw72nmFagEsIukD00V97LRa6TNCcgTDIEUpjLNDg3niWlwGhtF3q8iMn0AUK7xrCA48X
         y/QWYH4fyQvQo9Mj5TtgFp38mD5iF0pwgI4drGO3V1ob6MYor8tmy4YSLWAL5aTJBq1V
         ordCGnHar6ViE4QolBDPOiUZmY8vUOAagYAIZpnk+rb4Vt0sSDWZhHW83+6Zmw+h5fkb
         4yGVYdnPA8xFHFIIFAXD18EZe441q+sfOijkEDd8Nn8mXbxSN/eqOultIhrwWY5bFTka
         ESLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdfsimGBcASs5MzNjix5i6LRbw+fcDJoMI3YNPTfCJNyOVWpFHZm+ZdWf9OsCKHuo1fnkT5A==@lfdr.de
X-Gm-Message-State: AOJu0YyJSvcgG2BOo8QK416jiv3DR1DNBnZ35+yXggkAmXQ9uvJTSJbA
	UgyS+U24yRDOt/8T/P027tI1+OJJazlh+QUcIhHruIIKf2l6ZwdN
X-Google-Smtp-Source: AGHT+IHDhC0/hJh43kREqKUAw0ayNJro6Lvt/QVTyT7P77Vg07DXLCJuIelEOCCCxMtrEiksqhmJVw==
X-Received: by 2002:a05:600c:3f0b:b0:439:4b23:9e8e with SMTP id 5b1f17b1804b1-441d446ea6amr30813545e9.3.1746619287264;
        Wed, 07 May 2025 05:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHtuPy2D/xE29nKCQ0jzzyHefg7GK4srLQiGUt85If8gg==
Received: by 2002:a05:600c:1c8e:b0:43c:f182:cc48 with SMTP id
 5b1f17b1804b1-441d3f6c0c7ls3687865e9.2.-pod-prod-00-eu; Wed, 07 May 2025
 05:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOYIHLm9yIcgz51knY6hmBpZkIH+HkxQl4v1L1b1lI2Sku3z661t0sYJlTSy18r8de2IQOSWyFx/M=@googlegroups.com
X-Received: by 2002:a05:600c:8711:b0:439:5f04:4f8d with SMTP id 5b1f17b1804b1-441d4e4e42emr22096945e9.12.1746619285369;
        Wed, 07 May 2025 05:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746619285; cv=none;
        d=google.com; s=arc-20240605;
        b=g40o3P3LhjSkz7q6O18K8Dk+RgUr898ij7q5IxzA+cJwpVPMfE3pMgQmL4f1qYzT+J
         vbs4BkhPE3CHBXHVnLjgtqYqE49pKRaGSBRdh4wYTBWhoLk5E42VoFczkA2qPIezqkWt
         RUIB+V0gb/P/1CDLrdhGNpOIDeItgxaFU1Kkn4Fl6RRzWyPGtJSQR2qSuiBrX4TuB4x7
         5WZ7oKxhVetQ0+U6M4SY49A9x6TQQBzlxshtcNgqQrF/m/9F6iT2clju+j+XtACa3Xpv
         5iT8KiKhhPZgQsNEw7Z7kKJhSkQFxY18aNmeMwbeLrW/8mANe1gWC5ulWfen5UWW7ouH
         GPYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:dkim-signature:date;
        bh=RL2wxXAmed+PI/IjubgKwat4E+CcspkAjjt3L6RhK6w=;
        fh=5LgOg5hMHe1IfmFnW6K8B58w9dkMEP1FykAE3ty86lg=;
        b=bLhfGmZd/3CT6Z8P4t2IphNgfM/mtpjKvBBpp+HnS6nCFk3s1ruDE8BDYtQszFghma
         AnmZ18cMjldRU7ay/SHAn+rJAp0fLRMZPU/FpxJtd/wAOg/ryUOsE1B0nNtTpANySKBA
         wYb0Ka4IVtayZfimu8i/ECyx/dsyeils2pNvSkzYf+FvNGYyIgDHgZVssWxwx1CWXllY
         gpi2W4mxArdrjRPu0sZnSw5xKkB7Rq7eacZMM95qBCiyMMCCL0wtwwUXDZxRUytbGkxO
         687U4IEna6fnKebUmDDyulQF/RpNk1ElouSead45qzuwZK80quNR8gJc+kpjPpc0x6o4
         A/Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KqvLLeaW;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d15df86dsi1746045e9.1.2025.05.07.05.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 05:01:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
Date: Wed, 7 May 2025 14:01:21 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev
Subject: Re: [PATCH v3 1/3] gcc-plugins: Force full rebuild when plugins
 change
Message-ID: <20250507-emerald-lyrebird-of-advertising-e86beb@l-nschier-aarch64>
References: <20250503184001.make.594-kees@kernel.org>
 <20250503184623.2572355-1-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250503184623.2572355-1-kees@kernel.org>
Organization: AVM GmbH
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KqvLLeaW;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.171 as
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

> There was no dependency between the plugins changing and the rest of the
> kernel being built. This could cause strange behaviors as instrumentation
> could vary between targets depending on when they were built.
> 
> Generate a new header file, gcc-plugins.h, any time the GCC plugins
> change. Include the header file in compiler-version.h when its associated
> feature name, GCC_PLUGINS, is defined. This will be picked up by fixdep
> and force rebuilds where needed.
> 
> Add a generic "touch" kbuild command, which will be used again in
> a following patch. Add a "normalize_path" string helper to make the
> "TOUCH" output less ugly.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: <linux-hardening@vger.kernel.org>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  include/linux/compiler-version.h |  4 ++++
>  scripts/Makefile.gcc-plugins     |  2 +-
>  scripts/Makefile.lib             | 18 ++++++++++++++++++
>  scripts/gcc-plugins/Makefile     |  4 ++++
>  4 files changed, 27 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
> index 573fa85b6c0c..74ea11563ce3 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -12,3 +12,7 @@
>   * and add dependency on include/config/CC_VERSION_TEXT, which is touched
>   * by Kconfig when the version string from the compiler changes.
>   */
> +
> +#ifdef GCC_PLUGINS

Out of curiousity:  Why can't we use CONFIG_GCC_PLUGINS here?

> +#include <generated/gcc-plugins.h>
> +#endif
> diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
> index 5b8a8378ca8a..e50dc931be49 100644
> --- a/scripts/Makefile.gcc-plugins
> +++ b/scripts/Makefile.gcc-plugins
> @@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
>  
>  # All the plugin CFLAGS are collected here in case a build target needs to
>  # filter them out of the KBUILD_CFLAGS.
> -GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
> +GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -DGCC_PLUGINS
>  export GCC_PLUGINS_CFLAGS
>  
>  # Add the flags to the build!
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 2fe73cda0bdd..6fc2a82ee3bb 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -296,6 +296,19 @@ $(foreach m, $1, \
>  	$(addprefix $(obj)/, $(call suffix-search, $(patsubst $(obj)/%,%,$m), $2, $3))))
>  endef
>  
> +# Remove ".." and "." from a path, without using "realpath"
> +# Usage:
> +#   $(call normalize_path,path/to/../file)
> +define normalize_path
> +$(strip $(eval elements :=) \
> +$(foreach elem,$(subst /, ,$1), \
> +	$(if $(filter-out .,$(elem)), \
> +	     $(if $(filter ..,$(elem)), \
> +		  $(eval elements := $(wordlist 2,$(words $(elements)),x $(elements))), \
> +		  $(eval elements := $(elements) $(elem))))) \
> +$(subst $(space),/,$(elements)))
> +endef

Nice :)

> +
>  # Build commands
>  # ===========================================================================
>  # These are shared by some Makefile.* files.
> @@ -343,6 +356,11 @@ quiet_cmd_copy = COPY    $@
>  $(obj)/%: $(src)/%_shipped
>  	$(call cmd,copy)
>  
> +# Touch a file
> +# ===========================================================================
> +quiet_cmd_touch = TOUCH   $(call normalize_path,$@)
> +      cmd_touch = touch $@
> +
>  # Commands useful for building a boot image
>  # ===========================================================================
>  #
> diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
> index 320afd3cf8e8..05b14aba41ef 100644
> --- a/scripts/gcc-plugins/Makefile
> +++ b/scripts/gcc-plugins/Makefile
> @@ -66,3 +66,7 @@ quiet_cmd_plugin_cxx_o_c = HOSTCXX $@
>  
>  $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
>  	$(call if_changed_dep,plugin_cxx_o_c)
> +
> +$(obj)/../../include/generated/gcc-plugins.h: $(plugin-single) $(plugin-multi) FORCE
> +	$(call if_changed,touch)
> +always-y += ../../include/generated/gcc-plugins.h
> -- 
> 2.34.1
> 

Tested-by: Nicolas Schier <n.schier@avm.de>
Reviewed-by: Nicolas Schier <n.schier@avm.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507-emerald-lyrebird-of-advertising-e86beb%40l-nschier-aarch64.

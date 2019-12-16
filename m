Return-Path: <kasan-dev+bncBDAZZCVNSYPBB5VX3XXQKGQEG4CW32Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BA3A12024E
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2019 11:27:04 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id b8sf6643037pfr.17
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2019 02:27:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576492023; cv=pass;
        d=google.com; s=arc-20160816;
        b=YMYeIIfwR11AvC87Wivm1LRgI+WKdjsOyVkG/AVMbFPxaEudFuw9nDGABgvhndUaE6
         b15W7quiXgiAAUuA3E9D8p0LyptrZYjRz/meBvurJon/iJ65e9Cpd3NdMXtiUXRDnkfs
         gLy04GySyidcpbgaW9B5X5TGpvcBW/fe9i8dMCZUE3Uipdt5ruFpEunSq+Np48BTmnGI
         mZRQxnYJl4h5fW9pNFo1KstY0UzKdBpnGm3BAXZgf9kHKG6GGrZG66h6bPOKxtYdV828
         +OMC7CfBrgg05tsQ4snXVzPjrvFCkIZFe7HqbxvatGelCi9BPAMCmkpiBh5H6z8hlWOi
         rHgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=p8MGEH68aro69Vmi44lhIcamnSweWlKxRedqyieykTQ=;
        b=0twqjVIDZdOtVXIfVqEiz6tgkaUn0NQbkS2BmpGtD344b/kYxW/reAP+l3sUHRhRJm
         5piYOXs4LVDXcYGNyVR+tik18vGTNXwHBtZ7fey8LuKSekADVjdasZNch7yD9sunQ2fz
         ltjdNInZGIH1rwYJlEOcLzz5KRJwTniO+pA/Yk/Bz56rQzWbKBXH7pm4HwypKrREUhYG
         tsg+MjyYR5YGE8pU6uNaXJg4rsRHQ6tmiXM7SpeLFUUJ6mme+zLvLDGHNXfb8tPvSopt
         Ez320ATc+maQLbLy9Cffe9r2BT9ESlkfTjBktLTJZ0I5t9bOJmU7mbbX9aDAoEe2AJ2l
         5mrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oKrWqvEV;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p8MGEH68aro69Vmi44lhIcamnSweWlKxRedqyieykTQ=;
        b=sV9hQInkIpYFQzO2KaZ99LAV4OqfcL2MpHs6LsB2p1w5S4e39bPIZXUQ5nj8GFDXnR
         lkJJMJjhTf448/bFTpG2wGwAoBRMSIVvu/iMLOefBkyXdh2OxKIk6x6ObLDC11JyL/Pg
         gicIBrjU0NdkXFY39GnsS6EAG4fjgOqUYyWKm3Tx6BXDQ3P6Is7o7YcXsfJpBKVOSyHw
         ekGqMbOqHIXXV5DY1mKvCppi5S50SCW1zfLkP03VwErKCbe8wkp7BBFgcUzBu84vzgQl
         WJHR42Z63vJIkeMPmuPwZuBJplfjquuJ/cAscPO9KuiLOIhLd2NtnUW0YqkxHD7Lp+vX
         13uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p8MGEH68aro69Vmi44lhIcamnSweWlKxRedqyieykTQ=;
        b=PAlkh/kPfpg5gdDjRtsUrkdZfZwvN3SAirVCM+tbfngszgcCR+FVHk//ggRuoZYlf1
         MKozZ2UE7RP5fR92ZvDlREoJUi0u8AvY2GejwXDnT6jZJhaSQ9Yf5GUzxcys11qiRP7U
         +dRqLKg5tx+j+blZ6hTQUSC6ONBgsJwL82uE09/MWOekRmXXZPhGDVFWixvLZ3ULZcUp
         gCTmTABzhjlQHti9AqJztoQl3ChUz8pEpw0K7fsYqt49M4yF5qY9fS0d4ile/NnfT5PE
         2t66nsX0NvmWLJSAL6wVhpNK8i18AVizGKx3aLubNueJRnFnygSZvNIA/jeN4PYy5knE
         Vcfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWaEo7x9OyTTQ01SeZc1BeWVakwr91E9DU7idDHShSWT5qCT17c
	2mIUP4FCBz0FovdHUsHUDvQ=
X-Google-Smtp-Source: APXvYqwFL1AFhVf5cVzyFOvrxyqFH4sYpU4LgJy40E35yBSsvcVvHdaGK0q0nDgjkdkt4bRNIXSqNw==
X-Received: by 2002:a62:cdcb:: with SMTP id o194mr14795980pfg.117.1576492022830;
        Mon, 16 Dec 2019 02:27:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2646:: with SMTP id m67ls4174039pgm.2.gmail; Mon, 16 Dec
 2019 02:27:02 -0800 (PST)
X-Received: by 2002:a63:465b:: with SMTP id v27mr17537497pgk.257.1576492022373;
        Mon, 16 Dec 2019 02:27:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576492022; cv=none;
        d=google.com; s=arc-20160816;
        b=ioJ/XtCRo23ft1FbABcrmCgQ6DBQ8Lqf7XG6jg05rSK49IfylPiSDOJWcE7nY+hrYN
         RkbvET5K7jdNh8ay3dXQopavIQC/bRYDMpS3nK34o20jgQEBeA40vvHkFoiBB+sz2G3q
         8x7XZe0ujf2x+cFyEJGM7DK4zGcxg9DQePDItsiHK8+M1SbwUmsa+Xp6MuLwrD4YFHzO
         Mq2+x/xw5vvC02Xb8BXARSUAV8NJ602OBd9PKYdPP73wlT2jLN9n9SMM49Cdzi5TdNh4
         fzqFqlcHZKQnoXgyDPLbZlNuCLPsNkpl34ahXto7zxjQZrIADda+UDznZCTYGAEzQ92N
         md6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4DI59mFYbQm1kX9wiqUYzMfZAgvInq7fI2aKqj44QV8=;
        b=POqYMQ/ZG9hpwBu/nnNh4eVit5+Ud9I04MxE+dpleB0OeH75W2C6hELlX2lRzVacd8
         PakgRYvRdbn8lYURyg3jc3j00XCW/CN1yoBO2VXhJieVli2JBfPyT08DKoXuAzCc2bIF
         NGAZ58PHJ/Vn6l9iYvIfmW26GgrVPaIhr3qkZELg7qUns3QnucTfh0p5WS677Y6wSd9v
         HjtlXEA/O2zpFR8gVeq2despyTZzpfl3RfvNtpjAaLQS1x/n6eAwvb3ICdrAgCzYAW6u
         7T/7JLNGlu0EXgzzEGgLlO86ivLCz7uM966bbXSTPxxOqVaZ8UMJWZ/Nq6IHriKXLLm7
         Psjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oKrWqvEV;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a24si677347plm.1.2019.12.16.02.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Dec 2019 02:27:02 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BDADC206CB;
	Mon, 16 Dec 2019 10:26:59 +0000 (UTC)
Date: Mon, 16 Dec 2019 10:26:56 +0000
From: Will Deacon <will@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: Re: [PATCH v2 1/3] ubsan: Add trap instrumentation option
Message-ID: <20191216102655.GA11082@willie-the-truck>
References: <20191121181519.28637-1-keescook@chromium.org>
 <20191121181519.28637-2-keescook@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191121181519.28637-2-keescook@chromium.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=oKrWqvEV;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Nov 21, 2019 at 10:15:17AM -0800, Kees Cook wrote:
> The Undefined Behavior Sanitizer can operate in two modes: warning
> reporting mode via lib/ubsan.c handler calls, or trap mode, which uses
> __builtin_trap() as the handler. Using lib/ubsan.c means the kernel
> image is about 5% larger (due to all the debugging text and reporting
> structures to capture details about the warning conditions). Using the
> trap mode, the image size changes are much smaller, though at the loss
> of the "warning only" mode.
> 
> In order to give greater flexibility to system builders that want
> minimal changes to image size and are prepared to deal with kernel code
> being aborted and potentially destabilizing the system, this introduces
> CONFIG_UBSAN_TRAP. The resulting image sizes comparison:
> 
>    text    data     bss       dec       hex     filename
> 19533663   6183037  18554956  44271656  2a38828 vmlinux.stock
> 19991849   7618513  18874448  46484810  2c54d4a vmlinux.ubsan
> 19712181   6284181  18366540  44362902  2a4ec96 vmlinux.ubsan-trap
> 
> CONFIG_UBSAN=y:      image +4.8% (text +2.3%, data +18.9%)
> CONFIG_UBSAN_TRAP=y: image +0.2% (text +0.9%, data +1.6%)
> 
> Additionally adjusts the CONFIG_UBSAN Kconfig help for clarity and
> removes the mention of non-existing boot param "ubsan_handle".
> 
> Suggested-by: Elena Petrova <lenaptr@google.com>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/Kconfig.ubsan      | 22 ++++++++++++++++++----
>  lib/Makefile           |  2 ++
>  scripts/Makefile.ubsan |  9 +++++++--
>  3 files changed, 27 insertions(+), 6 deletions(-)
> 
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 0e04fcb3ab3d..9deb655838b0 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -5,11 +5,25 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
>  config UBSAN
>  	bool "Undefined behaviour sanity checker"
>  	help
> -	  This option enables undefined behaviour sanity checker
> +	  This option enables the Undefined Behaviour sanity checker.
>  	  Compile-time instrumentation is used to detect various undefined
> -	  behaviours in runtime. Various types of checks may be enabled
> -	  via boot parameter ubsan_handle
> -	  (see: Documentation/dev-tools/ubsan.rst).
> +	  behaviours at runtime. For more details, see:
> +	  Documentation/dev-tools/ubsan.rst
> +
> +config UBSAN_TRAP
> +	bool "On Sanitizer warnings, abort the running kernel code"
> +	depends on UBSAN
> +	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
> +	help
> +	  Building kernels with Sanitizer features enabled tends to grow
> +	  the kernel size by around 5%, due to adding all the debugging
> +	  text on failure paths. To avoid this, Sanitizer instrumentation
> +	  can just issue a trap. This reduces the kernel size overhead but
> +	  turns all warnings (including potentially harmless conditions)
> +	  into full exceptions that abort the running kernel code
> +	  (regardless of context, locks held, etc), which may destabilize
> +	  the system. For some system builders this is an acceptable
> +	  trade-off.

Slight nit, but I wonder if it would make sense to move all this under a
'menuconfig UBSAN' entry, so the dependencies can be dropped? Then you could
have all of the suboptions default to on and basically choose which
individual compiler options to disable based on your own preferences.

What do you think?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191216102655.GA11082%40willie-the-truck.

Return-Path: <kasan-dev+bncBD4NDKWHQYDRBUXG6WYAMGQE3LKB6UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CC858A59F3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Apr 2024 20:35:00 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-436d9e571c1sf15240181cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Apr 2024 11:35:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713206099; cv=pass;
        d=google.com; s=arc-20160816;
        b=zen8bmaJ1mpWxLTDkVxKFqDXOjHPksgQWXi5xg4yVOIilqel8pLzcEoSQpTL3dyt3c
         ni1liYvcL9eSnsCmynICOOoqvlvp90iZK7pqwBdUDZSXgreNXIm159UypRubnZdGaaDn
         CD/7uyS0Qn0c8N/FC1RBmMcKQPVbu00eF3NMyMjN0RnfoZvRiv5NFeiZZq3z/DBCe1U1
         00bAilz7VCHkD/JNR0rp/GDCaIOdJzIGatpZ4HcxQS5UzI/muYoJnFYQ3mIZ9cB5iHTd
         zwnStfbMPL5u4irunM5xj6O/ejlKBAnVumCzYS9KTmXuDOdkIleO1JKPU7TcmnoDhQh5
         VP+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NDvoan64fzRUeTBQINCqFVuzVVt8xPsiWyIWYeeBvfk=;
        fh=ouTxBvR6q3m4J0gjOBP7tTVB3VTOOonY/Rb9RZ0ENFY=;
        b=BtfO2dYymfahajK2tdyNWJXGQNRWZGHG0Mc6yfqC4lZ5k/svGDsj2iAhiCjnHCwTHh
         QEDiI+gYcJbYxQuDGWiOvjR0dcETS/OTl1rFx8HRp2HMlqeuy8i/TLQDoaYqgamNzQfS
         GVPpJIDbJCx5RYE/xhiPU92gEvlpLYLBmkLRJYe9e/bvFeSnhLWR5HjPubcSgziVMu1B
         NF9fMIG+l6vXfZ03GgfxOsZHJs+lJzGT43M2f+2jbSKh+yHpJalHS1pHSl5IhWCBUrGO
         BAwK4ANMTQNLEehguZzdBskVDIdRoMDyQ5vZ7TJOoEX/SL77F6+rFo4+JpFVdV7Yw+vr
         9O/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kx9jaLbp;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713206099; x=1713810899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NDvoan64fzRUeTBQINCqFVuzVVt8xPsiWyIWYeeBvfk=;
        b=Jazyh6cldwoMx29tUV2pOs4VFv95F+gzqJVvSklkjUVjLiFAeLZOfiW6o8rO+mihtg
         AWiQvJUdjBXEJsMvGlaT26AfuCkqdPogwFyFX5sLOm7SpNkVqoekKAASQX0YEOYNerpf
         VXp+HDd4eU5TcwrcCMPMdrhfKFQ17z8UPI4r8tfQ2Bh7VtLoo4fClyHWTCDIccCnSeJy
         2NA8IrFX/13Svmm7LbE2urUGhaSt5CmOfMbzZAKoljIalAhzE2VF/M/KIQLaTM+RdYmJ
         yl0GuDvnpB1SYoQahY2I0uDHQWcF8JEG3952qu6D3g8J+473oe5QPIwU6VUT9e2xfpBL
         mo0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713206099; x=1713810899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NDvoan64fzRUeTBQINCqFVuzVVt8xPsiWyIWYeeBvfk=;
        b=crnkwYTlwx0L6iQ02I9jaZqaC04XJMBZOmlRBDb0VI7FxZLPIpixui/JUaekNJUyrD
         TJIHwSiBdxVUDvxx5JNP1mx0QA1s9FPas6QW/btiMP/QttHIF7WSkXCRDS9BuptfPUYn
         x8hOWwy/sLKT0QhnV4ADJAeSvs/q+VAxf50qkL4QrikGGJ1r2UebcyrB3uPr7z2W/pwn
         6jjyP5KJubyxwPmWy1ABhQCr/5tAlVjTz3b1UqMvRtHshaj04sYbjr6xvsSdvQDVvxXp
         wAqwe/cVXN3hhXkJzQ199o+WZYrZx5ACQ9NPeqYF0hkVBBovBJVj+TS0D6vLmzhOyfb7
         0e2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBQGYAzl6b34nNSSFHE8rI3yuE8BYBFtGJ23PD2gJ4R7xeTRtjTWn2TYYX7O+4IoVlZuMcPZz4OeidDJysHgAD1Yj09aQDZQ==
X-Gm-Message-State: AOJu0YzuqOx6KfC0x4s940NMscdAKqKsKMje7d+c6xH/QMwrBEM1+DJ6
	b5ucNl9ZsyvIkOvVy9zza4YRxTrjH/2pNloCnvlwLPUEYQCedhjR
X-Google-Smtp-Source: AGHT+IFyjpF1lnEuZqzbW6/pE6XLPdr9tOhPJSVR0b9prg8GD9QgH3pgbTCQp80CUJpWTSYPfQj1Zw==
X-Received: by 2002:a05:622a:28e:b0:434:586f:6fc7 with SMTP id z14-20020a05622a028e00b00434586f6fc7mr11750457qtw.6.1713206098687;
        Mon, 15 Apr 2024 11:34:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:24c:b0:437:2b27:29a1 with SMTP id
 c12-20020a05622a024c00b004372b2729a1ls711697qtx.1.-pod-prod-09-us; Mon, 15
 Apr 2024 11:34:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhZyDAmSZ0MkaGaT9UzdCXDpzqHdTavZyQeQm7RZBmQoyiDS/fOJgofos8LSXD4ce4lncOp6cQ2LF2//ByxcYW3lzFqBJnIGHBog==
X-Received: by 2002:a05:620a:21c3:b0:78d:6e6f:9004 with SMTP id h3-20020a05620a21c300b0078d6e6f9004mr12436532qka.59.1713206097962;
        Mon, 15 Apr 2024 11:34:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713206097; cv=none;
        d=google.com; s=arc-20160816;
        b=LRcDH0r8V1XPSy/SWVkgtO0HjgHrYaU6S/pVC/wC+oFFwIj3iz+vby/mQSDEsfYbLv
         NivUgSazsx3acKyjoPSuPwo2/CYvzphZCfCXlvFjiDN+tTzyguWMDFhvLKnttt2swclB
         eyPClfyF8Hk4P24mIHVesKxuXRAC3vE8fd5Uo8AtoK7JUVAKQCKGgTolg0c9Iz9VgJAX
         Dj5ON3KAyMe9RB9eS+lPnhmT7yPQF3AoQBGIbtFn94hEgNkdiXIzu0IDa1X6AO7QSv8r
         nfsyVX7Rv9WZ0Wu6zr3INlmcC5GIe/GZbHm3jq+pElmtLmV5AZPXpZ7crJYFN+qJVMTJ
         /Kgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iFFYE3jra0j1b7MPgo9+PzO1BZLF4T+YLdNlf+DzL7A=;
        fh=KGR0t+/1idhS3pYs9ubPexA3zD1bQ08Ds4YACWAA8DE=;
        b=BDIlUAox+kQT82r9EQAG/h/k1uMIlIwR3+/Hl9S+SwS6XidFRzR1oTxTabTQ38iRpW
         uKadf2FmjP5WBm75DmRT4hRNFRgmI8ncTIs0tidUHhheOEE8Ofq8ZuYIYpYlVl7LQHE0
         MrkzN2YqrgsMNR6P/+DhDE2lPiFAABppx0818OkKVXbjmH32gQ5LMki1qMjUjWuy9CIo
         Ve0YMQlT4V/X8rsqHGZnW7Gp68Mm/1Al9wFtO/JOFTmKSiPwvPyd6bpZHYSlSA9mJr/+
         AFrjHsFFcGT2CMxbGwLdNqIzjrolgfuovLACqNDOafB9A76OgV8bw9zutj2pdHa2Mha6
         oLZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kx9jaLbp;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id tc7-20020a05620a2cc700b0078edc0a4482si283927qkn.1.2024.04.15.11.34.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Apr 2024 11:34:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7801E60B8C;
	Mon, 15 Apr 2024 18:34:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68BBEC113CC;
	Mon, 15 Apr 2024 18:34:56 +0000 (UTC)
Date: Mon, 15 Apr 2024 11:34:54 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Justin Stitt <justinstitt@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] ubsan: Add awareness of signed integer overflow traps
Message-ID: <20240415183454.GB1011455@dev-arch.thelio-3990X>
References: <20240415182832.work.932-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240415182832.work.932-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Kx9jaLbp;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Apr 15, 2024 at 11:28:35AM -0700, Kees Cook wrote:
> On arm64, UBSAN traps can be decoded from the trap instruction. Add the
> add, sub, and mul overflow trap codes now that CONFIG_UBSAN_SIGNED_WRAP
> exists. Seen under clang 19:
> 
>   Internal error: UBSAN: unrecognized failure code: 00000000f2005515 [#1] PREEMPT SMP
> 
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Closes: https://lore.kernel.org/lkml/20240411-fix-ubsan-in-hardening-config-v1-0-e0177c80ffaa@kernel.org
> Fixes: 557f8c582a9b ("ubsan: Reintroduce signed overflow sanitizer")
> Signed-off-by: Kees Cook <keescook@chromium.org>

As I mentioned, CONFIG_UBSAN_SIGNED_INTEGER_WRAP needs to be
CONFIG_UBSAN_SIGNED_WRAP. I applied this change with that fix up and the
warning now becomes:

  Internal error: UBSAN: integer subtraction overflow: 00000000f2005515 [#1] PREEMPT SMP

So:

Tested-by: Nathan Chancellor <nathan@kernel.org>

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  lib/ubsan.c | 18 ++++++++++++++++--
>  1 file changed, 16 insertions(+), 2 deletions(-)
> 
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 5fc107f61934..ad32beb8c058 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -44,9 +44,10 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
>  	case ubsan_shift_out_of_bounds:
>  		return "UBSAN: shift out of bounds";
>  #endif
> -#ifdef CONFIG_UBSAN_DIV_ZERO
> +#if defined(CONFIG_UBSAN_DIV_ZERO) || defined(CONFIG_UBSAN_SIGNED_INTEGER_WRAP)
>  	/*
> -	 * SanitizerKind::IntegerDivideByZero emits
> +	 * SanitizerKind::IntegerDivideByZero and
> +	 * SanitizerKind::SignedIntegerOverflow emit
>  	 * SanitizerHandler::DivremOverflow.
>  	 */
>  	case ubsan_divrem_overflow:
> @@ -77,6 +78,19 @@ const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
>  		return "UBSAN: alignment assumption";
>  	case ubsan_type_mismatch:
>  		return "UBSAN: type mismatch";
> +#endif
> +#ifdef CONFIG_UBSAN_SIGNED_INTEGER_WRAP
> +	/*
> +	 * SanitizerKind::SignedIntegerOverflow emits
> +	 * SanitizerHandler::AddOverflow, SanitizerHandler::SubOverflow,
> +	 * or SanitizerHandler::MulOverflow.
> +	 */
> +	case ubsan_add_overflow:
> +		return "UBSAN: integer addition overflow";
> +	case ubsan_sub_overflow:
> +		return "UBSAN: integer subtraction overflow";
> +	case ubsan_mul_overflow:
> +		return "UBSAN: integer multiplication overflow";
>  #endif
>  	default:
>  		return "UBSAN: unrecognized failure code";
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240415183454.GB1011455%40dev-arch.thelio-3990X.

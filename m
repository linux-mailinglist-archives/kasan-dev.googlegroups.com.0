Return-Path: <kasan-dev+bncBCF5XGNWYQBRB74H4ORQMGQEKFFNRUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AF6071EE70
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 18:14:57 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-33b3f549628sf8722945ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 09:14:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685636096; cv=pass;
        d=google.com; s=arc-20160816;
        b=hC5AB6i7WG2dnE2WqqlUexZ7tZDA6x1WxZWg6M6QaSdK9obmNs9wGkW6tEbQB126Sd
         1QRCYFhmSLYe/jHww4K9z1fxYUstQhRmFiO/1kbvv4pKotog0FxBeyfGqubMasR0GVz+
         sl5lQHevxKw+UmdzvOUgmUJXvZ1CSGKjQOONnahusPRLkR4J2YpgKuyHmXYiYI1GCFjG
         sV7hutF7+O+XMfIX2wt+MEkBSd7C706WxxSZHVf6USfmZQ5zOtUU0Zs+VSDcap1xlfGL
         NajTcjrC8/0JRSBc7LFurZEyqYY430YcN016Aze77L6hBvhQ1fQFHJUdGDRRcDIJy+ms
         nz2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YOMBO7UzZlacd2URSqlgn2/o55Yp2/SQ0nrzpfMX8H0=;
        b=hMYHBsfiakhS6N+Ya2XakSf3IjHbROyXDihgLbO3mDFtYACvq3kz2C0xNkAQ6cPO51
         fAJ++YU4IFtI1Dhb+RsrSRjyjYLhNlV9QJ12lfd1GenD5yRrTVNB5upOYW9IwlSx1m/E
         fCRPbk0+ObYCG4/is/4Ui9hG+2OFld+vGA6OwpyjyUpxL1ol5fTMIywHTfrRKc2fTUgs
         GX73xRQ7+5vjBETuzcn5PoB6KjuknfsmGcUVl7TEb6PI5yUWkYkVcLy7G6WhJt9fD9Tc
         vbZc/HriZh8XhHXgvcmuUJ9F4pS3IgYCjf/5ckjJjNbuIfKiKeQA/d54UrntGvuLccKl
         seHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BLOJsskD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685636096; x=1688228096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YOMBO7UzZlacd2URSqlgn2/o55Yp2/SQ0nrzpfMX8H0=;
        b=LH6BWBAxYSmtPDYDR7kSnBW06h9zeChdiQ36StJJjIJkpBaGNJquFHinP/th95iUSJ
         x/Hx5OnlwO8x2V6YNApBkOlXPQy2qrlWG4UV+vwLlk88M0hBJkE+0avwOLGjimTETdGT
         N37GCUQ8dVdX1di/Gs07lbnKFuoJlQ1s+86JPYVab+pTQQOmYPvnQ/vgBKa7RIBMFJd8
         yQ62En1oNfpgJaWqqb1hmUy/LBnuwrLDvaIa9J1IpEPWh3HAXRglHxAOngNiCJk8XZ21
         1MgFvliD2EDITHDpGUiJw0SbNLGgy3NV96LBDZ7RCUZfb8YpIlSE6Q1YSbmrbktRU7ee
         empA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685636096; x=1688228096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YOMBO7UzZlacd2URSqlgn2/o55Yp2/SQ0nrzpfMX8H0=;
        b=CZ0OiMvvIBMx4+AmEqpl8nlwLQd78WuI54O+Rx9CY7UNSNSCAd8hcCQM/8uyFwdSwX
         zmTXo6rCVr32zV7gfgxJHC1RTs5G9/8RHaZSm+e0G4wgd0EOJS48f9vYn3OmPWeRNz/d
         oDEvvPJ8wnszKRJgWW2ErVoYVbsb9q1sa5TtIsxp6HE2gLt2kW9IGWDRdtIl0gqXMmL8
         GLNXZkkN/l3WEp1vdznkDjkmozuzFLPqi5KtiEFixhvZ0uUrb97XfwTqSRfAWXwDAYlx
         sVF5B5XeZQMQCoZ+XvdDiZ3p/BOAzN9r9BPFjsS3eXUwcNqePAPvw2UKV9GvsGKvDHz0
         /X/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx6P7MDLkFrW4L18h1JPxiVJnmyuk0nfmgnQqb8Y3FWL+Fr4pWN
	s6SKAqOgm2whP2j16DLINwk=
X-Google-Smtp-Source: ACHHUZ5rc3bAJVe9QbSCTnyHTvcFoEJEzeqxxlMFitHsNfnP1EtiDCqllIQLqWoyUKB99BfCQ5Xzaw==
X-Received: by 2002:a92:d683:0:b0:33a:3823:bc7a with SMTP id p3-20020a92d683000000b0033a3823bc7amr5813573iln.18.1685636095831;
        Thu, 01 Jun 2023 09:14:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:156a:b0:33b:5017:ce30 with SMTP id
 k10-20020a056e02156a00b0033b5017ce30ls1000878ilu.1.-pod-prod-04-us; Thu, 01
 Jun 2023 09:14:55 -0700 (PDT)
X-Received: by 2002:a6b:f216:0:b0:774:7eca:d9c5 with SMTP id q22-20020a6bf216000000b007747ecad9c5mr8354617ioh.2.1685636095167;
        Thu, 01 Jun 2023 09:14:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685636095; cv=none;
        d=google.com; s=arc-20160816;
        b=HWCFjYzFg7p5zXocwk1hrTlMBjNoAOGbP9tILx2fn/gEJxIueOYWKtsZ8gul+Q4Iei
         SBhKqafS5+GRJjHlBgt47hE+wF+mmzvVES49oG5U19X+7Z8gtvuAEbAH1D4JScHIAHg1
         JcO677hQ5UkNs947psvpsevQHmYzMTjEPx+lzQiwLfCML1sXeDVeosbyPxVUpZcXh4R6
         8fm+LbswWSJc169DRNxV/EjcFLmuUqPKT5y4k3+eQ5UmW2VO1a9EA5/Ixb+OkydplgyQ
         bgGvZm9bGDPXf4WfiaoQ4qZ5FoUVSvNLr+7H5HT3y2UbAnw1y4EUnit12Q9BOKARBdn/
         iJtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hf1MMDnk8ATuiHQnpftM3deH6vV2jBlcAPqcuKGi0Ek=;
        b=brLqCc8GR6Wbd+cB9xPafshs4Xky7+NTIXtqd0iiGOY53asUe9WzJc1ltV3k7QVWCp
         EhrU7vw0jm0HDM9xJ9HYEcAyAKpk5i9gVw31Jknfjsk+am9BCCf9+luxHdHsmzmVqZ/w
         +bDDq7avsncNsiuVnroJI6CW+xn7Xkt+rEcKjGww7QGXIAFZ+JXRPEnTFDfx7/r7pvcE
         3jOFhDCycij6HATLvyjspPnV1Eeag0yqpfKC2xELzGymlA5M8BPez2wwQ9XMsWjQUkIR
         7oYBIDXxbrH+LipRUllc+Nvojq8uM+rxPpIpRnRqrHEh6LjSebqCFQ3cpoYTJTjwHxFE
         H2+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BLOJsskD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id bk7-20020a056602400700b00776f706bc63si1835787iob.3.2023.06.01.09.14.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Jun 2023 09:14:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1b18474cbb6so5954995ad.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Jun 2023 09:14:55 -0700 (PDT)
X-Received: by 2002:a17:902:c20d:b0:1ac:6d4c:c24b with SMTP id 13-20020a170902c20d00b001ac6d4cc24bmr6045835pll.3.1685636094447;
        Thu, 01 Jun 2023 09:14:54 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g14-20020a1709029f8e00b001b176ba9f17sm3680035plq.149.2023.06.01.09.14.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Jun 2023 09:14:53 -0700 (PDT)
Date: Thu, 1 Jun 2023 09:14:53 -0700
From: Kees Cook <keescook@chromium.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	elver@google.com, linux-media@vger.kernel.org,
	linux-crypto@vger.kernel.org, herbert@gondor.apana.org.au,
	ardb@kernel.org, mchehab@kernel.org, Arnd Bergmann <arnd@arndb.de>,
	Dan Carpenter <dan.carpenter@linaro.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, llvm@lists.linux.dev
Subject: Re: [PATCH] [RFC] ubsan: disallow bounds checking with gcov on
 broken gcc
Message-ID: <202306010909.89C4BED@keescook>
References: <20230601151832.3632525-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230601151832.3632525-1-arnd@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BLOJsskD;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Jun 01, 2023 at 05:18:11PM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Combining UBSAN and GCOV in randconfig builds results in a number of
> stack frame size warnings, such as:
> 
> crypto/twofish_common.c:683:1: error: the frame size of 2040 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> drivers/media/platform/mediatek/vcodec/vdec/vdec_vp9_req_lat_if.c:1589:1: error: the frame size of 1696 bytes is larger than 1400 bytes [-Werror=frame-larger-than=]
> drivers/media/platform/verisilicon/hantro_g2_vp9_dec.c:754:1: error: the frame size of 1260 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> drivers/staging/media/ipu3/ipu3-css-params.c:1206:1: error: the frame size of 1080 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> drivers/staging/media/rkvdec/rkvdec-vp9.c:1042:1: error: the frame size of 2176 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]
> drivers/staging/media/rkvdec/rkvdec-vp9.c:995:1: error: the frame size of 1656 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> 
> I managed to track this down to the -fsanitize=bounds option clashing
> with the -fprofile-arcs option, which leads a lot of spilled temporary
> variables in generated instrumentation code.
> 
> Hopefully this can be addressed in future gcc releases the same way
> that clang handles the combination, but for existing compiler releases,
> it seems best to disable one of the two flags. This can be done either
> globally by just not passing both at the same time, or locally using
> the no_sanitize or no_instrument_function attributes in the affected
> functions.
> 
> Try the simplest approach here, and turn off -fsanitize=bounds on
> gcc when GCOV is enabled, leaving the rest of UBSAN working. Doing
> this globally also helps avoid inefficient code from the same
> problem that did not push the build over the warning limit.
> 
> Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
> Link: https://lore.kernel.org/stable/6b1a0ee6-c78b-4873-bfd5-89798fce9899@kili.mountain/
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
> Link: https://godbolt.org/z/zvf7YqK5K
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

I think more production systems will have CONFIG_UBSAN_BOUNDS enabled
(e.g. Ubuntu has had it enabled for more than a year now) than GCOV,
so I'd prefer we maintain all*config coverage for the more commonly
used config.

> ---
>  lib/Kconfig.ubsan | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index f7cbbad2bb2f4..8f71ff8f27576 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -29,6 +29,8 @@ config UBSAN_TRAP
>  
>  config CC_HAS_UBSAN_BOUNDS_STRICT
>  	def_bool $(cc-option,-fsanitize=bounds-strict)
> +	# work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
> +	depends on GCC_VERSION > 140000 || !GCOV_PROFILE_ALL
>  	help
>  	  The -fsanitize=bounds-strict option is only available on GCC,
>  	  but uses the more strict handling of arrays that includes knowledge

Alternatively, how about falling back to -fsanitize=bounds instead, as
that (which has less coverage) wasn't triggering the stack frame
warnings?

i.e. fall back through these:
	-fsanitize=array-bounds (Clang)
	-fsanitize=bounds-strict (!GCOV || bug fixed in GCC)
	-fsanitize=bounds

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202306010909.89C4BED%40keescook.

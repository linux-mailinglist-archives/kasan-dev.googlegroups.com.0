Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT5TSHCQMGQE4N5EFAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id A3C54B2BFB4
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 13:02:41 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61bd4a37a10sf2728013eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 04:02:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755601360; cv=pass;
        d=google.com; s=arc-20240605;
        b=WektCmb5M2fktw410Z+Yd1S/ecc3wzbNd4Doia0iJL6OSknQ3OX/APgh8kCS8JzLQf
         2AJ1+nc2My0RpvPAbZOu+PEoCgYHOjXWI4HGzfoAoNA2K6zlHu1o331ZTOvXZ/vUGiQF
         lcCaMabJ2DsnBAbebWpBDdhoL8cceQq+yJnvCDDzJ/KZw9i0az0pMBBSss7kSM/GvLxC
         RcAbXJBNv+sFKSX5BnvV69Tc+nfQQkMbzXu1hWKXyQ3zckCqzwVDfOZO58vptyO3lYvU
         3SR4tTaEbLNAYlpEy9CoW4v0nNM5xdoblQiiI8qiL6xc0+xuQea5w4cO753dTGQF6Pkf
         Ap1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sBZJ1p2Xb1u1CdH7mrqHLUf3HFhJ1XaHM24ngAlRFHo=;
        fh=Mknr24uI9n/T8OTcMkHATDGJGXDUhp6vP2NxG69rBko=;
        b=Seboa1O5xbYSOCut4HC0TRlFmPUDg7dRx15KuIeFs36tLBvFmTk1uq/wIVvS7j9gSp
         eJdBlbTGAlhUKyzv2yg4+ga8hTGdOY5c0b6HSHyHY/ZoYozbFOdNNjc1ao6JraCQfyvQ
         TgWxuv45j+Q1X5zYnMGKBlgAVqis8nGMlSCyOMaqMetcRdBHkJJPxc5OO63qq6dC+Jaq
         DXlC5DtABF7/GW2X5JDwDcWUeSCDTa79d8qQBdwJcgr8M2S0547zs6sDD5POruHOnSvC
         KCMiRow5zpVEokh1PsDMg0U3UMvl7pcnE0BJwnAiGjascCvpzn2vnin0kagSEUNUJsNs
         oOqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="m66/i4R3";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755601360; x=1756206160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sBZJ1p2Xb1u1CdH7mrqHLUf3HFhJ1XaHM24ngAlRFHo=;
        b=aGDh+CTkmiIfZVCv7uAZLDSyQdCm0bTGzBnkhdzXYdj8nBOxaQqTNqpcoPCFLht1uP
         MEpp8Djcevnlk3teoT6KlWto/IueuRDsz6Arrz+Q3j/0kwpCaC2A2DxJUkh5qqvKQ01T
         UhsPsANZN0AEXppkqkdW7ZThg491YRfk491eqsWy5sXddUrMu7Syl0BLbUS1yGFe/fRh
         KQWGlWDBi8Ee9kNa4HvcvmMRxYOvW1o/LzPA6S5WuHxtDM4UVJ2A78kTXqZTrl89Hq5O
         ZAKEASjmqTHRSjmDK7KzaUOCsZPiX5U7dBcb4RhrjwX7dgR0ACli0hqDniRxWIUhip+6
         wzxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755601360; x=1756206160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sBZJ1p2Xb1u1CdH7mrqHLUf3HFhJ1XaHM24ngAlRFHo=;
        b=w2+q16pa9mVNJ4ziqiPJNFpVPbjU1fYLaCcUnM5ku6E3vEM0qfiw/Sj6Br3WA54hkH
         Lomp1Gb1GKPX6PFHVejCOvNDLyM1VPjXJ8euYMfpLj19wkNq6FJETIqL7nIZm3QyTp+n
         urNtI38VZBFsQjlv66cR81osHxFRYhUwsSX6fLnQ/ilHn+PjmOMUHRSfKDp6pxExWdZ8
         KWsO6m8+mjTziIBZlQE4zje6YJNi/3I8uvIr8oY5IqHcMzclNMCsrMwDVtVqYgIKJ5OD
         wh5nohS2837xtAWoMw1VTyRHfaxKlBQVHI8jb/HXV1XkfSj5bI4X1VlProHl1xNmV/I7
         dpPg==
X-Forwarded-Encrypted: i=2; AJvYcCUUOfNznEralN6yrhi0v0uZTL+CZFVJNbiWzUvgBMCV5ooU3Sn2LFENBEh6yKbQJ/DMGlYsFQ==@lfdr.de
X-Gm-Message-State: AOJu0YwycUdX+TwfLN/p+Mk9tTGRG4unoWLe2/QwTfeFn4+7BNlSubVx
	52QsMKBYYn+Ov2vh0NX9f8RJWfHF4MVSRpV9nD/OZyV6Ye3UiGQrWgG3
X-Google-Smtp-Source: AGHT+IFpeOAH3jUn6Lm9UXOfWnFUoryfPngXhv8PFM1V3RXIoReNj1KbMQeM4l3Cxi990K+tQ5Bv3Q==
X-Received: by 2002:a05:6820:813:b0:61c:b06:e344 with SMTP id 006d021491bc7-61d91a02b55mr1301814eaf.7.1755601360162;
        Tue, 19 Aug 2025 04:02:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/Z9fT+ra/g1r0uAXSkKDYRJTCxwGWPgtgVHfSUJ8aKA==
Received: by 2002:a05:6820:240d:b0:61b:fb56:5dcb with SMTP id
 006d021491bc7-61bfb5661efls476838eaf.2.-pod-prod-03-us; Tue, 19 Aug 2025
 04:02:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWO9dPf4Dv0dv2CukU6AfF4b575S3Z9/6KQzIMrK4diGUgpSfL1JTqWN3qCcuceV52bTEZwc6k+B9M=@googlegroups.com
X-Received: by 2002:a05:6820:1c99:b0:61c:378:acbf with SMTP id 006d021491bc7-61d919f76d9mr1189167eaf.5.1755601359268;
        Tue, 19 Aug 2025 04:02:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755601359; cv=none;
        d=google.com; s=arc-20240605;
        b=QLIvocWm2nS0C+WJHSnzcXsrcJqH83SSR3z7jjS/xa5caiKBavrQ19YMYHktTxZKS7
         +OSQDaVWM+GS6inUefUVG45DE+xCgQii99zwUovk0FzPxIkFOMwZtsDlSY7zuMXU0mW4
         Q7vpp9OFnPHWGxmSiRCPuc4rTGj0pKG5qGauQIHjgXxDNYRHO7yUFrUP23DAUsPoCTs/
         nfVGQSkGbb+CtYs63ohibIkjcuox7zjJu2D61lhRnBrMaIJH072I+IfdtxJeIWaBR6kE
         Qt4ylCiGC2tbbPnn46nP2D5OTHd3cheBgCYTXx+pK37JhPfeWInkHQCMl6Hcs7si/UPq
         68/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sE9Ynzec1RnRGjYxwL9GtFPPQqbiY+yne+LG1e9v81Q=;
        fh=P+OJktLzvmXYsipXVvb2bkGbY6ysPBepKbYDo+TbASM=;
        b=Rde1gAfoKE74MFeWK4gHlXidKlWV05yf7N7ccW9k1PXWgJQ4RHsFCboXZVXMK9K9+3
         4C2a4NH3SsNt/jMkTZXJTfdHXzHHJHq4KYBkXRq1iuvUngQhQV+crw4psiF4HwB0XuNr
         8/wCm/AWWm+tzUJTmqhWkFxKSR7nAx7oSiHFWBhMtGC5EBncc6aSwDnCrye27SGE+8vu
         o+ooMPfV+XjJrQQlbiZ/McylMIHK01/H9tPp0Vu+BxJWFZUKeb6wF0tspi9g89nGBJVc
         y2+ACbjiMeIoxkQdjFKQFmeBY/6ywh5xy0bnAKGcjbnkYNC480421ob+ANMsHSW0XnyE
         eqvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="m66/i4R3";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61bebfe91ffsi61947eaf.2.2025.08.19.04.02.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Aug 2025 04:02:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b471740e488so4862277a12.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Aug 2025 04:02:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDQ7TqrrrNwVcrZvXN28S5YAOQqeh9dIsi2gDEl/kSFTrtn9qnQyAHFSeFVLxUC/R6VFYht1093LU=@googlegroups.com
X-Gm-Gg: ASbGnctfBo6/HmOds3MYbc1EU9KvZr73jEHGPlDw025GxbsxhvQokcaiqyJNvCxSV/W
	ly3wXNuELVRBxVRFCFPHJv3/TjCIFqYWJs+VUxvuBVze6JGPhZW3dR2j2tIRSIYFRkVu41SQDg9
	1GsFDSIip9L95FOxXpUzJyasXTJ5JoATnh9L9BzY3xUAMpYfyaSuZbp1fd2jAoxQhpX+TKbcpqp
	wF5C+9ftL2k63hRu2/V0O0u9dh07N9T8taplWT0q716zaLHS0G/WoLQ
X-Received: by 2002:a17:902:e948:b0:240:6406:c471 with SMTP id
 d9443c01a7336-245e02aa70cmr26553885ad.10.1755601358131; Tue, 19 Aug 2025
 04:02:38 -0700 (PDT)
MIME-Version: 1.0
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org> <20250818-bump-min-llvm-ver-15-v1-10-c8b1d0f955e0@kernel.org>
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-10-c8b1d0f955e0@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Aug 2025 13:02:01 +0200
X-Gm-Features: Ac12FXzKM7g4sH5lbxe25GgocsgKN-jxowhmEsNtouQcGNhuUxoPY2G_RdLPDgM
Message-ID: <CANpmjNNwp=RRc4Tm7vrKkSzYqdJueeDSOkPRY1sCG-2W-yPVdA@mail.gmail.com>
Subject: Re: [PATCH 10/10] KMSAN: Remove tautological checks
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Kees Cook <kees@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, patches@lists.linux.dev, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="m66/i4R3";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 18 Aug 2025 at 20:58, Nathan Chancellor <nathan@kernel.org> wrote:
>
> Now that the minimum supported version of LLVM for building the kernel
> has been bumped to 15.0.0, two KMSAN checks can be cleaned up.
>
> CONFIG_HAVE_KMSAN_COMPILER will always be true when using clang so
> remove the cc-option test and use a simple check for CONFIG_CC_IS_CLANG.
>
> CONFIG_HAVE_KMSAN_PARAM_RETVAL will always be true so it can be removed
> outright.
>
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Acked-by: Marco Elver <elver@google.com>

> ---
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> ---
>  lib/Kconfig.kmsan | 11 +----------
>  1 file changed, 1 insertion(+), 10 deletions(-)
>
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index 0541d7b079cc..7251b6b59e69 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -3,10 +3,7 @@ config HAVE_ARCH_KMSAN
>         bool
>
>  config HAVE_KMSAN_COMPILER
> -       # Clang versions <14.0.0 also support -fsanitize=kernel-memory, but not
> -       # all the features necessary to build the kernel with KMSAN.
> -       depends on CC_IS_CLANG && CLANG_VERSION >= 140000
> -       def_bool $(cc-option,-fsanitize=kernel-memory -mllvm -msan-disable-checks=1)
> +       def_bool CC_IS_CLANG
>
>  config KMSAN
>         bool "KMSAN: detector of uninitialized values use"
> @@ -28,15 +25,9 @@ config KMSAN
>
>  if KMSAN
>
> -config HAVE_KMSAN_PARAM_RETVAL
> -       # -fsanitize-memory-param-retval is supported only by Clang >= 14.
> -       depends on HAVE_KMSAN_COMPILER
> -       def_bool $(cc-option,-fsanitize=kernel-memory -fsanitize-memory-param-retval)
> -
>  config KMSAN_CHECK_PARAM_RETVAL
>         bool "Check for uninitialized values passed to and returned from functions"
>         default y
> -       depends on HAVE_KMSAN_PARAM_RETVAL
>         help
>           If the compiler supports -fsanitize-memory-param-retval, KMSAN will
>           eagerly check every function parameter passed by value and every
>
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNwp%3DRRc4Tm7vrKkSzYqdJueeDSOkPRY1sCG-2W-yPVdA%40mail.gmail.com.

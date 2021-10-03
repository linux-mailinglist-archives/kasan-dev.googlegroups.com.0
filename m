Return-Path: <kasan-dev+bncBDW2JDUY5AORBUHB46FAMGQEGVTMA5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BAE4420335
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 20:05:06 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id d81-20020a251d54000000b005b55772ca97sf20817982ybd.19
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 11:05:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633284305; cv=pass;
        d=google.com; s=arc-20160816;
        b=OL+EYGh/wqyPcv1mCbpNbZSXIG1EIp97OSIijxUkOJvf6AU9h1nzf37hf62nnFsH4g
         CdqPWtYak98JersKwoDN82SEgbzq/T5B4wvcQv1NsGFuaFM9yBMxKfaPmG3SpQqA1Nbi
         Y/lGVw4uvAZWNnSByuyvWg8ePU2OhcqUQqpS4ytYpVd/Vd1vO/0qJq2wtxvfNJ7iTPrc
         xPPg8rHXh9Kic+TI2VEqkgndN7/DBBiavUR/1wLEqPHlHRfGBLF1lOo8e+y4PT4rq+XZ
         RDNa3HUZ1GNS85l9XOBgc5JEReNWoh+xiMF9BvVByuWPpaaI5lGWAFEJ8JVmD4BsStiY
         bOVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TFv2ky/PUZe8q/h4dkx1Q/dvF61Q3XQrifURyG0tZS0=;
        b=tCgAHqis1bflyUljV8Y2L8PirlF6JLEa8Y4uxDxUKYW7JJMGBE7AZVNtsyMA6kcHA+
         h8LyAbzaDqezlc0N3bwKgX02c3kSVCP8OnjXZOFKjJlVwVu2MuvkOBTqZIo6T5Piuf9G
         JNuOgziLp6s9d9GTov/WQCrHtxNlOo1Loa6+cb0nwmATjuq1YZRhfsCbmCuDhZwwzsAe
         RLb8A2uCIP+nQOjBg0sYwspUDSP0vTGxwfJkMRWBzKUDcATdWQ7kKyPTfoaEziqB1l3O
         f06r1/PABoBS+56TXfijL1Garq/kgCWbbg+ZgxUWV4Vc0Cnf82oCeRHjlJcofxoKwS0R
         Tskw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cB6WICj3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TFv2ky/PUZe8q/h4dkx1Q/dvF61Q3XQrifURyG0tZS0=;
        b=PYQl8tNklqbwG1Bd0/DH18KYSEzsdQZzEAfJVa/CiTdkl92pd2omG79D3TtRPIY2Zz
         75aLyPn4L/kPOi9scHQkG7DJIxkpP8bGsFt25UfUuKl4V6He1YMFJlRnGNjj5i8a2lCU
         lPPWw/aJmf5ghcugFHO3G3MHpc9E+y3SwjAge0VDki9dHx3rPDg2Hgyk3HvQZXvPhFJ5
         B1/zBzhKntVhQIEeQ80VrLjrw3pWHQzS4D5nJstTQzOZ9sq9oBy9GahQry5Ri9Upv52G
         n6tbyqQhey1O3IDEWwfPBUzIuIBdOQkSkyl4NwEGSFh6Kjb1qY58/dzhUI+rSTrVwifa
         /Q6w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TFv2ky/PUZe8q/h4dkx1Q/dvF61Q3XQrifURyG0tZS0=;
        b=c/GuIwpyC88OP4ZD49LNicQ4l6IKaCkRRshxETde8zUKysktxwcGdMJ1FMuaYo34r2
         virH1KMngQxnPJAi1ipDxwgZzM3Xf5MnCppEuiEM+cJbTVD7MwMrtgdt85ZxWbgxYGD4
         3jjVO4j+AO7W+hVxf10VDsY0LmWfWDUdRAeIyO4Hyhm7UqXh3CJNnvzxEFLEJYG/09V4
         DcJq5aBPZ29WU7/xKW7vsexJkMUxiF/24JCiimwfCq+W1dPLgnMFKrnnnUGqWkZaI8gi
         1pkODb/P7ZBBN+2CO87I2sxo0M3N0tzISTXGyX8NnhSm6PbacM6vGFW13g1EcanhePNk
         RI2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TFv2ky/PUZe8q/h4dkx1Q/dvF61Q3XQrifURyG0tZS0=;
        b=a+7pCJ8hV8t4/4a5UY1h7UBldUMHy+0YY1101TmYlkeFy/4ZCT8s86HP2Wvy2D/SH0
         WKEr3VZQggktWtbo3cDGDjY7BwALqYpZtaPeQn8gTAYkTz1V4+CbSjCd89Wj3s5qbf26
         gla9YWpgpUtwSKFwS6dWZyqfgjW8JOud5z7uYc0tvAPJtj7/QojF3rruTJQGWwZMM+/0
         eXMsbb/9RSGBF+a4cJ1ZMiADzj1OmR92YZhdE7ODyIvG/5ME8jcZmhDpROQ6+foTV5uk
         AuLOipO5362BMbpLJKs9r6LmRu+mdmKRsbhYYmPh7OQblgg8i9px78I/SjOJWxX/OZGU
         1plA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JKFysgjPcKT7ZxVVv1EjKJvqMg+SyPaAPpdX0HcfG8V6RgWOe
	LCXdYfJTnxJjH3+bf5b+RAs=
X-Google-Smtp-Source: ABdhPJwXoS09sWSDEKOFLCo2xlkVfSpRJaXwDwFYMX4EDnHfJ43zrzVzWXH6Uiw2FfOcToZVsVo4Qg==
X-Received: by 2002:a25:9241:: with SMTP id e1mr10055679ybo.38.1633284304958;
        Sun, 03 Oct 2021 11:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9788:: with SMTP id i8ls5213716ybo.4.gmail; Sun, 03 Oct
 2021 11:05:04 -0700 (PDT)
X-Received: by 2002:a25:45d4:: with SMTP id s203mr10466796yba.425.1633284304499;
        Sun, 03 Oct 2021 11:05:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633284304; cv=none;
        d=google.com; s=arc-20160816;
        b=E9swVRJ15dI34aaBRLOAIiwYUbUe0zyib6POVC8n1TlLIp6fy4jAyuJcVIfmmmfYhM
         Uvp5l7ww6aLqLoGXiy//A1/T610qAz/FZH7EQUq5boX+lQcZDGbdZava7ycXzDqUeVig
         qCOhnh2PcPD4KoWO7gv8r0nAed0kwPstC7HXUTZrlXRVK9gHCXudk+FAhElJmKWIqL+Q
         rt4G4JjX1eE9AqMx+5jZM284LonaDgLSSoAxn2d5nVB5mX7WNsBT0ehUhln3r1Mr1yoD
         WX011/fKFAssRDydxK2Z3E/Mu+cGgnQy7payFKZR/tdKMiDYHELOVXirX8ZCrZUUmwaf
         o3tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0t/uC6UY+gZWkI7u9HEXsrryIwtnXmLh6shI3cfFXHw=;
        b=qUTXLr4kPAIrr5fu5yqRAeVTOgWsJWyOo5liZD/VOOSwJ4GtV0ZJnfWV3IutgrC20K
         oC84CEUu+MVCODPcSBbKEEFFlSqa0mcBOI992VhmxQm5y1F9X0m9rwAJ+61EOrDabunx
         KrFMYXoAFyCWcQQaUPUZRcQ58zSmR4Z12SHUcgqS6hAYKe4VssNiZg4eHyIqbadEmD0f
         s0DDTjWMsnZDsiiWtOPEY7bhJBU9woK6ZJjKXg5OIewB9guESGqio7KXXa558uoqYVw6
         J8O44+QYMwUDXFcM72GYJ3A8s8zsWNyIexRbuCLc+GEkXtUpo8+aijnbQqEx0marRilW
         Uh0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cB6WICj3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id k1si680661ybp.1.2021.10.03.11.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 11:05:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id n71so17792456iod.0
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 11:05:04 -0700 (PDT)
X-Received: by 2002:a6b:c38d:: with SMTP id t135mr6528600iof.99.1633284304078;
 Sun, 03 Oct 2021 11:05:04 -0700 (PDT)
MIME-Version: 1.0
References: <20210922205525.570068-1-nathan@kernel.org>
In-Reply-To: <20210922205525.570068-1-nathan@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 20:04:53 +0200
Message-ID: <CA+fCnZdfMYvQ1o8n41dDzgJUArsUyhnb9Y_azgCVuzj6_KBifA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Nathan Chancellor <nathan@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=cB6WICj3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Sep 22, 2021 at 10:55 PM Nathan Chancellor <nathan@kernel.org> wrote:
>
> Currently, the asan-stack parameter is only passed along if
> CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
> be defined in Kconfig so that the value can be checked. In RISC-V's
> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
> asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
> is disabled, resulting in large stack warnings with allmodconfig:
>
> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12:
> error: stack frame size (14400) exceeds limit (2048) in function
> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> static int lb035q02_connect(struct omap_dss_device *dssdev)
>            ^
> 1 error generated.
>
> Ensure that the value of CONFIG_KASAN_STACK is always passed along to
> the compiler so that these warnings do not happen when
> CONFIG_KASAN_STACK is disabled.
>
> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---
>  scripts/Makefile.kasan | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 801c415bac59..b9e94c5e7097 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -33,10 +33,11 @@ else
>         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
>          $(call cc-param,asan-globals=1) \
>          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> -        $(call cc-param,asan-stack=$(stack_enable)) \
>          $(call cc-param,asan-instrument-allocas=1)
>  endif

This part of code always looked weird to me.

Shouldn't we be able to pull all these options out of the else section?

Then, the code structure would make sense: first, try applying
KASAN_SHADOW_OFFSET; if failed, use CFLAGS_KASAN_MINIMAL; and then try
applying all these options one by one.

> +CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
> +
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
>
> base-commit: 4057525736b159bd456732d11270af2cc49ec21f
> --
> 2.33.0.514.g99c99ed825
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdfMYvQ1o8n41dDzgJUArsUyhnb9Y_azgCVuzj6_KBifA%40mail.gmail.com.

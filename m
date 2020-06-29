Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBG5473QKGQEFHCVVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74F8020CEDA
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 15:37:09 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id a2sf4555652uaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 06:37:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593437828; cv=pass;
        d=google.com; s=arc-20160816;
        b=fVw+tvC5+HKk39Yfs3fA2MH/zvkXI97Vowj76do4GGZHTbyMFHBCL8ZoRz68dvJpfu
         dfDKl1tz4vy3/ZNo+ZZWbiV0SZoPdQISonGz2+O67BrWysSSjyvc2w6CK6oDJjhR6M4r
         r1aXlkyIpZf0owyLhslDzHF/DlVWHMHazs69sd+sbdwjIr4rgYxCjTivMuFMiBqK7RK2
         19c7NTxfJcz8LNGBdMkB5hjp4Ec6jkTtE8hflmJiPUmznAyshOGIcKxWLG+hhCCLDrBm
         xZuqtOWhjYAxtW4x8utkG5flABvgTJorrIuqDO8pqL7IZUKajMScjF5oW06g++G0QH7f
         DnAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iLF2hhJqKWyi0tkO2NE/9izCnEZ3uZ5x05RDxv9dzpw=;
        b=QHVhjWDfrXXiOphRX4eCZ7CBvgpLmk8tS4kO4zRfA7wJNDiNLn1hV+VOLspGQ9vQ/4
         vp2bhwDw/EYxkgv/vsM20YAgKwBOzauYiqdDakdFkEKbw8O7iDOc9R3AnGbb4MLNq6Ep
         NydrfpZaZdMl5TwZsU1eDcWBAoZKsvQTKD4BKgz6zkMmsBKP/Yz/cpSxR3B5vBuJ1P7+
         Ivc1ZMMdMiJ/E+BfC1146+/z2obg3g7XXuXVIXPdSgCEEryYLbKPVDsoxtTF1Oq9VeA8
         2km8FDerBSUWZLu6M8a3ZywY7SIBxzz5ShacIceeJpg5vignSOcC5FKt3hqGT4OHW6/r
         MKBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e/q+PfD5";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iLF2hhJqKWyi0tkO2NE/9izCnEZ3uZ5x05RDxv9dzpw=;
        b=rK8GE6JJCMSWuRSyj5l/nmLx2LmdQ8faEUE+xlWVYOpn3Zy+dc8iyEufi9bGfu8xiX
         TBl5taDNryrdV0C+bduuHw/r5/tYMrpRCORwAjEc4Sp/DDyKA56X6w8UKyPTaG+OQZJD
         kfDJ+ZcAlwutVesXLMmXEfCmOty8V/cvsSGiEmeDtQaYG1+oEDOnZcHIIs7xrHM2n7sJ
         sq4zysF7pwdKozqP0Tfgc7pLS+KAkEL8CZAP7mYUf0GoKWhMqzJeGY44Gjz/+/p0UIAJ
         oOLoQXiUEDyLs4VARTLUfGSKjr3dNDkUU6twjbCKLShPGbcISCpjT4KfGZAaGwiwafIG
         dnzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iLF2hhJqKWyi0tkO2NE/9izCnEZ3uZ5x05RDxv9dzpw=;
        b=JV7xb6pngCtF0vPT5KYFdsMbyIN0oYMdG3e9RvY/QYbOxRf4MIklNSy1BgscgQZ4bu
         oKErRM4JgV/GlZ2ZsK2fNF2yo0H/sV6gWSg3Hjpp9yQ3NUFFRJyasdj4o84sEFdGahvp
         8iRBtjyrolk11lCCJBQGTBw907E8Fh6/XcOteP3k5Z2Z3tXRIR6K2eINUNT4VlQtzxtw
         8HTFYxyfYS1f5cqrlXSn+wuV/nNV8wgzUDV1rWulX2TIPct4dawPqs30mS8TPRfSceiQ
         Y4N9fBmKIJzvYn4dEUlkLxvziueZdU4heGoZZpgTvyM4p11Am47ZUaIY002zDtV5skIz
         RMGw==
X-Gm-Message-State: AOAM533gglxT+/5gQSOZ0pSB03YS5FLJ6qRf1iLSnMq7q894OFe3h83h
	tspfS/GYX1Nzr7yxK80rUvw=
X-Google-Smtp-Source: ABdhPJzQ404OM9fq9mtagZBZq/ayg48NqUNOZEeDeBHM7RbLw3OaYRE8ffHr6oMc0LTqPt5C4kTLbg==
X-Received: by 2002:a1f:9151:: with SMTP id t78mr9917765vkd.89.1593437828303;
        Mon, 29 Jun 2020 06:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:21d0:: with SMTP id r16ls440947vsg.0.gmail; Mon, 29
 Jun 2020 06:37:08 -0700 (PDT)
X-Received: by 2002:a67:b90e:: with SMTP id q14mr11283512vsn.143.1593437827959;
        Mon, 29 Jun 2020 06:37:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593437827; cv=none;
        d=google.com; s=arc-20160816;
        b=b0CIwLQCby/7jnLtyLEOld5b4Yf752j3ns8DW9upeNZruSDD9YKhzUZUkIqCsPFvKJ
         jVdw9IikwciXvSUuL0lC1S/ZBtFPiXwQmRIkP1RpXqfRWzvnNoyC3hpqruy6nYvu5M2G
         Zxblrkd5Z0E+CJ8Tl/WBXYssWJPPRnoEz2bOF91CwLQA2A4llVEqYbmMGRt8CJAj+7gx
         o8ZC6v2gxR/WhazJTY5DfTkmVX5onufWE/qxswQpLNUfnoZhJbWPbOML+iYIGbwoXijx
         FrOA/VjSoXPbfb1elwigCxSXj4KPwd6W0if8wAFqDlZxF1LgMxfVE+SVJ7hVS6IndnqL
         wK6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5YTtTdEX8FTCzpnfrCubKRqJx+y/VqQUc/flbZtjjCI=;
        b=Cnx7wh5ldjOo9OdbYNUJffqrJd+TG9Ep5J84bcXtc4vjr/96w/JtNT+tBLGk1lAZw0
         8kmTPas9rm53QKqAhacs6OPJMNSC2G5wfUoHRNldtaJrO4OQznw++YmuctDyfvM6M+iC
         80GlqRon6Tqj1MgF8HvVCEhFXAZdXHaweNA2JSn+AHCxSpoQYZeSixpbfMdMi0h9aEzs
         l/LPdULE9V6cf+WEEvq7n7H1zol8dEFR+Sysl/01NjYg9L8bXpZfnm3lSZnd4HiwR1Mx
         jQvl2cqdk/X8Rsib1rx7nCNQ4wNWrY+IuSe4iUTQJXpxnUYF45FE0+bvueASBriC1vx5
         /5JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e/q+PfD5";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id a68si1391594vke.1.2020.06.29.06.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 06:37:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id d194so4936154pga.13
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 06:37:07 -0700 (PDT)
X-Received: by 2002:a65:64d8:: with SMTP id t24mr10733075pgv.286.1593437826864;
 Mon, 29 Jun 2020 06:37:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200629104157.3242503-1-elver@google.com> <20200629104157.3242503-2-elver@google.com>
In-Reply-To: <20200629104157.3242503-2-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jun 2020 15:36:55 +0200
Message-ID: <CAAeHK+y=1oocjAMfYd5m2_Zb9Y8M5r0X3K6YYyKvjs+zSAC8tg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: Update required compiler versions in documentation
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Arnd Bergmann <arnd@arndb.de>, Daniel Axtens <dja@axtens.net>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="e/q+PfD5";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jun 29, 2020 at 12:42 PM Marco Elver <elver@google.com> wrote:
>
> Updates the recently changed compiler requirements for KASAN. In
> particular, we require GCC >= 8.3.0, and add a note that Clang 11
> supports OOB detection of globals.
>
> Fixes: 7b861a53e46b ("kasan: Bump required compiler version")
> Fixes: acf7b0bf7dcf ("kasan: Fix required compiler version")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/dev-tools/kasan.rst |  7 ++-----
>  lib/Kconfig.kasan                 | 24 +++++++++++++++---------
>  2 files changed, 17 insertions(+), 14 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..15a2a53e77b0 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -13,11 +13,8 @@ KASAN uses compile-time instrumentation to insert validity checks before every
>  memory access, and therefore requires a compiler version that supports that.
>
>  Generic KASAN is supported in both GCC and Clang. With GCC it requires version
> -4.9.2 or later for basic support and version 5.0 or later for detection of
> -out-of-bounds accesses for stack and global variables and for inline
> -instrumentation mode (see the Usage section). With Clang it requires version
> -7.0.0 or later and it doesn't support detection of out-of-bounds accesses for
> -global variables yet.
> +8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
> +out-of-bounds accesses for global variables is only supported since Clang 11.
>
>  Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 89053defc0d9..047b53dbfd58 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -40,6 +40,7 @@ choice
>           software tag-based KASAN (a version based on software memory
>           tagging, arm64 only, similar to userspace HWASan, enabled with
>           CONFIG_KASAN_SW_TAGS).
> +
>           Both generic and tag-based KASAN are strictly debugging features.
>
>  config KASAN_GENERIC
> @@ -51,16 +52,18 @@ config KASAN_GENERIC
>         select STACKDEPOT
>         help
>           Enables generic KASAN mode.
> -         Supported in both GCC and Clang. With GCC it requires version 4.9.2
> -         or later for basic support and version 5.0 or later for detection of
> -         out-of-bounds accesses for stack and global variables and for inline
> -         instrumentation mode (CONFIG_KASAN_INLINE). With Clang it requires
> -         version 3.7.0 or later and it doesn't support detection of
> -         out-of-bounds accesses for global variables yet.
> +
> +         This mode is supported in both GCC and Clang. With GCC it requires
> +         version 8.3.0 or later. With Clang it requires version 7.0.0 or
> +         later, but detection of out-of-bounds accesses for global variables
> +         is supported only since Clang 11.
> +
>           This mode consumes about 1/8th of available memory at kernel start
>           and introduces an overhead of ~x1.5 for the rest of the allocations.
>           The performance slowdown is ~x3.
> +
>           For better error detection enable CONFIG_STACKTRACE.
> +
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
>
> @@ -73,15 +76,19 @@ config KASAN_SW_TAGS
>         select STACKDEPOT
>         help
>           Enables software tag-based KASAN mode.
> +
>           This mode requires Top Byte Ignore support by the CPU and therefore
> -         is only supported for arm64.
> -         This mode requires Clang version 7.0.0 or later.
> +         is only supported for arm64. This mode requires Clang version 7.0.0
> +         or later.
> +
>           This mode consumes about 1/16th of available memory at kernel start
>           and introduces an overhead of ~20% for the rest of the allocations.
>           This mode may potentially introduce problems relating to pointer
>           casting and comparison, as it embeds tags into the top byte of each
>           pointer.
> +
>           For better error detection enable CONFIG_STACKTRACE.
> +
>           Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
>
> @@ -107,7 +114,6 @@ config KASAN_INLINE
>           memory accesses. This is faster than outline (in some workloads
>           it gives about x2 boost over outline instrumentation), but
>           make kernel's .text size much bigger.
> -         For CONFIG_KASAN_GENERIC this requires GCC 5.0 or later.
>
>  endchoice
>
> --
> 2.27.0.212.ge8ba1cc988-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%3D1oocjAMfYd5m2_Zb9Y8M5r0X3K6YYyKvjs%2BzSAC8tg%40mail.gmail.com.

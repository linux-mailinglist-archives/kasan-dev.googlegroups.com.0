Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK6A3L3AKGQECOWTRZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 495881EC22D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:53:33 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id y10sf3085173pll.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:53:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591124012; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6u2/VZClioGO6PIfYym0SXzNiFNqPUzWZf7FTLGumQ/GzwKsKEON65vtAoXySZvc+
         U7DBNibXLUE40RUdcWIanaXYoJfs1BGne5YQu5DJIFRXZAbXWaUo/+HCXesdpXyiMlYT
         hbD8CnC+yhoGDAYFLlNQ4CLPiJRGXmfobz1846pYAOOFCt0Pe3qkObuE9l3jo3XYWpfR
         zTMiZ0b8dp2J+bakOGUFdUphrE9eMcGeU1d5f+omPIh43CmTb0sfWx47KoeLKk9FygwG
         XkgZ/hlYhfF+FCLfF2vymmAATZnrZJikMkoOW4gotozU5aP0Sr1cTSe1xEKAHBkr+woh
         hpsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c+Q7ZtbTKT4n1PXFCQ/hiGJKgoYzeehdiHNMalCWi/A=;
        b=U4GtFrSW4UTwdXEd3f7IvtMHAVrxtf6uHd9BoZgNW3wdd8xw4kgzdxSG2Kr0Axv+NU
         7aZDBVas9MKwsx/IyBX9s1xcMjZA2wQ1LKogf8yUb1PtBP/qA2XopgUCMQHblqdSkEa/
         hBtDkP9podc+URIK38uy/Uu66jyr4zR6JUcc+5+uPAI0KSS+kGaXxYJjFaHsuIhxGTBZ
         873N00cjoECaArk+aVexVKHtg2M8MQGpF4/U90eU5KxjzLydZaCSIg9ZSy+nXfDlZw5x
         mIPbbPbkViraq8HMNYyDh4sGSS8g5N3glzBhbeKKVh27SySoKvcy3WuIFCbG6PBDvZoW
         xe9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iY81CrGf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c+Q7ZtbTKT4n1PXFCQ/hiGJKgoYzeehdiHNMalCWi/A=;
        b=J/CU5/3vFtZh4jT06Fp8a1fB3NFaKLKdwWTShjwaPHRgSfg1rT2A6tQgMvGhyx61Jf
         F8BwSi8RwIeoa0g8q/H2SgRypJR0ocpZThPNZcFQLhe0Qh5Hld2yLYUr8XY/9+ryj/jV
         EAOW9m7h7qRtkKeGJCXIAixhUcILQ4xRElj+/bXV7tGHjtRAk34oFmBRAVBM9GpxaLIM
         oJ78j7ItX8fpnouEXgXE+pxsrucu6XJINQEvkjObWEFpxTZrV+yBzQ5ZrpEP2GxFtJlm
         N1lr2nMr/hreE/kZOEqB741a/y+ZXt4rGeJMWvE7I180RLy/zQ7BQ5TvJvm1h8e9XM/v
         Exaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c+Q7ZtbTKT4n1PXFCQ/hiGJKgoYzeehdiHNMalCWi/A=;
        b=RmDcEOhKtRWnA2pWwSzHgPVrljmoRVwYPK9VXhc5B1KtxPIwqdLeUZxI5yzTsT41Y7
         Hw8+jzBPw6x4EWSZyORob7oyCz4dDwONxmCZA0yobibAtDtPJ4tGslRTVmKdeEp6ne1I
         30TbDeulD+V4YRSjDucdktHn2TCjJiEV0i2egB9UKUEAWQNJQldYLUGa/FZxs/yhNMYp
         twaYHJQyCS7Q1UefxStEqQMerozjUEB/G7oSQU2/vOlOrSIXcRjUZgnmO1IOGZDmhjF2
         ja/3rqsmYpdiPPqrZBHwVwNuuOsCK3Pp+fVRC9YeJq2Ou13s7zJJsj70Jkz84S+QSjQA
         s0Gw==
X-Gm-Message-State: AOAM532yYUWr53qXYS1vgQQR8/Bxa78GLWf2S3qNJGBZM/MhRRl8FC7j
	QNJ1m290yUYr6KhbA2oxmY8=
X-Google-Smtp-Source: ABdhPJwhvqngOIAlF9V7jsCzoddZ+kFsfifT1h4Mq4lGDRCIXckRJwybUQ9f8w/VKGxSMM9X5GDy6g==
X-Received: by 2002:a65:48c5:: with SMTP id o5mr25707621pgs.193.1591124011849;
        Tue, 02 Jun 2020 11:53:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b82:: with SMTP id w2ls7283665pll.1.gmail; Tue, 02
 Jun 2020 11:53:31 -0700 (PDT)
X-Received: by 2002:a17:90a:ce17:: with SMTP id f23mr636295pju.51.1591124011468;
        Tue, 02 Jun 2020 11:53:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591124011; cv=none;
        d=google.com; s=arc-20160816;
        b=u56dY1o2jPxs9Awlao7laBCQSxgcAhjBk6mrsr1yOxNSCu7HErPwM91f6ReLCJfrpd
         F9i3rSk1YpquR/YrxTWd22W5NlyppNHsl3Ia4wr/rqoXleOs/IK3II5LLq4lKIkLptJg
         ycHmTtAAoLCHHtpAaUEfc0i6fC5x+Xj1NDjfsQadwRrJJpjCO34aUO4K8CoLKiTNgYFF
         wl5ky92SVACNte2gKmHjpBN0lKXnBeVPskjG7PL/OOapkFtTfCdcixvXGjvTRx228JCQ
         gvKzNhtEqRsPPsg1gK+PEM58Tfr8JadjSdZIU1fOrn7+bbJjnM3qhnRWxblQ7clnH1Xi
         08bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lcbY1VrV57GqPoFo7ptDB2znFdFUv0Mj9KOWNzaUW2E=;
        b=Te6Rk5g5yc0nvSRE8cmsa7wBhBCZPImChRAgN4rRX0pHdMkX2tgcWcpAiOKCPEDHUg
         ilh7GpQAo6X86YzgXAwNG/ZiedWbrhsDwT8RcCT0vsvFXFsx9bwMMIXuof76B2dkZvzq
         V/4QK56PX0byap0CFxw9n+wO7ARXjDIv8fOvK32AXPistkvU+MQhn2jxoAyLAsOdsjZi
         V7l4qVw9X8lyfUBjlDSpqQ33Tr7I1YLGSJP5Q3BfAFruZAiylyvZyBkMfV0fsR/5I2SE
         DUWAuwziEndYRxPLBr50aMS0gEc/uWq3kpN6h9JY57k1jieyoaIYRk1C2Yn0B+HUaeUA
         1EUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iY81CrGf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id q12si143925pfu.4.2020.06.02.11.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:53:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id nm22so1867984pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:53:31 -0700 (PDT)
X-Received: by 2002:a17:90a:2a8e:: with SMTP id j14mr627704pjd.136.1591124010835;
 Tue, 02 Jun 2020 11:53:30 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com>
In-Reply-To: <20200602184409.22142-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 20:53:19 +0200
Message-ID: <CAAeHK+wh-T4aGDeQM5Z9tTgZM+Y4xkOavjT7QuR+FHQkY-CHuw@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iY81CrGf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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

On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
>
> Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> have a compiler that does not fail builds due to no_sanitize functions.
> This does not yet mean they work as intended, but for automated
> build-tests, this is the minimum requirement.
>
> For example, we require that __always_inline functions used from
> no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> fails to build entirely, therefore we make the minimum version GCC 8.

Could you also update KASAN docs to mention this requirement? As a
separate patch or in v2, up to you.

>
> For KCSAN this is a non-functional change, however, we should add it in
> case this variable changes in future.
>
> Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Apply after:
> https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
> ---
>  init/Kconfig      | 3 +++
>  lib/Kconfig.kasan | 1 +
>  lib/Kconfig.kcsan | 1 +
>  lib/Kconfig.ubsan | 1 +
>  4 files changed, 6 insertions(+)
>
> diff --git a/init/Kconfig b/init/Kconfig
> index 0f72eb4ffc87..3e8565bc8376 100644
> --- a/init/Kconfig
> +++ b/init/Kconfig
> @@ -39,6 +39,9 @@ config TOOLS_SUPPORT_RELR
>  config CC_HAS_ASM_INLINE
>         def_bool $(success,echo 'void foo(void) { asm inline (""); }' | $(CC) -x c - -c -o /dev/null)
>
> +config CC_HAS_WORKING_NOSANITIZE
> +       def_bool !CC_IS_GCC || GCC_VERSION >= 80000
> +
>  config CONSTRUCTORS
>         bool
>         depends on !UML
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..15e6c4b26a40 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -20,6 +20,7 @@ config KASAN
>         depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
>                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>           designed to find out-of-bounds accesses and use-after-free bugs.
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 5ee88e5119c2..2ab4a7f511c9 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -5,6 +5,7 @@ config HAVE_ARCH_KCSAN
>
>  config HAVE_KCSAN_COMPILER
>         def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           For the list of compilers that support KCSAN, please see
>           <file:Documentation/dev-tools/kcsan.rst>.
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index a5ba2fd51823..f725d126af7d 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
>
>  menuconfig UBSAN
>         bool "Undefined behaviour sanity checker"
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           This option enables the Undefined Behaviour sanity checker.
>           Compile-time instrumentation is used to detect various undefined
> --
> 2.27.0.rc2.251.g90737beb825-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwh-T4aGDeQM5Z9tTgZM%2BY4xkOavjT7QuR%2BFHQkY-CHuw%40mail.gmail.com.

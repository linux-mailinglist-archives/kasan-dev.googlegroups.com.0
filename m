Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHUZO7AMGQEEZLCHIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id A8273A5F9E1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Mar 2025 16:30:09 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4767348e239sf25177011cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Mar 2025 08:30:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741879808; cv=pass;
        d=google.com; s=arc-20240605;
        b=b4nYcr50+Aq7qWFzubU0CYyoCq8WLNRUuSF2QXz8IVslHxyuGNCOp3qjuLrhHMIARB
         c/4Ymq2yDyvxJ98xL4l+yLdRVmKNMDIbfaZaKFcsjWT8BqwsA7cCDHZc1Zd+ZLu2K0Yn
         GH2qsPQz0rvsA60O9LWnCponf0gcpYr/sCAXcIp0utP06FRZiXvZnXjkky3dHKOfIkr5
         yJG537zgB5QKq2j+JGZP3vmTmItPed0bWKNcYYRc/+LZoJKIC0bI8tvIofskx7Ag8W8f
         KwRTYnxX9hvExOEqtaJAE9pF6J53ZtxAW4CfBvjwwwEVO2Ngp1tYt31+NpAjnq2Ypf9I
         3ijw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+b1a/4WkPi32soa37Fm4bP970ABc5KMR4WtkwJRCXLQ=;
        fh=wVZxmT1PC7Zh+m4rr/wXv6S5DHJLckkG5s5aFz/R744=;
        b=bkBSF/F6RcMGs5Lf+xHWXt6KOdCFsfTuqTkFheiIpOhIyV6gdSxaaXUZhK39Sx0FTc
         +EV1k2xFg+BcZPtrogxzEFJrUqvCS0vpUhNXA+EvEvrBDGrINsNu1wWciQqt1wgVrX+3
         PaYxgB5iCk0gNjCPboZ7ayHMiwW5w2+RUfqG6MB5A0z0cHuBhP1f5JSg1rPoHOHZ+VL4
         Bgkwt8vaLfLPpkMl1nLGpKNLGTPuANVYNNbbzevMB+C0DbJT0IIEpsm+sxToAJ/x0c/t
         orHk+aZGfr8BmMeYBmvhEnXEbYZ7bXXcGErkj6mOPZJ0nIozFhvL8QhZzVVRAgfLbn0C
         o4ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zYwwng92;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741879808; x=1742484608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+b1a/4WkPi32soa37Fm4bP970ABc5KMR4WtkwJRCXLQ=;
        b=dXJAcu3z1HvMj9RXUQuHe+Nyhv5LaE+y7MhpybGO9Mn8JUOgi59lIfiko88YSeYu/P
         WZBezkvy+3KkLaaBVjdzcC7A7gjMYLGONnxKhA0LlnmHjSSKZ/cFD3ZiJQPaQ8ydKU3x
         62abo8ynffc0qb2gEqMPs2I//8ZtG3AwuKkcaKF7P8ABU3iGVbUfjHW82xLaiYz4RcDt
         3sFBYsIqT8QPQtqLDinuXILVx7hX/4m3NNCyRmt1XUKySkuLuGcw40qjoJj+YOK9E5rY
         1eFMtIVsBtKezPFUZPi/rLssjA6Stm8RYVjjk9hesd1wPtsjC00GbCms5O9cLeHiaCHF
         Fnhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741879808; x=1742484608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+b1a/4WkPi32soa37Fm4bP970ABc5KMR4WtkwJRCXLQ=;
        b=CsrCj0dJ8JjZ/Avs+x9C4NFdP7wepThei+faoI2yhdfYTv9WwLKXStuPudhOlogeAi
         /pcUb0rQY4QJ8T7KyBZynhsSLXg3W6rzl9JsUnc+eV0YyULOQ3vZ1HoxDo0Lyoq1SlXN
         RgR6Lc/DbN6rXTsEo3+UBW7awI6UZjGqxiOD/IFIIk4da98wL4NybXUWicOWE8ZUqHnA
         BkaAfDOfPlOJgex0uSQFxEWmrvacyQz1saIZcgwNFICnduZI+N9sE24iwcfbtFadVPmf
         wHsfiTV7/isWDrWtl85nzG56o55m5Mojs9NC5DqoKis0SscmGkD7MuP/C2S6jV+retd2
         +mrQ==
X-Forwarded-Encrypted: i=2; AJvYcCVQSUM/+evWPxi+Z4j8kwhbEPdGSiB9m6Tevtz1p80I3uywiE1eV/UP6o0piCIMsed0kkzUFg==@lfdr.de
X-Gm-Message-State: AOJu0YwbpJWstZvSjUlMM23JIWp8ORbSeYQosITNxSpnoOA9juZ7iz5H
	xgH1VFzau+Id6/TV5oKxiy+pU+kB6WnwvBOXQ8HWVDs9d07QQii5
X-Google-Smtp-Source: AGHT+IEwidjiA7PpFrh/wHSEbBxQq5DwxgDjmB1Zx6anl+uQHcgmy9GCArQBcwoRW70lUiV6/wJNxA==
X-Received: by 2002:a05:622a:5cb:b0:474:e255:db2c with SMTP id d75a77b69052e-4769950e09amr139677041cf.26.1741879808515;
        Thu, 13 Mar 2025 08:30:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGpgqee7NSmIpRCJSwHId6JwFsG/nBEUqqVhvnwxn2tfQ==
Received: by 2002:a05:622a:1193:b0:476:b44f:8157 with SMTP id
 d75a77b69052e-476b7c3c472ls4801601cf.0.-pod-prod-02-us; Thu, 13 Mar 2025
 08:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfxwlx7FbmKu6opGkkqaSHKdESvyvqV3AZZvN66KiVkr0xhRe9L8wQmdXkEZG2CNzuo6C2Asf/Sdk=@googlegroups.com
X-Received: by 2002:a05:6122:3196:b0:523:dd87:fe95 with SMTP id 71dfb90a1353d-52419946b48mr13181833e0c.9.1741879807564;
        Thu, 13 Mar 2025 08:30:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741879807; cv=none;
        d=google.com; s=arc-20240605;
        b=jb9X084qv/EYTPoY+efB4pU40LUaoDhVGsAdrfPYGhqk2wdM3UyMylVsxSUakQqv4b
         QW9ln8UZeJRLxnsxLrJg4LjDl5imRWQP9s/HLC1xooonwiaQlfk4LS8RPqpZ4FYFjiCn
         wUctFPic/0o5FR6sVcI6hF8tLrEsQHZjf4lVXPbttCqEJsNCeyohBst80l/NV/k+blu4
         LHpQEIsaHg5nAEHYR7CQJX2TBeZewBbX1TfLDsM/lKDkg8McZQeFcldSsdFxoo8LQzZE
         SS5MERIcZggf6v2BSq2mppExtqrKgIspDiyuz8PlMBKEofBa91LMCGxSzMOcgdZB6H8s
         D+eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=00u7ecFNyPAZ4Z5cOSw/OvdLmibjnRE9ersVFXwW+QE=;
        fh=KkgMk4fzPCvvTejSf79cL/vmORnEaxqjjGMmHov6qpU=;
        b=lSn7XOBwNt1KOf/8DwUN/kKuqDdCm4Tr+ZsHlRVzkA9KeqUNl3wFsMuigMBkxpJ/s/
         1/SUS23zRMOLZZ3aTcGcdfiwv5UyTVoOKsk7I2vjylGaAOVxUy1wdmuxKYas5AND2bCb
         6ep8jQnE38EQKY0wBjZ3Huf6GZ6tMkEbfSMmJriZxoFsh4PgccKbqMdAQH6Kig6J0JND
         Cv3lGXhuHhf1sU1DKaMhVyty0VdleqbADH4OHR+qW3E4ULoErMffBXTnAsgJLl/6KbbQ
         T4M+rvga9Rnm2EerBdAq2d1wzduOONWdX1z2evug2r8NFKrfAh9ds0IUA/SYbZpTmD0q
         2n+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zYwwng92;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5243a58178csi91725e0c.1.2025.03.13.08.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Mar 2025 08:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2ff087762bbso1948198a91.3
        for <kasan-dev@googlegroups.com>; Thu, 13 Mar 2025 08:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJ+Mxp5PQS0adGcYZvvqobsTK+tD9RiKjiFu/Qby/GVHy93rUuu3xc9m2MtuOvpbV4GIG/fWw7nYk=@googlegroups.com
X-Gm-Gg: ASbGnctcN0y86dD9vWMGqtEKMD11pPMw9srKqA/E0hRRg6eBM4yKEoMZQ/JyhdxuG+I
	h283/9pn/+FpEk71qdBNeBAgV3epJwdYN6UShfY17MuvHcwG8+1umOYWlUd5WUYC7Vev8Xx8KMy
	zN6FMZNGwh/l5TlvGoVvuEytypB496fKhAvF2Pog==
X-Received: by 2002:a17:90b:2741:b0:2ff:7b28:a519 with SMTP id
 98e67ed59e1d1-300ff370231mr15211554a91.30.1741879806198; Thu, 13 Mar 2025
 08:30:06 -0700 (PDT)
MIME-Version: 1.0
References: <20250307040948.work.791-kees@kernel.org> <20250307041914.937329-1-kees@kernel.org>
In-Reply-To: <20250307041914.937329-1-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Mar 2025 11:29:29 -0400
X-Gm-Features: AQ5f1Jo2s3dBQmL6L50YXOekPGf_8rCDFxDD6svVuHOtyM0nHf71JobMTMo6fo0
Message-ID: <CANpmjNOHSanxX7EyXhia4AuVd+6q5v1mXQMTM_k0Rj20P_ASAA@mail.gmail.com>
Subject: Re: [PATCH 1/3] ubsan/overflow: Rework integer overflow sanitizer
 option to turn on everything
To: Kees Cook <kees@kernel.org>
Cc: Justin Stitt <justinstitt@google.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>, Miguel Ojeda <ojeda@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Hao Luo <haoluo@google.com>, 
	Przemek Kitszel <przemyslaw.kitszel@intel.com>, linux-hardening@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org, 
	Bill Wendling <morbo@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Tony Ambardar <tony.ambardar@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Jan Hendrik Farr <kernel@jfarr.cc>, Alexander Lobakin <aleksander.lobakin@intel.com>, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zYwwng92;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as
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

On Thu, 6 Mar 2025 at 23:19, Kees Cook <kees@kernel.org> wrote:
>
> Since we're going to approach integer overflow mitigation a type at a
> time, we need to enable all of the associated sanitizers, and then opt
> into types one at a time.
>
> Rename the existing "signed wrap" sanitizer to just the entire topic area:
> "integer wrap". Enable the implicit integer truncation sanitizers, with
> required callbacks and tests.
>
> Notably, this requires features (currently) only available in Clang,
> so we can depend on the cc-option tests to determine availability
> instead of doing version tests.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas@fjasle.eu>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Hao Luo <haoluo@google.com>
> Cc: Przemek Kitszel <przemyslaw.kitszel@intel.com>
> Cc: linux-hardening@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kbuild@vger.kernel.org
> ---
>  include/linux/compiler_types.h  |  2 +-
>  kernel/configs/hardening.config |  2 +-
>  lib/Kconfig.ubsan               | 23 +++++++++++------------
>  lib/test_ubsan.c                | 18 ++++++++++++++----
>  lib/ubsan.c                     | 28 ++++++++++++++++++++++++++--
>  lib/ubsan.h                     |  8 ++++++++
>  scripts/Makefile.lib            |  4 ++--
>  scripts/Makefile.ubsan          |  8 ++++++--
>  8 files changed, 69 insertions(+), 24 deletions(-)
>
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index f59393464ea7..4ad3e900bc3d 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -360,7 +360,7 @@ struct ftrace_likely_data {
>  #endif
>
>  /* Do not trap wrapping arithmetic within an annotated function. */
> -#ifdef CONFIG_UBSAN_SIGNED_WRAP
> +#ifdef CONFIG_UBSAN_INTEGER_WRAP
>  # define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
>  #else
>  # define __signed_wrap
> diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
> index 3fabb8f55ef6..dd7c32fb5ac1 100644
> --- a/kernel/configs/hardening.config
> +++ b/kernel/configs/hardening.config
> @@ -46,7 +46,7 @@ CONFIG_UBSAN_BOUNDS=y
>  # CONFIG_UBSAN_SHIFT is not set
>  # CONFIG_UBSAN_DIV_ZERO is not set
>  # CONFIG_UBSAN_UNREACHABLE is not set
> -# CONFIG_UBSAN_SIGNED_WRAP is not set
> +# CONFIG_UBSAN_INTEGER_WRAP is not set
>  # CONFIG_UBSAN_BOOL is not set
>  # CONFIG_UBSAN_ENUM is not set
>  # CONFIG_UBSAN_ALIGNMENT is not set
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 1d4aa7a83b3a..63e5622010e0 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -116,21 +116,20 @@ config UBSAN_UNREACHABLE
>           This option enables -fsanitize=unreachable which checks for control
>           flow reaching an expected-to-be-unreachable position.
>
> -config UBSAN_SIGNED_WRAP
> -       bool "Perform checking for signed arithmetic wrap-around"
> +config UBSAN_INTEGER_WRAP
> +       bool "Perform checking for integer arithmetic wrap-around"
>         default UBSAN
>         depends on !COMPILE_TEST
> -       # The no_sanitize attribute was introduced in GCC with version 8.
> -       depends on !CC_IS_GCC || GCC_VERSION >= 80000
>         depends on $(cc-option,-fsanitize=signed-integer-overflow)
> -       help
> -         This option enables -fsanitize=signed-integer-overflow which checks
> -         for wrap-around of any arithmetic operations with signed integers.
> -         This currently performs nearly no instrumentation due to the
> -         kernel's use of -fno-strict-overflow which converts all would-be
> -         arithmetic undefined behavior into wrap-around arithmetic. Future
> -         sanitizer versions will allow for wrap-around checking (rather than
> -         exclusively undefined behavior).
> +       depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
> +       depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
> +       depends on $(cc-option,-fsanitize=implicit-unsigned-integer-truncation)

Can these be in 1 cc-option? I know it might look slightly more ugly,
but having 3 different ones will shell out to the compiler 3 times,
which is a little less efficient. At some point it might noticeably
increase the build initialization latency.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHSanxX7EyXhia4AuVd%2B6q5v1mXQMTM_k0Rj20P_ASAA%40mail.gmail.com.

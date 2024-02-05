Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN4NQOXAMGQEAKYJJMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 369A18498D8
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 12:30:01 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3bfbc5de7b4sf4594204b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 03:30:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707132600; cv=pass;
        d=google.com; s=arc-20160816;
        b=LSf4PtM38JPTYS8lvi7fZwyHX7cfequDSTxhsc05Ns5i0sNF2JWJtwIxYsEqvp71qO
         YO9gPRJ6/gmi0HPc99m+VcW/UHAVl1O3d0FQBbEw4hzrYh685nvGhfOVlL+dL++Jczl3
         6pUNeucqKkEUcGXZmJVVpuLzG0J0azkFuRuJbca5DxuTQwuYMyMbAZrBdTPhRrWBebRH
         lbKmd6GG0hJdKfQusgLGmY0DxVT8N3Xk1WpgWqdOwtr/DXM2djs8yLxYb8tBAqyguTGt
         icghcOSJr9js9Apm61BdUi5FvUeO6oPplU3XSfvSr06H+DXGhiuwcS+5VIk4gmggZJL5
         RXBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8czn+ZjiDP09DB7PHwBj838fI0JJ7M8naPXPzQU5ZmA=;
        fh=FuxCWASizshHVamNIgsg7edI791GMw8EtBI8RGL60+Q=;
        b=r4msDukHm4rgVlXZteaCPP/IiuNDgJzJw81FXNbz/2uRk1VbrOUUgISWnS/WdGdNoe
         Cw8cm+QBClq6bPzNXiGxwOVgd0mFO/eB7cqVDQXkYTgL0JVT7O7lzsDhpIXPXTNTyRv5
         1v755GVC0hyivm+sxLX0Z3N8BwintDNVxIxpwGA6HKeU+QuN6IZ9DD02Tk7wVMbc8+DQ
         Do8b0DH4mKxlYdFM0JaisP2yEc7etT3o9EGS0xrIVYuz+/pTGYHSJqvY8Gxtmn6I9Ajq
         1R0MeshiAuBOF8OIqQKWFlUd/ROTlO9h0xR2rCB/A8Y02laq9eYAT8aLKD61XFKh/9dN
         JYng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="PS8J/eQc";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707132600; x=1707737400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8czn+ZjiDP09DB7PHwBj838fI0JJ7M8naPXPzQU5ZmA=;
        b=GLRE5354s6PYpjc2TQB8G4D0lrb+s3EPRzBo6uRTWAxMChKG1Du1/SSnfcf/uKRELG
         4+6QedDJ5z7e3LPdOFPINmt8pYgnY32/u79ULi6ZMQ156EacB9v84u6zHt9aIwNcGfuf
         OyliQmRamJXze5pIsDJRs9lokFGa4zPCAyBe9IT6r5FTXM5BpAMO6mQ4eQ/6+3u15Z1I
         fgQXLZiUf3jlVfBmwQQ+5PtAT0ybGPM5jcepwvoG/QbG75f063TItU++drAKC/zeAvNY
         pcG23QPmIB4nvfwKTKNzpm5rORiVYnJlbJwSiJldi2JgRmzxXqts3gRVxZcsDxUZ1tSm
         LDKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707132600; x=1707737400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8czn+ZjiDP09DB7PHwBj838fI0JJ7M8naPXPzQU5ZmA=;
        b=ja6xXpHI5XqJi60No8AfAk6FsE3EWA4ifpI+fSBBJdP4OpmJIT5NYysRUYl7Bid72l
         2/Cs0ousMGJZWiDjCUrNO8zMR81DUeprnrbj+p8X5P6cm/WS/XA/V6aueuBOcfWIlRgz
         e85ZhbH8FQf77+izVz6YPUpE3cd48akbHx3xyCV+WEWwcZhI0aNX2a2Vj733LXFdSxFX
         5LTIZs+lgBp/dAukbBuNYPdLmYNadzQy/8OeL15MdQbRG3vRqf0mNzO6cWVhamAvd8DO
         eLfRi+dcNF0Tqnc2AD1cc0gu3X/7JTZUk3kKW0GCKS5hhqavPvtRZJTkwSs8aP58UwFM
         7jlg==
X-Gm-Message-State: AOJu0YxxV+XJJtWA1HAt5brcMW2s9PORPrpOX5EnxAcy4GrUlWP7CzSX
	c/6B6jMyFXlmT7idCUu9omkopWHMUE3QKglDYupy526yybsj3RV+vxI=
X-Google-Smtp-Source: AGHT+IE5SCqD8Sq/JvfBcU7XD0RoE7AABSpGemVP6jO3FIs0qpkkOM/PrXaExF+mjHpc9uQf2ueCnQ==
X-Received: by 2002:a05:6808:2e8b:b0:3bf:cf7f:42e9 with SMTP id gt11-20020a0568082e8b00b003bfcf7f42e9mr9363543oib.43.1707132599912;
        Mon, 05 Feb 2024 03:29:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4196:b0:6e0:2469:fa1c with SMTP id
 ca22-20020a056a00419600b006e02469fa1cls816843pfb.2.-pod-prod-07-us; Mon, 05
 Feb 2024 03:29:58 -0800 (PST)
X-Received: by 2002:aa7:80ce:0:b0:6df:f8db:44db with SMTP id a14-20020aa780ce000000b006dff8db44dbmr6191139pfn.16.1707132598492;
        Mon, 05 Feb 2024 03:29:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707132598; cv=none;
        d=google.com; s=arc-20160816;
        b=MYM08cGL56vgxsyp/mbKkI7ks1+ycNTv3EDekCyELphdf12TJB0BLpMgle9MO0v/1Z
         tsb7lxUKtFSj5EYauFZ6ElGXHW20IDziv9gnryavfmgN/EIYA2PE+iipH4c77qMyuGe1
         udvR8xAWANPzKyno1gh23G7Azm4UHtIlNo6z0hgdvIUJjFGIVCfh70czrVJU0rKG7/Y4
         skMh8nHIfALuv6x30F8r/f0BcXcrmoPqPrzPh7xln8Zn8vyC9telysjTfZ5UaNDUkDo7
         5W3yTL+dbh85n9kjosLEq3eORhz0VbTdFk0FO+959qTf89lpAGzSusdBUyoLw/lweLhU
         ueAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vvI9aaRfua6v4nfD4rYGGOnDdTCaiW+Zj9IgNXb8Lrs=;
        fh=FuxCWASizshHVamNIgsg7edI791GMw8EtBI8RGL60+Q=;
        b=GeeZjDGJ7w6KLwd0h8O5ipUQpkTjGt+DMgXqfw58Up2/QvS3hWS2qAbhjx4nShjMVP
         6z8A5CmQd9TkKT51WLiHjF+5Qg85vmD0WLjQd/dfz+9Gc0Ur5ZqSO8wCDsgaAuzSgnvs
         LHihYG75C8uOn8MXo0zexk/HBWwYLu9kQE6iSqLu3LDItwKnHjeMt0PJ0Tv9W/LgAl9E
         pXJec8kPl3Q1yVj73+I37yWo78X6/8V3DStaVzJmCEAF9//VDx0psJvjH/4hEWiiW9iH
         dFGLePpxJIcmac77n1DSuA1oe1QeGf2ueOuA3tdApsUznnFyzy9HTtOgIv7Yf8fF6THE
         apvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="PS8J/eQc";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCUCpvoH+0fZsbxMFpBwfPJhgaB72mGV+rjqhH8FNS3QtkV6Cn98RBuiXhzLdNVOfGtLfcODR1tJx8fHRmJ9cWVSmurpAdDxCc6anQ==
Received: from mail-vk1-xa2d.google.com (mail-vk1-xa2d.google.com. [2607:f8b0:4864:20::a2d])
        by gmr-mx.google.com with ESMTPS id s9-20020a056a00178900b006e045ae9ba1si115216pfg.5.2024.02.05.03.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 03:29:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) client-ip=2607:f8b0:4864:20::a2d;
Received: by mail-vk1-xa2d.google.com with SMTP id 71dfb90a1353d-4c02be905beso222977e0c.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 03:29:58 -0800 (PST)
X-Received: by 2002:a1f:fc0e:0:b0:4c0:2767:b778 with SMTP id
 a14-20020a1ffc0e000000b004c02767b778mr1353840vki.16.1707132597345; Mon, 05
 Feb 2024 03:29:57 -0800 (PST)
MIME-Version: 1.0
References: <20240205093725.make.582-kees@kernel.org>
In-Reply-To: <20240205093725.make.582-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 12:29:21 +0100
Message-ID: <CANpmjNO0QOsHQOqDf_87uXFB0a=p6BW+=zF_ypb5K0FbaObvzA@mail.gmail.com>
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
To: Kees Cook <keescook@chromium.org>
Cc: Justin Stitt <justinstitt@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>, 
	Nick Desaulniers <ndesaulniers@google.com>, Przemek Kitszel <przemyslaw.kitszel@intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="PS8J/eQc";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, 5 Feb 2024 at 10:37, Kees Cook <keescook@chromium.org> wrote:
>
> In order to mitigate unexpected signed wrap-around[1], bring back the
> signed integer overflow sanitizer. It was removed in commit 6aaa31aeb9cf
> ("ubsan: remove overflow checks") because it was effectively a no-op
> when combined with -fno-strict-overflow (which correctly changes signed
> overflow from being "undefined" to being explicitly "wrap around").
>
> Compilers are adjusting their sanitizers to trap wrap-around and to
> detecting common code patterns that should not be instrumented
> (e.g. "var + offset < var"). Prepare for this and explicitly rename
> the option from "OVERFLOW" to "WRAP".
>
> To annotate intentional wrap-around arithmetic, the add/sub/mul_wrap()
> helpers can be used for individual statements. At the function level,
> the __signed_wrap attribute can be used to mark an entire function as
> expecting its signed arithmetic to wrap around. For a single object file
> the Makefile can use "UBSAN_WRAP_SIGNED_target.o := n" to mark it as
> wrapping, and for an entire directory, "UBSAN_WRAP_SIGNED := n" can be
> used.
>
> Additionally keep these disabled under CONFIG_COMPILE_TEST for now.
>
> Link: https://github.com/KSPP/linux/issues/26 [1]
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Hao Luo <haoluo@google.com>
> Signed-off-by: Kees Cook <keescook@chromium.org>

Looks good.

Reviewed-by: Marco Elver <elver@google.com>

And just to double check, you don't think we need 'depends on EXPERT'
(or DEBUG_KERNEL) to keep the noise down initially?

> ---
> v3:
>  - split out signed overflow sanitizer so we can do each separately

Thanks for splitting.

> v2: https://lore.kernel.org/all/20240202101311.it.893-kees@kernel.org/
> v1: https://lore.kernel.org/all/20240129175033.work.813-kees@kernel.org/
> ---
>  include/linux/compiler_types.h |  9 ++++-
>  lib/Kconfig.ubsan              | 14 +++++++
>  lib/test_ubsan.c               | 37 ++++++++++++++++++
>  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
>  lib/ubsan.h                    |  4 ++
>  scripts/Makefile.lib           |  3 ++
>  scripts/Makefile.ubsan         |  3 ++
>  7 files changed, 137 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 6f1ca49306d2..ee9d272008a5 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -282,11 +282,18 @@ struct ftrace_likely_data {
>  #define __no_sanitize_or_inline __always_inline
>  #endif
>
> +/* Do not trap wrapping arithmetic within an annotated function. */
> +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> +#else
> +# define __signed_wrap
> +#endif
> +
>  /* Section for code which can't be instrumented at all */
>  #define __noinstr_section(section)                                     \
>         noinline notrace __attribute((__section__(section)))            \
>         __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> -       __no_sanitize_memory
> +       __no_sanitize_memory __signed_wrap
>
>  #define noinstr __noinstr_section(".noinstr.text")
>
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 56d7653f4941..129e9bc21877 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -116,6 +116,20 @@ config UBSAN_UNREACHABLE
>           This option enables -fsanitize=unreachable which checks for control
>           flow reaching an expected-to-be-unreachable position.
>
> +config UBSAN_SIGNED_WRAP
> +       bool "Perform checking for signed arithmetic wrap-around"
> +       default UBSAN
> +       depends on !COMPILE_TEST
> +       depends on $(cc-option,-fsanitize=signed-integer-overflow)
> +       help
> +         This option enables -fsanitize=signed-integer-overflow which checks
> +         for wrap-around of any arithmetic operations with signed integers.
> +         This currently performs nearly no instrumentation due to the
> +         kernel's use of -fno-strict-overflow which converts all would-be
> +         arithmetic undefined behavior into wrap-around arithmetic. Future
> +         sanitizer versions will allow for wrap-around checking (rather than
> +         exclusively undefined behavior).
> +
>  config UBSAN_BOOL
>         bool "Perform checking for non-boolean values used as boolean"
>         default UBSAN
> diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> index f4ee2484d4b5..276c12140ee2 100644
> --- a/lib/test_ubsan.c
> +++ b/lib/test_ubsan.c
> @@ -11,6 +11,39 @@ typedef void(*test_ubsan_fp)(void);
>                         #config, IS_ENABLED(config) ? "y" : "n");       \
>         } while (0)
>
> +static void test_ubsan_add_overflow(void)
> +{
> +       volatile int val = INT_MAX;
> +
> +       UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +       val += 2;
> +}
> +
> +static void test_ubsan_sub_overflow(void)
> +{
> +       volatile int val = INT_MIN;
> +       volatile int val2 = 2;
> +
> +       UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +       val -= val2;
> +}
> +
> +static void test_ubsan_mul_overflow(void)
> +{
> +       volatile int val = INT_MAX / 2;
> +
> +       UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +       val *= 3;
> +}
> +
> +static void test_ubsan_negate_overflow(void)
> +{
> +       volatile int val = INT_MIN;
> +
> +       UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +       val = -val;
> +}
> +
>  static void test_ubsan_divrem_overflow(void)
>  {
>         volatile int val = 16;
> @@ -90,6 +123,10 @@ static void test_ubsan_misaligned_access(void)
>  }
>
>  static const test_ubsan_fp test_ubsan_array[] = {
> +       test_ubsan_add_overflow,
> +       test_ubsan_sub_overflow,
> +       test_ubsan_mul_overflow,
> +       test_ubsan_negate_overflow,
>         test_ubsan_shift_out_of_bounds,
>         test_ubsan_out_of_bounds,
>         test_ubsan_load_invalid_value,
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index df4f8d1354bb..5fc107f61934 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -222,6 +222,74 @@ static void ubsan_epilogue(void)
>         check_panic_on_warn("UBSAN");
>  }
>
> +static void handle_overflow(struct overflow_data *data, void *lhs,
> +                       void *rhs, char op)
> +{
> +
> +       struct type_descriptor *type = data->type;
> +       char lhs_val_str[VALUE_LENGTH];
> +       char rhs_val_str[VALUE_LENGTH];
> +
> +       if (suppress_report(&data->location))
> +               return;
> +
> +       ubsan_prologue(&data->location, type_is_signed(type) ?
> +                       "signed-integer-overflow" :
> +                       "unsigned-integer-overflow");
> +
> +       val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
> +       val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
> +       pr_err("%s %c %s cannot be represented in type %s\n",
> +               lhs_val_str,
> +               op,
> +               rhs_val_str,
> +               type->type_name);
> +
> +       ubsan_epilogue();
> +}
> +
> +void __ubsan_handle_add_overflow(void *data,
> +                               void *lhs, void *rhs)
> +{
> +
> +       handle_overflow(data, lhs, rhs, '+');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_add_overflow);
> +
> +void __ubsan_handle_sub_overflow(void *data,
> +                               void *lhs, void *rhs)
> +{
> +       handle_overflow(data, lhs, rhs, '-');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_sub_overflow);
> +
> +void __ubsan_handle_mul_overflow(void *data,
> +                               void *lhs, void *rhs)
> +{
> +       handle_overflow(data, lhs, rhs, '*');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_mul_overflow);
> +
> +void __ubsan_handle_negate_overflow(void *_data, void *old_val)
> +{
> +       struct overflow_data *data = _data;
> +       char old_val_str[VALUE_LENGTH];
> +
> +       if (suppress_report(&data->location))
> +               return;
> +
> +       ubsan_prologue(&data->location, "negation-overflow");
> +
> +       val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
> +
> +       pr_err("negation of %s cannot be represented in type %s:\n",
> +               old_val_str, data->type->type_name);
> +
> +       ubsan_epilogue();
> +}
> +EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
> +
> +
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
>  {
>         struct overflow_data *data = _data;
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 5d99ab81913b..0abbbac8700d 100644
> --- a/lib/ubsan.h
> +++ b/lib/ubsan.h
> @@ -124,6 +124,10 @@ typedef s64 s_max;
>  typedef u64 u_max;
>  #endif
>
> +void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_negate_overflow(void *_data, void *old_val);
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
>  void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
>  void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 52efc520ae4f..7ce8ecccc65a 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -177,6 +177,9 @@ ifeq ($(CONFIG_UBSAN),y)
>  _c_flags += $(if $(patsubst n%,, \
>                 $(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)y), \
>                 $(CFLAGS_UBSAN))
> +_c_flags += $(if $(patsubst n%,, \
> +               $(UBSAN_WRAP_SIGNED_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_SIGNED)$(UBSAN_SANITIZE)y), \
> +               $(CFLAGS_UBSAN_WRAP_SIGNED))
>  endif
>
>  ifeq ($(CONFIG_KCOV),y)
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 7cf42231042b..bc957add0b4d 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -13,3 +13,6 @@ ubsan-cflags-$(CONFIG_UBSAN_ENUM)             += -fsanitize=enum
>  ubsan-cflags-$(CONFIG_UBSAN_TRAP)              += $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
>
>  export CFLAGS_UBSAN := $(ubsan-cflags-y)
> +
> +ubsan-wrap-signed-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)     += -fsanitize=signed-integer-overflow
> +export CFLAGS_UBSAN_WRAP_SIGNED := $(ubsan-wrap-signed-cflags-y)
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0QOsHQOqDf_87uXFB0a%3Dp6BW%2B%3DzF_ypb5K0FbaObvzA%40mail.gmail.com.

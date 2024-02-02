Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4X6OWQMGQEDFSFD4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 52AA1846E8F
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 12:02:38 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-35fc6976630sf17472355ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 03:02:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706871757; cv=pass;
        d=google.com; s=arc-20160816;
        b=HnlfkX3y9aqC+5MUkyG0twyN0/1WIKuZJUW2VBuv7jCwE40jPUDZ8WIByWYmpyQtnt
         A2w2zN/HaqX8jeRBGVufIFAos8eGQSm/zqg79UX+6WNl4A4+0jVzf5PiC483t7BuguNQ
         ecy0/LLkZKkrqWMijptEbd2zOw+lMjhipxW5NfVoXmOG/TBXcgWqx14Buc85kjFHBp3b
         0X4kzPziTSgfR06nH5shMrwtDzWLahcmRhNcCoO7mOjhuWBhOFuAJoK0gEDt23Z1v9Qa
         +pRnQocbwMpE71l+pBMqk9xjsWnB/ZudloHnWxzXZ9YzHcgfTw+8ZMR2h1nOS3NflojW
         5QNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Iiaj66/nKYZCmja1XbY+myPrWnI6VAT0fR9PqjuxGBs=;
        fh=WmfqnsCZYJGVMf5fGQLHecXxUTj0kSote3wp9NhbJY0=;
        b=sOlM2E6reu+tXUV1gjE+XJeYrd7xPI18ZdZ+aleHWkwieUAdxuk/eFtBePJZxFbM+2
         8Kd/SPKz6v9UTQ0tcDYww5AajmkvtBwyg4Mo2dfkz1IYUkzs3e5xSObMV6lokNRa8sn3
         Z1dDnQPKOVRnu4ykoMOzuQMfB1CywCm/xFAyeuVnmwqTNIiUI7C3ALQPIkyRA5iE8nD/
         0Ygo79ievHBKAO5rZqCsjjUAGbuhRu4YMw5rBpsaS1uLYxIH89cHbWR73ATjcnN/7E5E
         B0BwTXAexv9UdU9xH8xZ5ebcatAFNm/7CS0j4NrBvorT9B+Hw1rPZ+PydSpsfHnVspFO
         Q8Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sAQU1r9P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706871757; x=1707476557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iiaj66/nKYZCmja1XbY+myPrWnI6VAT0fR9PqjuxGBs=;
        b=GU8uzZmx+A08pUOJM80N++CAquSwXVz3erhOKhSHKtcdoAs/wEqPELwSNZ6dQbnwXS
         vx7d3kXQC6wNAOLryzBfnaYblQaKldTHtBVESkDujyIndWQ8mASfco6aJNq2NQIIO9/J
         tXid+UW1U94ea0aIsR4Lj5C0W+prCMFHEGso6NkYxK6peqkM5ZI6MFm+0waJZ8oMTzbo
         QGXnEGjajBR6EuBrmJDgU531PgrfcMOLTkSy5u0o9IhNBMVcTrPWs4Lu6xHbBk0Y9Dkz
         wvOTa+TY5YRPiNdYDbSDqmHOf8vrrK8/b5frvy6j4hUtIZ7hvGauYfVWtzyisozTeg05
         l1KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706871757; x=1707476557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Iiaj66/nKYZCmja1XbY+myPrWnI6VAT0fR9PqjuxGBs=;
        b=TJaP85lks5pL0Y8hktrPkRxeN0uICPehC3blOzE7AoNDDyC4AfkPD6T2thbXfaFNq7
         IjE6AdwUnidh9DW7su3YMKRSfHdZt/wOVsE9ZCaRMVU7vQKhayZAAOWKcum5W3bay1xn
         7rkV11giJHGX9GXXjAZsmbVftVC5uwm+2LlypZ8G71wE1quWS+B9OwlrgCWN8KD+QqiO
         mUOfol1EhJg3XENwbw5nLB0+yv7dvMFRg9zuaKuZauLhrhz6NCiZZNCvOmLULaAs3dsp
         i2JTQhe8CQXJ9GIX+CpZeo4O/o53pysuxGiQ6K2OB5F+ZRLB40yiymRm/DW3gJWq3C0D
         KYWA==
X-Gm-Message-State: AOJu0YwDGu37xx5+a2XFXIZm/a8Y5SRkRE9oXh6wK8KYIBQuCHq5LFmV
	f4Lo0YBnkBW8YpfEvhCvedy/pFukYE5MQBApyMe9E+c7+G0Ey8+w
X-Google-Smtp-Source: AGHT+IHAPnjLcFwMZA+6GkQ/3mGHQbabL2Q2exmz0wIPGu9KbH81yVd1SqK8sV4tYUhHGy17IEUlZw==
X-Received: by 2002:a05:6e02:96d:b0:363:8440:94af with SMTP id q13-20020a056e02096d00b00363844094afmr1499180ilt.4.1706871755730;
        Fri, 02 Feb 2024 03:02:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:32c2:b0:363:7ae1:ab51 with SMTP id
 bl2-20020a056e0232c200b003637ae1ab51ls372627ilb.1.-pod-prod-04-us; Fri, 02
 Feb 2024 03:02:34 -0800 (PST)
X-Received: by 2002:a5e:a919:0:b0:7bf:f210:d48a with SMTP id c25-20020a5ea919000000b007bff210d48amr1862984iod.6.1706871754695;
        Fri, 02 Feb 2024 03:02:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706871754; cv=none;
        d=google.com; s=arc-20160816;
        b=H1K6VsXdx+3NTUp2LgC3Juu3rlLF0MV2xFv0km+2baUFiJY2JbNSjh1Gb/ZuWaN2UB
         nJ/48kDhI/fMetX9VaKRfPfzZOfV+CiobphiXq3etGoDcrivjRj960PxMHPQ/X2oI7gL
         tyZpcjGC2eDCRqntRMOoB2johfrd/phze4xkROGADTyDyks+T/9MC0b+PIr+stvOQhEE
         SSwIYyet7UPmbWft1hDvUUDGCvmdrpX/9s1EDx36oBfkcrjhCv3iTURiMXuCkYxShT+D
         oKs+5SBqjBXpE7shUa2esKvGXPRV4puwz922vXF2j2rIeaJVxvezWPo2ZnQak9/0+Jmm
         FBnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AKvTOkMfs92gzE0M+TFiSJEhkCKRpJTzmpH7agAwUHE=;
        fh=WmfqnsCZYJGVMf5fGQLHecXxUTj0kSote3wp9NhbJY0=;
        b=P/xnhLKPh6zrQkxwxgApXRnevvYGeKSa+dQjZVGUspb9vgcxFydATkJspw8N8AJ7xJ
         /cEhgKK8PUBstcXwI+d8s32MtXifXO8ygM17eUehawYYsGSbtrQVlsFBhDE47WUz1tiN
         jw2iXkszZLw6ydJxIEleqjWqiIT6ZQ1yaDSoLMx3/nNdqQR8cl0tvoGTQkmii0+A4QKE
         gYuHQX+qkqP1DAux3+Nmc2Oid4vRtAvpgSDkkGmsNx3PqftGMN90w1nAFYlwuYjIw3Ub
         /RHZmSW9TBdWOqpWP0XrNtX4kKKWb6JrECJN9vR48NnmJSbZBWBlXU2Tly6Ry1Sk7LWD
         2Sfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sAQU1r9P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCXrg0MaOxB5uWob67ohVYjWjebA2aXeQ+Nf88VOBiKOG1yx8ajmXKzZ+Tlle8MgI1fd5QMBCEl5yTY4KtjWHFwwR/u/wpzMjtYrOg==
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id t2-20020a5edd02000000b007bef30e05ebsi59247iop.4.2024.02.02.03.02.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 03:02:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id 5614622812f47-3be6df6bc9bso1252058b6e.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 03:02:34 -0800 (PST)
X-Received: by 2002:a05:6808:10c3:b0:3bf:80de:9831 with SMTP id
 s3-20020a05680810c300b003bf80de9831mr1988318ois.10.1706871754161; Fri, 02 Feb
 2024 03:02:34 -0800 (PST)
MIME-Version: 1.0
References: <20240202101311.it.893-kees@kernel.org> <20240202101642.156588-2-keescook@chromium.org>
In-Reply-To: <20240202101642.156588-2-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Feb 2024 12:01:55 +0100
Message-ID: <CANpmjNPPbTNPJfM5MNE6tW-jCse+u_RB8bqGLT3cTxgCsL+x-A@mail.gmail.com>
Subject: Re: [PATCH v2 2/6] ubsan: Reintroduce signed and unsigned overflow sanitizers
To: Kees Cook <keescook@chromium.org>
Cc: linux-hardening@vger.kernel.org, Justin Stitt <justinstitt@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Hao Luo <haoluo@google.com>, Przemek Kitszel <przemyslaw.kitszel@intel.com>, 
	Fangrui Song <maskray@google.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, Bill Wendling <morbo@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Jonathan Corbet <corbet@lwn.net>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org, netdev@vger.kernel.org, 
	linux-crypto@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-acpi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sAQU1r9P;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Fri, 2 Feb 2024 at 11:16, Kees Cook <keescook@chromium.org> wrote:
>
> Effectively revert commit 6aaa31aeb9cf ("ubsan: remove overflow
> checks"), to allow the kernel to be built with the "overflow"
> sanitizers again. This gives developers a chance to experiment[1][2][3]
> with the instrumentation again, while compilers adjust their sanitizers
> to deal with the impact of -fno-strict-oveflow (i.e. moving from
> "overflow" checking to "wrap-around" checking).
>
> Notably, the naming of the options is adjusted to use the name "WRAP"
> instead of "OVERFLOW". In the strictest sense, arithmetic "overflow"
> happens when a result exceeds the storage of the type, and is considered
> by the C standard and compilers to be undefined behavior for signed
> and pointer types (without -fno-strict-overflow). Unsigned arithmetic
> overflow is defined as always wrapping around.
>
> Because the kernel is built with -fno-strict-overflow, signed and pointer
> arithmetic is defined to always wrap around instead of "overflowing"
> (which could either be elided due to being undefined behavior or would
> wrap around, which led to very weird bugs in the kernel).
>
> So, the config options are added back as CONFIG_UBSAN_SIGNED_WRAP and
> CONFIG_UBSAN_UNSIGNED_WRAP. Since the kernel has several places that
> explicitly depend on wrap-around behavior (e.g. counters, atomics, crypto,
> etc), also introduce the __signed_wrap and __unsigned_wrap function
> attributes for annotating functions where wrapping is expected and should
> not be instrumented. This will allow us to distinguish in the kernel
> between intentional and unintentional cases of arithmetic wrap-around.
>
> Additionally keep these disabled under CONFIG_COMPILE_TEST for now.
>
> Link: https://github.com/KSPP/linux/issues/26 [1]
> Link: https://github.com/KSPP/linux/issues/27 [2]
> Link: https://github.com/KSPP/linux/issues/344 [3]
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Hao Luo <haoluo@google.com>
> Cc: Przemek Kitszel <przemyslaw.kitszel@intel.com>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  include/linux/compiler_types.h | 14 ++++++-
>  lib/Kconfig.ubsan              | 19 ++++++++++
>  lib/test_ubsan.c               | 49 ++++++++++++++++++++++++
>  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
>  lib/ubsan.h                    |  4 ++
>  scripts/Makefile.ubsan         |  2 +
>  6 files changed, 155 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 6f1ca49306d2..e585614f3152 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -282,11 +282,23 @@ struct ftrace_likely_data {
>  #define __no_sanitize_or_inline __always_inline
>  #endif
>
> +/* Allow wrapping arithmetic within an annotated function. */
> +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> +#else
> +# define __signed_wrap
> +#endif
> +#ifdef CONFIG_UBSAN_UNSIGNED_WRAP
> +# define __unsigned_wrap __attribute__((no_sanitize("unsigned-integer-overflow")))
> +#else
> +# define __unsigned_wrap
> +#endif
> +
>  /* Section for code which can't be instrumented at all */
>  #define __noinstr_section(section)                                     \
>         noinline notrace __attribute((__section__(section)))            \
>         __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> -       __no_sanitize_memory
> +       __no_sanitize_memory __signed_wrap __unsigned_wrap
>
>  #define noinstr __noinstr_section(".noinstr.text")
>
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 59e21bfec188..a7003e5bd2a1 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -116,6 +116,25 @@ config UBSAN_UNREACHABLE
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
> +
> +config UBSAN_UNSIGNED_WRAP
> +       bool "Perform checking for unsigned arithmetic wrap-around"
> +       depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
> +       depends on !X86_32 # avoid excessive stack usage on x86-32/clang
> +       depends on !COMPILE_TEST
> +       help
> +         This option enables -fsanitize=unsigned-integer-overflow which checks
> +         for wrap-around of any arithmetic operations with unsigned integers. This
> +         currently causes x86 to fail to boot.

My hypothesis is that these options will quickly be enabled by various
test and fuzzing setups, to the detriment of kernel developers. While
the commit message states that these are for experimentation, I do not
think it is at all clear from the Kconfig options.

Unsigned integer wrap-around is relatively common (it is _not_ UB
after all). While I can appreciate that in some cases wrap around is a
genuine semantic bug, and that's what we want to find with these
changes, ultimately marking all semantically valid wrap arounds to
catch the unmarked ones. Given these patterns are so common, and C
programmers are used to them, it will take a lot of effort to mark all
the intentional cases. But I fear that even if we get to that place,
_unmarked_  but semantically valid unsigned wrap around will keep
popping up again and again.

What is the long-term vision to minimize the additional churn this may
introduce?

I think the problem reminds me a little of the data race problem,
although I suspect unsigned integer wraparound is much more common
than data races (which unlike unsigned wrap around is actually UB) -
so chasing all intentional unsigned integer wrap arounds and marking
will take even more effort than marking all intentional data races
(which we're still slowly, but steadily, making progress towards).

At the very least, these options should 'depends on EXPERT' or even
'depends on BROKEN' while the story is still being worked out.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPPbTNPJfM5MNE6tW-jCse%2Bu_RB8bqGLT3cTxgCsL%2Bx-A%40mail.gmail.com.

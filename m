Return-Path: <kasan-dev+bncBDYJPJO25UGBBHPD3GCQMGQEONRTZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E548397961
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 19:42:54 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id 16-20020a1709063010b029037417ca2d43sf3644160ejz.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 10:42:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622569374; cv=pass;
        d=google.com; s=arc-20160816;
        b=zRW3P1V79k+V3yQkG+V6PzEXrQSG5LTJSLldVA4BKSTUUr8xht0EOedGh7/1tWksBq
         V8QiccH67Ocujd/zG3x8n7juKrSC5MJa6Rs78NaMd9oKkVyOr1wO9mfgkdw70JVH5hVZ
         qH9QbxH7NvAAjZBznCcmHlKJIeAyFS8JRfvBLxG++cFPKqWxSTP+V6CywgGr6c1o59/T
         mokQaackQ6QIgXG2Pa4SWj3Sv44o9zr+6CcWIm1yZhDSITNo43BVAwho/doISrK4x9eE
         BPV8+VAkiHGLJfgYf02+IFd0+YkTIQnv/ykJb3NGxcl2LnGsMzYGJY4ktR3hgFDcjnhp
         80RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=N93eWNbBnMc56ZKdxvJs6sDJ3PyJ/GWdN3mOSvjWpCk=;
        b=gYUmnOM1JSQs2CUEMUDuSbBS2ShyMqYhW/U9FukIDyX/ayZOD9h+lnWU6NKn4FTKLQ
         KCBWJrbdPgdFZazmDUQbfW8++CrjKe8HLDKrj7jrRrgwBZFOprqBp28JpuUIGO931zXl
         fbqj4U9Lbnv5n9hTXVicuFZX6+/1XuQl1oboMh808aPTCGbjZtvSaTMvJxHGR1Rl8K6a
         6zyDGRmrJaU6OOxXNkGlRmO8lCrr1rgrfXzWnXTWghQ/8WGbil+P+OXutJTOKlQ7hMrn
         b66KY7LgzDeSKZOkKdfmEEUH2HfqOCJqR1/y1RZ27a675tc5Q2Mh0HbovpCTV4PQUKOU
         dk2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dwDHvH0o;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N93eWNbBnMc56ZKdxvJs6sDJ3PyJ/GWdN3mOSvjWpCk=;
        b=jfxBsLgW4cz9blkKay4tpujOZ5r/w7xu4osPVOwTi7q/gS2dsC/qBqT0R5BWxQlFkT
         1y7mHktQEkyV/nkRZH+CCftqirOfa+whUf8Z6t5+AsTIW5Xc9DYc+p3aT8zFYomUKe+k
         nwQg8j5Xf6LuiNGO0SgUjNrrv5TSmAUjBnItbZskTcvAkgLtenWk64UEU4VZKihtlAtR
         Yr6ctRBqhO/d/TPFd7KKQEDlnm5qvKREIgyq1sOAW7Dtb1NorGEpNvbJwfxwoHw1sc/3
         +FcOGVvR2O9zs0ISCVEcbWtTrPhoMLr90DU4LLC/S7pYWsgK4yjwjXBav7pt26WmYBrD
         QJPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N93eWNbBnMc56ZKdxvJs6sDJ3PyJ/GWdN3mOSvjWpCk=;
        b=e4TGCaUY1+VSGA7ReNOFUpP61UP+OwAbnn5jP7J6qHfOhuQUt1GALSHEUUgi2pjybd
         fgRiQbvWIfV8BnYyy2XZp8dGvnyl5BfCLW2pbd21kCgDOPyBkEKsKhsmRRwarqvHAPgD
         bORULQEWL4aML3fwp0jXzCNfS0QTcbp+x49+XTINq2X46EVm+SQTnn/ZInbbZZWlMTiR
         UKqdOAwykgNgcUm48B7m/rNvoC/HEvPtz393kcb6e0sa/4lU+RPuA2u5chBqJZLnGRPs
         CjduKYWGpq08AoIyYEh6pWgrA3LFfis/nccBC8o2Hgoqx4aTb14l0VNBldIlo29zaYdc
         dt9g==
X-Gm-Message-State: AOAM531l6nIvCtgnB2HRIcx16U0oJaec6DbAY0iXEHIvswXLqYzog6UL
	WIsfTVW+ZTtqqgx45yR90mE=
X-Google-Smtp-Source: ABdhPJx6zy5mSviwQjrKY70tQz7JL7IwZdvRGKqow8qR071e2BSjbDCXX44maYpkzALRR9i7ImgSwQ==
X-Received: by 2002:a17:906:2c4a:: with SMTP id f10mr22726136ejh.493.1622569374138;
        Tue, 01 Jun 2021 10:42:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1f09:: with SMTP id w9ls6155893ejj.11.gmail; Tue, 01
 Jun 2021 10:42:53 -0700 (PDT)
X-Received: by 2002:a17:906:d1ce:: with SMTP id bs14mr31378800ejb.183.1622569373240;
        Tue, 01 Jun 2021 10:42:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622569373; cv=none;
        d=google.com; s=arc-20160816;
        b=Pg5t5nQVJ47RSjVAaFRcBe5xdBg8CNgqhFiuZ+hXcZcCFg9JU/RmHjsVLuHdmhpJ02
         Genm8SB0P4iQqRuVPtuyHBqWi+6eMdz7pU37JwJA0I/EfB0eRUEjxzDaxRbjldo46Knj
         40oDBZ7DfByvysmtjwlNbgMvliCJrqKHG1FHgWcIY5suKu2AN6TiKCclYdG7MDRzXUyQ
         xD18+Omc0CNhQW4COD+iysK/EbhwKkRZnwdZAzsLJwmRflogwYrloGBp1mJA43ZQTKtL
         nYRr23IUB/AQWhcp4Ow/VOljHeDw1PuYZV6It3B2Tzu30x53dJuxULgQc06Z4iIUjYoB
         xiRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yD/RqJ6Lx/pv1RbRPxCIzqHlKJgJbvGhxmkXtiq11v4=;
        b=NDpwcFdCxnxVFhozqzaPMzF+DIqfQ7VSj49F5klEHa8JHYy0iZ+YGepgtcNZRa7yZL
         4rbEguqK0vatBc36Q/55FSlyxHjmPnUtqQPo2sWeoEHp893R6e7pYAkHrJg4mq9cBYpc
         bSnC0OLTAgw27XAf7FwHSxWWyCDc3tOSZ5HnRpu5QCbNwDAT8tHA0A4vWrOttdD2XK4C
         /PiUEdjGOfTBuIs+EpwWqqQTq5Ut9LnwrK13LYod/0cCIEjW7vMpAEHqRosgMoevuHYv
         WADXSD0yoZbFZQl72Muq2WtIxPxmo3nG8IQanfrDaDuENOyZ7c6VQMUjtuuYymSpsuRO
         wUtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dwDHvH0o;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id r20si566255edb.3.2021.06.01.10.42.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 10:42:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id e2so20401892ljk.4
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 10:42:53 -0700 (PDT)
X-Received: by 2002:a05:651c:b1f:: with SMTP id b31mr22349478ljr.0.1622569372725;
 Tue, 01 Jun 2021 10:42:52 -0700 (PDT)
MIME-Version: 1.0
References: <20210527162655.3246381-1-elver@google.com>
In-Reply-To: <20210527162655.3246381-1-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Jun 2021 10:42:41 -0700
Message-ID: <CAKwvOdmgZXJB2dV7iG67qHgbDgVTJaH7b3dkpgZyea4ULgQjgA@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: add __no_sanitize_coverage to fix noinstr for
 all architectures
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, LKML <linux-kernel@vger.kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Kees Cook <keescook@chromium.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, Will Deacon <will@kernel.org>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Borislav Petkov <bp@suse.de>, Sami Tolvanen <samitolvanen@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dwDHvH0o;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, May 27, 2021 at 9:27 AM Marco Elver <elver@google.com> wrote:
>
> Until now no compiler supported an attribute to disable coverage
> instrumentation as used by KCOV.
>
> To work around this limitation on x86, noinstr functions have their
> coverage instrumentation turned into nops by objtool. However, this
> solution doesn't scale automatically to other architectures, such as
> arm64, which are migrating to use the generic entry code.
>
> Clang [1] and GCC [2] have added support for the attribute recently.
> [1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
> [2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
> The changes will appear in Clang 13 and GCC 12.
>
> Add __no_sanitize_coverage for both compilers, and add it to noinstr.
>
> Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
> if the feature is enabled, and therefore we do not require an additional
> defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
> always true) to avoid adding redundant attributes to functions if KCOV
> is off. That being said, compilers that support the attribute will not
> generate errors/warnings if the attribute is redundantly used; however,
> where possible let's avoid it as it reduces preprocessed code size and
> associated compile-time overheads.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
> v2:
> * Implement __has_feature(coverage_sanitizer) in Clang
>   (https://reviews.llvm.org/D103159) and use instead of version check.
> * Add Peter's Ack.
> ---
>  include/linux/compiler-clang.h | 11 +++++++++++
>  include/linux/compiler-gcc.h   |  6 ++++++
>  include/linux/compiler_types.h |  2 +-
>  3 files changed, 18 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> index adbe76b203e2..e15eebfa8e5d 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -45,6 +45,17 @@
>  #define __no_sanitize_undefined
>  #endif
>
> +/*
> + * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
> + * with no_sanitize("coverage"). Prior versions of Clang support coverage
> + * instrumentation, but cannot be queried for support by the preprocessor.

I'm not against a version check for supporting older releases (in
addition to the cleaner feature check, since the feature check was
non-existent); we can clean it up someday when clang-13 is the
minimally supported version.  Would having an additional version check
help support existing/older releases here?

> + */
> +#if __has_feature(coverage_sanitizer)
> +#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
> +#else
> +#define __no_sanitize_coverage
> +#endif
> +
>  /*
>   * Not all versions of clang implement the type-generic versions
>   * of the builtin overflow checkers. Fortunately, clang implements
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index 5d97ef738a57..cb9217fc60af 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -122,6 +122,12 @@
>  #define __no_sanitize_undefined
>  #endif
>
> +#if defined(CONFIG_KCOV) && __has_attribute(__no_sanitize_coverage__)
> +#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
> +#else
> +#define __no_sanitize_coverage
> +#endif
> +
>  #if GCC_VERSION >= 50100
>  #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
>  #endif
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index d29bda7f6ebd..cc2bee7f0977 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -210,7 +210,7 @@ struct ftrace_likely_data {
>  /* Section for code which can't be instrumented at all */
>  #define noinstr                                                                \
>         noinline notrace __attribute((__section__(".noinstr.text")))    \
> -       __no_kcsan __no_sanitize_address
> +       __no_kcsan __no_sanitize_address __no_sanitize_coverage
>
>  #endif /* __KERNEL__ */
>
> --
> 2.31.1.818.g46aad6cb9e-goog
>


-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdmgZXJB2dV7iG67qHgbDgVTJaH7b3dkpgZyea4ULgQjgA%40mail.gmail.com.

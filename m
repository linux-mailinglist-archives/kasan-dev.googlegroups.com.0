Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7F3GCQMGQE7HIS4AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 46455397973
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 19:47:00 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id c24-20020aa7c7580000b029038fd7468047sf4885839eds.20
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 10:47:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622569620; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y8gUHRr0WMzBGNMjsghv0O4plYQFWOTZHjmd47FZ7aTfBPXLnnWB62d6j2JljmlBsM
         MU0e0wk6C86TP3jUOmQeZkGOM8BDx9l2roonCjG+W/Vojd2mkJV2Yh/A2rQNhJ+uZkfu
         FH21A8O593XtWv7DMkcOfluwFjxFgxHdWMDwBypGtti7hOPlna1Vhgceoi8O1gVcn2Vh
         qc9bvpPTDCrA3+VOn/+qy/lv/zAFm4otHDB7VBrHPE1GkssPvUcjFYMI/RiH3R+bWHZ/
         DxR7sN/txJAPCAU/GdSVOSvCPBDxUFmZ1xcv3xG+ZRNW92SIMeG2R4uzjY5dtU8VuvMc
         6d0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZZBxsN0d3IWP6o6hLsLiHUnhIQuxyc9VodjkoxsQk4s=;
        b=HbRe/TDwSYF+LD/Va5uSdxx+0roVcjVTSkXGqo3V4gQttq76bxetGWFC/81Mkukz2R
         0UUeoxtcdHdGcdoVKIgCzwmjB5cJRGPsC2QbdWKG6MpFdwB60PpeyOMbyTC20+JA4dBO
         tJ6bmOixZTSEyfYR6OnbY32zFw9FFFPAlxlw+CZsFxgayWTgHll0htgRJisoFyZbqgue
         biFIP6LYczNyEMNYUTE2jUDF8CvrgJqOeUkQX2wCDcqJZNk3maEsIG3DVDA2l46hvdm6
         5T5uO0RjxRUV8mp6Spm6mOXdyyJAH35SOCm9Q0cGmARHuC1+Kv+fqK9n/uvna2fxPui7
         jESw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uiisl/l2";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZBxsN0d3IWP6o6hLsLiHUnhIQuxyc9VodjkoxsQk4s=;
        b=moQh3jUIWe428lu3fxXUbFKW57sbFEIAlDya8YJs0La7YtA4xg+U0V6LEmJGuWfRSA
         NxH6cGGTOJEpmJD/Y59mbxMxyB8wslmWDSspVKiwo1fKyrLPgmYf2G5ZeO+qufKQMjqJ
         wAErEUuvldI/cbcsQGaxZCkNJmDzkwcDQuN+xOvvrkvyKFVBBukVkn4fLprENZKDSAz2
         CG0sOnXxPTwCoXFt2E+jLu3kqlpUYwCDcV6RDpJmrfUBu3QgB3Wd47l2eAYACPRrGEPz
         7Vbays9Ny3Z4m5nLxQLAu5HJwwcFvqFwI5JrkFI69aZ/K2i/+I7+zt/ylGPBssxQpLW6
         JGEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZBxsN0d3IWP6o6hLsLiHUnhIQuxyc9VodjkoxsQk4s=;
        b=fc67bkL0Ew/1rPXu/gIptsQvdqaj45hycmwN1L2AxHM+y9z1MhzlUASiz08p+XsTQS
         BqTICTNod4R9VcuN8VeBRRpxRu59U3rZOBi5hE/OtaKRpEE9JIGwUy8Zz6fxlXZ7rr3a
         IXnOwXQZrxjMv6dvQa0N/CyYC7KTGSHsJXBXQQU0keo94wU78Rs4draVaxCrtkRHb6S9
         whT4Mqs/i1HJCCVdBOV7KagC9br2pdc1bsKZ+5IsaAy+zFk1fdGDFC9lraukvHG0J0XW
         l1tELso3xKFTxNpzj9VWlBzv1uP+ElRWQUX6fmYOMuzS+YvTyiBTH/KH5bAQLOLAiHFX
         8jCw==
X-Gm-Message-State: AOAM531HkTXbH6bmLad2s8cXTHk1+7UPnrBhqUFeng0WRCuFt9uPxyON
	ef0cjSrXTeHV5r/DiKhpFkw=
X-Google-Smtp-Source: ABdhPJz/lK7oNbWAYUiPhFXcL4zdw5vgolnC0crM5TI1gyjC4lbmmy1bB8o/gAIf2jrHVgsQZm3trw==
X-Received: by 2002:a05:6402:13d7:: with SMTP id a23mr6704454edx.120.1622569620027;
        Tue, 01 Jun 2021 10:47:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d2a:: with SMTP id gn42ls8145040ejc.4.gmail; Tue, 01
 Jun 2021 10:46:59 -0700 (PDT)
X-Received: by 2002:a17:907:62a7:: with SMTP id nd39mr30175454ejc.502.1622569618981;
        Tue, 01 Jun 2021 10:46:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622569618; cv=none;
        d=google.com; s=arc-20160816;
        b=G1QjfQ1MvuJ8KIpt2Zl/qlw4OUwVL+6r3hbCX49FqwUcK+KWOiDQ8yHj8H/nIUvZRC
         aOKXHayBTXPhaug839wM5eM7a5Q8fyfDoeX+7uzghBTN8f12A/h03oPMoLRnJQNn8YA4
         MEPJaIfGpOOH+D53vL9+bi+y6C3vzwxHvBN8ycdvKw02s8wkMvEKMgGWxG/tlokEjGoq
         ZXFjy2G67m2zoTp1iJro6JEPy9k3fJZ0cIB8xvmld83w5kM5nabwGZ41vSz3g6t/Whgx
         WYduyEaa59jks9pz1lPuLjnm8rciJFKzFWW+2ZBhjzhuSE8NJZJFSG1FIPvvoAsYxYod
         1obw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jJYP1ahOHUDkEz4I2iYxmBxvA/YEgFvm6f/leHoOsVY=;
        b=yBNQ53kGW8glFlDi2pcAITRFBnfgbRe7x/OGBqXWJYvG7NEqQ7bcfWsxr6HlvaKteQ
         rfWcc9zc2EkvR0j8vA4s2RAYNuvWSoE8QaiU4dNyiVBhML7zy8YzvNcjW1rhf1R2DODr
         12vawdYB+I6sVHvMb2R0OxAsEv9ZFf3TAw0+oUwPAd73RcZXexbpuoCda+eLvKDauYUN
         jRMnZN5WjINmndy/rYKNDszmiLdJvdJO9YHIR3PExIk1Iy+AWA6lsPW44NE4UF8nDVBl
         hX+DCF61KyshMlnqgE8CX2qrUE59cpM/4Vy3Ru7LHIOyCTN64SbYijVNbN+8m7nl86nv
         3WgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uiisl/l2";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id r21si1281900ejo.0.2021.06.01.10.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 10:46:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id q1so23128326lfo.3
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 10:46:58 -0700 (PDT)
X-Received: by 2002:a19:dc08:: with SMTP id t8mr8284937lfg.503.1622569618435;
 Tue, 01 Jun 2021 10:46:58 -0700 (PDT)
MIME-Version: 1.0
References: <20210527162655.3246381-1-elver@google.com> <CAKwvOdmgZXJB2dV7iG67qHgbDgVTJaH7b3dkpgZyea4ULgQjgA@mail.gmail.com>
In-Reply-To: <CAKwvOdmgZXJB2dV7iG67qHgbDgVTJaH7b3dkpgZyea4ULgQjgA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Jun 2021 19:46:47 +0200
Message-ID: <CANpmjNNqzCTks5dFkbbqzPP4UX7GDTdjbvJ7SbN2jcSNWjxQzA@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: add __no_sanitize_coverage to fix noinstr for
 all architectures
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, LKML <linux-kernel@vger.kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Kees Cook <keescook@chromium.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, Will Deacon <will@kernel.org>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Borislav Petkov <bp@suse.de>, Sami Tolvanen <samitolvanen@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="uiisl/l2";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12d as
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

On Tue, 1 Jun 2021 at 19:42, Nick Desaulniers <ndesaulniers@google.com> wrote:
> On Thu, May 27, 2021 at 9:27 AM Marco Elver <elver@google.com> wrote:
> >
> > Until now no compiler supported an attribute to disable coverage
> > instrumentation as used by KCOV.
> >
> > To work around this limitation on x86, noinstr functions have their
> > coverage instrumentation turned into nops by objtool. However, this
> > solution doesn't scale automatically to other architectures, such as
> > arm64, which are migrating to use the generic entry code.
> >
> > Clang [1] and GCC [2] have added support for the attribute recently.
> > [1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
> > [2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
> > The changes will appear in Clang 13 and GCC 12.
> >
> > Add __no_sanitize_coverage for both compilers, and add it to noinstr.
> >
> > Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
> > if the feature is enabled, and therefore we do not require an additional
> > defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
> > always true) to avoid adding redundant attributes to functions if KCOV
> > is off. That being said, compilers that support the attribute will not
> > generate errors/warnings if the attribute is redundantly used; however,
> > where possible let's avoid it as it reduces preprocessed code size and
> > associated compile-time overheads.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > ---
> > v2:
> > * Implement __has_feature(coverage_sanitizer) in Clang
> >   (https://reviews.llvm.org/D103159) and use instead of version check.
> > * Add Peter's Ack.
> > ---
> >  include/linux/compiler-clang.h | 11 +++++++++++
> >  include/linux/compiler-gcc.h   |  6 ++++++
> >  include/linux/compiler_types.h |  2 +-
> >  3 files changed, 18 insertions(+), 1 deletion(-)
> >
> > diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> > index adbe76b203e2..e15eebfa8e5d 100644
> > --- a/include/linux/compiler-clang.h
> > +++ b/include/linux/compiler-clang.h
> > @@ -45,6 +45,17 @@
> >  #define __no_sanitize_undefined
> >  #endif
> >
> > +/*
> > + * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
> > + * with no_sanitize("coverage"). Prior versions of Clang support coverage
> > + * instrumentation, but cannot be queried for support by the preprocessor.
>
> I'm not against a version check for supporting older releases (in
> addition to the cleaner feature check, since the feature check was
> non-existent); we can clean it up someday when clang-13 is the
> minimally supported version.  Would having an additional version check
> help support existing/older releases here?

The feature check will just return 0 on older releases, since the
feature does not exist there. Therefore, no additional code is
required to support older releases and a version check would be
redundant.

> > + */
> > +#if __has_feature(coverage_sanitizer)
> > +#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
> > +#else
> > +#define __no_sanitize_coverage
> > +#endif
> > +

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqzCTks5dFkbbqzPP4UX7GDTdjbvJ7SbN2jcSNWjxQzA%40mail.gmail.com.

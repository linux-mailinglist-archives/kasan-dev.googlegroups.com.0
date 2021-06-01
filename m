Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIPI3GCQMGQENCZW6KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 87599397984
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 19:53:37 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id h18-20020a05640250d2b029038cc3938914sf8267094edb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 10:53:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622570017; cv=pass;
        d=google.com; s=arc-20160816;
        b=gcNatoNeYsBkpdXWav6MOmrfVc7DRh7Csfk+yoHRdcLg2XyZeoApefU2WLil6d1M5S
         urJD7UlYk5ofVGiT8fUP8IYCMn+/Cwn7cYayYgDqezid3qhBAy1UWR4XM+lEGw29t3fo
         ULHDJzH5c+KwkpW3MHdr17QfUJlSVW/sW8xlHkHqB5/LcDCHXbtlTvyJxM4ztWnMc42w
         EIV9Q6nrTcVYIc3oiQ7g12LegzOWqF9+0NpaIYiQpscbVgqNtRUEGVUHOmb8B8u0hzqS
         uTj4r0TPe6ews8E36PpVauHNwNVW1EbSdFsh478jbBXJPnxDQE1f+avlDQ7u5+RPCrcu
         RFLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6th+lUN+C7+LfRqBJ/TmbnbCm2FCs8V3ylBgyrpOLJg=;
        b=WmK34QHtw6Wz3oV4Vfg1a/FLiGGYW3rXQWd03oV7FzYxlVW6wYDsynaX74l4QMyH4Z
         pya/LhVrfzjmvDb0m23uriptIG0qoNOThKeNlLngAjbsRzEv3Mat9Uw66yYZTjiiYhcM
         ZYykAYhNDdv1dVC9v0YK9Me2nvIQQl0I3AKXB87nI/JclGSE+vFltHJoFQkwnuYfD031
         vPu8bKzaiLAjUZ18IhfAkfz1Ms0GxqlY/JW1i0IetjUXIJAqiltych0MjvPjTwxcSwsw
         5LediVhoKA1dBc/f0Y5X6erKILzvQPZ+n9w6WfI2PTILtLIWoc1/rXexenCTakGFgG1K
         QuuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lqW4OyYI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6th+lUN+C7+LfRqBJ/TmbnbCm2FCs8V3ylBgyrpOLJg=;
        b=YOyfJczANvjnfK8BK0LLRQHURMNf7myhGNnQnVQRuzz3yjfAcHgN4WDSrGKt53bOER
         eJJgCpF+IEB/HXHas7/6SlA3ajiLJ3q0nz0/DH2qb/RjBF3/S1HHe7cay4g4PPVqx9IB
         WpP/ctBJcHj1QUr5FR9Q+gFFsOvx2q/q+bq4e36XMJHDreg7NNhIPdWkoJrJFNo2GtkY
         wkxmfv/8wxLx+6q6tE1sRWBg/onCIjtd8s64v+Yill2RsEUcrwsi7xfjJ+2/V/QCLg9F
         LnBxV8FTjGiAbgWdr+fhRCppam8WAFHxfNkDlMrT4gM946oP3LKOJdmof3HocRTLFgBX
         iEKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6th+lUN+C7+LfRqBJ/TmbnbCm2FCs8V3ylBgyrpOLJg=;
        b=hEijw5Za786/Q76+jYvJehIaHvlfDuWCs67fjA4PCPJbzubKtruGGo20FSaLlMdQyx
         5nz4QVvfMTLZQs7yVF4Wwq1EVaRTfXTIiiLfe2deLYJPsYtKrRT81Kh8ZXoMVEvC6dW3
         MCv5fDoioyM+7Qz4fX0e3G8ohHVs0Wg//z0GhW42Jb3CWe45MnnTHe+autumxWQaICqg
         bVR6MRXE/GReLf0lVkVSTem9hxkE5ati5kRPNZ9GzzVpcc4SEDourwsvret5TVYqxUns
         /uHAELnLvz6+6a+QLxUX9cbGf09I7UfTFc4oNA3Tn/Osxl0Y7tcDrjeHwuXNxNZnOu5p
         wLeA==
X-Gm-Message-State: AOAM532ccbrWLssVhIXdxYaRvbEXCZY6N2vWV0dWAXBwoEmceKy65ELo
	L/xAWy4mV546nh/i4FWNMLE=
X-Google-Smtp-Source: ABdhPJxI2o3vOOD61YVwAiWtOHcpqRsCHrz7WMux9UYBT1ul5WtUx7ZP49lJJLP8S6ZFaR5jHmQJtA==
X-Received: by 2002:a05:6402:1d8e:: with SMTP id dk14mr34241259edb.385.1622570017322;
        Tue, 01 Jun 2021 10:53:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7693:: with SMTP id o19ls4306405ejm.1.gmail; Tue, 01
 Jun 2021 10:53:36 -0700 (PDT)
X-Received: by 2002:a17:906:365a:: with SMTP id r26mr21531365ejb.340.1622570016356;
        Tue, 01 Jun 2021 10:53:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622570016; cv=none;
        d=google.com; s=arc-20160816;
        b=gbltgeN43PmAftzLaLoI1A15dLD5zZLbwusXTHt2tOfaBCNWdlcT2X8bPWk+O0NtNX
         YocugGektfI+dMIus2DLnhcj9E+DybDxaaRwlAFOub5wA7BrDtuOxAzuSK2hHafiEzli
         sdwLlk6vggpohSnBKFceo1RyptVh5h5rdl4qQAbG9U0YnLNorCvLL1ux7YoJqgK9QFPP
         7KUu2gWCsER9trVDqKqmg45cSxW5cPwXlJJXile3ZgSG9R+4jj/uOIBBus29EKJP/bNk
         L3/L8zjZjTXsCtjzgXPBZ1zp7E4MymIbt3h8dp+TYYXdQSnK24Q19Q9I7kHKZQrB0ZtO
         YmAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IKgq4o1KMFQWb4eqWEtxAreJyLSizVw7xMXtspskoP8=;
        b=lh7iKvpQIr186Zz1fBTP4Cy+JxmC2LF8MpikUctOgc+vKRHt61/FnpMCVQ9pzYINd1
         p+yGp9utGRhoDy+bwxPWX6gd7cT6AwDPVro2+DjQLAuk7MpW3J/Jj1Qdez1blPBr7bbG
         RXgdsj9avHbq398Qse9l8kJmrLp5SLGA769F8jtVaJo0WOmWGVixBftX5ltqBOf0EtTx
         kFrsHxDqYg20c1nq4Gn71rXi49Dnv7oA63Qa8b2AitLHivCA5TYUTCq0gnrSrg/aX+OH
         s8q+X0OBCddxgiUZN0tFFXES2QQp8Lrnwih5YUcPwqQGQyx0MglQTZUe+WSNXONe22Tm
         vKEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lqW4OyYI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id f16si908179edy.0.2021.06.01.10.53.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 10:53:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id f30so23207808lfj.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 10:53:36 -0700 (PDT)
X-Received: by 2002:a05:6512:46c:: with SMTP id x12mr5528836lfd.203.1622570015793;
 Tue, 01 Jun 2021 10:53:35 -0700 (PDT)
MIME-Version: 1.0
References: <20210527162655.3246381-1-elver@google.com> <CAKwvOdmgZXJB2dV7iG67qHgbDgVTJaH7b3dkpgZyea4ULgQjgA@mail.gmail.com>
 <CANpmjNNqzCTks5dFkbbqzPP4UX7GDTdjbvJ7SbN2jcSNWjxQzA@mail.gmail.com>
In-Reply-To: <CANpmjNNqzCTks5dFkbbqzPP4UX7GDTdjbvJ7SbN2jcSNWjxQzA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Jun 2021 19:53:24 +0200
Message-ID: <CANpmjNNXepu4=9Fgzdu9g8AzNQ_vfZvAf=AFOAfbWg8e8qzxRA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=lqW4OyYI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::130 as
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

On Tue, 1 Jun 2021 at 19:46, Marco Elver <elver@google.com> wrote:
>
> On Tue, 1 Jun 2021 at 19:42, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > On Thu, May 27, 2021 at 9:27 AM Marco Elver <elver@google.com> wrote:
> > >
> > > Until now no compiler supported an attribute to disable coverage
> > > instrumentation as used by KCOV.
> > >
> > > To work around this limitation on x86, noinstr functions have their
> > > coverage instrumentation turned into nops by objtool. However, this
> > > solution doesn't scale automatically to other architectures, such as
> > > arm64, which are migrating to use the generic entry code.
> > >
> > > Clang [1] and GCC [2] have added support for the attribute recently.
> > > [1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
> > > [2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
> > > The changes will appear in Clang 13 and GCC 12.
> > >
> > > Add __no_sanitize_coverage for both compilers, and add it to noinstr.
> > >
> > > Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
> > > if the feature is enabled, and therefore we do not require an additional
> > > defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
> > > always true) to avoid adding redundant attributes to functions if KCOV
> > > is off. That being said, compilers that support the attribute will not
> > > generate errors/warnings if the attribute is redundantly used; however,
> > > where possible let's avoid it as it reduces preprocessed code size and
> > > associated compile-time overheads.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > > ---
> > > v2:
> > > * Implement __has_feature(coverage_sanitizer) in Clang
> > >   (https://reviews.llvm.org/D103159) and use instead of version check.
> > > * Add Peter's Ack.
> > > ---
> > >  include/linux/compiler-clang.h | 11 +++++++++++
> > >  include/linux/compiler-gcc.h   |  6 ++++++
> > >  include/linux/compiler_types.h |  2 +-
> > >  3 files changed, 18 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> > > index adbe76b203e2..e15eebfa8e5d 100644
> > > --- a/include/linux/compiler-clang.h
> > > +++ b/include/linux/compiler-clang.h
> > > @@ -45,6 +45,17 @@
> > >  #define __no_sanitize_undefined
> > >  #endif
> > >
> > > +/*
> > > + * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
> > > + * with no_sanitize("coverage"). Prior versions of Clang support coverage
> > > + * instrumentation, but cannot be queried for support by the preprocessor.
> >
> > I'm not against a version check for supporting older releases (in
> > addition to the cleaner feature check, since the feature check was
> > non-existent); we can clean it up someday when clang-13 is the
> > minimally supported version.  Would having an additional version check
> > help support existing/older releases here?
>
> The feature check will just return 0 on older releases, since the
> feature does not exist there. Therefore, no additional code is
> required to support older releases and a version check would be
> redundant.

And to avoid further confusion: -fsanitize-coverage exists, but the
feature "coverage_sanitizer" queryable by __has_feature() does not
exist. The confusion is the price we pay for this technical debt --
but I'd rather not write an essay about this in the comments. Most of
it is in the commit message, and if people are still confused I hope
they find this thread.

There was also a v3 explaining this more in the comments, too:
https://lkml.kernel.org/r/20210527194448.3470080-1-elver@google.com

Hopefully that is all enough.

> > > + */
> > > +#if __has_feature(coverage_sanitizer)
> > > +#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
> > > +#else
> > > +#define __no_sanitize_coverage
> > > +#endif
> > > +
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXepu4%3D9Fgzdu9g8AzNQ_vfZvAf%3DAFOAfbWg8e8qzxRA%40mail.gmail.com.

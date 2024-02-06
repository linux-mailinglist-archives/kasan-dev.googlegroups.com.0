Return-Path: <kasan-dev+bncBCF5XGNWYQBRBX5GRCXAMGQEAS2XBJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9C2884B31D
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Feb 2024 12:09:21 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d93f4aad50sf1369845ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Feb 2024 03:09:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707217760; cv=pass;
        d=google.com; s=arc-20160816;
        b=ncPPKpoHDWkHjyaodQOV0VoOIHFH3J23rx+SA7/Y5QNLIvPY6iwCRY+TIZn/kXpAZH
         YaPenjKp9Y4jTyh5B2mrJA15b3RwHSxSdtCHqkOVK7tUIrcFigh2dgCYIArL39/7V9Ou
         ol0WuSxLagR0/V/ymgvdTXHKIgD+97MX0+qVStP7c+0oC9Nek8M0NcN3ONKu4AIPfaDo
         t5KgmIGCaJur3jWZLarpgZpLzftnjeiP8fto4J3LEqlOvhZvCYlsY1JymXvE4VPnUxIm
         ErAsTpFAgs6gKp5dkCe/uTUP6sqAqopNACLdxDyehn3wLm7KqjAqkv8bE7NczkxQmQY4
         9SKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rY5ebRxa7D2fKIP3C1ta/4SwXTcYLDgYJinLFquLJy4=;
        fh=7DGr2t5nBg5Cml2+tvc8HWMHg7v/jib+pArE7cjUbTg=;
        b=gEBf8JY9DTW1YZgbZlLewpOI7VNvnzVdgydGnYcPssE/oN6EfJ55/c6rOhG/2quSt1
         gg4pj3jmzwz+B5lAovPNhEKrU7af0KgOJLalT1hH3p0FIrACTagfOpG5xJVvaS2cXsAs
         QwrnhO5aHqdJzyy7oxlrrfPfa/0pi7hblIKa2tqXaY8HOvk9SIynNUIHvdP9YcOHXGQE
         1Xe10mhWrPuL/EMrY/PZ1j6+ViCWoteVIjGRNoaEiakJJG/Ruvrl79CuyOS/CgZHWYUf
         R57ta2DOY7gZZxSmS7xb96WfDrqVuQaOAnN8G/U4542G60NvJq5zaze8PpXgPdtK4KXv
         TjiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QN4xnr6a;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707217760; x=1707822560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rY5ebRxa7D2fKIP3C1ta/4SwXTcYLDgYJinLFquLJy4=;
        b=na1t3sEZFVYnzNmkEQl5YYOzLjlKnLV40jUB/43UlrhNAQ0KScjdNMjEYXKdI9MoXq
         RFjkfpWu+QtkLq/sd+jN2w64y1Ag9uvqR9i/TYtHxCEYa8Liv5A4fornFE5ZUqD2yhdq
         +9MWllHPCeUpxZEDUJ6OR3YnBFJYp+mvJzRm3RdMlV/LcNiq3fnEb3BQkZaMZyk+1ILR
         VGwGD/g4I7P16fgryJxjIKEcM07wxvaVe5ivOVs1LEner3le9UnfiPu8d0Kl5kW9H34X
         doHS/5vJD4xlpo9pQLDVp/2n6ZHTPvToEeQc5TJu8c7vYXm6Apu2vkpPm69++righwEM
         3g+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707217760; x=1707822560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rY5ebRxa7D2fKIP3C1ta/4SwXTcYLDgYJinLFquLJy4=;
        b=m7grokfwnkTetAxJnHFWZvibajkRcdNw/i5gSjfXUxMBTS5+qGBaKBLCzti1+7jGL1
         l8eDunfPFlHJR9RaKgeFXvzTBS9Onao9FWDs5h2FSqYAL99ozUWcsU4dTf6f1KNKWV0M
         n5kU9qIgB+2v0k1RgOLC0f6fZPi6shXLxgZ8jB+ZdpWlbR2HxXWfuyiIgHsktavSIsgV
         uWomlYI8rF7S2I7WNc/JZh/j9DXkYJOBp/US8eZApSK6/XRZZuXhdYEL4LAjz/OVwmoh
         mKOF4oajECepOX+l5MNXsxm/Z2nd9p2Nk4/SyypkicZ42WXjVluqMdmRtzRFvGZ+AfBh
         vSaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxyu5sDJePZ3f1/fP0BygzqdybHNHfqVVvvJogBIgL4vJS4zwBP
	nxY7KpcLgDdHCr6NqXwfPXp5wWRoTT2i8bY8ObLt5I1h3K4Dp2kX
X-Google-Smtp-Source: AGHT+IF7mUQoY2SsxmFgxtf37Lz1MF3TGYgULIya8r/TrnmDuBhgjScRzXGeQxEbLTb5LZg2ZP+Utg==
X-Received: by 2002:a17:903:32cd:b0:1d5:ed04:4d0e with SMTP id i13-20020a17090332cd00b001d5ed044d0emr220320plr.24.1707217759830;
        Tue, 06 Feb 2024 03:09:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3029:b0:6e0:4bda:b775 with SMTP id
 ay41-20020a056a00302900b006e04bdab775ls1302906pfb.0.-pod-prod-00-us; Tue, 06
 Feb 2024 03:09:18 -0800 (PST)
X-Received: by 2002:a62:e405:0:b0:6da:bcea:4cd4 with SMTP id r5-20020a62e405000000b006dabcea4cd4mr3216454pfh.16.1707217758665;
        Tue, 06 Feb 2024 03:09:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707217758; cv=none;
        d=google.com; s=arc-20160816;
        b=Zk3pfX2AhNtV1ILZRuex9+3xe1tT9/N+qGfuv9BzxbiCQMshH00VOZ1IySQed+b6Ju
         4I16IDyx1UVYJuXbMgbVPLwhn+LBWg4hEp25hyF4y0Eqd9TzAChNsPI3DJH0vofgIjvO
         ZNzRIw5fznt6SFArZdH8/PSaCYwDQTXzIo00Hk7dfueJR2PkKFG8LACnfNAGVwsy2PgR
         kC5n63mUwY8cdVQL7lnmMDen4l5wHCKnj6AJjReDd6Mt7z/Seqd9NMWvvbTqvH9FmwkZ
         vpW7IJ90UIRISx/xl4bJyL4TasjFXVKuHYa5wU3BhsmdQ4lmC1GBOUYF3ZsZhmmbyVvX
         bCWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OK82JrlJXMGwOCPdhn7BsC/hEWZwW73rbUs1KIvU8rY=;
        fh=7DGr2t5nBg5Cml2+tvc8HWMHg7v/jib+pArE7cjUbTg=;
        b=kZV9Hj8d94T/XmFlI9KA0rejgefP7nS+e3bxrhS/r3YWWrHHm7jIPS+EwUt5KOKcDq
         H759az2eRE7ZTRAyLVYbJqxGI5mFCMHIFlko+mAGV26q1Dz+mptfnSQERyvbXomULkmV
         EWkwUyFZScQvUKUg2BnGXu368YIM9hxz9LhxUdLVF7MdxXXhjXGvPp7YGHFolnjGHEbf
         uqE95wsVTPLqImtZncG6m2nY4NeQ9IdKyqMg+VueKmYWQZizjvxesp+yEPFE7Rg/Cufm
         TVHhoP0NmKxM1gBPcKXecFoBBfEMIBsYjrDXwRqDNZk3JSzzMuSMcvlrjwiKtnC6KQ8d
         mwkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QN4xnr6a;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCWJeLqvkfZLNLVWGfiLyVvVY2p9gBJtlpPRv9DQwK//OseS+qLvAob6BzZyvGQx9s9s3FGjrq211ak8Ynk+kTxWGu/BXj9OPCUUPQ==
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id dn17-20020a056a00499100b006e03dda48f5si87505pfb.6.2024.02.06.03.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Feb 2024 03:09:18 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1d958e0d73dso3924845ad.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Feb 2024 03:09:18 -0800 (PST)
X-Received: by 2002:a17:903:25d4:b0:1d9:803a:8b0b with SMTP id jc20-20020a17090325d400b001d9803a8b0bmr1488044plb.33.1707217758211;
        Tue, 06 Feb 2024 03:09:18 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCWD41BFbjj/gA9nr3hzGLWEWc28wGikJIa+U3DfYEG0+mhZav6ryva2TaZi/PuT+gDRDu3oPFfGLLauKK2I3iwCMOOkLmbqbllaBeIcb7Jfztp+AIIejdbl7TaDPuKZyAJU3Zi5oI6VCIuOR0uSOxs55kiSlmmhTdpw4iWIbnlbmzKnAeeNTRVdyMD7WLOMTJAfzFjLt4dlDx2gWwQ0SSli+08lhSJDOfaZFkSyqEAt9idPS4K9IBA0bgPei7tlmp98i5xFYyFtsvuMAFsnGwbcitjdhkSk+JjhPwTXPc+Cak+xGP930Q9GxgzYqvrScLmRHHswhkoOXiHfz4WS4FJoAGCXIak+7iFyl0/WnvOkBBnM3i6klYaN+gxVw2oLmoaLby9mJ7FioFHl3o/t9zZ+56J3jOuURB9oveQrlghN2XOHfRIUQQik1XssosFvbH2oCK4J8AIOnScjPQLuVjEoogGC0ZFii3Y9DUS2TkzP3HEy2L0NKH9YVD7LfyD6xOJJw93kac5+ZT1HEJ3MaTAhCkQKaaY/KQ8THpgBgZI=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id 5-20020a170902c14500b001d9557f6c04sm1567758plj.267.2024.02.06.03.09.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Feb 2024 03:09:17 -0800 (PST)
Date: Tue, 6 Feb 2024 03:09:17 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Justin Stitt <justinstitt@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
Message-ID: <202402060308.0FF75100@keescook>
References: <20240205093725.make.582-kees@kernel.org>
 <67a842ad-b900-4c63-afcb-63455934f727@gmail.com>
 <202402050457.0B4D90B1A@keescook>
 <CANpmjNMiMuUPPPeOvL76V9O-amx9uyKZYtOf5Q2b73v8O_xHWw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMiMuUPPPeOvL76V9O-amx9uyKZYtOf5Q2b73v8O_xHWw@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QN4xnr6a;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 05, 2024 at 02:10:26PM +0100, Marco Elver wrote:
> On Mon, 5 Feb 2024 at 13:59, Kees Cook <keescook@chromium.org> wrote:
> >
> > On Mon, Feb 05, 2024 at 01:54:24PM +0100, Andrey Ryabinin wrote:
> > >
> > >
> > > On 2/5/24 10:37, Kees Cook wrote:
> > >
> > > > ---
> > > >  include/linux/compiler_types.h |  9 ++++-
> > > >  lib/Kconfig.ubsan              | 14 +++++++
> > > >  lib/test_ubsan.c               | 37 ++++++++++++++++++
> > > >  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
> > > >  lib/ubsan.h                    |  4 ++
> > > >  scripts/Makefile.lib           |  3 ++
> > > >  scripts/Makefile.ubsan         |  3 ++
> > > >  7 files changed, 137 insertions(+), 1 deletion(-)
> > > >
> > > > diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> > > > index 6f1ca49306d2..ee9d272008a5 100644
> > > > --- a/include/linux/compiler_types.h
> > > > +++ b/include/linux/compiler_types.h
> > > > @@ -282,11 +282,18 @@ struct ftrace_likely_data {
> > > >  #define __no_sanitize_or_inline __always_inline
> > > >  #endif
> > > >
> > > > +/* Do not trap wrapping arithmetic within an annotated function. */
> > > > +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> > > > +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> > > > +#else
> > > > +# define __signed_wrap
> > > > +#endif
> > > > +
> > > >  /* Section for code which can't be instrumented at all */
> > > >  #define __noinstr_section(section)                                 \
> > > >     noinline notrace __attribute((__section__(section)))            \
> > > >     __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> > > > -   __no_sanitize_memory
> > > > +   __no_sanitize_memory __signed_wrap
> > > >
> > >
> > > Given this disables all kinds of code instrumentations,
> > > shouldn't we just add __no_sanitize_undefined here?
> >
> > Yeah, that's a very good point.
> >
> > > I suspect that ubsan's instrumentation usually doesn't cause problems
> > > because it calls __ubsan_* functions with all heavy stuff (printk, locks etc)
> > > only if code has an UB. So the answer to the question above depends on
> > > whether we want to ignore UBs in "noinstr" code or to get some weird side effect,
> > > possibly without proper UBSAN report in dmesg.
> >
> > I think my preference would be to fail safe (i.e. leave in the
> > instrumentation), but the intent of noinstr is pretty clear. :P I wonder
> > if, instead, we could adjust objtool to yell about cases where calls are
> > made in noinstr functions (like it does for UACCESS)... maybe it already
> > does?
> 
> It already does, see CONFIG_NOINSTR_VALIDATION (yes by default on x86).

This is actually a reason to not include the ubsan disabling in
__noinstr_section just to see what ends up in there so we can fix it
immediately....

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402060308.0FF75100%40keescook.

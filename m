Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2F4QOXAMGQEF4DGKZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 67D3E849B70
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 14:11:06 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-296a6b84448sf514251a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 05:11:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707138665; cv=pass;
        d=google.com; s=arc-20160816;
        b=u14tc46zfvrepIjCZrfuydnD3QNx8q5+//1Dn3/l1EfYsWVXxJxBnm83EC64nIxTCx
         3TBFaGmF6PQ73xiPw5Xg31YpXiweRh4DaBiFffPBxoDYwE5ChOaUX2UvZyI7y37zVuYS
         rzK1qEjILFrgSRXQlNhVCZ28c5d8mEqYhbzm3i2qg8PD8P9rYQuftt9TYIbQCcWVVLRn
         pDgVYQnoMtjFeJ6UjTZVmcLVXcAGqxfRP0SIYuDc4A48Up3S6GepNkv25NZnnlkXYtB1
         LMKIG+XkCvXES0/T7A00zcVgUjItFrCTwGviIXpLSkmu3V8u6VJtqdd7D3aFRZ8SFk5U
         dnvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VkswR0C4uiWvVf5bdh//IUJSL0YTXm6QxR8OeOMvElo=;
        fh=8VL8QGj5gCswi1VFyEMqINrhBbXhBhDdIVgaBukciNg=;
        b=fBjWjsonOgDaYwXgO2BqZJ/YM+HG6DdYHSLHZ4jQlJIGt3nQO8L9g32Rd3W0IjBdZ+
         Ti8RycuY4s5eJvXZe3myXE2/bKX2NFf0ftcdNHWMfXMo/byIpnCUVU8HGaW217u+o485
         NKz5Ep1ELrMLzwlKmlbR5UT2FEQwLFvDT9DCw9clkv0TjRb6PXXfuEclfo7jCkUq6nCp
         Mna3x5BIMp/tQwBFbjRsIwHaPk+Y4KcWzPppPuTDkUXcZxV61Tiq1jgYS1MCZen6CAWg
         syb+RZrImGk9ZIvdNuUvbJwlNdMPCDiERZJmbZ/QLzDl5FuZ1M4sDegvAb/Nxo82VoCq
         StqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nqxZO6f0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707138665; x=1707743465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VkswR0C4uiWvVf5bdh//IUJSL0YTXm6QxR8OeOMvElo=;
        b=Sg56ll4wEGIsTBnfAgY7ETfQ+t0PE+jIG4rciyEchAnRGPaLtbGuSiZ6gvGv2Bwi35
         gDDBZxtnkW8A+N0PIPdUYTHgN5/jRUrDq2EG6iIBTM8s22oeDKQU0tufi2Dsi/9658KA
         AV2K8U3wZRatK9ZVCuyJzAMh+8m/RfueibcacAldkIZ95GMexiZZk7mvRa9t11rW2KvW
         AdFxW1722DqiNJb5aLnAU8gh3cDxBo1nieg85CkIrJrnkXDB/1mm541oMmGQC6lmD74u
         mvgc1PCkQh4Y/kBiG2+0zL0v0Gl4FaSEiv+EShQcb/xDO6u6I7T7akXl9qClnLlKLQLA
         yBIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707138665; x=1707743465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VkswR0C4uiWvVf5bdh//IUJSL0YTXm6QxR8OeOMvElo=;
        b=p9aVIHYm41x67FxiZCdx4m+eFXQ+WsWLumnp54tCtP7FCvjOj6N/9TqUzxlI2Kf0EI
         qstdehXdUnZWJZUukY7lcVV/qU45iULjR5j6kxPjBtFVT1N+FQdIXLFLY+VFki4riCcL
         WMpIazVCVkmcDH5zdqgXrty8rxoMn3BUUrwvbkxceAvRqQ2RCxCGFs01Lyn6ck3VBiPh
         C0XsKJjsrmFoU6LFpYfuAoZmclw+Oirlu3q0jr4SXQTXgtwWpi+jHt915lEWfQ6TYDUP
         7dT5lbUZhcVmVnqTs4atKihGCKrMF+KFRfpJMAKZH3kCqEDpczBIIo4HxdUowQh1wJXK
         79ow==
X-Gm-Message-State: AOJu0YwFt/fytwjerNfl3+/HFgmYYiB/rqqsRJVXo6LaomaCeg6EQ3uk
	HMsWnfQmQPOwgxiP0wxqQgESmyS9kulSGqMO86yBFghMN/GEgefI
X-Google-Smtp-Source: AGHT+IGjRp5l9OaZgUU9hAslrnw5i1xwrJJf9sralLldXhex+DnQggLF2zNdkZuRTp2hPogmLgTFJg==
X-Received: by 2002:a17:90a:9708:b0:296:4f7f:c3ca with SMTP id x8-20020a17090a970800b002964f7fc3camr7877281pjo.21.1707138664907;
        Mon, 05 Feb 2024 05:11:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e74d:b0:1d7:6a5d:5a9e with SMTP id
 p13-20020a170902e74d00b001d76a5d5a9els3520413plf.1.-pod-prod-06-us; Mon, 05
 Feb 2024 05:11:03 -0800 (PST)
X-Received: by 2002:a17:902:d34d:b0:1d9:5ed4:ec07 with SMTP id l13-20020a170902d34d00b001d95ed4ec07mr11270879plk.52.1707138663730;
        Mon, 05 Feb 2024 05:11:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707138663; cv=none;
        d=google.com; s=arc-20160816;
        b=H506rezaAzozxSFJmU0lsdRPoDshzL6LqEUURFyymmfTr/7ydkiQ9tBMVwh/nabs0Q
         k8Uy//szNLwMTO6dGt43DXIgkZWwVrs9dxJhhKfx0Q9PJSfNj4551EfCQZ/kPqhFGv5T
         5U8OErSgB0D/MwnNokYHlVTqL63Xk4vGRGRIylddUKQ5+OAyqvVFMeQZHBcUNTfFFr8C
         vFHacYIFYdv1APkRQjqeZIpYqZ7GWZHJ0qs4WeIE7WwW3yqIo9inv9ZqJ+aLYjxEX/Am
         TdXnaucbomnIAD6z414K7xe8BeY1lzcZdXrpNin61VAG7MLkA5kEHeEFzq5uoKOMse6f
         3m3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kgO66v67ga2hZ/fa1VFxPxUYTn/f70qrUJZfQyHF9yA=;
        fh=8VL8QGj5gCswi1VFyEMqINrhBbXhBhDdIVgaBukciNg=;
        b=J6A4+iSLZSv/mOITD0hV8A8bldXmVCjVgdZ/LXqTkq7xT5FW8P/oGLSb9i6r1hLj+Q
         qkAlDGCYXOa5jRCd6HUPR8lrma5GhwhGG5ivQD4lTlVJEf8GobfMwsNn7h3OiyxIWOks
         oQKPLrp4igWN8+VvBOjrwwSadmJTHumlXdYJzvaFX0dXs/zX2ZVOGzuBI01DbUuiCdBT
         cQeaDZ4RxcJYMxtJwkWpMfdAsq8480Qt5pbWOPgLJfQGyb0UABonqKE6mZH/jYsGWIVC
         7J1Ut7wwA5lHDn4BSeyzRIjvdIlMw0epfnXLz5wDPAvfO4CxgyzdnVgIu5h/ciVquKSw
         GM+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nqxZO6f0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCX8yk8gX6XTYlm14OQspYptO6hzk5+xVIiN+oD2OAfC5eHC4+c1/QPzkhaRoeTGTodzaaeUKhS6y5iU4EqpxV3jVafsOEuTYOppqQ==
Received: from mail-ua1-x934.google.com (mail-ua1-x934.google.com. [2607:f8b0:4864:20::934])
        by gmr-mx.google.com with ESMTPS id r17-20020a170903015100b001d8f9b6e31bsi527231plc.10.2024.02.05.05.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 05:11:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) client-ip=2607:f8b0:4864:20::934;
Received: by mail-ua1-x934.google.com with SMTP id a1e0cc1a2514c-7d5bfdd2366so1505852241.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 05:11:03 -0800 (PST)
X-Received: by 2002:a05:6122:4d14:b0:4c0:1cc8:8819 with SMTP id
 fi20-20020a0561224d1400b004c01cc88819mr2759261vkb.5.1707138662522; Mon, 05
 Feb 2024 05:11:02 -0800 (PST)
MIME-Version: 1.0
References: <20240205093725.make.582-kees@kernel.org> <67a842ad-b900-4c63-afcb-63455934f727@gmail.com>
 <202402050457.0B4D90B1A@keescook>
In-Reply-To: <202402050457.0B4D90B1A@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 14:10:26 +0100
Message-ID: <CANpmjNMiMuUPPPeOvL76V9O-amx9uyKZYtOf5Q2b73v8O_xHWw@mail.gmail.com>
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Justin Stitt <justinstitt@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>, 
	Nick Desaulniers <ndesaulniers@google.com>, Przemek Kitszel <przemyslaw.kitszel@intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nqxZO6f0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as
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

On Mon, 5 Feb 2024 at 13:59, Kees Cook <keescook@chromium.org> wrote:
>
> On Mon, Feb 05, 2024 at 01:54:24PM +0100, Andrey Ryabinin wrote:
> >
> >
> > On 2/5/24 10:37, Kees Cook wrote:
> >
> > > ---
> > >  include/linux/compiler_types.h |  9 ++++-
> > >  lib/Kconfig.ubsan              | 14 +++++++
> > >  lib/test_ubsan.c               | 37 ++++++++++++++++++
> > >  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
> > >  lib/ubsan.h                    |  4 ++
> > >  scripts/Makefile.lib           |  3 ++
> > >  scripts/Makefile.ubsan         |  3 ++
> > >  7 files changed, 137 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> > > index 6f1ca49306d2..ee9d272008a5 100644
> > > --- a/include/linux/compiler_types.h
> > > +++ b/include/linux/compiler_types.h
> > > @@ -282,11 +282,18 @@ struct ftrace_likely_data {
> > >  #define __no_sanitize_or_inline __always_inline
> > >  #endif
> > >
> > > +/* Do not trap wrapping arithmetic within an annotated function. */
> > > +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> > > +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> > > +#else
> > > +# define __signed_wrap
> > > +#endif
> > > +
> > >  /* Section for code which can't be instrumented at all */
> > >  #define __noinstr_section(section)                                 \
> > >     noinline notrace __attribute((__section__(section)))            \
> > >     __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> > > -   __no_sanitize_memory
> > > +   __no_sanitize_memory __signed_wrap
> > >
> >
> > Given this disables all kinds of code instrumentations,
> > shouldn't we just add __no_sanitize_undefined here?
>
> Yeah, that's a very good point.
>
> > I suspect that ubsan's instrumentation usually doesn't cause problems
> > because it calls __ubsan_* functions with all heavy stuff (printk, locks etc)
> > only if code has an UB. So the answer to the question above depends on
> > whether we want to ignore UBs in "noinstr" code or to get some weird side effect,
> > possibly without proper UBSAN report in dmesg.
>
> I think my preference would be to fail safe (i.e. leave in the
> instrumentation), but the intent of noinstr is pretty clear. :P I wonder
> if, instead, we could adjust objtool to yell about cases where calls are
> made in noinstr functions (like it does for UACCESS)... maybe it already
> does?

It already does, see CONFIG_NOINSTR_VALIDATION (yes by default on x86).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMiMuUPPPeOvL76V9O-amx9uyKZYtOf5Q2b73v8O_xHWw%40mail.gmail.com.

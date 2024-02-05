Return-Path: <kasan-dev+bncBCF5XGNWYQBRBNVXQOXAMGQEPT7KZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EAC8849B33
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 13:59:36 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-603cbb4f06dsf81193887b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 04:59:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707137974; cv=pass;
        d=google.com; s=arc-20160816;
        b=gkfopFbhf/qmev6hTtuDa61VLWA3Zj014+/QKlGONjtgNlLdkgLmGktqUsCH0ND8Sr
         fNhu9FBP6Z4fpDwVI8CYfgZsWaIuie9ExL6+t8Nj6ygM/wCy286WG7gQmvO7Z5AGW+D5
         HCKT1KbA2QDqnC3DrUSedJELz/6RISGJqI86K4NbWETMEBOba6Uc4QTo3HtTARJFISaX
         3+oxHevQUv63MbsIhtszS04LfgGymzdC2uNsclky3IpohFKpnlDIQebHf5EiC7Pq3cSL
         b8MQC2ZnZLY5azpAvvEm2g1DzjHK8EdtOx/neTdL2DW/lcFwnRVI35VHieE8Agg2sPqK
         6CAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1CRI/7/MQhuvKnzSXmM89UIBN/T9cuU/Vk4lle6XNbA=;
        fh=xRq6+emt+pKKhv8mudFgrwIz20fksvT7qI+QjdPO7QE=;
        b=0BG4JmWN7gusv14BwmMDrVorSSHK2BbhkZWXVA4UB8Bv5fTCMwaLAEmEdPpRb1YwYV
         jFs9K4FuAzoVxZxkAtPln7OAoYX3WDeqtpy4JhCjdJ1pQXQ0SiKjzHskHeC/HafOrFm6
         j/g89K7pgLsnY/sUcb6Xh5VCcj5Ms5FxVlxg9F7WVQqtzErdcJ41XzN10pb816WjbkbT
         eVDtiLdHiZW/ICwfOn7F8qCOrGapS2lO4N89TfS0NYeHcSq3wM7mQy0xHuEB5Z4sQjdD
         5IMycnHaIRN/TRBux1cpe08PPzcmQZVIoMS8WHQciO6thsJrTU8M5v2T2s9HlNpQCVqd
         Fcww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Zpf1WvR4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707137974; x=1707742774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1CRI/7/MQhuvKnzSXmM89UIBN/T9cuU/Vk4lle6XNbA=;
        b=RcATaqMocz0EWoXmliDA54hk5zT7dgqn6CRnuEsS2LX7/5zhy8WwHdWBhe105fgbHU
         uxvzv+U/1UMjAj5i5ru3nmz/i+QoBiLJf0pfA6gq+R02gNMYOV2GtVwB/BPsnO5TsZYu
         JchyFglt/tIPs8bcAvVuIm/zGCTVQ+XeDpsM10r3SP2EAfcjTu/l5/XF7tfa4MumbXJ/
         6gOiuRVmZu98kHs92ROMG0EUTfH+X3IdIFkNjbLVNuGC7HCgq/exHOyLQAhvEZxsluDG
         j2xN6lcbpAbMrdmyF41GQSwlAu4scg0LePYumWWPINfCBlKuKy9TD8pzUl2XCOhLuA+O
         w07w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707137974; x=1707742774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1CRI/7/MQhuvKnzSXmM89UIBN/T9cuU/Vk4lle6XNbA=;
        b=I8hjgO2tJBuSlk0uQWTwYNLA8y2GV1yQ8iaYirMQGL7yNbndjLPPRd89G88bigzAkg
         ZRLfVr3A6MPadiFh4I8DCfoBt8wzxI+K2fQoAIUOTS4LvdFuq2pBSxpwioBYK1YPvOzp
         C5d+gpoUDlcVyhnVIe0TCFndGhiTJnsL1oAbpAQfadq2+09jdr9Ip6MGgAaI7uGRjVrv
         OP23yRr/91/Fd9yf1JMh7ljUqcBQvuBa6KXAjMC5RNb21oBFcML0eQFsieXnh16MjBs7
         yOEm3SMJeMq1p5aqRmvdBMDzzvfBu8PPFBa0R39xyojOs4A6GDQ350F3rYdhMA8QCy7s
         969g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwPhAvLXFtTBJR6NVxmNPIRf4FTmU6cUeongpd0nVcNVmb4oZKW
	l4UA21K98Q9smBernrVIO5qqJ9OF9TlMh+6sEC/NFB9jrGRsW/6W
X-Google-Smtp-Source: AGHT+IH5n6VsJ5XGvigW6ScSG9Wc8sMM9mEc49a85RH96r361S5Doucmck044H5GHHxlJvdSyqfzaA==
X-Received: by 2002:a05:6902:c1:b0:dbd:af86:426e with SMTP id i1-20020a05690200c100b00dbdaf86426emr14140981ybs.45.1707137974416;
        Mon, 05 Feb 2024 04:59:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:648:0:b0:42c:23c7:6544 with SMTP id e8-20020ac80648000000b0042c23c76544ls91584qth.2.-pod-prod-09-us;
 Mon, 05 Feb 2024 04:59:33 -0800 (PST)
X-Received: by 2002:a05:620a:1582:b0:783:e08c:98b1 with SMTP id d2-20020a05620a158200b00783e08c98b1mr14537526qkk.18.1707137973518;
        Mon, 05 Feb 2024 04:59:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707137973; cv=none;
        d=google.com; s=arc-20160816;
        b=L3nXEWHn6jxuTFS7+m4l6+6/igaKUALIbXb/u9f5lyScvUUzJtM0Ex9XXInYI+jpty
         Zohpav21qyy93mynu1haKy7aDs0nsS1Ed/eRtdze0lFiEQKZ34E/50ty7kpQIy5H7Dsb
         Z+oE2429wN+ayQvoe2wE5SFQZUGz8PcsRXIAX+phkjW2pQZCUldGQEcZ69Q9VelFGGM6
         RNQix4kKOKzbQXL4pkHzbAiF0AxwGa0WUi3LtJQEWDbtS2doMgLEMKloCPNQWY4HEBbr
         FoOHjrgWEC9Gr9T2dVCJ2cwatuz4tca6aMjLJ5OTVzV4oiTtuPQs8OLmtXo5m7GMOitx
         y42w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pEQX5AABggM2ljP9SXv5rHakiVcpbdiil+FOouwBr5w=;
        fh=xRq6+emt+pKKhv8mudFgrwIz20fksvT7qI+QjdPO7QE=;
        b=VdOrMQV3O0iGybseaae4aPtQiT1kucTcsJpbYZW2iH57X30LsBB+s8f0izqy+IyvV5
         rUUgImMEIYcm+HOTlQzI7E4zGcQaYcfII9htFkBADagaS/lTVEbhetu6YuBVMB9Slm5T
         DIce/M8/VaF9/rlpNeBWyvt1xVuYlbO0Xm+gf8klMkMJUHD3F6LRmNrgegVxN3JDJ4UI
         ipN62Z8kGcnoc7ZHoKMikweF4agIzLXGgwSDHa/RM1r/tKdGoA891mlzm+xdkjrxA/3L
         udcbkSILm46FG14w2BHr1t5z3FeK7YDjdgXecYtt3XRYXQv18BW4DIaLA41zu83thOkQ
         JvKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Zpf1WvR4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCX1+ZIvKuu2tqPdAvW37KokvZbSJ/CXaVigARsVPZ4YIuHzHfRHtFM8MyEyKO4DPldIka6rZ3hntH+QnDdKlh4wU0iisUQCXrkhEQ==
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id v28-20020a05620a0a9c00b00783f684e15bsi458738qkg.2.2024.02.05.04.59.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:59:33 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-6e04ea51984so184225b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 04:59:33 -0800 (PST)
X-Received: by 2002:a05:6a00:1d82:b0:6e0:4be0:ab8b with SMTP id z2-20020a056a001d8200b006e04be0ab8bmr1564859pfw.20.1707137973105;
        Mon, 05 Feb 2024 04:59:33 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCWdoon760LIuY5iUr9Hi1uwh8Klg/rh5yNXbpvuhjU1iSvDcI3jtn6GKu0BG9nDz2maou2kIO6N2SUXiKFH60gqsiXSMqdrzhd/XB75C3TRmGl1FTT3s9cQl/oSFe+anrJcpQZJevxFFZZfCQGVcOQ3bPlOJZ8o8QEa0A+EdQ8NwvOhefWaUcn4Hrzg4Dy2RXK0JuqOGz3Ubl+yVGc2a8kwz5g1KryQMA/W9cZOaCmo5bBL3JZSyTR6H8RFu1toDUEKycxhoKWLn8r1oxbqM1h11dkMpheSTbqHKQWT+DsCyhiE6wTcCFWBWDjK+TvNajeRGVFA7XKltL0UAHkKcDzp/iEWn5z5Gbn1qgSA8mqCU2R9YROzvb0n0Ny/xazTsKF/pyYWt8epGa5maZYF+tGbqJ6xVgZvn5J+omKKi8/nnmpIq3c8u5LZycH2FfSC0oyewbiOEZmP/QXB8eqs4FMa0V9P+KJ31ARWiXbHqMRd5Nuwj8jsBp741fDJ3iLMjONrghnCqcBB8zboGm/1jAQLbFMvRjYkpIE=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id it16-20020a056a00459000b006e0416c42c3sm188892pfb.198.2024.02.05.04.59.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Feb 2024 04:59:32 -0800 (PST)
Date: Mon, 5 Feb 2024 04:59:32 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Justin Stitt <justinstitt@google.com>, Marco Elver <elver@google.com>,
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
Message-ID: <202402050457.0B4D90B1A@keescook>
References: <20240205093725.make.582-kees@kernel.org>
 <67a842ad-b900-4c63-afcb-63455934f727@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <67a842ad-b900-4c63-afcb-63455934f727@gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Zpf1WvR4;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430
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

On Mon, Feb 05, 2024 at 01:54:24PM +0100, Andrey Ryabinin wrote:
> 
> 
> On 2/5/24 10:37, Kees Cook wrote:
> 
> > ---
> >  include/linux/compiler_types.h |  9 ++++-
> >  lib/Kconfig.ubsan              | 14 +++++++
> >  lib/test_ubsan.c               | 37 ++++++++++++++++++
> >  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
> >  lib/ubsan.h                    |  4 ++
> >  scripts/Makefile.lib           |  3 ++
> >  scripts/Makefile.ubsan         |  3 ++
> >  7 files changed, 137 insertions(+), 1 deletion(-)
> > 
> > diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> > index 6f1ca49306d2..ee9d272008a5 100644
> > --- a/include/linux/compiler_types.h
> > +++ b/include/linux/compiler_types.h
> > @@ -282,11 +282,18 @@ struct ftrace_likely_data {
> >  #define __no_sanitize_or_inline __always_inline
> >  #endif
> >  
> > +/* Do not trap wrapping arithmetic within an annotated function. */
> > +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> > +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> > +#else
> > +# define __signed_wrap
> > +#endif
> > +
> >  /* Section for code which can't be instrumented at all */
> >  #define __noinstr_section(section)					\
> >  	noinline notrace __attribute((__section__(section)))		\
> >  	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> > -	__no_sanitize_memory
> > +	__no_sanitize_memory __signed_wrap
> >  
> 
> Given this disables all kinds of code instrumentations,
> shouldn't we just add __no_sanitize_undefined here?

Yeah, that's a very good point.

> I suspect that ubsan's instrumentation usually doesn't cause problems
> because it calls __ubsan_* functions with all heavy stuff (printk, locks etc)
> only if code has an UB. So the answer to the question above depends on
> whether we want to ignore UBs in "noinstr" code or to get some weird side effect,
> possibly without proper UBSAN report in dmesg.

I think my preference would be to fail safe (i.e. leave in the
instrumentation), but the intent of noinstr is pretty clear. :P I wonder
if, instead, we could adjust objtool to yell about cases where calls are
made in noinstr functions (like it does for UACCESS)... maybe it already
does?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402050457.0B4D90B1A%40keescook.

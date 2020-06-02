Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6P3L3AKGQEHKGY3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id ACC5C1EC2AE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:26:00 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id k23sf6636445oiw.9
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:26:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591125959; cv=pass;
        d=google.com; s=arc-20160816;
        b=UdSt78uH65OwO7wHwy7z/DKILvUMkxwo545iRc8QOBiw6VvxJiqQdGrGZZrvzFO+qK
         ZyLQYGdCbFWzgZD7ZqoINDlsX6NTbU+l6qUh5xuOpPzBltW6Z52Y1EBJRDHvvAXuP/dp
         otWTQLymCkP5wmqrrpopapMJrg21VbeKphdkil4V65aVhDO4M0EwXkhMk9YZArcjFEoQ
         5bQVGPqygjEsSYsuwPVnf5p1I2W4MUS44iQijVcEn1I8V1El7Bz+EcskLGil0z/2oQ5l
         n+0XaRLMBLxkBGgcxYrXfWc5g3sVdFpqrtLyRPwQaSX24002ds16Rtvj79qQMZYrTHVQ
         R7lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ybVBo5+Olekl8w8KfPshznjmkkfacbumLAb/neBMpJ8=;
        b=vO0UBgRFrTlJFENC18F7SH1Dv27zg2qxBS3SJf3fsgSVZBFv7VW0AGcEiWbGNj2GHP
         RIP6LRetFMkXL5rQA/Ep9L5rKsxeQaLeQ1H5VnSYymRBd0elYVHGunNNg2t9ZlAN/+Fv
         gEov/Blzb0i605NFEat15VARB8VrwWcKtFh1iYlNlO5xkV20FBpkIkpZdmFtE5y6rsws
         xzG6IkOquthKgWsdRDd90a1B057TPgVQmNa/Fd3Zn8CFxMScN2Dq9IcfQSI1qUtfphNs
         P98wIwBP7bVyFPDWVkJcy/HSMji20skdW5dwqm2YUFf/6k22TxSkmN0XwOU7QqB75eZh
         u5KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fi2nlPxf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybVBo5+Olekl8w8KfPshznjmkkfacbumLAb/neBMpJ8=;
        b=CA+ZmzaL+wAibJjXXzM71wpjDaeB5Yz+Jj3F4srsnGKdxPwlGIjvDXhbhVusWziG55
         oteZc/FWy/ZJg3stywcPbpF1lf6yFrZTLjMZQlaCzmODOdkiGx8fXYwBoQ9PLoZyoj+M
         KzSBK5VeCp+TlKAmQymHOUf81rtTqlr8OdzrBNlW16SEcGBCuDjTl3fpBAAPp1w/aTcA
         5oMeC5x1iR8nEYoYBwZKz1Add/PsZvqo+1oAAA1leD7rydJqvKqLuQZb4jLPEKupipnz
         WjlZPSyc04465PdgpELyD0vJf6tqDJBcRpzLPE0OHCX6D7EDpb/52FSEdP2xf97nsk5p
         cOPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybVBo5+Olekl8w8KfPshznjmkkfacbumLAb/neBMpJ8=;
        b=BLswEU3PMHYeCYU55Dmg0ijNPrkVi5BEJ8cIdTPVGVdsuKUIwAL84eErtpPU4jJRjC
         usQQXvTQx4tzKCC25rRqXGdAnJT+TSNiC2L9r2g+z5cxWLVkbQHev/S/xG1Vxiyx5RC/
         eWYUk6hZQAH2pv44BvdSq35HHJdQfXupHvqs61bm2pDAoAuHxY2teWt8fa0chI4Hp0ld
         YqPPX8+d5PwOiuZKUPahOKRMUOdeMQuhQYszxUG7F0SRcc1ooSWOUR0O1WaXdkW7BV2n
         dQRPCBcXDflytYft/HkkgmOdEKxRx4xHjVU0RyFfKkreHVB2sdkhdXxiefDcbMiwf642
         Rfcg==
X-Gm-Message-State: AOAM533zURWZQFVfoclssgcWkq/ZDhZrYuh6XWvjeSIw0ky07RUWEe4r
	M0z6oW+aPGP9ytfGV1y99j8=
X-Google-Smtp-Source: ABdhPJydJSKY2++DmbX7vga2NH9P9+P67se4kidq3OyQjd101Cpm02/MGZbwJX6gkVj5kvbq89KCXQ==
X-Received: by 2002:a05:6830:2417:: with SMTP id j23mr606688ots.108.1591125959638;
        Tue, 02 Jun 2020 12:25:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:61c2:: with SMTP id h2ls3963747otk.10.gmail; Tue, 02 Jun
 2020 12:25:59 -0700 (PDT)
X-Received: by 2002:a9d:5c09:: with SMTP id o9mr571327otk.165.1591125959302;
        Tue, 02 Jun 2020 12:25:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591125959; cv=none;
        d=google.com; s=arc-20160816;
        b=eKOug9dteDUi/z64FAkrlcQQK4U5czoB/hS6iSLQBxZleqM6P6VwEM0DFUbAzC10g1
         vBADp98BD0aqIvuGZULLxids4o/YDwq8bv+l7MOtEY8qLw6K0mDSy01KnG4gA9ItwG3a
         chSPWTvBp5cs+1/ip3h8awW25A+fQgXAgunqLh9lDP0rrCiwozz5oPSMcxSVc7Mo9FBL
         7RpC0FltKS5ijX1RDE5hvxsV05T+C87CiZ/eg9VUy5+62cvE8VtjsUg+Uc1ELZ93ZYTx
         9ZeBBIbq4Q1lfvvk0DXQz8i1yk7LI69Eeta3VLThdfprgMEx/DoqGrEjmzaafCHbTlXX
         IueA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zgQoiQ3jaz0VjmfJxEyv0Pkaee0Wtz3ujBDf41O3EoY=;
        b=YcABAQPi22HDQ4/nENn2DVqZbSSTllsUUjcekhYJKW5qMU1+TUZCTkwJVZW6FXyEN4
         TZFD0VhMdeUnBjsLD2ZjfPFGYhcWlorX0K//PNrO6rEFBH31nD3cnIxKGZOAY4eec5EU
         5buuUdXrxJt2Te37tRAM9w1fLdWB7kEwjD7w0qOUGmSsycIEW4A2V28fKuZf8XQMGeCs
         kNv71OvPnm6HDdE8ryZp6bsaq3Vh7QbmyfLTpEb1RW9e+ekrzv7xAYmo58PQGclaYLcn
         aQmS4hQ6+9BRVryRSk9ZI0KvRA252KzJ9k+P+SdHx5xhBcyzCN3Hex/qSqc3nTOCtC4R
         51xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fi2nlPxf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id f133si175364oib.5.2020.06.02.12.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 12:25:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id j189so5573985oih.10
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 12:25:59 -0700 (PDT)
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr2388414oie.172.1591125958861;
 Tue, 02 Jun 2020 12:25:58 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net>
In-Reply-To: <20200602191936.GE2604@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 21:25:47 +0200
Message-ID: <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>, Will Deacon <will@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fi2nlPxf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Tue, 2 Jun 2020 at 21:19, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Jun 02, 2020 at 11:57:15AM -0700, Nick Desaulniers wrote:
> > On Tue, Jun 2, 2020 at 11:44 AM 'Marco Elver' via Clang Built Linux
> > <clang-built-linux@googlegroups.com> wrote:
> > >
> > > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > > have a compiler that does not fail builds due to no_sanitize functions.
> > > This does not yet mean they work as intended, but for automated
> > > build-tests, this is the minimum requirement.
> > >
> > > For example, we require that __always_inline functions used from
> > > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > > fails to build entirely, therefore we make the minimum version GCC 8.
> > >
> > > For KCSAN this is a non-functional change, however, we should add it in
> > > case this variable changes in future.
> > >
> > > Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> > > Suggested-by: Peter Zijlstra <peterz@infradead.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Is this a problem only for x86?  If so, that's quite a jump in minimal
> > compiler versions for a feature that I don't think is currently
> > problematic for other architectures?  (Based on
> > https://lore.kernel.org/lkml/20200529171104.GD706518@hirez.programming.kicks-ass.net/
> > )
>
> Currently x86 only, but I know other arch maintainers are planning to
> have a hard look at their code based on our findings.

I've already spotted a bunch of 'noinstr' outside arch/x86 e.g. in
kernel/{locking,rcu}, and a bunch of these functions use atomic_*, all
of which are __always_inline. The noinstr uses outside arch/x86 would
break builds on all architecture with GCC <= 7 when using sanitizers.
At least that's what led me to conclude we need this for all
architectures.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP3kAZt3kXuABVqJLAJAW0u9-%3Dkzr-QKDLmO6V_S7qXvQ%40mail.gmail.com.

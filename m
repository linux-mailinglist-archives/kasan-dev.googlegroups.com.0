Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV5QTTZAKGQEQNZPP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 947C115F928
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 22:59:53 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id r192sf6921005pgr.6
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 13:59:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581717592; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRAjw6MYZo+BR8MMVcYd46GmV3e6Sy6dMf1+dS2Xp+QWGMVzzIV9fHHCV7TOUP291X
         UWNgwrNc1BwO0yZqObG2ROewYZKcn0VimKltQmxCaVzMNYsArK4GcYxsSrAghQCVCkXM
         7SFLHRDZ8SQF6hkWqIrv21VHrppvtqxio3Ze1DjNfbcR9oyej68vMhhLpoalEjRyf1v8
         uOBeug9jXjq5809ib+Gxp5YVbp2mtr6rZt5MW0U0WcRUQu6xLuul7wsSvRWpQElHdV+7
         OXy0lCqA4B6QZAy/weTr5Tl3pfBBAfK8GIPWhOX37N4m6gxe2uZrb0Zd9cnuad8JFZw1
         SymQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hhzX9GOG0w2WUf2fGeJN9tBqJJQBI2YxW3aRFkw/xiE=;
        b=mUntxSdVWJu9oAp2UAtF/A/bdoUme3EkHJX9XFnNGvCCJCKsHF1/6clWfZUvZazbyr
         7Wapo+IRhrvJq3FqADARsJc/gIM1Kc+arAB7NBXAYjX5Y8WIWIj4W7vUrWkIoKL9y/tU
         28v0iJdq3rjtusroDvRbBIe1WlC7flMFbTEWir4p13lkA8DRaEB8jGmAWvxThDUUeqCl
         R3GqePZi80Eqvs6k8Xf8Q46QXM9qWe3mxHMW5yDxuoqCDsuqTQb2wU7HkVqoq7loiApM
         MreekVPX5kVOgkfStqLBIKwohNCOiocG4tu5vvmIudLug0P7aXgrNzcVCVG90hgEh4Nw
         xZ4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZz2i5Nb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hhzX9GOG0w2WUf2fGeJN9tBqJJQBI2YxW3aRFkw/xiE=;
        b=NShtMkaeC1pawm4tHcGEQqpu6K/NZ2EYtB/SbnTkW0ueHTOnvS9uqpv/7YogpV0w3v
         dZl9j/g9g+PhXEjyhseY/BbNmKp6cy5nfO51ouQdcFQSrkxeqTWbpVvzgLw7svdYJnag
         EM7Xz2HDweVQKacbR3BoQH+9XRMOBcow3s4qUX4po6DaCMtBE+ml5+l+drLoQk9gmiXZ
         6lNiUzahRcRe0TUYpHsqWBr8yQUrM8xE2FLRC8uSWt+JDg4/epo1yyoBUd6L9Gg4ZteG
         9LfhfLqKUfhpDz6H3e8h8rqTUfl/pVBFTUnNBDwJ9uccsb+XiC5pXz8X1fbZT1r8lOV0
         69WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hhzX9GOG0w2WUf2fGeJN9tBqJJQBI2YxW3aRFkw/xiE=;
        b=NEarv60AOGKb7UqB1BMFj10teiAEoA4uJr69NAbVpDhp0CBpgf1M7/RK5D/Bskxtfj
         R2q3NHZEbC1eRPGn8bH3mvSLD0n794cy2p0/RpPRWs1ZfeeVqB4C1ZUr8EYmTiZOVF8n
         fqClU5dv4cCKUD9xON7YRuY2VJ5EgdkAilAtUOpm8NMchX8HpGEPol1LqpfAGbQo6yfz
         HKwXsjIuUJ9ongtzAZBbshf53jSgru7GNjM+mlf8e8QO2KhvTIvgTLeuolgLdoKohoDk
         zYeqr9IFxraCtnJULBxAOgrwZmkdmodBn8Bm/O1lwMUck/IzGjJXlF9L9sdOa3EN5v2W
         n+yw==
X-Gm-Message-State: APjAAAUNO6OA3TjmlRJ1hQ+97SjmLK6R7iPUWDKJaJHOs1Dy5N1fJcOY
	hu20F4GWWpCTgH4Pgt3JghQ=
X-Google-Smtp-Source: APXvYqxDeG1hnNiatehYng7CrVTX5knPrv16hp/iFFnyXx9AFMPMAvByzcSr9kEJPJgBxJ0DLHq2EQ==
X-Received: by 2002:a17:902:7283:: with SMTP id d3mr5273945pll.118.1581717591749;
        Fri, 14 Feb 2020 13:59:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:253:: with SMTP id fz19ls2552770pjb.0.gmail; Fri, 14
 Feb 2020 13:59:51 -0800 (PST)
X-Received: by 2002:a17:90a:6c26:: with SMTP id x35mr5939251pjj.126.1581717591212;
        Fri, 14 Feb 2020 13:59:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581717591; cv=none;
        d=google.com; s=arc-20160816;
        b=U52t+Njjjud8R3fe34Ocg59YHjCuTiwgDKnmGSSwpjssGaEVV23bCNfoBdhO4Bx5Ps
         DztLZT8hRS5Qg2D5EJ7BITJ1if2wWmI10FXri6uKf1IsXpjZp18EcllH/7ftNgzPGtBL
         8K8OKeRclBC+JqXEOW2i59UKoLXfBGiy8tkJFgYB86U6CRiplkoYnHN5kavYb1vyEaQM
         Yi4Gth/HUoTjTgMUNqJ/CJcgvFqF3N2Pfoz7Z80H9HWuANZo2GGnixKN7Dk5FvrhaXee
         t0wRvanmJO4sutEWRjwyHTyNhcI49uN0ZJhbs2Lwni3hSTxHTE84F+S5bW5mzm4JUoaR
         uRkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FKtuIXcYzsOMF6YWjfEnFlloh3WEO2jbYZIpGax7YKs=;
        b=T/7WwE3ASmMp43l31xEsBgr78/ssAz7Kj6CKzqT3ei1Em6LODA7zXGDsdBI0mYzLQ5
         gU1Shfu3q0KjJcDke6Mcxqacz4Xls/gr6+c8ntOZa0bHmFNCaNjCYQAw5OLfCF5M7yaa
         +SUvnQkSAe3jRVBlP9t4ymOYn4l/Yy0yEhLZUwckxqN2bjNkwH8FahZP391aKd76ivET
         9+UNfShfn8jNF/jIWet5p1Q4lZV1n4lRsMc//gcuLqOsBrjBv6NqrcdoiLrRX8psjLcG
         8urFP5CJzRNMx9PQRfJOezUK3sfW4NHW5hfgx53scGjMpWRI1WCxx/VSpXh/zAMvai9u
         v9qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZz2i5Nb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j10si287092pgg.2.2020.02.14.13.59.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 13:59:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id 66so10578098otd.9
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 13:59:51 -0800 (PST)
X-Received: by 2002:a05:6830:1d7b:: with SMTP id l27mr3702226oti.251.1581717590307;
 Fri, 14 Feb 2020 13:59:50 -0800 (PST)
MIME-Version: 1.0
References: <20200214190500.126066-1-elver@google.com> <1581708956.7365.75.camel@lca.pw>
In-Reply-To: <1581708956.7365.75.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2020 22:59:39 +0100
Message-ID: <CANpmjNOANOLz0mzaWt_N2kqr5EOzGM6=SfTA7doyZ4fh-tQpiA@mail.gmail.com>
Subject: Re: [PATCH] kcsan, trace: Make KCSAN compatible with tracing
To: Qian Cai <cai@lca.pw>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oZz2i5Nb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Fri, 14 Feb 2020 at 20:35, Qian Cai <cai@lca.pw> wrote:
>
> On Fri, 2020-02-14 at 20:05 +0100, Marco Elver wrote:
> > Previously the system would lock up if ftrace was enabled together with
> > KCSAN. This is due to recursion on reporting if the tracer code is
> > instrumented with KCSAN.
> >
> > To avoid this for all types of tracing, disable KCSAN instrumentation
> > for all of kernel/trace.
>
> I remembered that KCSAN + ftrace was working last week, but I probably had a bad
> memory. Anyway, this patch works fine. Feel free to add,
>
> Tested-by: Qian Cai <cai@lca.pw>

Based your further feedback I've sent v2:
  http://lkml.kernel.org/r/20200214211035.209972-1-elver@google.com

Thanks,
-- Marco

> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Reported-by: Qian Cai <cai@lca.pw>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Steven Rostedt <rostedt@goodmis.org>
> > ---
> >  kernel/kcsan/Makefile | 2 ++
> >  kernel/trace/Makefile | 3 +++
> >  2 files changed, 5 insertions(+)
> >
> > diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> > index df6b7799e4927..d4999b38d1be5 100644
> > --- a/kernel/kcsan/Makefile
> > +++ b/kernel/kcsan/Makefile
> > @@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
> >  UBSAN_SANITIZE := n
> >
> >  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> >
> >  CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
> >       $(call cc-option,-fno-stack-protector,)
> > diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> > index f9dcd19165fa2..6b601d88bf71e 100644
> > --- a/kernel/trace/Makefile
> > +++ b/kernel/trace/Makefile
> > @@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
> >  ORIG_CFLAGS := $(KBUILD_CFLAGS)
> >  KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
> >
> > +# Avoid recursion due to instrumentation.
> > +KCSAN_SANITIZE := n
> > +
> >  ifdef CONFIG_FTRACE_SELFTEST
> >  # selftest needs instrumentation
> >  CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOANOLz0mzaWt_N2kqr5EOzGM6%3DSfTA7doyZ4fh-tQpiA%40mail.gmail.com.

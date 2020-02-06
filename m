Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7N6DYQKGQEB3LASII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 511CD154898
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 16:55:17 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id i16sf1558345ual.5
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 07:55:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581004516; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfsyhsTwzMjvwob7Ay5y0nQYRaxaA1i8GOQDsurbFEU4BOetoKvobV77KtI3k8k7le
         UKuerOs13DCiZvGiLCpYfuYUNoDKR+JK3Wba9QsXD38gAf+Mxa4NYSlFvFFU4TN64IQf
         zmJSIHr3vms3MwHjNE8cB0isv0BNjAnV210jLEMDrIyXwVho50AJQhErlljAdFpnZcIH
         BMs3WM820JtafpcSVBYbimB7TbOuAkeg4WNEM26YMweMeFsm0G/wVSZMtBMnodfR0W0S
         G+jPWQ0WCE4YU3Fz9RgFNpFRBe102Aa2TSUp7juyPDgRGHj9dkU5dGjXOpdb5bZ5+uKQ
         5QgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jw5EfDBf7UsOVutd1KjhRzidjwa1OxN3XWdJDLl7aoQ=;
        b=PK/27JOBMw9oraGdQwOXW36FlScOLYGr5Jy/uiBezSNZ8dpdWf3wUZtL7MekF74klB
         tdmQi5bCCj/ErsuTTREms3xFB8G9wBLTPOP5M3mnGW1KFlN/2An44/4gLrIS6mUxVuGA
         qZZJ4/H3QdNeMDT8yt84m3OP2Uexe0HfihGNSD2v58Sv+TYyvz0UUYvrC0Vg+ROCNpIQ
         mm6SbVTqtLa5147FB77/s5dALXmftwaHaaECv5uWurNOJpPoOBoR9Mf4JUiatsQuWEXF
         Mz2oJy/5ngf5wzk8ZINTwfk1px+qQyhLuaVkd1pLNNB3kr/wn4YR9tMoW0l9rRd1kusQ
         Di2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="o4/J9U6C";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jw5EfDBf7UsOVutd1KjhRzidjwa1OxN3XWdJDLl7aoQ=;
        b=IRJuhr32X+PBJQWIPL42mpnd0sc0fXMFHLHc33Hi6uca/UaR0J5JNt4bv0R9xzDUBC
         IBowb4aSVnEpdBse9Vo9Cc3SeFce7YWkcs7ZD9SSyp0jLa1lt5D/01BaVwcAt6jCV/jY
         W8lo0aVli/obrhQK5iR35GGCa+qqvirD8G5C0FKmPninEb/Zm0TEYJrv+ZOFAtjt+iNF
         QwushauuDEd9m76kgJrJLAG8dfkjqnzR1S7pN/eH9MgdmaFVUdauoKmW15cfq3NbbBhB
         QOlyz7JaCLbNydILURd4UBHgqHsnViUY/wrdEn574In6ZPh/tmI/6gGI9ZRPnhHE3Tps
         lMPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jw5EfDBf7UsOVutd1KjhRzidjwa1OxN3XWdJDLl7aoQ=;
        b=uH3B3bKPUm8d/epRjMNXUFUJ0nBKhDm4k6Xn3frbhjwDPkZBtPcmowAezqttFIM1xP
         mtQeWphGfrWmJy8zRfSM0wji55UVYFIFF8Am8Jg2KDupxbPeri8Ztz9B0n1SrcuJomTi
         nmzoxBv3SBK0IlIIsWH2hPsPL1258Qw4G8Wuii/ec5HNfiTho1M7K/8tiM+vP1fz64ZL
         fkf02+uFu+0w4KHIM9AfuXiWQeESz73EzVyvvpyhlP9bak1ah0H2Z4WzbawXzgKGu4/l
         kQSQrRvYl+9vJdKE/IzQciIOiCAvz8gwNJLL5EkNezilnRk1NA2a5QEORpq7eFfblKnu
         cdcg==
X-Gm-Message-State: APjAAAUnUqjxsPtROTwLSFoo03TUmywVt+REmZje3BEdPvUBGqEtebRk
	nRigDa+RteIAHKwyx1SE1X4=
X-Google-Smtp-Source: APXvYqy7k4ax3AINoImgqIqOBWavYCitYI92embwm2xABbsvl7bH96WLkJ54vj5pX/htrtcG4SEtag==
X-Received: by 2002:a1f:a9d0:: with SMTP id s199mr2139711vke.40.1581004515968;
        Thu, 06 Feb 2020 07:55:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:30d8:: with SMTP id c24ls521305uam.1.gmail; Thu, 06 Feb
 2020 07:55:15 -0800 (PST)
X-Received: by 2002:ab0:66d6:: with SMTP id d22mr1954304uaq.92.1581004515551;
        Thu, 06 Feb 2020 07:55:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581004515; cv=none;
        d=google.com; s=arc-20160816;
        b=dnPYCegszM+vGqPMlVbx4krHyYloggWTH2sbECiEn5ANsVVYebLCvBaggKCIL+JG38
         oX2h90BPARmi7xqpSasmiSIuAi+O1EFxg6qbs7iQBTCLcuO91332QjrEyO0k7RSolSHl
         R/BFXDHwLBia58132d7lYVIZuHyqr/c1A/cq7MuodwxfXYPHcs4TzmGACGUZdMKntTbY
         +AVoSncN/8PcBOiG5SJ4kkgfcXaIMCaCiWUmh1m8FayreopR+v7eVjbvZeMJPtyfiYJw
         5oTkbZG9KAiJ0i1aLsWZV5YzvYHZBP0Kz4zcwKipKRKn+d4fkELLW6Z8kkxRbm9vvP/E
         o1GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pEWX0npp6iSdZ2sCeEfnqok64qwFCdE1Pgq5folNH38=;
        b=BZ15kiAO9QPecrdI7SRDOgXiBMcMszgkHgYNvE37WU7cuwDisUgTcSs26HqpFKydFu
         PkUq+k3j58F7yysEK10/uBWNHpbTXZQbQlyhng3Z0POaSu7MEQo4PUMoW4BKFZhS9Goy
         /5NfFLkW+g/8YZUYlQ4U6cc4ntSWnApRNn/YjITJ6HIjaH+KblDuV2wXH5AZ6Xs2LD70
         xS5wPX2n+9QL+jbb1njVvqjoYlzbGXfbIPo3BNAe/BiekDf33uj2vW8OfWHp7CecjDAm
         Q9ZxXDhXO2tbxhj9fRxtdVXF8/hfCg1R/YUSDGPrmCWg6lt+M2BxeYoNq2+XbfY+ZxoX
         k8rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="o4/J9U6C";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id t76si173200vkb.1.2020.02.06.07.55.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 07:55:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id p125so5033220oif.10
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 07:55:15 -0800 (PST)
X-Received: by 2002:aca:c7ca:: with SMTP id x193mr7390131oif.70.1581004514655;
 Thu, 06 Feb 2020 07:55:14 -0800 (PST)
MIME-Version: 1.0
References: <20200205204333.30953-1-elver@google.com> <20200205204333.30953-2-elver@google.com>
 <20200205213302.GA2935@paulmck-ThinkPad-P72> <CANpmjNN4vyFVnMY-SmRHHf-Nci_0hAXe1HiN96OvxnTfNjKmjg@mail.gmail.com>
 <20200205220427.GC2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200205220427.GC2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2020 16:55:03 +0100
Message-ID: <CANpmjNO7_Dp=RtfnnVTrULAKRkX_XW0h5WE+EKGt6oyL6c21kw@mail.gmail.com>
Subject: Re: [PATCH 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="o4/J9U6C";       spf=pass
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

On Wed, 5 Feb 2020 at 23:04, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Feb 05, 2020 at 10:48:14PM +0100, Marco Elver wrote:
> > On Wed, 5 Feb 2020 at 22:33, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Wed, Feb 05, 2020 at 09:43:32PM +0100, Marco Elver wrote:
> > > > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > > > may be used to assert properties of synchronization logic, where
> > > > violation cannot be detected as a normal data race.
> > > >
> > > > Examples of the reports that may be generated:
> > > >
> > > >     ==================================================================
> > > >     BUG: KCSAN: data-race in test_thread / test_thread
> > > >
> > > >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> > > >      test_thread+0x8d/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >
> > > >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > >      test_thread+0xa3/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >     ==================================================================
> > > >
> > > >     ==================================================================
> > > >     BUG: KCSAN: data-race in test_thread / test_thread
> > > >
> > > >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> > > >      test_thread+0xb9/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >
> > > >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > >      test_thread+0x77/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >     ==================================================================
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > > ---
> > > >
> > > > Please let me know if the names make sense, given they do not include a
> > > > KCSAN_ prefix.
> > >
> > > I am OK with this, but there might well be some bikeshedding later on.
> > > Which should not be a real problem, irritating though it might be.
> > >
> > > > The names are unique across the kernel. I wouldn't expect another macro
> > > > with the same name but different semantics to pop up any time soon. If
> > > > there is a dual use to these macros (e.g. another tool that could hook
> > > > into it), we could also move it elsewhere (include/linux/compiler.h?).
> > > >
> > > > We can also revisit the original suggestion of WRITE_ONCE_EXCLUSIVE(),
> > > > if it is something that'd be used very widely. It'd be straightforward
> > > > to add with the help of these macros, but would need to be added to
> > > > include/linux/compiler.h.
> > >
> > > A more definite use case for ASSERT_EXCLUSIVE_ACCESS() is a
> > > reference-counting algorithm where exclusive access is expected after
> > > a successful atomic_dec_and_test().  Any objection to making the
> > > docbook header use that example?  I believe that a more familiar
> > > example would help people see the point of all this.  ;-)
> >
> > Happy to update the example -- I'll send it tomorrow.
>
> Sounds great!

v2 sent: http://lkml.kernel.org/r/20200206154626.243230-1-elver@google.com

Thanks,
-- Marco

> > > I am queueing these as-is for review and testing, but please feel free
> > > to send updated versions.  Easy to do the replacement!
> >
> > Thank you!
> >
> > > And you knew that this was coming...  It looks to me that I can
> > > do something like this:
> > >
> > >         struct foo {
> > >                 int a;
> > >                 char b;
> > >                 long c;
> > >                 atomic_t refctr;
> > >         };
> > >
> > >         void do_a_foo(struct foo *fp)
> > >         {
> > >                 if (atomic_dec_and_test(&fp->refctr)) {
> > >                         ASSERT_EXCLUSIVE_ACCESS(*fp);
> > >                         safely_dispose_of(fp);
> > >                 }
> > >         }
> > >
> > > Does that work, or is it necessary to assert for each field separately?
> >
> > That works just fine, and will check for races on the whole struct.
>
> Nice!!!
>
>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> > >                                                         Thanx, Paul
> > >
> > > > ---
> > > >  include/linux/kcsan-checks.h | 34 ++++++++++++++++++++++++++++++++++
> > > >  1 file changed, 34 insertions(+)
> > > >
> > > > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > > > index 21b1d1f214ad5..1a7b51e516335 100644
> > > > --- a/include/linux/kcsan-checks.h
> > > > +++ b/include/linux/kcsan-checks.h
> > > > @@ -96,4 +96,38 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> > > >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> > > >  #endif
> > > >
> > > > +/**
> > > > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > > > + *
> > > > + * Assert that there are no other threads writing @var; other readers are
> > > > + * allowed. This assertion can be used to specify properties of synchronization
> > > > + * logic, where violation cannot be detected as a normal data race.
> > > > + *
> > > > + * For example, if a per-CPU variable is only meant to be written by a single
> > > > + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> > > > + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> > > > + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> > > > + * race condition. Using this macro allows specifying this property in the code
> > > > + * and catch such bugs.
> > > > + *
> > > > + * @var variable to assert on
> > > > + */
> > > > +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> > > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> > > > +
> > > > +/**
> > > > + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > > > + *
> > > > + * Assert that no other thread is accessing @var (no readers nor writers). This
> > > > + * assertion can be used to specify properties of synchronization logic, where
> > > > + * violation cannot be detected as a normal data race.
> > > > + *
> > > > + * For example, if a variable is not read nor written by the current thread, nor
> > > > + * should it be touched by any other threads during the current execution phase.
> > > > + *
> > > > + * @var variable to assert on
> > > > + */
> > > > +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> > > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> > > > +
> > > >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > > > --
> > > > 2.25.0.341.g760bfbb309-goog
> > > >
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205213302.GA2935%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO7_Dp%3DRtfnnVTrULAKRkX_XW0h5WE%2BEKGt6oyL6c21kw%40mail.gmail.com.

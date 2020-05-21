Return-Path: <kasan-dev+bncBDAZZCVNSYPBBXNMTH3AKGQELCGEBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 37D291DCAE7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 12:22:22 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id x67sf3030629oix.21
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 03:22:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590056541; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zy1gKUIJrid0BCH0ec5pYdb1Ejxjueshr8y8whR+vGN/R10u9wadXlgXfebDTQ8+7n
         vbhgvW8XPb9vpbBOMDcchXvh8gXZaiwwGh7ZliXMOZ8NfbcUmDjapWZ3qS/hj8OpIZjR
         JmyH6B2uhZvQlt8JYN54C2rQPAKKqUxOcHQk56RLIbBjCrb3x6W/iOHiHq4hawIxO9Ah
         i0eykhVOtiukdC2+27S60wQLzazcCypuQuxROopwMoqP3Q80CZTJGEbwZGRol9nmkZux
         AuK/7j35cfGZIkxXnDug8+0GUOUYMm7p94tAlJZLYWx79XyCEDgJKTCDsXyeNpqXXVT4
         SE1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=PXwKqsEp6MUenmY2eXpP3QKMaI9wFXHJuCIeTegAkEI=;
        b=NMbFrHQQZpk6cVzABJ3BMntboZgtqwtTc+2VzYICcAz/i6pC0oIe3VLL0XOMsWjAFC
         rNgfoY1zK2hUqLPWPAEsoyifEpY2lENMgj/cMFfV6NrBN+ubLxh5p5W0+FqwvaAPwJO8
         WQWRGLxiaJRT0GHv9eoSFbOR5NjfsTBRE6b+ej5GghXOoLVCYcomF2xx1R0DbNjPg2OT
         GcquXDIizVAkWFTsvIlp2a0szBGAw1PwkMwVNBvnlFlcu/FHc9yzyBQ5Mc3Yo3xdd88m
         DlC0nR73/Za+xoPB9AVZuzd1iu4KfU0KSLnJI2VMoq1n65+KcTk0YyO4B37fqPrAk4Vw
         GbHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sb5C65+d;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PXwKqsEp6MUenmY2eXpP3QKMaI9wFXHJuCIeTegAkEI=;
        b=fPt+QGsT6jMFa1NU1AcT5xCH6ug9k6YI+bqcrSqiuMpOSq+8azwp1kjFmHNDmo3kiF
         gT1wzSCRj1kkBEvhZ0mD4tD1b/bR0Z4WIBp5b2FdrtSC1YyY3EVO4af+d0902JgJ7yb/
         yg7V4QhX3BxXkbN6twqADBuFO9dpA+3LQP2UTiEkkmfADJv1PPjGIgZzZc2skPFEehr5
         RU4hOHIPbzrpGYCm0ggIaja0yhyppowcrK+kiL6ATE5jcDmbqoCSJfGrIFLH2yfOBZqu
         uLe1YRnaNJ1/PZDFHHCYUHEFevHQcgBTMlNHkLnh/at1pkwOLhXpqHafJZr++QOgQ5yj
         sprg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PXwKqsEp6MUenmY2eXpP3QKMaI9wFXHJuCIeTegAkEI=;
        b=dkc+U2mMmnkmfQBRTgZXdmqfo5QOdFoOYvONIWabEWNYpe1QGci+zWckctvofcVq/e
         XfqE/BxjFeFejOXowdZ24TTLrRWUuz1cnQQI4t4+VYVd8rb+tUwoN6MJVUpa/Fu7/CX/
         y3iiTXA4ym20Ihhq6xhRFcrnuj1MAtoVyHWdntqAqOYc2OJrGsTVCiKcwGNtibVMdEfj
         4nc+nmdQxLmKaKiZj6E+DfeIjGm4e+aB+y+9D0UP4V72hR/PD3BmKvXirrAmv95Wm80p
         g6qfkIUT/E84Dqgq51n7MfUVJVZocV4Fr28oLRcHjkkx/8k9gc8kw6Z+0Tnr6HCFsbW0
         MZEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kKZWvjw/+1sUDfPlp1W06e4xhYGWxaimbF3R2zlitZRxIDGjd
	q6HgtDj6P3EJpxyOaeHpixE=
X-Google-Smtp-Source: ABdhPJwot2B1027EoeBEFUW0SrASHTu9P+bfx7VbfZYPNppHNhIztAkjoIjGPnjiJEZfvuXjuBATpA==
X-Received: by 2002:a05:6830:1d69:: with SMTP id l9mr7019715oti.127.1590056541176;
        Thu, 21 May 2020 03:22:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c54b:: with SMTP id v72ls315316oif.2.gmail; Thu, 21 May
 2020 03:22:20 -0700 (PDT)
X-Received: by 2002:a54:4802:: with SMTP id j2mr6434249oij.170.1590056540823;
        Thu, 21 May 2020 03:22:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590056540; cv=none;
        d=google.com; s=arc-20160816;
        b=XxiiUli0tETHcqkqwoqd3TR7svTke8n9JIXWt2oi9gx6CZaX6MieXrPFQ9jQSqomvZ
         1dteO62NU7rKLGlKBqcygS1HYaJwuA59i6GxIW1Z8q7uOI7sLwFMdEFNqZx+54zhntKa
         lnPe/b3v1vcJm9kNKDQ1LpJwIP+oS1AS5ihJMo1MH5hAoXN2E4QMJjAZgQCFjnWXhWhp
         bXS2qir3swRy+0/GY4/bpmRcrsK3+kmwjn+owea548blJ3Tzox/cLcLUHOTdQlN51+Cl
         eLiOMzGBr5UXs2SIazn7gdP9DFCh7R84oOH+Emr9mPtxgfuFvDhdhDIB3DvetQhF0kVj
         07aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FjG7FeHqf0yFBkIPr3XlM8T0X3uBGaYdIxJzuG74aFQ=;
        b=Wdn7ltg7OBb63HrupSi4AOJT7gao4W1Yfwg2wR9Kl6FS6HT4WIsBGjbdKKh0eHE4WU
         VfB6QIS3LUYSnpFZ1/MbJFZzNmTEcRkO8CP/9uYV1iJ+OymPJu4MQ1L9wK7YXBPeRVL+
         72k6q9KPAkdDymlL11DR82GD0QQfmKIN6M3CAvbNknzW6JVbbsYi3O/LtaAR5ACJ+UR0
         vmdx6mcUt6+2EL5cQn1Na4dXjGCj1pZG6YH0Dg+wp2W/NqI4ERbHoqfWGh/cdZDAn+bN
         1BCBkb4i7xy5JSCs7P59iWGx4IWCivpoadEGMBYzDgCLkhwbYS5tGAjM3umLlS6y/0mk
         mdZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sb5C65+d;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u15si461947otq.2.2020.05.21.03.22.20
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 03:22:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1AB3720721;
	Thu, 21 May 2020 10:22:17 +0000 (UTC)
Date: Thu, 21 May 2020 11:22:14 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH -tip 08/10] READ_ONCE, WRITE_ONCE: Remove data_race()
 wrapping
Message-ID: <20200521102214.GC5360@willie-the-truck>
References: <20200515150338.190344-1-elver@google.com>
 <20200515150338.190344-9-elver@google.com>
 <CANpmjNNdBrO=dJ1gL+y0w2zBFdB7G1E9g4uk7oDDEt_X9FaRVA@mail.gmail.com>
 <CANpmjNPLVMTSUAARL94Pug21ab4+zNikO1HYN2fVO3LfM4aMuQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPLVMTSUAARL94Pug21ab4+zNikO1HYN2fVO3LfM4aMuQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=sb5C65+d;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 12:18:14PM +0200, Marco Elver wrote:
> On Thu, 21 May 2020 at 11:47, Marco Elver <elver@google.com> wrote:
> > On Fri, 15 May 2020 at 17:04, Marco Elver <elver@google.com> wrote:
> > > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > > index 17c98b215572..fce56402c082 100644
> > > --- a/include/linux/compiler.h
> > > +++ b/include/linux/compiler.h
> > > @@ -229,7 +229,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> > >  #define __READ_ONCE_SCALAR(x)                                          \
> > >  ({                                                                     \
> > >         typeof(x) *__xp = &(x);                                         \
> > > -       __unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));  \
> > > +       __unqual_scalar_typeof(x) __x = __READ_ONCE(*__xp);             \
> > >         kcsan_check_atomic_read(__xp, sizeof(*__xp));                   \
> >
> > Some self-review: We don't need kcsan_check_atomic anymore, and this
> > should be removed.
> >
> > I'll send v2 to address this (together with fix to data_race()
> > removing nested statement expressions).
> 
> The other thing here is that we no longer require __xp, and can just
> pass x into __READ_ONCE.
> 
> > >         smp_read_barrier_depends();                                     \
> > >         (typeof(x))__x;                                                 \
> > > @@ -250,7 +250,7 @@ do {                                                                        \
> > >  do {                                                                   \
> > >         typeof(x) *__xp = &(x);                                         \
> > >         kcsan_check_atomic_write(__xp, sizeof(*__xp));                  \
> >
> > Same.
> 
> __xp can also be removed.
> 
> Note that this effectively aliases __WRITE_ONCE_SCALAR to
> __WRITE_ONCE. To keep the API consistent with READ_ONCE, I assume we
> want to keep __WRITE_ONCE_SCALAR, in case it is meant to change in
> future?

Ha! So I think this ends up being very similar to what I had *before* I
rebased onto KCSAN:

https://git.kernel.org/pub/scm/linux/kernel/git/will/linux.git/tree/include/linux/compiler.h?h=rwonce/cleanup#n202

in which case you can drop __WRITE_ONCE_SCALAR; the _SCALAR things shouldn't
be used outside of the implementation anyway.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521102214.GC5360%40willie-the-truck.

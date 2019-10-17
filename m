Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFF2UDWQKGQEKDD4FMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id DA364DA6BC
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 09:49:42 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d2sf925795pll.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 00:49:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571298581; cv=pass;
        d=google.com; s=arc-20160816;
        b=wDtDi7MzA46TE6PaHZPbxNk2UntQpPT5pNn9d1JsoOvwXPgrIOcrckMdCiIRisFUqD
         80V4L6+l/rZvsvQX8lkRiH/WUEdXEa4FypHm3t8GridaOjAna0QXWHf2iL2iQpKnfyea
         N5107ZOSwKUheu98TvSuObh/SzBBoCxbNvrEQSnQOSrhaDPk7W92beqCIF5IO8+hpUuN
         eEjwonE5rEw4lMFIAEeGWdAGVSHT8DTJ0FpXIBIPunCGluTVYthvc1O16R/gXIyNCQgA
         chuYSKflZEi9G2rd032fsNfmYgixEP3NCJXMycp0k7dDb+sVlD+aSAkP3MDqkNqq1cGL
         fVmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4k2mOFkH/IABbB/pnTPD9WroisSwc6hgj3/gmokgT6s=;
        b=ujpeP+YENfaCfKd7IjHEQcWENBwlklqtCfzGSfiA4sJWAFF2GdSVgCIdYUyAVDkWjD
         kTlPrSO2/M8EUkbtqQdecBVBtOMMGFF1AW3MAMymPmvLETppKrtwPtbYeIk2OYJaxY54
         gbMaqlFbd3pmzfS9YLrbfTzsJ8R82BV66gLi8wf6HjESxJ60SJxJHEVv83oO/gY7HDt9
         o4qKUTxnKpTIMGBOPqWkKKixLWv1ZRRazheqzM/nBx3YidcHmR0f58NAeCKjLkdWQ1gU
         VMd4V9GxcK4Kq3Plld557k22QKDrhI82GbItufslhQMXOHLWTk/gp8U/n2yQUoyQpegn
         zNHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dt61Iqtl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4k2mOFkH/IABbB/pnTPD9WroisSwc6hgj3/gmokgT6s=;
        b=LDfxLR4v3+SQt3EJo78KqFizzRT6xQ6LA0zCQRNwqoRWjl3fOkFEcM0/V4fTBGX4ty
         vMsUzO+gLrppuvAKuBywC9JTKHIoYZotmtcuBaqcCXHBdRIMleRp8EbhRXWSJLRF2463
         gOvDYvEEwQlqTjuB080TNRbVMVT+ft9gLVy+YL9mEGZ+Km9awwcT5FmOn51vrSGgsKSU
         M8VDGHHY9OCKjxu0c7BUTTz4YcdUysJLs5zPvORUyB/Dst/8tqKPdIj1NUszknN4uMge
         7/OhpBYbJzUBbahCUPLrla5WwMIQgrfuPo+e1GqSqbFkOX6zZJO1cmpAa7K4mI8gdzC4
         rtyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4k2mOFkH/IABbB/pnTPD9WroisSwc6hgj3/gmokgT6s=;
        b=Nt3qegefsDp2rVdfyOPGb9XhuA8gEjU2ZDENVXuOUJN44d3Zn+ZIgo5tHHJ80Q4dgy
         rZmTBvBYpOchobfDmohdDCxBB87U+dLRzne4uC9tYKuicKp81LORKrpJHbCqs9i4mYUU
         +sNZ15JUsXTs9X3ofbUyP1DUYu4SkA2GaGBz2tffjjJTVWnCwotexJV0+sG7EgDjtAQT
         vuxuCNSC3ftvZsyF55Gcb1qHneses4oxPwRCtAtr0tOJ4aO2TI0HsoP45lBTAVTXuGJu
         X22ZeGmToPnkOdGkmHJAGyXijg7rcfXm/ZEuM2MhuzwNZATY1LHn/6ErWC37YySIWMrW
         iMWQ==
X-Gm-Message-State: APjAAAVcO8zoLaM6FlDjGA8yBcAnHd9aBQj9yWytvCK9Q4OObUaiYSpt
	RQSiUWNosFSK6AT3M3alZ/s=
X-Google-Smtp-Source: APXvYqzBPlgoMl14VurRQMaq5NntOxJPT9K+UMzToxaSQGs9RjGuZTor/CPStAwNmqGubKqhJsxXwg==
X-Received: by 2002:a62:5284:: with SMTP id g126mr2220019pfb.95.1571298581014;
        Thu, 17 Oct 2019 00:49:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b413:: with SMTP id x19ls390543plr.10.gmail; Thu, 17
 Oct 2019 00:49:40 -0700 (PDT)
X-Received: by 2002:a17:90a:b304:: with SMTP id d4mr2688637pjr.27.1571298580481;
        Thu, 17 Oct 2019 00:49:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571298580; cv=none;
        d=google.com; s=arc-20160816;
        b=0+cbwCVzrpIbbsbbn9wUq2z6RRlcSb2YMfl72r4mq29Ie6YXJxUWRGri43Uc7JwdoZ
         70ujmjTq6fAWja5G/UNqzQIrAL+/BYaIVoSBdAZXIlF8+JzTOYpPYyP+KME6238IcH13
         AIOv/2QJEEQEa7okXEc3KyYH9DBP/eAoiegVv5Am3VDEs57ZZiGLuZ15axW5Oc3BcKsX
         GCAkoSFTFxyk9kz5iup6/DfOmClhnWB+XYZP8LL3f8NCnrwuB789ed+OZ0K9BZuNhsHK
         62q6MlYOlW2C2Ks6jUNqPLcS4l3rAl7ZjaPPjMQ1JyuBMfF+TtzADIl5GahMjQVPr9Of
         k1bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cUHCv9N4xmS+l1KgWpk7F+i9WTYTBzhVIUBy6Hulrwk=;
        b=mKCm16kRKelR84oia01VSNoa/7q9iM4PJHRnB6de88LPAwEppiLZMzKsPw2rmWbHxq
         XPT8jcVfb2FaL/psNJrEqggaQ7DYiFKJa9eac5mNB0EB5jqCoBW2EMqMkCsH96Zd9aUp
         SsuZVWGnExs0EkGy3QXUNxGZrREaSQTPPBelwie5VKxqaPQkX7ZZuBe/HkAfW7yP6gSA
         zvbCPH3pkF1fbP5a9QaUDb09PiDLpeFr50uv9h1Q3OIXi4NfzmbP0I0NIFhPxbuwDV5g
         IzGg2Av3KP9WLcakATlFSfxRF8hKWqzwvXVocwdkovfHl2DcphNWu6psgE5raf6dL4sP
         vVyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dt61Iqtl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id b1si112895pjw.1.2019.10.17.00.49.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 00:49:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id i16so1356007oie.4
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 00:49:40 -0700 (PDT)
X-Received: by 2002:aca:55cb:: with SMTP id j194mr1913152oib.155.1571298579393;
 Thu, 17 Oct 2019 00:49:39 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-2-elver@google.com>
 <20191016184346.GT2328@hirez.programming.kicks-ass.net> <CANpmjNP4b9Eo3ZKE6maBs4ANS7K7sLiVB2CbebQnCH09TB+hZQ@mail.gmail.com>
 <20191017074730.GW2328@hirez.programming.kicks-ass.net>
In-Reply-To: <20191017074730.GW2328@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Oct 2019 09:49:27 +0200
Message-ID: <CANpmjNPKbCrL+XzmMrnjqw+EYOa2H94cgE5sPJeuVONbCSqBHg@mail.gmail.com>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dt61Iqtl;       spf=pass
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

On Thu, 17 Oct 2019 at 09:47, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Oct 16, 2019 at 09:34:05PM +0200, Marco Elver wrote:
> > On Wed, 16 Oct 2019 at 20:44, Peter Zijlstra <peterz@infradead.org> wrote:
> > > > +     /*
> > > > +      * Disable interrupts & preemptions, to ignore races due to accesses in
> > > > +      * threads running on the same CPU.
> > > > +      */
> > > > +     local_irq_save(irq_flags);
> > > > +     preempt_disable();
> > >
> > > Is there a point to that preempt_disable() here?
> >
> > We want to avoid being preempted while the watchpoint is set up;
> > otherwise, we would report data-races for CPU-local data, which is
> > incorrect.
>
> Disabling IRQs already very much disables preemption. There is
> absolutely no point in doing preempt_disable() when the whole section
> already runs with IRQs disabled.

Ah thanks for the clarification, in that case I assume it's safe to
remove preempt_disable() for v2.

> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017074730.GW2328%40hirez.programming.kicks-ass.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPKbCrL%2BXzmMrnjqw%2BEYOa2H94cgE5sPJeuVONbCSqBHg%40mail.gmail.com.

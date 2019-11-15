Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFV2XPXAKGQED3XBTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id F32BDFE3BC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 18:15:04 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id i11sf8173327pfk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 09:15:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573838103; cv=pass;
        d=google.com; s=arc-20160816;
        b=kouh8fMUAB/Q5pXD20e/2VFyxyl5/1qDqPk4mp3ddYlv5m5CQ0nHLvkvHgzaIsm5yl
         EUY4Q5bxLCXzPsbuyFUMo8sdEOIfOIF1kUHQYkXqi4nWr+/k0oxhwWxNiOMO6+OcFfy4
         QpyGzASgpgyFkaX3NLt2/KMTf5HjU61+Tw6vN7M6P2ErnpvwnZANyeH4t+M/r1goxzHq
         FSea1v4iIEWeuuO7epQBYXrPDoQbQxQr1GvIc0FDv04rs3gz5EjLz9a2s3r0KJDouvUm
         L/TzbIIFVHg1vfPc47kRcO9E9H1v7hHzBB2XoMD3SSmADIHEoON187hdkpKv0cGUSTOf
         UtuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FqVm/iBLBU0qPfuADvagIcXfn1i38152Sr8s6wSDe6E=;
        b=oRH0B/FhTluvU72YMDHLSqBtvxw/fnNW/ItEr4ZFlVxbQSfWCMJdDIy1l4h1UQcMVR
         hXjUrOQtlo93Kb/UPEf1B9vasOtL96EtDnwerIB5QuIN8nshXC6PN7SDeMBMv2CZBdDs
         HYmmViEe4SjK8zJhG4rwivwbnjVGKlNPIGV5lq2XDqG/Kf5/3P4HYt/7+KzgGMMJAcyk
         572SvdIyFVr3A+2TkHiIE9f9N95EYZG9TZkRxdoKrpYA4mFUeu0vBQmzR+KihaTvZ5EB
         SlMO/HMWp20nerBSOjV0PfqlVa424xYNQGeC/bIuVbJJD1GFMIZdNr1xyY9nZbQUZjFH
         rqoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CBFLAcP+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FqVm/iBLBU0qPfuADvagIcXfn1i38152Sr8s6wSDe6E=;
        b=GGj3h0TnOQG/h2Ge8qKQh1Jlh5mNDidiF+gfUu5zkmrYKl65UcKnrBQ678sqLicAnJ
         nWFCjmjTU3yI2u5EivS3jDXrerMuq9Z08bK/ESbx5N0lRNPHjrbMNN0G6EzkcXvsGa+w
         4a+qko6H+GCJynkKLboQYIIa0R451Iby/3oPxs+AL33HGCpSjOF6llISQ9UiBgjAMC6Y
         qn4Dvt4jLOJsqceU+Nkf14nWumeHkf0W68y68RHI+jKG+0idawKC2GbdMluNDS0l6zDa
         gPGFseCVHN9D+wF3bHsb7Oz5mNVBgIi2961gmHyGgM3+G+4GrAnajGwAU/hpyVjYpWlq
         JG0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FqVm/iBLBU0qPfuADvagIcXfn1i38152Sr8s6wSDe6E=;
        b=saP5OwSLMGONXp0AIs8AY9UMKJr5riGHgpypn2LkQHo14rsbub9pZWxj3vEQk8ocuM
         xW2fTofHcf4r890yxOMslrM3F90WB9pMFBLZW3oQw82SPd0DRwt5saiD2q4KltjAaBsl
         Se4q0zM3xYA1jYLnnk5mOtx2YQAqV95SET5fqJGt+FBs9PE3tgLIo9MeLS2/4IGMCWme
         4S2d7ehcA1DsH1IiZ94HfWXllTTq+8JtKnnhoU/gkdvLSKpiN7OpLaVV+GYBBXiirtA1
         2u/RFS7EiONXdIzMCIm/1SlTeGTFgV+4b1EzXTtqrkUsaYGjRxRFmbvCEaoNAyA6Ga6E
         pCbQ==
X-Gm-Message-State: APjAAAVQl1Zjv4Hou5S4cDaTwJAMnBzXOk99e34vjtqKZDkYtj2aBngI
	trg5s0zICpl7yPU5+dlyvqs=
X-Google-Smtp-Source: APXvYqxSwGIpCNBE7zwS3k/5G+FWdcMV1hgqWxak+96LWlPn5n6gmc+iLO7NV4e+gr/NNzz6Ta+keA==
X-Received: by 2002:a17:902:728e:: with SMTP id d14mr10491725pll.19.1573838102849;
        Fri, 15 Nov 2019 09:15:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4851:: with SMTP id x17ls1941365pgk.14.gmail; Fri, 15
 Nov 2019 09:15:00 -0800 (PST)
X-Received: by 2002:a63:586:: with SMTP id 128mr16956784pgf.198.1573838100766;
        Fri, 15 Nov 2019 09:15:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573838100; cv=none;
        d=google.com; s=arc-20160816;
        b=Ll98RAVyOHE2ghehObI1c8bR9UjdP64974kxDaVojFDE0PMjZRF6OdLRFrYG+Q3+bi
         kJadxTc7srAfpsTSjj9qL9PlSgR3hunp07hlktf6HPPzR13Cif8oJm5swh1nFEGKxvel
         R/Fbq+fsK2DtsVvfZ01f2AV1S8ntt/N1A6MKsxMeyIXy+mHITlaXkzxg5xMJg4doo15c
         Ux8Clw79jdRtYDXeD2iDCKvb1WCm9B2Gqmf3gZQt08w0alhRC9zFNkSd3HC611giDziq
         iBdra+vC9kNruv3V+ky52uOGpu6MaKG9rlfvYE5QvLhU2Mv36Uw7bGiTH4Kw+DAwQLfv
         zu2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OMJenj5JQASv6g4NovikQm2+Hb7lZX8x9WL40qMINts=;
        b=07qhf4UhgljUw6ljddgYqP7jD4goPHHj6Vr+s03P2mA0m03FB672vV2h8484iFDI0V
         O+u+w3lw7fu8ETi2HVwbubh/0NH2Mt6tahL4p8ACJjd4z/Nl9DTypT348xeupDmpSOQ4
         qU0xbO9LSQg/zMq4crGI6Gs44dl/XfSAhCBQZ3inozdxvwylA6Cej7UJ9GfJasLA8N54
         wNyYC6GSo3CwabUxj5h6yL06LjuA6e8JlRa4qaYJ0cULbu2/zySg44yaseRuRwrq94lf
         XLPED79I0a6FS9TuiOGvV2XeBmWwqcjsdgJ8WWJ07nRo376tlj0jme6StOlORnmrLsjm
         oMeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CBFLAcP+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id w63si332811pfc.1.2019.11.15.09.15.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 09:15:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a14so9248408oid.5
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 09:15:00 -0800 (PST)
X-Received: by 2002:aca:4ec6:: with SMTP id c189mr8959788oib.70.1573838099466;
 Fri, 15 Nov 2019 09:14:59 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com> <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com> <20191115164159.GU2865@paulmck-ThinkPad-P72>
In-Reply-To: <20191115164159.GU2865@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Nov 2019 18:14:46 +0100
Message-ID: <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CBFLAcP+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 15 Nov 2019 at 17:42, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> > On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > > >
> > > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > architectures is relatively straightforward (we are aware of
> > > > > > experimental ARM64 and POWER support).
> > > > > >
> > > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > > integrated the feedback where possible:
> > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > >
> > > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > > can be found here:
> > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > >
> > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > including several articles that motivate why data races are dangerous
> > > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > > >
> > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > [2] https://lwn.net/Articles/799218/
> > > > >
> > > > > I queued this and ran a quick rcutorture on it, which completed
> > > > > successfully with quite a few reports.
> > > >
> > > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > > you mentioned, we're fine with your assumption to targeting the next
> > > > (v5.6) merge window.
> > > >
> > > > I've just had a look at linux-next to check what a future rebase
> > > > requires:
> > > >
> > > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > > >   re-inserting the instrumentation into the right places.
> > > >
> > > > Otherwise there are no issues. Let me know what you recommend.
> > >
> > > Sounds good!
> > >
> > > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > > approach is to fix any conflicts during that rebasing operation.
> > > Does that make sense, or would you prefer to send me a rebased stack at
> > > that point?  Either way is fine for me.
> >
> > That's fine with me, thanks!  To avoid too much additional churn on
> > your end, I just replied to the bitops patch with a version that will
> > apply with the change to bitops-instrumented infrastructure.
>
> My first thought was to replace 8/10 of the previous version of your
> patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
> for bitops"), but this does not apply.  So I am guessing that I instead
> do this substitution when a rebase onto -rc1..
>
> Except...
>
> > Also considering the merge window, we had a discussion and there are
> > some arguments for targeting the v5.5 merge window:
> > - we'd unblock ARM and POWER ports;
> > - we'd unblock people wanting to use the data_race macro;
> > - we'd unblock syzbot just tracking upstream;
> > Unless there are strong reasons to not target v5.5, I leave it to you
> > if you think it's appropriate.
>
> My normal process is to send the pull request shortly after -rc5 comes
> out, but you do call out some benefits of getting it in sooner, so...
>
> What I will do is to rebase your series onto (say) -rc7, test it, and
> see about an RFC pull request.
>
> One possible complication is the new 8/10 patch.  But maybe it will
> apply against -rc7?
>
> Another possible complication is this:
>
> scripts/kconfig/conf  --syncconfig Kconfig
> *
> * Restart config...
> *
> *
> * KCSAN: watchpoint-based dynamic data race detector
> *
> KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)
>
> Might be OK in this case because it is quite obvious what it is doing.
> (Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)
>
> But I will just mention this in the pull request.
>
> If there is a -rc8, there is of course a higher probability of making it
> into the next merge window.
>
> Fair enough?

Totally fine with that, sounds like a good plan, thanks!

If it helps, in theory we can also drop and delay the bitops
instrumentation patch until the new bitops instrumentation
infrastructure is in 5.5-rc1. There won't be any false positives if
this is missing, we might just miss a few data races until we have it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ%40mail.gmail.com.

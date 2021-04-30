Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFPWKCAMGQEHILRU5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BEB3837043E
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:50:21 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id q16-20020a05683022d0b029029c29a681b9sf4373otc.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619826620; cv=pass;
        d=google.com; s=arc-20160816;
        b=SmPIsT4a81mxacGX44sPFEU1oJuYCHORt/lueok4Ce6FgR6d1pmi/y/aZj1N2PZ6gZ
         gclqFGrOHaPnw4e0r+YB6Z8zzWFxLRDrqS/lJJMvsJRA8ES0QaY2ypuXVpjXF6uKsu0f
         rxG8UnTNOLFXSTI9zZemJiPqpGTIRiNocXWMlSpu8gyCyhBXlVueDRhI91TwxWLrt9U+
         Sq6PMmNnk3uBFebImCb7vfRG7pcrUzSAPOeLAvODTivlBUgpeF5gROmQYMG7qCr2g+Ga
         ueJKjQssU49yBBFlHLs1eXsHB91tK6aJyGSkBZLKms3zcPjVeSCQWPsbTqsBFo4SHxGO
         GPqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BzXJ+8hmHhfw3cBFCBaCWJ8KVr3S9rYIeSkB35Ckzp0=;
        b=N9Q25fw5G3HWHBiLel88pBoDOSyKOXy1rgHq2SpNGPg5yITTp6V+TVNiI75tw7x8B9
         YKOtN3Ayvyh+ODP6MYttDbMt8XPmHjxVwoiCpg/5ziTzRk/aDSQ4I7ZQU01kJrHq4L8M
         TkBolyRHn/Ir+3jCHzQtJjeEU80ahQ5DhTpE3lIouEN7t/Kh42mc9WBrTke3kkXi+OZ0
         sQcohBvMOHUZQLMq5seF0qTxSKd1foPSgpjr8ZQpngkeCmipid5zTDgFmtefQ9Z13879
         idldkS/lA9MIsrMnlw7ijblserTuTXpj3pjthI90yPyuxxxi7t28LEsqKjasHOVYR6RQ
         r6Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cI3yQrkN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BzXJ+8hmHhfw3cBFCBaCWJ8KVr3S9rYIeSkB35Ckzp0=;
        b=bW/t4GcYzyeXePy5C7pXd7qLhTxnGJNArGqo9sbNqBPey2sauajXLBQvPm+Sn06km5
         YfvnGL9+vGs7PlPWUtDyEJ5/TXMrqZmp6p8rmSJuaowcGLutR53sRkiiEEY4PEirvypt
         GjEzMh8u0tCyl+fBihHAz7MLDJqchG2bwlSr5P4psLMkoD6flym374n9sV1/os5D/Xl2
         TTGbPNfI665L6WJbRGeYLnrbRgSVrpRnfrdjJDz2FSdE/3ySw2sncu+XIWUns+gNoVAy
         WEIuuO8H/OhgDs7rRyREavXCbOdoAu7kqQQ7yvGNFzhTNw19Dz8OG23GT6QSJYN4dl0H
         GwcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BzXJ+8hmHhfw3cBFCBaCWJ8KVr3S9rYIeSkB35Ckzp0=;
        b=OTXi25LJJbdw75qpC6ydePqZb6B/hAoT/vK0gPdeHCWSl3tJhZRNjFnzrI/fcevd3l
         2+2lwtOrTKyEmrPHiyEBbWJt8QdjlkMPc6DRtbdtkE0mrA95jp7M4PgPQdlau8wGmfXN
         Gr+Hjcal9MbOcXvYPBVX6/vOw3+xHz75Ln9EVFoxdF5te85ZxtCTX557fznv3GrmWTrq
         IYt+20FKnON4/dOHp5aFSYLPLqMVgR15SAoVpuE5z4Ocsb21lI01P7I043qWcSMgZr5i
         T9s03oldUDsfCbetfysHSVP3g98x4iEIp+0dfwRAJ4fVD8ElW1mkz176xguD0G9npN+2
         d0fg==
X-Gm-Message-State: AOAM530oxuMYUeLHSBNhBd004d/7knb1jbVzgY9CmLK/K4/rFoCOC3m1
	y/Y+RVszYQevTccnXhjZoiY=
X-Google-Smtp-Source: ABdhPJyOvs0RT2VWOTphCPWF5AyvoUqxCV/BlcP+EUaN+6YYnMD+HCJzXy7jTsfYKikrn8yppc32kg==
X-Received: by 2002:a05:6820:381:: with SMTP id r1mr6618770ooj.79.1619826620700;
        Fri, 30 Apr 2021 16:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:724f:: with SMTP id a15ls2179778otk.4.gmail; Fri, 30 Apr
 2021 16:50:20 -0700 (PDT)
X-Received: by 2002:a9d:6f8c:: with SMTP id h12mr5914643otq.30.1619826620337;
        Fri, 30 Apr 2021 16:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619826620; cv=none;
        d=google.com; s=arc-20160816;
        b=ooo0t8YfAdlMsWqlHRrW8eKpfTPF2GT0J4r/+Z0FvGD+UuJPkje/pmnpLdgsaDPjno
         sAnBU3VLq58GA7psyC+dfLv6z0uRDxtUDV5JBfxgq2yXvqs0bybOeocClEbWFHHVDaTC
         pcq8G0iihOGI2Zeg1ZSUE8ckAdXknWhUaXPOJd5wVbZ7o9uMhhUkMe8zVU4z4y99hgI9
         fzck6MZomO1s5RIErR5pY4JbJoIr5VakYWxYOCcZCYpYMUwi5ucvsg1dZi70cH+TR1mY
         w9YWYAm55g/4kssgFLCObuFeGE9yQjDJt0CTvOKvLv/5E5QOh/OEtQPy1ah6zg6ecmVe
         6eWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q/q7DptLC8egYbR7opYakYP8H9u2iTP4dEK6HMA0wYI=;
        b=mB7Nd3aOi8OTcesv07vhs8SoQoGpLF9JWNu3ZZNZSwJnkcZwy2uyt4hDt7hJXfLTom
         7zeP5DZSb8axPYbVWLEMoalR5M7bbi4b/XdPhEKrAemaIaHOxlzQz/bMlEIJzA9tIwP/
         r1euYWiKJ7z1L8zSTk/lJk0xMzN53hWqthBhkepJQji81u2iyIChYDYxUUR413MNU2nO
         malaZ3jItwFU/8ghivs0YX/PK0LjRHWHU++9WaYbYn3IKoh6UJLrgc8ATxPEhaXJhfQC
         QMFo2mA3NDTTMqJfFnyI2x4X6KDBICA4BSq+lsyDJxWYyNbueGJsTA/cAGlb4hXiLI3G
         zHjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cI3yQrkN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc29.google.com (mail-oo1-xc29.google.com. [2607:f8b0:4864:20::c29])
        by gmr-mx.google.com with ESMTPS id f4si823522otc.2.2021.04.30.16.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Apr 2021 16:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) client-ip=2607:f8b0:4864:20::c29;
Received: by mail-oo1-xc29.google.com with SMTP id i3-20020a4ad3830000b02901ef20f8cae8so8596492oos.11
        for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 16:50:20 -0700 (PDT)
X-Received: by 2002:a4a:e692:: with SMTP id u18mr6616156oot.54.1619826619823;
 Fri, 30 Apr 2021 16:50:19 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com> <m17dkjttpj.fsf@fess.ebiederm.org>
In-Reply-To: <m17dkjttpj.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 01:50:08 +0200
Message-ID: <CANpmjNNU=00iq50xyVpqeg21kata+cTS=wZ7zcU_78K=rWL-=w@mail.gmail.com>
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cI3yQrkN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as
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

On Fri, 30 Apr 2021 at 22:15, Eric W. Biederman <ebiederm@xmission.com> wrote:
[...]
> arm64 only abuses si_errno in compat code for bug compatibility with
> arm32.
>
> > Given it'd be wasted space otherwise, and we define the semantics of
> > whatever is stored in siginfo on the new signal, it'd be good to keep.
>
> Except you don't completely.  You are not defining a new signal.  You
> are extending the definition of SIGTRAP.  Anything generic that
> responds to all SIGTRAPs can reasonably be looking at si_errno.

I see where you're coming from, and agree with this if si_errno
already had some semantics for some subset of SIGTRAPs. I've tried to
analyze the situation a bit further, since siginfo seems to be a giant
minefield and semantics is underspecified at best. :-)

Do any of the existing SIGTRAPs define si_errno to be set? As far as I
can tell, they don't.

If this is true, I think there are benefits and downsides to
repurposing si_errno (similar to what SIGSYS did). The obvious
downside is as you suggest, it's not always a real errno. The benefit
is that we avoid introducing more and more fields -- i.e. if we permit
si_errno to be repurposed for SIGTRAP and its value depends on the
precise si_code, too, we simplify siginfo's overall definition (also
given every new field needs more code in kernel/signal.c, too).

Given SIGTRAPs are in response to some user-selected event in the
user's code (breakpoints, ptrace, etc. ... now perf events), the user
must already check the si_code to select the right action because
SIGTRAPs are not alike (unlike, e.g. SIGSEGV). Because of this, I
think that repurposing si_errno in an si_code-dependent way for
SIGTRAPs is safe.

If you think it is simply untenable to repurpose si_errno for
SIGTRAPs, please confirm -- I'll just send a minimal patch to fix (I'd
probably just remove setting it... everything else is too intrusive as
a "fix".. sigh).

The cleanups as you outline below seem orthogonal and not urgent for
5.13 (all changes and cleanups for __ARCH_SI_TRAPNO seem too intrusive
without -next exposure).

Thanks,
-- Marco

> Further you are already adding a field with si_perf you can just as
> easily add a second field with well defined semantics for that data.
>
> >> The code is only safe if the analysis that says we can move si_trapno
> >> and perhaps the ia64 fields into the union is correct.  It looks like
> >> ia64 much more actively uses it's signal extension fields including for
> >> SIGTRAP, so I am not at all certain the generic definition of
> >> perf_sigtrap is safe on ia64.
> >
> > Trying to understand the requirements of si_trapno myself: safe here
> > would mean that si_trapno is not required if we fire our SIGTRAP /
> > TRAP_PERF.
> >
> > As far as I can tell that is the case -- see below.
> >
> >> > I suppose in theory sparc64 or alpha might start using the other
> >> > fields in the future, and an application might be compiled against
> >> > mismatched headers, but that is unlikely and is already broken
> >> > with the current headers.
> >>
> >> If we localize the use of si_trapno to just a few special cases on alpha
> >> and sparc I think we don't even need to worry about breaking userspace
> >> on any architecture.  It will complicate siginfo_layout, but it is a
> >> complication that reflects reality.
> >>
> >> I don't have a clue how any of this affects ia64.  Does perf work on
> >> ia64?  Does perf work on sparc, and alpha?
> >>
> >> If perf works on ia64 we need to take a hard look at what is going on
> >> there as well.
> >
> > No perf on ia64, but it seems alpha and sparc have perf:
> >
> >       $ git grep 'select.*HAVE_PERF_EVENTS$' -- arch/
> >       arch/alpha/Kconfig:     select HAVE_PERF_EVENTS    <--
> >       arch/arc/Kconfig:       select HAVE_PERF_EVENTS
> >       arch/arm/Kconfig:       select HAVE_PERF_EVENTS
> >       arch/arm64/Kconfig:     select HAVE_PERF_EVENTS
> >       arch/csky/Kconfig:      select HAVE_PERF_EVENTS
> >       arch/hexagon/Kconfig:   select HAVE_PERF_EVENTS
> >       arch/mips/Kconfig:      select HAVE_PERF_EVENTS
> >       arch/nds32/Kconfig:     select HAVE_PERF_EVENTS
> >       arch/parisc/Kconfig:    select HAVE_PERF_EVENTS
> >       arch/powerpc/Kconfig:   select HAVE_PERF_EVENTS
> >       arch/riscv/Kconfig:     select HAVE_PERF_EVENTS
> >       arch/s390/Kconfig:      select HAVE_PERF_EVENTS
> >       arch/sh/Kconfig:        select HAVE_PERF_EVENTS
> >       arch/sparc/Kconfig:     select HAVE_PERF_EVENTS    <--
> >       arch/x86/Kconfig:       select HAVE_PERF_EVENTS
> >       arch/xtensa/Kconfig:    select HAVE_PERF_EVENTS
> >
> > Now, given ia64 is not an issue, I wanted to understand the semantics of
> > si_trapno. Per https://man7.org/linux/man-pages/man2/sigaction.2.html, I
> > see:
> >
> >       int si_trapno;    /* Trap number that caused
> >                            hardware-generated signal
> >                            (unused on most architectures) */
> >
> > ... its intended semantics seem to suggest it would only be used by some
> > architecture-specific signal like you identified above. So if the
> > semantics is some code of a hardware trap/fault, then we're fine and do
> > not need to set it.
> >
> > Also bearing in mind we define the semantics any new signal, and given
> > most architectures do not have si_trapno, definitions of new generic
> > signals should probably not include odd architecture specific details
> > related to old architectures.
> >
> > From all this, my understanding now is that we can move si_trapno into
> > the union, correct? What else did you have in mind?
>
> Yes.  Let's move si_trapno into the union.
>
> That implies a few things like siginfo_layout needs to change.
>
> The helpers in kernel/signal.c can change to not imply that
> if you define __ARCH_SI_TRAPNO you must always define and
> pass in si_trapno.  A force_sig_trapno could be defined instead
> to handle the cases that alpha and sparc use si_trapno.
>
> It would be nice if a force_sig_perf_trap could be factored
> out of perf_trap and placed in kernel/signal.c.
>
> My experience (especially this round) is that it becomes much easier to
> audit the users of siginfo if there is a dedicated function in
> kernel/signal.c that is simply passed the parameters that need
> to be placed in siginfo.
>
> So I would very much like to see if I can make force_sig_info static.
>
> Eric
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNU%3D00iq50xyVpqeg21kata%2BcTS%3DwZ7zcU_78K%3DrWL-%3Dw%40mail.gmail.com.

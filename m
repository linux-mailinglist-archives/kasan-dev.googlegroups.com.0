Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF65QSBAMGQEYUZFEUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id D2AD932D9E1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 20:01:44 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id 129sf4143516vsv.9
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 11:01:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614884504; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+eisMeesq/OqdiJix70sd+PJdHLvQaIjmrKcKN4M6RrL5yf1aOGViIqROF/VwW0N/
         PfNcFhG2tESCjDCM5IaBWXuPth+RStMniqEjeQcZkPw3S91g2iZD99ovarrqW9gM4EO2
         72DK0B0pb/Y/yzaQGrObuOwgd38WTqxY65lVX7zzC7VBhvYu03Be57Hp8R9bxQY+XKuT
         38bmkIDUjsAB2FYodgLCzzdAVXcKndGOuUc5gDcGT+0MyiW+uaPfDhFqAkRFlcgQvVsy
         kEVrsJ5NHCATAaIWTwKwWg6eSBDl6Ouv8gxPq6uNmTiJNw27M+as3KpQmpiT0sIkB2Fc
         dDBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4tI24kW2uoFKFxjH9TJqxuONUpI/AEdH1cPkK9Nsl1o=;
        b=ak8ecR1Wy3LjEDVlsN173EFkGx9+uUhCpQecBUVIFW922iWM/lQZp8Oy3rziaLchQt
         cst2HcWZFGgHcNDnFeHvdfa2jBYoC4s1fjeMwAqUnOvFk23nTyvzHO9PQUMroxsnG9ks
         EFNndG/IUsH3+rj4Sp1LV2sqDdNukjBeTL16b1AVbcJHKr6XuTkVeYF+3PwbiBPLwG03
         //WwDreqbuWh6DoKor2wpNMZeOWmeDF8LdKDYPudnGLqnIiEFI5fBwRT/lnUWWYGDwy0
         nJkLraW4aJdk7qN9yo+B1CEvZaU1fdqp17iZbYF33Demf80ZVL1XVWygZkP7vh80AG4A
         ezLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVSvNizI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4tI24kW2uoFKFxjH9TJqxuONUpI/AEdH1cPkK9Nsl1o=;
        b=E1oFtuK/z5K+plT1nFES511CIdjLvx+70/iVB7nwj+hSfIpGgabVV7POpOvAr1gbnN
         tZZdHM36Jr+U2ot2EvQnXGO1t87YhnYHOrGYEC1LqerM2eGji7d/tDI6Tem9v+TVJiGP
         kfkY00RWNDYS3T1f2tuURFWgJgiKDIB3tPkzw38BtjCKAoc58zgfk3E//kfXsWSCe7xu
         BlLK1uYiZaqqVte4xhCaJaGA5CiELxgyX+0NkRDmv3ZpLbSu6oMks89jVkINSyraMGd1
         uqtU5JsKumiGfGAMTpmoTWgUV2FqYxcrRyYd1j/RCOMA/PuPxiP9S0PbG1wwkTBW8jvQ
         1qRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4tI24kW2uoFKFxjH9TJqxuONUpI/AEdH1cPkK9Nsl1o=;
        b=RH6GhnFdny31LRsCYqR09IODVXesRe9UZDsRhKJukn64PugpCir5sYnb1oQI6vuhx0
         Y+Raq9DuklyuNt6vmwK2X33+RsboIeKHfnH1VACLqsmrvrB0a1IInloSUEBIiEjVShdn
         tP62x2Yl6bWPoihjD+iDjskb3ZMC/nu79Z9mkG5iz4sJD0E/GBJqb+5yhBSYtj1zZf6d
         oBzY+EJCRxCBU038dh8zo4yexmucz72VHimz1DOTTow6sFCQwtJOwyyVAtRicR9HrNhB
         GR4WaY0hY8U6ttv0HtPag3pg2g5nq1+wg0ovJi2CFkNXWDM/tdMNuFWTkic5nBxP3oJR
         1G7Q==
X-Gm-Message-State: AOAM532vkDsSUGfrZFEgf/IXgFDhylfK5iU0QCUTLmxTV29+OFdiwcQ1
	V691AK8TWwfoOfdkcwHvSMQ=
X-Google-Smtp-Source: ABdhPJx/5iegqxeB/ONIp+9tF8LF9nfIjJ8RBFYp8QpB2yNDf4IDnj587yiSdZQYWqQkQcyuXnyOlw==
X-Received: by 2002:a9f:2b8e:: with SMTP id y14mr3722842uai.8.1614884503768;
        Thu, 04 Mar 2021 11:01:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7c86:: with SMTP id x128ls889003vsc.5.gmail; Thu, 04 Mar
 2021 11:01:43 -0800 (PST)
X-Received: by 2002:a67:e219:: with SMTP id g25mr3616173vsa.38.1614884503279;
        Thu, 04 Mar 2021 11:01:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614884503; cv=none;
        d=google.com; s=arc-20160816;
        b=c9L1+6dA37mUs+GVgpLHOjQ2x8dYk7Iiehh2yIeqV8u9HGD+1sigkSZfMZE0V0a3Z/
         mc5CszgR/FSqAZE5w6ih5hmvzLCNsm4E78iviMWRrP2MxKUMLj466CeBE+GwD/FWrHW6
         r9J3NSntVJ/IIVNPxFqTn7PHsKJW/HKq10Syp67TGT9CDQIeUsWRYnqYQkMpRy/iKNu+
         q/kOwM6WrQ4BfB91uHSUCXGhe9ELlpSiKZA/jFTal2ADkyjSxWTz+dpwTbVPGtmjGc6g
         cWRyCvK8PE7a1af2fjfJrgq+VWZ9yBbJvu+UP6MuKBZhfoKBfQIDclYPKxUEAc3Qmn6L
         i12A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0aoBG9bt7K2Nwml5Y4UALv6dR/n8jqT8XlWBeYmu5Iw=;
        b=IF8z2LVQ8jQVVviwrcWjcw6+dQfBzSxA1owh0mRpINWxCGfNqCG01Tx0QvjrwgwIVE
         OzSxRWz4oNyTE4QP/8vUgYBcIHq/oySby4ZPdX3HmPAbseLZlYPBG8O8mmNP6FMXFWXq
         MU/xlwJOErp0sFayyvg2+6Fsu6N2XLs5lctGKqAWLKjpexBqUI3IHoM5XfNOViWAN1mn
         hprqAbs+rolHYKAIO9Z9mM1X9YmAsde8bpkc17B26DTmiKAZ/pYvB/w4Q2029OIBhpTR
         L5mfpJ1bWCbB/GlN7IMW4khouFDp6P1yAzIhlZ4Um35lDB0M2AGKdA5Gk5A1eDPyJ/XU
         BvfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVSvNizI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id w26si41956vse.2.2021.03.04.11.01.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 11:01:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id a17so3654749oto.5
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 11:01:43 -0800 (PST)
X-Received: by 2002:a9d:7f11:: with SMTP id j17mr4694384otq.251.1614884502710;
 Thu, 04 Mar 2021 11:01:42 -0800 (PST)
MIME-Version: 1.0
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local> <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local> <YEEYDSJeLPvqRAHZ@elver.google.com>
 <20210304180154.GD60457@C02TD0UTHF1T.local> <CANpmjNOZWuhqXATDjH3F=DMbpg2xOy0XppVJ+Wv2XjFh_crJJg@mail.gmail.com>
 <20210304185148.GE60457@C02TD0UTHF1T.local>
In-Reply-To: <20210304185148.GE60457@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 20:01:29 +0100
Message-ID: <CANpmjNMQNWBtWS7O_aaCfbMWvQUnzWTPXoxgD8DzqNzKfL_2Dg@mail.gmail.com>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Mark Rutland <mark.rutland@arm.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, broonie@kernel.org, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NVSvNizI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Thu, 4 Mar 2021 at 19:51, Mark Rutland <mark.rutland@arm.com> wrote:
> On Thu, Mar 04, 2021 at 07:22:53PM +0100, Marco Elver wrote:
> > On Thu, 4 Mar 2021 at 19:02, Mark Rutland <mark.rutland@arm.com> wrote:
> > > On Thu, Mar 04, 2021 at 06:25:33PM +0100, Marco Elver wrote:
> > > > On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> > > > > On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > > > > > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > > > > [adding Mark Brown]
> > > > > > >
> > > > > > > The bigger problem here is that skipping is dodgy to begin with, and
> > > > > > > this is still liable to break in some cases. One big concern is that
> > > > > > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > > > > > or outline functions, causing the skipp value to be too large or too
> > > > > > > small. That's liable to happen to callers, and in theory (though
> > > > > > > unlikely in practice), portions of arch_stack_walk() or
> > > > > > > stack_trace_save() could get outlined too.
> > > > > > >
> > > > > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > > > > can guarantee a specific function acts boundary for unwinding (and
> > > > > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > > > > need some invasive rework.
> > > > > >
> > > > > > Will LTO and friends respect 'noinline'?
> > > > >
> > > > > I hope so (and suspect we'd have more problems otherwise), but I don't
> > > > > know whether they actually so.
> > > > >
> > > > > I suspect even with 'noinline' the compiler is permitted to outline
> > > > > portions of a function if it wanted to (and IIUC it could still make
> > > > > specialized copies in the absence of 'noclone').
> > > > >
> > > > > > One thing I also noticed is that tail calls would also cause the stack
> > > > > > trace to appear somewhat incomplete (for some of my tests I've
> > > > > > disabled tail call optimizations).
> > > > >
> > > > > I assume you mean for a chain A->B->C where B tail-calls C, you get a
> > > > > trace A->C? ... or is A going missing too?
> > > >
> > > > Correct, it's just the A->C outcome.
> > >
> > > I'd assumed that those cases were benign, e.g. for livepatching what
> > > matters is what can be returned to, so B disappearing from the trace
> > > isn't a problem there.
> > >
> > > Is the concern debugability, or is there a functional issue you have in
> > > mind?
> >
> > For me, it's just been debuggability, and reliable test cases.
> >
> > > > > > Is there a way to also mark a function non-tail-callable?
> > > > >
> > > > > I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> > > > > on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> > > > > function-local optimization options), but I don't expect there's any way
> > > > > to mark a callee as not being tail-callable.
> > > >
> > > > I don't think this is reliable. It'd be
> > > > __attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
> > > > work if applied to the function we do not want to tail-call-optimize,
> > > > but would have to be applied to the function that does the tail-calling.
> > >
> > > Yup; that's what I meant then I said you could do that on the caller but
> > > not the callee.
> > >
> > > I don't follow why you'd want to put this on the callee, though, so I
> > > think I'm missing something. Considering a set of functions in different
> > > compilation units:
> > >
> > >   A->B->C->D->E->F->G->H->I->J->K
> >
> > I was having this problem with KCSAN, where the compiler would
> > tail-call-optimize __tsan_X instrumentation.
>
> Those are compiler-generated calls, right? When those are generated the
> compilation unit (and whatever it has included) might not have provided
> a prototype anyway, and the compiler has special knowledge of the
> functions, so it feels like the compiler would need to inhibit TCO here
> for this to be robust. For their intended usage subjecting them to TCO
> doesn't seem to make sense AFAICT.
>
> I suspect that compilers have some way of handling that; otherwise I'd
> expect to have heard stories of mcount/fentry calls getting TCO'd and
> causing problems. So maybe there's an easy fix there?

I agree, the compiler builtins should be handled by the compiler
directly, perhaps that was a bad example. But we also have "explicit
instrumentation", e.g. everything that's in <linux/instrumented.h>.

> > This would mean that KCSAN runtime functions ended up in the trace,
> > but the function where the access happened would not. However, I don't
> > care about the runtime functions, and instead want to see the function
> > where the access happened. In that case, I'd like to just mark
> > __tsan_X and any other kcsan instrumentation functions as
> > do-not-tail-call-optimize, which would solve the problem.
>
> I understand why we don't want to TCO these calls, but given the calls
> are implicitly generated, I strongly suspect it's better to fix the
> implicit call generation to not be TCO'd to begin with.
>
> > The solution today is that when you compile a kernel with KCSAN, every
> > instrumented TU is compiled with -fno-optimize-sibling-calls. The
> > better solution would be to just mark KCSAN runtime functions somehow,
> > but permit tail calling other things. Although, I probably still want
> > to see the full trace, and would decide that having
> > -fno-optimize-sibling-calls is a small price to pay in a
> > debug-only-kernel to get complete traces.
> >
> > > ... if K were marked in this way, and J was compiled with visibility of
> > > this, J would stick around, but J's callers might not, and so the a
> > > trace might see:
> > >
> > >   A->J->K
> > >
> > > ... do you just care about the final caller, i.e. you just need
> > > certainty that J will be in the trace?
> >
> > Yes. But maybe it's a special problem that only sanitizers have.
>
> I reckon for basically any instrumentation we don't want calls to be
> TCO'd, though I'm not immediately sure of cases beyond sanitizers and
> mcount/fentry.

Thinking about this more, I think it's all debugging tools. E.g.
lockdep, if you lock/unlock at the end of a function, you might tail
call into lockdep. If the compiler applies TCO, and lockdep determines
there's a bug and then shows a trace, you'll have no idea where the
actual bug is. The kernel has lots of debugging facilities that add
instrumentation in this way. So perhaps it's a general debugging-tool
problem (rather than just sanitizers).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMQNWBtWS7O_aaCfbMWvQUnzWTPXoxgD8DzqNzKfL_2Dg%40mail.gmail.com.

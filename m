Return-Path: <kasan-dev+bncBCJZRXGY5YJBBNONSCCQMGQEMJHW2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B01B38818D
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 22:42:30 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id o12-20020a5b050c0000b02904f4a117bd74sf15040584ybp.17
        for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 13:42:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621370549; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwDyg8UJ98F40fbKRLosFHgSwfdWomQZWI7KvdTUpMtO2tI4yHfBIMukKZ2r3vewcF
         EXT/Mdv87Y2OgZB4FB9hpOoehhJefKo6ppbEGSKn41XYDlA1ojlTGCVKrw168Cd4EJ+6
         LBA3eYbK6b7jTbIyoYgoQYH26SoTQCcKNRkBfkwaGo9hyKHGWGNUlEDYlXGCdTE8RlAB
         p/Qeus291vgaNVDI8bmPAuly7+AN8aSaoIVhKsS/KdcVQBYJS61Lu9h1qIpv5SwtOuZR
         TZrErvje0ogkzQOPsOlA6I5SOUOTKSYeuwFFIS3Hb+Hkd3fRykL9Js8ghK6ngIqyipOI
         InCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=2yxwjXEE2YZa4IbegTUOStR/vVRpXQ6HqiiRbazdTKI=;
        b=MEAPgEytviMHqZ0vJb0XDxO/i4NYHUj1ty0rMIKadz7g5Vk0+K6JlReV0leRmqP9mw
         Ffe72BYMjCIiMGzticE189EN9ABiBY7iziqdj2RRTpb4pS7+WLA392HNUKAAKz2O/dwU
         /n3xGtpVkwqnp1u3lE+pLBzICgzDwMv/J8P77x61qrGayj0wmRPyqSyIHDZdEeKDnLym
         emQgrQ/d0xzCKsVvFdGTWtzc/RsSQU3FoGBgoG71FyBF/w0DWxHsebA3qIByz84Zlp3H
         UHHX5pczNoM+jDXtzvR0y0bqVRlGLNXQbGoINUmNLRJJYOch7tVGCUqYU0haMJHBy1xm
         D/Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WlIKmObp;
       spf=pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2yxwjXEE2YZa4IbegTUOStR/vVRpXQ6HqiiRbazdTKI=;
        b=Yb0ioW5kZREiOIWMF0qwcm1/ArLkc4Z1vmgiJtbYcHVyl0ilepEJyIvIa5ggCF26ti
         egHda4lNHktmEfJ62fHpWFkbsOsDzdqR+UXGbeS0dnaWwO9kYXGOoGBMUv1bqLezIsVr
         ZMEbFxLVafKL8pspuSs1f3QsdV1G4/MzqRQ1ZIa33WzTBb8EyvBU9LZ04feZpBjmIHwy
         5xmhv5QYb1r14C9xaDZrK29xdHt+q1deHJnfjznwy8x/cucrpy5UQ9wQsLBF7DwRhoQa
         UDBlvoa+B1XTUBz2rDMd3JQ1nfHnI1zOSA3HyDSG6wFPKi2NL3/DzhMXIK1BAllRl0Oo
         1TFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2yxwjXEE2YZa4IbegTUOStR/vVRpXQ6HqiiRbazdTKI=;
        b=fGNmlOHtB8jy7CqXV35bopuqs/U+7vjqjjjd6yw4slVFro9vxI36M7y/0KC3Sxif8U
         K5N2+Tb7lAaTXZADiGq+KTdJiUD9sCFRq6garedyokopYeJzfLSxPJTLQu5EVP07NceO
         qR1pzwM6lk1UQ6ii/cdN1HFtJU5w7j0Riw2TSMuxEIb+6/aLoanWnG73sp0sfQ4R8JGn
         a6d1e8enFlAHp1gdilhPzBjDw5W9k92CjTZ1Eo2gVUUPPvdYTC+hcOBE9RmISqFe7jHz
         Fk2G2Qjq3UGDhrgV/0y0+TwfEl5if3eNJ5tFVCuxpsB8YCGrLmuMK/ju02qJ7GH+AZzW
         9ntQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uQba47M2vsb9jy4MnFiAY023PbZaYcR3tN+1XQMLrkJo/8O4a
	GbOG9S4vqBbC3p7OHUhh0d4=
X-Google-Smtp-Source: ABdhPJyBvC+xv5+r4O7cqWKN7lIlEiHNbdg3re6ZrxAuZtjJzprS8UnvJdcz62ElUxYbKKD2MqSV8A==
X-Received: by 2002:a25:a265:: with SMTP id b92mr9692976ybi.486.1621370549517;
        Tue, 18 May 2021 13:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7808:: with SMTP id t8ls10597767ybc.3.gmail; Tue, 18 May
 2021 13:42:27 -0700 (PDT)
X-Received: by 2002:a25:cb0b:: with SMTP id b11mr10297932ybg.477.1621370547378;
        Tue, 18 May 2021 13:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621370547; cv=none;
        d=google.com; s=arc-20160816;
        b=TouWBKjU9m93idGXkL40xRncOD2FZQ0ocGf4syROSGZXYCmFzCD8R7bH3H8W8o08Tm
         Uz+/17M7zS3Y3tmhtnWND9xvLqTIDH5BrDDkmb+UEug6+V31PtcltaUmOLeGaqi4rpvY
         VLLnv4opWfGZQZ9KSQYH5FYKtpSia1z4DOXUyFe0QgxC/edT2pBlSm4m5ZPAuXvvo22h
         /WvN+xokRn9yoiAI+Wuy6Gl74/ud8JVQjPMIiSQUOr2rGdMgHDRxCy+T8iHimHVmC3QM
         0CumMI/Xq09CK/zKxrtUk/MuULjjpJkGQGXcMcFBlVY4zFwpj3o0dC4DhYFWfBVBr/hp
         otRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IBnEpSyWyNXWLrFDO78K42yNMQ9BCegV6R4cQO6bXBU=;
        b=SQxtb2t6CAfWwtQZMiVIVugqxYK7naAFhqyY68zEbyv7x/PrHTc9OOHXwOs4uQa2YD
         zXM5jiuooqSgSwbInxJ6Su6c9UunMFxFKAmKLH9EnbGmzeF3Apeo7f1JVsGseTnXDOi/
         bx7a0ATSo+PP6dU02pJoEO9dkuxXfVjMuyuWKad9T8n5U945fgavAM/geAelNkUcSAzO
         2KETYPW0HuLHSW3Md6/FzxjX0Fh9qPrfFN+8q3f75L8oF9CYb/9hR/tY+7aHRcQa9B7u
         OQhG4N4fOlzfxIcQSoIz9lePMmA/YNptUkl7YwOAutvDmHufJxuLa3dNg0b8EAVfyTw+
         rbTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WlIKmObp;
       spf=pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x5si74311ybs.5.2021.05.18.13.42.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 May 2021 13:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 59C5E6112F;
	Tue, 18 May 2021 20:42:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 049FF5C013C; Tue, 18 May 2021 13:42:26 -0700 (PDT)
Date: Tue, 18 May 2021 13:42:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WlIKmObp;       spf=pass
 (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, May 17, 2021 at 07:12:36PM +0200, Marco Elver wrote:
> On Mon, 17 May 2021 at 18:44, Paul E. McKenney <paulmck@kernel.org> wrote:
> [...]
> > > FTR here is a link to the paper I found:
> > > https://www.microsoft.com/en-us/research/uploads/prod/2019/12/QL-OOPSLA-2020.pdf
> > >
> > > That's an interesting approach. Initially how they obtain the program
> > > "state" and calculate the reward, but the "default observation" thing
> > > answered my question.
> > > I think such approaches may be useful for the SPIN-territory where we
> > > verify a reasonably local and isolated algorithm, e.g. RAFT
> > > verification they used for benchmarking.
> > > But if we take, say, whole Linux kernel then such approaches become
> > > somewhat fragile, inefficient and impractical, e.g. capturing all
> > > tasks and mutexes may be impractical and inefficient (state
> > > explosion), or controlling all sources of non-determinism may be
> > > infeasible. And at the same time it's unnecessary because we still
> > > don't have even the most basic implementation, the random scheduler,
> > > which is not even what they are trying to improve on, it's several
> > > steps back.
> > > I would start with a random scheduler, maybe with few simple
> > > heuristics. That should be simple and robust and I am sure it will
> > > give us enough low hanging fruits to keep us busy for a prolonged
> > > period of time :) Here are tracking issues for that:
> > > https://bugzilla.kernel.org/show_bug.cgi?id=209219
> > > https://github.com/google/syzkaller/issues/1891
> > >
> > > Maybe you did not mean Linux kernel at all, I don't know. For
> > > something like RCU verification (like what you did with SPIN) it's
> > > definitely more suitable.
> > > Interestingly, if we have a notion of "state" we can use
> > > coverage-guided fuzzing techniques as well. Though, I don't see it
> > > mentioned in the text explicitly. But you mentioned AFL, did you see
> > > this mentioned in the paper?
> > > They set a goal of maximizing state coverage, but they don't seem to
> > > preserve a "corpus" of schedules that give maximum coverage. If we do
> > > this, we can mutate schedules in the corpus, splice them, or prime the
> > > corpus with context-bound schedules (see CHESS, another seminal paper
> > > MS research). Generally, the more technique we include into the same
> > > feedback loop, the better, because they all start helping each other
> > > progress deeper.
> >
> > My hope is that some very clever notion of "state" would allow
> > coverage-guided fuzzing techniques to be applied across the full kernel.
> > Here are a few not-so-clever notions I have thought of, in the hope that
> > they inspire some notion that is within the realm of sanity:
> >
> > 1.      The current coverage state plus the number of locks held by the
> >         current CPU/task.  This is not so clever because the PC value
> >         normally implies the number of locks.
> >
> >         It might be possible to do a little bit better by using the
> >         lockdep hash instead of the number of locks, which could help
> >         with code that is protected by a lock selected by the caller.
> >
> > 2.      #1 above, but the number of locks held globally, not just by
> >         the current CPU/task.  This is not so clever because maintaining
> >         the global number of locks held is quite expensive.
> >
> > 3.      #2 above, but approximate the number of locks held.  The
> >         question is whether there is an approximation that is
> >         both efficient and useful to fuzzing.
> >
> > 4.      Run lockdep and periodically stop all the CPUs to gather the
> >         hashes of their current lock state plus PC.  The result is a set
> >         of states, one for each pair of CPUs, consisting of the first
> >         CPU's PC and both CPU's lockdep hash.  Combine this with the
> >         usual PC-only state.
> >
> >         I could probably talk myself into believing that this one is
> >         clever, but who knows?  One not-so-clever aspect is the size of
> >         the state space, but perhaps bloom-filter techniques can help.
> >
> > 5.      KCSAN-like techniques, but where marking accesses forgives
> >         nothing.  No splats, but instead hash the "conflicting" accesses,
> >         preferably abstracting with type information, and add this hash
> >         to the notion of state.  This might not be so clever given how
> >         huge the state space would be, but again, perhaps bloom-filter
> >         techniques can help.
> >
> > 6.      Your more-clever ideas here!
> 
> All the above sound like "functional coverage" to me, and could be
> implemented on top of a well-thought-out functional coverage API.
> Functional coverage is common in the hardware verification space to
> drive simulation and model checking; for example, functional coverage
> could be "buffer is full" vs just structural (code) coverage which
> cannot capture complex state properties like that easily.
> 
> Similarly, you could then say things like "number of held locks" or
> even alluding to your example (5) above, "observed race on address
> range". In the end, with decent functional coverage abstractions,
> anything should hopefully be possible.

Those were in fact the lines along which I was thinking.

> I've been wondering if this could be something useful for the Linux
> kernel, but my guess has always been that it'd not be too-well
> received because people don't like to see strange annotations in their
> code. But maybe I'm wrong.

I agree that it is much easier to get people to use a tool that does not
require annotations.  In fact, it is best if it requires nothing at all
from them...

> My ideal abstractions I've been thinking of isn't just for coverage,
> but to also capture temporal properties (which should be inspired by
> something like LTL or such), on top of which you can also build
> coverage. Then we can specify things like "if I observe some state X,
> then eventually we observe state Y", and such logic can also just be
> used to define functional coverage of interest (again all this
> inspired by what's already done in hardware verification).

Promela/spin provides an LTL interface, but of course cannot handle
much of RCU, let alone of the entire kernel.  And LTL can be quite
useful.  But in a runtime system, how do you decide when "eventually"
has arrived?  The lockdep system does so by tracking entry to idle
and to userspace execution, along with exit from interrupt handlers.
Or did you have something else in mind?

> This is of course a ton of work, and I wouldn't want this to be a
> pre-requisite for the more concurrency-oriented functional coverage
> you suggest above. Just wanted to throw it out there. The major
> technical hurdle I think is that of generalization vs. specialization,
> and I think specialized functional coverage can probably be
> implemented more efficiently. But if it's not supposed to be used in
> production, but only for debugging, maybe it's possible.

No argument with any of this!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210518204226.GR4441%40paulmck-ThinkPad-P17-Gen-1.

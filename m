Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEGIRKCQMGQEITLPI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F0C5383AD4
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 19:12:49 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id h7-20020a5d9e070000b029041a1f6bccc8sf3888097ioh.18
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 10:12:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621271568; cv=pass;
        d=google.com; s=arc-20160816;
        b=FcGKHPpxdnMoqOY+vunkVnu/5oZFXLMzdOXvWLDHSvp/WgJt4Ov0dGJxgfyjpblZ35
         BNoIuBbCeZlAOJK4vS83KQYZwB3uOdMkmCwJZybg3dTGXjv5lqAyiGlyw2PlMoyuEjcO
         ocHCQvB6CiLNufZC2Nv+o/0xIY9I1B4OQkowTo0/cYI35iBh+xK/8yGruoDgXcrFSifY
         IvW8woCRN/IfoKKUYpW70ZWUcu1sB+Af+qxhTUydrXgQBKATMnOTw7LPf/PsEAkXy9YT
         CuF8gGuo/fz22CTrWbMjWz9n/upcpE6UI0Dsg83/4FhsDXwzX5SrU1hPhsguhD+58D1f
         SFtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IrGDhRqeiR3w3yCtyKkdDrh1lDXRdF1bTKzUYmD/AhM=;
        b=eRpBDsUMXiEJ1uLKmVQhXashMMfIyKFfZOn0sj0CgQAYWQ2f77Y4GbyjxQojRvWibq
         lw621YfdVZNITw/+ukbBVgk6DOgAyz62Qq8WNL+F2PHJlpR8gNoxC7eMfz6VuF3sSKq9
         QsEkD4e/seV8j2pNIa2PiTlmohx5Os8JvTaxMsyyOIra0Weu30RTd7+MhvapCnZI0wsK
         0H5NzWZ9pQIRYrbZB5oQuntmLcvE90PbXSZwglhGzApVW3jwvB+Q2pvZVXVdj5p66Ngl
         f7nVF58utW+GymF+5uSypoGc2LY4W8mYrDI7JOl9NKhuSLN7Sz2KMWZeo6uMEc9jw/e3
         YB0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jep8+l7a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IrGDhRqeiR3w3yCtyKkdDrh1lDXRdF1bTKzUYmD/AhM=;
        b=LDCu3OInZGxGjQJA0lZ46ZOAswimXku3rDCdWUvK9BguConlppTM7HH1rwGtdCdNSy
         cmRwPQaAxFYLxgzktOcqSWyWAYiHuJ2bDaaQJB1UlprFoNvqZyrBkvsGsSssDsbMBtbe
         VoPHWfws2VHnmX7yOp+wGH8H6m40rDi78/gq2ZJAEIUhBj6xkUcQFIGtaI47Xp2R6uZ5
         6VSiqh1yE6hLZppC4NfP2BRxds/uevBe3hlIxGoqqMhtvFiMrhxRl19W6Qh/xjaO9z9B
         ATjp2/hWo8juLyVNT2CtapmXq7C1wTGzx3fS1O156vHnTa//GT1pcuQKeyF9XFBBwcFA
         NB3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IrGDhRqeiR3w3yCtyKkdDrh1lDXRdF1bTKzUYmD/AhM=;
        b=bsyXmzdBlnDxS+kab9llNTjB+EJqR1CPjf9jsCJ6jtZ4/D4pNw24n+H4ycmv4/YAaq
         btldQjH/Q53PdfxXUghE7oQGEkR2GJyPCy+02Lp2enNmHRTQa2RvkNq9SPxtO3A4mTCO
         xQNoCCL02EVyfMvZY/QwAm5qChwm+16331gPzI+AOnFxktsxQgGCqnmCqacaRJmg+NTD
         CBv7mKPHQ4HCtFmWZsl5Uxdc/QJmwNiRlkwR4QesXglFovqsgFXgUXC8bWch3LhlO0Ig
         RUwEmf2srRlAzp7E8HNe6nIDa7mF3bVPMfA1bSfesR8/XDpmSdhKVZiDMe9l7MqCEdZn
         4Vbw==
X-Gm-Message-State: AOAM531UlXRHhFQQmJXAheW6p0V7I10e2p+7a0wRrTOw4z0MkWCfBTHX
	heeBcy3xSx8U58J2jJMexWE=
X-Google-Smtp-Source: ABdhPJz4Jl4YoJTrQ7AGX4XTIY1pgGyuQSiR686OYbJA/Tc5wcXSDa/X78XMOBedynl4c0LD1E37eg==
X-Received: by 2002:a05:6602:3146:: with SMTP id m6mr855185ioy.158.1621271568453;
        Mon, 17 May 2021 10:12:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:240c:: with SMTP id z12ls2656150jat.0.gmail; Mon,
 17 May 2021 10:12:48 -0700 (PDT)
X-Received: by 2002:a05:6638:2181:: with SMTP id s1mr1023584jaj.66.1621271568057;
        Mon, 17 May 2021 10:12:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621271568; cv=none;
        d=google.com; s=arc-20160816;
        b=Ds6DDlFuh/s9Wz1EvPnOZcGghqPyRrQ1RhcC0Gq8VrfcH9xSTcv6iSrakyyHP6ELAa
         ro+4g3n+A6Z1ifhyQcdHos+rCknaj2O6a6w5iHrWJ9qNNvWGGHdmfKwepv00mEwoC8ed
         9ThjodpfSM4wwXPs6HM9vp/tE37JCldv93GIrcWyjR9N5B4eB4YRXu2H/epKlFUnOhM1
         mg96rcxzOGBdhiaV5L5WffXz3ctiCyNEWeVE7xC+wuxPVPgKSr2/l8PU2vST8Rnyt7f8
         4BIwcDzy8Y5GIVGkl1HfGGEyJl6G3eJob1AndDbmKYf9O+DTqZLi9zxw9HUE17eMmRnS
         QLFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fQ+5sjY9KrMIVsaJONGrcXAzd5BvTqL+pm/s5X9bK+k=;
        b=osXB/iqEve+IdwCkMby7efcsh7nCvpW/HKn6OfrKicrGucIxHs88RKj/o6f44ldqw+
         Q5AOL5WWQnjxnf6ShEGVu+UsvteDxQUNwOaCLjQhtSPJbWmw3vvKL12BHVp0LFHWRlYx
         0vcV8zp49yhej2aIAGs4W9zzg4sm6zzQm4Cqn/MCIICqWT3vInhE9C87BlSWjIAhrcFT
         1aGcE1I4ZR+Lnj1OYMCwxtNT162o3RzQLcNhOIv1w8PgFQr+ZICzLt8NrM41mphgBn8Z
         n7BJA82xF6y9NqDlEuHjQzaHV4Avn9+iVFvBs81TX+9MCAn3959dY5srt0Z7iqNSd+Mo
         r/0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jep8+l7a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id o3si1446440ilt.5.2021.05.17.10.12.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 10:12:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id s19so7132398oic.7
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 10:12:48 -0700 (PDT)
X-Received: by 2002:a05:6808:f94:: with SMTP id o20mr578995oiw.121.1621271567537;
 Mon, 17 May 2021 10:12:47 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com> <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 May 2021 19:12:36 +0200
Message-ID: <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jep8+l7a;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Mon, 17 May 2021 at 18:44, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> > FTR here is a link to the paper I found:
> > https://www.microsoft.com/en-us/research/uploads/prod/2019/12/QL-OOPSLA-2020.pdf
> >
> > That's an interesting approach. Initially how they obtain the program
> > "state" and calculate the reward, but the "default observation" thing
> > answered my question.
> > I think such approaches may be useful for the SPIN-territory where we
> > verify a reasonably local and isolated algorithm, e.g. RAFT
> > verification they used for benchmarking.
> > But if we take, say, whole Linux kernel then such approaches become
> > somewhat fragile, inefficient and impractical, e.g. capturing all
> > tasks and mutexes may be impractical and inefficient (state
> > explosion), or controlling all sources of non-determinism may be
> > infeasible. And at the same time it's unnecessary because we still
> > don't have even the most basic implementation, the random scheduler,
> > which is not even what they are trying to improve on, it's several
> > steps back.
> > I would start with a random scheduler, maybe with few simple
> > heuristics. That should be simple and robust and I am sure it will
> > give us enough low hanging fruits to keep us busy for a prolonged
> > period of time :) Here are tracking issues for that:
> > https://bugzilla.kernel.org/show_bug.cgi?id=209219
> > https://github.com/google/syzkaller/issues/1891
> >
> > Maybe you did not mean Linux kernel at all, I don't know. For
> > something like RCU verification (like what you did with SPIN) it's
> > definitely more suitable.
> > Interestingly, if we have a notion of "state" we can use
> > coverage-guided fuzzing techniques as well. Though, I don't see it
> > mentioned in the text explicitly. But you mentioned AFL, did you see
> > this mentioned in the paper?
> > They set a goal of maximizing state coverage, but they don't seem to
> > preserve a "corpus" of schedules that give maximum coverage. If we do
> > this, we can mutate schedules in the corpus, splice them, or prime the
> > corpus with context-bound schedules (see CHESS, another seminal paper
> > MS research). Generally, the more technique we include into the same
> > feedback loop, the better, because they all start helping each other
> > progress deeper.
>
> My hope is that some very clever notion of "state" would allow
> coverage-guided fuzzing techniques to be applied across the full kernel.
> Here are a few not-so-clever notions I have thought of, in the hope that
> they inspire some notion that is within the realm of sanity:
>
> 1.      The current coverage state plus the number of locks held by the
>         current CPU/task.  This is not so clever because the PC value
>         normally implies the number of locks.
>
>         It might be possible to do a little bit better by using the
>         lockdep hash instead of the number of locks, which could help
>         with code that is protected by a lock selected by the caller.
>
> 2.      #1 above, but the number of locks held globally, not just by
>         the current CPU/task.  This is not so clever because maintaining
>         the global number of locks held is quite expensive.
>
> 3.      #2 above, but approximate the number of locks held.  The
>         question is whether there is an approximation that is
>         both efficient and useful to fuzzing.
>
> 4.      Run lockdep and periodically stop all the CPUs to gather the
>         hashes of their current lock state plus PC.  The result is a set
>         of states, one for each pair of CPUs, consisting of the first
>         CPU's PC and both CPU's lockdep hash.  Combine this with the
>         usual PC-only state.
>
>         I could probably talk myself into believing that this one is
>         clever, but who knows?  One not-so-clever aspect is the size of
>         the state space, but perhaps bloom-filter techniques can help.
>
> 5.      KCSAN-like techniques, but where marking accesses forgives
>         nothing.  No splats, but instead hash the "conflicting" accesses,
>         preferably abstracting with type information, and add this hash
>         to the notion of state.  This might not be so clever given how
>         huge the state space would be, but again, perhaps bloom-filter
>         techniques can help.
>
> 6.      Your more-clever ideas here!

All the above sound like "functional coverage" to me, and could be
implemented on top of a well-thought-out functional coverage API.
Functional coverage is common in the hardware verification space to
drive simulation and model checking; for example, functional coverage
could be "buffer is full" vs just structural (code) coverage which
cannot capture complex state properties like that easily.

Similarly, you could then say things like "number of held locks" or
even alluding to your example (5) above, "observed race on address
range". In the end, with decent functional coverage abstractions,
anything should hopefully be possible.

I've been wondering if this could be something useful for the Linux
kernel, but my guess has always been that it'd not be too-well
received because people don't like to see strange annotations in their
code. But maybe I'm wrong.

My ideal abstractions I've been thinking of isn't just for coverage,
but to also capture temporal properties (which should be inspired by
something like LTL or such), on top of which you can also build
coverage. Then we can specify things like "if I observe some state X,
then eventually we observe state Y", and such logic can also just be
used to define functional coverage of interest (again all this
inspired by what's already done in hardware verification).

This is of course a ton of work, and I wouldn't want this to be a
pre-requisite for the more concurrency-oriented functional coverage
you suggest above. Just wanted to throw it out there. The major
technical hurdle I think is that of generalization vs. specialization,
and I think specialized functional coverage can probably be
implemented more efficiently. But if it's not supposed to be used in
production, but only for debugging, maybe it's possible.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPbXmm9jQcquyrNGv4M4%2BKW_DgcrXHsgDtH%3DtYQ6%3DRU4Q%40mail.gmail.com.

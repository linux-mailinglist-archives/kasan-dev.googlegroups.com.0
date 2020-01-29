Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GJY3YQKGQE75HM5OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F32114CD54
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 16:29:58 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id e26sf37031qvb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 07:29:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580311797; cv=pass;
        d=google.com; s=arc-20160816;
        b=ie9ZrktC0xMwWxXtRrM+VC0Nq4+9kCwvKnmYqg0ZS0nmwByCpgiYjNIky/pEKD+nPb
         9HJc4dimlp76ik2uHuAXA1kDpnBZQ8TRbKT6R3SbI+lW12+JgsKMWetliHaX89fTcD61
         Gr6pdbXcJo9NPV1tVafaViyOrYNQ1tdkKCQWWyjuiNqrtp2UHXgQ2HBjJ0HVwQpCxmYh
         LWlUSCzBa4S4/88bP/Y48Ub46TMI5DmyMswjiIHOsl85jvQ/kWACT3lxaBzQmcjzwX5N
         tpQtvS4gcW7n66jUAQLjPlidQSVuf2adYsalvafmOHn7HalAP0Ckm9xDXPlDrFa/aZec
         LZkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ipFza+slhy1EDDBk2WMiyIujhcdvq1dvQijiyIsmV1w=;
        b=VH+1FsR/AwrZcbj7o82xUAU4w54VwAgXVTm4lfCxrBjy6+rv+VIsRWU3Z9I6yXQNUj
         IxJRwVfb9aTwWpPLZaABFDVuPAKbeK8T64xmEmhUaSrjxVQWmOojF9q1jIz2ARWy1SDv
         4Q6qzB3wcuTqAacqpCsDNa+4JLs27x3F1cUXc2BZVe4goXN2fNeKdjozRp92DLnOB8fd
         tAohtsRsB5aKgV5/ylhhA/RFAtEDK7dXAKeuKk17gk0V+raeLUBi34dL2BndjyBdj0t0
         py7g9n9IO+y72uMuJD9wbaMT3Ki46PYCAkaH1vM/tI9ec1PxqbaB2z2t+sup5x5bZYXJ
         GpsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HMNe8mc+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ipFza+slhy1EDDBk2WMiyIujhcdvq1dvQijiyIsmV1w=;
        b=HTaIM1OR0Xk0Zw2oqraf6NUtcNj2ns7TLuzfip5t8tp6WoGI1FgqJv3FmfSgQhmW7n
         lNV0sN+QwRFHDsvE4h5VgzcJ2By4cqfMc3J4lXPCUfh8ugRxF38k25nHq8K+kkKnF9G7
         0jZG2WLaxw3KQAGchyw4HZmeRuhzVFR6Eg3o+w7/+hXQRlOMMgVsZmnPJjqRSU2dUenW
         V8uor0ZIVdAl7XcJy2FqcHlSvDEo2lGjG4LZ2Z+Fg1N1b/wBakcl+m3BbCqBBoykUT4V
         CnwdjaPRPVVGjXoEGiDMosWs/7yDB06aQ1WGNkG5iwdCMShYeRS0IXkBkv09ZunzmPWH
         HS9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ipFza+slhy1EDDBk2WMiyIujhcdvq1dvQijiyIsmV1w=;
        b=td9ZVripilQvyfLrzUpyBO2Dbcpl5YvQI/DAsx8w/jCX9evutxT10lxkddlvhvx0YH
         pk+sm1gpQs5nj/C7IncNrfhoieZOglFM8Wccgw2dulmwuu8HEP/+wPhwHKyaSHi3Kczq
         5ihn08tsahlgD+qwlymRSyttOqAwCwC6jpbDbneBtcakuUsOgj8SZuiUBw8fQF66yJER
         sJG+3TO0Z97zZs5Tn47iyGsNimb8BEsmPjotytkfXD7c+oyJsaKWS/1/O7ueiTFdpaLe
         ZKJxdMWet3IAziAi4YXbzKvYY6Zu62v/eDjh5rW2cGJT0wq3fTi7OsNplpRDDOuqcZ6K
         4YZw==
X-Gm-Message-State: APjAAAXGDBvjJyzAwBbDseNifIDHshR2TtVtHGnTzxob9MBD1FjlurF0
	fNedUSG2kUcgBe+QYCuCDOs=
X-Google-Smtp-Source: APXvYqwaizmNrP2jWsZdJGlsIhHzVyV/lmKzxlCc5cDQmL5Yj4xY0YftBAIyDVU9OpHDqA4WzYKX2Q==
X-Received: by 2002:a37:98c6:: with SMTP id a189mr192649qke.500.1580311797032;
        Wed, 29 Jan 2020 07:29:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:73d8:: with SMTP id v24ls6385204qtp.3.gmail; Wed, 29 Jan
 2020 07:29:56 -0800 (PST)
X-Received: by 2002:aed:2f45:: with SMTP id l63mr28173688qtd.221.1580311796372;
        Wed, 29 Jan 2020 07:29:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580311796; cv=none;
        d=google.com; s=arc-20160816;
        b=LcLr98lX0V64byj6ZB1POuMESashMofrXnkRJEQ05Cl5pSOWP5zrQoX9CGit4gaxQb
         I3wVcuTP76dFeVKDB75ik2+0jqDMiBgaD/HC3CKYNg7w+PZyaM0OHoPmpctB3yAaLxqs
         KCgsvf4OPnDtv6PNff35pgGKRhzOn7xFy95yJsCm2/JRbdKyW9s00gm6ul3jOz0aSq5T
         UA9PzZ5KlqSbB24uT/KfTMke5pk6nuwNhraduve8FYUkrRMZGueigekqGb+2ceqNit77
         iSNlDODBpWmhrc1RRv8JOSgRRpG4wAGK2uqpcEXWrcZZSt22+d2/x/ZFFS2kYnNaGvKp
         b77w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V/uFh0yYZSP8uHetzeu1eWpPtJLcY84cq4Xfc1+OZCk=;
        b=I91nIOji+icdpIIb3c4UlAhTNN0Mdch2LKvuVoyMn1Ad2mR+Hg/sO5gUkfNl6cJaCa
         ZFo6UMxoLL2a0UbQCkykpJZHwqWedZQTCZdXfLAABpN85F1exvp9Oa/GVELJI5DKhn4j
         hd1d65YMBh6QtmkZaTb9VIIZILpL8ElkEnqV3Bv1hUcURFDtToBaqUiY83F+WhQ8XVwP
         niU1YrH0SooFmJjSh1McNowpuoV63uiZyE8fRBY6zsKoW6vyg+uRYjujtW7VCbSApyOK
         YfLjtUCZ9U7R+W+L+G2Z0oFnZVhqIGD0p34ativh7qyeA2OHlqcYZjHzdPScK4g9DleU
         Ln4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HMNe8mc+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id c22si88103qkk.0.2020.01.29.07.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jan 2020 07:29:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id a142so69680oii.7
        for <kasan-dev@googlegroups.com>; Wed, 29 Jan 2020 07:29:56 -0800 (PST)
X-Received: by 2002:aca:36c1:: with SMTP id d184mr6743720oia.70.1580311795512;
 Wed, 29 Jan 2020 07:29:55 -0800 (PST)
MIME-Version: 1.0
References: <20200122165938.GA16974@willie-the-truck> <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com> <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net> <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net> <20200129002253.GT2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200129002253.GT2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Jan 2020 16:29:43 +0100
Message-ID: <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Will Deacon <will@kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HMNe8mc+;       spf=pass
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

On Wed, 29 Jan 2020 at 01:22, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Jan 28, 2020 at 05:56:55PM +0100, Peter Zijlstra wrote:
> > On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:
> >
> > > > Marco, any thought on improving KCSAN for this to reduce the false
> > > > positives?
> > >
> > > Define 'false positive'.
> >
> > I'll use it where the code as written is correct while the tool
> > complains about it.
>
> I could be wrong, but I would guess that Marco is looking for something
> a little less subjective and a little more specific.  ;-)
>
> > > From what I can tell, all 'false positives' that have come up are data
> > > races where the consequences on the behaviour of the code is
> > > inconsequential. In other words, all of them would require
> > > understanding of the intended logic of the code, and understanding if
> > > the worst possible outcome of a data race changes the behaviour of the
> > > code in such a way that we may end up with an erroneously behaving
> > > system.
> > >
> > > As I have said before, KCSAN (or any data race detector) by definition
> > > only works at the language level. Any semantic analysis, beyond simple
> > > rules (such as ignore same-value stores) and annotations, is simply
> > > impossible since the tool can't know about the logic that the
> > > programmer intended.
> > >
> > > That being said, if there are simple rules (like ignore same-value
> > > stores) or other minimal annotations that can help reduce such 'false
> > > positives', more than happy to add them.
> >
> > OK, so KCSAN knows about same-value-stores? If so, that ->cpu =
> > smp_processor_id() case really doesn't need annotation, right?
>
> If smp_processor_id() returns the value already stored in ->cpu,
> I believe that the default KCSAN setup refrains from complaining.

Yes it won't report this with KCSAN_REPORT_VALUE_CHANGE_ONLY.  (There
was one case I missed, and just sent a patch to fix.)

> Which reminds me, I need to disable this in my RCU runs.  If I create a
> bug that causes me to unknowingly access something that is supposed to
> be CPU-private from the wrong CPU, I want to know about it.
>
> > > What to do about osq_lock here? If people agree that no further
> > > annotations are wanted, and the reasoning above concludes there are no
> > > bugs, we can blacklist the file. That would, however, miss new data
> > > races in future.
> >
> > I'm still hoping to convince you that the other case is one of those
> > 'simple-rules' too :-)
>
> On this I must defer to Marco.

On Tue, 28 Jan 2020 at 17:52, Peter Zijlstra <peterz@infradead.org> wrote:
> I'm claiming that in the first case, the only thing that's ever done
> with a racy load is comparing against 0, there is no possible bad
> outcome ever. While obviously if you let the load escape, or do anything
> other than compare against 0, there is.

It might sound like a simple rule, but implementing this is anything
but simple: This would require changing the compiler, which we said
we'd like to avoid as it introduces new problems. This particular rule
relies on semantic analysis that is beyond what the TSAN
instrumentation currently supports. Right now we support GCC and
Clang; changing the compiler probably means we'd end up with only one
(probably Clang), and many more years before the change has propagated
to the majority of used compiler versions. It'd be good if we can do
this purely as a change in the kernel's codebase.

Keeping the bigger picture in mind, how frequent is this case, and
what are we really trying to accomplish? Is it only to avoid a
READ_ONCE? Why is the READ_ONCE bad here? If there is a racing access,
why not be explicit about it?

I can see that maybe this particular file probably doesn't need more
hints that there is concurrency here (given its osq_lock), but as a
general rule for the remainder of the kernel it appears to add more
inconsistencies.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD%3DcozW5cYkm8h-GTBg%40mail.gmail.com.

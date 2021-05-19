Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQFISOCQMGQEDSA2ZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D184388A14
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 11:02:58 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id i11-20020a4a6f4b0000b02901ef8b6e92a6sf8671314oof.7
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 02:02:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621414977; cv=pass;
        d=google.com; s=arc-20160816;
        b=04niGfVSd+74NteOF7Blw01q+pclZnStP8yo4GMo6kKOSvYBimjIG3srBUcJuElZSi
         CM5JV+UxAhvDsjmCA1LR9teM4cFKzRSqMPZEZXRLCZq4V9incCvsUYPxrLDZqISYJcBX
         tP2m0/DTTQ3KPQwE/ydEUYxdKeE9cQ5bbWHD6TIuUmFiGILP7qfzh5bSQRjf7QotqxvV
         gSNZ0KwTMP466oHfIbr0ORE8oqBnpubv3Ri4/I7/pedGM4ACd8NLQf+sEn+soNoTwb5/
         Y5gOptCohbjoLM+se4opAmv1PXnrXYcpfG3D6PYSOx/xxBwpGHQkPx+YcFL9TD5a67V+
         k9Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9bFg+OiKZow6eosaxulZE028Qcn/m8exZWucwvrefjE=;
        b=Iw2yi88Iu+y+hG3aalbGV2xKmnqCsixwLzOHeTqqR/u2KZhseUDb9fSIvkjxBJQyNL
         IAIbw/6TldrhAr4UYhd+xtrlwJIjMEro0wRR7Emzp3tfpIc5SRCfht3/nH04kbE8a+Ml
         ECkeoZ/hL7hmWvOkFdJKtQForG9jUCbQ9qS8UUsY/PgsWUVFGtJfh9Jrw+F71X0WfMjK
         WHMnd+dEwEjA2n2UBiv9g7ms6lDr8+Foe9CayQmvgnl8iYK2PGn1/OgIyexLOE/GMpmq
         uqXe+6SnMResmH+uPlRAvCUgiMn5bu1c1rNrbC0yk1pnGiJbvm/UZHzomflOq4qRuor7
         oY0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C8EmKK0c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9bFg+OiKZow6eosaxulZE028Qcn/m8exZWucwvrefjE=;
        b=hv3E0bx5/jfMqptZv5c2Y7CqKEsQTjj5YAc7a2AuWo81qNWSp6Hi4964M3P8LEHc07
         f9R/BwVoSSEgliaoFox/JI4+Vco7PNA0VoET497ncIiR95O1Jec8cYqCZG/mWV8dFK6s
         k8tJ54od4LDFJoISPxD3f4DpeRF3CUVLHdnKo+mJBA+m6kZBgf/NZwlKuDtfBwyqRcwj
         RvPmCZO4pdvwiI/ZZU8ZwO2TgGVPwViaf9xARwfNdoprz3u7T7785zBz0DIXlJNUd5MH
         RkyaAzbumA4lCv/swteXz5Gqn0utP/WizhLNOE/gVgTE3Vjyo9vSQkO6Z+JIVppw0Yqk
         EY0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9bFg+OiKZow6eosaxulZE028Qcn/m8exZWucwvrefjE=;
        b=l201opH+WYIhdB+yjNKbgwIJKY4b4qt7fLRKBp1u3hWf1G5KxnJm5QtvdiOFOJW73G
         LfrZf5XZH/MRxizNX57qutjHYaVblKdB6TMGiWOE1ROcimuASZo30EvTM6Ec+YbXAL0R
         oEYWR6cRGJpMhwIiO29CgaWDjCRs29qQmHJ5iQM9D0GIbzTzXonRzwlV3egvR1yUgQ5c
         veHIRnWpcOXfT7Nb1OxgzMkkLEqYKnm9SpRT9qdyemLxahzp1bRppD3H1lrilCpNUGEi
         R0jQXOVhHhHOUOb81/jE45g5h9n0S4MEnoPhnnFKGRUBOrWkPIFewQpPz1hogZZAGc+H
         yalA==
X-Gm-Message-State: AOAM531m1CIw3xNuUFNT+0Zxj+psaQvmdMITS2corzg1RKvQlORf6M0n
	jgd4jxrP2aq26ZUPeR1D5H8=
X-Google-Smtp-Source: ABdhPJzAPgH3WjiP5IaxeTF5IudXgo8/vuna6SaUzLZNnYoFRElogihiYo1f/wMfIZgrRl4dr86Krw==
X-Received: by 2002:a05:6830:1f52:: with SMTP id u18mr7868318oth.298.1621414976992;
        Wed, 19 May 2021 02:02:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d487:: with SMTP id l129ls6233490oig.11.gmail; Wed, 19
 May 2021 02:02:56 -0700 (PDT)
X-Received: by 2002:a54:4e81:: with SMTP id c1mr7618963oiy.119.1621414976608;
        Wed, 19 May 2021 02:02:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621414976; cv=none;
        d=google.com; s=arc-20160816;
        b=M7FFe4V9tJKjIqbeA17RV3k83ZHFmuH3GFQEhS2mxjcETc6LeN60hwc0gGamqh6Rfk
         YpNpctnbecX8oEdDYBfY3C+rMTcpobtrNgDiSgNOoDqGOMttYX66/Hj/OtwGSrOOvk1p
         pEF7IaenUrk2CWQhjc4g4Rw6zJasJ7qM7Z1BAZVehYELxruwkbkyR5X8BkXN2Ed7tn5S
         UrLtHCHvK2aBxUe2leB79ecQxi58eEatXo6tqw7ciutmgryrCOhiv4TskBk6i+gSFBAP
         2a+ZkrYHTS8lfXXL2Po8VS7ob4BDjsD5gqiHmCvn1zDJBCsK9mZCsAf2RRdC7/7qaqgc
         qYtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zVuRM5Cvw95EXFNT1B3YV+ow+Bdf9kLj0bSesSiCR4c=;
        b=tyKZ4l/WCDmQmVl3GOs+wa7m82m0mFwGU31z/tST/AeObOMrltZGjKWshFUC0h58Pd
         rBCuQdnY21VuQfFLSzUZ2ffdA9MWBnksYs7VMl7Sj8CCENkTBbVQ3e6QPjbXJAh6ZRpf
         u3Iel0rWfc8BWbL9S3bmqlflvLW9U7MkesPUmIb2rCvTUaS6ol2QFOGDddqqpY0P1aEe
         b2E+SL9KNW5DbrPWYZUm2xOoTFd0/qjYfKcHsOu7Js0gJaF8kYgxW3Dem1BD4bGp9goQ
         WofJD40/oUnK9Bam2NUGQz6XFmkijjwQar3nUcs+qflfa6CbyC/RFKURdGNOfyoYa3KY
         /APA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C8EmKK0c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 12si1706741oin.2.2021.05.19.02.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 02:02:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id w127so8658077oig.12
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 02:02:56 -0700 (PDT)
X-Received: by 2002:a05:6808:f94:: with SMTP id o20mr7439091oiw.121.1621414976129;
 Wed, 19 May 2021 02:02:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 May 2021 11:02:43 +0200
Message-ID: <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C8EmKK0c;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> > All the above sound like "functional coverage" to me, and could be
> > implemented on top of a well-thought-out functional coverage API.
> > Functional coverage is common in the hardware verification space to
> > drive simulation and model checking; for example, functional coverage
> > could be "buffer is full" vs just structural (code) coverage which
> > cannot capture complex state properties like that easily.
> >
> > Similarly, you could then say things like "number of held locks" or
> > even alluding to your example (5) above, "observed race on address
> > range". In the end, with decent functional coverage abstractions,
> > anything should hopefully be possible.
>
> Those were in fact the lines along which I was thinking.
>
> > I've been wondering if this could be something useful for the Linux
> > kernel, but my guess has always been that it'd not be too-well
> > received because people don't like to see strange annotations in their
> > code. But maybe I'm wrong.
>
> I agree that it is much easier to get people to use a tool that does not
> require annotations.  In fact, it is best if it requires nothing at all
> from them...

While I'd like to see something like that, because it'd be beneficial
to see properties of the code written down to document its behaviour
better and at the same time machine checkable, like you say, if it
requires additional effort, it's a difficult sell. (Although the same
is true for all other efforts to improve reliability that require a
departure from the "way it used to be done", be it data_race(), or
even efforts introducing whole new programming languages to the
kernel.)

> > My ideal abstractions I've been thinking of isn't just for coverage,
> > but to also capture temporal properties (which should be inspired by
> > something like LTL or such), on top of which you can also build
> > coverage. Then we can specify things like "if I observe some state X,
> > then eventually we observe state Y", and such logic can also just be
> > used to define functional coverage of interest (again all this
> > inspired by what's already done in hardware verification).
>
> Promela/spin provides an LTL interface, but of course cannot handle
> much of RCU, let alone of the entire kernel.  And LTL can be quite
> useful.  But in a runtime system, how do you decide when "eventually"
> has arrived?  The lockdep system does so by tracking entry to idle
> and to userspace execution, along with exit from interrupt handlers.
> Or did you have something else in mind?

For coverage, one could simply await the transition to the "eventually
state" indefinitely; once reached we have coverage.

But for verification, because unlike explicit state model checkers
like Spin, we don't have the complete state and can't build an
exhaustive state-graph, we'd have to approximate. And without knowing
exactly what it is we're waiting for, the simplest option would be to
just rely on a timeout, either part of the property or implicit. What
the units of that timeout are I'm not sure, because a system might
e.g. be put to sleep.

Also see Dmitry's answer, where he has concerns adding more dimensions
to coverage.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%2BnS1CAz%3D0vVdJLAr_N%2BzZxqp3nm5cxCCiP-SAx3uSyA%40mail.gmail.com.

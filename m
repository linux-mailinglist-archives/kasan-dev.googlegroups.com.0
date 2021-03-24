Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC4G5WBAMGQEXBBYY6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AA5E3479E0
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 14:47:56 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id x129sf514981oia.10
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 06:47:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616593675; cv=pass;
        d=google.com; s=arc-20160816;
        b=rWUeEs07L8NGa2AOB8hGp5RUShKim7ExyrI4mhihcxHnJl56Cf0xLPBunyYBc3+mfk
         msrSnw/ot08E3pe+8bw8OgclqTT6l6fk/fpBzzBOmVfG8+Wo4hGffN4/ggKVTXzUJk10
         DrUCvbJVSJ2Ahei7oLHdKSRnA/Q+8K4ZtPey7392uMBoCr+TrMN7rH0UksWOUOfAqGRu
         Gto+R0iQpmHYSaOit5eitDhGM/if93t6VmDLWsXmLykRL0NhNQacLhUXXblZie9tCSL6
         /1Ggb5wzQAtum/Z+Rj4pHTMuFxDCYtkiLibuf9//bXHWvjXMWqdpV5JX/dclu4X8a6g5
         FBUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bBjmeYlSAfAX7FG9cECGfKIfNyHCYqD8wEUFSF6maSY=;
        b=cW4DzHjv/+byN6y26Pv6Bd8uAJI+XWJCdo8+jv2V6hTIU0Aon1pgTMsuq8s23nbgR+
         UInAt3rZ8ITzeO8Uo8NbZC8hr2CMwQgrW2HQ1Y1/WFtmsj2F4plz5ZBkKuXsQy6RNW1e
         W+vMmlxFXWK7m6VF8/YTYFtZLBd5xhXmjs1IiGa0Z7ezvTcpDGcTy66V2XRWkeAYTldz
         t6JF+48jptC/zXBItgXBw1VJydTTHG9+grALVLaEf+EOtA9c1VQOQlOGXxU8uzvhj7Wk
         IGetkwj2st5ZuSMGwv4NGp1UlW/Jszxg8W6b9RAa5cuafn5+CqLRVJIhA5EHfz0P9l9N
         zPzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NQINk5lc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBjmeYlSAfAX7FG9cECGfKIfNyHCYqD8wEUFSF6maSY=;
        b=WT12E2OyaUb+1J1snw7Gh18Y2DQCVWKiHuQi0uhblQnRiStugm+HeiTeoG8nlAPM8W
         KCgPm2np13EYvI9ShZmCTXHOvGw/AuBAkXRQOd+T+sKVZowAfY7F31StGwUyJzlWpmi0
         46bHY7k0ckapUu/5dv/BFpPc6R7Efoz/i4Z4gmJCzNAz/wx3yLz1bDiP6qg+3nsn2i8r
         ZOOe442ncCsQPwJn6QeOmAYtEkXRzMi99si+SjzkdRV/tRETl1rXBcgdzELFxPuULgTV
         NyCyyCNP0TeobO/p247eZLhtif/DFN9sppK3yKmfF94dcsiE+sFTwMt5bFD2L32tVkU7
         GR6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBjmeYlSAfAX7FG9cECGfKIfNyHCYqD8wEUFSF6maSY=;
        b=SvGfLUxfwfUVghfnKEDUc0Dc433mgVsC27gf18i5iQgF5DFooX6BMsCyBkE5zuIU1Q
         9fFy7Wbcod9WxE3a5xnCbRANp9rF9ZtP0PZ8u6xGu4oI1Xzbbb9NL8ubWwtQnbMDeQ1U
         FTO9iOygnSzkuG1/fTYvCvl5z2dUb0cYsKeW+hfqVku4aqBX23Q6Bp2k7QMfRCWW7rxB
         cuDyLOzdAT7ks3PEkjl66Rp0c8yYlSUPUchaqoXMwUjOC3K3kynP13OL56f2iN+2ZBcZ
         K9GoF4U5dbyryNsmZkoScERzGBFoql0FZTepIw90VKyQTOlC+pVtBTLN0Dk5GC8IjmpA
         pT4A==
X-Gm-Message-State: AOAM530WT4SC8jf4DIh0KGdd2npQAVQvfdn9kMz/9L/+tIrpI7jsur8N
	aOdtzDpRc82hazPqBy0B66I=
X-Google-Smtp-Source: ABdhPJxJGWGLHtDRIyqopTP7JWjkSPLFwKM7cfnCBPI2JnzbPwMx76iiAkAhVkicc8Xuq59evjjZvg==
X-Received: by 2002:a4a:8845:: with SMTP id e5mr2938109ooi.90.1616593675351;
        Wed, 24 Mar 2021 06:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3113:: with SMTP id b19ls644294ots.5.gmail; Wed, 24
 Mar 2021 06:47:55 -0700 (PDT)
X-Received: by 2002:a9d:2628:: with SMTP id a37mr3385800otb.366.1616593674960;
        Wed, 24 Mar 2021 06:47:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616593674; cv=none;
        d=google.com; s=arc-20160816;
        b=rqOp/IRW+luwsTHIpYlqlZtSis0F9hoAvZpIj9RF0bhr/KoQbeOU/hXYfbTf1+bGX9
         iqbdtMa5FnOI5pLUYstpqsnFLTXUtiEDwdbLVMLYfwUj5Q9pTlywbGGsI1ck/0cSCptu
         Tde3+lpPHZvmnDRZ426Mu/Za5sThu1m7jW7t8uBhSkz5A/Op6E3/sKeiFvpnQK6rDZ39
         Bxn+e0mtq+WsHq11ZXRVVJzEh51V1Ib8UbhD6mhDOpcxcQ+Sjbe2z+qY+nhNoirmw4FZ
         pUQwU3nfj4IcyWCPr3hD4mPduEfr35CTsPGeo/vItaJ3nZYkFRKsG+p55O0InqYvw5Bz
         59VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tUH1uT1xGENlL23VeLmAGT6RQ/hIIGv8URJxekLD7KA=;
        b=aYBVPqU2dTSuAThNhpojlB6FTu2YQIVShgARVeS2Wo0kgk/K97Ry/GrV0+dgSlAh3F
         HyYt4xCorzw2xsv4v2EVIihywX0ud0/asvSkaacH6D9el1MN4rGgdto/6JbJUzaezYBR
         fs33dVdh1dFIvOHJ9Ivs7Hy3JV18//tD4Y4FGdaWaUwcfLHXG6R6Bd0Y3Za0Zk8YbUro
         Q5V4ELXTb/CuY8jxruB3tLrqkzpHk9CYNuOkyz4x0dnmYdMwxihlp05nm2GnvCmGvhyQ
         jaymdUPup3hI2xyPjENiaZI250tGR0B76YI8sYLlHMV1XKSUNnmcQu+SrniHPUOLabFN
         RnxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NQINk5lc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id h5si188516otk.1.2021.03.24.06.47.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 06:47:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 68-20020a9d0f4a0000b02901b663e6258dso23023456ott.13
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 06:47:54 -0700 (PDT)
X-Received: by 2002:a9d:5508:: with SMTP id l8mr3422469oth.233.1616593674497;
 Wed, 24 Mar 2021 06:47:54 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
In-Reply-To: <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Mar 2021 14:47:43 +0100
Message-ID: <CANpmjNOXheY0e96uVAFL3YAB9OztyBs1Uh6Bg18-dPHKc=ehHQ@mail.gmail.com>
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on SIGTRAP
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NQINk5lc;       spf=pass
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

On Wed, 24 Mar 2021 at 14:21, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Mar 24, 2021 at 02:01:56PM +0100, Peter Zijlstra wrote:
> > On Wed, Mar 24, 2021 at 01:53:48PM +0100, Peter Zijlstra wrote:
> > > On Wed, Mar 24, 2021 at 12:24:59PM +0100, Marco Elver wrote:
> > > > Encode information from breakpoint attributes into siginfo_t, which
> > > > helps disambiguate which breakpoint fired.
> > > >
> > > > Note, providing the event fd may be unreliable, since the event may have
> > > > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > > > triggering and the signal being delivered to user space.
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > > v2:
> > > > * Add comment about si_perf==0.
> > > > ---
> > > >  kernel/events/core.c | 16 ++++++++++++++++
> > > >  1 file changed, 16 insertions(+)
> > > >
> > > > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > > > index 1e4c949bf75f..0316d39e8c8f 100644
> > > > --- a/kernel/events/core.c
> > > > +++ b/kernel/events/core.c
> > > > @@ -6399,6 +6399,22 @@ static void perf_sigtrap(struct perf_event *event)
> > > >   info.si_signo = SIGTRAP;
> > > >   info.si_code = TRAP_PERF;
> > > >   info.si_errno = event->attr.type;
> > > > +
> > > > + switch (event->attr.type) {
> > > > + case PERF_TYPE_BREAKPOINT:
> > > > +         info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > > > +         info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> > >
> > > Ahh, here's the si_perf user. I wasn't really clear to me what was
> > > supposed to be in that field at patch #5 where it was introduced.
> > >
> > > Would it perhaps make sense to put the user address of struct
> > > perf_event_attr in there instead? (Obviously we'd have to carry it from
> > > the syscall to here, but it might be more useful than a random encoding
> > > of some bits therefrom).
> > >
> > > Then we can also clearly document that's in that field, and it might be
> > > more useful for possible other uses.
> >
> > Something like so...
>
> Ok possibly something like so, which also gets the data address right
> for more cases.

It'd be nice if this could work. Though I think there's an inherent
problem (same as with fd) with trying to pass a reference back to the
user, while the user can concurrently modify that reference.

Let's assume that user space creates new copies of perf_event_attr for
every version they want, there's still a race where the user modifies
an event, and concurrently in another thread a signal arrives. I
currently don't see a way to determine when it's safe to free a
perf_event_attr or reuse, without there still being a chance that a
signal arrives due to some old perf_event_attr. And for our usecase,
we really need to know a precise subset out of attr that triggered the
event.

So the safest thing I can see is to stash a copy of the relevant
information in siginfo, which is how we ended up with encoding bits
from perf_event_attr into si_perf.

One way around this I could see is that we know that there's a limited
number of combinations of attrs, and the user just creates an instance
for every version they want (and hope it doesn't exceed some large
number). Of course, for breakpoints, we have bp_addr, but let's assume
that si_addr has the right version, so we won't need to access
perf_event_attr::bp_addr.

But given the additional complexities, I'm not sure it's worth it. Is
there a way to solve the modify-signal-race problem in a nicer way?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOXheY0e96uVAFL3YAB9OztyBs1Uh6Bg18-dPHKc%3DehHQ%40mail.gmail.com.

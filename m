Return-Path: <kasan-dev+bncBCMIZB7QWENRB5ER5WBAMGQE7NNGLRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A05E9347A5E
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 15:13:09 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id g9sf1708768ilq.23
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 07:13:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616595188; cv=pass;
        d=google.com; s=arc-20160816;
        b=za+4rm4eXrNrsqijO39Unb4tm8QtcHcDdCWdkKgYhT4ivlea2gFAw2vwhwGACmo47M
         5/7+1NR8MTovgX2V7RS7/HwSWVLUfuN29MYe40ovAQ+0ZfZzD3x2szwzbuFgk/C3bqRh
         QJQuCqi4+lKvvsH1l8N1SmKuhsynRxGc6RClCQujcj09xfW6yFkMYe5hRWzrqFPZSsP+
         vXWsb1jNVQbRjDyf7k+pkn+924bLxua0tAUGSGykGz+BROJiKt17ZrwaJTvu57pPJeC3
         8j/HvWRsHGnL8ibbAfM+8iJ4uG6PbCRizBy/afbWgNXM6big/GOeMpN6Msg/i1piDcW+
         4UtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZRHOLUoHjxnwBtARRiwYc3FPwE0eHTsGeunMEGnk5SA=;
        b=SynTkYpfBLDdH0tnAvvR+aXFAQ4P5tVhwiRj9iifmh33ouaBcU5XSG+ykj18CL1tpz
         FkoBkQh20psu2FOY0mPu3LjmOeC+KN1MxGtzomrssDvhYuVPDNWQSBX8CpNjOV662LQz
         6BnkPdQdtpEt7yvsLDdqABl0n+hCQ4ORXXA7FJPQymBF5TzxyPeU55d4BiMPcDOodz2/
         YVP8j4VuaKctBt0yHYhA1GFujLvkJ8TzoxExhMXKJR6afzop+TimbKbXu0ZKeIgqBobM
         4eRpFgrbjICbx6CNusD8RFiUnf/ebk7L94JBMMvbH+hfsgXUxy49367UEHGM8LKehpMd
         hZiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AuieUtcn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRHOLUoHjxnwBtARRiwYc3FPwE0eHTsGeunMEGnk5SA=;
        b=nHHRnV5damdJPYiWL0TAPzUSh5fQES2JGyUMTZiQcn54yVCqUhv89geKTBflv7bMfh
         HTMLfaVfGgKX7ll/LhxVV88ObFrZv0Ef2UfYtGooFJWgz5sc9sORyQ+QtWhMx0ydRTA1
         l1W+xyKg26BRJUT18k+scSCv61G6JAgTwHHWaNJ63pRGDed3tTBXO3Q74PEd7be5mS6L
         PnzRUAjWJbT4hOZKVpoyIKxmN2rvixVDMRgdHLjTC1vPR21uKJzkd/c7HGjpez+rX//P
         9wI6vf2d+ZDC/SzBMUU5/Lxr4xMLtvOyOa1Wd7ZMqFhjSajipE96hBf/xMuU4C0yOiO6
         McvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRHOLUoHjxnwBtARRiwYc3FPwE0eHTsGeunMEGnk5SA=;
        b=OZ3EJYjPiIcotPzHDkpC3hGhMjPtQEhqgYigdTqMk/lfJn8VwmKSGf59r7OcTal0PX
         8n6T0R5wsZSw/GbyoSyBsoWSfFFJcG5xASII7polsmAGuwt8lcc80Omet2S/FEILS72/
         FQ+Wys7EdRaRaaET8xdSMMLhFR8vG7WTxtR4CvAqZ7amvTzj/Xk8KseZEeUUy9ht1fe0
         90YJoizLD6qkI7u5WyYrS/u5cuV+Z15QPlRe8kD1TGrLkt3Vb599NCVOpzQRUtmm3+D3
         QM5XhI9h+hQO5z51L+Fu0J9/ZP9aDKVb/ukqpoCDmMfap/UAhKPSfwzr9zdFPXLzTdWv
         jItw==
X-Gm-Message-State: AOAM532nG/yvb8rCjeMrcMN2GcBXhnfxBlj7Vaz1uXP0DA285W6XFldc
	GM82cn8zaUVGivrzbyYcXYU=
X-Google-Smtp-Source: ABdhPJywmHzdA6zbVmQzj8SOIBIXKCUryp9TYd93OH8Gu51QSRLMZ41z2djRTlgOdCkNaFXQyN1ORw==
X-Received: by 2002:a5e:840a:: with SMTP id h10mr2660768ioj.206.1616595188674;
        Wed, 24 Mar 2021 07:13:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c6a2:: with SMTP id o2ls307885jan.6.gmail; Wed, 24 Mar
 2021 07:13:08 -0700 (PDT)
X-Received: by 2002:a05:6638:3049:: with SMTP id u9mr3043542jak.57.1616595188346;
        Wed, 24 Mar 2021 07:13:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616595188; cv=none;
        d=google.com; s=arc-20160816;
        b=mqPcUnNV7Z2bAEPlnRNmMYT8/ajoOGnz/sxXSMDjU4QuJlR/gp2e+DhXwgBJFaAwdg
         XrC8DbUkVJ5COUG2FNZX+hvGJXgC9LqPYeD0lMbabP6CNj6mgm96yyOyt2TtGjQN6/I2
         ZAfDt06+Rl1cBZjsix4axL4MeNOY41RGXuJuZmD0kmz6CmJxOfKwF3Ma6t/IdU02IAUR
         wr2Xe86fahc5mO2Swrca7W8H+fT+51E7FSAjlxFYXEBl6dkc0dtVAYc+Ibu/8H9qEv1s
         Ve36nJywwMv+FiV4pmsR16pG0b0ABCCOliQt3r0NpxfiXHzISCyQLVbCK7pqoUw5d+PU
         uWHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1XohPHX9rWTqjJvRyYcCWXA2q1vwA5OihINXfd2z/zo=;
        b=xTkoKyrmVpzhw4d1fJo34qIHlXUo9j++k4ArFqeL/CF0lbx+1dobhfkVd1HKy9vkSf
         xRmORrE31ozO3H6No4KtX6hDDDyRQ3IsHQeE6w+N/ZmYG9+70vouRR26lukXGbYLuIN2
         Xmr+f4EFyV4UpI+A0Bzsamoqgy+egwSPJQkqw3ynQhR7ONlzS4Ibn0hLy3yi/PsHH749
         Tp4xAgmvUK5AATJgVsmGkfnuUmYk0W+VbgLz0G8K87olO5ttqULURjhpkGyArVj/9QUd
         8ZBFeEhSZbr+cNNZz2l99FBPgU2hycfOJ+w9ILGlyA6ou6lgUCA7U1FejF10DyGKevXj
         fT7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AuieUtcn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id y8si149556iom.1.2021.03.24.07.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 07:13:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id i19so2080324qtv.7
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 07:13:08 -0700 (PDT)
X-Received: by 2002:ac8:6696:: with SMTP id d22mr3164170qtp.67.1616595187453;
 Wed, 24 Mar 2021 07:13:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net> <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net> <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
In-Reply-To: <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Mar 2021 15:12:56 +0100
Message-ID: <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on SIGTRAP
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AuieUtcn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Mar 24, 2021 at 3:05 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 24 Mar 2021 at 15:01, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > One last try, I'll leave it alone now, I promise :-)
>
> This looks like it does what you suggested, thanks! :-)
>
> I'll still need to think about it, because of the potential problem
> with modify-signal-races and what the user's synchronization story
> would look like then.

I agree that this looks inherently racy. The attr can't be allocated
on stack, user synchronization may be tricky and expensive. The API
may provoke bugs and some users may not even realize the race problem.

One potential alternative is use of an opaque u64 context (if we could
shove it into the attr). A user can pass a pointer to the attr in
there (makes it equivalent to this proposal), or bit-pack size/type
(as we want), pass some sequence number or whatever.



> > --- a/include/linux/perf_event.h
> > +++ b/include/linux/perf_event.h
> > @@ -778,6 +778,9 @@ struct perf_event {
> >         void *security;
> >  #endif
> >         struct list_head                sb_list;
> > +
> > +       unsigned long                   si_uattr;
> > +       unsigned long                   si_data;
> >  #endif /* CONFIG_PERF_EVENTS */
> >  };
> >
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -5652,13 +5652,17 @@ static long _perf_ioctl(struct perf_even
> >                 return perf_event_query_prog_array(event, (void __user *)arg);
> >
> >         case PERF_EVENT_IOC_MODIFY_ATTRIBUTES: {
> > +               struct perf_event_attr __user *uattr;
> >                 struct perf_event_attr new_attr;
> > -               int err = perf_copy_attr((struct perf_event_attr __user *)arg,
> > -                                        &new_attr);
> > +               int err;
> >
> > +               uattr = (struct perf_event_attr __user *)arg;
> > +               err = perf_copy_attr(uattr, &new_attr);
> >                 if (err)
> >                         return err;
> >
> > +               event->si_uattr = (unsigned long)uattr;
> > +
> >                 return perf_event_modify_attr(event,  &new_attr);
> >         }
> >         default:
> > @@ -6399,7 +6403,12 @@ static void perf_sigtrap(struct perf_eve
> >         clear_siginfo(&info);
> >         info.si_signo = SIGTRAP;
> >         info.si_code = TRAP_PERF;
> > -       info.si_errno = event->attr.type;
> > +       info.si_addr = (void *)event->si_data;
> > +
> > +       info.si_perf = event->si_uattr;
> > +       if (event->parent)
> > +               info.si_perf = event->parent->si_uattr;
> > +
> >         force_sig_info(&info);
> >  }
> >
> > @@ -6414,8 +6423,8 @@ static void perf_pending_event_disable(s
> >                 WRITE_ONCE(event->pending_disable, -1);
> >
> >                 if (event->attr.sigtrap) {
> > -                       atomic_set(&event->event_limit, 1); /* rearm event */
> >                         perf_sigtrap(event);
> > +                       atomic_set_release(&event->event_limit, 1); /* rearm event */
> >                         return;
> >                 }
> >
> > @@ -9121,6 +9130,7 @@ static int __perf_event_overflow(struct
> >         if (events && atomic_dec_and_test(&event->event_limit)) {
> >                 ret = 1;
> >                 event->pending_kill = POLL_HUP;
> > +               event->si_data = data->addr;
> >
> >                 perf_event_disable_inatomic(event);
> >         }
> > @@ -12011,6 +12021,8 @@ SYSCALL_DEFINE5(perf_event_open,
> >                 goto err_task;
> >         }
> >
> > +       event->si_uattr = (unsigned long)attr_uptr;
> > +
> >         if (is_sampling_event(event)) {
> >                 if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
> >                         err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaKmdsXhRZi2f3LsX3m%3DkrdY4kPsEUcieSugO2wY%3DxA-Q%40mail.gmail.com.

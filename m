Return-Path: <kasan-dev+bncBDTIRYVLZUEBBOHK6WDAMGQEOAWAFRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 047263B8E6F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 09:56:42 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id k13-20020a9f30cd0000b029025e3e26edb8sf1385022uab.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jul 2021 00:56:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625126201; cv=pass;
        d=google.com; s=arc-20160816;
        b=RNcrOVKQ2DAx5BHAFGZ70T0bY05q/LaRpMVtBeaIrOHZF1g2JMcbbRP8ojmOkizwOY
         aTrS9FPSZ+nYmwLivLvO6vfZc30QcSLit6vz8LOPLF8ldZfRQBi1ss7wQp82b5L3FJl3
         BmejofhqojU+igPU4UKvAcvVxD4OMB0dQz4lo6wSs1ZUwRTnzj/sUmFuX/oLCvSjIMKi
         A3QCd1HKYJeQbW07id3uiORKy795fMbF01r/3NHMG0zk6d4I+jByObm2YA76lQNY7hCK
         /ugg7wA1a70i/txF6qCdB1U59/tpZlvTBtR9xoiuJS++1lWpfp5WMt/zNSImaO6Ba5gb
         CfkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=upEh/jlIC/phF6ZOR6TN7if2yOCd8WsotljgnkY7me8=;
        b=TUg0UAgWhg7zsqPqTzfKzZ9GqaSqGEfE7/XyZXocqFy20sL4kw/J24RzE1+uLAWWRd
         SxVL5gZWOejPIw8SXN9NvgUZJLbK8uflUzGS2dCqryC1Ctqzr5GPBpOKOAHc8HfxaJ+A
         dOE9PjpMM+aYDKDNF3Myzh2UAvVzn4P3P/+WbeosNP8bGzTCZo8KXQEBDgkZfVUPIvhn
         7yb1HvZxtfV4NquY33ishUyaPpALmMpmIGC5ZihA4Fpyc3y0Pv5JhPgsEHu10jMy+8+x
         AqOcudPXkDbj5H5MVXIttMuOxxiP9JNasIq+O1c0zQIwJxiWExYH45I8gWjdE9Q1P6se
         ftCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Ry3iiT/b";
       spf=pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=upEh/jlIC/phF6ZOR6TN7if2yOCd8WsotljgnkY7me8=;
        b=jn+NowEAaguHZmOFrTQaiolsABMwj6eaTDaGcAzW5DeQbn1VLFTsbjn9vr0Lf7w6OP
         xQWvZKh3uH5hdq3l+X5Mr+pzmGTthN3pF4Xqds934nQGkaaPpn22g3un1c/s7eDeTW+5
         m0GKkHaApYZkDWzWZiC6anrxR3sDdU/g7oNE6czhTbPPCOukxPidNZkgxQsRwNBySPiN
         q8kry+ijlOy9D/f8qrgVZIhwAVnztmEPeii/LX2Xh2diC+PXtcnWT+Nt1BpP2i6emK1p
         tyQuM38IK/w8mXW4aTzo6dgBhjcCnO78RW5hNWfd9svGIIIgVrXtHNVyH5LL9Zut9G+m
         Hm+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=upEh/jlIC/phF6ZOR6TN7if2yOCd8WsotljgnkY7me8=;
        b=aS6quEFI1rQaUT/dTWXGktg92taUeRw0n0nzQBu/+4Zu6RmrTHUCCVKoPRdjFzK4ws
         TNy7Sps9SO8UFR7V4rvrQzx22daiQ2bky4EVZhp0Jgn0bkYRWY8IqNMT27QADqfM/Kzc
         jKNRp5/hC2YhTB+lPu1lYDv2ek+GCFIVqL0rjsw4NFGd/TExj0R2280Rd5FL0TGvUcew
         r7OQbIqwFMuK/XI1uRuCg7M8fH4Tsh2yiYj8g+lwbeQ3lH14k1ETMj5gPl4L174sr6Zx
         W5dLW/6Xv3/o5Upow6+O8FYWa4V4q3Oy2d9xo8oR8iCFidvyUkzVJC7vb7TDpcQNsfa1
         6U0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DnFH5vAPtXv6Dm4K0KuNVlX3NOhltO2DpTc1+CcvgKHBGh1sm
	RXO+21dFpFnsn7k1AWSHnIQ=
X-Google-Smtp-Source: ABdhPJyXWlhRmVK3sLuKc3xn5pgLYmaap4v3beIyJ0LfpeMsgW4FdZpz+Q7e32ROK1kJSXoCOylDoA==
X-Received: by 2002:a67:ec97:: with SMTP id h23mr3527684vsp.41.1625126200910;
        Thu, 01 Jul 2021 00:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:48c2:: with SMTP id v185ls622827vka.11.gmail; Thu, 01
 Jul 2021 00:56:39 -0700 (PDT)
X-Received: by 2002:a1f:7c05:: with SMTP id x5mr31919222vkc.17.1625126198953;
        Thu, 01 Jul 2021 00:56:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625126198; cv=none;
        d=google.com; s=arc-20160816;
        b=AeE6D3teMmYicoS+BICc1jkPgIoNHibwrmkzO677EJZ+RmoxrIshiIbYnStUwffM7B
         Q2Slcc3pJuVgBBH8xh78ytTIlcsPe1oW9dJGTquG0DgfDQbVnZw3MAAOunHoDX68k8kD
         Cc8e/LZUuznIP1s5+ng0Vi5e5zFVRy1DQvRADWUx/YB9iL3jDrCVTYLALvwpRM22COmP
         LhF2JdPABJ4WGSn8MbN5w6IVsNyzqGsSBpHfcq6MqXYn8a6ieJ4szow1duw8Btf4RVl1
         x58PZGU352jcLQV2GCd30dgNRKShBk8mFbONmN8j8EN1Z+6gRrLfjaZnaISrWaRwW2Qz
         uJCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y9jC4b7qIauKiDKeodtcEhNEX/AsDIdv8KzKy1Dzuxw=;
        b=pH2avuGeDidFgQ9wTzkbR7mrZWRjfCs/G0ST8rw0cXItkv8rH3pPWjnnLRaOIj09Jd
         Wr2Nkpw/kgbpHoa1+SYp06dRfw9onXQy0HdcFssN7AjgVyjaKHLhBVzjfeUxcDeW6sUb
         P3KwT4guQRW7BXLfuETh9GuUm2igLUMg6//ZJ3kGTO2Wlsgm0YgWPcVAinPe1Os6gKWh
         G2f+41F/xuprL3abLf+t/5+AWb7P9BIBvV4I+Jzg0kFK2NZNc3yAjkCvxvbBoCcoYoek
         SRPaICPZGr7YaqcmWCOOVldUriNpKNy5ySPl/UvdCcXlCScS45JyvPTi7QWmCgMQNllm
         AYEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Ry3iiT/b";
       spf=pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a6si1935208vkm.1.2021.07.01.00.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Jul 2021 00:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yb1-f197.google.com (mail-yb1-f197.google.com
 [209.85.219.197]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-268-zPYfx0LpN4ObLsmYGTCKaQ-1; Thu, 01 Jul 2021 03:56:36 -0400
X-MC-Unique: zPYfx0LpN4ObLsmYGTCKaQ-1
Received: by mail-yb1-f197.google.com with SMTP id p10-20020a056902114ab0290559cc105fe3so5331045ybu.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Jul 2021 00:56:36 -0700 (PDT)
X-Received: by 2002:a25:25cd:: with SMTP id l196mr30064768ybl.226.1625126195761;
        Thu, 01 Jul 2021 00:56:35 -0700 (PDT)
X-Received: by 2002:a25:25cd:: with SMTP id l196mr30064748ybl.226.1625126195525;
 Thu, 01 Jul 2021 00:56:35 -0700 (PDT)
MIME-Version: 1.0
References: <20210630093709.3612997-1-elver@google.com> <CAFqZXNtaHyKjcOmh4_5AUfm0mek6Zx0V1TvN8BwHNK9Q7T3D8w@mail.gmail.com>
 <YNxmyRYcs/R/8zry@elver.google.com>
In-Reply-To: <YNxmyRYcs/R/8zry@elver.google.com>
From: Ondrej Mosnacek <omosnace@redhat.com>
Date: Thu, 1 Jul 2021 09:56:24 +0200
Message-ID: <CAFqZXNsABvdcR4MPYS+o+SEpqtaU1FrUkmP8bv+1czvcv_3ADQ@mail.gmail.com>
Subject: Re: [PATCH] perf: Require CAP_KILL if sigtrap is requested
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@kernel.org>, kasan-dev@googlegroups.com, 
	Linux kernel mailing list <linux-kernel@vger.kernel.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, 
	Linux Security Module list <linux-security-module@vger.kernel.org>, linux-perf-users@vger.kernel.org, 
	Eric Biederman <ebiederm@xmission.com>, Dmitry Vyukov <dvyukov@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: omosnace@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="Ry3iiT/b";
       spf=pass (google.com: domain of omosnace@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Jun 30, 2021 at 2:43 PM Marco Elver <elver@google.com> wrote:
> On Wed, Jun 30, 2021 at 01:13PM +0200, Ondrej Mosnacek wrote:
> > On Wed, Jun 30, 2021 at 11:38 AM Marco Elver <elver@google.com> wrote:
> [...]
> > > +static inline bool kill_capable(void)
> > > +{
> > > +       return capable(CAP_KILL) || capable(CAP_SYS_ADMIN);
> >
> > Is it really necessary to fall back to CAP_SYS_ADMIN here? CAP_PERFMON
> > and CAP_BPF have been split off from CAP_SYS_ADMIN recently, so they
> > have it for backwards compatibility. You are adding a new restriction
> > for a very specific action, so I don't think the fallback is needed.
>
> That means someone having CAP_SYS_ADMIN, but not CAP_KILL, can't perform
> the desired action. Is this what you'd like?

AFAIK, such user wouldn't be allowed to directly send a signal to a
different process either. So I think it makes more sense to be
consistent with the existing/main CAP_KILL usage rather than with the
CAP_PERFMON usage (which has its own reason to have that fallback).

I'm not the authority on capabilities nor the perf subsystem, it just
didn't seem quite right to me so I wanted to raise the concern.
Hopefully someone wiser than me will speak up if I talk nonsense :)

> If so, I'll just remove the wrapper, and call capable(CAP_KILL)
> directly.
>
> > > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > > index fe88d6eea3c2..1ab4bc867531 100644
> > > --- a/kernel/events/core.c
> > > +++ b/kernel/events/core.c
> > > @@ -12152,10 +12152,21 @@ SYSCALL_DEFINE5(perf_event_open,
> > >         }
> > >
> > >         if (task) {
> > > +               bool is_capable;
> > > +
> > >                 err = down_read_interruptible(&task->signal->exec_update_lock);
> > >                 if (err)
> > >                         goto err_file;
> > >
> > > +               is_capable = perfmon_capable();
> > > +               if (attr.sigtrap) {
> > > +                       /*
> > > +                        * perf_event_attr::sigtrap sends signals to the other
> > > +                        * task. Require the current task to have CAP_KILL.
> > > +                        */
> > > +                       is_capable &= kill_capable();
> >
> > Is it necessary to do all this dance just to call perfmon_capable()
> > first? Couldn't this be simply:
> >
> > err = -EPERM;
> > if (attr.sigtrap && !capable(CAP_KILL))
> >         goto err_cred;
>
> Not so much about perfmon_capable() but about the ptrace_may_access()
> check. The condition here is supposed to be:
>
>         want CAP_PERFMON and (CAP_KILL if sigtrap)
>                 OR
>         want ptrace access (which includes a check for same thread-group and uid)
>
> If we did what you propose, then the ptrace check is effectively ignored
> if attr.sigtrap, and that's not what we want.
>
> There are lots of other ways of writing the same thing, but it should
> also remain readable and sticking it all into the same condition is not
> readable.

Ah, I see, I missed that semantic difference... So ptrace_may_access()
implies that the process doesn't need CAP_KILL to send a signal to the
task, that makes sense.

In that case I'm fine with this part as it is.

> > Also, looking at kill_ok_by_cred() in kernel/signal.c, would it
> > perhaps be more appropriate to do
> > ns_capable(__task_cred(task)->user_ns, CAP_KILL) instead? (There might
> > also need to be some careful locking around getting the target task's
> > creds - I'm not sure...)
>
> That might make sense. AFAIK, the locking is already in place via
> exec_update_lock. Let me investigate.
>
> > > +               }
> > > +
> > >                 /*
> > >                  * Preserve ptrace permission check for backwards compatibility.
> > >                  *
> > > @@ -12165,7 +12176,7 @@ SYSCALL_DEFINE5(perf_event_open,
> > >                  * perf_event_exit_task() that could imply).
> > >                  */
> > >                 err = -EACCES;
> >
> > BTW, shouldn't this (and several other such cases in this file...)
> > actually be EPERM, as is the norm for capability checks?
>
> I'm not a perf maintainer, so I can't give you a definitive answer.
> But, this would change the ABI, so I don't think it's realistic to
> request this change at this point unfortunately.

Indeed... I worry it will make troubleshooting SELinux/capability
errors more confusing, but I agree it would be a potentially risky
change to fix it :/

--
Ondrej Mosnacek
Software Engineer, Linux Security - SELinux kernel
Red Hat, Inc.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFqZXNsABvdcR4MPYS%2Bo%2BSEpqtaU1FrUkmP8bv%2B1czvcv_3ADQ%40mail.gmail.com.

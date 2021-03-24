Return-Path: <kasan-dev+bncBCMIZB7QWENRB74S5WBAMGQEGI7SNWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 04454347A65
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 15:15:29 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id k7sf205282vka.7
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 07:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616595328; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdO886nySMDPDIwkDtD5PMUTxfd3dcv/Qmu79qFe6doR8KK5Zt2jaXuipYakAajryf
         nJtf/sLmRIe8/mLE2oO+XjXNs2mqtWYH4zR5rfnbYeZ4Kp/6A0gIYy3g9zEE2ZuczcOD
         1QOytM7zk+9HIPPDlY5pplUywbRln27S93utaaQSCbA4btca/XlaHH9qy3rENL7Vx5OZ
         eXtHbt7mNan0QAJH9XnMldFVOh1j3Gz3QZy+qWPxmr4+ha2oW+epo/wCSlloqMSUHFCa
         tziQXBdP1/wz9MtYrlRfmsdsRMbCzDpdgeI0+JIhBRm18peNPud2UtfY9TcXHy6zemXE
         R4Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AM3CD0A4l4JyU/HhsluQfRzyHOb2yBeMW2md6km6UAg=;
        b=udeZTFlR8s4NRyfkqXeyzRHthjkmB1Qt31od7SWWtgUwCwt3sQMQmJDoyCtBAtJ0W4
         vTrWbghmaRiFiIBj3iNI69FpvIoFR28+POK/5z2Env3q8EuBnowhZ2XbbxXCLo0rE/Ua
         2GMjsiKoANa9RyS6wiJsTI+9eKy5GtLiv7u7DcfNUPFUWy8aAu7eDIgVb77PVGyAF4yB
         XDfJ7cjiO+WZoKlm+zAAMzkqDHzKK+JvAFspF0YTbKLo9IUg/Grx5Ad7UhAKbYiBeZ84
         YFHhBg9/29Fmr2gk+DL8Y3ScPqobekBlHQHe/snrdE3esU//mqIlTxFKh9QqnMKlYVKy
         faCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qR67sYL0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AM3CD0A4l4JyU/HhsluQfRzyHOb2yBeMW2md6km6UAg=;
        b=rwRy9nA+ATDh2qld9mF1h9KfAJHiocKjUf4u8NFDy7r+UhlTh7eHNJqnydF54QItHO
         BZ1eswfyaEzaHpaioNiBDm+zg5yqePgFe1GewpgXRcndxghccmpnR9YLArEtZFWKkDhW
         2OtGn96sN+bR4OpJ9x7FZILFkWUtbBBG6q6KTJXL/pGaKFzvS6w5Jo6+xyNqH0xv7Lvf
         V4Yz/hqiHx9enniwbLVXQ5DX1QVN9sitJV0Qs+tLVduamXDwSSNWv6IsjTx2OBlB/ht9
         7uFq4uDrEt8YxBwgqCsRC19/0Cd5l/D2d8Mfxu+zX//3iO6faLDjNMNiG9UXuGhVH0Iy
         MQoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AM3CD0A4l4JyU/HhsluQfRzyHOb2yBeMW2md6km6UAg=;
        b=TchgK2FErnNkYWrOVVngVMpVb6Q9ESYbxUk/KFOTBWx8D2UXA9LVhsl+sdGaotTwFk
         9K3AdGxINy9RFlad5gOBaK7+KsdekkyiLpX4k8hQDT2Xx0AufptWH5pJvIS83aiuAcWb
         zRo9UKju3ydzERKgq+qBQoQdOoW6ht733lCvyrUPcLi43GzERoIMkUUfTOCvciaQ9nAs
         7wIuFTQEiMultIOpgCDGnh74nE26lw1WwPB6m6po+fLOXBgRb7YBLtnSbITQTF51d2v6
         z95PX4Eoe7/lBdUYu5aWFMisHYcs+797Ix3HYfShiHrQVJIGVLawirc8MYyPX7tKxjkw
         6rhQ==
X-Gm-Message-State: AOAM533i/LkHjE9QEBXFA90SYcu/ZmpR7yjy0kZgMAazNpLYyQOIsaz4
	ozJiBBxso1rgoSbdS88fTPs=
X-Google-Smtp-Source: ABdhPJzQEghG1yoqCmZIOru1e1qyma65+8qRZpclgEbEasfhuHAWtiY2VAeeAGwZaD373jJbqLlfhw==
X-Received: by 2002:a67:ff91:: with SMTP id v17mr1915229vsq.38.1616595327621;
        Wed, 24 Mar 2021 07:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a290:: with SMTP id l138ls126033vke.8.gmail; Wed, 24 Mar
 2021 07:15:27 -0700 (PDT)
X-Received: by 2002:a1f:aa43:: with SMTP id t64mr1883937vke.22.1616595326578;
        Wed, 24 Mar 2021 07:15:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616595326; cv=none;
        d=google.com; s=arc-20160816;
        b=YoulNmC28yUqYqRgt/t18JiMhlRIxbBavqaBdN/TetTbNpIB7HaA3FIcOWcUsL1jbn
         RcbGLC9iMm3R/LvNXKROc0I6jJAKiUA42UQhSDv6E/9fWqI9ac9691GdxjL9HPOmLM91
         OX53bLKacIuHG2ijfmztUMGS7Xc1KNfMADLyFzLQNwCTedMGgWTIq9NEUXWWMhwsPFOw
         3pJSoIzo27cr54ohJ0zk+0FeaKMpkeIQNaTLInsD3tPjwsL//OoG/HgjFRTWl58Eidwu
         mE2/g8tNpLOWdK/OyqXmYHikHh5zvOjCVv13Ww5/0rHalCtMuy8IP+Rp+dfmtIM9ptZq
         zHsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GZvbm9pmWdatUwvODu4QKBbBncw4Nm+3D4c7UW8iDYU=;
        b=xzK9d0IQfSH6k4i++tQx2s4ePMr0WhsB2IgOv5WD4XwCuLxPVbTa0L3ZzZSr2FKa4Q
         mKhIoTmy8JGeRGyOs/lcrHYLHVIQFPQbjV5Qtgpo55CWOmbR/E03L20KJynbq0R3KVmY
         4iz59YY2hTdE0Hc1+SCMLHB3ffGkKL/Kw8NepvXZV7h/m1i4Yw0cso1NNDkgXDVXkFm9
         i55642Cj8TDfHAKMkQZ7Jb7soQe6jY6kJmTPnqAfhsICSqHbt/9r/UkMusmWTEZF8/ZM
         acFk+PAsNlEMKwKq6NAoxsS5PP1tGedMtSNn5We749E2uIckXBWCZEGLm9xTvQQGF5/L
         6syw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qR67sYL0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id i2si83429vkc.0.2021.03.24.07.15.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 07:15:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id q9so12315160qvm.6
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 07:15:26 -0700 (PDT)
X-Received: by 2002:ad4:50d0:: with SMTP id e16mr3524290qvq.37.1616595325859;
 Wed, 24 Mar 2021 07:15:25 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net> <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net> <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
 <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
In-Reply-To: <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Mar 2021 15:15:14 +0100
Message-ID: <CACT4Y+aRaNSaeWRA2H_q3k9+OpG0Lc3V7JWU8+whZ9s3gob-Kw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=qR67sYL0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d
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

On Wed, Mar 24, 2021 at 3:12 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Wed, 24 Mar 2021 at 15:01, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > One last try, I'll leave it alone now, I promise :-)
> >
> > This looks like it does what you suggested, thanks! :-)
> >
> > I'll still need to think about it, because of the potential problem
> > with modify-signal-races and what the user's synchronization story
> > would look like then.
>
> I agree that this looks inherently racy. The attr can't be allocated
> on stack, user synchronization may be tricky and expensive. The API
> may provoke bugs and some users may not even realize the race problem.
>
> One potential alternative is use of an opaque u64 context (if we could
> shove it into the attr). A user can pass a pointer to the attr in
> there (makes it equivalent to this proposal), or bit-pack size/type
> (as we want), pass some sequence number or whatever.

Just to clarify what I was thinking about, but did not really state:
perf_event_attr_t includes u64 ctx, and we return it back to the user
in siginfo_t. Kernel does not treat it in any way. This is a pretty
common API pattern in general.


> > > --- a/include/linux/perf_event.h
> > > +++ b/include/linux/perf_event.h
> > > @@ -778,6 +778,9 @@ struct perf_event {
> > >         void *security;
> > >  #endif
> > >         struct list_head                sb_list;
> > > +
> > > +       unsigned long                   si_uattr;
> > > +       unsigned long                   si_data;
> > >  #endif /* CONFIG_PERF_EVENTS */
> > >  };
> > >
> > > --- a/kernel/events/core.c
> > > +++ b/kernel/events/core.c
> > > @@ -5652,13 +5652,17 @@ static long _perf_ioctl(struct perf_even
> > >                 return perf_event_query_prog_array(event, (void __user *)arg);
> > >
> > >         case PERF_EVENT_IOC_MODIFY_ATTRIBUTES: {
> > > +               struct perf_event_attr __user *uattr;
> > >                 struct perf_event_attr new_attr;
> > > -               int err = perf_copy_attr((struct perf_event_attr __user *)arg,
> > > -                                        &new_attr);
> > > +               int err;
> > >
> > > +               uattr = (struct perf_event_attr __user *)arg;
> > > +               err = perf_copy_attr(uattr, &new_attr);
> > >                 if (err)
> > >                         return err;
> > >
> > > +               event->si_uattr = (unsigned long)uattr;
> > > +
> > >                 return perf_event_modify_attr(event,  &new_attr);
> > >         }
> > >         default:
> > > @@ -6399,7 +6403,12 @@ static void perf_sigtrap(struct perf_eve
> > >         clear_siginfo(&info);
> > >         info.si_signo = SIGTRAP;
> > >         info.si_code = TRAP_PERF;
> > > -       info.si_errno = event->attr.type;
> > > +       info.si_addr = (void *)event->si_data;
> > > +
> > > +       info.si_perf = event->si_uattr;
> > > +       if (event->parent)
> > > +               info.si_perf = event->parent->si_uattr;
> > > +
> > >         force_sig_info(&info);
> > >  }
> > >
> > > @@ -6414,8 +6423,8 @@ static void perf_pending_event_disable(s
> > >                 WRITE_ONCE(event->pending_disable, -1);
> > >
> > >                 if (event->attr.sigtrap) {
> > > -                       atomic_set(&event->event_limit, 1); /* rearm event */
> > >                         perf_sigtrap(event);
> > > +                       atomic_set_release(&event->event_limit, 1); /* rearm event */
> > >                         return;
> > >                 }
> > >
> > > @@ -9121,6 +9130,7 @@ static int __perf_event_overflow(struct
> > >         if (events && atomic_dec_and_test(&event->event_limit)) {
> > >                 ret = 1;
> > >                 event->pending_kill = POLL_HUP;
> > > +               event->si_data = data->addr;
> > >
> > >                 perf_event_disable_inatomic(event);
> > >         }
> > > @@ -12011,6 +12021,8 @@ SYSCALL_DEFINE5(perf_event_open,
> > >                 goto err_task;
> > >         }
> > >
> > > +       event->si_uattr = (unsigned long)attr_uptr;
> > > +
> > >         if (is_sampling_event(event)) {
> > >                 if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
> > >                         err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaRaNSaeWRA2H_q3k9%2BOpG0Lc3V7JWU8%2BwhZ9s3gob-Kw%40mail.gmail.com.

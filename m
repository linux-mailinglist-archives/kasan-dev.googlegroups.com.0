Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMO5WBAMGQEM2BUX6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 853B7347A2A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 15:05:14 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id o23sf1344964oop.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 07:05:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616594713; cv=pass;
        d=google.com; s=arc-20160816;
        b=VIBGA16ynUTGeTr7ZcC05pIb8a2JMRrEdUVt9zZ7FzwIJ8KT/EyjUHNbAD5hsvStJ0
         mvE1G6358rycg9YbE9e1Pu4rKG0kbuCDgvX2SmOlkJXYxpTgXHQevMzA+ofYLcQ0UStq
         vUDE0voIG2gK0SXGzkuvg4NZimwW7r6oQrIDGcQQAmtxsoleoayF+KKVtaTmSJWSa2ud
         dWAPP5G6HbgY7q3Xb5Vr7l7FD3op4JDZMO0T9C+M0BuPhgL8HNnS8Pj5yN64uox5UjFX
         bDRPmuS9GEf69hcY9DFYc+h10vQ/PCvxBDA5Ni+JVYcFQsbC99n1c75x8x7H5pVT/WE+
         Wg7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ogkcPEvwRNPAekCly3X3nOp7D0o18go3EdEiZfD3oEQ=;
        b=q76sqV4lRIlukhYzVbElzEghlap5ziCSfNRF8aKxXxSpg30quiovKcthkVJP/PaYxY
         lW6kt2lzz9FzZ6xOREH2mSGuQZtxdT/wSRn14GJyb4XftgP7MpiFIZLOfEJrYou2L2qw
         8fH3qn1u8r57Hf0BAyDpIPqEvvE2sX9n0vHUzdC6gDpUvAjXULCLwL0vDRMcHzYwAE95
         2ItG9hlqx/jCNQNN6jie5NqTMNmF0LS/vAOwtW3rql8t1SIDfKFqMCG+XLaeQlYTija7
         usw0ee0oXwege70NQSKwRf8AUsrB0H7at51gXq+iMivwt2gg8ubb8IOntYTF6pjod7ES
         6lUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kIHyqH8J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogkcPEvwRNPAekCly3X3nOp7D0o18go3EdEiZfD3oEQ=;
        b=cvZDJjLyDlWYKBqeFdsI71T/Irm2qZpHixli1BlYsHFFaXIaHN7JFqWE/IU/IO/cdb
         yorR9HTqX6BFibLFQ/OXcr35hqdCOZIZ9jrsuPJMhX8xzRyYUbvWO3gJpspBou1WkSqW
         p2v0G9vfC+We7+XGlMZZ2NheLOZMkExYd08ltMSPrhe5nyyOg/pp+HdJEv0wGu0OIdmH
         iKl+AFi2Cm4dDOnpPNP9NZmLdhK3ysVqXaGRmK47biRP4XjINE8OX1YZkNsMG2kMmOFL
         hwTGWjsItrtCeTVMKlVwaFG6uc7T1u6i52cfr7ZHQj0Wf+CcI37HUj2+ACdE7RAX2rGf
         T+Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogkcPEvwRNPAekCly3X3nOp7D0o18go3EdEiZfD3oEQ=;
        b=YvnyZyWJ5PGZ+Lp4T02NpgV/7cLT9w0/6RCqM3oFb/a0jjrIvZQzJqEUDiwAJFzxtv
         2C74pMlWpr3SoBiRF/EYL9Dq+yA1Mj8Ww8xfuy81o0DLVvN3JBYykEDUlAgM/BNa0941
         k0M+QQDHvvJbcL7cMwlaUPz3XpCSiEEDUxj8/KgnE5htRwi7giMWGVU/Czmo0PTtUM3Y
         zxwsL2ohCthb+aijxSkaISJd0qTqt0dOqO9PGVCMimm+wMuI+kAyeNqC4BCcJL6W28k0
         qdCLDmLxsBu6ZXE6rZzrPLxWSktr3pINKc7fPibMs8ymzHjbOnyCWEmyKhQXC7aLmXdq
         65dw==
X-Gm-Message-State: AOAM531aiKuzc2M5RAZPKQstn6+XAPPW7Qf8u4PtysbQ06s7A1wIfJOb
	VOdO4heJO82cQegeBZ4lbC4=
X-Google-Smtp-Source: ABdhPJwFg7/n2LJCxdJv4bxx6if6Ltgb+fzrJYdn9om8p8Co/PnpLZAyfssdXPaiR13ZnCD8TwlDMw==
X-Received: by 2002:aca:1c14:: with SMTP id c20mr2478878oic.146.1616594713491;
        Wed, 24 Mar 2021 07:05:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d54d:: with SMTP id m74ls561055oig.11.gmail; Wed, 24 Mar
 2021 07:05:13 -0700 (PDT)
X-Received: by 2002:a54:488b:: with SMTP id r11mr2623306oic.166.1616594713164;
        Wed, 24 Mar 2021 07:05:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616594713; cv=none;
        d=google.com; s=arc-20160816;
        b=D/yj8+xaob2WfK8EXDRNfygqumVpSkLhI7YJQWeb9LRbShhoc3dSeCioGPN2/Iprjc
         JrWPbBpezwXJdV9WI20+xdRC4MKsx03d7xbyt0m9Kg2kJiZQn412RgC2+oZsK+rgua1v
         DPhTzTQZIhoBVT16knPRYhCWRFQnP+f5tbYThoFCkSHLKvWow50jkBJBaz6r3Ddj+EYC
         tQRRcEKG3HcBucj1+8Y0Pc6bJ0RRJ1g0/wixmmInHTTqAdTOSoadN7rvEuGszsh/AODA
         ApYrZ3m+AxY/k4R8Sy6EvEjytDm+uS5vDKIr4C8NF8kXi8IB9zbRY/LEWuYjZXSMZW/q
         QREA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OfhOIdD0/JF1R4rl2yl8LbcQIZX0RUkjo+PIbGE7ciE=;
        b=okpHj64h/yrZMXydTjX1LwB+E7O0Ej4bIDyc47XmC2iBJoSLIGdun6A1IMltMlLOoC
         e6lwYB/R3MA1g4mPZ3+ATPuFrui+gAavhlGF4A6SvOPqDva1LwpI2hXx0Jsm9W+AqIqi
         8hUBNNwHhsfTid5WkwnlK98sV7v+LpyLMxRBdCshdM/kFe46p1WCjjPMySfleApikXRC
         FkVTCU+kRUD6bfSNWggZTxGYjWluc+34YoZJcmGjafs07kCdLf3LuTlRqEca2nQCshpL
         1Egtaz0maS74Zy0Zepb4PKXTP8eH/bGGqaG+RLw652oChRpU7DsPQScY2vx8PcpFjY9H
         KAag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kIHyqH8J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id w4si123713oiv.4.2021.03.24.07.05.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 07:05:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id x2so20872399oiv.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 07:05:13 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr2482806oia.172.1616594712647;
 Wed, 24 Mar 2021 07:05:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net> <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net>
In-Reply-To: <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Mar 2021 15:05:01 +0100
Message-ID: <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=kIHyqH8J;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Wed, 24 Mar 2021 at 15:01, Peter Zijlstra <peterz@infradead.org> wrote:
>
> One last try, I'll leave it alone now, I promise :-)

This looks like it does what you suggested, thanks! :-)

I'll still need to think about it, because of the potential problem
with modify-signal-races and what the user's synchronization story
would look like then.

> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -778,6 +778,9 @@ struct perf_event {
>         void *security;
>  #endif
>         struct list_head                sb_list;
> +
> +       unsigned long                   si_uattr;
> +       unsigned long                   si_data;
>  #endif /* CONFIG_PERF_EVENTS */
>  };
>
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -5652,13 +5652,17 @@ static long _perf_ioctl(struct perf_even
>                 return perf_event_query_prog_array(event, (void __user *)arg);
>
>         case PERF_EVENT_IOC_MODIFY_ATTRIBUTES: {
> +               struct perf_event_attr __user *uattr;
>                 struct perf_event_attr new_attr;
> -               int err = perf_copy_attr((struct perf_event_attr __user *)arg,
> -                                        &new_attr);
> +               int err;
>
> +               uattr = (struct perf_event_attr __user *)arg;
> +               err = perf_copy_attr(uattr, &new_attr);
>                 if (err)
>                         return err;
>
> +               event->si_uattr = (unsigned long)uattr;
> +
>                 return perf_event_modify_attr(event,  &new_attr);
>         }
>         default:
> @@ -6399,7 +6403,12 @@ static void perf_sigtrap(struct perf_eve
>         clear_siginfo(&info);
>         info.si_signo = SIGTRAP;
>         info.si_code = TRAP_PERF;
> -       info.si_errno = event->attr.type;
> +       info.si_addr = (void *)event->si_data;
> +
> +       info.si_perf = event->si_uattr;
> +       if (event->parent)
> +               info.si_perf = event->parent->si_uattr;
> +
>         force_sig_info(&info);
>  }
>
> @@ -6414,8 +6423,8 @@ static void perf_pending_event_disable(s
>                 WRITE_ONCE(event->pending_disable, -1);
>
>                 if (event->attr.sigtrap) {
> -                       atomic_set(&event->event_limit, 1); /* rearm event */
>                         perf_sigtrap(event);
> +                       atomic_set_release(&event->event_limit, 1); /* rearm event */
>                         return;
>                 }
>
> @@ -9121,6 +9130,7 @@ static int __perf_event_overflow(struct
>         if (events && atomic_dec_and_test(&event->event_limit)) {
>                 ret = 1;
>                 event->pending_kill = POLL_HUP;
> +               event->si_data = data->addr;
>
>                 perf_event_disable_inatomic(event);
>         }
> @@ -12011,6 +12021,8 @@ SYSCALL_DEFINE5(perf_event_open,
>                 goto err_task;
>         }
>
> +       event->si_uattr = (unsigned long)attr_uptr;
> +
>         if (is_sampling_event(event)) {
>                 if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
>                         err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPkBQwmNFO_hnUcjYGM%3D1SXJy%2Bzgwb2dJeuOTAXphfDsw%40mail.gmail.com.

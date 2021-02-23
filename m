Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4PQ2SAQMGQEYPNSKWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 687EB322F6B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 18:16:35 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id v16sf10099532pgl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 09:16:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614100594; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Aj6TuU4uhZ8Mk6EkbBfIcPpt+siR1xchEnSyD7HeSc6SO2qL8Zh0TdKIcf/4N8Dz1
         GBgHOj42xYvp++io/ghqptLjrcu41svwxKymf3XrCciP+7jL0d6mG3hP4L9O77Kf+Bo6
         VMvDbje4Q3wKsfAd+jYeEmUqZYVzpW4ZkmH2AQ3ka6Nj+rypWJV/wA0qAS2NMvmCG73a
         KW7bT01aypzbox7t+c6tQxotoBxBrnrcxuW+UnqmRMpk/owP+cRBc3vlpG1s1nCBkzAj
         KTI0oxktSzJwn/1ai1T6CSWgzxZV69QWmYRJScrBRjVrS4NeKd1xBPKDADJkJll3AvD/
         Bg2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v+gcc4bt8hS49Q8L1wv7YWsPZpF+w/W9JEtOF5cI7eM=;
        b=N3m+WT7YKh7KmTHGcKfkOwaiGXiNdohx1JwJNFSAg746apX7aO7mS3EID5UdR4berK
         5ozpX0vyFmaC+bg9sdrV1ObFhyWP9IiN2ah0aUz0eVXqR5nMGDNMerzdK3Im96IZWPFO
         LB+HJrwaCY4z5wgqJa7fCxfON4pggxYnzrsr7B82j3j267IQZimdUGvZxsxZhHxNwl3E
         mplnfsiYzh13Tbg9JT7B8JDMAq64lcV7tv+i7XtQy7uh0OQ1VHKkFmBHBGpIyBC8wbeD
         QBr4HYqLaU1sbQ5NtFY9dyEWXbk4EefavYUdZ9XyfeHeijJbBMwgqfFS0uRa/uFhG2IG
         rQhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mRjlqnBT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v+gcc4bt8hS49Q8L1wv7YWsPZpF+w/W9JEtOF5cI7eM=;
        b=ThcWlYMncHciijJgQGE0qaiaYf4DdpjtSbEyP/ptx2V8tm1AslwLxC3T9roDz1+U0I
         Nva8jbaFWr3Xg4MQtSuhtjvtrAXRDYwR4FTNFswD3Iw1sSK3FMQcVnaj0evDB7lt2nDN
         Mx56/r4ghiExsba2NzytBoPu3QIVt36y+OJLGh78ezdKI1Q62p9h8LsPgdJAs0awiIbq
         k2NlZ6qLj7y3Gz3P4pC5Ux2oNw69PxpcHPXmG9VnDdocH1VhYb0e6DdgXgP8mCDRBbWy
         6vYGo+d9m5G2g/wbW6UGSdZkGLySOSxnDGsMOSKraYNb61PasjvQc/LAx3onpQy6R5Xu
         cFmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v+gcc4bt8hS49Q8L1wv7YWsPZpF+w/W9JEtOF5cI7eM=;
        b=ha7B6emKG+Lct16k+Sxhcvar7BlSYpNH44mazNdEZTclORZvw+zOSvflZ7cd3tyPH8
         5RYx6OYammkAQoWow/FrwDRECsYl+gnu0mdJjsKMSxXZMJBv4lnA8wrtu0GCzqoPBDuY
         2RnUap5xPFPov0Xd5mtj0gwQ11ZgRfgBlwOO2xRtoZGDA9yPFcQhxt5QXp8vjSfilIXo
         eHgmxrhYX2jKRsY1nxkH+WC2OxQ+eQerEhWaB7eIQBf8dYFV5V00polfApK1xBW1auKQ
         yk92KEOxZSYiR8Gkjoik9vW5txfphRAzJD+4DL5MSI09z8YnH/bY/7KWE/pTM9tv2GbS
         Ry5A==
X-Gm-Message-State: AOAM532DHW7cMA3bxLFi0dapKZNqjThmHsIN7t5hqrUG/X64ItZqtlbo
	oY9ZZYBjqdzKIfGgZCp6IHM=
X-Google-Smtp-Source: ABdhPJwGgbD4kBfPeuGdY+ZiolE03sd7vW8jU7YLlkoWggri/nWhTzq4GRrpR8cNie7zTFcYiglyZw==
X-Received: by 2002:a63:6384:: with SMTP id x126mr24666353pgb.345.1614100593952;
        Tue, 23 Feb 2021 09:16:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0d:: with SMTP id u13ls8289556pfh.3.gmail; Tue, 23 Feb
 2021 09:16:33 -0800 (PST)
X-Received: by 2002:a65:6a4b:: with SMTP id o11mr25020831pgu.138.1614100593070;
        Tue, 23 Feb 2021 09:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614100593; cv=none;
        d=google.com; s=arc-20160816;
        b=O3AVhLgVSgGPBzRoqb5i3N1+UZ3YzEEVbuZHt36awlVR7msxvOTIJqP/vLqAoqnIJE
         yZgcroPOvl3dgL/Ek7jKBTOcc4+6LjcEGyWYFxPfETlg5TZeoeZ7Cq19nZevtqIRY1u6
         gmLGbbSPlgZSzn2Du3F/CwKxjr3RT962i8vZAEIMcLKqFN+KaexsHHM6a1iVaR2CqMwp
         0cvEC37qOAWbrQPxX/JsRs7CihYsuFOYWO/rb7a/QT92nWB/GRIonmi//9soqTYFyl43
         SToPUjb1Wu/eSlHocPTYLa+Cz42deQTFAkN5W/7RbktiQvjD2XZFE1UdRarJzuutnKPx
         5pEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y/7lyBIawgXVibPEQjRnIJxZC4/J4mTsACbEERnxYDg=;
        b=osq8ZxZfUW0VzaKmz3bLsEjk59WZ+nsih2PWlPQx4xUGi6wHNxeGTShhllfibJ69TK
         xny+nwUjqW9YAbb5iSP0W1bREOcHI9pThUTCa6Dfm9WmtoSpaYPcMQOORVvhdekgYVI4
         u2SXZ+ws4ejdQOu1rADXm0nTqgxnHGM+ZD1aNUupP3v6/Z8Q4H98xc6EEpiQuqJRqkg3
         fZXrQtsfac/Qq0ertkO3Ok1o8xzT7Z5GeHJiZieQ460ohthvCGvo1yWcrCbLV6YA3jiy
         8J2uU8JslOs+YcAFR2+9ZdqRXVeuvtUzxIYcoPM4GbYdhoTtHQc+uhMlUUNM0rE4gHEA
         gCkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mRjlqnBT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id j11si1348677pgm.4.2021.02.23.09.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 09:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id s107so16310621otb.8
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 09:16:33 -0800 (PST)
X-Received: by 2002:a05:6830:1552:: with SMTP id l18mr21502367otp.233.1614100592568;
 Tue, 23 Feb 2021 09:16:32 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-5-elver@google.com>
 <CACT4Y+aq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ@mail.gmail.com>
 <CANpmjNP1wQvG0SNPP2L9QO=natf0XU8HXj-r2_-U4QZxtr-dVA@mail.gmail.com> <CACT4Y+ar7=q0p=LFxkbKbKhz-U3rwdf=PJ3Gg3=ZLP6w_sgTeA@mail.gmail.com>
In-Reply-To: <CACT4Y+ar7=q0p=LFxkbKbKhz-U3rwdf=PJ3Gg3=ZLP6w_sgTeA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 18:16:20 +0100
Message-ID: <CANpmjNO-xj8jnakVoWBbjPjn2gjHaugEVJTOebfdpvSwZhG5LQ@mail.gmail.com>
Subject: Re: [PATCH RFC 4/4] perf/core: Add breakpoint information to siginfo
 on SIGTRAP
To: Dmitry Vyukov <dvyukov@google.com>
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
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mRjlqnBT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Tue, 23 Feb 2021 at 16:16, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Feb 23, 2021 at 4:10 PM 'Marco Elver' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > > > Encode information from breakpoint attributes into siginfo_t, which
> > > > helps disambiguate which breakpoint fired.
> > > >
> > > > Note, providing the event fd may be unreliable, since the event may have
> > > > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > > > triggering and the signal being delivered to user space.
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > >  kernel/events/core.c | 11 +++++++++++
> > > >  1 file changed, 11 insertions(+)
> > > >
> > > > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > > > index 8718763045fd..d7908322d796 100644
> > > > --- a/kernel/events/core.c
> > > > +++ b/kernel/events/core.c
> > > > @@ -6296,6 +6296,17 @@ static void perf_sigtrap(struct perf_event *event)
> > > >         info.si_signo = SIGTRAP;
> > > >         info.si_code = TRAP_PERF;
> > > >         info.si_errno = event->attr.type;
> > > > +
> > > > +       switch (event->attr.type) {
> > > > +       case PERF_TYPE_BREAKPOINT:
> > > > +               info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > > > +               info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> > > > +               break;
> > > > +       default:
> > > > +               /* No additional info set. */
> > >
> > > Should we prohibit using attr.sigtrap for !PERF_TYPE_BREAKPOINT if we
> > > don't know what info to pass yet?
> >
> > I don't think it's necessary. This way, by default we get support for
> > other perf events. If user space observes si_perf==0, then there's no
> > information available. That would require that any event type that
> > sets si_perf in future, must ensure that it sets si_perf!=0.
> >
> > I can add a comment to document the requirement here (and user space
> > facing documentation should get a copy of how the info is encoded,
> > too).
> >
> > Alternatively, we could set si_errno to 0 if no info is available, at
> > the cost of losing the type information for events not explicitly
> > listed here.

Note that PERF_TYPE_HARDWARE == 0, so setting si_errno to 0 does not
work. Which leaves us with:

1. Ensure si_perf==0 (or some other magic value) if no info is
available and !=0 otherwise.

2. Return error for events where we do not officially support
requesting sigtrap.

I'm currently leaning towards (1).

> > What do you prefer?
>
> Ah, I see.
> Let's wait for the opinions of other people. There are a number of
> options for how to approach this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO-xj8jnakVoWBbjPjn2gjHaugEVJTOebfdpvSwZhG5LQ%40mail.gmail.com.

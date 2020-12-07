Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64YXD7AKGQE7E337FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C06872D0E9A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 12:05:32 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id l7sf8441265pgq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 03:05:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607339131; cv=pass;
        d=google.com; s=arc-20160816;
        b=lmq2dq8ERD0T6U18ELwzx2NH1mCOiE5/j6yrAXztu4UR11NAkNaRl5N1JPKPT3yDoo
         8U7xZUdNEikBncwHiDGXDBb20PygaESyUu3xgmeZyfwHyLD00aw/vf0NZ7HdfYbdMrXw
         cDfY3R15PB05I9E0/gpk8haqVOxsrylmapnORvt1iFxQTYW6jqEb57ZPa5hns3nnO9yw
         FLqKuHRED7HStndCvzvR2kFCuDBmfJJZOp95S0iuKlQT6qSlBqfKhhKdCNu7IPKe7Lo3
         9sLgalXQDnAOcL7sXJD/2J39+hJK0Wj44nb+z0QF1wpg9Y0OZcTNHpb7zU6Yhr6RslCW
         BJ/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vT4m3XpgJzh5BhkIzZjAMoTincY18dLAAaXLcchI4Z0=;
        b=OkqcYeIa2kcUsiuZBAOeh2uJJQXBhvbp0aJvuUe0xPxbfFfkJ27YgNNYtC33rvyJDF
         GtKpbE6H6TUuybm7hCOa88FuleoQs7vXoZIC19oAaYht7VdTzO8EoTaXOm4kayTn+JJX
         kdTrQ3lshYC9aQi6WBIIqjRJDqfezfzqKImfvlUX+GYHxQznTi5L6ieKdvufuES1hQpM
         jwns+iBMIaSCbiKjT0x151tU4WfZ3qcNa5XCjmTu6rhc9UX7HyYmC/dCoGLyy8BXJpub
         0hxwdAc+L1GrRkmwXxn0053wMAm+OXaw35MTMkAL/boZe+ZaEUoV5vitFPkQ2thyCE0l
         VOXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iCLr+DpH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vT4m3XpgJzh5BhkIzZjAMoTincY18dLAAaXLcchI4Z0=;
        b=cX4yNIqrD6ux5NMIgnGN9RwzbFCQwJXZoGgMpNY+2d48NihqnJ4zken6e77FrvaES6
         hRDFq38ZddKJbCaxfqcHNbx/0xItnfkvLl/3BjvFsdSNnl4ebs0TWTtyen41vGAi658P
         OETG/6PS4LjHsFxGoifnPnxCnJnOfv9xadUdhFRUF7a7XcRic8SDA3WFKoEFdqiwEG9x
         T0bGnvBcFw6CuMxC/6ZZTvkdYRtXuMxa/9aRiitUgeqZEo5l24p83jUzMQJVlRLyKCoR
         3xLkbwJcOzjEuvho+pi6OjCJwbBn//jYLvQcA1n5/N8vV867oUtT7Es7h/PRamVVQPP+
         +RGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vT4m3XpgJzh5BhkIzZjAMoTincY18dLAAaXLcchI4Z0=;
        b=KCbwI8/kYX36r55GIpR0r3480pYQpvlo5xbMtmmMc76znNmXs19HTKt/AE9xUzjqTg
         R/XGDnW8u5IG970NwCrFRgDiF7tts9nUtduW4PArJiIxDMx4lVp/Ylc335An6Fw0y7+b
         skdHHe8jpNqmRmEgq77aLsAcmw1EDT6WG+AcfzVdFNJeh0uad+Nee+z3v0rIbXqr9nI6
         3nyRHUJSbqsW34nYs9/ccJeJ57Lw4e6+PN6AzdjHCcKnfN4sgBR01CC4W2V3R508kxqq
         GvzblYl0bHm9GpGFKrl/x4N5CFqdgpl89NxIoMFbFQIKL9NGviDe5qui0qXvlZNLv54u
         gJdQ==
X-Gm-Message-State: AOAM530aj8Y7AUur8AT6dJgExNsWgaIBwSwOI/Bh0IXETRmw+rZ+CXyx
	dPqWZook8lPVxf0t8++CcLs=
X-Google-Smtp-Source: ABdhPJx/hCE3Nywb710xut+jFkZhglOX+aoMUw6fvb/jcGxACJ7BexJpDU2Go+rdfR1RMb/BfVwFtw==
X-Received: by 2002:a17:90a:578f:: with SMTP id g15mr16193477pji.3.1607339131393;
        Mon, 07 Dec 2020 03:05:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d4f:: with SMTP id j15ls1901908pgt.11.gmail; Mon, 07
 Dec 2020 03:05:30 -0800 (PST)
X-Received: by 2002:a63:f919:: with SMTP id h25mr18039404pgi.440.1607339130827;
        Mon, 07 Dec 2020 03:05:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607339130; cv=none;
        d=google.com; s=arc-20160816;
        b=lkCOd5SzBZGKM6buJK+lw18ofyEwct2wqaw6qITBTPSitzGgF17sam78IViwvIM/W5
         +Pz8WGMuunsdWhunT7/RQ3nBaM+elOo+iDNdpuUTzsX4nwrd6hPTLT7XikGr8HvosQ1h
         sZVPtFcrNo4/lxp4l5FbKhchmu18ehJM0W58kr+9aadRSfZk1hW6wOviLaaQ4VwFxIRQ
         f+IIxClP/WiTsd196yiIZzecDhHBLzbhUoOwZhMcCzXEe9ubiQkha1Czz3hy/pTxGqu8
         f86UgMYf7ws+V+57ViKNvP/aPumKwIQ/me9MCF+zgYldIVvZLeqY/1vj91FI/Cr5uih6
         4oeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FJXCIOJkKH6hh2jpxv9ilCGF+BcWVUo0z/wPZmqyr0o=;
        b=aKA/08cpv4Mfc3wVZe+QidbNAsA4URTQuvtRMBerN7XZrDrd77Ng5BImFZTAQ1E6eV
         pazTDwLuCAzDs2KAXCkRcca5xta5ifM/1S1Wn178loe14mgcUtHABrZm/BO6rqnKRBRw
         v0oqWJvD4fA2BnYJxjGmcvF/mV2HQ+kuwzosABQrWhkCP9Ul+h/oOssMxLIweIO2A/C3
         aq4eJWUTOoZ9/d+U9M8A3EeiqmWCRreHNvOxXLSJEO+/3OW09HoB1ae1aTDYKo7w4XMr
         QrGaYJJ2BDbX0rSke6xpRIaXs8DIoFWaWTzCFZVm9qIIHMdyCc4TogJBXXEiy/jyzGd7
         QXjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iCLr+DpH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id mp23si600774pjb.1.2020.12.07.03.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 03:05:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id o25so14964487oie.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 03:05:30 -0800 (PST)
X-Received: by 2002:a05:6808:313:: with SMTP id i19mr12226310oie.70.1607339130259;
 Mon, 07 Dec 2020 03:05:30 -0800 (PST)
MIME-Version: 1.0
References: <20201206211253.919834182@linutronix.de>
In-Reply-To: <20201206211253.919834182@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 12:05:18 +0100
Message-ID: <CANpmjNPh1dhTmsBY7LCaL73wiYFLNMG9Cm5S12D38NEuRsXKGg@mail.gmail.com>
Subject: Re: [patch 0/3] tick: Annotate and document the intentionaly racy tick_do_timer_cpu
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iCLr+DpH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Sun, 6 Dec 2020 at 22:21, Thomas Gleixner <tglx@linutronix.de> wrote:
> There have been several reports about KCSAN complaints vs. the racy access
> to tick_do_timer_cpu. The syzbot moderation queue has three different
> patterns all related to this. There are a few more...
>
> As I know that this is intentional and safe, I did not pay much attention
> to it, but Marco actually made me feel bad a few days ago as he explained
> that these intentional races generate too much noise to get to the
> dangerous ones.

My strategy so far was to inspect random data races and decide which
ones might be more interesting and send those, but I haven't had time
to chase data races the past few months. Thus, getting rid of the
intentional boring ones will definitely scale better -- relying on a
human to do filtering really is suboptimal. :-)

> There was an earlier attempt to just silence KCSAN by slapping READ/WRITE
> once all over the place without even the faintiest attempt of reasoning,
> which is definitely the wrong thing to do.
>
> The bad thing about tick_do_timer_cpu is that its only barely documented
> why it is safe and works at all, which makes it extremly hard for someone
> not really familiar with the code to come up with reasoning.
>
> So Marco made me fast forward that item in my todo list and I have to admit
> that it would have been damned helpful if that Gleixner dude would have
> added proper comments in the first place. Would have spared a lot of brain
> twisting. :)
>
> Staring at all usage sites unearthed a few silly things which are cleaned
> up upfront. The actual annotation uses data_race() with proper comments as
> READ/WRITE_ONCE() does not really buy anything under the assumption that
> the compiler does not play silly buggers and tears the 32bit stores/loads
> into byte wise ones. But even that would cause just potentially shorter
> idle sleeps in the worst case and not a complete malfunction.

Ack -- thanks for marking the accesses!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPh1dhTmsBY7LCaL73wiYFLNMG9Cm5S12D38NEuRsXKGg%40mail.gmail.com.

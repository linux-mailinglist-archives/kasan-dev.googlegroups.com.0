Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBFJVG4QMGQEL253EZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 12A8E9BD34A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 18:23:18 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7180ef2acd7sf4761483a34.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 09:23:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730827397; cv=pass;
        d=google.com; s=arc-20240605;
        b=G2ropxn+EfdXrpPibeQQv5l3MScrqmxE0ztOmUPWSMKl6upBnz68jroH/N/XwxLuAk
         mlnhFXkLGfHX/EFWDsmdCbXvD7Lrv7oX/WjyjRrDtEp3SArS+oHQmP5ETdGvlexgiNUW
         FTYcWr9AoXnth9HafTVi7ZcTFs54j1FoT//dirXYDcOnar9zD4VHkoYjlTHZykU9DJH4
         JZKvvXE6d70Cu7keL3Hy9e1mHiETbfVAXqeJFzFx1oGNK5Jv4GeY1ySwWYg5ero0/rh5
         1OJDdp76R8uehB8ORD5m7KxKn7xaoURIoVwxqZ5GOJp7LqRx0uC8VY8Jg6E6NgPo65wf
         INHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3ydUzszPCmTSa4b7zKLoNGGiohezwbqg2XKZUGGGBDg=;
        fh=d87xCyZoaw2MLuJdhMsFTozPvqwKt7Kw45aN3g9qTL8=;
        b=Sh9ZGofnsr+UMIDemYCwtQxucdmhk8rZ3lIy1++8PzSSuDPaZyDv8xZLsbILMo2pwO
         gyr1Zidv1NgHBT3spIGDee5SEq0PoxV7Go9RJgnA5yDTSYxVuuqNXjYIDW7sTznwEUqi
         qhleonBoOcDCLDGvfjCafb2NAFIeSa+DgSgjKy65310o56ZF9z6e0qQ1XJX7NChCJSqk
         omnmwxEtQX54n2Qrs5KyQ7Jzm+jZcFy3xKNAL46sJZ4buEiVfYh4P/PyVWttYtkr9DzZ
         6dB9j1LwAVhazIwJvScpnJX9jPljl6GdgsOcozW+Q6Hq2coOVsXdMxVVlvgICUiIO+p3
         q0sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0br0sKlY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730827396; x=1731432196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3ydUzszPCmTSa4b7zKLoNGGiohezwbqg2XKZUGGGBDg=;
        b=jdO8R5QyqS00xP+pdZfnkED1iwTUtyce/EafHo2nfvR+R6c88mKlMnSDjA4A9ZFzd3
         zeEr16axhyOOmt7WPlaUKSjSFGDYc8+EBi+IqgPxX5+OHfaeppDIv2iMGqqKByJAM1IW
         r+Sb41WHp71J/InXcicHJOhvRHP/sa4O3qrJhVwBu1mOm13DO+hJc6n/acGL3NlT6hmV
         kRBiE3rbtldqI1g7WbvzvQjodtNHEngkOnHSGLxA2s7pQT2fWlJqjmk4JINxJc6WJx7X
         xcx6+CDKYE6OQzNpgQ2vRH5PeVaeOx/A0Dwj49d8TlKWD8jg/o6UHaH265jTjBIm0OC0
         f0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730827396; x=1731432196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3ydUzszPCmTSa4b7zKLoNGGiohezwbqg2XKZUGGGBDg=;
        b=ugI3r1NheppkqQQFePwmdY5o5ShrvbRBBRAuEjHddk+xRe017p5rbOTElvyu48Wbha
         NaqmvOpHobizuNpvEs0YGSS8aSslcH9RWxgvM9xc/ft3VCKwXFrBf0hufJDwGhK6obIR
         tXoBzQ3jZAe9EtET5CVIi08Q4VVISORgSX5Gcu+Pi6beYBk1ygZYKbPWw1WDKExr8u9s
         PMOXgWye3+bGgOmOrRDzIhs53pJpsGifidqm39Hlsoan0qcxA8mDCHH+lHrRhIpSGP90
         q0/tCHadluxbwkgveZWcBnA4OURdhmgXhc7EOgGM8b/n/eUQI2bvJbee1bpm0wF5s8zR
         9CWQ==
X-Forwarded-Encrypted: i=2; AJvYcCUGOrUcA/QriDMp8vmYXKfEKDEY4kky3EN8cmA/wl3mlDRX4w2aQFoNrzewoX8blxdxKI+p0A==@lfdr.de
X-Gm-Message-State: AOJu0Ywwd2RWQWrhj4ytpzDLd2otuxteocMgw8uVIMekqR0e+EzHv4uv
	NFxBiQxugIQzhvc/0eiboEIKyT95RzuO/T4Ru3Puf62GTHa2axpW
X-Google-Smtp-Source: AGHT+IHiqJxrpPcTlHiQ9zaFDvQIKIUTqSVPe9j5I8PhHU56L57i58wtvGEFKaTRyJE4r8RhGNbEiA==
X-Received: by 2002:a05:6830:670b:b0:718:137e:c7e3 with SMTP id 46e09a7af769-7189b55e7f6mr18993661a34.31.1730827396762;
        Tue, 05 Nov 2024 09:23:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c703:0:b0:5ba:c07d:d1e3 with SMTP id 006d021491bc7-5ec6d2aeb0dls3297869eaf.1.-pod-prod-03-us;
 Tue, 05 Nov 2024 09:23:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUAaho8LJoo7R6rYQMxWmZQBgN06cWoZdaRRxx8m0wUAiftyZna6ZJgO9oAgvM9p0Ep2471+ns8c4o=@googlegroups.com
X-Received: by 2002:a05:6820:161e:b0:5e1:ea03:9286 with SMTP id 006d021491bc7-5ec6db4a30dmr11752935eaf.6.1730827393737;
        Tue, 05 Nov 2024 09:23:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730827393; cv=none;
        d=google.com; s=arc-20240605;
        b=XDOVImiJE5AgJAvx5oZvJMOYCCfm9ZjZduzCUHTzVX/noi7NbOb33Oe1oxNEzc5j5c
         pjte1Epsi+Yxpf107tl4Q3OiCoZlkefZKtTkdDs3EOgT4nEDC9TMmpcNVAt+hGlBVMyc
         HKyrYhaJO7PRLLi+Eh8rIvQ3TqMPzcUeSMgZZZCA3P3Ami3vkdPs2PUsMYz3I+aI+Vo/
         pitDY80TRbXLrzeFO0EzFXCSDlS7GSHpayW0tHbbq48s4oz2gwTS4C8hbn830WZmdZyj
         4Nld4hAVbGSVEMjCsxv2+9mDJ3l/3UL/5fGXebrwEJIqhETyYlejcG5X7goR81rBbxDa
         nItA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dFEkJSmFiPqxmVdTIAWTeQZ4orXSMuinYyWJKTteJXA=;
        fh=ygp13Ia9g7j+CLgoYScfAoSY7tBlfbSQ1YY/yHUst5E=;
        b=AIltDrmci6dxebyU8mKAtIp5EhW3gu+RxasSdleZ63gMVqepAL2uI5fRWQ0nBcRWa0
         JrCue3Cm70j3hR1a+xsdKbl6X6vsOwWuMl8moLibIhSzOI4VLHm/Jw8M8yNlMBldg8S9
         oqff230xmfssf0F3ZRkydrlge6MQbjlpGWpVR99AJy1078CUBmtSBeMhAMKSMF/GAHhQ
         xW2RhwNjPdYy2s7yRMpr0VX4RdUgv8+7CheL95bG/0XqsBxcaRMC74x8CKoicxJYWj4i
         WOQA/qYJLx1V310VZ6m76OjVVP7fO1yul8gmBewsa79xsHcMVu1CWCQJfufSBZLX/ekf
         XnQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0br0sKlY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ec70556477si575772eaf.2.2024.11.05.09.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 09:23:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-7ea76a12c32so4332573a12.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 09:23:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWHnYaXaR9f742vt8wGGmvqLUVg7ay0cXhYGTfCOb+VTJ0bHWulZ2cphcSUN0DO6jZv9V7q4P4u/Xk=@googlegroups.com
X-Received: by 2002:a17:90b:4c8b:b0:2e2:cd80:4d44 with SMTP id
 98e67ed59e1d1-2e93c1d22famr25936840a91.28.1730827392768; Tue, 05 Nov 2024
 09:23:12 -0800 (PST)
MIME-Version: 1.0
References: <20241105133610.1937089-1-elver@google.com> <20241105113111.76c46806@gandalf.local.home>
 <CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com> <20241105120247.596a0dc9@gandalf.local.home>
In-Reply-To: <20241105120247.596a0dc9@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2024 18:22:36 +0100
Message-ID: <CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y=YqxoUx+twTiOwA@mail.gmail.com>
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0br0sKlY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 5 Nov 2024 at 18:02, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Tue, 5 Nov 2024 17:53:53 +0100
> Marco Elver <elver@google.com> wrote:
>
> > > > +/**
> > > > + * task_prctl_unknown - called on unknown prctl() option
> > > > + * @task:    pointer to the current task
> > > > + * @option:  option passed
> > > > + * @arg2:    arg2 passed
> > > > + * @arg3:    arg3 passed
> > > > + * @arg4:    arg4 passed
> > > > + * @arg5:    arg5 passed
> > > > + *
> > > > + * Called on an unknown prctl() option.
> > > > + */
> > > > +TRACE_EVENT(task_prctl_unknown,
> > > > +
> > > > +     TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> > > > +              unsigned long arg4, unsigned long arg5),
> > > > +
> > > > +     TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> > > > +
> > > > +     TP_STRUCT__entry(
> > > > +             __field(        pid_t,          pid             )
> > >
> > > Why record the pid that is already recorded by the event header?
> >
> > To keep in style with the other "task" tracepoints above. I can
> > certainly do without - it does seem unnecessary.
>
> Hmm, new_task, pid is different than the creator. But rename is pointless
> to record pid. I would get rid of it here, especially since it also creates
> a hole in the event (three int fields followed by a long).
>
> >
> > To cleanup, do we want to remove "pid=" from the other tracepoints in
> > this file as well (in another patch). Or does this potentially break
> > existing users?
>
> We can't from task_newtask as that's the pid of the task that's being
> created. In other words, it's very relevant. The task_rename could have its
> pid field dropped.

Ack - will do.

> >
> > > > +             __string(       comm,           task->comm      )
> > >
> > > I'm also surprised that the comm didn't show in the trace_pipe.
> >
> > Any config options or tweaks needed to get it to show more reliably?
> >
> > > I've
> > > updated the code so that it should usually find it. But saving it here may
> > > not be a big deal.
>
> How did you start it? Because it appears reliable for me.

Very normally from bash. Maybe my env is broken in other ways, I'll
dig a little.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTcrk7KtsQAdGVPmcOkiy446VmD-Y%3DYqxoUx%2BtwTiOwA%40mail.gmail.com.

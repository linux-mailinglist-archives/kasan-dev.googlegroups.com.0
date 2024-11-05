Return-Path: <kasan-dev+bncBCU73AEHRQBBBOM7VG4QMGQETN463PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D1D29BD307
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 18:02:52 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-71819a87993sf4880675a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 09:02:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730826170; cv=pass;
        d=google.com; s=arc-20240605;
        b=B2QINZUBTFgiCGYL2GJIFOns05KS6p6sLhIis/3KGCqSdzxhZIhvrUVTUEcX8kiwTP
         8A6JslDvqEIeJok4V1i5hMw0yp+Bw8msG+ulRubCQTAwahD+5OJ2VS91LbhTWHCuwlYY
         eWlWPuPL10ECNiabzX7xLSXE9NWdoMIHcuEWyjXBVQzzauyTFwHnH/xZYE+cyAYJ/xuO
         dMj3auo8Skg8Q2dBzADffQ9xP+N0b8/cpE+dxGsp/4FC9Rqt6bIO//pgDY+3W86fBHxI
         G1kWPB28byyIASWFGjY7p9hAchEHYWsjKmSt2LNfqiqCULrpRHS8b8BSeQmA6u7Sb5to
         11HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=zWa6/rqrQArcAcxouzg9xXpUoefAOPeRkDZfQzkVVp0=;
        fh=pGmYCOtPVcDxxvWrsKoE235p0NU0DcmTDk1vEVs4gqA=;
        b=YMuSwUmT0E0i8GYdcvw/x5W48IpIxC88mtdu8J14cm/Znrjg2AAwAYuRIhgs+bO4KU
         Zklzk/r/RQJuEHzZjnQ93xvKr3ieTVsdJuR/rMl3HOWcPJttaLJrL9SkisjG7j2LErfx
         PYGPFW9CoXdyFHfLY85dWEw/QJx32b0O1UKtn2tJG48aJybnMem/OAj9dJhVkYxbNKK3
         IMGjmDnE7nQAgzJ+5z4hYGC/4TKvlBQGa6AzyCYOnjaTP6LtTCP7sLvWRV02o6ff1NLn
         vopSy0BJiL4UleBzSIKG8yYfyvbkRl5haej3dJVO7P2WyD5lmM1+h4ezarRjtyG9t0aq
         1lvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730826170; x=1731430970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zWa6/rqrQArcAcxouzg9xXpUoefAOPeRkDZfQzkVVp0=;
        b=XkJyZ0MeR26KSW+VD2+R2NsM/L5xvumoMSV9+TF8FUhnRMBHrQjV2JrY6YxzI0Pjqn
         emUb8Cu+cVgtqDSW4iQAQXCHkgxjHXaRn/ZFnuv3IBZf7UJQrtWB7qo1DdgQFRaJ8a0w
         sy/mH+rdvvo8JO2gkF+yGCG0rmVM/9+s5yQlaMaIbvKno1O+76gipHl6RQy39QA5UtE9
         V1cc9SLPxCZDskomhcOKEScLLSyF8/zrk+SvuOA7S1bT/6mCwiJoSo6PBaGuwy06sZiG
         v7KB1etQpjP/qe9XvE95TT/MjDHbFJO0u5nGSQN2cdw0zEwEEsc5RtL5GrDFY5BUdCP/
         AAZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730826170; x=1731430970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zWa6/rqrQArcAcxouzg9xXpUoefAOPeRkDZfQzkVVp0=;
        b=QyW2QJLzLxHaah96UuDWwZTCp8FFLH0z1IEW5smxOY/MgvNqB4WHC0eFhVG7fs5jNc
         5o6lg07cK7ZBdfjkZ0JtDoN2BjRS948c7LQo1DzmTkiVFSC+3ABuvcxpcYFuOGmw8ucz
         OxNKCTWoo9iYlZzmwoZ5ZfF1Eq8gPws9bfpQmDNcAOMlGppLVt5LMour+KbOvidW0o9S
         sKsytIas6CjTLa+TosldnFRuYC9UDq5BdOr+fceL9g4Sm1WbRFAShOo9i1OcskH6GAG4
         Oj6tU9Wu+s2F/Fq+oCQekTx1lsjEPp9iUh5NrXLgpKyduMAMSuUwiS0itaeTagv5zH11
         NMGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhNRseSA+PNPSBtzwdRtysas5a2uuqQrp1M8vgXrLX1aNNN7TGReD89W4rxVWR1dml2lnBdg==@lfdr.de
X-Gm-Message-State: AOJu0YxBs9g0moctir7WwqU2QhMgulh2WOiQmvUWT5+U9dBubevVOiih
	q0177FXJUCn8vdXnal2lMBveFfcCPDzPGAzf1e6Ds6ReR+Ke6RxG
X-Google-Smtp-Source: AGHT+IFyS+C+mO5Q8O3/pqiybgb2Xm8y4LP+PncS0LY8Gpu2wwO4B4pNVxawuwHSdVXoINfZCVBckA==
X-Received: by 2002:a05:6870:c83:b0:25e:1edb:5bcf with SMTP id 586e51a60fabf-2948442bfd0mr18801015fac.6.1730826169989;
        Tue, 05 Nov 2024 09:02:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:459a:b0:288:487d:4311 with SMTP id
 586e51a60fabf-29482776cffls4800576fac.1.-pod-prod-02-us; Tue, 05 Nov 2024
 09:02:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1vZifTQ3L4HxHuKTGjNcEMMmdegnmm09yD/4ncR2SmIqf8m/QG4VOMeoyXExCIiKVz4Oq/sZPXmE=@googlegroups.com
X-Received: by 2002:a05:6870:8311:b0:290:2933:571c with SMTP id 586e51a60fabf-29484010408mr16812370fac.0.1730826169202;
        Tue, 05 Nov 2024 09:02:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730826169; cv=none;
        d=google.com; s=arc-20240605;
        b=ks6Lm6W6JrNFXHEZ8Zn88mYb1H2WrTDPkxgo1kGclAc0gbZ/g1rEV3js5Ll3KXK6up
         pA+G316VwRo7RwXjhzKyciifPn24DQ27oUdnf8h3anGz9k8gmQeNKnN2a4A5pj20FGXs
         bggELkZsRLV4SVtK8FTjLAC+T55d0GxLQy9eDsIV8kljYCnRTXtyBtlO/Km+VHuxeR/s
         6mCOGRIWtcCRHN4j/QCc3b79VtnHvv2n01VyjIxORg8qn8/7s1hq5SXff30TpPQsCGgf
         kvt3GH74qyHyPvYPUMmYgYvKIrO1Ee6/NWfg/trntHIrKICxFoqBs6lYvcN29tcoJco7
         Znhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=YXtkqRSmMmg4rGSqNZJZCM9SQk/N8jgUYHYlyaW3+i4=;
        fh=/KD3HwrGuO9MAu+3rlkhZeCCXxkrJnqg5M+fZj/pNlI=;
        b=YS4zfUuuQ30nfaHzX9beivJuFh3fGQu9bLaXNZhSS4+l65DQpCvlPN+blX3v7wayE3
         CFHm0FTUeY67/MpFwvnnJKOVPkVXPq64kn3XGJkSZ7vraw232Jib/WBlKJV+WRSSgq+k
         9iUdsUr0WJlBTmoeh+TKK7q2faQJ+e4bGk1x6bfOR4s5W2g+0IItYVouq/HbWNA1xhtr
         KWLt6dV5yhOTGDd59BIxxN8Dr7BzwDS0SKmRo2Duk4GZRKoB2MMiu5n0Sc3jxudZwfXc
         +cr2/DSKQRBQyGUvC1IcrNIs6t2uztM5NZFBF3QTXYFMyciDHPZROiS4woIPCEM9S5CB
         N6Bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4de0489ef57si427345173.2.2024.11.05.09.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 09:02:49 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 765CAA43643;
	Tue,  5 Nov 2024 17:00:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EB424C4CECF;
	Tue,  5 Nov 2024 17:02:46 +0000 (UTC)
Date: Tue, 5 Nov 2024 12:02:47 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>,
 linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] tracing: Add task_prctl_unknown tracepoint
Message-ID: <20241105120247.596a0dc9@gandalf.local.home>
In-Reply-To: <CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
References: <20241105133610.1937089-1-elver@google.com>
	<20241105113111.76c46806@gandalf.local.home>
	<CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=s2ql=sa=goodmis.org=rostedt@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=s2ql=SA=goodmis.org=rostedt@kernel.org"
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

On Tue, 5 Nov 2024 17:53:53 +0100
Marco Elver <elver@google.com> wrote:

> > > +/**
> > > + * task_prctl_unknown - called on unknown prctl() option
> > > + * @task:    pointer to the current task
> > > + * @option:  option passed
> > > + * @arg2:    arg2 passed
> > > + * @arg3:    arg3 passed
> > > + * @arg4:    arg4 passed
> > > + * @arg5:    arg5 passed
> > > + *
> > > + * Called on an unknown prctl() option.
> > > + */
> > > +TRACE_EVENT(task_prctl_unknown,
> > > +
> > > +     TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> > > +              unsigned long arg4, unsigned long arg5),
> > > +
> > > +     TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> > > +
> > > +     TP_STRUCT__entry(
> > > +             __field(        pid_t,          pid             )  
> >
> > Why record the pid that is already recorded by the event header?  
> 
> To keep in style with the other "task" tracepoints above. I can
> certainly do without - it does seem unnecessary.

Hmm, new_task, pid is different than the creator. But rename is pointless
to record pid. I would get rid of it here, especially since it also creates
a hole in the event (three int fields followed by a long).

> 
> To cleanup, do we want to remove "pid=" from the other tracepoints in
> this file as well (in another patch). Or does this potentially break
> existing users?

We can't from task_newtask as that's the pid of the task that's being
created. In other words, it's very relevant. The task_rename could have its
pid field dropped.

> 
> > > +             __string(       comm,           task->comm      )  
> >
> > I'm also surprised that the comm didn't show in the trace_pipe.  
> 
> Any config options or tweaks needed to get it to show more reliably?
> 
> > I've
> > updated the code so that it should usually find it. But saving it here may
> > not be a big deal.  

How did you start it? Because it appears reliable for me.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105120247.596a0dc9%40gandalf.local.home.

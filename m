Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSE3VG4QMGQEMQNFDQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A2D1C9BD2E4
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 17:54:53 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7203cdc239dsf6833613b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 08:54:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730825672; cv=pass;
        d=google.com; s=arc-20240605;
        b=CC0rmNIlSXCSJIsImOpbtKfzOmcJhZ92ivZASapPbbwXpJ9OYhQefwnQISZTRNLwOQ
         n9PBHQi2RuMNy2JJbY1/kw0euRlgWfTTRq9Quv4AfN5u+Jj5mVWd+VPJCbVmsm+KBxAy
         QzzpUvKRaR7n51G5xYQJlv9b+eEcuPtdpRVl51ZjSfnboCBHAn51oyNw6nOhwATb6rHt
         KXo/eyQq8yXNAkyehli29hB7sWuQ6bObKP2doInpceckw8eB6YH/O+iJEpAcL7mMkTY9
         FtrWAJltO6AZppyEbt/8PMdlM6NAODLh9IjatXXlxnXQr6umNM1ACkONc3dey9MsOv1+
         UnQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WT/LnwxByxQOw7s/S93htx1YZbAHmvL7Vfr09KpgmkY=;
        fh=TkArdQtlZxcoGKcnPd+l/1Bx8bO+rsrUham5mgz8R/o=;
        b=jmSBiz3ob62dFbVFGHGvrxb0ljfjXDZOSsl7PZ744zKfFnJpZSpUYHBNUNzxw5Op6a
         dQCQfUiHNpVH4Q7a0yMjHqtNnlljXXB76EoumYo81q/cB4+4E3ZXQvIHNL6DHOOwDwHj
         KnGxmE/HLhiyQB/RYQubkv5kE5BX4hGG+YLnbWufoMraNcjh+tD8wItb2fnkLNcVQbwA
         CVVbBC9w2gTtc/ACJS4J0hBsTHNNBTZaP2EONlrMCFvo3Hq0cMDGMGtNvNA9qOgLN5bK
         /Np+XNaaPx7BMmpFoOgh4oD0u9moo31W8WV1m4RJXpM4SlML3lWESWPorKF9LRvkBWuv
         YD/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bbk+B/Uj";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730825672; x=1731430472; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WT/LnwxByxQOw7s/S93htx1YZbAHmvL7Vfr09KpgmkY=;
        b=BWgnXdmIw6XqotGiL1I3uqhNOStIZ0SzaACTVyTGHxB2+PEPB7i1m8h/MJDvejed8D
         pUhASnFKVoJMqGob+23LU1mAuB2ezceodMiT1v7AWa4plQ7aqHFy39LK5npyDKvXKrWj
         GeWdAi6D62IAaegMnFuXrn1fWENMwGB3BdfwtPHn88bEw5r6zW9/FdrLcIyU+XQ+3ZtP
         LWvE5rdoNx2oQ6XfPJbAOgaq2C+RLDqEB6iovt2R2xpCpsOchrMqE/8mb4jqB2kb4oXv
         Mxmv7DeNQu2/v5nl11Qa0xpeDItSBNMG4e8xgy9rKz8E07C3dKDP4bau5dxA+QNhXUES
         98Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730825672; x=1731430472;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WT/LnwxByxQOw7s/S93htx1YZbAHmvL7Vfr09KpgmkY=;
        b=qXJFy56odWNtsoTEnpLrPpLBI8jymgt6UKefhswUmsXRuCjmRBLQY7qCxcg+Z8DpZy
         1TpRRSkTT1hHuxO6zaZfn3AT9c9kKWYYspYPx+VtrsD06ZYYiEJ6vcmbXfwnJOHgV1oI
         dymw0yW9uM8i2ecqLmNs/VtuvxAaepoHQKX/Hz6c9mRccga9pngLt18ugXyGAAuk7mAM
         NkwiGJIZ4AGyB+YA+uNjisiCBCFWdx79cmYXvjCK+F+GnUm5Xgs/qsRjjgF6YbqRyQew
         Uim9NkBNKCx2+5gfSvlGjWV+/TcSMj2Axj16acj7GHj+F4f0tfZILGmebHGcxXrxZOmm
         MP0g==
X-Forwarded-Encrypted: i=2; AJvYcCWvGCyamxONDL/KMqwEuOm/WjuLKvlZW6mC+1dUPvjwlSzfGzA75cYR4rfRMZjaEt0+yX0U0A==@lfdr.de
X-Gm-Message-State: AOJu0YzBKWPVSmOAYDhhzX5lQKZTsErU0C779IzvHP+LWutAbG6TdSv2
	u/F24oLZrWwHloPKq6ps8LB42HoztTq0rDbOw170+1jBoN8cjZRf
X-Google-Smtp-Source: AGHT+IFFqiaBH63e1K+XJFECFhIyn8jqRCx1vM7i1I3KafLHWvhwtjzJLg2kXgExmdeBU+o6Nnx7Uw==
X-Received: by 2002:a05:6a00:ac4:b0:71e:587d:f268 with SMTP id d2e1a72fcca58-720ab39e43dmr35686769b3a.4.1730825672371;
        Tue, 05 Nov 2024 08:54:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:88c7:0:b0:71e:6edf:b2ac with SMTP id d2e1a72fcca58-720ba12255bls1096920b3a.0.-pod-prod-01-us;
 Tue, 05 Nov 2024 08:54:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUF1zUgPRXwCjDejYOPs59oa/yHKxOePaXVgVF0geJNlLvntWk1ncxAi7+iygR+ICs3JgO/6BHqCNg=@googlegroups.com
X-Received: by 2002:a05:6a00:b93:b0:71e:589a:7e3e with SMTP id d2e1a72fcca58-720ab39e77fmr32587243b3a.3.1730825670730;
        Tue, 05 Nov 2024 08:54:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730825670; cv=none;
        d=google.com; s=arc-20240605;
        b=ir8B/0wxLeWMJ+KnXeQTMZBogO5La7Tga+duY5ifyd9qMUmSjcMiO2Ps26BmDHACvJ
         EX1NhHc2VXHwUJ7U1VxEko5bENTiwoW8KhDObvyZ1OephheMtyGU7ziWpymDZpb8dpAj
         i5fyCFUSrk/C/77fOMLO/XN/mvR4/K6j1A8T16T+aKhi8vBLLe/R42sZGnwTgYjoT7C5
         zu5artEaoaXB6AlWQZmrmXXMw5ZfNWrI8ejXgD1R7Mw08N5aem/gB5UGDho4iQmLBL9I
         Ig+2t23ENKXgddJ/kibixzrFQU/I+ICj9H/Imev24XcGlWC+ZXDAo9ZDCp8qc2mhaWau
         EWbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V83vNZjqmDf/Us+3d1QTdKDw13qNe5x5q2rn92+ivN4=;
        fh=MhMFISl3pYTBXMTvyINMyMJSwkNkN+FAR+i+2e3kPb4=;
        b=PMsYvC+OfvlOodKkAWkwUPSNmcldLkNPwsfVPUfkT7ZKNGSxq4e5M6tjEKPvKzKEkb
         YhoHRQePuX6dZUD4oeXN4p0SCnnN65TVYwCyylTSWd/C0Wh/paD50jcLo3NTEU9mkwLg
         fMcnVIzIIvXLgqVBn/EENJ/hyZPb0vYtRibHLu+UHrJncddxctI3d4eHhomcn7Y7Wml3
         FIkPPUfz/lfsTGszke0Wf6fwTQSDpTAk2SfqmdJkUSOB9kLAhG9lHK9Xe37DKkK1eLST
         5nio1c47rB4xT2bZevfrIIEfDJjrC2Tt0c+Ab7QmyU3HkGZXpIgnME6w9n3DUFMM1rPW
         Hyzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bbk+B/Uj";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-720bc32f0afsi544117b3a.4.2024.11.05.08.54.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 08:54:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-7e6cbf6cd1dso3830978a12.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 08:54:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWyNps4kfZCI9WTVduVbNix3qkFmAI0DvFtxkyLE+5I3gBIxqKlMcq6P/fWP5Xf5PygmcDwxOJVfL8=@googlegroups.com
X-Received: by 2002:a17:90b:3908:b0:2d8:e7db:9996 with SMTP id
 98e67ed59e1d1-2e92ce50f8dmr27815450a91.13.1730825670072; Tue, 05 Nov 2024
 08:54:30 -0800 (PST)
MIME-Version: 1.0
References: <20241105133610.1937089-1-elver@google.com> <20241105113111.76c46806@gandalf.local.home>
In-Reply-To: <20241105113111.76c46806@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2024 17:53:53 +0100
Message-ID: <CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4+Emkr8hWD++XjQpSpg@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b="bbk+B/Uj";       spf=pass
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

On Tue, 5 Nov 2024 at 17:31, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Tue,  5 Nov 2024 14:34:05 +0100
> Marco Elver <elver@google.com> wrote:
>
> > prctl() is a complex syscall which multiplexes its functionality based
> > on a large set of PR_* options. Currently we count 64 such options. The
> > return value of unknown options is -EINVAL, and doesn't distinguish from
> > known options that were passed invalid args that also return -EINVAL.
> >
> > To understand if programs are attempting to use prctl() options not yet
> > available on the running kernel, provide the task_prctl_unknown
> > tracepoint.
> >
> > Note, this tracepoint is in an unlikely cold path, and would therefore
> > be suitable for continuous monitoring (e.g. via perf_event_open).
> >
> > While the above is likely the simplest usecase, additionally this
> > tracepoint can help unlock some testing scenarios (where probing
> > sys_enter or sys_exit causes undesirable performance overheads):
> >
> >   a. unprivileged triggering of a test module: test modules may register a
> >      probe to be called back on task_prctl_unknown, and pick a very large
> >      unknown prctl() option upon which they perform a test function for an
> >      unprivileged user;
> >
> >   b. unprivileged triggering of an eBPF program function: similar
> >      as idea (a).
> >
> > Example trace_pipe output:
> >
> >   <...>-366     [004] .....   146.439400: task_prctl_unknown: pid=366 comm=a.out option=1234 arg2=101 arg3=102 arg4=103 arg5=104
>
>           ^^^                                                       ^^^
>
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/trace/events/task.h | 43 +++++++++++++++++++++++++++++++++++++
> >  kernel/sys.c                |  3 +++
> >  2 files changed, 46 insertions(+)
> >
> > diff --git a/include/trace/events/task.h b/include/trace/events/task.h
> > index 47b527464d1a..ab711e581094 100644
> > --- a/include/trace/events/task.h
> > +++ b/include/trace/events/task.h
> > @@ -56,6 +56,49 @@ TRACE_EVENT(task_rename,
> >               __entry->newcomm, __entry->oom_score_adj)
> >  );
> >
> > +/**
> > + * task_prctl_unknown - called on unknown prctl() option
> > + * @task:    pointer to the current task
> > + * @option:  option passed
> > + * @arg2:    arg2 passed
> > + * @arg3:    arg3 passed
> > + * @arg4:    arg4 passed
> > + * @arg5:    arg5 passed
> > + *
> > + * Called on an unknown prctl() option.
> > + */
> > +TRACE_EVENT(task_prctl_unknown,
> > +
> > +     TP_PROTO(struct task_struct *task, int option, unsigned long arg2, unsigned long arg3,
> > +              unsigned long arg4, unsigned long arg5),
> > +
> > +     TP_ARGS(task, option, arg2, arg3, arg4, arg5),
> > +
> > +     TP_STRUCT__entry(
> > +             __field(        pid_t,          pid             )
>
> Why record the pid that is already recorded by the event header?

To keep in style with the other "task" tracepoints above. I can
certainly do without - it does seem unnecessary.

To cleanup, do we want to remove "pid=" from the other tracepoints in
this file as well (in another patch). Or does this potentially break
existing users?

> > +             __string(       comm,           task->comm      )
>
> I'm also surprised that the comm didn't show in the trace_pipe.

Any config options or tweaks needed to get it to show more reliably?

> I've
> updated the code so that it should usually find it. But saving it here may
> not be a big deal.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMuTdLDMmSeJkHmGjr59OtMEsf4%2BEmkr8hWD%2B%2BXjQpSpg%40mail.gmail.com.

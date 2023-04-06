Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWVGXOQQMGQE3SJPP4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1826D6D9941
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Apr 2023 16:12:44 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id v10-20020a05622a130a00b003e4ee70e001sf20570033qtk.6
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Apr 2023 07:12:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680790363; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXVLrB4z9eYu3cmVOKDbEkcx0IYltVXHFS5OMUFh2Fg615vYuku1dbtnB4Gu1TzPOW
         DpvKUTPd1tY0FfdkieEwTuEQT1h81Kx7lsYgVoddzPsVKOrVte45zYrCx9ityx0w6bFr
         yssYBWvodqeOTZ5C5UGm7/wXah54+JR1rXKmf0KB3veUlVaMxnBesilDcdXR+DQIH0nP
         QvMG3VRKOQqdUqn5ZkCBrkRHZ3i3sRDyjS/Sam+DEkk3BtSWJty9JhqqC5+VSCxbGTjG
         LLlFt3G9mlisCp7SWozwlnU38lhxcucPmyl+wxZldhdpCnyS1XiZo11vJ4l+eONzEypK
         zbHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RDrDNu603icttDHfUZ7HE9jHs94TVjfxSTDmoPMM6ZA=;
        b=pe015/iI9fPgFUMn90ss5H0mNLUi9wCRr8wEL6nzpGSmrdBaFZxX9/8chqZ28QYgNv
         G6lU/WIDeBG3bt+X/+cPklA4oJB40WoHr5UJ/KlqX1Gl3xlFyYsgBHQabKMmdpWllhZs
         XBHBDctK30fQ6f3m6D3YDc6tbUP74UHXV6VK3PsEvlU7zLizT8lj5uzwAns8Hc92The7
         rHbm5sAgXg8kZhHyLvZDqLakOci5ZMxYxQ6FyQPcLzM679D1e9+TRSKpttCGypiL2hoC
         TypGfHd+cKqg2VRX7vx3XV3O5PynZMVOSv59U9gSK1MrreUtSFavwTByyr1AKBwnIPZL
         tV0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tYw73/Fy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680790363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RDrDNu603icttDHfUZ7HE9jHs94TVjfxSTDmoPMM6ZA=;
        b=Iryot/1sYokvwFpul1aEaiRW31G/w+K2kArJJgu5TLzSncCoauBQSAMqK3OQ4+eNv4
         HbLSZQrpjkKhfEaztPo4rLCXkS1ocB5gqTazNmzaa9Apyw9xp6u1oKhnRgbJHiFsgOf/
         8KONj9APWZWpy86OsBO2RUEQ3hVV0rIwWmOC94Zbch0A2DhebctY2w+z1CH0u2PYa1fs
         pbZcCGhy7CELhHw1Xiawb6d9GFDkNxctzT3injWSqR/qSCq87ycZZJMrf8uyoNLHuZlg
         gza7ORP0hVSGgh2oy6ytCsudPIcEMTfbyujE1B/kuPcyoEP20ciG+39nGUEuGf8Oh0Ao
         GNPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680790363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=RDrDNu603icttDHfUZ7HE9jHs94TVjfxSTDmoPMM6ZA=;
        b=biTtq2qvvZrHfTcn4xrfWhIIlonJZSB3Kg2G+wTUB1M5Pn+Ke9idaWA8uH4tm0MdQi
         eXuRz0/bWDsFmWZBWLKUuFrURXwK0a1xSP2AGb9w4ih/CSsaBpALMFIOYTCR/zJZM0Fr
         +Kiq+OoQCiT6sZ5WRf0N7hY1FK7i7KuIcI37v1l1kVtMmK5HYs4rRM26iqh0bGQQQpjp
         IpF+slctZ4nt9w6sjd7jckyBvP5SmqD2e9WXu/T7diauWw/MOfIMRt5ihMav8uSHhyor
         8KEkqEl8coKDJ8VWkOUFcugOadrKOCXWa51YbzAEyEq6NasAdfTUmufNN2g+FyHA0iR4
         lMwg==
X-Gm-Message-State: AAQBX9cYecCECuhgZIzD7FQK+k7K+dNmr4oAV5AaCZ79ajW1v93Q0Foa
	ARiJSlMdw7onpapRl2RHj6g=
X-Google-Smtp-Source: AKy350Ys+uvzRKO70PVY3NnnNn1kbwjK9Y9auMFVngUzHIdF8JZX23tZafiwByKigEbv3bW45/ZHoA==
X-Received: by 2002:ad4:58f2:0:b0:56e:b401:ee3f with SMTP id di18-20020ad458f2000000b0056eb401ee3fmr581784qvb.7.1680790362737;
        Thu, 06 Apr 2023 07:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d98:b0:3d3:ead1:4e62 with SMTP id
 ff24-20020a05622a4d9800b003d3ead14e62ls21392989qtb.5.-pod-prod-gmail; Thu, 06
 Apr 2023 07:12:41 -0700 (PDT)
X-Received: by 2002:ac8:5c04:0:b0:3e4:ee15:ad44 with SMTP id i4-20020ac85c04000000b003e4ee15ad44mr11076185qti.31.1680790361675;
        Thu, 06 Apr 2023 07:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680790361; cv=none;
        d=google.com; s=arc-20160816;
        b=q/cddBmiX6hejYn0/w8N6qnOuAZNl9StZOodllgWcwRYPPdvkfzEZH5Ebt7BldOvh6
         Ifq4tcU9qAUfh25xFtO0mpSpUz22HDW+mLYwPQOSqxqpxS6bsODzuQqDQ5TKtLnxLHrI
         Sjpjp04F9gnfZqrln8pIAv3f/vJFtMq1Z1g2QYatl9uqA8iKrJ5I/5rZBsIOCItCY5aZ
         KKfVzRXTEBDHPRtP9bH2KhiQksxXu50/SGK7KO4T+ioo/nVWimHX5+o6ZGjbSodD/IWg
         wGDU4GflJIe8hpVPwIXKsMO149iLBmUzGoaP37szNJXWG8omtIhCR6acgQCDfywH0LrM
         RErg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EK2TuG+WkLupwO9C8GXLQol+GTLoseAFOILf7LMA4Ag=;
        b=vA49tqbN+fzASNpcumKioH3C4D1gsUBSZKNZMIYHj/rdVC4y9pzXrvlzKXklYlI/v+
         axeXPXBDsRJ4Dsmble2Dz1u3x7bjjDVjVvCxLaPlG4vGSW4vyXM3EY2yxZzbcihuGWVM
         Jo3A2O0PkmM+CVhwa9oqM6Xv6YmA7ebOV2/f8pXWvcvZi6L4VlGiceXv6aPiNgL/NGlN
         fM2EnXKEpJ9LIzlpG0fam7Rsby5N+neu3XqrlTOLx8sXaSWxoKYUJhnCQ3wK1SOs4h58
         pHtpptTy+YJYZ1zaRyt051Qq8OJMHbi6HIMGaNAlQCXe7pVOMuJTj6TW1Yn4AsC2TBez
         GxCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tYw73/Fy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id bz5-20020a05622a1e8500b003e25bce470esi143170qtb.2.2023.04.06.07.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Apr 2023 07:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id k17so17423447iob.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Apr 2023 07:12:41 -0700 (PDT)
X-Received: by 2002:a6b:d10a:0:b0:744:b4c2:30fa with SMTP id
 l10-20020a6bd10a000000b00744b4c230famr6986944iob.18.1680790360988; Thu, 06
 Apr 2023 07:12:40 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com>
In-Reply-To: <20230316123028.2890338-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Apr 2023 16:12:04 +0200
Message-ID: <CANpmjNOwo=4_VpUs1PYajtxb8gvt3hyhgwc-Bk9RN4VgupZCyQ@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>
Cc: Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Frederic Weisbecker <frederic@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="tYw73/Fy";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d33 as
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

On Thu, 16 Mar 2023 at 13:31, Marco Elver <elver@google.com> wrote:
>
> From: Dmitry Vyukov <dvyukov@google.com>
>
> POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
> thread of a thread group for signal delivery.     However, this has a
> significant downside: it requires waking up a potentially idle thread.
>
> Instead, prefer to deliver signals to the current thread (in the same
> thread group) if SIGEV_THREAD_ID is not set by the user. This does not
> change guaranteed semantics, since POSIX process CPU time timers have
> never guaranteed that signal delivery is to a specific thread (without
> SIGEV_THREAD_ID set).
>
> The effect is that we no longer wake up potentially idle threads, and
> the kernel is no longer biased towards delivering the timer signal to
> any particular thread (which better distributes the timer signals esp.
> when multiple timers fire concurrently).
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Oleg Nesterov <oleg@redhat.com>
> Reviewed-by: Oleg Nesterov <oleg@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v6:
> - Split test from this patch.
> - Update wording on what this patch aims to improve.
>
> v5:
> - Rebased onto v6.2.
>
> v4:
> - Restructured checks in send_sigqueue() as suggested.
>
> v3:
> - Switched to the completely different implementation (much simpler)
>   based on the Oleg's idea.
>
> RFC v2:
> - Added additional Cc as Thomas asked.
> ---
>  kernel/signal.c | 25 ++++++++++++++++++++++---
>  1 file changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 8cb28f1df294..605445fa27d4 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1003,8 +1003,7 @@ static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
>         /*
>          * Now find a thread we can wake up to take the signal off the queue.
>          *
> -        * If the main thread wants the signal, it gets first crack.
> -        * Probably the least surprising to the average bear.
> +        * Try the suggested task first (may or may not be the main thread).
>          */
>         if (wants_signal(sig, p))
>                 t = p;
> @@ -1970,8 +1969,23 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
>
>         ret = -1;
>         rcu_read_lock();
> +       /*
> +        * This function is used by POSIX timers to deliver a timer signal.
> +        * Where type is PIDTYPE_PID (such as for timers with SIGEV_THREAD_ID
> +        * set), the signal must be delivered to the specific thread (queues
> +        * into t->pending).
> +        *
> +        * Where type is not PIDTYPE_PID, signals must just be delivered to the
> +        * current process. In this case, prefer to deliver to current if it is
> +        * in the same thread group as the target, as it avoids unnecessarily
> +        * waking up a potentially idle task.
> +        */
>         t = pid_task(pid, type);
> -       if (!t || !likely(lock_task_sighand(t, &flags)))
> +       if (!t)
> +               goto ret;
> +       if (type != PIDTYPE_PID && same_thread_group(t, current))
> +               t = current;
> +       if (!likely(lock_task_sighand(t, &flags)))
>                 goto ret;
>
>         ret = 1; /* the signal is ignored */
> @@ -1993,6 +2007,11 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
>         q->info.si_overrun = 0;
>
>         signalfd_notify(t, sig);
> +       /*
> +        * If the type is not PIDTYPE_PID, we just use shared_pending, which
> +        * won't guarantee that the specified task will receive the signal, but
> +        * is sufficient if t==current in the common case.
> +        */
>         pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
>         list_add_tail(&q->list, &pending->list);
>         sigaddset(&pending->signal, sig);
> --

One last semi-gentle ping. ;-)

1. We're seeing that in some applications that use POSIX timers
heavily, but where the main thread is mostly idle, the main thread
receives a disproportional amount of the signals along with being
woken up constantly. This is bad, because the main thread usually
waits with the help of a futex or really long sleeps. Now the main
thread will steal time (to go back to sleep) from another thread that
could have instead just proceeded with whatever it was doing.

2. Delivering signals to random threads is currently way too
expensive. We need to resort to this crazy algorithm: 1) receive timer
signal, 2) check if main thread, 3) if main thread (which is likely),
pick a random thread and do tgkill. To find a random thread, iterate
/proc/self/task, but that's just abysmal for various reasons. Other
alternatives, like inherited task clock perf events are too expensive
as soon as we need to enable/disable the timers (does IPIs), and
maintaining O(#threads) timers is just as horrible.

This patch solves both the above issues.

We acknowledge the unfortunate situation of attributing this patch to
one clear subsystem and owner: it straddles into signal delivery and
POSIX timers territory, and perhaps some scheduling. The patch itself
only touches kernel/signal.c.

If anyone has serious objections, please shout (soon'ish). Given the
patch has been reviewed by Oleg, and scrutinized by Dmitry and myself,
presumably we need to find a tree that currently takes kernel/signal.c
patches?

Thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOwo%3D4_VpUs1PYajtxb8gvt3hyhgwc-Bk9RN4VgupZCyQ%40mail.gmail.com.

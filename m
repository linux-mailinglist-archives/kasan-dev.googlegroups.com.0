Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNUWCDQMGQEDUENMAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C443C4970
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 12:32:46 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id w3-20020ac80ec30000b029024e8c2383c1sf10958188qti.5
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 03:32:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626085966; cv=pass;
        d=google.com; s=arc-20160816;
        b=UWZ7QR/Bdr7RC26gGsPzxFCNwNnwTvKF4QP+s3txz0y1vfeLWAzpQwSw/UVhh36XzF
         2xkFy6J9y5imtwmL5EXOZ2M2+BpEOnug+tpbW02PpZroGjAKaOe1JbCHRucW8AoVPYl3
         8EaL1+xlaTEOPKnBM6YhY7fAXkJs71yVUluuXbPhkslVSQbdkfDOd+vNt6aVxDou15ar
         B4i99cLbFlmZuiNzwAvEz+nf/9BkNtZXTmPX7HLqLsZAnJBANPoopULC6AdCYW/vDO12
         BmWAYLPBFcYFau0UDvkXxyxa559/SfTPFwHJ52lmcikxzlNGIlhpjqWI0QSOpa2U7SoP
         hWTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gm13mCozU2H8Ihqfc2O5U+ipjp7ov/hmyYi3bXyx4Ps=;
        b=mmYrluNVe9xTdYGS5QHX9HJVyavV9drsWWVyYb+dBhGpN/Mx78GbcAuyh2Ek5io+Uk
         CrCKeYBF79dxuqH7Edstyk6CzGgGK0vGHR97VTA4WhvoZ3+WSDLCbFUUrT53yeX8epxu
         o2FKWOqhbQeqHSZqIZLnYukPy7wr4LT+B9HiHVCPSwByZ4j7WOvcVmnsefOG4KRuf+Ie
         wltFN4il6d5XNoJRmYX82c8r80tDHb4lNairKy+B0NwWGfKAusW/3c60CEoF+MLa6ry1
         F2rkfLHRNod63IrIi2lmnlXxZ1xAwg+tKX8T7sbbni6Yw/JSZ4ZYt6QZXHEWWj9Xfpcp
         /t1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F5afFXcZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gm13mCozU2H8Ihqfc2O5U+ipjp7ov/hmyYi3bXyx4Ps=;
        b=F2jIP4bLBoINAwEr6pdWYsmrtGqI9HxkvULS7s91qZW1dUwYxymFdzYeTE9j4LxyDa
         vlLoK/Bl/G1YIQOBJUBu0WumzROpYLkprj4+GVvtqD6UpfjHN5Gh5ossOOr/vmVpnvut
         Q/+UH+vg0zZ/ugpNPqBTXDTf5wASMOIF5eyPXRCYeGhsVJG3FidN2X8n+NW4Y4K87que
         Z38WXIPD97mY6zeDOxGbTbbR2UUs9ZzHfNUhONLz1rJq+t2VjYKu7YwpRZAS03gQpv/B
         TUkJQqy9ODBPRi6a0yLAho5Zp+gXErDCxHIWSmEE7RwWzOvyarr2AppTKaDjBt1QpIFW
         4Y4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gm13mCozU2H8Ihqfc2O5U+ipjp7ov/hmyYi3bXyx4Ps=;
        b=LhoEpfJEpzs8L83V9g9D4LjJzYfu9ACeWXfrGOIphkRbTYLVv/RVuTIeHYPP7TI5Px
         ck7N9moLdHq8sIjVR1prRO6AuQl72TtqxBLDY1F9yblku55zx2xI+AWEKDOHu2PxHhYs
         gGbjHooKBiqgDHnRQcWOFHMTVG4/JKt8g5oMoiTR9xhtyNCsTXNVtmUrro+az3q9so4O
         fZZwnGBG/MFGjpYmtesN04CxA6E/EgKHfCFFaCf4ae3CMhxbGezeGWfYVS37Crah8h7H
         1F1Yr4MXcG2nE1EP7M9LWMIJXCuK6UsuIEhAuQ9nv7+YJfLIbv8LY3Uok2U4MUemuV28
         HFyg==
X-Gm-Message-State: AOAM5300jdRxtO5coeJUrqRianhnu5yRykChj+n7IK1CPJt1WgTVn6ae
	BfZg2Ri/BR7IAwCEZ7nV/d0=
X-Google-Smtp-Source: ABdhPJwiyO5NKB4yl6uF9wceUqdJNSXPGrBudnrySkas/5LdPtjkHAgXIlTXoElzRiy9CBgPux/e2A==
X-Received: by 2002:a05:620a:6c9:: with SMTP id 9mr52004098qky.303.1626085965941;
        Mon, 12 Jul 2021 03:32:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:111a:: with SMTP id o26ls5177809qkk.6.gmail; Mon,
 12 Jul 2021 03:32:45 -0700 (PDT)
X-Received: by 2002:a37:6f05:: with SMTP id k5mr50624297qkc.497.1626085965497;
        Mon, 12 Jul 2021 03:32:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626085965; cv=none;
        d=google.com; s=arc-20160816;
        b=dWSnavDp3NYQv7Urrj5EUiPO5iHz4ict9+YBfmRx0IDNaeNE9UgTZua39sMiec2HKs
         GZq3xrRyqPw4lEhE6WRoXZlTuyxI+u3Aqs5WuehRef0pN2GMQYhpE2GZh/aIOm+ixIKo
         8fHCJM3aAqSc2Rr7h0uuq0+CmcZf1dhq9UATGuoVkhvp6eygkmvcNgM/YM2eJm6ph5iI
         yWlw2jsY3UgP55lmq9naFZRnv0leCfEHS9kk3LvILBgNZ8pPU+pHYuEdfd7km5NGvwNt
         +BJ2/8EK/LW2bBnizrznc/uzocoU2GPDq5+HO1X+AssYVQfYAHHo4eu90VM1PwGNfiBr
         kdxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6hEyAkHkInoJotPHkAfN0wodjsUHpYTw3naBo9WfZZI=;
        b=0yZFaENoOnHIM+Bb5rFvGbeGGrQITxAfRpiiYYCkF677RUlrf5vRg2NQWeDT/sRVzY
         GLKOfE01Q00Sous01UTS3pK7kjbfCpf7xGgIHI30Hr199p4vGkYOu7gtEZqs81wPNpZz
         BcbBU3MggmTlAF8a50WS8m+o/VnVEqk/d2FFz+bbPGygau81ds2P7gKlHGOfDd6pW879
         ESuR+OUMEfPWLmwU3gJWFMK4NN39FpjLI4gGI5A/bzUjAS+Lb4XFRabBcnli4nY2gY5b
         KWNXEO9XqubEKZdr3Cn55ov2Lhd9n7K5kgF/iFuU87RC3PFLW8s/9bcFRwIsCwbodqRw
         1DBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F5afFXcZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id e30si1445645qka.4.2021.07.12.03.32.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jul 2021 03:32:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id 75-20020a9d08510000b02904acfe6bcccaso18356240oty.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Jul 2021 03:32:45 -0700 (PDT)
X-Received: by 2002:a9d:650e:: with SMTP id i14mr12659704otl.233.1626085964667;
 Mon, 12 Jul 2021 03:32:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210705084453.2151729-1-elver@google.com>
In-Reply-To: <20210705084453.2151729-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Jul 2021 12:32:33 +0200
Message-ID: <CANpmjNP7Z0mxaF+eYCtP1aabPcoh-0aDSOiW6FQsPkR8SbVwnA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] perf: Fix required permissions if sigtrap is requested
To: elver@google.com, peterz@infradead.org
Cc: tglx@linutronix.de, mingo@kernel.org, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com, 
	alexander.shishkin@linux.intel.com, jolsa@redhat.com, namhyung@kernel.org, 
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com, omosnace@redhat.com, 
	serge@hallyn.com, linux-security-module@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F5afFXcZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

It'd be good to get this sorted -- please take another look.

Many thanks,
-- Marco

On Mon, 5 Jul 2021 at 10:45, Marco Elver <elver@google.com> wrote:
> If perf_event_open() is called with another task as target and
> perf_event_attr::sigtrap is set, and the target task's user does not
> match the calling user, also require the CAP_KILL capability or
> PTRACE_MODE_ATTACH permissions.
>
> Otherwise, with the CAP_PERFMON capability alone it would be possible
> for a user to send SIGTRAP signals via perf events to another user's
> tasks. This could potentially result in those tasks being terminated if
> they cannot handle SIGTRAP signals.
>
> Note: The check complements the existing capability check, but is not
> supposed to supersede the ptrace_may_access() check. At a high level we
> now have:
>
>         capable of CAP_PERFMON and (CAP_KILL if sigtrap)
>                 OR
>         ptrace_may_access(...) // also checks for same thread-group and uid
>
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Cc: <stable@vger.kernel.org> # 5.13+
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v3:
> * Upgrade ptrace mode check to ATTACH if attr.sigtrap, otherwise it's
>   possible to change the target task (send signal) even if only read
>   ptrace permissions were granted (reported by Eric W. Biederman).
>
> v2: https://lkml.kernel.org/r/20210701083842.580466-1-elver@google.com
> * Drop kill_capable() and just check CAP_KILL (reported by Ondrej Mosnacek).
> * Use ns_capable(__task_cred(task)->user_ns, CAP_KILL) to check for
>   capability in target task's ns (reported by Ondrej Mosnacek).
>
> v1: https://lkml.kernel.org/r/20210630093709.3612997-1-elver@google.com
> ---
>  kernel/events/core.c | 25 ++++++++++++++++++++++++-
>  1 file changed, 24 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index fe88d6eea3c2..f79ee82e644a 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -12152,10 +12152,33 @@ SYSCALL_DEFINE5(perf_event_open,
>         }
>
>         if (task) {
> +               unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
> +               bool is_capable;
> +
>                 err = down_read_interruptible(&task->signal->exec_update_lock);
>                 if (err)
>                         goto err_file;
>
> +               is_capable = perfmon_capable();
> +               if (attr.sigtrap) {
> +                       /*
> +                        * perf_event_attr::sigtrap sends signals to the other
> +                        * task. Require the current task to also have
> +                        * CAP_KILL.
> +                        */
> +                       rcu_read_lock();
> +                       is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
> +                       rcu_read_unlock();
> +
> +                       /*
> +                        * If the required capabilities aren't available, checks
> +                        * for ptrace permissions: upgrade to ATTACH, since
> +                        * sending signals can effectively change the target
> +                        * task.
> +                        */
> +                       ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
> +               }
> +
>                 /*
>                  * Preserve ptrace permission check for backwards compatibility.
>                  *
> @@ -12165,7 +12188,7 @@ SYSCALL_DEFINE5(perf_event_open,
>                  * perf_event_exit_task() that could imply).
>                  */
>                 err = -EACCES;
> -               if (!perfmon_capable() && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
> +               if (!is_capable && !ptrace_may_access(task, ptrace_mode))
>                         goto err_cred;
>         }
>
> --
> 2.32.0.93.g670b81a890-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP7Z0mxaF%2BeYCtP1aabPcoh-0aDSOiW6FQsPkR8SbVwnA%40mail.gmail.com.

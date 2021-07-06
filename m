Return-Path: <kasan-dev+bncBCMIZB7QWENRBVXKR6DQMGQERRH2N2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 72C673BC656
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 08:16:56 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id d1-20020a17090ae281b0290170ba1f9948sf984776pjz.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 23:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625552215; cv=pass;
        d=google.com; s=arc-20160816;
        b=FgI7gr0u7mfFwO941luGju6SxmsZQANjl0ZmRJ6wKm1VVF2LX3PgOgfXTGOfoSdZoU
         tJNr/uFdzEDjA3BjzRpx7Mf6Vo/WfY38e4tYwv8R1QjMCbadJb1Q8E+L7uEpIceuyEmY
         J4MLfhVIz2zmRhYSGUPO8Yl6cC7saivxuNZXL01PeHFUJkd/5V5WZX9C+rmC4TsBscHP
         1BVJ71dwmi1cy8B6kA7a4fimLanIulA9KDBXmDlIZT3Mn+18uPGcNRrCmX21mcXZC29R
         DNwQDSIDOCsbtS53EofKfnQycaNN/leoIlZWaTVzZOjMmS6oBCJQvMyWcEz/6gaHEBPn
         LNHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3tlVn9jTHankWRSN+Mm59ZFvTCYJkoBPUwPDOC8ZB0Q=;
        b=o5mM4VyWaf+aaovFlpcgpcx3jb4RK4XVwAZAlTht1H+oMU8VdaadymqiWd63SB14QM
         cGn8UU/QhBrA1JzTXJPCpjpGRpyv2XZMWCRjB4X7e1BsoGp7faHlqt7Strm1wAVEqQoA
         po9Zs5Da/uAGSfgc0eVyDZpEkKfb4HLZoPWMNudwn78l+p6zrufkCcrhpxA+2SWOKCvC
         AurfbHpjCOXkd1DPZ4YPGLvWqX3B8mCwH8AZVPYNVEgOlxDydhmR8bbjWVP/oDpziWm9
         Edum0NQCKbQVt+uX+0y2+1KgZrf1BPlwUGGYM6Il9Bd6Hib60jpTctV40/gu2kMvLln2
         F2BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Gzikz/eE";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3tlVn9jTHankWRSN+Mm59ZFvTCYJkoBPUwPDOC8ZB0Q=;
        b=byVl3wcRL7OdvcAI/7Dg6SZ4HcQ75C42yWH3R1OLsjPgHwxdPqy0k+nBQDCoRdISc1
         CFhpsc4BDvztdQ44RED6WEJ+bHnDFL+ugBihetmvieqPm7Aa8tOBJTmDqy5YoSC1NMPP
         wV84Q0yI60nCBQPtU7hsEiZtRPA9iux+1wN6vtVbBzYK5aVbWPXKhZchogtZIrsqsU5j
         vShK8aCuI3mPiE6UZ+YzxTxFVqlnXPXgWz66lULCpbIjtmh9aSPo4pO/nFHzggNO0Ox4
         QQYMP2/0A2n9H8s+noLgQtqRi61qLAD3uHfnrlPA2Lp/jE7Y+s+in3rpq8uha0IPh4Pc
         oGeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3tlVn9jTHankWRSN+Mm59ZFvTCYJkoBPUwPDOC8ZB0Q=;
        b=d3bJPr0+Wz8XHIDeNRYxPtgvvwjE0GFPhNKDIGBRdBXxylZC7hXPOR/Z5o1Y2hH+Sr
         JHvvaCrZFvs/1NL5GxunmZ+0OLUDSBYvKMxhKmRdAwoJDS+kNnxvWwNgW2tIfxsefNOL
         e2Z/PS0hWHxIE4Y7+gNpavr7J5ucZeohQXKTkisWa9n+d/+ElOteXYn6NKhmEexyIfzw
         Mz3F93y8u04Q1E3hBxo8mP9CofdAH9JdjFmvD+3O5PFyjEDXI3+swfSGJNiHAXkcKuj9
         UYBekngdzk/EERkjdUOUzvmC4rxPgdpxoUkr5OyN56wEq5kXhMF+b9kzJH/itZTiwTRT
         cbTw==
X-Gm-Message-State: AOAM533neBi9WC7W0BHQ5+U36Ov7thd2PK0xs89z/VWROpwjj1dNE0Ws
	g1kfy5Ly2V3EXsGKI+uqGCU=
X-Google-Smtp-Source: ABdhPJwnfPVap7VAM4mGPshR1vhQKyklzzmYvhMv/77oWPDPae1TIHJhj5lks21x1AYYHDxtjOtbYQ==
X-Received: by 2002:a62:4e97:0:b029:312:7b4c:55b7 with SMTP id c145-20020a624e970000b02903127b4c55b7mr18389556pfb.47.1625552214905;
        Mon, 05 Jul 2021 23:16:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1943:: with SMTP id 3ls10349236pgz.8.gmail; Mon, 05 Jul
 2021 23:16:54 -0700 (PDT)
X-Received: by 2002:a63:65c5:: with SMTP id z188mr19546938pgb.174.1625552214402;
        Mon, 05 Jul 2021 23:16:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625552214; cv=none;
        d=google.com; s=arc-20160816;
        b=hLCjwe/jnrTjVDRuq7S75i0j5HAdYcqT06rI2OuoE8nkkGAP2dbtbfQd+aN4H2hiU2
         OF6R6xbK37XQPa9QemAUxGkNoOND0sF2e8Fs/Dbkq42A4NlfQtiIh2ziOXw+i2Rp9lo+
         ym+UJGZxYtqn/ou5Nu/dXaH2QkfCXhzBHW0s0u7be2JcDH7iDnPMqHE4oHc1dwqAZgW/
         spqeTUNpg1GPV2CLg/EoH5RCbwSOgSG3CCyqLc7IeZ+J/4wUNx0tKfqp/FSEl5Hpo/IP
         zhN6X24N/2W7IS0jhpk7ATI3D5ZhWNGrOFOlTqYi214wXZ4aZTfQJXsq+mmEiQ7lfls+
         25iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RoGi9t0tW2ZKROiX5vNisDNKd+fSc5OvBjzFvq9gYvY=;
        b=U/KiI4wwRjAouhhr5CfCyZ4TBCbLvXQH21QNsCqZvRReaNSXTHq8pKhtDIXV8EIl18
         ol9KJ5DdptTHdO75GqEhlcJOQmj5b8qTEW4LwL0bp7SP0tYDpKDBDHKcc9tZr4UIaK8T
         aOw2vt2ZMUDffmRe17SAbO9ZcaujQPa0PlL44exwF4CMi9/a3MQgj5G7KNhX/qnGS/qw
         kxjxt6Yip9f1de8FErA21k4C1dorf4La2mX+j3HsTNDDWe2ADubk9K3JksH3MRfPuZ57
         H2FuF3xwcgUlSDGogDvKS1cgTIyHUd41bKo9iPhlj2ChPxIM9t0+EMBlqY5T+jcHk8zj
         YTYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Gzikz/eE";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id u38si619052pfg.4.2021.07.05.23.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 23:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id t19so4486679qkg.7
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 23:16:54 -0700 (PDT)
X-Received: by 2002:a37:6614:: with SMTP id a20mr10617401qkc.501.1625552213306;
 Mon, 05 Jul 2021 23:16:53 -0700 (PDT)
MIME-Version: 1.0
References: <20210705084453.2151729-1-elver@google.com> <20210705084453.2151729-2-elver@google.com>
In-Reply-To: <20210705084453.2151729-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Jul 2021 08:16:39 +0200
Message-ID: <CACT4Y+ZjjuW5wZ-QsYj7btZYYyNEiSnGh6JtV3bmSNx9mY_bZw@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] perf: Refactor permissions check into perf_check_permission()
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, tglx@linutronix.de, mingo@kernel.org, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com, 
	alexander.shishkin@linux.intel.com, jolsa@redhat.com, namhyung@kernel.org, 
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com, omosnace@redhat.com, 
	serge@hallyn.com, linux-security-module@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Gzikz/eE";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d
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

On Mon, Jul 5, 2021 at 10:45 AM Marco Elver <elver@google.com> wrote:
>
> Refactor the permission check in perf_event_open() into a helper
> perf_check_permission(). This makes the permission check logic more
> readable (because we no longer have a negated disjunction). Add a
> comment mentioning the ptrace check also checks the uid.
>
> No functional change intended.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v3:
> * Introduce this patch to refactor the permissions checking logic to
>   make it more readable (reported by Eric W. Biederman).
> ---
>  kernel/events/core.c | 58 ++++++++++++++++++++++++--------------------
>  1 file changed, 32 insertions(+), 26 deletions(-)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index f79ee82e644a..3008b986994b 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -11912,6 +11912,37 @@ __perf_event_ctx_lock_double(struct perf_event *group_leader,
>         return gctx;
>  }
>
> +static bool
> +perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
> +{
> +       unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
> +       bool is_capable = perfmon_capable();
> +
> +       if (attr->sigtrap) {
> +               /*
> +                * perf_event_attr::sigtrap sends signals to the other task.
> +                * Require the current task to also have CAP_KILL.
> +                */
> +               rcu_read_lock();
> +               is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
> +               rcu_read_unlock();
> +
> +               /*
> +                * If the required capabilities aren't available, checks for
> +                * ptrace permissions: upgrade to ATTACH, since sending signals
> +                * can effectively change the target task.
> +                */
> +               ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
> +       }
> +
> +       /*
> +        * Preserve ptrace permission check for backwards compatibility. The
> +        * ptrace check also includes checks that the current task and other
> +        * task have matching uids, and is therefore not done here explicitly.
> +        */
> +       return is_capable || ptrace_may_access(task, ptrace_mode);
> +}
> +
>  /**
>   * sys_perf_event_open - open a performance event, associate it to a task/cpu
>   *
> @@ -12152,43 +12183,18 @@ SYSCALL_DEFINE5(perf_event_open,
>         }
>
>         if (task) {
> -               unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
> -               bool is_capable;
> -
>                 err = down_read_interruptible(&task->signal->exec_update_lock);
>                 if (err)
>                         goto err_file;
>
> -               is_capable = perfmon_capable();
> -               if (attr.sigtrap) {
> -                       /*
> -                        * perf_event_attr::sigtrap sends signals to the other
> -                        * task. Require the current task to also have
> -                        * CAP_KILL.
> -                        */
> -                       rcu_read_lock();
> -                       is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
> -                       rcu_read_unlock();
> -
> -                       /*
> -                        * If the required capabilities aren't available, checks
> -                        * for ptrace permissions: upgrade to ATTACH, since
> -                        * sending signals can effectively change the target
> -                        * task.
> -                        */
> -                       ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
> -               }
> -
>                 /*
> -                * Preserve ptrace permission check for backwards compatibility.
> -                *
>                  * We must hold exec_update_lock across this and any potential
>                  * perf_install_in_context() call for this new event to
>                  * serialize against exec() altering our credentials (and the
>                  * perf_event_exit_task() that could imply).
>                  */
>                 err = -EACCES;
> -               if (!is_capable && !ptrace_may_access(task, ptrace_mode))
> +               if (!perf_check_permission(&attr, task))
>                         goto err_cred;
>         }
>
> --
> 2.32.0.93.g670b81a890-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZjjuW5wZ-QsYj7btZYYyNEiSnGh6JtV3bmSNx9mY_bZw%40mail.gmail.com.

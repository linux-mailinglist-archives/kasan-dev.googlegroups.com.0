Return-Path: <kasan-dev+bncBCMIZB7QWENRBOHKR6DQMGQE6MRK2TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C7913BC652
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 08:16:26 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id w38-20020a6347660000b029022342ce1f8bsf15369311pgk.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 23:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625552185; cv=pass;
        d=google.com; s=arc-20160816;
        b=zVgzMUAu4873rRR4SPDfqyH/DyZSII18wWz2gBUD/DYpl3IP4kuIrD4voGbYJ+BNUI
         lvhJvmySXI9d+2p/yjUNRnEYegLofPrqqaoLdLzSHP4L/Q0QuC32qQmplZY/fPgQOTfX
         NWe+YNsZYVFkHedeK8fKqjNcGlCX5wE9mGb6A7GtzxXUlMagNt6HpYKZBMdTqWrWN89Y
         6QhXns6UzTX4ydnqDLo+a8MLOFuQ8AuWqoba2QQUYcmnlQBOoSsUd5tK9nCymIhYRGtu
         lqUJPxHLh5ofLVyGphRj93gV+hbYFraetL3UL/y+XIGybgxyh4+Crhcn7edgM+6MvYe7
         bjcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SH5K4N7oGhKT4J1WllrcGSjTeLgOtL/Du7mHPGiRhyU=;
        b=Q6a37uq66XOmO0L5BIV85M4e9sgcCxzQ/oFeHVqsbTSrkewOufSApoPeuN/hyRdDfp
         uOmEBJlVxzptUCq+a6A+1JkPvo1w6LGHipTUcPAr9quyyscb8RPM1The4Fo7LN0ZASBI
         hi1Nu3txKUFHRE1yku0ZSdee8oEHqSp73AYWAM2yNUEpGhzh93IhhZVmpqpwpLZ5z+AK
         sUv9n3/N5l22d1VUHlwMhec58/zw2ycNOXz/sqXAsHBeQUfmtju/MlV3TjXEpZxvNY81
         fGHvq97qYtRMNgD09X6JEOsaALpE1cniUSBYdWyyIt2rdvKJT/ndsF1RP7boAcRC/Hqs
         hMtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ap8WxFAv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SH5K4N7oGhKT4J1WllrcGSjTeLgOtL/Du7mHPGiRhyU=;
        b=OBaTGRqILUQ/RV5sUxUF45EpXVbKjVmfeFJOtjtLu99jnrRqHWLZDHla5iFPqkGYDg
         XSlu+rfxCvN7D8rJCG7Xo3oOjQZB/lJEqY12IccMzSVEf7IcOFJUyKli7miKVD472baW
         2Y92f48/a4Ow6qD1VsX7sA6p+I/dysQx+UkPNU2p8XDC7RbyAmMXOwdZXe2b8UfBH+Xs
         1dWdwpwk9Y/jhT/gOmRAHeiEk3Zj7l1UyKlzlCihwXxk/LKTxxJRjy2itXdqfw4OvX8v
         MEZlJdkvO4d7lwtJmokwm4WA8gvPsr6yyetXLf0BEHm6fN5KAi6cAEgTTHRrxxCcyTgs
         p+ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SH5K4N7oGhKT4J1WllrcGSjTeLgOtL/Du7mHPGiRhyU=;
        b=IsosGDwdrt6wPaF4L0lrRiyMxwyzL5Fm9txPQMi6b2CQx1O63N2jyDzZHACtlpLECM
         oVy5Uk/3NkX6+Bvp5b5Dr3cX/tJ/j3WM4BHvilyxBVr35gXUE1j6EN5CQUfsQAuMTaEf
         V+M3q1zqst71IU5sU9CETGA1RwClik26H3cCJhhRRFQCPBsQF2kuDlP73pJWeEIBvQh8
         Zqrj3PCv1dI6eczHjnKiUgKkIgBlk7IlZSFPtPtsi//15kQGti0ERvka8aum+w664E2N
         910AdVNT+sI5wlKJZeNH/EdNzaYrgN1t3BkOtNQHIBIsl6ZYGtm8aZpY2hVcVDtYJvKe
         tXGw==
X-Gm-Message-State: AOAM532a0iDr9Jep09cv1rlwBacINvmj13x1RKqqbOeT5EjtwpH+ahaA
	xOlpnaQk7T9O4y0VH3l5fa0=
X-Google-Smtp-Source: ABdhPJwfuEYJF9YaVgYA4dZWrWfTFVDCIYhJ4im9NYb7eN8o0p4sxyCePPIzFwbiOs4sY0IaeLIRbg==
X-Received: by 2002:a17:90a:9511:: with SMTP id t17mr19243300pjo.108.1625552184805;
        Mon, 05 Jul 2021 23:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2406:: with SMTP id k6ls9349195pgk.9.gmail; Mon, 05 Jul
 2021 23:16:24 -0700 (PDT)
X-Received: by 2002:a65:498a:: with SMTP id r10mr8650510pgs.7.1625552184291;
        Mon, 05 Jul 2021 23:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625552184; cv=none;
        d=google.com; s=arc-20160816;
        b=jdDu5OTjYOHrEO7Ty5hDeR2QOjW/CdUyigGWQboRT/lJVjf/jxCYwUFIlWswzvFqI3
         5rv37JXOuh1mqoMQgW0WjZg1KOnJIYGN9lCJ7SHiivdlR8Kax9IDa2NAjo+V429NZy5p
         5eTrICiCD0EjbEYNGiVshhpthz29ylidp9P3aeT85N648m+oFS82JOUl/c7MBaWZdFk0
         oTjdfJ3aeYIgYS6C2gBkb1uiCkd5MW/5SjgE7w02tbUgAwIkrv4tjuPrWxjKkb8LGw0o
         iSUuJjJMJxmvRvwXTLBOTvAVPGRLO/TbBdPcYWNNOL7BeGweMbFslbVQfBvCN0xMya8O
         cBMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i2kc2sPl4mFDGHgoHEBwsK+YcufyFuxpzKrHOh0bOKs=;
        b=a/t365bLOxj+yOyif146McA/8cZ/G6e0gS3rotl3kaV0wYGuexKfXG7B2B0Xi/htH+
         HZbmsjhK4Ba1EmkCdzcq1zgPw99PRA3pCb470/20flh9khmmuZiOnWb5epmLu3OpORFL
         qVj1mVoJv4YUAAI7fDmjr+7e4QvTI2rZhlOJ7T44/DJoAF5AQrZcsHSO9rx3MT41cwAS
         s6weKHWTDZtRWFksL7BaSLdQxDYcWJMXNVZJwNVg3OouzYy4c8Wsl+ezItVn05I/w0Fx
         BeL/prX0+4hitMKcvp/XHHH5Y/ewCakjUcbZNgVHYxGFkoRky0Tpxy/bjLbp3nmCh1Ve
         /YyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ap8WxFAv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id h17si1338450pfk.3.2021.07.05.23.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 23:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id j13so19136709qka.8
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 23:16:24 -0700 (PDT)
X-Received: by 2002:a37:6888:: with SMTP id d130mr18540942qkc.265.1625552183218;
 Mon, 05 Jul 2021 23:16:23 -0700 (PDT)
MIME-Version: 1.0
References: <20210705084453.2151729-1-elver@google.com>
In-Reply-To: <20210705084453.2151729-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Jul 2021 08:16:07 +0200
Message-ID: <CACT4Y+bQovD7=CZajMJ_AZz=Rf37HpDQiTp0qnhi-GhuP0Xdeg@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] perf: Fix required permissions if sigtrap is requested
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, tglx@linutronix.de, mingo@kernel.org, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com, 
	alexander.shishkin@linux.intel.com, jolsa@redhat.com, namhyung@kernel.org, 
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com, omosnace@redhat.com, 
	serge@hallyn.com, linux-security-module@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ap8WxFAv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
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

Acked-by: Dmitry Vyukov <dvyukov@google.com>

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbQovD7%3DCZajMJ_AZz%3DRf37HpDQiTp0qnhi-GhuP0Xdeg%40mail.gmail.com.

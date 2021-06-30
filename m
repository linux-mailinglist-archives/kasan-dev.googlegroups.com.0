Return-Path: <kasan-dev+bncBDTIRYVLZUEBBW5D6GDAMGQEEL3YXJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id AA54D3B811C
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 13:13:32 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id w22-20020a5ed6160000b02904f28b1d759dsf1593784iom.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 04:13:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625051611; cv=pass;
        d=google.com; s=arc-20160816;
        b=fWywduHCYWn4NG39DH7Fm9EgXidqpX3x/8pN5UXtIzw/IXwTbP3DjBpk5A1+iMJ0LG
         bmSxjcw/oYQOn/JpT06n8rSF3WLDo/MVliCGcJ+Y6KMLjn4DJM4ayKTjAjvTgkmQ4FZN
         B/fZI9tEVMZM7u2kaA2wLYVDW2kQsKRkYFSrolTkKIHYkxKwkNY0AfUlNocXBj0ovPB8
         vW3b5kbMnaG9AJytSTJN+87ciYvr2nIK7CyUMtjD4rprtikKov/Iu+IHLDjg4Vlh6jML
         xGfqnIHCBx/9dH0gNop5mFbu/BZy5GVZ+V90DiDjrjTzjZHJmjG2fzXS2mkwUNgQb7AE
         G4Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=y04PKl85rEiIjH5pGGmXuZPAhT7mxBNGDV7FsTn0Uq0=;
        b=n207NUR8DHj8YtmBYBacpfgVuuVbHPstQHqqNz2ZUcw0yh0zzuuDGkJEik/4r40t5i
         /wISMmaa/hDfGTJ/qNXATO2vvi4bJkZgQ0FboAaSj6qy5jSMPel5ryyyni0TvNWwe211
         gh84s/Dku6CiwK3Kn+K7gWlLjYhj58G8VJsoUyOdtAqD4a1NbpQ3dvVxRxUwn+1eRazV
         Ldit5fijk0ZVFk3LAEikCyba6Ra1Dh75LZWtwrueRtDDTjP4jlpuy9nlog7HQdYFe6jq
         d3uoCxuX7K1NInWUz/2AsdtYOOa5RvU6I/j+5+XivW25IP4qftznd1qSRFAqT6/oZiMe
         bAnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OFIttBl6;
       spf=pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y04PKl85rEiIjH5pGGmXuZPAhT7mxBNGDV7FsTn0Uq0=;
        b=qXD2JU3ggSSA9GcB3AbF7WSMS+6s4hD9HCeIS9oBt/eM/yABUTATgv47c8krlsueRO
         vcZbWEDVDvv2ZQJIA8Z5t7Zja/HIRjL6mMcYfQG2SZ2pemtW/XPICNCiKrOt6ABkOvNW
         vhUW1M6RK3PyvUjHjzF7bQRBIiaKLqRfXErvbWxKLqmvtypMaeP3E8uWyydh9z5wKeHs
         WuneaHeebnW+x0v2xqanv0VQ3fItsfB+zfZ0SrXi2ol4Srw5yEYJJVBlQdnY2+hHq5gT
         AczXbvg6MQW0p9FWIqDnVbRREP/5SqxgAMFaS8rej9wB+Ewr/QtXFYvuDHxLhcqBxwPx
         DO3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y04PKl85rEiIjH5pGGmXuZPAhT7mxBNGDV7FsTn0Uq0=;
        b=Ct8Q/dwwjD8fYgOLRWaMRoCpsgtWIaVFCTemCIrbAldzexCgcedKtVZcgQ99nslojV
         M9k7GYgI98Jvju7ibsEDhJWeJbVTsyAg4G3vSGJg7fBvQzypIO6ieVaD4HX7YszqRcEh
         OfMtiwRVKM36tILZ+efzx5M3SGso3AdGjoNFX17bIvCWazEbHFTWilVtAV64M9FbU4t2
         B3P10ekpeJ56M0KKam7JKpmzmiL/ytdCNc1V/Xi6WrZN/guPfITMW/KlXHuQySnZSpGO
         P/CYWGuUYJj0ScHiKtsXxpMoYmbffWSaNd2Qvqgxlz6rLnhF2iU11fDmQ0e7bTnyVdG/
         rOrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JViZs3JIuJO2ayJ5J7AoO2mtobwkKJ/vp8V9oUHK3eGfAo7VJ
	KONWXa4wISmo/LUvFhk5qH0=
X-Google-Smtp-Source: ABdhPJzscjCuFowTZ09tiT9YXWB3nu2PuPeKkctIw1Afyxbj07Ej8AmJZcDZbWwuwhVzrfwh3w6MSw==
X-Received: by 2002:a92:c6ca:: with SMTP id v10mr1599753ilm.78.1625051611344;
        Wed, 30 Jun 2021 04:13:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:33a6:: with SMTP id h38ls289400jav.11.gmail; Wed,
 30 Jun 2021 04:13:31 -0700 (PDT)
X-Received: by 2002:a05:6638:380b:: with SMTP id i11mr8306990jav.57.1625051611037;
        Wed, 30 Jun 2021 04:13:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625051611; cv=none;
        d=google.com; s=arc-20160816;
        b=tMZ4uZUNQ108uVca+7YaP54JzgKLSxL6SpT+g+N8uShC/YdLIaF9mtOK8Qv9/PBdH9
         MpHpv1iIq5CL5to0wcqsDiUj/oESKpYFxNIfiV7UrPWUcEaLzh0y3Eq/qstth1nkfEI+
         lUemJSam61O+xuHnJw+CZxUqiJj6T5P7glSpw3sbtOaA4ihoSyK4bf+iLv6CUTk7Y8tm
         sWJGt1zFHHV5IrOAnLxeDGgYE3vodJ+rFkJSvo9fg33Sag6RQTQ3Y/rvmfJOAPIdcXPe
         9CWbNGKP2a/imsuIQGLkwPCP+RFFCFqED7gKWS1hHKGvUMseiREShRMXm6zD9tRUuTEf
         OiAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wtjN3Md/HDsTchOR16eskClgAhrk26PnBhGXdpdYyVw=;
        b=iNghn3Lp1V1i4R9Lo4tTQBiXHynTh8baMYUsR8PhP9Wt3vcu9lVQpImIXqGFE7TiZN
         NYEdlvR2zUEuXJCNCDfcAn5ltNrpfl0Uqa0bXIuMuHT/9mEpLt8wozl+cMi1nIjB23hn
         mmDvhhvr0C9ddMCMrm4CHV0i8GVGNCSCk6ah/YdMvQNn6wEV8IgiRLmhyzHks/KkdZSN
         Xx6r9ud8WtBNAemQ/odLlGHywEHevYIn/IkIhNLP2TZ9HM/9jhhLn1ZqNOYpVHTntBcY
         7ljE4YgoiKEaXbOLfFr8sjiPkZFK/IxYFZXCFBDkBuVIOnFWsj75X8d6+V7eMwfis1mK
         9SNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OFIttBl6;
       spf=pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id w8si910494ioc.1.2021.06.30.04.13.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Jun 2021 04:13:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of omosnace@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yb1-f198.google.com (mail-yb1-f198.google.com
 [209.85.219.198]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-166-mU-G7lnDPjetNVPG2s8hug-1; Wed, 30 Jun 2021 07:13:26 -0400
X-MC-Unique: mU-G7lnDPjetNVPG2s8hug-1
Received: by mail-yb1-f198.google.com with SMTP id 132-20020a25158a0000b029055791ebe1e6so3346280ybv.20
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 04:13:26 -0700 (PDT)
X-Received: by 2002:a25:ed0d:: with SMTP id k13mr45134071ybh.439.1625051606340;
        Wed, 30 Jun 2021 04:13:26 -0700 (PDT)
X-Received: by 2002:a25:ed0d:: with SMTP id k13mr45134031ybh.439.1625051606119;
 Wed, 30 Jun 2021 04:13:26 -0700 (PDT)
MIME-Version: 1.0
References: <20210630093709.3612997-1-elver@google.com>
In-Reply-To: <20210630093709.3612997-1-elver@google.com>
From: Ondrej Mosnacek <omosnace@redhat.com>
Date: Wed, 30 Jun 2021 13:13:14 +0200
Message-ID: <CAFqZXNtaHyKjcOmh4_5AUfm0mek6Zx0V1TvN8BwHNK9Q7T3D8w@mail.gmail.com>
Subject: Re: [PATCH] perf: Require CAP_KILL if sigtrap is requested
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@kernel.org>, kasan-dev@googlegroups.com, 
	Linux kernel mailing list <linux-kernel@vger.kernel.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, 
	Linux Security Module list <linux-security-module@vger.kernel.org>, linux-perf-users@vger.kernel.org, 
	Eric Biederman <ebiederm@xmission.com>, Dmitry Vyukov <dvyukov@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: omosnace@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=OFIttBl6;
       spf=pass (google.com: domain of omosnace@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=omosnace@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Jun 30, 2021 at 11:38 AM Marco Elver <elver@google.com> wrote:
> If perf_event_open() is called with another task as target and
> perf_event_attr::sigtrap is set, and the target task's user does not
> match the calling user, also require the CAP_KILL capability.
>
> Otherwise, with the CAP_PERFMON capability alone it would be possible
> for a user to send SIGTRAP signals via perf events to another user's
> tasks. This could potentially result in those tasks being terminated if
> they cannot handle SIGTRAP signals.
>
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/capability.h |  5 +++++
>  kernel/events/core.c       | 13 ++++++++++++-
>  2 files changed, 17 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/capability.h b/include/linux/capability.h
> index 65efb74c3585..1c6be4743dbe 100644
> --- a/include/linux/capability.h
> +++ b/include/linux/capability.h
> @@ -264,6 +264,11 @@ static inline bool bpf_capable(void)
>         return capable(CAP_BPF) || capable(CAP_SYS_ADMIN);
>  }
>
> +static inline bool kill_capable(void)
> +{
> +       return capable(CAP_KILL) || capable(CAP_SYS_ADMIN);

Is it really necessary to fall back to CAP_SYS_ADMIN here? CAP_PERFMON
and CAP_BPF have been split off from CAP_SYS_ADMIN recently, so they
have it for backwards compatibility. You are adding a new restriction
for a very specific action, so I don't think the fallback is needed.

> +}
> +
>  static inline bool checkpoint_restore_ns_capable(struct user_namespace *ns)
>  {
>         return ns_capable(ns, CAP_CHECKPOINT_RESTORE) ||
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index fe88d6eea3c2..1ab4bc867531 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -12152,10 +12152,21 @@ SYSCALL_DEFINE5(perf_event_open,
>         }
>
>         if (task) {
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
> +                        * task. Require the current task to have CAP_KILL.
> +                        */
> +                       is_capable &= kill_capable();

Is it necessary to do all this dance just to call perfmon_capable()
first? Couldn't this be simply:

err = -EPERM;
if (attr.sigtrap && !capable(CAP_KILL))
        goto err_cred;

Also, looking at kill_ok_by_cred() in kernel/signal.c, would it
perhaps be more appropriate to do
ns_capable(__task_cred(task)->user_ns, CAP_KILL) instead? (There might
also need to be some careful locking around getting the target task's
creds - I'm not sure...)

> +               }
> +
>                 /*
>                  * Preserve ptrace permission check for backwards compatibility.
>                  *
> @@ -12165,7 +12176,7 @@ SYSCALL_DEFINE5(perf_event_open,
>                  * perf_event_exit_task() that could imply).
>                  */
>                 err = -EACCES;

BTW, shouldn't this (and several other such cases in this file...)
actually be EPERM, as is the norm for capability checks?

> -               if (!perfmon_capable() && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
> +               if (!is_capable && !ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
>                         goto err_cred;
>         }
>
> --
> 2.32.0.93.g670b81a890-goog
>

-- 
Ondrej Mosnacek
Software Engineer, Linux Security - SELinux kernel
Red Hat, Inc.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFqZXNtaHyKjcOmh4_5AUfm0mek6Zx0V1TvN8BwHNK9Q7T3D8w%40mail.gmail.com.

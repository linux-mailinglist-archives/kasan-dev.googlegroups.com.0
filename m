Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUON6GDAMGQE7AFN4QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C4353B8251
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 14:42:57 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id c15-20020a056000184fb0290124a352153csf898236wri.9
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 05:42:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625056977; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpJiI3cbft/cjAuGOol89HTa61QEfqVb5C9eO7p2967tflXykFwVFbU2UFSOSZrMCx
         1w9PFB+1KKx5+OpV3OXrBgrjWJ/vbxQw6iFWIQ4Qcm3YXnMBS3nErwVNZz+sLTwxvgbW
         sb1siWitxUttY+Vead0bG7T7b4eeENeeu17D3s2tBzsfhQXPscm/KLwqH4zJ7kZahqvR
         KUx1VPyTimmxTXT2Wf25y7xJUqA2hto3w3m1uj1s0XWdjpOW9ybDygElZIuK65DMhBX/
         Q4MJkMldtPQlvZ2Q0H2I+oVaA9QH9QzIcaWouOQJi4nf5m+8en2thnI/4atmpqNBWHTR
         h8Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1w0O8LoTFIqaORil/yi5GzVgQQcQhB5hFh4pBOJ5ti8=;
        b=CfC4PAyGoCE6PdC0eWQwqeRdvTWpF+9cIWVbJd7qh9SS2dNa6c+muWiiGfM+8a+4Mi
         tc6qwhc4RHRmcMzmkWUVjlcyw6K4kvM9rEMUlWF/jbRQGJ4VvI2h3YMo3qobSYLuISMl
         +d/PyZgEHz5rTuoknYyZ4U2dEVv8jbilhvV6dn3SsfgmkdHKsquqX9ueUs7sT4iLme3s
         rlxGgBctvzI0i2sQDXvPWmhXREEcQ18txkgPADKmWg/IfdDMVGfn2MudlpBD5l9Q0a4D
         IpbqNetPXrQA5/+TCE/wPZLJsa65uoQxlaZ0AyJoAEUqJlmCjWCkGFOnWPdXQG2zPXd6
         hKZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g8Vc9Hii;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1w0O8LoTFIqaORil/yi5GzVgQQcQhB5hFh4pBOJ5ti8=;
        b=qT7S7RFKPn5gtm0wytJ9lBmtxphQjOC3lfU+aWKPAxz1u5/JUZ/LTZMssBdmrKQBiC
         caBDcLsy3YbjHGsKu5piGk7jiEOEDIiGKAb7PfBaI6nLsIeYDLiND+sUH1P9Jb4oE+Rx
         ZxGzUg4+B4NOpXX4hC+gvmZhqKUIyrG2EpjeQXAaLKafuQjYdKW/bVSuzAXqA8RFax4p
         vByj7iw+h0GhiO6/+kW+SuUE+bnRTB3PrrbwlUEFHqgWrjCdKDCBOQFXW7eIsnb9Uuca
         8oVK7rz4IYEiuT03yQE2tUDZZbtBnFcjhTEdLV5O487VGLXiorASm9FCmddZ5apU9WMi
         62VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1w0O8LoTFIqaORil/yi5GzVgQQcQhB5hFh4pBOJ5ti8=;
        b=SC0aTET2wnggvcmHPH0kjKK1lcz7fnSqC7ywGTuH3JIsxcq1GTZtYEm7nbnZdulR7a
         hy0PZP+QrY9vkF7MuBfwY7M9QOYTaNKOCjpFxPd+bpg1CxTfW9v98795EMr/54qa2PtD
         K9FiMtzfnTtM21ZIk/bVpARNNEqHBaOwzjAloI1zTueocV2ofi2PwB0NH3bgosAsU15m
         1/IGXuR8X4ZJZQZ53uHUtQtb1FKB76Rya+jZou0JbLsM+T7quFyAEqoIrf+XhNLknw1z
         vWCV37hCCfJqBahWEyxNiWgE2FPohSwcFq196F+w4k0SLS1Jxideihdny5I2rR39XqZ6
         SkXw==
X-Gm-Message-State: AOAM531AVE16jIV57Re/7qHzMl+2e9BVco1yBsUY5jz1seeskcd/bsIJ
	yRiFYZ5ITs/42vSabw0fOZc=
X-Google-Smtp-Source: ABdhPJyj9E07Pde/w4G4A3lYq+wx/CFx4x5ll0TQOSNcfXVgiUFJXrR+mnNk8236jMFvKIKUHqGoIA==
X-Received: by 2002:adf:fa4c:: with SMTP id y12mr762334wrr.302.1625056977291;
        Wed, 30 Jun 2021 05:42:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:: with SMTP id i4ls3677315wmq.1.canary-gmail;
 Wed, 30 Jun 2021 05:42:56 -0700 (PDT)
X-Received: by 2002:a05:600c:2116:: with SMTP id u22mr37740899wml.179.1625056976272;
        Wed, 30 Jun 2021 05:42:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625056976; cv=none;
        d=google.com; s=arc-20160816;
        b=Y0+wPC9aDZI1PYEyGa5J/mvrH+fN2/eCJYSV1UwDi1F08WfxuLkN48byz4jA1TJmey
         xKLNM0y6EmTuELP04Ytmtc4DDkDSFsZf3pHP653+UNpBzeSJ9mWcU4JmVkQxSAj6fBjA
         +pRtTKmxwzT6rUYEqIyGJHxpu0XxVgnI2qZBMbotOd1OnGnUNDJPaKRkT0/UTztQKXY5
         3zZJsnLdx+HztZ9CEjiqUslDYyA5b2gIpP9G3w+2qniIHCE4/O2pC1x9221fTs03830q
         f476ZTSSIoiNmYtMPywiJFpebPfhc83mslwDd/dTkOBaPtOZMp5oNs3S282Ya9Xs+z0M
         bqMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GH3eDDlIhhzC5YYUSXzbXcyeMUM12l/VQtqBde75cxY=;
        b=rJHorsAoPh5cZUf3/AAOdCQvkyBGp1NKnv8lVn8w++NzKY7ErmMIKLfqPlCkmiy8Ky
         orp0JouGfEkhW6WCZDP0YpQu+ANdy4VUJnuEcYdPthuI62t8jeYjiGFdvOz+JgQ2JbZC
         QI0eG1RVWwNWlj+nNhIgSv8A/EPb209HbrZY3yiztWgY407OOOa8VDrJ2mO8NeqzQqtW
         PM5Sp0zEIrjJu7TIEwUn3xBYdiJreWkzM/3YYybWQZ5HhH24Mv3FBIZa+aE2nQi9xVIe
         tWEeUYLLDJ5hsLZWZvxAEIBLCV4FgeIWjq/LG0DnvShVk35J2Rc/80AGWPZ7m0D90eIh
         ypJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g8Vc9Hii;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id h15si580262wru.3.2021.06.30.05.42.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 05:42:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id f14so3099375wrs.6
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 05:42:56 -0700 (PDT)
X-Received: by 2002:a5d:65c1:: with SMTP id e1mr40845057wrw.196.1625056975754;
        Wed, 30 Jun 2021 05:42:55 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:8b0e:c57f:ff29:7e4])
        by smtp.gmail.com with ESMTPSA id r16sm13220921wrx.63.2021.06.30.05.42.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jun 2021 05:42:54 -0700 (PDT)
Date: Wed, 30 Jun 2021 14:42:49 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ondrej Mosnacek <omosnace@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, kasan-dev@googlegroups.com,
	Linux kernel mailing list <linux-kernel@vger.kernel.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Linux Security Module list <linux-security-module@vger.kernel.org>,
	linux-perf-users@vger.kernel.org,
	Eric Biederman <ebiederm@xmission.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Require CAP_KILL if sigtrap is requested
Message-ID: <YNxmyRYcs/R/8zry@elver.google.com>
References: <20210630093709.3612997-1-elver@google.com>
 <CAFqZXNtaHyKjcOmh4_5AUfm0mek6Zx0V1TvN8BwHNK9Q7T3D8w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAFqZXNtaHyKjcOmh4_5AUfm0mek6Zx0V1TvN8BwHNK9Q7T3D8w@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g8Vc9Hii;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as
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

On Wed, Jun 30, 2021 at 01:13PM +0200, Ondrej Mosnacek wrote:
> On Wed, Jun 30, 2021 at 11:38 AM Marco Elver <elver@google.com> wrote:
[...]
> > +static inline bool kill_capable(void)
> > +{
> > +       return capable(CAP_KILL) || capable(CAP_SYS_ADMIN);
> 
> Is it really necessary to fall back to CAP_SYS_ADMIN here? CAP_PERFMON
> and CAP_BPF have been split off from CAP_SYS_ADMIN recently, so they
> have it for backwards compatibility. You are adding a new restriction
> for a very specific action, so I don't think the fallback is needed.

That means someone having CAP_SYS_ADMIN, but not CAP_KILL, can't perform
the desired action. Is this what you'd like?

If so, I'll just remove the wrapper, and call capable(CAP_KILL)
directly.

> > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > index fe88d6eea3c2..1ab4bc867531 100644
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -12152,10 +12152,21 @@ SYSCALL_DEFINE5(perf_event_open,
> >         }
> >
> >         if (task) {
> > +               bool is_capable;
> > +
> >                 err = down_read_interruptible(&task->signal->exec_update_lock);
> >                 if (err)
> >                         goto err_file;
> >
> > +               is_capable = perfmon_capable();
> > +               if (attr.sigtrap) {
> > +                       /*
> > +                        * perf_event_attr::sigtrap sends signals to the other
> > +                        * task. Require the current task to have CAP_KILL.
> > +                        */
> > +                       is_capable &= kill_capable();
> 
> Is it necessary to do all this dance just to call perfmon_capable()
> first? Couldn't this be simply:
> 
> err = -EPERM;
> if (attr.sigtrap && !capable(CAP_KILL))
>         goto err_cred;

Not so much about perfmon_capable() but about the ptrace_may_access()
check. The condition here is supposed to be:

	want CAP_PERFMON and (CAP_KILL if sigtrap)
		OR
        want ptrace access (which includes a check for same thread-group and uid)

If we did what you propose, then the ptrace check is effectively ignored
if attr.sigtrap, and that's not what we want.

There are lots of other ways of writing the same thing, but it should
also remain readable and sticking it all into the same condition is not
readable.

> Also, looking at kill_ok_by_cred() in kernel/signal.c, would it
> perhaps be more appropriate to do
> ns_capable(__task_cred(task)->user_ns, CAP_KILL) instead? (There might
> also need to be some careful locking around getting the target task's
> creds - I'm not sure...)
 
That might make sense. AFAIK, the locking is already in place via
exec_update_lock. Let me investigate.

> > +               }
> > +
> >                 /*
> >                  * Preserve ptrace permission check for backwards compatibility.
> >                  *
> > @@ -12165,7 +12176,7 @@ SYSCALL_DEFINE5(perf_event_open,
> >                  * perf_event_exit_task() that could imply).
> >                  */
> >                 err = -EACCES;
> 
> BTW, shouldn't this (and several other such cases in this file...)
> actually be EPERM, as is the norm for capability checks?

I'm not a perf maintainer, so I can't give you a definitive answer.
But, this would change the ABI, so I don't think it's realistic to
request this change at this point unfortunately.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNxmyRYcs/R/8zry%40elver.google.com.

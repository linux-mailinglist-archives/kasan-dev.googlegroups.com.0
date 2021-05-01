Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2PCWSCAMGQEGDB2NNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3C093706EB
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:46:02 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id x15-20020a9d6d8f0000b02902a57c3fcd37sf788534otp.17
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:46:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619865961; cv=pass;
        d=google.com; s=arc-20160816;
        b=yxb13qjAhWvk9MEI2Xj+NSw51XML549nrce7fipkWckuQ468DPyPsKO04W1v7uK8OQ
         iUVjn9xj6Jg1OI9z46jw2nucFBYB6zYkqUHZ9z/t5qd5E9AkrR22P7TvL64FmGltBT0D
         xWsbOQP3KrHsLdLNd76DdYdwNE7SwoNfB0/s2bLJDy0SoFP3eTWnd/4AZb3pOQV7jVwJ
         F7oiiGZW4hFmY+500APtniYvEk8MXK0qH3YWSyDCCwmx5P/NzPKyw1CkUmm9ITyiiUSr
         2+bHqatlrMz7yi/Hcm7POxnVfXk4HFSNHZmRotWQ9K5AmCoomXnptw7ckD/g7Cp1Xja9
         VcVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ctZfCapQaN0gtZV3R9Af3dAZ6IpHo/baNvx3fhvOpGg=;
        b=RJ9v/S10YOUha4ura0ZUdc2ZB/WSap9A3Mk59qy0YExs/q5qCs76OEo6BqvedDoKFv
         eh5SukOw34XqqTYOUNmrJTF9SI9+Xt+Za0SaD1zZ7tUqFX7B33CSWlIutGDV9qm9j6vi
         tNA9P6YiAIt5DSievkZAbsvNYeEYDWT7eKTct55yeZLfJlL9kqiEbvDvbe0TgIXF+FI/
         qMOYy4djO5BFky3k1NfAYUMLZjI7wLRX/4nDW2KMY3Fo7E2LLs6334OhprwdKx/Y60Iq
         xBv5qhq4Y+/GO/fLj5ZwO124Z+YwJfF43nvmrzOqQT3KUFC74WXPd/GDVJDp6PV4uo5v
         ENEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IMwXPYTH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ctZfCapQaN0gtZV3R9Af3dAZ6IpHo/baNvx3fhvOpGg=;
        b=MZT137TVvK4teWRK51UJ5nWPRW2he+mZeGbD9CfbKlprYhX9jX+2mREotR0wes03GC
         OQ3PLz0SWqAd9qN+TaMLOHyk2wiRCy2KYZGCXHoPQmmuory0uUovrIq+JoEOqQhDPmAN
         nHQmiZFRIlpQ7vUGMbEV+JD1w4fpOIVv4cBKPwIz5fTJA4bWRSo7scMDcgPgCaryk1XO
         DxS1nd04R64zT1VHEvkQHG4gg8nVG5pYb9yu4ybUVntb3DFkHnL8RDu7RSDuwwr5uhcS
         AX8rYlJnvFJUbogdBghU0S8VruTy+VS9466WzfyEompJGijOl1byCkeBJWKDPGmn3oJr
         yDHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ctZfCapQaN0gtZV3R9Af3dAZ6IpHo/baNvx3fhvOpGg=;
        b=dW3g2EaiWvUNGxN8a4R82gnaKkfu+2Bcj8I9W1x1Bx1wtVODA6NsLoueWUyCYnCTFh
         m/hY32xE/KFU9hVcBkr7wcdHgUeoAw9fUlutN9IIw2AcDMxE+gCALoTh3oWaJIjleWB8
         c7kn4K2LB+VbHAQqL9yEGrPiQTxORP58BuxwUFPQAm93lbBa/FfO8fZzHGZ1LzhUzqiR
         w7BxVSHYLwQC4HLEQ0WoP9h4OTQMN9Fcj89gSYzWLdZng9HWmdrw4Okuv1Ejcf/qQ4L7
         nBw2Z5wiRXnkLnOvVL+Lem8Y/9jZcYF2jSEMtv2OrLzp1ejmDfG5gRxggf1W0SQlF534
         b1Vg==
X-Gm-Message-State: AOAM530REGRyvyIsbX4L87fKfXB4aVfZuCxGWXNHRBhGbfIVRSqLRQwX
	lGFUhROBK+UATlgP9su5U2M=
X-Google-Smtp-Source: ABdhPJwGXFPvoXV8vg7wZwdYH6sJP2rbYY4Mc8gZE14AGKu6N4RMi+clgtuKJ9lOIkXXc0Nrpbv7Ow==
X-Received: by 2002:a05:6808:b3b:: with SMTP id t27mr7256288oij.131.1619865961751;
        Sat, 01 May 2021 03:46:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:760d:: with SMTP id k13ls2456703otl.9.gmail; Sat, 01 May
 2021 03:46:01 -0700 (PDT)
X-Received: by 2002:a9d:3e1b:: with SMTP id a27mr7509534otd.101.1619865961389;
        Sat, 01 May 2021 03:46:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619865961; cv=none;
        d=google.com; s=arc-20160816;
        b=js7nVRItQKbMledhcNYT3Yb+PUZ6eccRzeiJlI5elOHYrqHHK8n5APVa4Sw91CW27Q
         d5Gyb+rRPGtzsT6TItKIHO55tMB3kRHdU1rMzKHtK9UTKh+jyGrRT1SDDuzWfm/R3NM+
         +WAyZ+awaJxjRfBrdTDUwnew5t8tzOLwObBSLNK+r9IV74clTXTmZvB8lBhCs2w+40Nz
         +rSV0zX7/nanGpWrMIMmDi9PdhXMje+9Q2Olki4f47zCCY/X8+3317Z3l/NH3gXN+rs7
         rPT4gFAdw94ME+3GeGR2ZkbumxQz7JBqcq2NqHNqwLzuK/qz2HsN+/rJJr3WhlbsknD3
         DV1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dER8WYp4YE8meKl/Etoz17guMOCTTHD//33hX1fp/nc=;
        b=llMj6qs8a9XUhcAj+tfmonQYIpBslbHkDhKDArrojP8D1Q/bSnQvq0IYiGnv5UlOJl
         65yds4ClBbc4z8G5QZNLyV4iYpWV9isD/rgB9xJmx3NeYoEkVMelIdzi3yuEgnKvqOYr
         6GgUKx8vmdjKQT8DcNAf6xap9hOvGUls1gYL96+Mov1ZoQmxGB3ERAYD+kM9ud4q6sXl
         dIIqS5y53ljN6ZhC+ZIDeL7TLKN+u4/HhgvUhnSOQJAZD1UlXUlstfPTIrH3XnczAN9A
         BMDEhC88DdQqn8h0ggK0pd+dzMGTeaq9R6ZKH6ueqn+gZwzuNucTsLyrxlnLU3NsKt8H
         nxjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IMwXPYTH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2c.google.com (mail-oo1-xc2c.google.com. [2607:f8b0:4864:20::c2c])
        by gmr-mx.google.com with ESMTPS id l24si783830otd.5.2021.05.01.03.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:46:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) client-ip=2607:f8b0:4864:20::c2c;
Received: by mail-oo1-xc2c.google.com with SMTP id c12-20020a4ae24c0000b02901bad05f40e4so200031oot.4
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:46:01 -0700 (PDT)
X-Received: by 2002:a4a:3511:: with SMTP id l17mr7963113ooa.36.1619865960952;
 Sat, 01 May 2021 03:46:00 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m17dkjqqxz.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m17dkjqqxz.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:45:49 +0200
Message-ID: <CANpmjNP32SRsnJBBfhjX63fcMyPAMgj8VDuMPdJXeut_+g2x_A@mail.gmail.com>
Subject: Re: [PATCH 6/3] signal: Factor force_sig_perf out of perf_sigtrap
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IMwXPYTH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as
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

On Sat, 1 May 2021 at 01:43, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Separate generating the signal from deciding it needs to be sent.
>
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---
>  include/linux/sched/signal.h |  1 +
>  kernel/events/core.c         | 11 ++---------
>  kernel/signal.c              | 13 +++++++++++++
>  3 files changed, 16 insertions(+), 9 deletions(-)
>
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index 7daa425f3055..1e2f61a1a512 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -318,6 +318,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
>
>  int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
>  int force_sig_pkuerr(void __user *addr, u32 pkey);
> +int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
>
>  int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
>  int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 928b166d888e..48ea8863183b 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6394,8 +6394,6 @@ void perf_event_wakeup(struct perf_event *event)
>
>  static void perf_sigtrap(struct perf_event *event)
>  {
> -       struct kernel_siginfo info;
> -
>         /*
>          * We'd expect this to only occur if the irq_work is delayed and either
>          * ctx->task or current has changed in the meantime. This can be the
> @@ -6410,13 +6408,8 @@ static void perf_sigtrap(struct perf_event *event)
>         if (current->flags & PF_EXITING)
>                 return;
>
> -       clear_siginfo(&info);
> -       info.si_signo = SIGTRAP;
> -       info.si_code = TRAP_PERF;
> -       info.si_errno = event->attr.type;
> -       info.si_perf = event->attr.sig_data;
> -       info.si_addr = (void __user *)event->pending_addr;
> -       force_sig_info(&info);
> +       force_sig_perf((void __user *)event->pending_addr,
> +                      event->attr.type, event->attr.sig_data);
>  }
>
>  static void perf_pending_event_disable(struct perf_event *event)
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 690921960d8b..5b1ad7f080ab 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1753,6 +1753,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
>  }
>  #endif
>
> +int force_sig_perf(void __user *pending_addr, u32 type, u64 sig_data)

s/pending_addr/addr/

to match force_sig_perf() declaration.

> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = SIGTRAP;
> +       info.si_errno = type;
> +       info.si_code  = TRAP_PERF;
> +       info.si_addr  = pending_addr;
> +       info.si_perf  = sig_data;
> +       return force_sig_info(&info);
> +}
> +
>  #if IS_ENABLED(SPARC)
>  int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
>  {
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP32SRsnJBBfhjX63fcMyPAMgj8VDuMPdJXeut_%2Bg2x_A%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NKZOCAMGQEWJBMGJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB0B374379
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:27:22 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id f12-20020a056e0204ccb02901613aa15edfsf2175231ils.5
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235641; cv=pass;
        d=google.com; s=arc-20160816;
        b=skGrW+sdOhtbbyLePaN2ioOifnbyseVMAhzQvR/qaBsq8N0bKalro7KQ3D9pCh2izX
         lDz3zkjIx1Z2bVJKudCaoOc/7jtnQFJTWP27Ee6iwmUMOyPMaZDxNpM8ofm89wIrjakh
         JZy8EviSeMvRdNVI6gGQfgQVs/o2dmpG3Cmjxl55iohFSi8rcdWwIAsCDAlIdX4w/dVD
         omVisWyKCity8AQ+vJhBMRGXkPTLYfY5asuZ0RnPZkZuWfAPWIl4fXrQx7ZZfbmQYEsG
         cdYMg7kwjnmebHQ5Aa0Yca4qTS5F1DxGQXilOYSsMmagtSBfUzGoS8rvZ4BPyxsJwCxb
         hFDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MA+pku89KqkOLEhs0b8bbXz22Z7zyxlb4GiqIIcQVmM=;
        b=gbRorhEZdTlwfkOESJ1WVAWBhuuHOOQIQOj5AbRm4Y/twmWkiqEWLEeQjekcVAZIkt
         3OrXfU6DV3C+XA1B1KRQlDGusN7hUsO7htQx7p7+YA6MNxBqoFMX/A7NdnWCA2JeE+Ig
         go6tcu3oDfl4s8gMYonCPeeQGWBdqxLAN0BEZ5hS+y9jqxekSjA9EvLVmTBGZl+UWeeV
         +tm6VTSE8xGRJg6QUslr4RTNmm0zs4U6sXpjEmN1J6LYOtdtgvl2PUcAOmT1WOWAssYG
         Y6Mql7xc6Jbq59bxZ9G398vyPAq0/WL34ckh0OXug2kAgWk1Vt5fDExKDuKMQ0eqETJ2
         NG2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Esk6Xw2g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MA+pku89KqkOLEhs0b8bbXz22Z7zyxlb4GiqIIcQVmM=;
        b=sIs1ofxrz4Zi2OwTVq3Q639pixP8VP+KIva/r2AlqcO5r9CsBB86lcI9suoyUTOP64
         SLoI5daFywY6iMnmFsDtL0cpHtUG3euaCIhcqZHT7vEl9jyjMkH2DOfIE1ngNaGzZ/dw
         h8Gdb+5y/3dRHDnpGvxgYoKxlb5xVeRO/WHB9t78KGuVkmjYoWcMyXLuU7BqpM7/trOw
         9pfVqyMP/uKEHqTbBGp335bQzJNXtYTN6ErUVms0TDcJBokrYccb2LgMRmfiH/LDlj0k
         KELaVBJIcT3cNig/OJoCWyirqcEVQMlJYR0BM/plv9Jt/bYil7vOfubFP57g2kcpH61Q
         zU5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MA+pku89KqkOLEhs0b8bbXz22Z7zyxlb4GiqIIcQVmM=;
        b=k8ksLRAcr92dRUvbS58KcriAthJUigbZ2KPacJRcIy/iqo+boAL0cnpmxOoEm7ElN0
         rzgF4UBbxOLNT7flbHPn4fz2sB1JVn70w5GFV5XEJwo49HenRKzxWhOVjw6k8rDpM4MC
         Y4T39OGB7AAqWQFZ9sXMeiLynu4fRTHMIvV3ZbJucUi6xwNPkolz0K0Y7BjSTb7qix5q
         uWotkOqz8nDHP/RfgDLXWHRZLgLlGxelukp1Rg8rS6c7hjCqPyuUAkSns/r2ZcAlwgBC
         QL25BRzHtGVufkcfF89Vn/fI4fjgbY1ZpE2aD1KgLssmphm69G6cI1VhIfKuGmJ21l1R
         rz7w==
X-Gm-Message-State: AOAM5329OMssar6xlcEsb22sFa/0ruaFe8kfm7qQ6lCzwvDae0nW6GUy
	9sysJ0NMX8EFBAUoY2jTuCI=
X-Google-Smtp-Source: ABdhPJxX+YyR87TYbvt1n6y0CoNJMvQGsDnf4SfDMxHWdtvo0fnywYTQndF8h2z1bUq1tJakdkRYcA==
X-Received: by 2002:a05:6638:1650:: with SMTP id a16mr29456359jat.23.1620235641625;
        Wed, 05 May 2021 10:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7083:: with SMTP id f125ls1469681jac.7.gmail; Wed, 05
 May 2021 10:27:21 -0700 (PDT)
X-Received: by 2002:a02:ce9a:: with SMTP id y26mr19763481jaq.8.1620235641103;
        Wed, 05 May 2021 10:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235641; cv=none;
        d=google.com; s=arc-20160816;
        b=uWfj1uI9ioQvphO/p99Pb7PXeAG1TvpY7NnNRd0BGRDK60EEhsmx8EQ7/Aa8TdaBlH
         NdPnQZN8C21QZ58/APFau7JTQ8t53A3yXo2PB6yVe7VE8a6nSIa75AOmef0+mBqLCDiZ
         lfDsmbr6FA/9S4ec6jpTdI+KM++u3SnPyEezU3yogqQZ1ZzRgTO2ZvNBx07RTfxcKTbU
         5QxQ7Frwq3LWGDJVhvr1WojQ2vCmzkV6ZaPSMWUWiCsi+v5q/YPhmJQlBJeUY/BdfF9V
         fhqyrFzYjlma4+zr5hx7OyY4rQXcE2If5eOOGXIF5V6ILGMLaW9WxTZvfO4hahJ0DtIK
         tMTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7JIG5LLXWdpg9zojMMRRLnT8KwKVn0+Fa9SXUYjSITY=;
        b=XCkTHsZI42It8i78QfzLWlxJjRx8nOujQSHemlehmWKmKPwvGmxawnInIZs/6Iaq1G
         4EI2Kqsvay5TH3QKk6Lk6UZnu3Y+SOVY8aC8cP62xLEzq3TibRkDqTEYTcG5URiOOUh4
         I8O3w9ceGwc/m+zo3Yl+VW/cebfHW9Dxln8SwmkercQKw3lIDch1YXzSNOV9o9PghUTA
         dLZaFeXxc5TeY2wWgkTBlHHgIxPyU7TaULDsE7L7EKFXUqPoPTobpy0lbuv8zeSbFH/s
         nZSq47liTeCxp1xqYhheuTJL7EScMCyhcP+sIiFMjIrZRpqTl1m3satI6p7l8QIPGSuo
         1K6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Esk6Xw2g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id s14si658939ilu.3.2021.05.05.10.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id g4-20020a9d6b040000b029029debbbb3ecso2380095otp.7
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:27:21 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr25558136otn.233.1620235640677;
 Wed, 05 May 2021 10:27:20 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-10-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-10-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:26:00 +0200
Message-ID: <CANpmjNPS_mCs3_5boGrVwnUmC4szG8dudvPqjAMcrM7JSYWvLw@mail.gmail.com>
Subject: Re: [PATCH v3 10/12] signal: Factor force_sig_perf out of perf_sigtrap
To: "Eric W. Beiderman" <ebiederm@xmission.com>
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
 header.i=@google.com header.s=20161025 header.b=Esk6Xw2g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Separate generating the signal from deciding it needs to be sent.
>
> v1: https://lkml.kernel.org/r/m17dkjqqxz.fsf_-_@fess.ebiederm.org
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>


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
> index 697c5fe58db8..49560ceac048 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1753,6 +1753,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
>  }
>  #endif
>
> +int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = SIGTRAP;
> +       info.si_errno = type;
> +       info.si_code  = TRAP_PERF;
> +       info.si_addr  = addr;
> +       info.si_perf  = sig_data;
> +       return force_sig_info(&info);
> +}
> +
>  #if IS_ENABLED(CONFIG_SPARC)
>  int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
>  {
> --
> 2.30.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPS_mCs3_5boGrVwnUmC4szG8dudvPqjAMcrM7JSYWvLw%40mail.gmail.com.

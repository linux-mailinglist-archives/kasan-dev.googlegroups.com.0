Return-Path: <kasan-dev+bncBC7OBJGL2MHBB65KZOCAMGQESNIUYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64E6F37437A
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:27:24 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id d201-20020ae9efd20000b02902e9e9d8d9dcsf1644772qkg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:27:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235643; cv=pass;
        d=google.com; s=arc-20160816;
        b=j2urqeiRw0VJUAwFmaa0noT7FwLgC+dsuoaKv1g+d9AwGBkknWHLEzP2JHQrz+gP67
         UmvenIAC7UIIovz8sfoR3dYoJhMlz2ITHG7d4ma/tjIkhT2nVKxL3O8V6kDOL4C1da2M
         AyXV5lrVKdv74d97j3ctUbEL5Xf2SmQh53r9r6JHJZQn20MFCVohGGYA5g8jZq6KEMu2
         7Wi7lYcP4MIopwzP6BpCM948png+YILvgg+cQdRrRU2d8PFDRMIibtVcUbzk9kIwwR2v
         bM8VscimZyFR0mtrnMLBgrtPANYnxw+wMKTZVxgUcEAMwcN32CAidQtAUr85QqNXXKMa
         ITGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xhb4bGpYyd1+mniaNIqkQxi3BNyUHGUzeja9aaPmAM4=;
        b=DPK9bkilUVeaJEEGjjPb5cO9LTg2daxGo7WpdoGLnErzzVgn3F9S4xwGmXw1mmDgQI
         E7ed4aO/0449I/V8FPzq+zlwKcIhP+2ctU/aw5HHnkThXIFBLfsJO+C07PZmo5LGE4HY
         LX6YjVu5F7vqAQTj3+gCZwYdL+GTm2YK+8qSCkpN2lhI95CFveFn57z2BU/tuu3zKZjS
         xbp/QQ+wHoqYFkuLWoVIWtJXFyJXgXsWSzbQ96moQclyhyp+E6RE+Yq56wraQAXyU0tu
         BYIm9XiEz1/aWDgM9FgD+LJbjnpn01j1d1O91OJSmED7RKCNlE5gpxonyrxo01SLwXSH
         ga4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="EcCh/rMi";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xhb4bGpYyd1+mniaNIqkQxi3BNyUHGUzeja9aaPmAM4=;
        b=dTEOZiMm/9ej2sjUnfIVXk/y8qAbLpEkp2LjC2XeyyitdZjAyocLHk16e3elfQkZe+
         uRWjqIARCjC3nZXbi2qVxX38uapFbUVIcZh/DPmIeNmBezxNQxjGUz38KqGcqQmx9eh3
         cz9/ZFpu2xyroGtmjGsSDRb85rsN2EznAtdE5Fw+mrjGk5M45n/WXAOD1qKC042M0pf6
         1+oTaYzYqBEAncBsQ+FOYhvV3hJxOdTCndBc4hRzxJtsBfpbYKeqWyqzzfTbt7omS0e0
         cALum5tMST7jKNLc2hKntIBmlY7GULCXr/Tr1+kr7LyGUB1hRPDGCMWQWoXl3MtK5A3D
         0n0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xhb4bGpYyd1+mniaNIqkQxi3BNyUHGUzeja9aaPmAM4=;
        b=Cem3iFBOMkB5K+zoHnes0zDztaorsWbJWbWjLJSPDpGs3KLgsdHKpHNNh3Sbh6GPyw
         W/SVK1QoEN0H4Hz1G+5dG6YSgT1zslc3ZbdcWLDH/xZGz6sh5s/4cZIiLjch2qjLSMno
         udYBh6trldeEj7t6wZg7YzpPN+witIEqVh8YNbnk4AXWcoxeK8QiQKS2kkH/pnX3/2E1
         9j4qQ/EtqsD9GeNrPMju6dkZBy+rEwc9AEKOxXE1YiBvcoss9K3B//poGWV5hkNp/xaz
         ho+LCGky1NG5jBsXDx3x4wIZ1puyoRiGGS0NSmwZmQ3Dwsa3N/USXpT5JsTVmqpmQ/SM
         37qQ==
X-Gm-Message-State: AOAM531BnzGHw5vDb6sU6JbcfMOWRRuCtd8DHGtBTTWdJCWEjuxTLrtF
	rx03Xw/pyFo6BH1SertKp94=
X-Google-Smtp-Source: ABdhPJxXoIpdPtxs+Qe6oLqXao5D8ljzt1z5AixuK5dRywNNHGV9tlvnRtwOA6fDqSDWyrjfopXFbg==
X-Received: by 2002:a05:620a:1344:: with SMTP id c4mr7583707qkl.489.1620235643550;
        Wed, 05 May 2021 10:27:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4d44:: with SMTP id m4ls5073190qvm.1.gmail; Wed, 05 May
 2021 10:27:23 -0700 (PDT)
X-Received: by 2002:ad4:4441:: with SMTP id l1mr6638qvt.1.1620235643075;
        Wed, 05 May 2021 10:27:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235643; cv=none;
        d=google.com; s=arc-20160816;
        b=a3uczBtT+TIghlwDcZHKs74OAz0xhXKQAGpn1dscB3A46LBbYlN77TYw5wj9SFFGys
         uiTsJrQNAwtJMrMi2XECkJC1ABwHXYvNESgE+DB+t4DiszxsiIBelgdHkzphEtkez4vh
         TrzM6Limi8iqnFUYLTTM+sFgi0K56y8GwXxdyZv97nz7S4ChM5iLw0I6i54TMjZS9hZd
         70VI0Gh26mnTOpK5eFL79PA7H1tewg7NHJxIum5xrdpKq+VdoNSQAO0EdFVub2sv0pft
         6yFHhJlU8u+hbTKx46faunPe5O+nncz7EkWndnreKGLK2U7aT8bhFi0RN7vnq6qzM8D0
         qsew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M03sKOxWmfO4zIIvVJvRTj0HkcVDUTsP1sbeJa/EAZM=;
        b=PZIM5xQuq3UHoIpvPgRaM8hP8KwEOnmAQ4ndBmdJRuPpChjRSuyzo4d1qOvYZjOFmw
         pEnVCAgcU9JMQ9cEB3NE9HpJLTlvenbMYiQtOEJaouLjVUPZLoeHdk+GRd33q1Fd7mxm
         Gmy7csFsBxImVhjx1yDwf2WgpTEq+7kXEXC0RgVNpMkT8+nZsZuLPlkQxjTcnN2Hs7LK
         F/CvlGqG5+HibOgnzhPQM3sBS8mTOZZoCQIO6NGzuqup4LDKJYgocz+P7qhvnn20FehJ
         HlwfcqCZ7X2MP5ZidM1q8mUJF4ifiFk+UmROj7SvtdMXe+IQqW8dbmLu8KSLnzwRDzuB
         Wqqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="EcCh/rMi";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id c26si6629qtq.1.2021.05.05.10.27.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:27:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id q7-20020a9d57870000b02902a5c2bd8c17so2399160oth.5
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:27:23 -0700 (PDT)
X-Received: by 2002:a05:6830:410e:: with SMTP id w14mr23870964ott.251.1620235642416;
 Wed, 05 May 2021 10:27:22 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-9-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-9-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:26:00 +0200
Message-ID: <CANpmjNPmPWymJ9ZsQWys9wC3okt5M5fj7edp7ejk8RpTTMsxew@mail.gmail.com>
Subject: Re: [PATCH v3 09/12] signal: Rename SIL_PERF_EVENT
 SIL_FAULT_PERF_EVENT for consistency
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
 header.i=@google.com header.s=20161025 header.b="EcCh/rMi";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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
> It helps to know which part of the siginfo structure the siginfo_layout
> value is talking about.
>
> v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
> Acked-by: Marco Elver <elver@google.com>
> Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>



> ---
>  fs/signalfd.c          |  2 +-
>  include/linux/signal.h |  2 +-
>  kernel/signal.c        | 10 +++++-----
>  3 files changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index e87e59581653..83130244f653 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -132,7 +132,7 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_perf = kinfo->si_perf;
>                 break;
> diff --git a/include/linux/signal.h b/include/linux/signal.h
> index 5160fd45e5ca..ed896d790e46 100644
> --- a/include/linux/signal.h
> +++ b/include/linux/signal.h
> @@ -44,7 +44,7 @@ enum siginfo_layout {
>         SIL_FAULT_MCEERR,
>         SIL_FAULT_BNDERR,
>         SIL_FAULT_PKUERR,
> -       SIL_PERF_EVENT,
> +       SIL_FAULT_PERF_EVENT,
>         SIL_CHLD,
>         SIL_RT,
>         SIL_SYS,
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 7eaa8d84db4c..697c5fe58db8 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1198,7 +1198,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>         case SIL_SYS:
>                 ret = false;
>                 break;
> @@ -2553,7 +2553,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 ksig->info.si_addr = arch_untagged_si_addr(
>                         ksig->info.si_addr, ksig->sig, ksig->info.si_code);
>                 break;
> @@ -3243,7 +3243,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                                 layout = SIL_FAULT_PKUERR;
>  #endif
>                         else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
> -                               layout = SIL_PERF_EVENT;
> +                               layout = SIL_FAULT_PERF_EVENT;
>                 }
>                 else if (si_code <= NSIGPOLL)
>                         layout = SIL_POLL;
> @@ -3365,7 +3365,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_pkey = from->si_pkey;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_perf = from->si_perf;
>                 break;
> @@ -3441,7 +3441,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 to->si_addr = compat_ptr(from->si_addr);
>                 to->si_pkey = from->si_pkey;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = compat_ptr(from->si_addr);
>                 to->si_perf = from->si_perf;
>                 break;
> --
> 2.30.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-9-ebiederm%40xmission.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPmPWymJ9ZsQWys9wC3okt5M5fj7edp7ejk8RpTTMsxew%40mail.gmail.com.

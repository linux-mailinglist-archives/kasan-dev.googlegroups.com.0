Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRPDWSCAMGQEJYAQH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E7EDC3706F0
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:47:34 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id g134-20020a1f9d8c0000b02901e488c819edsf201563vke.7
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:47:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619866054; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHODCCwUYKFwh973Qv1Pv81GcC+0oDwzFl/JdAm2t1Af8hUTOeGtYX/ORYjiKjkNRo
         ciqTSYWS2LnXxB8vQ/nIg6/2T7PiunJOnhNC9vCGUZyKO0NXvW13haZKZ+3QzoM1/ahf
         YoQzKKDY4AfrozBz0h5TOa0czPN3EghdYLaHRU1hvUUJzr46LutEqXhbdM5hXHc8e7YL
         bThSvh5r/ArhMN0yPxgXqebFffSvP8aP+F3k0hrwv7oGeRE4g/3rutsP8o98qeA8N39p
         ZSTUx8UtBxZQD05Dm1Mn3rtRgrJ/UUA9/cjcofXv+OA9VQIvh3R2q2GBIwfFyU7Ho6dp
         T/Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ejG34KY4xUo1hoVUSGnJNQnmLMPwo/Omgjn6WYbFfxY=;
        b=bfg6872SzQILblt1ZKBig4VCOHM9DxsAiFzunQdsV/rfq8nHmfzMbM7ijOcGlXhXxs
         v6G9zQ6QJ0jioBVg3a62ff2K8bpTekEdlsOUVJoJdpQpmkVIG2yDC2AyWgYYshCEcV4f
         S/fq25mEQIbxfQklt9A8Z2gAhKyAdUKnsfBnKEBgA4vaRfLLeBUons1GG5nQTlDzON/k
         rkLBvBQ6zldMlOCMaNfOUANb8IQV8zrBwzNKgs/RkA/Nh75c/bE4dVd79Hw6/EqW5SCr
         XMnR2MWS5aKOqp3pQliWIaMzuGpnCpa5iHEK12y5yrhPbZ6s/VAEj+FdzqRloCI+OD76
         iuKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RXd7Pa84;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ejG34KY4xUo1hoVUSGnJNQnmLMPwo/Omgjn6WYbFfxY=;
        b=PViEhYUpsKZiBl254rRChyMkq1Oob8XaE1oYErpYYGd3TNaxbALBRxsvOt4fmU7y5o
         5RGJE9oX2nmoKcPaz+opK2ByLzZrsu/zP1JyCSop5nbc+LmRB6x7/yb23sqgWbRMQmXM
         mzSZn56fTWChft+lXnoBW4fhB55o7y9bV/M5KqbA/Afzg4OXLwCQiSfSiC2G9UeG0yU5
         xjw9v7rbG3gVJLdfhiqA6cNf7d4htGzPM0z6HimmAKrtgLmcPYSmPispF7uSYBuwG0hV
         gCwhJCxE+PlPAQ4OeonO6G2DQLLRQgCXdwcYSBsIfInT1+ghndw7NaIzFXrrX+gtx2BN
         pUWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ejG34KY4xUo1hoVUSGnJNQnmLMPwo/Omgjn6WYbFfxY=;
        b=QH9DdRwefGew2CDZz1r8a0niLgHjAE5BuQbfp87UNf2moF8RphNVeuSVFBlkvlm61L
         vMOVI92fBpES1s/LdWbHIXGVtyUrUvCSp6eCf6rueR7TwRBmOfY81PLRWabbscKxEay/
         ObKVfwAA35JOFhdokAhEOGNCYMBuU4eOCNRJOuvvRURqUhp5BnSdoXpoLeKnWozHR/Qi
         A0wxBWk/LNmuGt2Sg0HYCghEHc7uadtOoDSd0cERWjcba9k15plEvOM9WpfLsDYE2a6O
         Ob++tUHWE4EJoMmlEb4dHGg5+mxkHpjD3r4spT81ZbO4qpo6WZDceZfjdW9WUrO3AjPR
         UKnw==
X-Gm-Message-State: AOAM530tcAc5EduIyLdzDhSEgS7UZ6MCsgYXTlBC3Xge42Uz0Wvo3Me0
	gG6vJ363OKacL3M7jH6D5ng=
X-Google-Smtp-Source: ABdhPJzpzSQv5/C35JDG6o62oNKvRiwe6zfPoPQeK0aR6EWevoCgAqS0HnSL1kWTMxjha5NLY0m29A==
X-Received: by 2002:a67:71c7:: with SMTP id m190mr10187220vsc.28.1619866053894;
        Sat, 01 May 2021 03:47:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:31d0:: with SMTP id x199ls1755081vsx.0.gmail; Sat, 01
 May 2021 03:47:33 -0700 (PDT)
X-Received: by 2002:a67:e06:: with SMTP id 6mr10263234vso.21.1619866053366;
        Sat, 01 May 2021 03:47:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619866053; cv=none;
        d=google.com; s=arc-20160816;
        b=fl/VheBkQ7aNerKP1bPm8wHMSlhIpFWge+1V/oNg7P4Hw2HeEb6/OhQrtO1NOc4l+U
         6fLFN2JxYcN53VaiV+7Ehr/RFTS+jQxOYJlKwkACX5IZGrBAdd6xPNhLtovxqKeC6QAq
         MjLDyrZeQSg3Paz+MLvbqehHJX3Zb46PCkGbmBT4D88pTVyli0sE7AfGS0TJfTjJ7UOo
         aliiK9xq+Kk/B6/QMcdMPq9W0zk7gxIUiaruBnWPXLWysQrkpVUaw/+IDg4QG7t5fGjB
         SNwGiVcPmT6xKrGnVoWSDkqJvV2QSxDWsZVAIqLaWRBX5p44RIC+Vx3cg19Bh9AKXDXS
         7BxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dogrgVKo+eUYaN7DWgb4gh1G07uaLoO2fYWTRss9iAI=;
        b=kIF73ZKwx8wesfPrh088RRleU1VM77ooOWUP6L+R6gryA90jkGu6LaFeVF5MBJXBFT
         yo9Rb9Ic3heaVOnNUFIinsrnNnFmyXPy884zNUHn2GhCwuyNmjqzoZ7ZEztNvu2sNR9V
         mSgUhdr9kxomKJ+Or0QHv2rElY9s4gKDoX2saymx18OOebhmuI8N5ZEpmRJ2YfM8Xlr1
         1Au6/6echQWtW+4HRrwH+tuEmogF2YWNsj+4upXGkI4vP+0+2ySbWhLm3U8obzToVEWR
         keU1yeHVQFQ0t+jGWZ0fm8SheMc0bq9qOP/GP2ctsjzgC4VBJCt2bHe0ijbW0iKp7KBk
         ng2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RXd7Pa84;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id x24si1013237vsr.1.2021.05.01.03.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:47:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 103-20020a9d0d700000b02902a5baf33f37so363009oti.9
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:47:33 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr7373221otn.233.1619866052694;
 Sat, 01 May 2021 03:47:32 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m11rarqqx2.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m11rarqqx2.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:47:21 +0200
Message-ID: <CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
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
 header.i=@google.com header.s=20161025 header.b=RXd7Pa84;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Sat, 1 May 2021 at 01:44, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Don't abuse si_errno and deliver all of the perf data in si_perf.
>
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---

Thank you for the fix, this looks cleaner.

Just note that this patch needs to include updates to
tools/testing/selftests/perf_events. This should do it:
>  sed -i 's/si_perf/si_perf.data/g; s/si_errno/si_perf.type/g' tools/testing/selftests/perf_events/*.c

Subject: s/perf_data/perf data/ ?

For uapi, need to switch to __u32, see below.

>  fs/signalfd.c                      |  3 ++-
>  include/linux/compat.h             |  5 ++++-
>  include/uapi/asm-generic/siginfo.h |  5 ++++-
>  include/uapi/linux/signalfd.h      |  4 ++--
>  kernel/signal.c                    | 18 +++++++++++-------
>  5 files changed, 23 insertions(+), 12 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 83130244f653..9686af56f073 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -134,7 +134,8 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 new.ssi_addr = (long) kinfo->si_addr;
> -               new.ssi_perf = kinfo->si_perf;
> +               new.ssi_perf_type = kinfo->si_perf.type;
> +               new.ssi_perf_data = kinfo->si_perf.data;
>                 break;
>         case SIL_CHLD:
>                 new.ssi_pid    = kinfo->si_pid;
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index 24462ed63af4..0726f9b3a57c 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -235,7 +235,10 @@ typedef struct compat_siginfo {
>                                         u32 _pkey;
>                                 } _addr_pkey;
>                                 /* used when si_code=TRAP_PERF */
> -                               compat_ulong_t _perf;
> +                               struct {
> +                                       compat_ulong_t data;
> +                                       u32 type;
> +                               } _perf;
>                         };
>                 } _sigfault;
>
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index 2abdf1d19aad..19b6310021a3 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -90,7 +90,10 @@ union __sifields {
>                                 __u32 _pkey;
>                         } _addr_pkey;
>                         /* used when si_code=TRAP_PERF */
> -                       unsigned long _perf;
> +                       struct {
> +                               unsigned long data;
> +                               u32 type;

This needs to be __u32.


> +                       } _perf;
>                 };
>         } _sigfault;
>
> diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
> index 7e333042c7e3..e78dddf433fc 100644
> --- a/include/uapi/linux/signalfd.h
> +++ b/include/uapi/linux/signalfd.h
> @@ -39,8 +39,8 @@ struct signalfd_siginfo {
>         __s32 ssi_syscall;
>         __u64 ssi_call_addr;
>         __u32 ssi_arch;
> -       __u32 __pad3;
> -       __u64 ssi_perf;
> +       __u32 ssi_perf_type;
> +       __u64 ssi_perf_data;
>
>         /*
>          * Pad strcture to 128 bytes. Remember to update the
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 5b1ad7f080ab..cb3574b7319c 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1758,11 +1758,13 @@ int force_sig_perf(void __user *pending_addr, u32 type, u64 sig_data)
>         struct kernel_siginfo info;
>
>         clear_siginfo(&info);
> -       info.si_signo = SIGTRAP;
> -       info.si_errno = type;
> -       info.si_code  = TRAP_PERF;
> -       info.si_addr  = pending_addr;
> -       info.si_perf  = sig_data;
> +       info.si_signo     = SIGTRAP;
> +       info.si_errno     = 0;
> +       info.si_code      = TRAP_PERF;
> +       info.si_addr      = pending_addr;
> +       info.si_perf.data = sig_data;
> +       info.si_perf.type = type;
> +
>         return force_sig_info(&info);
>  }
>
> @@ -3379,7 +3381,8 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -               to->si_perf = from->si_perf;
> +               to->si_perf.data = from->si_perf.data;
> +               to->si_perf.type = from->si_perf.type;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid = from->si_pid;
> @@ -3455,7 +3458,8 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = compat_ptr(from->si_addr);
> -               to->si_perf = from->si_perf;
> +               to->si_perf.data = from->si_perf.data;
> +               to->si_perf.type = from->si_perf.type;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid    = from->si_pid;
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNJ_MnNyD4R2%2B9i24E%3D9xPHKnwTh6zwWtBYkuAq1Xo6-w%40mail.gmail.com.

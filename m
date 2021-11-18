Return-Path: <kasan-dev+bncBCMIZB7QWENRB45Y3GGAMGQEAVJQEMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 193F3455D34
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 15:00:21 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id bj10-20020a05620a190a00b004681da13edcsf4917363qkb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 06:00:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637244020; cv=pass;
        d=google.com; s=arc-20160816;
        b=er83FxHigakDsb2DSh2/Vbkn9IgrTa33Vzwa0CdVeJFTeN4xJKC2h4rGvJT1p1mSIl
         3weYwXWOHaWqZPEDyycqXmkUozDXe+5cNvpyZKUkD/QuSAxINCRYMzjnvBym1585gC+a
         xB3xzWw8ebhtfn0ZKkTZewSNUhUzuS3dGD5Tm2tEf+Hv5+2f/c5IQxWvW9Zyl3zYH36f
         /cuPAyBg/5BxD/UdvUCh302RT7u5HqrC8e2RbO3zwsVs36eh8CG4xWrzMbiF2SlLEUo4
         4guF9UJIvnBg7YgA6rw6wJrHo7PCdwrotxjhIAuhnKWPF8QmkRAp/73E1/n9Qg2fdbpu
         zYWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D6HLOWPzXppUHxWRKbW0pMHnVZueMaHvCc7unR1EjnA=;
        b=wcXmYiHOi+FUnq70wqQ0Zjjkp+0NqIzMHxQoCr+MFpYnWct9UZwF8cwdXZ+u820crh
         X54RLhBdlBNlS6Dbhv02DfSJNYebfb6/jrxpLAZcDQvaS2MVcFbnkvojVgRtpvgjfVvt
         sZwuG3++QqalKzMlgc4dxRmP3Y0sHNHWJ0V6sFJcMgaC+h41CrRIJZdtD4zn8RWJhpgo
         x+auw+9YpPYFCff/KpQvmh5tttQbF9usqOo2mqT96VdaUzqhbVhiPQ3H+mpyylM2fMk6
         Q59XNcVSaqL/qXyq/We37dm+Uog1cUBI7/ziFGidYoQiYlVhcBB0jkHhpFti/MB1hmZF
         M8Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g38VSvHO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D6HLOWPzXppUHxWRKbW0pMHnVZueMaHvCc7unR1EjnA=;
        b=jYuU7oIAwToe4nSpyZRyDrZSsVly2NYAFX8ZCg+8CudeAcmqkypOmCTSeZNHHvmBCb
         N1xDNZWZgcNDTeV0G1eGbswHBfp+m/Y9Y4Z3e9XG2R7Fsnm2M6wJXdfo7qhbH4lP1GUu
         8+t1j89LucaRDAIelBUNOrJcuRcMw9CG4YXDV1KLZ01+ZdXMpnfVYe5ZcRnXpuPWoI06
         KvsPrhz9tGw3hmwIjxBramITdBSv+qUxm4VEuClem5wTu2l7H4n2FCerqOS6E9oZgh3a
         PGqVKDwARdyhZDfbdHoXSq3nP+IgqjhTK9dX2HiWS0RaWWfTkQWbI1Dlstz3L0ZtPKTs
         no6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D6HLOWPzXppUHxWRKbW0pMHnVZueMaHvCc7unR1EjnA=;
        b=FWHG2/0RkOxSpTwrcwLDLPkv0afBG6VirmCSffzDyGZqVBqQqrUxRqXqqj7aPoI3b5
         enZx2qL5zS7vrDVbMR8Kaakp4hFKRcYj3PLkzrgOVkYKgziT+Hxxh18uE3KVcgNTZpv+
         uELmZUhqC9Fv3N09dYStUR7hBGZR+/dceV8/nsaBZ9h0dAajypEprekHSmsTHZI7lH7X
         X5LxBoN7pWoYSDAvg35eGzW7Ju1yEIOz+a2bf8TyEHoVJlpsVVdknpqkzTxgrI8G7ejG
         f/qcScOGlwSOqONLS366p+GEaKPZ47jOIFhWrdx2TNnwx0ElEzhM7QMkatzBu8zTe3GF
         L+eQ==
X-Gm-Message-State: AOAM530tMQihRBKhbCdDYdIisg5qpZgHVMqVZ/wHVZv2mdWG80dEQsrS
	I3V/88x/X75vfXQsVuAjyAo=
X-Google-Smtp-Source: ABdhPJwN5KVuEj/yTcoX4qaNhDs7uV+vqiBlljc5LkokVyd/PDEHX++v9Pr3a3jIfw8gGuhx0tp9uw==
X-Received: by 2002:a37:8906:: with SMTP id l6mr20489110qkd.210.1637244020059;
        Thu, 18 Nov 2021 06:00:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4a04:: with SMTP id x4ls1870222qtq.1.gmail; Thu, 18 Nov
 2021 06:00:19 -0800 (PST)
X-Received: by 2002:ac8:4155:: with SMTP id e21mr25913630qtm.312.1637244019583;
        Thu, 18 Nov 2021 06:00:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637244019; cv=none;
        d=google.com; s=arc-20160816;
        b=Xh+qqPb+uzR+ncUCFd4bzpkSzFR71uw2i36hkZUe9n+LrtwH2pEUkhGqk625Xal35O
         EDXYHLFAmnkXPL5Pq0upV2HLWgz3hxtWQRlU8uDGSEgTN03tpcCWAuhY01oxq43PSypY
         qPUUr/fMG45WckpZP2TgVcrLoiDhoZ60foDmx8rl+iD7iZ6jfCAbjD4li6szFfco1Wwa
         /kolEoOcaQao8lwSVfFsx5ia49IkixDHmiL6D2y2ZBTMzHqgOrwGMDqj0AEDgS5a7UZ3
         MP0H8EAzQFmFBeuzAOgLm4Ekfl65oQUHn2TOHO1dSe8mYWHvSETM+2s+UxAT0Wb5B3kg
         0ZQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a+FyNz0pXjfppEydoj/lLxWxvoerNkGHwTC6CZVssPk=;
        b=saRmEO4BwkxQhv4Yp5a2FCDSgNstE8Zn0XHPJu5Afv6VTBzDfZ9be6W0l/IweOj80y
         MySvzZEkIrnWpeoPsFrdvvO9uuclKl9m0HRVwgGgzXWJ+6aZ7Jq61Eg0MnuN9vg3Cj/k
         S8qLrhsMJ2w6ctqXAumEr9phJdgOGEgbdVByOkY/MC8w+kRDwr2GnvHvvRT3Q2x5CNhP
         7ZOyiPx9neYFi4iVK3f8Itcoaeyl2Fig5SgKMKZrNog1cNyYFvqM2d1kxE9vE1sikluU
         CeBWLg2ytBnxPvvTuHG9fMElBPwSFKaDLLo597ZXKuyH7MAqgwGCUDxsUultqdVdK8G4
         ZcnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g38VSvHO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id i6si652068qko.3.2021.11.18.06.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 06:00:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id bf8so14446383oib.6
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 06:00:19 -0800 (PST)
X-Received: by 2002:aca:3104:: with SMTP id x4mr8087672oix.128.1637244018908;
 Thu, 18 Nov 2021 06:00:18 -0800 (PST)
MIME-Version: 1.0
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
In-Reply-To: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Nov 2021 15:00:06 +0100
Message-ID: <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=g38VSvHO;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22d
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

,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com> wrote:
>
> Sometimes we only interested in the pcs within some range,
> while there are cases these pcs are dropped by kernel due
> to `pos >= t->kcov_size`, and by increasing the map area
> size doesn't help.
>
> To avoid disabling KCOV for these not intereseted pcs during
> build time, adding this new KCOV_PC_RANGE cmd.

Hi Joey,

How do you use this? I am concerned that a single range of PCs is too
restrictive. I can only see how this can work for single module
(continuous in memory) or a single function. But for anything else
(something in the main kernel, or several modules), it won't work as
PCs are not continuous.

Maybe we should use a compressed bitmap of interesting PCs? It allows
to support all cases and we already have it in syz-executor, then
syz-executor could simply pass the bitmap to the kernel rather than
post-filter.
It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander proposed here:
https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
It would be reasonable if kernel uses the same bitmap format for these
2 features.



> An example usage is to use together syzkaller's cov filter.
>
> Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> ---
>  Documentation/dev-tools/kcov.rst | 10 ++++++++++
>  include/uapi/linux/kcov.h        |  7 +++++++
>  kernel/kcov.c                    | 18 ++++++++++++++++++
>  3 files changed, 35 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index d83c9ab..fbcd422 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -52,9 +52,15 @@ program using kcov:
>      #include <fcntl.h>
>      #include <linux/types.h>
>
> +    struct kcov_pc_range {
> +      uint32 start;
> +      uint32 end;
> +    };
> +
>      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned long)
>      #define KCOV_ENABLE                        _IO('c', 100)
>      #define KCOV_DISABLE                       _IO('c', 101)
> +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, struct kcov_pc_range)
>      #define COVER_SIZE                 (64<<10)
>
>      #define KCOV_TRACE_PC  0
> @@ -64,6 +70,8 @@ program using kcov:
>      {
>         int fd;
>         unsigned long *cover, n, i;
> +        /* Change start and/or end to your interested pc range. */
> +        struct kcov_pc_range pc_range = {.start = 0, .end = (uint32)(~((uint32)0))};
>
>         /* A single fd descriptor allows coverage collection on a single
>          * thread.
> @@ -79,6 +87,8 @@ program using kcov:
>                                      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
>         if ((void*)cover == MAP_FAILED)
>                 perror("mmap"), exit(1);
> +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
>         /* Enable coverage collection on the current thread. */
>         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
>                 perror("ioctl"), exit(1);
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index 1d0350e..353ff0a 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -16,12 +16,19 @@ struct kcov_remote_arg {
>         __aligned_u64   handles[0];
>  };
>
> +#define PC_RANGE_MASK ((__u32)(~((u32) 0)))
> +struct kcov_pc_range {
> +       __u32           start;          /* start pc & 0xFFFFFFFF */
> +       __u32           end;            /* end pc & 0xFFFFFFFF */
> +};
> +
>  #define KCOV_REMOTE_MAX_HANDLES                0x100
>
>  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned long)
>  #define KCOV_ENABLE                    _IO('c', 100)
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote_arg)
> +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kcov_pc_range)
>
>  enum {
>         /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 36ca640..59550450 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -36,6 +36,7 @@
>   *  - initial state after open()
>   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
>   *  - then, mmap() call (several calls are allowed but not useful)
> + *  - then, optional to set trace pc range
>   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
>   *     KCOV_TRACE_PC - to trace only the PCs
>   *     or
> @@ -69,6 +70,8 @@ struct kcov {
>          * kcov_remote_stop(), see the comment there.
>          */
>         int                     sequence;
> +       /* u32 Trace PC range from start to end. */
> +       struct kcov_pc_range    pc_range;
>  };
>
>  struct kcov_remote_area {
> @@ -192,6 +195,7 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>  void notrace __sanitizer_cov_trace_pc(void)
>  {
>         struct task_struct *t;
> +       struct kcov_pc_range pc_range;
>         unsigned long *area;
>         unsigned long ip = canonicalize_ip(_RET_IP_);
>         unsigned long pos;
> @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
>         t = current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>                 return;
> +       pc_range = t->kcov->pc_range;
> +       if (pc_range.start < pc_range.end &&
> +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> +               (ip & PC_RANGE_MASK) > pc_range.end))
> +               return;
>
>         area = t->kcov_area;
>         /* The first 64-bit word is the number of subsequent PCs. */
> @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>         int mode, i;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
> +       struct kcov_pc_range *pc_range;
>         unsigned long flags;
>
>         switch (cmd) {
> @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov->size = size;
>                 kcov->mode = KCOV_MODE_INIT;
>                 return 0;
> +       case KCOV_PC_RANGE:
> +               /* Limit trace pc range. */
> +               pc_range = (struct kcov_pc_range *)arg;
> +               if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kcov->pc_range)))
> +                       return -EINVAL;
> +               if (kcov->pc_range.start >= kcov->pc_range.end)
> +                       return -EINVAL;
> +               return 0;
>         case KCOV_ENABLE:
>                 /*
>                  * Enable coverage for the current task.
> --
> 2.7.4
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYwNawV9H7uFMVSCA5WB-Dkyu9TX%2BrMM3FR6gNGkKFPqw%40mail.gmail.com.

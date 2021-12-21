Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XNRCHAMGQEMOEAV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id CE2D647C82D
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 21:19:55 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id u13-20020a17090a450d00b001b1e6726fccsf2198495pjg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 12:19:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640117994; cv=pass;
        d=google.com; s=arc-20160816;
        b=oGCQVdwV0WFTBKJmZE5l79sO57hK4zHY0Rrhbm4D6J8v1MKqTBmzaGCJ4TfJqfzxaO
         +YLxG31UzOYKtTpLGD+V/DVD/8dBc9E0zKsM1fZvqPCJVyPMH/jEvniN5NVMMeaKn2Eh
         4a5Y4IVgzO+Q8VTTKhl8T7FURcsoAH61Ll/BYlD+dhP1Qgy8DAnmQPFUfpea/LoLcQEN
         2T9PUrn8fBFA8I0DYkmaOMk3F+NRHCC3V0Nx4yp+c8TEEFCyURqxmjNUMwR6Q9mYlYf1
         sMRTy7dOPRPPgr4VpJAdLET2zPJK7lDhIfAWEAYiJob4IKrQGOjChjm0My8nptfSFOUA
         fojw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vKx3sTMgynsObdyhIKBk0NiSxApOoVc5x3V3ZcLWdb0=;
        b=bEBXIC/LvJJUqQh25id98LoNdyk+bS4dGpJUFQRvyWus36KIq1FVdNCJPcksiczD7J
         FhSGhLXeDTMKu8JDYB/xFdtI0rEt8bcZU3R3+LxbJmLGoFVax0V56uxQgKILHluozMo8
         opYWQyYC0u3W84MMKMmvWSQHGVFHGdb4DbS3GQv9VkBmF6wrPU73205nGw3GRbwTzXUg
         CQactdapfj+9idxjzOz6TpuRgKPQA1bBmoBXKFjjqJBsVWaK1owxW6QG4kNCODXqXh4I
         fxkKygy5FmkJtZ3js+R+W6DBa9obAfJ6JtAXQsbzMWN5MItPzTN0pfH1Bfsqw46fVJB+
         kyWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hFET+5vc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKx3sTMgynsObdyhIKBk0NiSxApOoVc5x3V3ZcLWdb0=;
        b=sTsctKBgazDs+nFjX9o3VKk8DDxuRRZcPYDBQqUL5wDZGaoG4OnlPYJ/LU+o1nkb50
         N7oiJIsnfLergmMKiJqf+Wi8Q4SGPUxCI8jnDcl5S1q3tjuTKGcEjTLNGaU86c3/rzpo
         i8tkinuKUDwbJwt6LFeUMnAIFo7hixw0FU6iAZm2OgalgNIgqzqpQ5ZM3+sOhvGdw26L
         UNzQ3Pn4/FvkZDmNCCp15JffmsMTJtEAF8d0idtkIHT99mUfkB/Bt0PwK9TLLKcJz6ym
         pAsTLmcFD37v+LNgpMwEokMbMz7yWDuiiS/gAPJ8xbE6qnOsphgLA+d+NMGLpst3bMW3
         ugSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKx3sTMgynsObdyhIKBk0NiSxApOoVc5x3V3ZcLWdb0=;
        b=N//X7Fh+nn0iSCvMGPw5hjzHC6S+nJC+ZIv/wSe5jwmzkeXP2fE+CLdAySHeivysHs
         RvHLFWRaJMiCBM0lijYNIRQf/KaBfKr09i9DqUrfBd+09c1irf3vxk0RdWqAS0jBgqa8
         o410o9MxxEmot39EMoTZHa7PEtxSxnwD5Sh7zG/6TXdF4GpNzKLKyTNMBVovMFnVaJf1
         RAMt6vIw7j0pjQk+2zNZibcAfg/gNOrjyb3GNPRhWKb4Z7Ud+oA2HbbjuFru9XFMod+Z
         6JfEjnEhbOB3ZLjeEZ7UIlzMppb6fpDf8Jh6IiSswf3/CYQagRx5/b6jbUvHvtEps3S6
         4eOA==
X-Gm-Message-State: AOAM533ayd54vip/wo4Cu52wQ/gkbATp3emmXklGd3n328tYlEYr5Fk0
	PPGzcjAKrGxlN3vYcHo9gp8=
X-Google-Smtp-Source: ABdhPJycHS3Cuof7hAM6tZepRHo9dcaZ5zDJ2HyyarBCF3SvtqeSCXwntKtDofk5uL0zg9RU3xVJbw==
X-Received: by 2002:a05:6a00:2444:b0:4ab:15b9:20e5 with SMTP id d4-20020a056a00244400b004ab15b920e5mr4890681pfj.0.1640117994179;
        Tue, 21 Dec 2021 12:19:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1f8d:: with SMTP id x13ls2637835pja.1.canary-gmail;
 Tue, 21 Dec 2021 12:19:53 -0800 (PST)
X-Received: by 2002:a17:902:e805:b0:149:95a:1983 with SMTP id u5-20020a170902e80500b00149095a1983mr5106164plg.9.1640117993531;
        Tue, 21 Dec 2021 12:19:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640117993; cv=none;
        d=google.com; s=arc-20160816;
        b=e8PZ7mINkw3qNvHkkbD11qZmU9PGeLT9p+UFoIkPIsyBDAfICll2riE658HZv50LUG
         sJx/xPAMyDTlFhqZRARKHU9AIliiBNpGSf5gPX40VvUy2DE0X6AAs8OG4uGARtb2jPn+
         ksmV3o2DoMzZ7w4rgZO5yUXh7pkSlmbfR4rD4oH7tKlHm4GXXo1ZwlqGGqvhi/UiZ7TP
         ddWkoJZrDgWVEO1TmcZrpN6GDy6yHAQ1/it3G/CaTG6OuXioLzBacbSS/zEsmUTbW3MF
         sukF405IxGw3hnTlJ+u0eBgbnty0MXXNUGrvcD7hT5h4sdcViG6Ojdpp2XUwlU0q8KH1
         r90g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G9LWWkXvMjCHJdkHQwVy+G2bXdZtAb8HFnc0qRd88BI=;
        b=hhMwCyUw2QVpnkgHilEn10AesI7Jd/4mIS/6AeOsVMZRBtEMtGAo/PC5/cmCtAazGf
         8/hhFVG3Hz1JGP7TFNWRV9YKnHpVrn+pjPzex4yWRNlrknXRz5oLU3APXJEeWYCR/Rfy
         99W0pyCb63lJl/zX2Ifo019Zxl1QpU78eR2VwaHAmekoUO7XJFLaw07qer8TzvJ97+qo
         GpICZ/4mtmRtdMn6DcVYoHtEQW6UB6RTqkrxiiNwB8nwRVCzRl/0eI6EN5Rwr/qBzaeE
         2vsIVYS4hNwBdwc98/Ftzc3qzvp8FirFjHzCihHJznGESObuUTknoqp2d8ywCIaTTKib
         bzDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hFET+5vc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id c9si1374208pgw.1.2021.12.21.12.19.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 12:19:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id w64so489576oif.10
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 12:19:53 -0800 (PST)
X-Received: by 2002:aca:6245:: with SMTP id w66mr90879oib.134.1640117992657;
 Tue, 21 Dec 2021 12:19:52 -0800 (PST)
MIME-Version: 1.0
References: <20211221170348.1113266-1-nogikh@google.com> <20211221170348.1113266-2-nogikh@google.com>
In-Reply-To: <20211221170348.1113266-2-nogikh@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 21:19:41 +0100
Message-ID: <CANpmjNMAWuE0Y20ZuBUSRXkvWZd8NC1d=DDYYrEZytJz9ndxeA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kcov: split ioctl handling into locked and
 unlocked parts
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, dvyukov@google.com, andreyknvl@gmail.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hFET+5vc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Tue, 21 Dec 2021 at 18:04, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Currently all ioctls are de facto processed under a spin lock in order
> to serialise them. This, however, prohibits the use of vmalloc and other
> memory management functions in the implementation of those ioctls,
> unnecessary complicating any further changes.
>
> Let all ioctls first be processed inside the kcov_ioctl_unlocked()
> function which should execute the ones that are not compatible with
> spinlock and pass control to kcov_ioctl_locked() for all other ones.
>
> Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
> handling to kcov_ioctl_unlocked(), so that its planned change is easier
> to follow.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> ---
>  kernel/kcov.c | 64 +++++++++++++++++++++++++++++++--------------------
>  1 file changed, 39 insertions(+), 25 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 36ca640c4f8e..5d87b4e0126f 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -564,31 +564,12 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                              unsigned long arg)
>  {
>         struct task_struct *t;
> -       unsigned long size, unused;
> +       unsigned long flags, unused;
>         int mode, i;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
> -       unsigned long flags;
>
>         switch (cmd) {
> -       case KCOV_INIT_TRACE:
> -               /*
> -                * Enable kcov in trace mode and setup buffer size.
> -                * Must happen before anything else.
> -                */
> -               if (kcov->mode != KCOV_MODE_DISABLED)
> -                       return -EBUSY;
> -               /*
> -                * Size must be at least 2 to hold current position and one PC.
> -                * Later we allocate size * sizeof(unsigned long) memory,
> -                * that must not overflow.
> -                */
> -               size = arg;
> -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> -                       return -EINVAL;
> -               kcov->size = size;
> -               kcov->mode = KCOV_MODE_INIT;
> -               return 0;
>         case KCOV_ENABLE:
>                 /*
>                  * Enable coverage for the current task.
> @@ -685,6 +666,43 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>         }
>  }
>
> +static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
> +                            unsigned long arg)
> +{
> +       unsigned long size, flags;
> +       int res;
> +
> +       switch (cmd) {
> +       case KCOV_INIT_TRACE:
> +               /*
> +                * Enable kcov in trace mode and setup buffer size.
> +                * Must happen before anything else.
> +                */
> +               if (kcov->mode != KCOV_MODE_DISABLED)
> +                       return -EBUSY;
> +               /*
> +                * Size must be at least 2 to hold current position and one PC.
> +                * Later we allocate size * sizeof(unsigned long) memory,
> +                * that must not overflow.
> +                */
> +               size = arg;
> +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> +                       return -EINVAL;
> +               kcov->size = size;
> +               kcov->mode = KCOV_MODE_INIT;
> +               return 0;

This patch should be a non-functional change, but it is not.

To do that, you'd have to add the locking around KCOV_INIT_TRACE here,
and then do whatever else you're doing in patch 2/2.

> +       default:
> +               /*
> +                * All other commands can be fully executed under a spin lock, so we
> +                * obtain and release it here to simplify the code of kcov_ioctl_locked().
> +                */
> +               spin_lock_irqsave(&kcov->lock, flags);
> +               res = kcov_ioctl_locked(kcov, cmd, arg);
> +               spin_unlock_irqrestore(&kcov->lock, flags);
> +               return res;
> +       }
> +}
> +
>  static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  {
>         struct kcov *kcov;
> @@ -692,7 +710,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         struct kcov_remote_arg *remote_arg = NULL;
>         unsigned int remote_num_handles;
>         unsigned long remote_arg_size;
> -       unsigned long flags;
>
>         if (cmd == KCOV_REMOTE_ENABLE) {
>                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
> @@ -713,10 +730,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         }
>
>         kcov = filep->private_data;
> -       spin_lock_irqsave(&kcov->lock, flags);
> -       res = kcov_ioctl_locked(kcov, cmd, arg);
> -       spin_unlock_irqrestore(&kcov->lock, flags);
> -
> +       res = kcov_ioctl_unlocked(kcov, cmd, arg);

Also, I find that kcov_ioctl_unlocked() isn't a very descriptive name,
since now we have both locked and unlocked variants. What is it
actually doing?

Perhaps kcov_ioctl_with_context()? Assuming that 'struct kcov' is some
sort of context.

>         kfree(remote_arg);
>
>         return res;
> --
> 2.34.1.307.g9b7440fafd-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAWuE0Y20ZuBUSRXkvWZd8NC1d%3DDDYYrEZytJz9ndxeA%40mail.gmail.com.

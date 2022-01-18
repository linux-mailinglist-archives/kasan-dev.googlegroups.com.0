Return-Path: <kasan-dev+bncBCMIZB7QWENRBC6MTGHQMGQEWF3GZIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D78A9491FA7
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 08:02:36 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id w133-20020acadf8b000000b002c6c86f4afbsf12881468oig.16
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 23:02:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642489355; cv=pass;
        d=google.com; s=arc-20160816;
        b=R2quQUxz9HygpOr5KqlWeqvB8m/6Cpx1acRweTRAbPaDdyOzV63eNypYeS0glmyqhV
         WZKZjCgokgfmU9Jhf0gjBU23yipTnrrrpZknsTAtBM2QDGA0yWWAaoVFrfEusddN3gN9
         ZOw5EfyYgPVH9idhLpp77jOlL6ORRlnEA/7C40Bc9ZSUdTC1qd1Q6ruIaSn4Xi7GfeWl
         oG5TIdooRwzq0OsINCy/IJ1PRwYl5PmpJ5ERNCRLyzEzJad4MzvLMAGbTq+vCzSuuWrs
         RSfRaHeyj50NLHeHCM+m12WI1X75rOfXWwjNAoSccjLISF0uKT5zR0D/3ggwv9bcA8yI
         7XJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zOevC0S65un53NbB9A0Gst6RD9Ns9kAnD2OnaHOGZzU=;
        b=WGmrZTxg8ooaixU4N7dfSNvxX9aH/0fMIttAMJ4+2gnsw4GylXrK+zP56aXAs0/7Tx
         ULp+i4wSKtK8PyieSvFuogshGVXDtxBlqaEbC2Dg2wuehmA50nUcf2qpi9a/XEc5hsb6
         rrlTTHZfpPLvRJy6i7kcY35AAtgrco+uzqFcYXkwGajN+oEgYYMbAFDQtJRWoPGlIkCU
         5jyewAn4q25dWI9Nv2wetRbCMfsBAc2cQH60JkNkb3RtiXKMstqw+6LKIfxafiIgT+Is
         /U6e8K3po45zrpzAAuU5b49rHAIO/F3xcyNSdCNSl4i7hT0UsnzKgK3y5+qPkMwiAQit
         5l4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kkmxCxwD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zOevC0S65un53NbB9A0Gst6RD9Ns9kAnD2OnaHOGZzU=;
        b=m2wE+acNRqyXlhRVlGzSmETdu4jsZvlPOlrBTScj85gtnWDhxigxsFzXr98Fbs7LuK
         rShEI/08BVytbdda/6v56gxBibb98ggDk/xzWD1/ru9xWV8rzHOtjjWH5ukbQlDEDI+A
         xH0yE1VzNTWuS9P6z/h2xOwU9+j5K2epi1cYMhqtjlVsacs5sev3uNM0d26rNBLtQ+wu
         Jtn2/MFKlAjBJNh4JXHn9oU7k+nxkxHykLMj8bLE/rlG5uL5d1xnfjYxlcqcTxs3k1d+
         ISuX/ofONP2Bn6Jj7S5MKgq00rPFe9IyF7FpFrgtK/VS9D3L7pRzAfW0N2qMubcF3r8T
         VVnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zOevC0S65un53NbB9A0Gst6RD9Ns9kAnD2OnaHOGZzU=;
        b=upPdKH0twhseL08NFc1zturXT/eBXJuJXzHFu0UOG1YlzII0/kbfLJc/4qXd1EBfTB
         +XBRaQEd2NxQaBOUYWNRKS50OnParR/bLiIlsZPe9iNFlaewVdZTYxu8ao3EHBcDzkO3
         IkUm7yLbZ+UCtPCy1b39kCMZq+3r7PlQN6JUDphqgBX2gGQtKXgxn5tyKD4bGUR0y6Bb
         6opQaFC0ts7zVMcRzWvAAixGomNtUtN2yL0lI7pnRoV4iVKzBbJ7/vzPzDJ4D+s+GvGJ
         jQV24/HflzlhGyv0R4Yg+4SqgPEdxIKKkhNJmAOs2L/G2Rmer6R2dsTmugB2pC6IKD0g
         VnSg==
X-Gm-Message-State: AOAM532Wb72hjymaOCgxmwOfzAibekwkW5zrtYmXudl+uaIlUdsLrE+X
	SQ+lMVvlZiMWkodu27KyiwI=
X-Google-Smtp-Source: ABdhPJx2CQZ94b25xJ81vOqz8emWj3nESEJkqor1WgCreHgMKDAHuBTjqXEMKghEubP3k7su99A7tg==
X-Received: by 2002:a05:6830:1e37:: with SMTP id t23mr15322557otr.160.1642489355396;
        Mon, 17 Jan 2022 23:02:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1412:: with SMTP id w18ls4281823oiv.4.gmail; Mon,
 17 Jan 2022 23:02:35 -0800 (PST)
X-Received: by 2002:a05:6808:2097:: with SMTP id s23mr16423045oiw.132.1642489355118;
        Mon, 17 Jan 2022 23:02:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642489355; cv=none;
        d=google.com; s=arc-20160816;
        b=He31g8EYB3aYAsNWWAN7+YRm+kAd/tJ/I4ieGL1NIbrBUhVEABE7NIvNi1KA47LwX4
         fdywSkAZh0oX8rfbFoH0ziOQsMR13n+y/jvLb+2qDqpZS1KjDRVEGGYG8y7sPDdAHvE1
         qd34a7ezBXNoHv3nucXFGEQfzvWdlbnoJg8IotFB5/fj/2lBL82SmX1ZLgGenzMp6Jeb
         3lK+z0Qvw53Zq+4gGuJR1Q6kcrfElcD8SOhU2OyEl68gXXXs+amRiHU6Bl+3bMK5W97N
         0K6ocE0weQHMoMoAVdxJ08dZyQadMjDwseqGzlIK8dbmWcsBsB8JSPuEABCktiGtUQT4
         6wcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OU1bIi6zrErACRNMAd72qpHOpezdoqwFxeDmsExWnOE=;
        b=onWXs0Lj5w17MfUL3oMhZmUpVXhjDm8PC4LQiKVOgM+P91m3xZ9eSIKVX6zB4NP/2H
         jkx9w7cUjgAEIh9tlBoMPpks9jL5FGVXjOOoH3qps4WnAPAN4cLAyaLfjusMGMCeST7H
         9FXL4ZSXvuTiEVmOnpkW7ddCzAoUdtew3MxZjOCHWXSeHSwu2jYkmTks8hPaTYXmuhGO
         5RWVLVbDjNZcfLV6WaEsIVo/sUfex+Mo2ivxXkdZNxXbkNnwuOtsX9pqfoeIgWuRpGQK
         l1gQUidOnmhYDMMkmcrjxpHBCTmxvhuLTLcH2RflCzT1r9EQ1P4jwZ2ZB7Au24T6OnEj
         ysvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kkmxCxwD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id b3si644681ook.0.2022.01.17.23.02.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jan 2022 23:02:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id r138so27150799oie.3
        for <kasan-dev@googlegroups.com>; Mon, 17 Jan 2022 23:02:35 -0800 (PST)
X-Received: by 2002:aca:abc1:: with SMTP id u184mr14344282oie.109.1642489354590;
 Mon, 17 Jan 2022 23:02:34 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-2-nogikh@google.com>
In-Reply-To: <20220117153634.150357-2-nogikh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jan 2022 08:02:23 +0100
Message-ID: <CACT4Y+btn2qz-Q22LyWeT6hq2NLwToOXyD96K-MKfjyB3ukDFg@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kcov: split ioctl handling into locked and
 unlocked parts
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kkmxCxwD;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231
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

On Mon, 17 Jan 2022 at 16:36, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Currently all ioctls are de facto processed under a spinlock in order
> to serialise them. This, however, prohibits the use of vmalloc and other
> memory management functions in the implementations of those ioctls,
> unnecessary complicating any further changes to the code.
>
> Let all ioctls first be processed inside the kcov_ioctl() function
> which should execute the ones that are not compatible with spinlock
> and then pass control to kcov_ioctl_locked() for all other ones.
> KCOV_REMOTE_ENABLE is processed both in kcov_ioctl() and
> kcov_ioctl_locked() as the steps are easily separable.
>
> Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
> handling to kcov_ioctl(), so that the changes from the next commit are
> easier to follow.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcov.c | 68 ++++++++++++++++++++++++++++-----------------------
>  1 file changed, 37 insertions(+), 31 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 36ca640c4f8e..e1be7301500b 100644
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
> @@ -692,9 +673,32 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         struct kcov_remote_arg *remote_arg = NULL;
>         unsigned int remote_num_handles;
>         unsigned long remote_arg_size;
> -       unsigned long flags;
> +       unsigned long size, flags;
>
> -       if (cmd == KCOV_REMOTE_ENABLE) {
> +       kcov = filep->private_data;
> +       switch (cmd) {
> +       case KCOV_INIT_TRACE:
> +               /*
> +                * Enable kcov in trace mode and setup buffer size.
> +                * Must happen before anything else.
> +                *
> +                * First check the size argument - it must be at least 2
> +                * to hold the current position and one PC. Later we allocate
> +                * size * sizeof(unsigned long) memory, that must not overflow.
> +                */
> +               size = arg;
> +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> +                       return -EINVAL;
> +               spin_lock_irqsave(&kcov->lock, flags);
> +               if (kcov->mode != KCOV_MODE_DISABLED) {
> +                       spin_unlock_irqrestore(&kcov->lock, flags);
> +                       return -EBUSY;
> +               }
> +               kcov->size = size;
> +               kcov->mode = KCOV_MODE_INIT;
> +               spin_unlock_irqrestore(&kcov->lock, flags);
> +               return 0;
> +       case KCOV_REMOTE_ENABLE:
>                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
>                                 offsetof(struct kcov_remote_arg, num_handles))))
>                         return -EFAULT;
> @@ -710,16 +714,18 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                         return -EINVAL;
>                 }
>                 arg = (unsigned long)remote_arg;
> +               fallthrough;
> +       default:
> +               /*
> +                * All other commands can be normally executed under a spin lock, so we
> +                * obtain and release it here in order to simplify kcov_ioctl_locked().
> +                */
> +               spin_lock_irqsave(&kcov->lock, flags);
> +               res = kcov_ioctl_locked(kcov, cmd, arg);
> +               spin_unlock_irqrestore(&kcov->lock, flags);
> +               kfree(remote_arg);
> +               return res;
>         }
> -
> -       kcov = filep->private_data;
> -       spin_lock_irqsave(&kcov->lock, flags);
> -       res = kcov_ioctl_locked(kcov, cmd, arg);
> -       spin_unlock_irqrestore(&kcov->lock, flags);
> -
> -       kfree(remote_arg);
> -
> -       return res;
>  }
>
>  static const struct file_operations kcov_fops = {
> --
> 2.34.1.703.g22d0c6ccf7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbtn2qz-Q22LyWeT6hq2NLwToOXyD96K-MKfjyB3ukDFg%40mail.gmail.com.

Return-Path: <kasan-dev+bncBDW2JDUY5AORBNGSXSHQMGQEO6COISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 239CC499D37
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 23:33:26 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id k16-20020a4aa5d0000000b002eaa82bf180sf431459oom.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 14:33:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643063605; cv=pass;
        d=google.com; s=arc-20160816;
        b=DS1oVjOzZSiomTooGvZWcrGyTyN6CNcYS3MSfDWC1vh2vlYLBwiNAWM5H72JjoWpNM
         se60R82PIwAJ3QHxkyIWrkt4WQLVI92BPrRl0XwXUaX2mCCzqeiiUJBgRW2xuomRSDrZ
         AcgBbsO7Cg9t/yMCt9BOslxY40W9X3oUqOXqmRjTY2OulSnemS4wiG/6Cy5tOiN5+uDM
         JaQyMYbajn2fEvL2UpGreFNuuuw22VOJpIXn7RBKcyAVkTL4z2hIlyG30dwEcAWv+gak
         fVtKLwL2Sjn06Demgxr4G2bcfUKS3A6pPWlL4/WBn5W5/ezbLkjVjK5mmmdFD0G9LUx2
         ZH7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=CM1DXMrPWlkRJdHSrVQZKpbcE0QUOs72+l2MFv5Ep94=;
        b=Y031Tw9KjSlrrXyAF9J03p5d+OH2Ujo69WFdHQaKN9E01Gs+mL7bosfCFy7lJA3FPD
         E7eG3D+QZ5pDz7phueoJbQVtSBx270JYLhJjuP5jHFPNqsvlygwRe/O9BSiXcHVmLpIG
         jtJwRZAbRvzh+NvgNuc/t3Qjsn6IWo6L1s4OlY21+AW+y3xZF63QvjknQuU0ruSvojID
         8lpJEBHEMu7A01PNRx8hO6WlKsBDJOI746JxQmBBTgYZF1hmeEWev+XiL5/Fb67mpEPI
         a1vWHGQKT7x/g2GOi3eGLvAw6mb1Kj+BfWkkBhshxgqibz5SmENgEJV40OUSBdgsOkZd
         6IEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mZ8GIjqK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CM1DXMrPWlkRJdHSrVQZKpbcE0QUOs72+l2MFv5Ep94=;
        b=jGnBdep94pZGcMszfTiLYp3YhNJl3PV+3O1uRatTrIiQtBvXnihepKtG/uyvyQ4XKv
         UgqQ4BDSXI2EFhnuSmLiYQxR4CpIVw23D6Un9r7VumilNipOJa+RTLIFESy0HHagGzKZ
         7KwpMaNbbCKEqOOT4xi8HLFqKnoxyULgTql4/rOHprjjNxtTOxEWJirgZMbYQ86mHQEi
         kpDx7PVW9KCK81VmAFV2wNwZJ99MFg2EggyK3ZBe8ndBM67wHfME97SLQmRooo1kSfuF
         cAf8bwd68SocQqXXoZNWJZj9PjZxQIb7hj+B4JXq+5DzuI0rcpMAnbWNi1XH1FyiqNp1
         VQkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CM1DXMrPWlkRJdHSrVQZKpbcE0QUOs72+l2MFv5Ep94=;
        b=F0Is+1mSFpPJF9i2r3dEckt2NlVq+ZlBBXrVIGJUJGIs7WF0LPt/Hu3TBoNl/j1CXK
         Cv4+t4Z4wohZvS3k0VcdS0Gg/iFMdRfPr2eTjin4jA1UiRWM6GpabiFz+fxivs0biJ5s
         v50BTDwi1NSw0SG6CAMGCZD42lTf3OOhYaMNNfhMJkjdC24DCkbXQTm+mXA5qE8+3BnU
         nINtfubInXGUDmOdic9TFn19XEy3TlgS7wwAUSD7H/Inc/5yk1OoYSSRHIK0Pa/g03oT
         lDx7NEg7UUBOJRHyP/RBjGrqU/+233AAZoaiYszBdwkErN3fCie36XYQ9GpYj/tV2hIA
         9E/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CM1DXMrPWlkRJdHSrVQZKpbcE0QUOs72+l2MFv5Ep94=;
        b=QBUB00NZ3QWKP3bHtg7FCZHE9RjPrxAZqrjknkFbAqUoiYvVkYb0Bx/B745W8JTko/
         6k80tpPyGVEeQQvE+GhOEoQ0PcK+TreBfeEXkGtCG1Pbv9SKn64UaWF8Ggl4F+gZvpQK
         7BmpPV/GlCIZG7IyixssI8nUM86qzZqHRlHXacVb2NYO6BYiiBMJ9kFlwT4OWYeM4PCX
         QH0EK6bnP4nao43m/hk4yOU2pdE/+lyIt6Ib3o3GgWjFWWBRxP3Lkrik+ii+snfcfdeK
         Ic310iOPcwCd3LtpI/BpGJiUSLotzdg/au7A6brTViKRBK3eIcOz/SzGvl2oFRCj0vnU
         8iYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RLCuKpNlL2sBXp1tdcCVe7uTTLPmFPjE1ANiCMBXX/OSzktTZ
	AMHXOqHkuzsjAfmpt5eA23E=
X-Google-Smtp-Source: ABdhPJwHreFsZ0wmOBYMWxqPaPRfn1MBDZKihQeaxA3BWGVe3z9IatEWXBXKmwIcXuhcFogy8N9k5Q==
X-Received: by 2002:aca:90f:: with SMTP id 15mr3216442oij.27.1643063604896;
        Mon, 24 Jan 2022 14:33:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4807:: with SMTP id c7ls5358996otf.0.gmail; Mon, 24 Jan
 2022 14:33:24 -0800 (PST)
X-Received: by 2002:a05:6830:2814:: with SMTP id w20mr6432347otu.10.1643063604576;
        Mon, 24 Jan 2022 14:33:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643063604; cv=none;
        d=google.com; s=arc-20160816;
        b=v4MZurG5S/oGM7qYDGEuDNtXgC7RbExel8a2550Y4lvPEOlhwP+VxBEZLpdH4oviga
         xZWQv64nTPyJ5Jq2DEqs8smcsjq0TRgumezZeHg6k4hIqf2DsTfJDGj/cJwKO/wLAGMK
         YKjVKyY5DmfrGOdgrZkJP3AngBHNw3d79ZfItw8HuAwEGMCZE39zg2BLMNwBChNRlBMK
         Nks16a9iOHN/gI2a5vGdw+v+ZvcTF1H9hh0+LJKya+Nv0sYIfj1U1qEuenSyYKNgslHl
         lDMD9yWqZeclzy6Tl7ZwYi69IAQYfgZXVwbm4jpbCgKkBxW0+SCkHTWrWqkZKuNSXofW
         5T2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O5eAllqBOa11gWFD3bXB1J+EOSlOaRJV9IqmWOlMTeg=;
        b=UUpSpWk8i1zAtycYSpDBbyIYzNKSHbhz/k9zPoFOmmmEGuxAiarZ09Mc+nmsSRsMju
         sJq3fTxnt2XpGoZIAwsishDUXSoeA5DU3obRCI0gY+lK9X8ughuGfqOK8k7nfF9fQv9P
         HrFUVkgKFE+cAB71CwvVY435rAlk8LfsiS8VnnROx+Z8Cc7QlgviqUMsRixJgmNCKECi
         ncI5gfufGvazkB7ARYNqx6zBDpsmctuqdSPGdN7j/YTNmXKQdQtxcmoWuTYyCuLjjCCi
         ifnRbJ+T/9MEMnbqSe2wc+1kq11EMyuDXr882DFbh7AZ1edL3yufPLSp1KuofbiIG0sr
         H2ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mZ8GIjqK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id h8si136220otg.1.2022.01.24.14.33.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 14:33:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id s18so4925037ioa.12
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 14:33:24 -0800 (PST)
X-Received: by 2002:a02:bb98:: with SMTP id g24mr8335227jan.22.1643063604155;
 Mon, 24 Jan 2022 14:33:24 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-2-nogikh@google.com>
In-Reply-To: <20220117153634.150357-2-nogikh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Jan 2022 23:33:13 +0100
Message-ID: <CA+fCnZdO+oOLQSfH=+H8wKNv1+hYasyyyNHxumWa5ex1P0xp0g@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kcov: split ioctl handling into locked and
 unlocked parts
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mZ8GIjqK;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

.On Mon, Jan 17, 2022 at 4:36 PM Aleksandr Nogikh <nogikh@google.com> wrote:
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

Arguably, we could keep the part of the KCOV_INIT_TRACE handler that
happens under the lock in kcov_ioctl_locked(). In a similar way as
it's done for KCOV_REMOTE_ENABLE. This would get rid of the asymmetric
fallthrough usage.

But I'll leave this up to you, either way looks acceptable to me.

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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdO%2BoOLQSfH%3D%2BH8wKNv1%2BhYasyyyNHxumWa5ex1P0xp0g%40mail.gmail.com.

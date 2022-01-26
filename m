Return-Path: <kasan-dev+bncBCXKTJ63SAARBV45Y2HQMGQE6UK6S3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC6D849D174
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 19:11:36 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id x5-20020ac84d45000000b002cf826b1a18sf356445qtv.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 10:11:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643220695; cv=pass;
        d=google.com; s=arc-20160816;
        b=ivWEEsLg5tR/fYLDFJSYm/8nnawFHATGX7rYSuxn4g/C1pxN7pRls30381qrpuFKzP
         0ViqXQC7u9h6GEOe/7/Cn7O7lfCRhSNhEQmiKVE1X5IEQR2S508VDF2WtZ2gRL9nPLJ5
         6wLPphlhgWy44hu871rRDHszpS+xQjVwYrMsZ9S4vGtJlaywmMDBvrHRR3JzNU0DCNKs
         /jiYVQwUT5rqRT2G4BK6i2PSUweMctI2dhM1+oXj1UjZ86hltSgU2u8nAgFNayHPNyCR
         sLOqKFlxW72QeQq25yGSdpqiTTaIvwMXfVasX4w/v7zF4QFhw0wBiPSWXvVCR1oph6mh
         3hbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bwAZM13IYfHiOWUcpq+HO+R8PGzRAo3HTEVUUDPnUUM=;
        b=EjOwGHVbV9V4smbeBkz7RdULIxNgK8k2YLqEB1Ss+hdOxznYPsILX4AY0shvb7QpKc
         b10uiDon+fnVc+FCDi/jrOFpU87QSP0j16Yy61ORKLVxjdtAhTuljagW9VlbAHuwPmtB
         UW1zr+Ol0H2zKNF1NKAsDzaqVft7LsVQhC5kufQHHywE+ULYIIxzx7V4fhP2T47bPElI
         qLfDtt4mGXGWf3Cb8rFaBJMr6/KR2/jlVmVWAgCGLM+lijbMlLdBp9+xh4QA+fRyRoZz
         uYXv2HeZCCV1DY4XGNwbSE8WXJNtYV7CFloq4GfhwL9sD+nXFTay3sUQfOYlaLB9JYtu
         hffA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n0bOA9FA;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bwAZM13IYfHiOWUcpq+HO+R8PGzRAo3HTEVUUDPnUUM=;
        b=bUQja+nXEa10mJwMlwunD1mBRABBYYO2A+mN+4cW/WaKPl1s6YvBswBBvKfbCUvdkf
         Yyo2LAdWADXTJT4pt290fUb3HvKiMsWaVRqq6BA5kcR/315PRK8mnLezLjXFqo28B6Cz
         Jp9APydZAfcbvgBAUjI+ojO4pOipxJ9znA9Awis9Olqhnb9FXX9n5KIyJaiJtGXI81sy
         d2ZdD6Xtiz90VeiZjl6MfKaeYEY1Vs9qjxTXm+zGIiI4kpNqLborQJSOQH1aknQ8yhNz
         JdI1jzJ71YlcVchjR1D9JAWzWYGUEqhWK6GHJwCQKYB+xAHDfTW2eJnTwPtTT2KPKayJ
         aM8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bwAZM13IYfHiOWUcpq+HO+R8PGzRAo3HTEVUUDPnUUM=;
        b=zt7MTS4oyjs2bJygWeLQ1CWuwZTeV3VGWSQj5EQIGWEVm2R5fG1Np7KTRSizBmwkr5
         /lHGJvktCO4Tq4Rq+M/JohQsM41iHSN8dsoydpXwJjK06wJN45BaaUjaknkRnA1Jny3R
         mN0GebrXd3Gt0raUsONZIGxOtvL7NKziyWUl3YXw87kC05UU8XR+WYwZee6s5NqoR1LB
         4ozAQ4kfbRKU/iGZh65yBi00bIP8pNjHQinn1c4doyGwIV0lh+0I8tJmsYQQuqENooYL
         0vIXsjJsZhh6RfrtSeakEBZqnzl2KvSVLx3Vdp5urci9bbJxa7QCUnc99yKinBxf48hC
         aOxA==
X-Gm-Message-State: AOAM530stBZlcJk+ib1e6MMcvJ8Wlj5IkORZQ+WTVmR2MPMBEGqfokQi
	meEl9CEMK2BriUxF3jgw1i4=
X-Google-Smtp-Source: ABdhPJyVwA4pQr69u09CVMmuWPvMqrwI7aEkrRe+xwH6QonGtKzEeEYPN8GbQbkl7mVx/NitCmSZJg==
X-Received: by 2002:ad4:5ba3:: with SMTP id 3mr7393072qvq.113.1643220695565;
        Wed, 26 Jan 2022 10:11:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5057:: with SMTP id h23ls1511731qtm.1.gmail; Wed, 26 Jan
 2022 10:11:35 -0800 (PST)
X-Received: by 2002:ac8:7c46:: with SMTP id o6mr21254765qtv.587.1643220695101;
        Wed, 26 Jan 2022 10:11:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643220695; cv=none;
        d=google.com; s=arc-20160816;
        b=x22117vDFI5/Ma2ucilr44BvYIM2SgApvCdRAOhl+w7WKxmpeye+qJMFNKEexLzNwR
         32ERi0DmbmNlDEDesi+a18AHikxn/8/0DA51HnWoFscwkcwnIaalwCMVCVcufhcn1RQI
         Vs/0sIUVwsF/9L0HMGaJVx5RG/TjGiNitHGEMX1y+EFMld4My+9eCgT5mXLaTWT9ffJL
         bIDRvUXjSK7z4vW2AITDhz6rd7jTBtIauVprdmOxcq07MsuABS/nCh36wRhfIn+ZjLpN
         rhwLazhUtz8RB/4wtDt1U5T1caaMpZ5/GADE432L7CF6JYil6UWumtGQdVPLI7Ptf13u
         L+xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vm/173MgUik8C/5SMcwN9zwaSmwUKvdrsn1QPcEg1Po=;
        b=t04Sdmr+JQ7+oKbXIfmTswAkg+0Eeum4F2Nr4PAmJwncf6mo0kfcVOCS5IJkLaeY9t
         FvH8f75jDL2TBxESSAAi10o43iJ0YXpKnoQLkbIm6IAz6gclJvY2WfKr4/uiWFCdW2if
         lxdEoMSI9XOrPEtGoWkZedlZ1D3eXWEpqzowF58S5r018wnzYTeo4VlVhPaUDI+61Y3b
         Yz/l0/nIxID07Hhpjb8wBMqQ0hADejpJtFVyhKRBiUoZi2/dQlDEYwYRbHVGgk87f9S8
         putZm6CDuS1cxXTp9dlBtjVgMSZyRQH19F6MAGpKE8Xywls7SIBC1chWYJJQAWHhgZPr
         FI3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n0bOA9FA;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id m1si2325536qkp.4.2022.01.26.10.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jan 2022 10:11:35 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id z7so400968ilb.6
        for <kasan-dev@googlegroups.com>; Wed, 26 Jan 2022 10:11:35 -0800 (PST)
X-Received: by 2002:a92:b50e:: with SMTP id f14mr216291ile.208.1643220694380;
 Wed, 26 Jan 2022 10:11:34 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-2-nogikh@google.com>
 <CA+fCnZdO+oOLQSfH=+H8wKNv1+hYasyyyNHxumWa5ex1P0xp0g@mail.gmail.com>
In-Reply-To: <CA+fCnZdO+oOLQSfH=+H8wKNv1+hYasyyyNHxumWa5ex1P0xp0g@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Jan 2022 19:11:23 +0100
Message-ID: <CANp29Y6HkhHyM1PZGbMtD=U6GeK2LfOHTDiOqiPVEhEXUHN7_A@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kcov: split ioctl handling into locked and
 unlocked parts
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n0bOA9FA;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

On Mon, Jan 24, 2022 at 11:33 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> .On Mon, Jan 17, 2022 at 4:36 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Currently all ioctls are de facto processed under a spinlock in order
> > to serialise them. This, however, prohibits the use of vmalloc and other
> > memory management functions in the implementations of those ioctls,
> > unnecessary complicating any further changes to the code.
> >
> > Let all ioctls first be processed inside the kcov_ioctl() function
> > which should execute the ones that are not compatible with spinlock
> > and then pass control to kcov_ioctl_locked() for all other ones.
> > KCOV_REMOTE_ENABLE is processed both in kcov_ioctl() and
> > kcov_ioctl_locked() as the steps are easily separable.
> >
> > Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
> > handling to kcov_ioctl(), so that the changes from the next commit are
> > easier to follow.
> >
> > Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> > ---
> >  kernel/kcov.c | 68 ++++++++++++++++++++++++++++-----------------------
> >  1 file changed, 37 insertions(+), 31 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index 36ca640c4f8e..e1be7301500b 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -564,31 +564,12 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >                              unsigned long arg)
> >  {
> >         struct task_struct *t;
> > -       unsigned long size, unused;
> > +       unsigned long flags, unused;
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> > -       unsigned long flags;
> >
> >         switch (cmd) {
> > -       case KCOV_INIT_TRACE:
> > -               /*
> > -                * Enable kcov in trace mode and setup buffer size.
> > -                * Must happen before anything else.
> > -                */
> > -               if (kcov->mode != KCOV_MODE_DISABLED)
> > -                       return -EBUSY;
> > -               /*
> > -                * Size must be at least 2 to hold current position and one PC.
> > -                * Later we allocate size * sizeof(unsigned long) memory,
> > -                * that must not overflow.
> > -                */
> > -               size = arg;
> > -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > -                       return -EINVAL;
> > -               kcov->size = size;
> > -               kcov->mode = KCOV_MODE_INIT;
> > -               return 0;
> >         case KCOV_ENABLE:
> >                 /*
> >                  * Enable coverage for the current task.
> > @@ -692,9 +673,32 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         struct kcov_remote_arg *remote_arg = NULL;
> >         unsigned int remote_num_handles;
> >         unsigned long remote_arg_size;
> > -       unsigned long flags;
> > +       unsigned long size, flags;
> >
> > -       if (cmd == KCOV_REMOTE_ENABLE) {
> > +       kcov = filep->private_data;
> > +       switch (cmd) {
> > +       case KCOV_INIT_TRACE:
> > +               /*
> > +                * Enable kcov in trace mode and setup buffer size.
> > +                * Must happen before anything else.
> > +                *
> > +                * First check the size argument - it must be at least 2
> > +                * to hold the current position and one PC. Later we allocate
> > +                * size * sizeof(unsigned long) memory, that must not overflow.
> > +                */
> > +               size = arg;
> > +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > +                       return -EINVAL;
> > +               spin_lock_irqsave(&kcov->lock, flags);
>
> Arguably, we could keep the part of the KCOV_INIT_TRACE handler that
> happens under the lock in kcov_ioctl_locked(). In a similar way as
> it's done for KCOV_REMOTE_ENABLE. This would get rid of the asymmetric
> fallthrough usage.
>
> But I'll leave this up to you, either way looks acceptable to me.
>

That would indeed look nice and would work with this particular
commit, but it won't work with the changes that are introduced in the
next one. So it would go against the objective of splitting the change
into a patch series in the first place - the simplification of
reviewing of the commit with functional changes.

With kcov->area allocation in KCOV_INIT_TRACE, we unfortunately cannot
draw a single line between the unlocked and locked parts.

> > +               if (kcov->mode != KCOV_MODE_DISABLED) {
> > +                       spin_unlock_irqrestore(&kcov->lock, flags);
> > +                       return -EBUSY;
> > +               }
> > +               kcov->size = size;
> > +               kcov->mode = KCOV_MODE_INIT;
> > +               spin_unlock_irqrestore(&kcov->lock, flags);
> > +               return 0;
> > +       case KCOV_REMOTE_ENABLE:
> >                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
> >                                 offsetof(struct kcov_remote_arg, num_handles))))
> >                         return -EFAULT;
> > @@ -710,16 +714,18 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >                         return -EINVAL;
> >                 }
> >                 arg = (unsigned long)remote_arg;
> > +               fallthrough;
> > +       default:
> > +               /*
> > +                * All other commands can be normally executed under a spin lock, so we
> > +                * obtain and release it here in order to simplify kcov_ioctl_locked().
> > +                */
> > +               spin_lock_irqsave(&kcov->lock, flags);
> > +               res = kcov_ioctl_locked(kcov, cmd, arg);
> > +               spin_unlock_irqrestore(&kcov->lock, flags);
> > +               kfree(remote_arg);
> > +               return res;
> >         }
> > -
> > -       kcov = filep->private_data;
> > -       spin_lock_irqsave(&kcov->lock, flags);
> > -       res = kcov_ioctl_locked(kcov, cmd, arg);
> > -       spin_unlock_irqrestore(&kcov->lock, flags);
> > -
> > -       kfree(remote_arg);
> > -
> > -       return res;
> >  }
> >
> >  static const struct file_operations kcov_fops = {
> > --
> > 2.34.1.703.g22d0c6ccf7-goog
> >
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdO%2BoOLQSfH%3D%2BH8wKNv1%2BhYasyyyNHxumWa5ex1P0xp0g%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y6HkhHyM1PZGbMtD%3DU6GeK2LfOHTDiOqiPVEhEXUHN7_A%40mail.gmail.com.

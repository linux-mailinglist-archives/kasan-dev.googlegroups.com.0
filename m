Return-Path: <kasan-dev+bncBCXKTJ63SAARB5MSRCHAMGQE3VC2XBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 052AF47C4A9
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 18:05:59 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id n18-20020a4ad132000000b002c64a9d89a4sf7782263oor.4
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 09:05:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640106357; cv=pass;
        d=google.com; s=arc-20160816;
        b=C6/1VG3nDgRGJixfVdFeKijjRA1HA92qQOaLKK7WjYYiQbIaadSZSbH6m2hJg5yJXw
         6Eyjf5PJ5yMzonqU6ocanNKtj8hJffg8rL4JFiqhGwUFfUFnXMHdvh00OsozcXNNUSKT
         K7fE7hZ7h7wA+IlS4+heXK2yd4scRf6EV6SIATIQTqCX8hM/Q5DZqOwPq/T1AjBFC35c
         RICY7NhqpKuTQC8gTRlPxoT7bLhQeoFg3xNLqtJ4KU25ZRjplGypVtpAtw5AfeoYjTWS
         LOgp5UKc8qTnGM3pQFGC+lt7uBmNWI2d19RYLUrsTgJFBXSR9lOXpZkgo+FmhLdGgnxJ
         MYfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tt5KLDyF34U2I1J/zD3c8qSlV54oCRvGfU66nAVoe5o=;
        b=YAMTe/1e7teHqLXWXbcZATGeq6XOzKfxzteIZQayLdelx+Gdm+c1WV1foGafivODHY
         L7vHOwgsQwxK9YvJ/zzfBkAbFcWf7g1wMPmPU/nMNw1nTeNGBCN+mjTJO+GcyCn3t0sK
         c+ZcP3brZxQT3M3PWda9zdQt7OeMnwG1npRzzveu34yVCNqvTPmYOJaQMEvTHkFYHeGN
         rxyv4Z2owvv6ANP0XQKD+N+TuTFS2Dh32ibVGbrYlmQdwHNY1hLyVCWEL8YPY0zGGPqD
         oUDlp56UneLBlQxdXmnl9ao07R4zG/HfNFietgW2l2A2pCWzF/UwQ04M67aXAmuX7q4q
         8gLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XJURkKA6;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tt5KLDyF34U2I1J/zD3c8qSlV54oCRvGfU66nAVoe5o=;
        b=Is9lOkuANSKbHuO/x4m/QgwVayt9CBQ5VNg8k7z17BjZ2KxzFLex0rRyT6sXDYvazT
         EojvpTqTAPzy6FhVl1DEsNM5CZ325fB8RKOMnUx+AJFkptTyQcyCRZHviUrfTl9gyg7g
         G5x7DHau3ZZyY3wBkrmnOHAW0U3aDxUTmPpJw+E4lJpbZi5Cm1FWsif1HbZ9njcrT+ZJ
         dL2ERoAKhm5LsGGBVelz2+EZOXm60VA4x29m9aP+FmbYhyXeNIRaanMRXQLF4oH8xtT6
         m+c79KfSpouW/ICvBrY/qS8wC4GxNnxD5SqLYNwUqf8Z2mHx1Y23DrWJIis+iywxb1Wh
         P69Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tt5KLDyF34U2I1J/zD3c8qSlV54oCRvGfU66nAVoe5o=;
        b=3VlO5Sbl0ZuidT9OKUAMEcdrOb36qBWX5uTUPqVPzFn/hYM0L8iFu+SN/QKXZHa+NA
         YHFGPuKlvzaCMbFeNaXkIOSoZtqc/Dcka1y4R/QtG7RCa7O3ribXCiVQHEPNkQqZ1PDJ
         8W2RgkMgfOzGO+YAigVINuY8zhK2rwq2C0a5Qzhz3LvN2FGLFz9TX7llECGacmuILWXn
         D1IK5ytdw2BNps/iMM5hTdRL9T2rffTD+w+TjM8XQAlr7zqDrBZeekECJVpQwdV1RSq/
         YTD+4FS5ZNyAi//jzdxvoZfsdiFsz7DCYc0VGz2N9IOcSSKgJY1o80701YnJcZl1elDf
         Ej7A==
X-Gm-Message-State: AOAM532loCPn9aQy1bQzZGBj+XV+FCrNnjwZCNpXwCEORRxvhEWSrUo3
	vWVmzxPQglZ3tcd5oCe/n3I=
X-Google-Smtp-Source: ABdhPJzYjQFeJSPnoGg+0tiUAzT7iZ6X2BYHIU9UF7TSv6BwdGRWlZLdCldfu5lypRMFIud7TW8ziQ==
X-Received: by 2002:a05:6830:199:: with SMTP id q25mr2914259ota.150.1640106357647;
        Tue, 21 Dec 2021 09:05:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2466:: with SMTP id x38ls4589706otr.10.gmail; Tue,
 21 Dec 2021 09:05:57 -0800 (PST)
X-Received: by 2002:a9d:27e1:: with SMTP id c88mr2135696otb.354.1640106357290;
        Tue, 21 Dec 2021 09:05:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640106357; cv=none;
        d=google.com; s=arc-20160816;
        b=LiTkQHJAF2m1KoG2/3fAPr0HYnoI5PyQ83mZPiJUDYgbNnlqK+Iw7E5FmZITZiZtF4
         GUTzMEgsbo60I7um1lotPTHlNiNF7ggrI2yaWRxWrL2dJO4lYMjKBaVd6RLWsfw+o+Dj
         ybbasGobArfnQmxVMynFZPXp1GjmXRoEAXRnSpKm+44dcx1XDBHqIe6GHNsmommN4k+2
         WxzSRZKTpniXgAI2cVGMqpq8murwftSvJGsHjrBY4SwnMX1DJIUXR9JFim2JX9T2wl9/
         XlkGJGTm8TxcHOK4tLV98MXxd54AyHMx/V462hXjV20IVhXO6rdMoYW9n6WUNVvfJDal
         /qOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pf9Q/hl+uiiucU7OfdQapd310FBBGphvRuGQ17j7ZWE=;
        b=TRKVh4e2J4iu6MNNa57hWq9Grazu0TdWI0jgzkmmCGyQLxkhruTmDS/U653LOaK1fp
         gx01vhwHbUDL+RBnXuYC6PNWt3YBcLl/UbGXSO8xbX90y+bQVu7ov24on57cJsyyVM1L
         Fk/k8IgzQttOyJphMpLkgSLYxdGcvoHcU8B+47LPO0zuLHx+VY6uxVWzlGg9Zkuf9w6a
         IosDTEBZSYNkfgfSkGnGvjkX9C3XhAdWF8gQ+6CSglYWPx06rvI9MON+B9dTE0BjdgxZ
         EAWWr6HAGJPTwZeUir+C09/RaOo280q3o6rxwGA4yACTwC1renUWPpFvhbwuwapclLFV
         Jktw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XJURkKA6;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id e20si1481789otj.1.2021.12.21.09.05.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 09:05:57 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id l5so10690274ilv.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 09:05:57 -0800 (PST)
X-Received: by 2002:a92:d18e:: with SMTP id z14mr984879ilz.245.1640106356791;
 Tue, 21 Dec 2021 09:05:56 -0800 (PST)
MIME-Version: 1.0
References: <20211220152153.910990-1-nogikh@google.com> <CA+fCnZePxPCpZcXv+Cj04ZFbNfF8DOikX_EN1bDt_psSpNrKSA@mail.gmail.com>
In-Reply-To: <CA+fCnZePxPCpZcXv+Cj04ZFbNfF8DOikX_EN1bDt_psSpNrKSA@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 18:05:45 +0100
Message-ID: <CANp29Y4R1o5+9_ATPFZuvX5qyJM46BVSapLEY8sb_r3oWRs95Q@mail.gmail.com>
Subject: Re: [PATCH] kcov: properly handle subsequent mmap calls
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XJURkKA6;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as
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

Hi Andrey,

Thank you very much for commenting!

I've prepared and sent the v2 of the series:
https://lkml.org/lkml/2021/12/21/737

--
Best Regards,
Aleksandr

On Mon, Dec 20, 2021 at 4:59 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Dec 20, 2021 at 4:22 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Subsequent mmaps of the same kcov descriptor currently do not update the
> > virtual memory of the task and yet return 0 (success). This is
> > counter-intuitive and may lead to unexpected memory access errors.
> >
> > Also, this unnecessarily limits the functionality of kcov to only the
> > simplest usage scenarios. Kcov instances are effectively forever attached
> > to their first address spaces and it becomes impossible to e.g. reuse the
> > same kcov handle in forked child processes without mmapping the memory
> > first. This is exactly what we tried to do in syzkaller and
> > inadvertently came upon this problem.
> >
> > Allocate the buffer during KCOV_MODE_INIT in order to untie mmap and
> > coverage collection. Modify kcov_mmap, so that it can be reliably used
> > any number of times once KCOV_MODE_INIT has succeeded.
> >
> > Refactor ioctl processing so that a vmalloc could be executed before the
> > spin lock is obtained.
> >
> > These changes to the user-facing interface of the tool only weaken the
> > preconditions, so all existing user space code should remain compatible
> > with the new version.
> >
> > Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
>
> Hi Aleksandr,
>
> > ---
> >  kernel/kcov.c | 94 +++++++++++++++++++++++++++++----------------------
> >  1 file changed, 53 insertions(+), 41 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index 36ca640c4f8e..49e1fa2b330f 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -459,37 +459,28 @@ void kcov_task_exit(struct task_struct *t)
> >  static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
> >  {
> >         int res = 0;
> > -       void *area;
> >         struct kcov *kcov = vma->vm_file->private_data;
> >         unsigned long size, off;
> >         struct page *page;
> >         unsigned long flags;
> >
> > -       area = vmalloc_user(vma->vm_end - vma->vm_start);
> > -       if (!area)
> > -               return -ENOMEM;
> > -
> >         spin_lock_irqsave(&kcov->lock, flags);
> >         size = kcov->size * sizeof(unsigned long);
> > -       if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
> > +       if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> >             vma->vm_end - vma->vm_start != size) {
> >                 res = -EINVAL;
> >                 goto exit;
> >         }
> > -       if (!kcov->area) {
> > -               kcov->area = area;
> > -               vma->vm_flags |= VM_DONTEXPAND;
> > -               spin_unlock_irqrestore(&kcov->lock, flags);
> > -               for (off = 0; off < size; off += PAGE_SIZE) {
> > -                       page = vmalloc_to_page(kcov->area + off);
> > -                       if (vm_insert_page(vma, vma->vm_start + off, page))
> > -                               WARN_ONCE(1, "vm_insert_page() failed");
> > -               }
> > -               return 0;
> > +       spin_unlock_irqrestore(&kcov->lock, flags);
> > +       vma->vm_flags |= VM_DONTEXPAND;
> > +       for (off = 0; off < size; off += PAGE_SIZE) {
> > +               page = vmalloc_to_page(kcov->area + off);
> > +               if (vm_insert_page(vma, vma->vm_start + off, page))
> > +                       WARN_ONCE(1, "vm_insert_page() failed");
> >         }
> > +       return 0;
> >  exit:
> >         spin_unlock_irqrestore(&kcov->lock, flags);
> > -       vfree(area);
> >         return res;
> >  }
> >
> > @@ -564,31 +555,13 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >                              unsigned long arg)
> >  {
> >         struct task_struct *t;
> > -       unsigned long size, unused;
> > +       unsigned long unused;
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> >         unsigned long flags;
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
> > @@ -685,6 +658,49 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >         }
> >  }
> >
> > +static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
> > +                            unsigned long arg)
> > +{
> > +       unsigned long size, flags;
> > +       void *area;
> > +       int res;
> > +
> > +       switch (cmd) {
> > +       case KCOV_INIT_TRACE:
> > +               /*
> > +                * Enable kcov in trace mode and setup buffer size.
> > +                * Must happen before anything else.
> > +                *
> > +                *
>
> Accidental extra lines?
>
> > +                * Size must be at least 2 to hold current position and one PC.
> > +                */
> > +               size = arg;
> > +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > +                       return -EINVAL;
> > +
> > +               area = vmalloc_user(size * sizeof(unsigned long));
> > +               if (area == NULL)
> > +                       return -ENOMEM;
> > +
> > +               spin_lock_irqsave(&kcov->lock, flags);
> > +               if (kcov->mode != KCOV_MODE_DISABLED) {
> > +                       spin_unlock_irqrestore(&kcov->lock, flags);
> > +                       vfree(area);
> > +                       return -EBUSY;
> > +               }
> > +               kcov->area = area;
> > +               kcov->size = size;
> > +               kcov->mode = KCOV_MODE_INIT;
> > +               spin_unlock_irqrestore(&kcov->lock, flags);
> > +               return 0;
> > +       default:
>
> I would add a clarifying comment here saying something like:
>
> /* All other commands are handled by kcov_ioctl_locked(). */
>
> > +               spin_lock_irqsave(&kcov->lock, flags);
> > +               res = kcov_ioctl_locked(kcov, cmd, arg);
> > +               spin_unlock_irqrestore(&kcov->lock, flags);
> > +               return res;
> > +       }
> > +}
>
> Please split this change into two patches:
>
> 1. Add kcov_ioctl_unlocked() that handles KCOV_INIT_TRACE special case
> without any functional changes.
> 2. Functional changes to kcov_ioctl_unlocked() and other parts of code.
>
> Otherwise reviewing is a bit hard.
>
> > +
> >  static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >  {
> >         struct kcov *kcov;
> > @@ -692,7 +708,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         struct kcov_remote_arg *remote_arg = NULL;
> >         unsigned int remote_num_handles;
> >         unsigned long remote_arg_size;
> > -       unsigned long flags;
> >
> >         if (cmd == KCOV_REMOTE_ENABLE) {
> >                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
> > @@ -713,10 +728,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         }
> >
> >         kcov = filep->private_data;
> > -       spin_lock_irqsave(&kcov->lock, flags);
> > -       res = kcov_ioctl_locked(kcov, cmd, arg);
> > -       spin_unlock_irqrestore(&kcov->lock, flags);
> > -
> > +       res = kcov_ioctl_unlocked(kcov, cmd, arg);
> >         kfree(remote_arg);
> >
> >         return res;
> > --
> > 2.34.1.173.g76aa8bc2d0-goog
> >
>
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4R1o5%2B9_ATPFZuvX5qyJM46BVSapLEY8sb_r3oWRs95Q%40mail.gmail.com.

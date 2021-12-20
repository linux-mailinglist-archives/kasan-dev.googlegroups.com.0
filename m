Return-Path: <kasan-dev+bncBDW2JDUY5AORBYOQQKHAMGQEFBJO3OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id D866A47B0C6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 16:59:30 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id v13-20020a05620a440d00b00468380f4407sf6221046qkp.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 07:59:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640015969; cv=pass;
        d=google.com; s=arc-20160816;
        b=XCY9u1L4kX7VXOUQWuSSQHY64njibbEuiDwH2VjwjPIEp5fV3wiz5buQvCYTFwMmW4
         q5QShiXc0LrA9fy+g6G7sbMX7g8sZh+tSZjiuVy327tOsax8ZNouVrLl/Z6YcS/RzHc5
         5sq0ngQ7427S18AfOsDosrilMJOqeuuTtmR11f8uVXKGpWcyO/MME3ZDWm3arkjmUHi6
         vChEwWztS9ulnGuoBcOVzvwhT1Wv5PMn5CEkjxF4wTEsRRe4bjG83X9v3+rBIzI3uJqP
         n6y9lTiNAFUe8SB8R4J7aADiiuSEkqB0fhPf7Glqm3yLgRpNq2EYEBLq8WxRm6zYFNlW
         r//w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jIyLuIarMR5HHNTzArIJcvBLh9plM3wcc9cLy4HXYOo=;
        b=ArgUVkm5czF+Q4X6kmc7dlN5xHSjDQvZ441kJ5UgOHVcNk+c3pnS6IZXSg/ekDObf/
         yppUeucj/hpcQDpjYTVY5swj1yL5wTjZPZ0u0wvyZhdv+4M8PPWqsQlU5CEVre+XsiH2
         GepvW4gUK7IJsTyKmbEg+ghZVIyRZUrkBGHZPYZFzxfjDbztAgIyDnTLQ7ivX+Ytl+AU
         WeTvATJSZ/n5fho/meglR+0MxJDhl2nLwOro6beZbt77dzIEpbRb+TizTKM0NT8rwwbX
         wU03DcAsBAbX6nGejW7NhpmIrFrGqWzb5sb/FUNI2AowWc4MfiX94G3gzYY17CZnH+Gc
         +Gqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EMrCLB48;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIyLuIarMR5HHNTzArIJcvBLh9plM3wcc9cLy4HXYOo=;
        b=f2ayLK3vyCFq3EikjSLPqA8h+p49ZeF7U+LF+iGug7Ja6a2hmK75wxueOf1TC+zjVv
         OH0NKKaEAdOiHjc4SSKIIqEasywD/DP4/VTCONJBcdxvhQOvxuKX2+X6YkI/CzmM4Q/2
         2+j6TGKp7Sdmj01IrxqHCzNbwe5KACSyj7+WKs5/VMLdA7BbW6HH9JP3MkkqDUr9qKbE
         BBbZ3knsGl0AZMT5zf+yNKuWVyDug0PZ/TcZ72Yij11CiAZ8FSQv+3Ivvq7Kmijm1Xy2
         vIHkYjDEKPllSCbwvruv5VZVjPQQcJEuxNgaGsxQQyRasWYgfzwejtZC6sWKTco22h0/
         BNug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIyLuIarMR5HHNTzArIJcvBLh9plM3wcc9cLy4HXYOo=;
        b=ngothuYaWRbkWfbouHq08KlXvDiprLecBudqvHz/Hrcbp31c45jxO06RSMF4pgpAwY
         YHyJ5Fvd/1LXGAb2PwCkJmcfFHrJ03IiZ+aRsemd4ZoKbbA7hNvFnqg1JwJ0rq3NLJ0R
         YG3BksyjrYacKNtNlVylGpOmj7rqh8Jb8RkKJGgcJJ00zN2kKf5jXZlr2nuJmIL1/QTg
         Rsk85gK90ooI2xSZ8/TCnCv2UXg9ud9KbPOg3J5mWUvzhe/mYrRXXsITZUgIDxm6WyKd
         Npd+5eGRi+VhVQLE6r5RTt9QgUy2Y/8i6VX8uBAqPsLIPETnuVyDe1aX8UEPlPVPkeQZ
         dzRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIyLuIarMR5HHNTzArIJcvBLh9plM3wcc9cLy4HXYOo=;
        b=lQsELetPeJ/8vwjVFGHiHcr0nsxH7tPCN/TH8z+bWNh4qGJ+FQBUDBEO3zKsm/qSHc
         gdgI1SSnctnbEAgYtlJwBiYlYfj9LdHgNe51dYBAwelLaBY4dA6WpD2lLrb9682bNtkO
         hUUtZi9Ku8Hr2Oi6le6BaDREK0Psc0M+uEjziYylpojp0yiDLQ0SqbDR4bjVy51Vad4U
         BEKjkBOLGLOgAb0mqqGAjWq1CXLj9NfHzP3rBwP1zYf0+XWqLqsra0/YUWLoJD4aZBxo
         t4q1Oi9Q+LIQArzXob2De622LkG68L+MkUMmdGuQdSeCm1rFvSBjOemVuKXKIhCFgnp2
         FYPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l6mHtrD36nRGSz235UM/beqVOhi4S5UNRBMsMWEgAj8IWVJmJ
	3BcfM0QoLF6FdYsENj8w764=
X-Google-Smtp-Source: ABdhPJy49Vnq908rYOxunpVgCYFieoqn9xI/z+5Y2Ik65WBChVSXfuCm5GkBEj9fXifgd7kzOLcsGA==
X-Received: by 2002:ad4:5cef:: with SMTP id iv15mr13382449qvb.85.1640015969793;
        Mon, 20 Dec 2021 07:59:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:318e:: with SMTP id bi14ls8304094qkb.9.gmail; Mon,
 20 Dec 2021 07:59:29 -0800 (PST)
X-Received: by 2002:a05:620a:2955:: with SMTP id n21mr10003115qkp.581.1640015969379;
        Mon, 20 Dec 2021 07:59:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640015969; cv=none;
        d=google.com; s=arc-20160816;
        b=mXIfcX4cQPcV5e7RVmlF02ecPHDCyj3dm2cOtc5LV1bZdwOmk+/oWQsTOKkq4uR0yy
         iYAzLwf1b40ukNwZmcnQJG/33YW3aKuJ/4fd0+MFwlt+6hCDYuXnEwJNJONF7t8NGso3
         5xsTkbPrLLD/b+USrzgl4aNdRJhha15oJGagyW7y6MLJHRn35QerFXXy2+RsfBECmM7F
         2MATgvTHS18carsUsrnqOIZ2uR+XGlNtSEVEmuxEN51Z5rnd4letlJ2Y1ZBaFUa2MWUQ
         rmBFnpBiheki7amW34F06JblYUymRm84M2YAPnuIYcDcyi7ULIfMsu5UUpYdy62IbpJ9
         /V5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mPyAcHKRlcPk29q+H7gyncoQZnF0rHqG5b49zBrkFDs=;
        b=bRGq3eKHFvp5cjY0oKdFfnf5Xq1nx4EpkVU1vnZYci4jagL7xcXY8EmONdTyhvuLpu
         j+2DDy3WUaYZ/oZLyWD7Tjq10SKPLStt40Z+nrJ++monxvEeIKcn44WPMOT+68AWwqU4
         a9e+ShzVT3bFmNXOa8CHV/Dfs5qDQCGG9Ec8xQU12LXut2Hv/FqKQeis9yg0otWmzVUh
         Iz8bvoPNsHyt33cRRiAxOAE30n6OMz2ynDiqSuYANaVp2O/WXrLlPhhCob+w999qGsNB
         Amq6okfo86Ustp7hKkS2HIpVuS9c97nXRl0/ePcTR5Xx6MChBGLYiaYjfhZ7FtE9HoR8
         +hhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EMrCLB48;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id d14si1239232qkn.4.2021.12.20.07.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 07:59:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id b187so13867160iof.11
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 07:59:29 -0800 (PST)
X-Received: by 2002:a05:6638:2512:: with SMTP id v18mr4756500jat.22.1640015968872;
 Mon, 20 Dec 2021 07:59:28 -0800 (PST)
MIME-Version: 1.0
References: <20211220152153.910990-1-nogikh@google.com>
In-Reply-To: <20211220152153.910990-1-nogikh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 16:59:18 +0100
Message-ID: <CA+fCnZePxPCpZcXv+Cj04ZFbNfF8DOikX_EN1bDt_psSpNrKSA@mail.gmail.com>
Subject: Re: [PATCH] kcov: properly handle subsequent mmap calls
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EMrCLB48;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36
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

On Mon, Dec 20, 2021 at 4:22 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Subsequent mmaps of the same kcov descriptor currently do not update the
> virtual memory of the task and yet return 0 (success). This is
> counter-intuitive and may lead to unexpected memory access errors.
>
> Also, this unnecessarily limits the functionality of kcov to only the
> simplest usage scenarios. Kcov instances are effectively forever attached
> to their first address spaces and it becomes impossible to e.g. reuse the
> same kcov handle in forked child processes without mmapping the memory
> first. This is exactly what we tried to do in syzkaller and
> inadvertently came upon this problem.
>
> Allocate the buffer during KCOV_MODE_INIT in order to untie mmap and
> coverage collection. Modify kcov_mmap, so that it can be reliably used
> any number of times once KCOV_MODE_INIT has succeeded.
>
> Refactor ioctl processing so that a vmalloc could be executed before the
> spin lock is obtained.
>
> These changes to the user-facing interface of the tool only weaken the
> preconditions, so all existing user space code should remain compatible
> with the new version.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>

Hi Aleksandr,

> ---
>  kernel/kcov.c | 94 +++++++++++++++++++++++++++++----------------------
>  1 file changed, 53 insertions(+), 41 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 36ca640c4f8e..49e1fa2b330f 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -459,37 +459,28 @@ void kcov_task_exit(struct task_struct *t)
>  static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>  {
>         int res = 0;
> -       void *area;
>         struct kcov *kcov = vma->vm_file->private_data;
>         unsigned long size, off;
>         struct page *page;
>         unsigned long flags;
>
> -       area = vmalloc_user(vma->vm_end - vma->vm_start);
> -       if (!area)
> -               return -ENOMEM;
> -
>         spin_lock_irqsave(&kcov->lock, flags);
>         size = kcov->size * sizeof(unsigned long);
> -       if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
> +       if (kcov->area == NULL || vma->vm_pgoff != 0 ||
>             vma->vm_end - vma->vm_start != size) {
>                 res = -EINVAL;
>                 goto exit;
>         }
> -       if (!kcov->area) {
> -               kcov->area = area;
> -               vma->vm_flags |= VM_DONTEXPAND;
> -               spin_unlock_irqrestore(&kcov->lock, flags);
> -               for (off = 0; off < size; off += PAGE_SIZE) {
> -                       page = vmalloc_to_page(kcov->area + off);
> -                       if (vm_insert_page(vma, vma->vm_start + off, page))
> -                               WARN_ONCE(1, "vm_insert_page() failed");
> -               }
> -               return 0;
> +       spin_unlock_irqrestore(&kcov->lock, flags);
> +       vma->vm_flags |= VM_DONTEXPAND;
> +       for (off = 0; off < size; off += PAGE_SIZE) {
> +               page = vmalloc_to_page(kcov->area + off);
> +               if (vm_insert_page(vma, vma->vm_start + off, page))
> +                       WARN_ONCE(1, "vm_insert_page() failed");
>         }
> +       return 0;
>  exit:
>         spin_unlock_irqrestore(&kcov->lock, flags);
> -       vfree(area);
>         return res;
>  }
>
> @@ -564,31 +555,13 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                              unsigned long arg)
>  {
>         struct task_struct *t;
> -       unsigned long size, unused;
> +       unsigned long unused;
>         int mode, i;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
>         unsigned long flags;
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
> @@ -685,6 +658,49 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>         }
>  }
>
> +static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
> +                            unsigned long arg)
> +{
> +       unsigned long size, flags;
> +       void *area;
> +       int res;
> +
> +       switch (cmd) {
> +       case KCOV_INIT_TRACE:
> +               /*
> +                * Enable kcov in trace mode and setup buffer size.
> +                * Must happen before anything else.
> +                *
> +                *

Accidental extra lines?

> +                * Size must be at least 2 to hold current position and one PC.
> +                */
> +               size = arg;
> +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> +                       return -EINVAL;
> +
> +               area = vmalloc_user(size * sizeof(unsigned long));
> +               if (area == NULL)
> +                       return -ENOMEM;
> +
> +               spin_lock_irqsave(&kcov->lock, flags);
> +               if (kcov->mode != KCOV_MODE_DISABLED) {
> +                       spin_unlock_irqrestore(&kcov->lock, flags);
> +                       vfree(area);
> +                       return -EBUSY;
> +               }
> +               kcov->area = area;
> +               kcov->size = size;
> +               kcov->mode = KCOV_MODE_INIT;
> +               spin_unlock_irqrestore(&kcov->lock, flags);
> +               return 0;
> +       default:

I would add a clarifying comment here saying something like:

/* All other commands are handled by kcov_ioctl_locked(). */

> +               spin_lock_irqsave(&kcov->lock, flags);
> +               res = kcov_ioctl_locked(kcov, cmd, arg);
> +               spin_unlock_irqrestore(&kcov->lock, flags);
> +               return res;
> +       }
> +}

Please split this change into two patches:

1. Add kcov_ioctl_unlocked() that handles KCOV_INIT_TRACE special case
without any functional changes.
2. Functional changes to kcov_ioctl_unlocked() and other parts of code.

Otherwise reviewing is a bit hard.

> +
>  static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  {
>         struct kcov *kcov;
> @@ -692,7 +708,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         struct kcov_remote_arg *remote_arg = NULL;
>         unsigned int remote_num_handles;
>         unsigned long remote_arg_size;
> -       unsigned long flags;
>
>         if (cmd == KCOV_REMOTE_ENABLE) {
>                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
> @@ -713,10 +728,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         }
>
>         kcov = filep->private_data;
> -       spin_lock_irqsave(&kcov->lock, flags);
> -       res = kcov_ioctl_locked(kcov, cmd, arg);
> -       spin_unlock_irqrestore(&kcov->lock, flags);
> -
> +       res = kcov_ioctl_unlocked(kcov, cmd, arg);
>         kfree(remote_arg);
>
>         return res;
> --
> 2.34.1.173.g76aa8bc2d0-goog
>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZePxPCpZcXv%2BCj04ZFbNfF8DOikX_EN1bDt_psSpNrKSA%40mail.gmail.com.

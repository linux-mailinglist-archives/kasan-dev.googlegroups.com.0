Return-Path: <kasan-dev+bncBCXKTJ63SAARBE4VY2HQMGQEEKB72WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id A27F049D128
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 18:53:24 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id z188-20020a3797c5000000b0047cf1030280sf290933qkd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 09:53:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643219603; cv=pass;
        d=google.com; s=arc-20160816;
        b=BKL+VLSj/nO79gvfVQdj6saz3FdbNXjWzidyUbjVSfwKQdOzjRFOs/r6Jb90V907TL
         hq9LYJQp5RnElbcfF4JWFqPT6wgZyg1oQ535tBThyPyzVNY71GjwB8m5IYwSVEQQQe54
         zAIbjuXV+FahSwKsJPGXiw3WPqC3qZbkD8cyqmPQkQg+OzDoV75pAxrajD8g/Zi0PxAV
         grJCRKJ82hyt90TAOkM8QSJ//iCrky8EQ1bsYCfcrYsnMY4+8n/P0itAoM11frCkIX9H
         LnfzP0wrjO38r6NdUMmrwk5bMvQPgiQtb//6zxHMQjncgJ13lBAWMsy1nceRm1XD9A1B
         RNaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aY+Fq8hd+bSiBlfPPo08a0+kAc6aZR/xa+h+FTHv7lk=;
        b=cWJOnlr2YLiGMD+Bfbc7iLuwNkW22hjqnqRuBKBxNqoI/rOXZJpzpUfh/W9V/i/eC5
         sOvosQk4L6bvv4wZu3ao94I+kRO9Iut4Qg1mFA63YQ+DYBkJzo2rA3cwht+ib4Lc6M64
         2L0I0T1qb4AKoE7FJwcxUD/Eh/NQwW/4k7MFJYxS5q4oZwM8sKMPT6zEcJLRoLtvbf1/
         wtH6aKBWZEh8iZkeMS8UinC4SdJkTkphrO5nVd7HeIz7GWVloiBEaH8anoOaWfCkjt4x
         eqW3xl65XXyy9RXPX2GvXnNbqJY+E+eBAjLhT1namxEEPyHRSazb49ktD39rPy9Gr9ON
         NyTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=i9L6HTFH;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aY+Fq8hd+bSiBlfPPo08a0+kAc6aZR/xa+h+FTHv7lk=;
        b=lJda0v63F6oZmQqjEVa+L4hct4tkZrs3xC5ui+f/PKucjtU1/lHKYS++EI45XuYqXg
         hcmz0COOh+mzRwRVnLmVP2IuDuAT27tjK6tGFxr9QsfG5iq2CKl+HavSD9wxw5CbzPZq
         nnvlLQG7WBMNq41YZtPdm016QIQpbB1S5Ohk7nl323c1HZu0ePMkpVwq+1gB97L8GtH6
         H3mv2fBCLPbKvxH6O2ORXfDcoskmPmQHxaZJbU8Dqi72fvynh4zhh/odUUugv1OrXZNb
         wJaEk9oEuNjIUbqasOCjPUFtt8gY8sHk0EYfrzdBoOpKJp+vj4eCRdn3zlSpmYHn/R5f
         I4Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aY+Fq8hd+bSiBlfPPo08a0+kAc6aZR/xa+h+FTHv7lk=;
        b=Bz3bRaGPDooiF3/WMcQGAnIPN6LykdqTW+/SySynrZKIRboLcr8IPAWgPxxXYz7p/b
         lrmD6A0iIw3x+6tKEkGHADMLjdJNZ1PCFbsm1cGSR9Exy1NMu5+ciFYTGqDOEh7pnGTl
         whMwF+IGlwWc9IyfN1yEgsDPl7tzTj+OyeKtJlMdG9Q03635LmNqupYsZNEmdSxnLhVf
         UCKo3Hk5OFC9Injop+u8LeDeAiL9vvEet6UXa5fhmTZQrei9cyr30EWjoqjJn5yFuw8k
         fdq57hwUO/KTHgxYc58D/joUEo/mPYHTTEO+26Af60AqeuefPSdfOIc5rOaukJUPAWdm
         tqNQ==
X-Gm-Message-State: AOAM530o22QX7KaNRmKwr6Ewv1udDDpOEIyW3omydeIWWpi9UqZAgTpc
	g6QtO4SrD8ASleAbefzZsDA=
X-Google-Smtp-Source: ABdhPJwJZt7uIPlj46d722IlIrqR+Do7lAR5hWbyh+a0z2g7luVEa0s/MJaA5ait/M0a+xdTpWChCQ==
X-Received: by 2002:ac8:57d4:: with SMTP id w20mr11377305qta.67.1643219603412;
        Wed, 26 Jan 2022 09:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:24c8:: with SMTP id m8ls1430252qkn.5.gmail; Wed, 26
 Jan 2022 09:53:23 -0800 (PST)
X-Received: by 2002:a37:ae43:: with SMTP id x64mr14251387qke.681.1643219602897;
        Wed, 26 Jan 2022 09:53:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643219602; cv=none;
        d=google.com; s=arc-20160816;
        b=Xvbf3BOMG+mp5aNkZ8/2y3+Nvn7Yodm7jVTpMDe+0YIkZWKhS6jAQzB1mh53D3Ie8L
         rB4AeKfhl4kQxjW/XigxW9lZaOi7ZmYo4fzb3xqfuSyHN2uiqBse9M2/c4cNbycpSDiW
         CjMvbXCVWadgkL7WMr55NIlSsWGKWvcUS+omeKPz4r3+BA6yg5YHGA4pui8l8O2Cc/M5
         /GzLdx+Bn44w3b7xkh7159pGQtWN4nxCsK4vxmbkeS7Jw4jkfhLuxw3Jpct9Bsk2ZP7q
         53INcsY396QaGUqE5qQ4A4gfgOiP2wCBPoT1c/j6fGn5qNWVdO+2CCdzyuAL4SoMKMEx
         vYBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dtNWMQ6fpndr+gNiN9rmzbRxHIN+CmzsS5NgAG+zOwA=;
        b=gVGsV7qSQVQgHZhFVdvsg6Sb2I5Te29DsYc3EQhJ+WR+dFbcjPI1kjn2Jx5JBBZCE3
         LuCuq0Qi2R8vQhnz8zxtp1aNxl0RgSvSQ6GJo14spocJq10zDNRE/4vnRpdn9O2RZ+GO
         VezzmtU4SVkrfo12J7qPIKLuXFlvKPoZ20T6qfmnXjFQutG3CeVeyjhMI+c2DfZVEnv5
         i3M5zpYKFAODTkHONEw5sLKB2vWMhwJD2XWgsRffTVRjFnV3VDhaI0APW1zIjTJgiKQP
         UTKkig4HGKerYW4jejoFPHxHsyZzdo1bcp1J2FcGHDVQIs/VgsfgBqJ2JKWtHFpMtr+4
         itfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=i9L6HTFH;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id i7si2457265qko.1.2022.01.26.09.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jan 2022 09:53:22 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id c188so511987iof.6
        for <kasan-dev@googlegroups.com>; Wed, 26 Jan 2022 09:53:22 -0800 (PST)
X-Received: by 2002:a02:9427:: with SMTP id a36mr11213152jai.259.1643219602187;
 Wed, 26 Jan 2022 09:53:22 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-3-nogikh@google.com>
 <CA+fCnZdUJS=qcTKews9XEgZi8=u5=iHPkDh1MaZryKL45vOKDQ@mail.gmail.com>
In-Reply-To: <CA+fCnZdUJS=qcTKews9XEgZi8=u5=iHPkDh1MaZryKL45vOKDQ@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Jan 2022 18:53:11 +0100
Message-ID: <CANp29Y63K326mhX8AVQ+w2PeccUsy9V8uvKO5iR-N6PqaaDUJg@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kcov: properly handle subsequent mmap calls
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=i9L6HTFH;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d2e as
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

Thanks for reviewing the code!

Yes, it is safe to access kcov->area without a lock.
1) kcov->area is set only once since KCOV_INIT_TRACE will succeed only
once. Reason
for that is that kcov->mode is only set to KCOV_MODE_DISABLED during
kcov_open().
2) kcov->area won't be freed because an ongoing mmap operation for the
kcov fd won't let
the kernel invoke release() on that same fd, while that release() is
necessary to finally
decrement kcov->refcount.


On Mon, Jan 24, 2022 at 11:33 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Jan 17, 2022 at 4:37 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Allocate the kcov buffer during KCOV_MODE_INIT in order to untie mmapping
> > of a kcov instance and the actual coverage collection process. Modify
> > kcov_mmap, so that it can be reliably used any number of times once
> > KCOV_MODE_INIT has succeeded.
> >
> > These changes to the user-facing interface of the tool only weaken the
> > preconditions, so all existing user space code should remain compatible
> > with the new version.
> >
> > Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> > ---
> >  kernel/kcov.c | 34 +++++++++++++++-------------------
> >  1 file changed, 15 insertions(+), 19 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index e1be7301500b..475524bd900a 100644
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
>
> Hm, you're accessing kcov->area without the lock here. Although, the
> old code does this as well. This is probably OK, as kcov->area can't
> be changed nor freed while this handler is executing.
>
>
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
> > @@ -674,6 +665,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         unsigned int remote_num_handles;
> >         unsigned long remote_arg_size;
> >         unsigned long size, flags;
> > +       void *area;
> >
> >         kcov = filep->private_data;
> >         switch (cmd) {
> > @@ -683,17 +675,21 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >                  * Must happen before anything else.
> >                  *
> >                  * First check the size argument - it must be at least 2
> > -                * to hold the current position and one PC. Later we allocate
> > -                * size * sizeof(unsigned long) memory, that must not overflow.
> > +                * to hold the current position and one PC.
> >                  */
> >                 size = arg;
> >                 if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> >                         return -EINVAL;
> > +               area = vmalloc_user(size * sizeof(unsigned long));
> > +               if (area == NULL)
> > +                       return -ENOMEM;
> >                 spin_lock_irqsave(&kcov->lock, flags);
> >                 if (kcov->mode != KCOV_MODE_DISABLED) {
> >                         spin_unlock_irqrestore(&kcov->lock, flags);
> > +                       vfree(area);
> >                         return -EBUSY;
> >                 }
> > +               kcov->area = area;
> >                 kcov->size = size;
> >                 kcov->mode = KCOV_MODE_INIT;
> >                 spin_unlock_irqrestore(&kcov->lock, flags);
> > --
> > 2.34.1.703.g22d0c6ccf7-goog
> >
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y63K326mhX8AVQ%2Bw2PeccUsy9V8uvKO5iR-N6PqaaDUJg%40mail.gmail.com.

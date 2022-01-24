Return-Path: <kasan-dev+bncBDW2JDUY5AORBPWSXSHQMGQEBX4CM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D317499D38
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 23:33:36 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 127-20020a250f85000000b00611ab6484absf37676565ybp.23
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 14:33:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643063615; cv=pass;
        d=google.com; s=arc-20160816;
        b=WNrt4gmz3hoFyyqvv4p8vjEYI66y8GLMrxxF1WiOP7XzzkvYhhU9ZH7Q7wnCA+LmEI
         aFiYeqci8mXAgaWqFy9acSIX51WDsgDeHx21y6odUsRqONzsR4t6ImQVJX6OAvcP88jo
         +Tgy/1yuYWjdFNd0s+w69o2CKXYBvuaimaVOGBmCtdoL+kEIdp4ya+8IiysuS5CuvakG
         Ueq3b84bEEGdvDRENXXEy1nOxS0BxGEXgvdW/Kg2B062yZTOD6R5+jS/4pLZmdnjYfCZ
         d4ztqYASPsdrWINkmaY3y0GHPRCsSDwjZCbaWjdDi5N7uII+ME/mgAYx2RKAmzBpJNaJ
         F86Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Qr/zBOR6KGDA/xQNEcoFA1GwT5Cu2RTL4wT/H6QPMXA=;
        b=HPE9Wvy1keNdRZcFXMLU9Z9rWxOnJ66IeadRH+Hinw/dz3ojYsCnYmi4P6A0NMTnNs
         HC3mxz0bTl9CO3tcQt7ILUt0mOHraJHCBdHfM3O4nrSKRqgeZ+yxPBIo0Aw/OPDtNoiA
         wTw6yxCycSmGnoe+nr61xK0feWf9KnvvCg/EsPZ3CpNBrrVKd+kHymm6+5pmXMQopLNZ
         MXxlhgCEBNpTF8RXUg6kmWlq2a2HKr1rpwMxH0WLx/aSyVjAuYPbg3Gv/43rtaZK0Rmh
         EckajrM/H3ZlnPnRp4M7JUldyTr89E7AM5JPiNSCWQXsxxwfa/RBWPVQadh8DtLFMe4G
         CeDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Vj6YY87H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qr/zBOR6KGDA/xQNEcoFA1GwT5Cu2RTL4wT/H6QPMXA=;
        b=Fe7hdTEo6nfOUewAnerr75mhiHrMejSbX2Q16OCoPFhwgf351+KIi13cZHmQ4wL+nx
         q4dZHeOBqRyyzROOe4N4Cl82sH4ktWS9ALJPe19hJImdK8CkTgI69+G/nzADPN+qAzl+
         /I/yfYQuK2Kx+oBMkNCqFk3C2yFfJRZsGEq3KI9S/DuSIOPJPhT1Aj/3eqN2DDDDkpu0
         2tQi3/ZRwxyaA2VWVenokdN/PjGcnaqSf3edQlVul4BHFP36TgGpg/QvcjhO3v+c2XNo
         OMvnvq6t/YeVzHwuOX9oJGCR7gED5zIA2DQipoSHwwAyVCwlgZ1xD0+5nkyzvhHpPe2Q
         EPpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qr/zBOR6KGDA/xQNEcoFA1GwT5Cu2RTL4wT/H6QPMXA=;
        b=c++m4RUQuTKB6vuybavw+M4x7Wg3FITWg5lsHoSCvpBrV801UvfX1naR1gI45IFZz+
         /mah6OEuhEKmpKgCs7tSm7Eu+BwWH7abjET1u4aI5b86BtIGAbCTFXJ0ltiJfw2pROfw
         Op+562b9VneIq5JQauvCGXcJwacZDuA+mBxEd+cjYIs6ce1r5DTRyx7aBQuar83p8khP
         cLcANGdTMGujmRVRHHO2fiiiqisTwHY7oZZPqz147ZD0Fc8c//nTZobxHHhnigYdYxE6
         hTeky2CVTtVnuT1tL1v1iAV5hafD1BNaWRijU/6w67ECn4majWAEd7LyQy+BfeCywqHw
         Glog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qr/zBOR6KGDA/xQNEcoFA1GwT5Cu2RTL4wT/H6QPMXA=;
        b=evsQe6I4aAnVuZJ8JBvIBDbSVZArlNVfSqTCjgwGYn/RITIejacRL9eC/89bABRx3a
         qTlCl5swQYy05EEieOrTwhx1j2J53wPPbHF93J/DWR2GGpY7wIZAoGDzAJT12LTkkJfZ
         MWrg9j6FHxdzXxvZH8NzeKlCxm4ti3Xs8shw3BVSuG8MPIO3tUpHMWB9Mk2DBH9qnvAB
         G/DhmCJILJai/1/vo+TMzL4RRn1L9+OSusVSSTP8gDusClaaFCslHrzEdQuKYXiUivIA
         fTHEATil0g7Y0AOd46xTZrxoFljVdHycDqdMXdtEZAq1Z1wE3dVR9TaMDJ1nSy1jnoGb
         CqtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531m0PvvAVM5Apa/WimE8Q8qFqHPWuYUeyLCw0DPJPH3eY2Qqr3h
	aaRn0Cod8oNk1cvc957ykZM=
X-Google-Smtp-Source: ABdhPJySX05I1E6aTPlPDvBWLoZd5flVLtsSfyv3KD0Z6r2ADQH8Y1ekgQzfStB0ifyg4tS9weoz3w==
X-Received: by 2002:a25:bb13:: with SMTP id z19mr25762710ybg.360.1643063615077;
        Mon, 24 Jan 2022 14:33:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6103:: with SMTP id v3ls18313948ybb.0.gmail; Mon, 24 Jan
 2022 14:33:34 -0800 (PST)
X-Received: by 2002:a25:afd2:: with SMTP id d18mr25978833ybj.609.1643063614624;
        Mon, 24 Jan 2022 14:33:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643063614; cv=none;
        d=google.com; s=arc-20160816;
        b=fnsAkYXY4JdwB+NtDArQ1ZbIeAtqiXR4ZFb8CwsV9xRZS1AcO/PQ2fdUhqtcVEymyo
         VA7Xn+U4dvHN3WXvruDcO5XPGMvYyjqlWNeYfPHWL+0cFO3YT4H0LdFVfu0e3jwufG10
         1a3WWao/1bwo30fjT7RCwOasJzxgFQUHhTbanxsRaV6PsFRLrJi9OKZZfZhfjkbGZyp8
         diqDwqhZVSyL884CSB3idOpdFFu89KNCOSYVZ5geUwVGnq248vjOz8pjbnNC4BXkgqLL
         FJ4bY0ecqXpjNMbwdUp30XT5bl3/9EbLzBfxd+jz1Rvn048/sHEsrJmEI92hEdgfkYCy
         63Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CgcWWoipX9AEgl7WxsfTrdOoQ6j1cPPjeKFCSVhOPgs=;
        b=hmuPbBhZ/imFBEPG1Qlf5UEGZ8ac1jkSgfnEtAWY/XeATnRNPBnYNwxI18KuyqalFI
         FUZ4JAEHjS+t6SMedwOEqLADgbyUtcgGJ7+VUKmmR3J0y4qa/iMVXW0xd/EDyaW2yz17
         Y62xnDICwE1lWqCSPoc97DoBALI71eC+cQqjLWMsXWMwrFhdmQ1tUBshEyGLwMP/zgQJ
         UrbPQgrD58a+eKk/tHW3vqFouIhFiYgBiYW3Q8L4hjZzTwMAfh2gaL/kvaffHFiCWtIZ
         MuRklTRDLtC+NgwdJiWE1qBl9qlOvX41YmO7ie3secIIR6T3Y6FNFTpklV7P/ykbRyYa
         YTsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Vj6YY87H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id s11si1128698ybu.0.2022.01.24.14.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 14:33:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id h7so3498779iof.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 14:33:34 -0800 (PST)
X-Received: by 2002:a02:c80a:: with SMTP id p10mr2768417jao.218.1643063614305;
 Mon, 24 Jan 2022 14:33:34 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-3-nogikh@google.com>
In-Reply-To: <20220117153634.150357-3-nogikh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Jan 2022 23:33:23 +0100
Message-ID: <CA+fCnZdUJS=qcTKews9XEgZi8=u5=iHPkDh1MaZryKL45vOKDQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kcov: properly handle subsequent mmap calls
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Vj6YY87H;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f
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

On Mon, Jan 17, 2022 at 4:37 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Allocate the kcov buffer during KCOV_MODE_INIT in order to untie mmapping
> of a kcov instance and the actual coverage collection process. Modify
> kcov_mmap, so that it can be reliably used any number of times once
> KCOV_MODE_INIT has succeeded.
>
> These changes to the user-facing interface of the tool only weaken the
> preconditions, so all existing user space code should remain compatible
> with the new version.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> ---
>  kernel/kcov.c | 34 +++++++++++++++-------------------
>  1 file changed, 15 insertions(+), 19 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index e1be7301500b..475524bd900a 100644
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

Hm, you're accessing kcov->area without the lock here. Although, the
old code does this as well. This is probably OK, as kcov->area can't
be changed nor freed while this handler is executing.


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
> @@ -674,6 +665,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>         unsigned int remote_num_handles;
>         unsigned long remote_arg_size;
>         unsigned long size, flags;
> +       void *area;
>
>         kcov = filep->private_data;
>         switch (cmd) {
> @@ -683,17 +675,21 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                  * Must happen before anything else.
>                  *
>                  * First check the size argument - it must be at least 2
> -                * to hold the current position and one PC. Later we allocate
> -                * size * sizeof(unsigned long) memory, that must not overflow.
> +                * to hold the current position and one PC.
>                  */
>                 size = arg;
>                 if (size < 2 || size > INT_MAX / sizeof(unsigned long))
>                         return -EINVAL;
> +               area = vmalloc_user(size * sizeof(unsigned long));
> +               if (area == NULL)
> +                       return -ENOMEM;
>                 spin_lock_irqsave(&kcov->lock, flags);
>                 if (kcov->mode != KCOV_MODE_DISABLED) {
>                         spin_unlock_irqrestore(&kcov->lock, flags);
> +                       vfree(area);
>                         return -EBUSY;
>                 }
> +               kcov->area = area;
>                 kcov->size = size;
>                 kcov->mode = KCOV_MODE_INIT;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
> --
> 2.34.1.703.g22d0c6ccf7-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdUJS%3DqcTKews9XEgZi8%3Du5%3DiHPkDh1MaZryKL45vOKDQ%40mail.gmail.com.

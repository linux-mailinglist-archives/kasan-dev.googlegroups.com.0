Return-Path: <kasan-dev+bncBCMIZB7QWENRBF6MTGHQMGQEGALYNIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id F2818491FA9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 08:02:48 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id x13-20020a056e021bcd00b002b7f0aa0034sf12037614ilv.17
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 23:02:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642489367; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBZlyw6lylXCf802sGs6OUw9V0OaZgLDn+9lndgblWH8eF1vxSQuBkgrWjIpuurF+8
         peCVR6OzzNYWdzdvSsgInGV1Vgn7c+jHnC6uC94E91hUSI6u7DhMysdJ4x76COh//6k5
         JDx5OhJSLZg05C4/bV0QUoedZiVcNJ04ZJaLchfH0E1+ON57ouVzaxo8yl6MfyYchj6G
         +ys0Epn+4zIjOX+U5B14YGElV2zhY79bfky7JFb17pEkuBAZDof4o4VPeTMinbqihpCx
         0+0Wsszpm/c0yFnq7fg9KTsuM2ChEedEYZ4Ct8HuoqoYH4DHhWFmayyIiHMXcgXXsbt3
         RPuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bLauiDaz+uFGjJ/MfC3Yp+WAuYwgYzRfitEEQnAAQAg=;
        b=uy3CQOugOUejUH6g9+buSB41ui1i6DDhDSYZUIom5JcXm+ua6dw3+j3NzQaiy0pJc0
         YB28I3h1/xmkvi1iqVOUqqltv93NAq1BtxoMn+xLz742PSPI8bQVb0gzU5sSUnGdHHJ9
         4ROIDqlHhFXigxc50HoZ8wKABROlh5nnRKrNkqnn9bKdQ8kJ+vYdWyzYouieMoEHRAhi
         F3MTREZcMmmd0jR94yMi5MI/qzZIqjxTPJKXvbsq7uEUa9WCdcKoZloFJLgITp04TmFy
         0udj91ypRvlgLSGX4mZVaZquJjiGTKrI8xDSzqqU8omS4n2NkTl0gJ29cANIqMm/nJNr
         MteQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BEvv2LoI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bLauiDaz+uFGjJ/MfC3Yp+WAuYwgYzRfitEEQnAAQAg=;
        b=IuTUI853kZAicKT5PnhFLk3owJeyutZIwi7Uwvw/9e0OzZP1UGPqz5FsK0xvoZqb89
         AnwBP1MNR10fC+CrrMkbi7CbPZX9+9T4Vfp9NEJTaMP7AjVeTdjPXaTbPqasKuUKo4Mo
         LUuYZUGfBbbobqgUB32BJXaoav5d6DxYd4l1KOmdeyq5e16I8tDoNYRNcUXVWNq2qXaN
         T6WM0Vr8TZ6uSaSsyI0O+Nfgf455IeCHHUiYpTqUbkO4b29qm4vIhZ4Jlh7GtV4t0pDh
         JYF73sJxE2xqCHOPAmY8X4BnouiytDYOcG7T2YwXheOxadE7a9Ion0oLY5iNXcWR2EAZ
         WgnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bLauiDaz+uFGjJ/MfC3Yp+WAuYwgYzRfitEEQnAAQAg=;
        b=Y5dXESJ2ebX6BHJp5USEJnY+J/VOhu2HTN1iWmki+a24xdk7J4+S1de+b5nUWdjoJ+
         6BSZ73i1hKcobZuXm+im1RLFilTB2+ZhADCBsKdk8Jrx5wwr9yl/Xh3xRQDnWtxKeGEm
         ZpjVbTwbf1RhuzWkU42I1Z9EoRXfa79njOZXbK87LP+qsplfwDAH3OdpWN0rcwfRYQ4z
         kRXALZmIm/8+aOm37LgOEr3s5PwexFyOvPPumMKCyc9O5S/mtBeRU+PVOwUKth3Dz90O
         o+xglSvW7BUpL9GT3+RriNXirQs6QPhogfnrJa1OF4LoF4PSIcvMgEmwoNpsFunZ0aFP
         3S4A==
X-Gm-Message-State: AOAM532/kP6tLYojLzCw2QEr1UzdQoQTlu0Yc6B0d7E57Mg3S2X10lBR
	CKNdDpiadkHvd7jRFY7ZDto=
X-Google-Smtp-Source: ABdhPJyft405vkN4nRd39Chkmd3ZcdmAc20LZX1UgfbeOLlFiI9yzI6p6U+QVj7AGZtMyez0wQXCJw==
X-Received: by 2002:a5e:8717:: with SMTP id y23mr8279706ioj.79.1642489367741;
        Mon, 17 Jan 2022 23:02:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cd8c:: with SMTP id r12ls379339ilb.9.gmail; Mon, 17 Jan
 2022 23:02:47 -0800 (PST)
X-Received: by 2002:a92:c268:: with SMTP id h8mr12540332ild.135.1642489367401;
        Mon, 17 Jan 2022 23:02:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642489367; cv=none;
        d=google.com; s=arc-20160816;
        b=jI5+UFqNbQ5i56jwmgDq+tkg4vgaTeXAp2idbTeRVaN/O/yTYffddypwRTQc3rJFv/
         kAz/pIPBOMLUdFDmE1Jwj9tM7HTYcLebwK30Wd8lTF39QUMZGoFcvUGfH8NHZus8JRlZ
         4+T5bQi93euwQdfowM6M9ZmGNwB1IWn/ZLWnrli2rxsDlijb0Ui5gDC3xkqwtRpcWzep
         mUKjgPPe2Nj6pAGW+HZ8snRYmiiSvvkcu67MxhlQ9KtfXaF4lnldevM8GjBuP4NJBum8
         Sa0UFdYltH1pVnf7A6WyUVofAZgbulNIm9rMvlody23gI6pzSJc+VXjDN9fXt3MbXjCw
         u0uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jPb1J18pp2+JcNd7ly09xmW41XnMO+ZDAZ+Gr42WbPA=;
        b=lpgs0S/ty2fkjz626Nz4WhHvAwKvA+I26lFl9FVR5kKDxDZhZrQNmEZD+gVnyLWU4Y
         2EeWzKUFBIUXftppJ4cstmwMXgEgAvjvrVPwij0JBiEifT/K9DVkkFkWzLQrZ0k/C1Oh
         YULxkdnlxolU7o8HYah7EmbzIFrn5H2E+HhyYRIiKLNcdrdHatmcglt4eD6MmsTSLDBr
         aVkVF2On8MBGekarwS/xioNTysemA1fRCUHnzOUXwLsjxYQknhxlSwRYMWe1jtTOexxU
         +4URfMktlIgQKLoYEfX3YDPpMr0n94FtXKVKi8+r7VlGbFryyspyTzUcK3Y4xA3XcvCf
         piHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BEvv2LoI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id h25si1204264ila.2.2022.01.17.23.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jan 2022 23:02:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id s9so27078468oib.11
        for <kasan-dev@googlegroups.com>; Mon, 17 Jan 2022 23:02:47 -0800 (PST)
X-Received: by 2002:a05:6808:290:: with SMTP id z16mr11273405oic.128.1642489366843;
 Mon, 17 Jan 2022 23:02:46 -0800 (PST)
MIME-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com> <20220117153634.150357-3-nogikh@google.com>
In-Reply-To: <20220117153634.150357-3-nogikh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jan 2022 08:02:35 +0100
Message-ID: <CACT4Y+bVMp26=aL3a1e_wccXwwNHwwy8-fmCienQ7hSmdmmw8w@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kcov: properly handle subsequent mmap calls
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BEvv2LoI;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c
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

On Mon, 17 Jan 2022 at 16:37, Aleksandr Nogikh <nogikh@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbVMp26%3DaL3a1e_wccXwwNHwwy8-fmCienQ7hSmdmmw8w%40mail.gmail.com.

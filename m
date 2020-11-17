Return-Path: <kasan-dev+bncBDE6RHVB4YGBBNVBZ36QKGQEJQWNZFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FAE62B5B70
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 09:58:31 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id z29sf24161798ybi.23
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 00:58:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605603510; cv=pass;
        d=google.com; s=arc-20160816;
        b=pxO55hh/mLbNRyxFJU0BqByNe/I4a52b4+6yCwNQNTCasDReVuO7mKtWuI/6xEBYSw
         M3CB8t8HS52XKj17e8qTMP9grr7sRVqfUXsLiuuXdOaT+2vLB92whGVPem0X1BDdnGlc
         d1dww49jgajlFqJIvkFGeB48m6tw67tK6d5G35++z+UsxWv1gUntd5c8+V2I/QSyv955
         vgqwwL4+b+MytEsidh3gWv9EWQ7rwSOPUJGJ3VOEsjW8m+2trXBHgrg1Up+droWyxn/A
         MSO1OzQGVD+rjDKxgi0RqB4ALzrRqPP7jVVuA6aKrOijD0z6mcQVy3DjTr6xhxKYVZ+e
         0TyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=DXOlIVQf0xq2VHSxn8gR71fgHiLmU7oMf5S2GOeks9M=;
        b=MWjqSF3gwrbu6uKhm6ZISbdWtWU9HdA6nvxPCL84Jwh0eUhM1LRRiYQhUZSAnaHX52
         MgykcCemFSgqh7B9HiAiVJ2Cv76rlb6uV5UKC0RzatQJrB1/O1LnEPyh7bj0SkOLDAld
         djf0GAQ+Z1hhbQr0/LBV68uJe0gpWck/8iLJHOgXQEaVq0sDVwBpL57fcP0TuaZ5QRTm
         fzcpetB+LV0VZfFpvBUsqdY1kpuD4tPEEvuXjI0XmetPIHvXWLVZy7BHrbun5CU0wARS
         /Y1JIj0gM6xBcGo+rGSZy3ghjf6Y2OR+gCnCXwGIhzA5C2nYaIAkXDjlJGooESKWN5nl
         hffA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=temperror (no key for signature) header.i=@szeredi.hu header.s=google header.b=OKvVi+Jx;
       spf=pass (google.com: domain of miklos@szeredi.hu designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=miklos@szeredi.hu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXOlIVQf0xq2VHSxn8gR71fgHiLmU7oMf5S2GOeks9M=;
        b=Pwsq2vd0lRhOhmBty1oTDFsVfEvzHdkzTaktyC6yGYnaaPV8dq4cJGjSkbhLB6O2l8
         Y9EuOJIYOlLmCkIgMb20fndcC3HKHmLrZ8zPdkcPzxujkCLgBRXMSmF1l+1rGVG9Kcqx
         ZAfkXNJ5dhYWAuy87AhH7blxYn4Ssa2jV4nyGGAfqoqQmV0SjOi/42gd+knStFYCIJfY
         jiBncyVk44iSY9cTtQ99Wu7BJiP0Hl8E77vx4IH8dit6ZzgGWFWscV0Nisck7CxACK5i
         /qiuiID6cgr4wgDGE6TP0UT/+IomnlvbVQ1MWvsmLiSke06doZBTHPTfWbKmsJ20cdsV
         rCmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXOlIVQf0xq2VHSxn8gR71fgHiLmU7oMf5S2GOeks9M=;
        b=jgafuWTvKrI9r9rwPXrBblo6rPAq8Jl+AWUiil6P43CGRWjGwpfQShWcchAEK9uBcJ
         FoOFCzpvnF6qoSW7K6Oj5zE4I/M3V+UQTBhUKGa4TH8HO29cjovRysZABt/+CSr9MP+2
         bkXhW485SHRJhxWnyOMPuH3wY5CW/4zk8jZNH41eXBIRQgyp56owdWDR3LaOO0NjI/cZ
         7GfI+YEMppJcQ56YJDgI3ZOU4HPfFPvAc1MHotkCsn+0Uzb6nTP3Z3fWy/mA+ww/B2Je
         klPVAmkt4F/p93LiXDfVeW6GZXxLgEjrxP5sYS8W/8IcwhiTCSt8kVc/7DYP1InIzlUi
         eVOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MKmjSm35wHnhVeiCOi/EBl8PXyEw6gtExRpuA6TI5NdE2vMXX
	2qCSRtT/LbvyEEq42ABL4n8=
X-Google-Smtp-Source: ABdhPJwsBVvxP2AtT5BbQsmn2WJh4JUst5A3ETkLI4Jb+UYRkO1YCMXaU9YzBj9Bd/uerKSHA8sR9Q==
X-Received: by 2002:a25:b803:: with SMTP id v3mr15197340ybj.326.1605603510620;
        Tue, 17 Nov 2020 00:58:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a268:: with SMTP id b95ls8289668ybi.10.gmail; Tue, 17
 Nov 2020 00:58:30 -0800 (PST)
X-Received: by 2002:a25:544:: with SMTP id 65mr31219068ybf.70.1605603510160;
        Tue, 17 Nov 2020 00:58:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605603510; cv=none;
        d=google.com; s=arc-20160816;
        b=LPAUv2SwNmK5+PJHCZNKzkXxTpvGTXJshpk76W7X6AtvkB5D8JQ9YG4qB/eX4YGgHp
         SPjRxjNTiyuWue5ytrJzYEGITT8WX1gVLu+hmxZYOWF6S+rgB68jLL1bWqEMJkhZHEHR
         HZV8gcw5GsSI9Xva7cIlJjrpD78TLy/tvqtkSfIkApEkXIXBjKgpy0hQpGqWyeyE15h/
         uPrvujWh77AluHjOlcs7YhHmWj8uoJoiDdQ8jUb0oeW9z1PIVVUNUYQdERLMaGhCQQn1
         Oztw5pLJ2XfJ47/0jmaUBR8S+KidlW+mAjFUBVXm4brwx08j/zmw1TFaM2YTGHKK9rIR
         ifEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SHJFy/YZF0XB4eGF/ZvX/fiRUi3iszemfHnSFZkXlNY=;
        b=FdmtvORCti4kBL7BczyELX1mh59u98oriV24gHRZRSfMesbLQdSuns01ydo9PUSI2H
         utEls3lgqy6FD+tW1tPDfREJm8N+NRMezCOJvDeFciBW1guFocIllehga1dI+hpXizcd
         rMGToWfQhrHGRyNub41h+g39Lg+BS5Xrc4C3Qcg0HIoir//TQddu6qhOwEpFBpz0s/t2
         pxuk9ut14OrNk7lCeefnrT1NdFrNo6pMTTD1hDAsEkQig+xAdhD5QXVvo5IGB/4JI9KA
         TkOBhW5ecxFDE41HnaM5k/4a3Yn2wyjdCchnkzLr3O3BJxH86HUGtI4D8FfpJ46IHUuk
         6Y3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=temperror (no key for signature) header.i=@szeredi.hu header.s=google header.b=OKvVi+Jx;
       spf=pass (google.com: domain of miklos@szeredi.hu designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=miklos@szeredi.hu
Received: from mail-vk1-xa31.google.com (mail-vk1-xa31.google.com. [2607:f8b0:4864:20::a31])
        by gmr-mx.google.com with ESMTPS id l7si389497ybt.4.2020.11.17.00.58.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 00:58:29 -0800 (PST)
Received-SPF: pass (google.com: domain of miklos@szeredi.hu designates 2607:f8b0:4864:20::a31 as permitted sender) client-ip=2607:f8b0:4864:20::a31;
Received: by mail-vk1-xa31.google.com with SMTP id d191so4356504vka.13
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 00:58:29 -0800 (PST)
X-Received: by 2002:ac5:c96c:: with SMTP id t12mr10487686vkm.19.1605603509197;
 Tue, 17 Nov 2020 00:58:29 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bUfavwMVv2SEMve5pabE_AwsDO0YsRBGZtYqX59a77vA@mail.gmail.com>
In-Reply-To: <CACT4Y+bUfavwMVv2SEMve5pabE_AwsDO0YsRBGZtYqX59a77vA@mail.gmail.com>
From: Miklos Szeredi <miklos@szeredi.hu>
Date: Tue, 17 Nov 2020 09:58:18 +0100
Message-ID: <CAJfpegvoiGb5R1Y2a+_rNgTXgfJD=kFrkXBn7zSZDHKxwe992Q@mail.gmail.com>
Subject: Re: suspicious capability check in ovl_ioctl_set_flags
To: Dmitry Vyukov <dvyukov@google.com>
Cc: overlayfs <linux-unionfs@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Merna Zakaria <mernazakaria@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miklos@szeredi.hu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=temperror (no
 key for signature) header.i=@szeredi.hu header.s=google header.b=OKvVi+Jx;
       spf=pass (google.com: domain of miklos@szeredi.hu designates
 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=miklos@szeredi.hu
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

On Tue, Nov 17, 2020 at 8:56 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> Hi Miklos,
>
> We've detected a suspicious double-fetch of user-space data in
> ovl_ioctl_set_flags using a prototype tool (see report below [1]).
>
> It points to ovl_ioctl_set_flags that does a capability check using
> flags, but then the real ioctl double-fetches flags and uses
> potentially different value:
>
> static long ovl_ioctl_set_flags(struct file *file, unsigned int cmd,
>                 unsigned long arg, unsigned int flags)
> {
> ...
>     /* Check the capability before cred override */
>     oldflags = ovl_iflags_to_fsflags(READ_ONCE(inode->i_flags));
>     ret = vfs_ioc_setflags_prepare(inode, oldflags, flags);
>     if (ret)
>         goto unlock;
> ...
>     ret = ovl_real_ioctl(file, cmd, arg);
>
> All fs impls call vfs_ioc_setflags_prepare again, so the capability is
> checked again.
>
> But I think this makes the vfs_ioc_setflags_prepare check in overlayfs
> pointless (?) and the "Check the capability before cred override"
> comment misleading, user can skip this check by presenting benign
> flags first and then overwriting them to non-benign flags. Or, if this
> check is still needed... it is wrong (?). The code would need to
> arrange for both ioctl's to operate on the same data then.
> Does it make any sense?

Yes, looks like an oversight.

The only way to fix this properly, AFAICS is to add i_op->setflags.

Will look into this.

Thanks,
Miklos



> Thanks
>
> [1] BUG: multi-read in __x64_sys_ioctl  between ovl_ioctl and ext4_ioctl
> ======= First Address Range Stack =======
>  df_save_stack+0x33/0x70 lib/df-detection.c:208
>  add_address+0x2ac/0x352 lib/df-detection.c:47
>  ovl_ioctl_set_fsflags fs/overlayfs/file.c:607 [inline]
>  ovl_ioctl+0x7d/0x290 fs/overlayfs/file.c:654
>  vfs_ioctl fs/ioctl.c:48 [inline]
>  __do_sys_ioctl fs/ioctl.c:753 [inline]
>  __se_sys_ioctl fs/ioctl.c:739 [inline]
>  __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
>  do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> ======= Second Address Range Stack =======
>  df_save_stack+0x33/0x70 lib/df-detection.c:208
>  add_address+0x2ac/0x352 lib/df-detection.c:47
>  ext4_ioctl+0x13b1/0x27f0 fs/ext4/ioctl.c:833
>  vfs_ioctl+0x30/0x80 fs/ioctl.c:48
>  ovl_real_ioctl+0xed/0x100 fs/overlayfs/file.c:539
>  ovl_ioctl_set_flags+0x11d/0x180 fs/overlayfs/file.c:574
>  ovl_ioctl_set_fsflags fs/overlayfs/file.c:610 [inline]
>  ovl_ioctl+0x11e/0x290 fs/overlayfs/file.c:654
>  vfs_ioctl fs/ioctl.c:48 [inline]
>  __do_sys_ioctl fs/ioctl.c:753 [inline]
>  __se_sys_ioctl fs/ioctl.c:739 [inline]
>  __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
>  do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> syscall number 16  System Call: __x64_sys_ioctl+0x0/0x140 fs/ioctl.c:800
> First 0000000020000000 len 4 Caller vfs_ioctl fs/ioctl.c:48 [inline]
> First 0000000020000000 len 4 Caller __do_sys_ioctl fs/ioctl.c:753 [inline]
> First 0000000020000000 len 4 Caller __se_sys_ioctl fs/ioctl.c:739 [inline]
> First 0000000020000000 len 4 Caller __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
> Second 0000000020000000 len 4 Caller vfs_ioctl+0x30/0x80 fs/ioctl.c:48
> ==================================================================

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfpegvoiGb5R1Y2a%2B_rNgTXgfJD%3DkFrkXBn7zSZDHKxwe992Q%40mail.gmail.com.

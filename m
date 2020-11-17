Return-Path: <kasan-dev+bncBCMIZB7QWENRBK4EZ36QKGQESO47OWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D70242B5A8D
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 08:56:28 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id w8sf24161416ybj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 23:56:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605599787; cv=pass;
        d=google.com; s=arc-20160816;
        b=zV20TKCiLfbZPeXGMZ/dMDNzuIP1C/xyHAQ933eTKa85E5z+ZyJ95EXY7/r7yMsfPn
         rbV7+c1B6oYz6+y+6cpPqPFl/VmlgLaN/xRK3zCwiK0kKkvex8sN5HAErORH2iucGGdp
         A5j2Ft+h8mF5PrsCn0VNF1qFWePBvdBYZylaw20OQJHoYIRgopW2P8Ruf6CwCBxPZzu1
         9AyM0/HngIhiqoTvemdAiBux1csdq6/pcrWNzD/1YzAGtPw7etvEqO+ZoC6AgHakJSxi
         IYkvHPt/RjQiQannehu+2Ex/yC9lyhBdMWD3sfQJLTsons3kvolR2Al4WaUoO3viHLVs
         B5yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=wzsKiADthMOpC5rbVKgHFAkoTR0A7k+g489a/H0ZBak=;
        b=02cGUtuE41wq4CWvMDiQsEhb4yJYNA0uXCdkXz4qGOJ8oTqeAgADVpR7XHMQQwJYji
         cRp93C/xF3YQ/NinWT6VRHmxaCElR5eO7/mKuslVxg9QaXkyMKxKLS95A1CrwDB6s96/
         AnJxfUrRqLwNbglu1ld5gVvCCTO/lUVEKq2DQvloQBcxN/p96VflNF2mhhKkvs+2Cqt3
         Jcj7Z2Kq+xt6fVDTXOXqjBMGkhvVUiKk9cHqGWJufiuSDL3V4Rf8blK6BL5R24cvQLuq
         UVRls3m4GSM8mcEoJz5W6gE5YRypnMC5ocjSOigoS1FxrDUbaDkNnTHdvu8L9lAqo9HX
         5Hqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vr6WiLEj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wzsKiADthMOpC5rbVKgHFAkoTR0A7k+g489a/H0ZBak=;
        b=TiIiSn/Hvnm+yKPXHf01U7gI1uIrtbl0rDnGamSnaeBDTDiFv5fyVuwBUUHnfk9pKT
         x1q8yUuhidXtYgSv47C0gpuGy2pHjx/ELmcCX/aNGEhR3oHeeRQKSiNWVJ62DcNMHPyv
         vI4Glj59WOYTctd/dOO6mEs8sLbH93qnlDzoMyglXnj0EajOpLo7YCEJbpzjSVzW5NgH
         XllmLNC4ouSaLE9xZhofnRvVNTbmQlrQPoGF+PI6ejAJly0CvTFiu3DnGgtL+qEL0vE7
         rbbg4sE1YxmSCOdiMmLAiSSUqjK4r1dXERP+iH5dGoK/wJD/KmF80sJVRCzQICIXRNcY
         HIsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wzsKiADthMOpC5rbVKgHFAkoTR0A7k+g489a/H0ZBak=;
        b=p6jsaRSvWoumC2M8ddy49syuA5xrpvECsa5sed7JzVHUbC9x8BFzVrf11k9WSbGvun
         bXTT//3nLkECo84K/KUPmvYHKgOqCgJcJHUUMngJ74QyUKZG/N4JoUBrH+r1mFS9quuc
         ZtqNxQpO+kjK0HfOhwO2Fgko1Gk0KWScsmNr4ik2WXmCFWUAqkGvoqrVUA03BeLo2NgF
         OYobNwxPyhQMvMyrmN7A/eOX6xzt7U5LB6d5tTTSBQXOXmhOHPw5snjt6YmqApwrzBGU
         j0dm8iY9wl4Z5iabqSOZEUf+DqMb5ZV2e9Cby+O6k59AjioSyzWwfBcYTO8eslF0cd7n
         l6bg==
X-Gm-Message-State: AOAM5331235rZ+1UmL/UBT7j/E+Mfarht0PMhH8LzyQw0kMTQUAmlWBX
	3evR3AefiVbDhP30PTod3vE=
X-Google-Smtp-Source: ABdhPJx7V6jtk7d5P6qlBin2hDqNp13f9P77Lxc+ayoK5mdBaDPeR2pUAAfUzZ+4e+yd8L9A+axduQ==
X-Received: by 2002:a25:848e:: with SMTP id v14mr21288652ybk.153.1605599787651;
        Mon, 16 Nov 2020 23:56:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a268:: with SMTP id b95ls8212107ybi.10.gmail; Mon, 16
 Nov 2020 23:56:27 -0800 (PST)
X-Received: by 2002:a25:aac5:: with SMTP id t63mr25844547ybi.22.1605599787201;
        Mon, 16 Nov 2020 23:56:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605599787; cv=none;
        d=google.com; s=arc-20160816;
        b=XSgH1m8zP+jAOP8Q+pUeY5lKA86GWiNMT+UgE+xsbPDzzTgwLHHlI1YKjZn2IMTjQ3
         PaaNC7D3GfE4hD0R2lUf4qWHzAc5pH3ir04rlf4KAmlKrv8ASVoOqcGZkY7MWpa2Um+T
         6f6dIDaP4BypkQKXOByirg151DKDbjh3LK1Szwp/7BhMg2OoL2nmogxM90FlxXVMNen1
         Q/PbAuB1jPon8441CHwRzXgforEYe83sRVZ3DfVD6J9SYkOvWnOq4UEYKMHUWElGPrgG
         AT9CicpLPkA1tfXaHdq67AXMdvs8ZpLmk/5jIQu6NMO7jWWDSXgukC3rYqHh1SjNpKfL
         obhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=H3l9soqm+SREQlc2IEV9Idb1VORHh3SoM0Ng1Iin3Dc=;
        b=lyFf6rqUyF6fUUlvJUUOSx8ryVqATyGZkgTbi4IyShThHjjpyIrhgvulFfYomcGyQ9
         d+Sb0vFDDj095MLHtF5NoPAgJdzPAd+TBffZWrZE0rpetvCAMBI4sg4cHBtUNPRkCqpr
         AwpNsreRjzHu51MRHEP3tYyP1zipgC8MQ7Qr6SCcmvbLmbT6W8BolHcEykii68GsHH5l
         MrEhve2kanN4dRi6H8t8+u84Kh7ZEG9RThNfitRlwW3+ryoYAkdIoiB8W7O4Zt8M3RPo
         xuNWxBL2JyU/i6EssQickX+Y7liFQmtVYQD8EZ1+zCEyoN37OCIBZWHHOQiefCH7C8sv
         GNdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vr6WiLEj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id y4si1387431ybr.2.2020.11.16.23.56.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 23:56:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id n132so19628039qke.1
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 23:56:27 -0800 (PST)
X-Received: by 2002:a37:9747:: with SMTP id z68mr17899362qkd.424.1605599786651;
 Mon, 16 Nov 2020 23:56:26 -0800 (PST)
MIME-Version: 1.0
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 08:56:15 +0100
Message-ID: <CACT4Y+bUfavwMVv2SEMve5pabE_AwsDO0YsRBGZtYqX59a77vA@mail.gmail.com>
Subject: suspicious capability check in ovl_ioctl_set_flags
To: Miklos Szeredi <miklos@szeredi.hu>, overlayfs <linux-unionfs@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Merna Zakaria <mernazakaria@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vr6WiLEj;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731
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

Hi Miklos,

We've detected a suspicious double-fetch of user-space data in
ovl_ioctl_set_flags using a prototype tool (see report below [1]).

It points to ovl_ioctl_set_flags that does a capability check using
flags, but then the real ioctl double-fetches flags and uses
potentially different value:

static long ovl_ioctl_set_flags(struct file *file, unsigned int cmd,
                unsigned long arg, unsigned int flags)
{
...
    /* Check the capability before cred override */
    oldflags = ovl_iflags_to_fsflags(READ_ONCE(inode->i_flags));
    ret = vfs_ioc_setflags_prepare(inode, oldflags, flags);
    if (ret)
        goto unlock;
...
    ret = ovl_real_ioctl(file, cmd, arg);

All fs impls call vfs_ioc_setflags_prepare again, so the capability is
checked again.

But I think this makes the vfs_ioc_setflags_prepare check in overlayfs
pointless (?) and the "Check the capability before cred override"
comment misleading, user can skip this check by presenting benign
flags first and then overwriting them to non-benign flags. Or, if this
check is still needed... it is wrong (?). The code would need to
arrange for both ioctl's to operate on the same data then.
Does it make any sense?
Thanks

[1] BUG: multi-read in __x64_sys_ioctl  between ovl_ioctl and ext4_ioctl
======= First Address Range Stack =======
 df_save_stack+0x33/0x70 lib/df-detection.c:208
 add_address+0x2ac/0x352 lib/df-detection.c:47
 ovl_ioctl_set_fsflags fs/overlayfs/file.c:607 [inline]
 ovl_ioctl+0x7d/0x290 fs/overlayfs/file.c:654
 vfs_ioctl fs/ioctl.c:48 [inline]
 __do_sys_ioctl fs/ioctl.c:753 [inline]
 __se_sys_ioctl fs/ioctl.c:739 [inline]
 __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
 do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
======= Second Address Range Stack =======
 df_save_stack+0x33/0x70 lib/df-detection.c:208
 add_address+0x2ac/0x352 lib/df-detection.c:47
 ext4_ioctl+0x13b1/0x27f0 fs/ext4/ioctl.c:833
 vfs_ioctl+0x30/0x80 fs/ioctl.c:48
 ovl_real_ioctl+0xed/0x100 fs/overlayfs/file.c:539
 ovl_ioctl_set_flags+0x11d/0x180 fs/overlayfs/file.c:574
 ovl_ioctl_set_fsflags fs/overlayfs/file.c:610 [inline]
 ovl_ioctl+0x11e/0x290 fs/overlayfs/file.c:654
 vfs_ioctl fs/ioctl.c:48 [inline]
 __do_sys_ioctl fs/ioctl.c:753 [inline]
 __se_sys_ioctl fs/ioctl.c:739 [inline]
 __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
 do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
syscall number 16  System Call: __x64_sys_ioctl+0x0/0x140 fs/ioctl.c:800
First 0000000020000000 len 4 Caller vfs_ioctl fs/ioctl.c:48 [inline]
First 0000000020000000 len 4 Caller __do_sys_ioctl fs/ioctl.c:753 [inline]
First 0000000020000000 len 4 Caller __se_sys_ioctl fs/ioctl.c:739 [inline]
First 0000000020000000 len 4 Caller __x64_sys_ioctl+0xfc/0x140 fs/ioctl.c:739
Second 0000000020000000 len 4 Caller vfs_ioctl+0x30/0x80 fs/ioctl.c:48
==================================================================

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbUfavwMVv2SEMve5pabE_AwsDO0YsRBGZtYqX59a77vA%40mail.gmail.com.

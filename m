Return-Path: <kasan-dev+bncBCMIZB7QWENRBA7LVDTQKGQELZ5WUEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 83CDD2A8DE
	for <lists+kasan-dev@lfdr.de>; Sun, 26 May 2019 08:43:16 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id v187sf11115998ioe.9
        for <lists+kasan-dev@lfdr.de>; Sat, 25 May 2019 23:43:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558852995; cv=pass;
        d=google.com; s=arc-20160816;
        b=g9SBddoVp6jEjx9T+PYceVxTrtcJpHoG9hci/gjARw16fUknjqY2z2yQ/jsO7So4Gz
         tz4p2dPnHXjcYc2TAC7e6lnVWo+5mwWekF9cZTyiPJbc2kPJxcUVR+YD7YbP1lgqyfQ5
         HQ2A8jVQmCd/tNwzIQgpOwukN7mKWxRcfTpvwwSOFUZCMkAiD7IiFOcmcl7Tism3Uwdz
         G4Z5YUE/DR2Y5hZ4HXd/sq1iuBDOhmHHf2f+lpAyh5f+vOiRFih+dYQ5yPap/XZs0QAr
         VQT+i6pT7z4qohpZUrybQqIa6N2vbrlS2LHLsJWgyzVQEyn441j8uNYexV6KN8WAcpmz
         wAPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+SaSto+7pzWnplyVGolAuKe6bzgd3u9i7khGE6gU/yA=;
        b=pmokW/EDx9uVPnx3RbhR4qrCp9veuFYTJSTys9ZSSLGRyXria36YP536QocNcf4gd4
         c7s5OtqYhfWrDMnuBmb9TICth8jMceGr9pZ3hy1KPyjiLhKYqzYjNU2PBqGDYAyEixWW
         S96PYw4rr90iZhEeBmZIsOWni3bjpklF+6XV7hBTnj2kR9ytqAUerS+Lf6vEk9gHhg+t
         zjwW7pqwJRUgNlGYqt6oxCfX8eaH2hv/XL3/TXobY2l/Oc5NVaY4K+qS8PRconNHKsZk
         a+Wi3cNJPPd+b4OrnFq0nK4Euqyojo9YzeipjZtQeo8nhD09PnQX10qW+zfsxLA6JEab
         /YgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6Mjp9Yw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+SaSto+7pzWnplyVGolAuKe6bzgd3u9i7khGE6gU/yA=;
        b=KVLpJIRDMRWOFtrXgLaOLUxhwS71f3cFLWQatXqEW9jIcBF1f5BTR7uo8MVvEk5LrC
         EO7+uIp6PHuaIXXXhX+8DaYcEzjOi4oAO9dG4XblsIJZflpfYAzXP7O1QFVm8MeKqHT3
         qm9EjNIqpsOACnzJGol6RoDHxewaIj3dIfVCjgOFgzRoYh3XYMWystNJEVtbYWLraG9Z
         mePGfQe7iarlo1Mm0pdzwGunCzHveMQiP2MA9YusyVU+1rhOUgRugS7iz+qHpc/2SyvF
         iDdWU5qYWa31kYW98+rbJ8i79EigcDh5qEI916EwHAGIIGPEXW2bjMPfSL+egt66adhM
         iiZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+SaSto+7pzWnplyVGolAuKe6bzgd3u9i7khGE6gU/yA=;
        b=k9F9ulrY5HJsKOrk+FDD9dDENDZlHaXXdv+AnxjZ8iVi9cKVm53Q7RRoaOIvbydRh2
         k5nodMut1EnkXZzh/4mzvkPMXF7yMaghgCT5SAGpGBmOYFYI9IZ8/FN//l13wnfO7Mv+
         gjqY6s79CyaEtlCb/OVxgIo7xmV14aC+ZblH3v41Wc4/O0JsM3vnu0+NSKf67AVJiaJN
         ty/QX9bJX/L1ngVTccSn4gu4bKqwgFlwaTYGnGocgQV7TJVu0il5UPtb1zRhJ9WTFij8
         9Y9l0foaPqqNeVlHpgR1n53/dN3wO9SNGD89FWPAWdpv/HMNCG0ZueLfj0XJJZEkaeHH
         gl8g==
X-Gm-Message-State: APjAAAWRWDLjb9VbWSVoR2zTxgls59eWpohFXvQbD4PPwEr2fcNBIPc6
	7QorY47pvpV9eWd0gOtrItA=
X-Google-Smtp-Source: APXvYqysx212hSH21zLtFQiF9g4t7X05J89pQJTTN50gHozbEbdXTSsy2GqBee/waDfCYdzQrTJx7g==
X-Received: by 2002:a24:29d0:: with SMTP id p199mr1164916itp.134.1558852995162;
        Sat, 25 May 2019 23:43:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:3946:: with SMTP id l67ls5633490ita.5.canary-gmail; Sat,
 25 May 2019 23:43:14 -0700 (PDT)
X-Received: by 2002:a24:78d1:: with SMTP id p200mr25006765itc.69.1558852994872;
        Sat, 25 May 2019 23:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558852994; cv=none;
        d=google.com; s=arc-20160816;
        b=0zr8grGmXcH9WHaE/NEVYRlAGDvQa6aGTJonQd9nOzQ1qMY8yjl2y++zlnMm0/VYDx
         djmAgkzpW3uU9uLSrEV9O4f1LdsvAZxzuh2T83zeOUi2XLgYJAdXPv5egIc//T9zVgH9
         QyW/rYhSEocsgFxYTVokJgnAgkbNTnvUDefvfHUHYO7qLnMKUVHDkBSfJrcSCnM8+Vty
         wZOrzu3TNNau97IMBzlJyYCvFfGBcYglCyzY7DMUQOVEKiaWVIq1W8jeFYL+XGOS1Qgw
         Jeuw9lz03KhrMZ4pir8WmJkgvp1UVq/HhRRs/RkIbS180WeCsMdz/p4VTsBm/wUnnyfX
         /eFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ykvxJITftYjuXxiA50DtpHZBYlqXNVskwhB9Mpf150E=;
        b=S1Jgi4N1HJdsFQdzEb4S97Ov4NUaWNjutbUkEgz9sHtxzaF1jLetGuA4HKJWWxk8O0
         gBiiixcAhns+cwPUpZPLi7VXATOKMCooa7Jc+m3aM9aEkw87+uGpuMTxArwefXyyUcn5
         cAPcelTb6LAWbC3ut7NOTXfiqForDD+9wbvtCiryACzk27Ba6W/EKC9U34mEkwwuetbe
         N96fONoZ9qsNiDXJtG8u87sqvcs00NzoIenL5QonVaqNhfyaRM2wApLVMR0DCaLp/a9s
         e2aZKpgSs0FVbKOZKZ+DBXm9lIApX616SxY8pY7ShNUhHkaVFEtbUj4n3NPxBvfZktd7
         BVgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6Mjp9Yw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id n74si414217itn.0.2019.05.25.23.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 May 2019 23:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id b3so5508517iob.12
        for <kasan-dev@googlegroups.com>; Sat, 25 May 2019 23:43:14 -0700 (PDT)
X-Received: by 2002:a6b:dc0d:: with SMTP id s13mr35756721ioc.144.1558852994241;
 Sat, 25 May 2019 23:43:14 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000001a546b0589b9c74f@google.com>
In-Reply-To: <0000000000001a546b0589b9c74f@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 26 May 2019 08:43:03 +0200
Message-ID: <CACT4Y+bME3hecCNXQHvr6uwWjYY6BEqCnu8W4RUMZCm7XemPmQ@mail.gmail.com>
Subject: Re: KASAN: use-after-free Read in class_equal
To: syzbot <syzbot+83c135be90fc92db7e13@syzkaller.appspotmail.com>, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=m6Mjp9Yw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
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

On Sat, May 25, 2019 at 7:38 PM syzbot
<syzbot+83c135be90fc92db7e13@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    c50bbf61 Merge tag 'platform-drivers-x86-v5.2-2' of git://..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=12130c9aa00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=fc045131472947d7
> dashboard link: https://syzkaller.appspot.com/bug?extid=83c135be90fc92db7e13
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=12e7d84ca00000

From the repro looks like

#syz dup: KASAN: slab-out-of-bounds Read in class_equal

+bpf mailing list

If bpf maps started badly smashing memory in a way that KASAN can't
detect, please fix asap. Or we will start getting dozens of random
reports. The usual question: why does not KASAN detect the root cause
smash? How can we make it detect it?


> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+83c135be90fc92db7e13@syzkaller.appspotmail.com
>
> ==================================================================
> BUG: KASAN: use-after-free in class_equal+0x40/0x50
> kernel/locking/lockdep.c:1527
> Read of size 8 at addr ffff88807aedf360 by task syz-executor.0/9275
>
> CPU: 0 PID: 9275 Comm: syz-executor.0 Not tainted 5.2.0-rc1+ #7
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> Call Trace:
>
> Allocated by task 9264:
>   save_stack+0x23/0x90 mm/kasan/common.c:71
>   set_track mm/kasan/common.c:79 [inline]
>   __kasan_kmalloc mm/kasan/common.c:489 [inline]
>   __kasan_kmalloc.constprop.0+0xcf/0xe0 mm/kasan/common.c:462
>   kasan_slab_alloc+0xf/0x20 mm/kasan/common.c:497
>   slab_post_alloc_hook mm/slab.h:437 [inline]
>   slab_alloc mm/slab.c:3326 [inline]
>   kmem_cache_alloc+0x11a/0x6f0 mm/slab.c:3488
>   getname_flags fs/namei.c:138 [inline]
>   getname_flags+0xd6/0x5b0 fs/namei.c:128
>   getname+0x1a/0x20 fs/namei.c:209
>   do_sys_open+0x2c9/0x5d0 fs/open.c:1064
>   __do_sys_open fs/open.c:1088 [inline]
>   __se_sys_open fs/open.c:1083 [inline]
>   __x64_sys_open+0x7e/0xc0 fs/open.c:1083
>   do_syscall_64+0xfd/0x680 arch/x86/entry/common.c:301
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
> Freed by task 9264:
>   save_stack+0x23/0x90 mm/kasan/common.c:71
>   set_track mm/kasan/common.c:79 [inline]
>   __kasan_slab_free+0x102/0x150 mm/kasan/common.c:451
>   kasan_slab_free+0xe/0x10 mm/kasan/common.c:459
>   __cache_free mm/slab.c:3432 [inline]
>   kmem_cache_free+0x86/0x260 mm/slab.c:3698
>   putname+0xef/0x130 fs/namei.c:259
>   do_sys_open+0x318/0x5d0 fs/open.c:1079
>   __do_sys_open fs/open.c:1088 [inline]
>   __se_sys_open fs/open.c:1083 [inline]
>   __x64_sys_open+0x7e/0xc0 fs/open.c:1083
>   do_syscall_64+0xfd/0x680 arch/x86/entry/common.c:301
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
> The buggy address belongs to the object at ffff88807aede580
>   which belongs to the cache names_cache of size 4096
> The buggy address is located 3552 bytes inside of
>   4096-byte region [ffff88807aede580, ffff88807aedf580)
> The buggy address belongs to the page:
> page:ffffea0001ebb780 refcount:1 mapcount:0 mapping:ffff8880aa596c40
> index:0x0 compound_mapcount: 0
> flags: 0x1fffc0000010200(slab|head)
> raw: 01fffc0000010200 ffffea0001ebb708 ffffea0001ebb908 ffff8880aa596c40
> raw: 0000000000000000 ffff88807aede580 0000000100000001 0000000000000000
> page dumped because: kasan: bad access detected
>
> Memory state around the buggy address:
>   ffff88807aedf200: 00 00 fb fb fb fb fb fb fb fb fb fb fb fb fb fb
>   ffff88807aedf280: fb fb fb fb fb fb fb fb fb fb fb fb fb fb f1 f1
> > ffff88807aedf300: f1 f1 00 f2 f2 f2 00 f2 f2 f2 fb fb fb fb 00 00
>                                                         ^
>   ffff88807aedf380: 00 f3 f3 f3 f3 f3 fb fb fb fb fb fb fb fb fb fb
>   ffff88807aedf400: fb fb fb fb fb fb fb fb fb fb fb fb fb 00 00 00
> ==================================================================
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> syzbot can test patches for this bug, for details see:
> https://goo.gl/tpsmEJ#testing-patches
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/0000000000001a546b0589b9c74f%40google.com.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbME3hecCNXQHvr6uwWjYY6BEqCnu8W4RUMZCm7XemPmQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.

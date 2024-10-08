Return-Path: <kasan-dev+bncBCQPF57GUQHBBG63SW4AMGQE4TCLKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 389969955C9
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 19:36:29 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6dbbeee08f0sf767117b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 10:36:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728408987; cv=pass;
        d=google.com; s=arc-20240605;
        b=KtsSp3I83WApgZtVO7tDTYgPPeMfl9uL9132JnLpMw0nB3ZH9jep6Dxjo3rakr/JCk
         4bylJBA/tYNOXxQ+545Z69pNgGO/M4bIV14ZTmDfP2MGmdlOerfXIYv6oQgdsq7gJi/u
         bx/Ggr+AOmDaXmsQu02ftHL/9XiAQBBacNCu32jXl2sJa8H7kTVr28luCAf3minO0XXl
         JZnVo2fsVtwfgrPnY3+qLtpeRswHs5G9kL80alSBzAH+yWAyuTArtKKrBu6VAkWgXmMv
         Y7Q1PLDaPH7LJlk+yIcRFRcBTRxSC9Rvo52Rbb5CiRGNdgKWf4nBWWPLuFYa43SPr6U7
         KHHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=Do7cecd+nXUsGOfLdXocb+TN0H3cM1upn+pcnbMPNKM=;
        fh=Nfd+QqYBMvbUIXEUL9ThJCvVi8QfzeViGbn3ZfeXwmY=;
        b=R0svtkyRzEMXNDjzixUJxs4hy8hiII105GwzbgmvvhZ/az/FKiX2irJR5HgRvBBrDA
         DI7YbembIUF8QiywwpPyWr5N9qa6Lbxsd91sMwYSmLmcRK5BjNRAnxb+pJC21YB5cmyd
         TJhYa+SQ3+0hk0RVf89r89fD7rqkLbuMTXW7KQ/5w97VaDfd7fy/OvdQmiPHySSA6ucV
         W3h6TycPBzswFb963qJug2aCbGuhq8mUeEIdvIvSxTKLoH2XTWdbEVRRn1SWTYrKuvMx
         zQmfQ5Siv3aey/2LnFxJsFu9bLHUc/zTt3ZbIdAPKTy1w4OaOO0ea4S6iNT/qJHGbdEX
         /vPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mw0fzwkbamg6cdyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3mW0FZwkbAMg6CDyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728408987; x=1729013787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Do7cecd+nXUsGOfLdXocb+TN0H3cM1upn+pcnbMPNKM=;
        b=CtpNegGtELaYmVjJ9IOFKTbR0c2l2i2VczKSkfJRkeoKvOBdWsQDYy/Ez+Dcm6sqRi
         S/yJ8OK2oWCi4jfev+Z/JR5r+74+IjCtj3Sn6SNUJLmTAf8ZqeWgqVMON03+zwCOeuUm
         5ueP8ZXrgmUwgqr3AXmcw4jy7euXcU+9LpHEt83TRv7gX7ehoKwxjr6zsLbRiDH4jMea
         ehnykmeFrC5SXQMmQWnBAPC/a16+APLBxx16LQRYYLgjQlft4+AvKrP3I36bMQHbmvyZ
         v0avdCDOVkUaMTnRY6J7lvvzJ6c33smiZg1CKd/pmTaaDwRa+LIG8xguIzlGlYo3Ybsu
         WYWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728408987; x=1729013787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Do7cecd+nXUsGOfLdXocb+TN0H3cM1upn+pcnbMPNKM=;
        b=RdFs/Aiy2tjjuqG+piX57LM7WLs6Gff1v/w5HJSikyKMUkPRFqnoLX5e8EmkyxB5tB
         NY/zDjd63EsSOnVtwzGHfYkUq0jhUp/ObZ6c4DpR/e7A057QPZKd5H/h3hv3tkYgt/Rr
         uRUwvj08A8483JtuyifAXK9uRPQBrs1lQzxDRsS0m9u88Cw4g5/cnV+srz4UkBUQCGEV
         uuenNHGvthnZTD0Xl+IfCWTXrdrCYY1UbkSVlu2OTUCajb46TQWjXAcCbnl8JNHUcL0V
         ZTThz7XM8wKmPz19Lj9EwC1CFr2BBTs2a2IlUTdgWxN2TPzeHyt3puaT6wm3eKLNwHTr
         1OPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUgY0qj180HVMxbmZng89QgBDAaB3zyIJGf8RooBKz2QWflmfZSLKEi/yoVQvlZ8eBoBc9GjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxSbDtsMh0m9ZK2EkVx9VMPlp5oNbeHL3uIffaqgHSuQqymV7+v
	Sp9xUcdswhzwt1xR9XqqgIQs8qAM6X/kHqinZ1JxNVKnOOsAFibV
X-Google-Smtp-Source: AGHT+IGBXS3AMvR/jlMx9cPEIeA9dCO3V3UqI4eOD1V0vn+YgOmCdeyc3t9iyGk8HoXYmDVmHuxwrA==
X-Received: by 2002:a5b:74e:0:b0:e03:5505:5b5b with SMTP id 3f1490d57ef6-e28f9420b3fmr1096550276.0.1728408987478;
        Tue, 08 Oct 2024 10:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1201:b0:e24:8e92:5cd4 with SMTP id
 3f1490d57ef6-e286fa8d7f3ls1071876276.1.-pod-prod-00-us; Tue, 08 Oct 2024
 10:36:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUr9hbT8bOuqUouz/l3mOUrz0OZtqROKPFpa1cBb83oXhmc/OJl7JacyuIAfb+rfRgDPntz2suGxDo=@googlegroups.com
X-Received: by 2002:a05:690c:6512:b0:6db:da0e:d166 with SMTP id 00721157ae682-6e31d76c534mr9615057b3.12.1728408985803;
        Tue, 08 Oct 2024 10:36:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728408985; cv=none;
        d=google.com; s=arc-20240605;
        b=g0XmOghKrUqtcvkl+WzuQdvRU3apAHQlV3eF4tW6muu85YmvQvwaeKHlQU3PFsMGiB
         8CecnLBZBQ/qgEnYqu4Dq/kgVE8V8IPz3bU+RXVnalTaTHqW19kC/ylL1Xnon8gEkRNr
         IGSTwUBlUeFgTNx23ZyT6TjYd4z1+iapgWpYT+drRdtmyC0c1sYxzNelMSOBlQC0GrfJ
         oTuqNY0EYtyIaa2qNWNu/S7a1NvMYU9WxpwchSXuptkxwczxIXWsG846gYmq3N3rRx47
         z9o11fBx0gMQhJDGWMU2X6jL56uaVPFHhaskCBV7iWjUOHCha0CTIi/ReWLQdmvJdf48
         8a9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=knim6RMb0UOBysPQSJ6ShmsHPlXqICjEz5a6oGa8pOw=;
        fh=EmkbwW+tmw0U5NDM3yLP0+lDNWr+pv6hlnjO+OFStNI=;
        b=aEIUnniXvyI+RJOQjWmlevvMZPkyStlMpKQaaHa1le1i1XcX5t6bDS/COUyRPE+tP9
         Eh9VsoQyML/4lUN+5KvuEQLtacH2WQrWsbthW6AywLns5YwT7lHR6gvXYOnCGILrx2HT
         gDnH86WZ4rrvAsRfa0oKckTagkEO8PyG2FUaFeNX3GToHp6m4Mp0QLHuwbKYMGkBg0w0
         ozdXTPL0xsXSDMRZYO+qSVeljRt3lWWh6ZdK4KL8DYJPqCCprBlA+/MrTsLPPBenQS9J
         QmyvSuaXJkgnev1gTyD+dZqIWHqVfxMhthCgUWfpmk84SGgjf4H3losf0Ix1f+7/1BsI
         z1CQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mw0fzwkbamg6cdyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3mW0FZwkbAMg6CDyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e2d927195dsi1765397b3.1.2024.10.08.10.36.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 10:36:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mw0fzwkbamg6cdyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-3a39631593aso249695ab.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 10:36:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWdWAvhLJ9ucWz4plLQ4eU6n1vNQgF95dOMQQhE689KCYpfrbFroQvtrkgO59sqex/SeuXp4ybznWA=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1a8e:b0:3a2:6402:96b9 with SMTP id
 e9e14a558f8ab-3a3946e88e6mr7458785ab.9.1728408985198; Tue, 08 Oct 2024
 10:36:25 -0700 (PDT)
Date: Tue, 08 Oct 2024 10:36:25 -0700
In-Reply-To: <000000000000939d0a0621818f1e@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <67056d99.050a0220.840ef.000a.GAE@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_fault
From: syzbot <syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, muchun.song@linux.dev, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3mw0fzwkbamg6cdyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3mW0FZwkbAMg6CDyozzs5o33wr.u22uzs86s5q217s17.q20@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

syzbot has found a reproducer for the following issue on:

HEAD commit:    87d6aab2389e Merge tag 'for_linus' of git://git.kernel.org..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=17e11780580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
dashboard link: https://syzkaller.appspot.com/bug?extid=7bb5e48f6ead66c72906
compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17dd6327980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16d24f9f980000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/676a1b91b952/disk-87d6aab2.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/f47965c6cebd/vmlinux-87d6aab2.xz
kernel image: https://storage.googleapis.com/syzbot-assets/9ada52fd0e29/bzImage-87d6aab2.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com

INFO: task syz-executor390:6168 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:28288 pid:6168  tgid:6166  ppid:5217   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 io_schedule+0xbf/0x130 kernel/sched/core.c:7552
 folio_wait_bit_common+0x3d8/0x9b0 mm/filemap.c:1309
 __folio_lock mm/filemap.c:1647 [inline]
 folio_lock include/linux/pagemap.h:1148 [inline]
 folio_lock include/linux/pagemap.h:1144 [inline]
 __filemap_get_folio+0x6a4/0xaf0 mm/filemap.c:1900
 filemap_lock_folio include/linux/pagemap.h:788 [inline]
 filemap_lock_hugetlb_folio include/linux/hugetlb.h:795 [inline]
 hugetlb_fault+0x16ff/0x2fa0 mm/hugetlb.c:6406
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc90009107c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001220f98 RSI: ffffc90009107cb8 RDI: 000000002001bd48
RBP: 000000002001bd48 R08: 0000000000000000 R09: fffff52001220f97
R10: ffffc90009107cbf R11: 0000000000000000 R12: ffffc90009107cb8
R13: 000000002001bd50 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ad6168 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f4df1ba6348 RCX: 00007f4df1b1f8b9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f4df1ba6340 R08: 00007f4df1ad66c0 R09: 00007f4df1ba6348
R10: 00007f4df1ad66c0 R11: 0000000000000246 R12: 00007f4df1ba634c
R13: 0000000000000000 R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6172 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27104 pid:6172  tgid:6166  ppid:5217   flags:0x00000006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_wp+0x1b4a/0x3320 mm/hugetlb.c:5894
 hugetlb_fault+0x2248/0x2fa0 mm/hugetlb.c:6454
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x60d/0x13f0 arch/x86/mm/fault.c:1338
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0033:0x7f4df1ae75cb
RSP: 002b:00007f4df1ab5170 EFLAGS: 00010246
RAX: 006b6e696c766564 RBX: 00007f4df1ba6358 RCX: 00007f4df1b1f8b9
RDX: d8e7cd4472269fec RSI: 0000000000000000 RDI: 00007f4df1ab55a0
RBP: 00007f4df1ba6350 R08: 00007f4df1ab56c0 R09: 00007f4df1ab56c0
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f4df1ba635c
R13: 000000000000006e R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6171 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:28288 pid:6171  tgid:6167  ppid:5213   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc90009117c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001222f98 RSI: ffffc90009117cb8 RDI: 000000002001b8a0
RBP: 000000002001b8a0 R08: 0000000000000000 R09: fffff52001222f97
R10: ffffc90009117cbf R11: 0000000000000000 R12: ffffc90009117cb8
R13: 000000002001b8a8 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ad6168 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f4df1ba6348 RCX: 00007f4df1b1f8b9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f4df1ba6340 R08: 00007f4df1ad66c0 R09: 00007f4df1ba6348
R10: 00007f4df1ad66c0 R11: 0000000000000246 R12: 00007f4df1ba634c
R13: 0000000000000000 R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6174 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27104 pid:6174  tgid:6167  ppid:5213   flags:0x00000006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x60d/0x13f0 arch/x86/mm/fault.c:1338
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0033:0x7f4df1ae75cb
RSP: 002b:00007f4df1ab5170 EFLAGS: 00010246
RAX: 006b6e696c766564 RBX: 00007f4df1ba6358 RCX: 00007f4df1b1f8b9
RDX: d8e7cd4472269fec RSI: 0000000000000000 RDI: 00007f4df1ab55a0
RBP: 00007f4df1ba6350 R08: 00007f4df1ba6358 R09: 00007f4df1ab56c0
R10: 00007f4df1ab56c0 R11: 0000000000000246 R12: 00007f4df1ba635c
R13: 000000000000006e R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6384 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27040 pid:6384  tgid:6383  ppid:5218   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc90009597c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff520012b2f98 RSI: ffffc90009597cb8 RDI: 000000002001d000
RBP: 000000002001d000 R08: 0000000000000000 R09: fffff520012b2f97
R10: ffffc90009597cbf R11: 0000000000000000 R12: ffffc90009597cb8
R13: 000000002001d008 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ad6168 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f4df1ba6348 RCX: 00007f4df1b1f8b9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f4df1ba6340 R08: 00007f4df1ad66c0 R09: 00007f4df1ba6348
R10: 00007f4df1ba6348 R11: 0000000000000246 R12: 00007f4df1ba634c
R13: 0000000000000000 R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6385 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27088 pid:6385  tgid:6383  ppid:5218   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ab5168 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f4df1ba6358 RCX: 00007f4df1b1f8b9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f4df1ba6350 R08: 00007f4df1ab56c0 R09: 00007f4df1ba6358
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f4df1ba635c
R13: 000000000000006e R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6457 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27408 pid:6457  tgid:6453  ppid:5216   flags:0x00000006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ab5168 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f4df1ba6358 RCX: 00007f4df1b1f8b9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f4df1ba6350 R08: 00007f4df1ab56c0 R09: 00007f4df1ba6358
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f4df1ba635c
R13: 000000000000006e R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6501 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27616 pid:6501  tgid:6500  ppid:5215   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc90009567c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff520012acf98 RSI: ffffc90009567cb8 RDI: 000000002001e260
RBP: 000000002001e260 R08: 0000000000000000 R09: fffff520012acf97
R10: ffffc90009567cbf R11: 0000000000000000 R12: ffffc90009567cb8
R13: 000000002001e268 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ad6168 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f4df1ba6348 RCX: 00007f4df1b1f8b9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f4df1ba6340 R08: 00007f4df1ad66c0 R09: 00007f4df1ba6348
R10: 00007f4df1ad66c0 R11: 0000000000000246 R12: 00007f4df1ba634c
R13: 0000000000000000 R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>
INFO: task syz-executor390:6502 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor390 state:D stack:27184 pid:6502  tgid:6500  ppid:5215   flags:0x00000006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5315 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6675
 __schedule_loop kernel/sched/core.c:6752 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6767
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6824
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4df1b1f8b9
RSP: 002b:00007f4df1ab5168 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f4df1ba6358 RCX: 00007f4df1b1f8b9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f4df1ba6350 R08: 00007f4df1ab56c0 R09: 00007f4df1ba6358
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f4df1ba635c
R13: 000000000000006e R14: 00007fff98b1c2f0 R15: 00007fff98b1c3d8
 </TASK>

Showing all locks held in the system:
1 lock held by khungtaskd/30:
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline]
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: rcu_read_lock include/linux/rcupdate.h:849 [inline]
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x7f/0x390 kernel/locking/lockdep.c:6720
5 locks held by kworker/u8:8/3033:
1 lock held by klogd/4663:
2 locks held by getty/4978:
 #0: ffff88814c4320a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x24/0x80 drivers/tty/tty_ldisc.c:243
 #1: ffffc90002f062f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_read+0xfba/0x1480 drivers/tty/n_tty.c:2211
3 locks held by syz-executor390/6168:
 #0: ffff8880614a9498 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock_killable include/linux/mmap_lock.h:153 [inline]
 #0: ffff8880614a9498 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6108 [inline]
 #0: ffff8880614a9498 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x3a9/0x6a0 mm/memory.c:6159
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 #2: ffff88806034b8e8 (&resv_map->rw_sema){++++}-{3:3}, at: hugetlb_vma_lock_read mm/hugetlb.c:276 [inline]
 #2: ffff88806034b8e8 (&resv_map->rw_sema){++++}-{3:3}, at: hugetlb_vma_lock_read+0x105/0x140 mm/hugetlb.c:267
2 locks held by syz-executor390/6172:
 #0: ffff8880247719b8 (&vma->vm_lock->lock){++++}-{3:3}, at: vma_start_read include/linux/mm.h:704 [inline]
 #0: ffff8880247719b8 (&vma->vm_lock->lock){++++}-{3:3}, at: lock_vma_under_rcu+0x13e/0x980 mm/memory.c:6228
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_wp+0x1b4a/0x3320 mm/hugetlb.c:5894
2 locks held by syz-executor390/6171:
 #0: ffff8880614a9e18 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_trylock include/linux/mmap_lock.h:163 [inline]
 #0: ffff8880614a9e18 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6099 [inline]
 #0: ffff8880614a9e18 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x35/0x6a0 mm/memory.c:6159
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
2 locks held by syz-executor390/6174:
 #0: ffff88801d6e7070 (&vma->vm_lock->lock){++++}-{3:3}, at: vma_start_read include/linux/mm.h:704 [inline]
 #0: ffff88801d6e7070 (&vma->vm_lock->lock){++++}-{3:3}, at: lock_vma_under_rcu+0x13e/0x980 mm/memory.c:6228
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
2 locks held by syz-executor390/6384:
 #0: ffff8880612e3a98 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock_killable include/linux/mmap_lock.h:153 [inline]
 #0: ffff8880612e3a98 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6108 [inline]
 #0: ffff8880612e3a98 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x3a9/0x6a0 mm/memory.c:6159
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor390/6385:
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff88806270b8f8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff88806270b8f8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
3 locks held by syz-executor390/6457:
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff888060fa4148 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff888060fa4148 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
2 locks held by syz-executor390/6501:
 #0: ffff88807d5a4d98 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock_killable include/linux/mmap_lock.h:153 [inline]
 #0: ffff88807d5a4d98 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6108 [inline]
 #0: ffff88807d5a4d98 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x3a9/0x6a0 mm/memory.c:6159
 #1: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor390/6502:
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8880232a0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff8880611b69c8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff8880611b69c8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881442d0728 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872

=============================================

NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 30 Comm: khungtaskd Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
 nmi_cpu_backtrace+0x27b/0x390 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x29c/0x300 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:162 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:223 [inline]
 watchdog+0xf0c/0x1240 kernel/hung_task.c:379
 kthread+0x2c1/0x3a0 kernel/kthread.c:389
 ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244
 </TASK>
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 3033 Comm: kworker/u8:8 Not tainted 6.12.0-rc2-syzkaller-00006-g87d6aab2389e #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
Workqueue: events_unbound toggle_allocation_gate
RIP: 0010:lockdep_recursion_finish kernel/locking/lockdep.c:467 [inline]
RIP: 0010:lock_acquire.part.0+0x126/0x380 kernel/locking/lockdep.c:5827
Code: 94 c1 6a 00 45 0f b6 c9 ff b4 24 f8 00 00 00 41 57 44 8b 44 24 2c 8b 4c 24 28 e8 a5 ad ff ff 48 c7 c7 40 d3 6c 8b 48 83 c4 28 <e8> 25 23 b7 09 b8 ff ff ff ff 65 0f c1 05 40 d7 97 7e 83 f8 01 0f
RSP: 0018:ffffc90009a577a8 EFLAGS: 00000082
RAX: 0000000000000001 RBX: 1ffff9200134aef6 RCX: 0000000000000001
RDX: 0000000000000001 RSI: 0000000000000008 RDI: ffffffff8b6cd340
RBP: 0000000000000200 R08: 0000000000000000 R09: fffffbfff2dc4d88
R10: ffffffff96e26c47 R11: 0000000000000000 R12: 0000000000000000
R13: ffff88801b07b078 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000055a312fe8fd8 CR3: 000000000df7c000 CR4: 00000000003526f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <NMI>
 </NMI>
 <TASK>
 __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
 _raw_spin_lock+0x2e/0x40 kernel/locking/spinlock.c:154
 spin_lock include/linux/spinlock.h:351 [inline]
 __pte_offset_map_lock+0xf1/0x300 mm/pgtable-generic.c:375
 pte_offset_map_lock include/linux/mm.h:3014 [inline]
 __get_locked_pte+0x79/0xc0 mm/memory.c:1992
 get_locked_pte include/linux/mm.h:2727 [inline]
 __text_poke+0x224/0xca0 arch/x86/kernel/alternative.c:1899
 text_poke_bp_batch+0x493/0x760 arch/x86/kernel/alternative.c:2373
 text_poke_flush arch/x86/kernel/alternative.c:2486 [inline]
 text_poke_flush arch/x86/kernel/alternative.c:2483 [inline]
 text_poke_finish+0x30/0x40 arch/x86/kernel/alternative.c:2493
 arch_jump_label_transform_apply+0x1c/0x30 arch/x86/kernel/jump_label.c:146
 jump_label_update+0x1d7/0x400 kernel/jump_label.c:920
 static_key_enable_cpuslocked+0x1b7/0x270 kernel/jump_label.c:210
 static_key_enable+0x1a/0x20 kernel/jump_label.c:223
 toggle_allocation_gate mm/kfence/core.c:849 [inline]
 toggle_allocation_gate+0xfc/0x260 mm/kfence/core.c:841
 process_one_work+0x9c5/0x1ba0 kernel/workqueue.c:3229
 process_scheduled_works kernel/workqueue.c:3310 [inline]
 worker_thread+0x6c8/0xf00 kernel/workqueue.c:3391
 kthread+0x2c1/0x3a0 kernel/kthread.c:389
 ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244
 </TASK>
INFO: NMI handler (nmi_cpu_backtrace_handler) took too long to run: 1.676 msecs


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67056d99.050a0220.840ef.000a.GAE%40google.com.

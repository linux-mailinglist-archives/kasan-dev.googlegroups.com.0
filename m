Return-Path: <kasan-dev+bncBCQPF57GUQHBBNHF7S2QMGQEKGOHYPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25DDE954769
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 13:06:30 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5d5bde1600fsf1746686eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 04:06:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723806388; cv=pass;
        d=google.com; s=arc-20160816;
        b=bLto0HmLdlgCswcTd90ZXql/fg368U+QL7tfk7mnGDFYwlt48I+ZKgfL3DFuTV+8aJ
         pxjMHVF/1yLAnt77shnodUo/rc8AxqBAASFTPepNrTdMHOoZt33f2LpWsXvixwIgIhYd
         F5RFNrobw9KAjw9fFJf6wRp3jjHtBoAherOVB1ssxsYnmU6Cp9bujKvrogJ/L1XJdaIN
         rWnU0nk1Xny2hNvJciBfKU4uV8oxG43fAtz6pfuknMMxE/80Rajyj3OVFbFngiV33YCm
         8C/1nGjajChRI8/VsgjHD8Ia+LjFNRDByeIpJcj21SsUTnLb806gXyr9XoN5fwbMNtCs
         0csA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=dcgSSK5eRuydsuiE1ws90169uoI46Q5KxFrOF6DD5W8=;
        fh=ZPuIYXWnG0eaRea34z9rozqGp9b0or11QHnf0fBLrSo=;
        b=v68Nsz5llNdRPKfCGbAqFuJZURtLRfk7IlYV46vFk7dV1aHoZSDKz3g8DOb1rBEHR4
         LgjPp1jGzh4lvHzbMz8RH3o6sBs4Ytojvj6rPlwtx3HSe7tNGz9dTnQcA8Flz/bRogMt
         HeRYLsscnOxJ+N2NftItVKyauzVVQ+qNw32q/GZQqXUPWTVm7Xy/PyVlNeuKj5K13mFW
         iRrNcCO7yf0svZdc3/SiAfSOAXte1P/vQVGTWCh/f92/0WWSwP7gbOW76UMtT9XdblvG
         LJNhJ+i7sjZSxa+0VYeDWsJoO79UOMuL+MKPPOUJ4FHf7b2t5OwoUcIZuWOcsTDeBWiC
         4Iog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3szk_zgkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=3szK_ZgkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723806388; x=1724411188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dcgSSK5eRuydsuiE1ws90169uoI46Q5KxFrOF6DD5W8=;
        b=mlf06OUDSwHd/Kyy/bJYJ5ZslNUzCjrSu1iMwMZ1wbJ7szrzq8NqX9fn8KRSFrocQw
         /8wtDVFeJUg9QS53k4yXxavQejVbZnjot9JnCeVKGL/mylilrIyXU9cscC6i1MuXm6n1
         LukLbOKzrvwNsZV9eED9MgRV6kNSSBOoHsYcM/LdK+g+//HjwujojJuPNCq8pWr74M+h
         TVzComL9Z7Q4Nm0slo1Iht/6Ier0chQRj5bQ6/hCvl2ej/hzpUHeWWV/RII3iUnh7Nqz
         BrYgUCfjY/cshHxVIR982qFhLfkYljeaSEcTI6Kn0FNOgcWkBbU28B8JPy5LO7Qa6huz
         TecA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723806388; x=1724411188;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dcgSSK5eRuydsuiE1ws90169uoI46Q5KxFrOF6DD5W8=;
        b=iaAhuaeWRL92vRhLZucqf10mB8JhlG8z1BamcfF10iBTyjRyCAdgnLKMWPpN6uY1nf
         yKB3fBTWoTK4bost261asCFX2vu0w1uz3yrZPW3SeenID89SSkYWpRyjx8nwnrAXFRr/
         EiJ1vfEYG7O2zrXmDLa9JRR2gNArQuRr4hHBIUf+39CAoQfRcvOo9StQMeAg2ge3kTYY
         PLpNR/FwYuSNcm5RbipfpEM9iy4/3SlpiV4+KP6Sl0CA1efnoQ0SUlXVO1Dn1iZZEE05
         m5LMRDm9kPZWfaANRQPOjbkhoo66eCLrKdYjJEMQufUIbLLu09GcnJeARH+1OgxRrW6K
         MeGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDGtoJq4dEfTcSm6h7gDi+wVyYHBd2EoR7LUdShibeIbxeYxeOA+/otG2V2IGRnGMjN83abptz7doHe3Tt9qQdiOd9Ezns6g==
X-Gm-Message-State: AOJu0Yz0bmv3ZFyhSa1/rlWhjmL1wYL2OKZZqBQr9aRlNQMHQNzASQdy
	NGIRoa4cBHIRsUSmpc9GWTe03hJOxGAJDCQqrT8Nb5WgxHn1DzeT
X-Google-Smtp-Source: AGHT+IEv1/jCqnwyiWA73gpsYe08U546JxOWRvWBMPaxMLy56iq09gjmSPgr4C98pjBb/oY3BwPNWA==
X-Received: by 2002:a05:6871:3a1e:b0:25e:ba6f:a93f with SMTP id 586e51a60fabf-26fff4e9996mr2530232fac.13.1723806388453;
        Fri, 16 Aug 2024 04:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6b98:b0:25c:ac6e:8806 with SMTP id
 586e51a60fabf-26fff3a135als1025498fac.1.-pod-prod-00-us; Fri, 16 Aug 2024
 04:06:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0BWC3G99RNSZGthiJEx+88XUshA3KarlhsOIWoSuofqNaoeaGwFCJM3ZaUb/QXYx6hVWYri0xIkI5PBmnk2LzbdDXk0m3mSi1iQ==
X-Received: by 2002:a05:6870:2198:b0:260:24b0:5a21 with SMTP id 586e51a60fabf-2701db2b13dmr1015951fac.1.1723806387478;
        Fri, 16 Aug 2024 04:06:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723806387; cv=none;
        d=google.com; s=arc-20160816;
        b=pJvayI48C5eAnmfpLe7yyDZ/dnQVbh7x4zE4ubzdmiuRoiW8bMTJ+70/9a8WLLTeiA
         p/wvHcnquE9eYzPT598azDUkk+R10aN5Bv/yNm5UEnyADAq3kZyKsDbhabld0v1vdzSJ
         Yyv9wrzjiNBuTpNvvwe35VF8lBpfB+bfcOBMdYJfbmt5hXtCUOG6qXZrgswxsJibkIg4
         lmMq0sn3NkTjWI3Dwa+g+UG3ReTEOU5+qouVifS/ocogJ3sfXUKBt+9/vSTs586SKLix
         VkgrqI7JoL1kbrY9wwxg+m9PGbGnETy6GuILRh5LfD+2OTFjnq/IL1LCM/PAPEkVKCS5
         D7bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=h++Y0J1RJSpy/WXrmtYTzWU8qMOhjabLz05/9Ewdu20=;
        fh=+XUWaVptDM4IHCkOKXAbtiB9Y3+AiHynOwJsIgEEcSE=;
        b=l+PteaxYotUyO4aRdykRzYsecfLj+FPqFyiZlmQiQyuxS4f3GODikgnz1qp3LL161Q
         u7MY0ZtcawbRWq/0+RYnYjAodlX4FuqOKk3czdf4wxwVdm76e84kP0Lh1udcLe86Dmes
         3283d8uLylCzi3zNdY87zznlmSVUIt4zIWg5lpI4GIUSo5iBeoQMNfkiHgixbRyNvhHa
         Y5jWWl5QnCy4lZJg4bXYETLJHLjR+vBGCQ2PJvhe7FyO1/9Qq7IQTk7tmxEGDjb6V5td
         npMePrX759PckcULeFgcvUYZZ4bgwas5qx+v5uTM5AED9aKj3pRS93Go+MidEiBeMIkV
         iJ3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3szk_zgkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=3szK_ZgkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f71.google.com (mail-io1-f71.google.com. [209.85.166.71])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27004009a75si164096fac.0.2024.08.16.04.06.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2024 04:06:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3szk_zgkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) client-ip=209.85.166.71;
Received: by mail-io1-f71.google.com with SMTP id ca18e2360f4ac-81f8293cdb1so184311539f.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2024 04:06:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8uXQo6SNqj55Xz9uPepy1YOsffPUogSgiAof4gbBYEGmoPzB/t8NhUCPYbKfpEq1ZnI0irAOfsI0Tg3rOJ0OPIAvyOSZvvwa7LQ==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:b2c:b0:39d:1144:e784 with SMTP id
 e9e14a558f8ab-39d26d6ee1emr1647265ab.4.1723806387077; Fri, 16 Aug 2024
 04:06:27 -0700 (PDT)
Date: Fri, 16 Aug 2024 04:06:27 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000005d16fe061fcaf338@google.com>
Subject: [syzbot] [kasan?] [mm?] INFO: task hung in hugetlb_wp
From: syzbot <syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	keescook@chromium.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	muchun.song@linux.dev, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3szk_zgkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.71 as permitted sender) smtp.mailfrom=3szK_ZgkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

Hello,

syzbot found the following issue on:

HEAD commit:    6b0f8db921ab Merge tag 'execve-v6.11-rc4' of git://git.ker..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=16509e8d980000
kernel config:  https://syzkaller.appspot.com/x/.config?x=801d05d1ea4be1b8
dashboard link: https://syzkaller.appspot.com/bug?extid=c391aebb8e8e8cd95c55
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40

Unfortunately, I don't have any reproducer for this issue yet.

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/8e1d5e5016fb/disk-6b0f8db9.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/0487df01ffef/vmlinux-6b0f8db9.xz
kernel image: https://storage.googleapis.com/syzbot-assets/cc8e8e0932d5/bzImage-6b0f8db9.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com

INFO: task syz.3.186:6037 blocked for more than 143 seconds.
      Not tainted 6.11.0-rc3-syzkaller-00013-g6b0f8db921ab #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz.3.186       state:D stack:25688 pid:6037  tgid:6037  ppid:5773   flags:0x00004004
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5188 [inline]
 __schedule+0x1800/0x4a60 kernel/sched/core.c:6529
 __schedule_loop kernel/sched/core.c:6606 [inline]
 schedule+0x14b/0x320 kernel/sched/core.c:6621
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6678
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x6a4/0xd70 kernel/locking/mutex.c:752
 hugetlb_wp+0x104d/0x3a90 mm/hugetlb.c:6027
 hugetlb_fault+0x26de/0x3780 mm/hugetlb.c:6579
 handle_mm_fault+0x173f/0x1980 mm/memory.c:5831
 do_user_addr_fault arch/x86/mm/fault.c:1338 [inline]
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x459/0x8c0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0033:0x7f31cf341498
RSP: 002b:00007f31cf63fb98 EFLAGS: 00010246
RAX: 0000000020000080 RBX: 0000000000000004 RCX: 0070616d65676170
RDX: 0000000000000008 RSI: 0070616d65676170 RDI: 0000000020000080
RBP: 00007f31cf63fc70 R08: 00007f31cf200000 R09: 0000000000000001
R10: 0000000000000001 R11: 0000000000000009 R12: 0000000000000032
R13: 00007f31cf63fc90 R14: 00007f31cf63fcb0 R15: fffffffffffffffe
 </TASK>
INFO: task syz.3.186:6038 blocked for more than 143 seconds.
      Not tainted 6.11.0-rc3-syzkaller-00013-g6b0f8db921ab #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz.3.186       state:D stack:22360 pid:6038  tgid:6037  ppid:5773   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5188 [inline]
 __schedule+0x1800/0x4a60 kernel/sched/core.c:6529
 __schedule_loop kernel/sched/core.c:6606 [inline]
 schedule+0x14b/0x320 kernel/sched/core.c:6621
 io_schedule+0x8d/0x110 kernel/sched/core.c:7401
 folio_wait_bit_common+0x882/0x12b0 mm/filemap.c:1307
 __filemap_get_folio+0xb7/0xc10 mm/filemap.c:1898
 hugetlb_fault+0x1b10/0x3780 mm/hugetlb.c:6531
 handle_mm_fault+0x173f/0x1980 mm/memory.c:5831
 do_user_addr_fault arch/x86/mm/fault.c:1389 [inline]
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x2b9/0x8c0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:__put_user_8+0x11/0x20 arch/x86/lib/putuser.S:107
Code: 84 00 00 00 00 00 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 48 89 cb 48 c1 fb 3f 48 09 d9 0f 01 cb <48> 89 01 31 c9 0f 01 ca c3 cc cc cc cc 66 90 90 90 90 90 90 90 90
RSP: 0018:ffffc9000317f778 EFLAGS: 00050202
RAX: 0000000000800000 RBX: 0000000000000000 RCX: 0000000020000020
RDX: 0000000000000000 RSI: ffffffff8c0ae6e0 RDI: ffffffff8c606400
RBP: ffffc9000317fec8 R08: ffffffff9017ce2f R09: 1ffffffff202f9c5
R10: dffffc0000000000 R11: fffffbfff202f9c6 R12: 1ffff9200062ff7d
R13: 1ffff9200062ff08 R14: 0000000020800000 R15: 0000000000800000
 userfaultfd_copy fs/userfaultfd.c:1735 [inline]
 userfaultfd_ioctl+0x28e7/0x70a0 fs/userfaultfd.c:2133
 vfs_ioctl fs/ioctl.c:51 [inline]
 __do_sys_ioctl fs/ioctl.c:907 [inline]
 __se_sys_ioctl+0xfc/0x170 fs/ioctl.c:893
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f31cf3799f9
RSP: 002b:00007f31d00e5038 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 00007f31cf515f80 RCX: 00007f31cf3799f9
RDX: 0000000020000000 RSI: 00000000c028aa03 RDI: 0000000000000004
RBP: 00007f31cf3e78ee R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000000 R14: 00007f31cf515f80 R15: 00007f31cf63fa38
 </TASK>

Showing all locks held in the system:
3 locks held by kworker/1:0/25:
1 lock held by khungtaskd/30:
 #0: ffffffff8e9382e0 (rcu_read_lock){....}-{1:2}, at: rcu_lock_acquire include/linux/rcupdate.h:326 [inline]
 #0: ffffffff8e9382e0 (rcu_read_lock){....}-{1:2}, at: rcu_read_lock include/linux/rcupdate.h:838 [inline]
 #0: ffffffff8e9382e0 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x55/0x2a0 kernel/locking/lockdep.c:6626
3 locks held by kworker/u8:2/35:
3 locks held by kworker/1:1/46:
 #0: ffff888015880948 ((wq_completion)events){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3206 [inline]
 #0: ffff888015880948 ((wq_completion)events){+.+.}-{0:0}, at: process_scheduled_works+0x90a/0x1830 kernel/workqueue.c:3312
 #1: ffffc90000b67d00 ((work_completion)(&data->fib_event_work)){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3207 [inline]
 #1: ffffc90000b67d00 ((work_completion)(&data->fib_event_work)){+.+.}-{0:0}, at: process_scheduled_works+0x945/0x1830 kernel/workqueue.c:3312
 #2: ffff888062701240 (&data->fib_lock){+.+.}-{3:3}, at: nsim_fib_event_work+0x2d1/0x4130 drivers/net/netdevsim/fib.c:1489
3 locks held by kworker/u8:3/52:
 #0: ffff888015889148 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3206 [inline]
 #0: ffff888015889148 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_scheduled_works+0x90a/0x1830 kernel/workqueue.c:3312
 #1: ffffc90000bc7d00 ((linkwatch_work).work){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3207 [inline]
 #1: ffffc90000bc7d00 ((linkwatch_work).work){+.+.}-{0:0}, at: process_scheduled_works+0x945/0x1830 kernel/workqueue.c:3312
 #2: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: linkwatch_event+0xe/0x60 net/core/link_watch.c:276
4 locks held by kworker/u8:10/2503:
 #0: ffff8880166e5948 ((wq_completion)netns){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3206 [inline]
 #0: ffff8880166e5948 ((wq_completion)netns){+.+.}-{0:0}, at: process_scheduled_works+0x90a/0x1830 kernel/workqueue.c:3312
 #1: ffffc90008c67d00 (net_cleanup_work){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3207 [inline]
 #1: ffffc90008c67d00 (net_cleanup_work){+.+.}-{0:0}, at: process_scheduled_works+0x945/0x1830 kernel/workqueue.c:3312
 #2: ffffffff8fc75790 (pernet_ops_rwsem){++++}-{3:3}, at: cleanup_net+0x16a/0xcc0 net/core/net_namespace.c:594
 #3: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: fib_net_exit_batch+0x20/0x90 net/ipv4/fib_frontend.c:1638
1 lock held by dhcpcd/4896:
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: devinet_ioctl+0x2ce/0x1bc0 net/ipv4/devinet.c:1101
2 locks held by getty/4983:
 #0: ffff88802af030a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x25/0x70 drivers/tty/tty_ldisc.c:243
 #1: ffffc90002f062f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_read+0x6ac/0x1e00 drivers/tty/n_tty.c:2211
1 lock held by syz-executor/5218:
3 locks held by kworker/0:4/5282:
 #0: ffff888015880948 ((wq_completion)events){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3206 [inline]
 #0: ffff888015880948 ((wq_completion)events){+.+.}-{0:0}, at: process_scheduled_works+0x90a/0x1830 kernel/workqueue.c:3312
 #1: ffffc90004017d00 ((fqdir_free_work).work){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3207 [inline]
 #1: ffffc90004017d00 ((fqdir_free_work).work){+.+.}-{0:0}, at: process_scheduled_works+0x945/0x1830 kernel/workqueue.c:3312
 #2: ffffffff8e93d580 (rcu_state.barrier_mutex){+.+.}-{3:3}, at: rcu_barrier+0x4c/0x530 kernel/rcu/tree.c:4486
2 locks held by syz.3.186/6037:
 #0: ffff888063f3fd18 (&vma->vm_lock->lock){++++}-{3:3}, at: vma_start_read include/linux/mm.h:690 [inline]
 #0: ffff888063f3fd18 (&vma->vm_lock->lock){++++}-{3:3}, at: lock_vma_under_rcu+0x2f9/0x6e0 mm/memory.c:5999
 #1: ffff88801baea0f8 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_wp+0x104d/0x3a90 mm/hugetlb.c:6027
3 locks held by syz.3.186/6038:
 #0: ffff88805a331e18 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_trylock include/linux/mmap_lock.h:163 [inline]
 #0: ffff88805a331e18 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:5870 [inline]
 #0: ffff88805a331e18 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x32/0x2f0 mm/memory.c:5930
 #1: ffff88801baea0f8 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x575/0x3780 mm/hugetlb.c:6451
 #2: ffff888028c88ce8 (&resv_map->rw_sema){.+.+}-{3:3}, at: hugetlb_fault+0x67b/0x3780 mm/hugetlb.c:6458
2 locks held by syz.3.425/7080:
 #0: ffff88801cf73b68 (&vma->vm_lock->lock){++++}-{3:3}, at: vma_start_read include/linux/mm.h:690 [inline]
 #0: ffff88801cf73b68 (&vma->vm_lock->lock){++++}-{3:3}, at: lock_vma_under_rcu+0x2f9/0x6e0 mm/memory.c:5999
 #1: ffff88801baea0f8 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x575/0x3780 mm/hugetlb.c:6451
2 locks held by syz-executor/7564:
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: tun_detach drivers/net/tun.c:698 [inline]
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: tun_chr_close+0x3e/0x1b0 drivers/net/tun.c:3510
 #1: ffffffff8e93d6b8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: exp_funnel_lock kernel/rcu/tree_exp.h:296 [inline]
 #1: ffffffff8e93d6b8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: synchronize_rcu_expedited+0x381/0x830 kernel/rcu/tree_exp.h:958
1 lock held by syz-executor/8404:
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: rtnl_lock net/core/rtnetlink.c:79 [inline]
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: rtnetlink_rcv_msg+0x6e6/0xcf0 net/core/rtnetlink.c:6644
1 lock held by syz.2.726/8553:
 #0: ffffffff8fc82308 (rtnl_mutex){+.+.}-{3:3}, at: dev_ioctl+0x639/0x1340 net/core/dev_ioctl.c:737

=============================================

NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 30 Comm: khungtaskd Not tainted 6.11.0-rc3-syzkaller-00013-g6b0f8db921ab #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 06/27/2024
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:93 [inline]
 dump_stack_lvl+0x241/0x360 lib/dump_stack.c:119
 nmi_cpu_backtrace+0x49c/0x4d0 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x198/0x320 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:162 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:223 [inline]
 watchdog+0xfee/0x1030 kernel/hung_task.c:379
 kthread+0x2f0/0x390 kernel/kthread.c:389
 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244
 </TASK>
Sending NMI from CPU 0 to CPUs 1:
NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 46 Comm: kworker/1:1 Not tainted 6.11.0-rc3-syzkaller-00013-g6b0f8db921ab #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 06/27/2024
Workqueue: events nsim_dev_trap_report_work
RIP: 0010:get_current arch/x86/include/asm/current.h:49 [inline]
RIP: 0010:__sanitizer_cov_trace_pc+0x8/0x70 kernel/kcov.c:215
Code: 8b 3d 7c db 95 0c 48 89 de 5b e9 03 94 5b 00 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 48 8b 04 24 <65> 48 8b 0c 25 40 d7 03 00 65 8b 15 a0 5f 70 7e 81 e2 00 01 ff 00
RSP: 0018:ffffc90000b67498 EFLAGS: 00000202
RAX: ffffffff81413211 RBX: ffffffff909bed9c RCX: dffffc0000000000
RDX: 0000000000000000 RSI: 0000000000000001 RDI: ffffc90000b67670
RBP: ffffc90000b675e0 R08: ffffffff8141454b R09: ffffffff814130bf
R10: 0000000000000003 R11: ffff88801becbc00 R12: ffffc90000b67678
R13: dffffc0000000000 R14: ffffc90000b67630 R15: 1ffff9200016cebc
FS:  0000000000000000(0000) GS:ffff8880b9300000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000110c2a2c5c CR3: 0000000022eec000 CR4: 00000000003526f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <NMI>
 </NMI>
 <TASK>
 unwind_next_frame+0x1ac1/0x2a00 arch/x86/kernel/unwind_orc.c:648
 __unwind_start+0x641/0x7c0 arch/x86/kernel/unwind_orc.c:760
 unwind_start arch/x86/include/asm/unwind.h:64 [inline]
 arch_stack_walk+0x103/0x1b0 arch/x86/kernel/stacktrace.c:24
 stack_trace_save+0x118/0x1d0 kernel/stacktrace.c:122
 kasan_save_stack mm/kasan/common.c:47 [inline]
 kasan_save_track+0x3f/0x80 mm/kasan/common.c:68
 kasan_save_free_info+0x40/0x50 mm/kasan/generic.c:579
 poison_slab_object+0xe0/0x150 mm/kasan/common.c:240
 __kasan_slab_free+0x37/0x60 mm/kasan/common.c:256
 kasan_slab_free include/linux/kasan.h:184 [inline]
 slab_free_hook mm/slub.c:2252 [inline]
 slab_free mm/slub.c:4473 [inline]
 kfree+0x149/0x360 mm/slub.c:4594
 skb_kfree_head net/core/skbuff.c:1084 [inline]
 skb_free_head net/core/skbuff.c:1096 [inline]
 skb_release_data+0x676/0x880 net/core/skbuff.c:1123
 skb_release_all net/core/skbuff.c:1188 [inline]
 __kfree_skb net/core/skbuff.c:1202 [inline]
 consume_skb+0xb1/0x160 net/core/skbuff.c:1426
 nsim_dev_trap_report drivers/net/netdevsim/dev.c:821 [inline]
 nsim_dev_trap_report_work+0x765/0xaa0 drivers/net/netdevsim/dev.c:850
 process_one_work kernel/workqueue.c:3231 [inline]
 process_scheduled_works+0xa2c/0x1830 kernel/workqueue.c:3312
 worker_thread+0x86d/0xd40 kernel/workqueue.c:3390
 kthread+0x2f0/0x390 kernel/kthread.c:389
 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244
 </TASK>
vkms_vblank_simulate: vblank timer overrun


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want to overwrite report's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the report is a duplicate of another one, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000005d16fe061fcaf338%40google.com.

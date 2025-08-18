Return-Path: <kasan-dev+bncBCQPF57GUQHBBEV5RPCQMGQEFFOOIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 84385B29B94
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 10:04:36 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e56ffe6c5csf38455635ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 01:04:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755504275; cv=pass;
        d=google.com; s=arc-20240605;
        b=DJAnx6f1u1P7zCNLAHL4ItC13aKfHvfkfY9mV/jEeWRc8iYnh3SsCTG2hRpPqYgMgN
         OS6X8dMpzjGapa4TKOCCn6t0HC4TqdW6Uzj7PslJYKpJ6ytpLRzIHkpkyo9T+y8P34Fq
         WUREcilGxBzyNK53kp3PgbFTjeEQRuxm9xPyOb29gtT01b2tXMQscB/C8uPH5cTMrvbR
         X62rpVJRxRnnYsUh9iISVy4sp7mWj4vz+Y71gTre8/HJyKcmem0diJHBs9T7SNthPW1h
         VPDFiLVmBiS6Fa1Gb1HV+5veVrPKyW0ZZE7aWjp6gyWp06BXLRy1OJqZqX+eh38gpr8j
         UPGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=uTYFY7dR2vEtw4e+z/cZPqxIYnBZk8xbn/sL7I14cMg=;
        fh=Ue71y6C0/sj82vZm8k9uLTqlkO2qxkdLR4JZxHwCAUM=;
        b=Tdvxda7NQCytXN9ITpswTAdorhx2Zb2XBk6qlRWb0on1MrRuWPj38eljMkLgxrhBXL
         3EQ8TuOS+WZwKpGfJq9O+5qTMw8dTXwckfdXogcOfhNiAb3j+R/ItpdG3Bzs9daugdTw
         HHZYyRsjnsfRhVhTAD2MGk007hRcIV6VYKuWfPEqpr49XkKW1qB15Mf/H7Z0QITyiPRP
         64ohjmc5mzYxv8lrthDDb6qFRTngG/KXikcEvflvFfDfIOAC6wLIZuFDs5114RhSZWrD
         IwSrSkEjV5MBZqEURUtyZ/1BJG7f8rdvdrzIWfJirnLMEebR+ukS+jnlWQ+pxv2u02i0
         m9xA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3j96iaakbacqsyzkallerappid.googleusercontent.com@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.78 as permitted sender) smtp.mailfrom=3j96iaAkbACQSYZKALLERAPPID.GOOGLEUSERCONTENT.COM@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755504275; x=1756109075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uTYFY7dR2vEtw4e+z/cZPqxIYnBZk8xbn/sL7I14cMg=;
        b=ldH9cgSVCVBxZb38q0Y7g00mfJDdTq5bFvWWDm3waIK38ecaH5yIU5rdknWe7fGNTM
         opZl7WJqte63qrnUmGIXGIBom3YVifrKtCDwiSz4bCUCaZX2JhHFoWrrpHei8lj80Sxb
         anSazlMFLSubhBBBIiH/Dcufx1/Lkre3/h4v2nXiy51dfLwk1T7AEWHRylA48KRBgZx5
         PzZnMD8x9ZLwTbQx+391hDUYx7yxsdmrx+Bf2fQl9LFk7qIUfAVZTsWaUxH42xv0rlkY
         z2XOg6zwjc3G/viJ/Dh9IHhdJqnAAdGCtuGDWOhj86E2Zl2UBhDTc4bw+QosEGsWAAr2
         iS0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755504275; x=1756109075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uTYFY7dR2vEtw4e+z/cZPqxIYnBZk8xbn/sL7I14cMg=;
        b=d8vZlu52mwhoNsnvB//FpJBPggUSQzjcEBE+J0m9IbKsOTUL3D/ZNP0bPguYEOcwWG
         2MZHUBQrwcbjHrQVFAzde752n78Xdvi+HId7BJ8WEjB0FPGKpNtQd57eLb0lcfi8C+1C
         SpGF9/NwCDn194l8jLhIKYMRqcIy4ZiDOBvDGCReRJY80H8+2/YzfWdPBDgGFl+RhlTK
         +aP6Q/DBH5GA3HmB62vm6ruB+NE2Ixnx0PO+3mLbdeH+lIwFszVsINd9fPX2Ra8nUqvj
         nbOyTsm+U6SIJcpivzytHWUzS8eXxgeIRzc7lAIbuQUH0vk12x9HR3hWcRhADLO92h41
         edaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWFqrx2MtwHUAzpugyDTQ+d8RPWI5PqLQAQI0HG4utOtMxX6a66GLh4G3WnQMzdX4L/0Tx9g==@lfdr.de
X-Gm-Message-State: AOJu0Yz7pAyV8JjXDiIuPWfJJEZmgfjxtA/vSfOo1YzA4BVrMDcezaWr
	nxpvMXd/gY3Lz5mAf8/DmiDKn7SDWkpaYzKCmujGgQ9aYJ7dg3eSDLI+
X-Google-Smtp-Source: AGHT+IGtfbrq3hodOdODU7P+i5uOiQ4mAbEkCXKaG6TTbaUoUOJJv4xj/QqElK5/m0zqx0xbpGyFiA==
X-Received: by 2002:a05:6e02:12ea:b0:3e4:9a1:6542 with SMTP id e9e14a558f8ab-3e57e9d348bmr251119635ab.18.1755504274844;
        Mon, 18 Aug 2025 01:04:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcPq9c0Y8W8Gl5XchT/iE9uSLFb4hjq9WSm3av6hJx4ug==
Received: by 2002:a05:6e02:2163:b0:3e5:77c5:919b with SMTP id
 e9e14a558f8ab-3e577c593a7ls29159405ab.2.-pod-prod-03-us; Mon, 18 Aug 2025
 01:04:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvFSP1JdhfGnEiZ2ExzRc8xcNYCvwFIk3ZkmH6iI1DwdIbuViY0ivH66d7V7CQgjm8zg82Ga3Gw4I=@googlegroups.com
X-Received: by 2002:a05:6e02:214f:b0:3e5:52a3:dafe with SMTP id e9e14a558f8ab-3e57e84acacmr194775665ab.5.1755504271388;
        Mon, 18 Aug 2025 01:04:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755504271; cv=none;
        d=google.com; s=arc-20240605;
        b=N1nxZI2aSO7zuuj15g8ci4BR3AFoIL5mVRdmB39v2BvUnqAqGhrCl/Q8SgKY2d8qSH
         b3jmsBLkrk+qzuygptkNhkdJczdz+VB52lPo10MBO3cziZ+XbBR0yejPRO80RmfuOAPC
         h3kqH3+3+pSX728KARm4G5cDID5d1q+NQdzKJ8ctCovEJahDLftI/o9nQChtD1O4ztdE
         X1YQzOyxpahdNqqn+4lFljHLf3VZALQG303Se5N5WpjqUgFSBSx1BknmYEmw2qsPZ33P
         C/s2t75xKsV2ZUZVhsXSyX//t6tqDFgK5xkgxWtWhYyYgrrWLnng68M1MDtmDG1YQ/J6
         li5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:date:mime-version;
        bh=SXCnyKQ3Vm9M1IoDEuwjwfWaE/02hODwJqv40lVhlK0=;
        fh=C6gfNrReKXY913PlZ3+orKHKDatbMq7yu/R0FazoRig=;
        b=MyhRQHTP+zUSBFVCUohTv/wV32Yyv47I2aRG9EWtSkg8lheehfNPDsGKfXovXYzX+F
         oCMjDfy73O95V3dDDJ5jbkmVm0KTBpcyBgKBBp8Eo9SorIwFcmXUZi0Oj9kU1CWKchLX
         7Wyt6VLjtn6X8XoGN6QfCqSgISG4sKAahWj5uEaGkqd5t+JZr5ctifiXf6UWBNZul/EM
         rwFXM8sW7SgTBbgVLxDIyRXXyEXleROF+Jhn5Yb9KEE5R0zQkhDO1a7jjoclyoWH1Y+X
         MQaJJdUzYGscgzz2juNNsZ2JenerYlUUBf8xU9lhRAwQAnyLg3bBcLxOHpxflIRwoVRN
         HDSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3j96iaakbacqsyzkallerappid.googleusercontent.com@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.78 as permitted sender) smtp.mailfrom=3j96iaAkbACQSYZKALLERAPPID.GOOGLEUSERCONTENT.COM@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f78.google.com (mail-io1-f78.google.com. [209.85.166.78])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e66b6a671asi908785ab.2.2025.08.18.01.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Aug 2025 01:04:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j96iaakbacqsyzkallerappid.googleusercontent.com@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.78 as permitted sender) client-ip=209.85.166.78;
Received: by mail-io1-f78.google.com with SMTP id ca18e2360f4ac-88432cbe110so426276639f.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Aug 2025 01:04:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLlglLFWjI4hSnIjor6PI6fUODp0p24UGw4+7mx23iQ/FSg1KWnMjB/vChw/975pZw1enNZkriPeQ=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6602:15c7:b0:876:a8dc:96cc with SMTP id
 ca18e2360f4ac-8843e39e913mr1960591339f.6.1755504271041; Mon, 18 Aug 2025
 01:04:31 -0700 (PDT)
Date: Mon, 18 Aug 2025 01:04:31 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
Subject: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
From: syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com, 
	elver@google.com, glider@google.com, jack@suse.cz, kasan-dev@googlegroups.com, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, oleg@redhat.com, syzkaller-bugs@googlegroups.com, 
	viro@zeniv.linux.org.uk, willy@infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3j96iaakbacqsyzkallerappid.googleusercontent.com@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.78 as permitted sender) smtp.mailfrom=3j96iaAkbACQSYZKALLERAPPID.GOOGLEUSERCONTENT.COM@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    038d61fd6422 Linux 6.16
git tree:       upstream
console+strace: https://syzkaller.appspot.com/x/log.txt?x=15f5a234580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=515ec0b49771bcd1
dashboard link: https://syzkaller.appspot.com/bug?extid=d1b5dace43896bc386c3
compiler:       Debian clang version 20.1.7 (++20250616065708+6146a88f6049-1~exp1~20250616065826.132), Debian LLD 20.1.7
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=158063a2580000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=1335d3a2580000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/34e894532715/disk-038d61fd.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/b6a27a46b9dc/vmlinux-038d61fd.xz
kernel image: https://storage.googleapis.com/syzbot-assets/f97a9c8d8216/bzImage-038d61fd.xz

The issue was bisected to:

commit aaec5a95d59615523db03dd53c2052f0a87beea7
Author: Oleg Nesterov <oleg@redhat.com>
Date:   Thu Jan 2 14:07:15 2025 +0000

    pipe_read: don't wake up the writer if the pipe is still full

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=1498e3a2580000
final oops:     https://syzkaller.appspot.com/x/report.txt?x=1698e3a2580000
console output: https://syzkaller.appspot.com/x/log.txt?x=1298e3a2580000

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
Fixes: aaec5a95d596 ("pipe_read: don't wake up the writer if the pipe is still full")

INFO: task syz-executor224:5849 blocked for more than 143 seconds.
      Not tainted 6.16.0-syzkaller #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor224 state:D stack:22952 pid:5849  tgid:5849  ppid:5848   task_flags:0x400140 flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5397 [inline]
 __schedule+0x16aa/0x4c90 kernel/sched/core.c:6786
 __schedule_loop kernel/sched/core.c:6864 [inline]
 schedule+0x165/0x360 kernel/sched/core.c:6879
 io_schedule+0x81/0xe0 kernel/sched/core.c:7724
 folio_wait_bit_common+0x6b0/0xb90 mm/filemap.c:1317
 folio_wait_writeback+0xb0/0x100 mm/page-writeback.c:3126
 __filemap_fdatawait_range+0x147/0x230 mm/filemap.c:539
 file_write_and_wait_range+0x275/0x330 mm/filemap.c:798
 v9fs_file_fsync+0xcf/0x1a0 fs/9p/vfs_file.c:418
 generic_write_sync include/linux/fs.h:3031 [inline]
 netfs_file_write_iter+0x3d8/0x4a0 fs/netfs/buffered_write.c:494
 new_sync_write fs/read_write.c:593 [inline]
 vfs_write+0x54b/0xa90 fs/read_write.c:686
 ksys_write+0x145/0x250 fs/read_write.c:738
 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7fb29049bef9
RSP: 002b:00007ffeb3361588 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
RAX: ffffffffffffffda RBX: 0000200000000140 RCX: 00007fb29049bef9
RDX: 0000000000007fec RSI: 0000200000000300 RDI: 0000000000000007
RBP: 0030656c69662f2e R08: 0000000000000006 R09: 0000000000000006
R10: 0000000000000006 R11: 0000000000000246 R12: 0000200000000180
R13: 00007fb2904e504e R14: 0000000000000001 R15: 0000000000000001
 </TASK>

Showing all locks held in the system:
2 locks held by kworker/u8:0/12:
1 lock held by khungtaskd/31:
 #0: ffffffff8e13f0e0 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire include/linux/rcupdate.h:331 [inline]
 #0: ffffffff8e13f0e0 (rcu_read_lock){....}-{1:3}, at: rcu_read_lock include/linux/rcupdate.h:841 [inline]
 #0: ffffffff8e13f0e0 (rcu_read_lock){....}-{1:3}, at: debug_show_all_locks+0x2e/0x180 kernel/locking/lockdep.c:6770
2 locks held by kworker/u8:6/1337:
 #0: ffff88801a489148 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3213 [inline]
 #0: ffff88801a489148 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_scheduled_works+0x9b4/0x17b0 kernel/workqueue.c:3321
 #1: ffffc9000451fbc0 ((work_completion)(&rreq->work)){+.+.}-{0:0}, at: process_one_work kernel/workqueue.c:3214 [inline]
 #1: ffffc9000451fbc0 ((work_completion)(&rreq->work)){+.+.}-{0:0}, at: process_scheduled_works+0x9ef/0x17b0 kernel/workqueue.c:3321
2 locks held by getty/5596:
 #0: ffff88803095f0a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x25/0x70 drivers/tty/tty_ldisc.c:243
 #1: ffffc900036cb2f0 (&ldata->atomic_read_lock){+.+.}-{4:4}, at: n_tty_read+0x43e/0x1400 drivers/tty/n_tty.c:2222
1 lock held by syz-executor224/5849:
 #0: ffff88807f8cc428 (sb_writers#8){.+.+}-{0:0}, at: file_start_write include/linux/fs.h:3096 [inline]
 #0: ffff88807f8cc428 (sb_writers#8){.+.+}-{0:0}, at: vfs_write+0x211/0xa90 fs/read_write.c:682

=============================================

NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 31 Comm: khungtaskd Not tainted 6.16.0-syzkaller #0 PREEMPT(full) 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 07/12/2025
Call Trace:
 <TASK>
 dump_stack_lvl+0x189/0x250 lib/dump_stack.c:120
 nmi_cpu_backtrace+0x39e/0x3d0 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x17a/0x300 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:158 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:307 [inline]
 watchdog+0xfee/0x1030 kernel/hung_task.c:470
 kthread+0x70e/0x8a0 kernel/kthread.c:464
 ret_from_fork+0x3fc/0x770 arch/x86/kernel/process.c:148
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
 </TASK>
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.16.0-syzkaller #0 PREEMPT(full) 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 07/12/2025
RIP: 0010:pv_native_safe_halt+0x13/0x20 arch/x86/kernel/paravirt.c:82
Code: 53 de 02 00 cc cc cc 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 66 90 0f 00 2d d3 ad 21 00 f3 0f 1e fa fb f4 <c3> cc cc cc cc cc cc cc cc cc cc cc cc 90 90 90 90 90 90 90 90 90
RSP: 0018:ffffffff8de07d80 EFLAGS: 000002c2
RAX: eefad1cde067ed00 RBX: ffffffff81976918 RCX: eefad1cde067ed00
RDX: 0000000000000001 RSI: ffffffff8d982fba RDI: ffffffff8be1ba40
RBP: ffffffff8de07ea8 R08: ffff8880b8632f5b R09: 1ffff110170c65eb
R10: dffffc0000000000 R11: ffffed10170c65ec R12: ffffffff8fa0b3f0
R13: 0000000000000000 R14: 0000000000000000 R15: 1ffffffff1bd2a50
FS:  0000000000000000(0000) GS:ffff888125c57000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000055943a295660 CR3: 000000000df38000 CR4: 00000000003526f0
Call Trace:
 <TASK>
 arch_safe_halt arch/x86/include/asm/paravirt.h:107 [inline]
 default_idle+0x13/0x20 arch/x86/kernel/process.c:749
 default_idle_call+0x74/0xb0 kernel/sched/idle.c:117
 cpuidle_idle_call kernel/sched/idle.c:185 [inline]
 do_idle+0x1e8/0x510 kernel/sched/idle.c:325
 cpu_startup_entry+0x44/0x60 kernel/sched/idle.c:423
 rest_init+0x2de/0x300 init/main.c:745
 start_kernel+0x47d/0x500 init/main.c:1102
 x86_64_start_reservations+0x24/0x30 arch/x86/kernel/head64.c:307
 x86_64_start_kernel+0x143/0x1c0 arch/x86/kernel/head64.c:288
 common_startup_64+0x13e/0x147
 </TASK>


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
For information about bisection process see: https://goo.gl/tpsmEJ#bisection

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68a2de8f.050a0220.e29e5.0097.GAE%40google.com.

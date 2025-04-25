Return-Path: <kasan-dev+bncBCQPF57GUQHBBNHKVTAAMGQE7DVOW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 97A7BA9BF41
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 09:09:42 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b0b2de67d6asf2112868a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 00:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745564981; cv=pass;
        d=google.com; s=arc-20240605;
        b=CGqwif1JLgdFwGOL0PvZw28u1FBiN8QNaGTa2+mh4LLn1DC66NXYx0RAGceK+E/OlN
         JwCHaVP12YuFIH4l57snHxMOiOgjcu9BTNeFasPapeUXm7wwBZ5Pps+c5OYac7BgKjge
         9vcTHGLOyuoHSiad50TBc+pNiS2mCbaLzw9+Q7uQeHLJjAGiLoVUdcWfMXB+eM0eD4EU
         UV0zwtkLfziL8IdranspjjfZLX/uy/3DKTtoNCsxuaA8AM0z5c4GTb1Zk9oF2rXb8ZiO
         qnesJjz8w7Qn2fsfMKht370RdP9Jrh2pTmin3SlVuGldKCEF5tePgr5xlP571kyp1/Ee
         BPaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=1W4VBPoEcNF1CRh18N1rKlaf4eH67MsC2UFR3OIF3UM=;
        fh=DNiD5NBvsjDUy4J3Uxpt3QuyXNOe7PyCZInRJ4t2GQs=;
        b=aL08CxFRazhUL6Vw/vzn90/xDuR8Xr/fynaqSjCvMuDK670Z+WMwQ55Tr9C/2Fb/JB
         4mslITDBxeoSVJXa4fhzzy09MLmFBA4yoHU7CmrCwrD8/n4D3ISSGzNZ3U4nwUDVukSs
         yu/Dow8FHQJdP17njs0RnhA04+WWz1EZTVhpSWxs0AJfuGoPzqh1bBe9/Qn8CVJmtXsW
         RWl14JxirxnaATwt53Wl9xYzuzKjZQGVzHCn4jPh+LlhpUy6lgiec0Tc5DmDE9NVZ1O/
         smyJs1+KLu8ocqDeEdnrbwHTFHnsvUSJ8hritDrLwAm16yKCUCQ9NhY4L7aHKky9UbLi
         PVHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mtulaakbaba8ef0q11u7q55yt.w44w1ua8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.77 as permitted sender) smtp.mailfrom=3MTULaAkbABA8EF0q11u7q55yt.w44w1uA8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745564981; x=1746169781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1W4VBPoEcNF1CRh18N1rKlaf4eH67MsC2UFR3OIF3UM=;
        b=bExFF8dlAxg0iTEbOgvrXXJtuPeqX41u0meP2M5DcDwDwZhWuaq075O8sSN2XMnYut
         usuL5+ZNucbV177OsJcGK8kd/CrSaAtsr/Iv6dsrBPUGozlLJVfE1ehrgnUGrvGXMnRi
         TDc3uZYM8T3K0ef+K0HjDKq/mtWzS09UJV81I8NzTl+6lZYoJZnyN9h/UcrMTEJNn19o
         xqFrcfHTN70y+EgHL1OEokTTG8R+BLQzmAXUiLnn0L4czPG+xPjk262IV5hi2Ov4zwcj
         JC7xmEzEQD0EEPXPLJa0zXdxkSRW7vaT21EyD/Clp2ADReD2lk0hi8vqC7jGhqwtK0Wh
         hLPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745564981; x=1746169781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1W4VBPoEcNF1CRh18N1rKlaf4eH67MsC2UFR3OIF3UM=;
        b=piQooxx88liXp3Mg3L/2JlM5XKwlSa5REH8VeJuPoaFsINJSor2pOCi11LxCSkSjfY
         bt1om7hbKntuB9lsyk0HFpYH9GrbuO0wkgMdm3vczRZaf8SvuyZ2y8JEtE/j59KksLVg
         EEKNI6xRt0oKlWz+DVCzD70Bw2mU7SuuUuuCJPfdKnqwpiEGZNSmMdwC5+inM31MPWiI
         //G6piosOC9pXoFE0VfDAUugNRecx2QCnGx5YtkbbOS4fncGdAoJLYHZ7scvzQUX335h
         3Xz2pBYX4WnxJEVA/ABORHNFlqJlSrdX2o0UTDD5DhENtu3364kWScg5gZToQyLlpK8p
         f3rw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzPwJzrW4I9ESjv4hAoIg61iUeM83Q2YlLHo1hStgTRPS37pZkgwWIWOwmBOcbAjyi7h9YXw==@lfdr.de
X-Gm-Message-State: AOJu0YwXttsSXAyAnPT4VEUeDlmgP+EO9ZUcXniWk/CNH6VrDjs/f944
	WZ0wU2IWH0bBXennL5f9uoNM4GDtiZ30BAB9ZUtx4Os3maQLEKLE
X-Google-Smtp-Source: AGHT+IGancg53ouwFqIIwIPIgnkPsD9OYOsSjfASADuM7MJUS9AxLZc0zLnQlgMO0oj8/+/+0B+g0g==
X-Received: by 2002:a17:90b:5344:b0:2ee:ee77:2263 with SMTP id 98e67ed59e1d1-309f7da6b52mr2488614a91.7.1745564980648;
        Fri, 25 Apr 2025 00:09:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF2hBhVr3oiNEAgi+HsZrf/3Dwk3zYIPIPTfv4CVv79dw==
Received: by 2002:a17:90a:fd97:b0:301:aec9:2622 with SMTP id
 98e67ed59e1d1-309ebd16cd6ls187502a91.0.-pod-prod-03-us; Fri, 25 Apr 2025
 00:09:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4sAhjUcV9SSAqslXfkmUlNWfn/dYkBCcvefjW5zsseFVI8SVRFI4FJ64VnCb+sT4dhsmWYrDIbsA=@googlegroups.com
X-Received: by 2002:a17:90a:d64f:b0:2fe:b907:562f with SMTP id 98e67ed59e1d1-309f7de01b7mr2547676a91.14.1745564978525;
        Fri, 25 Apr 2025 00:09:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745564978; cv=none;
        d=google.com; s=arc-20240605;
        b=gL5u6SIbU7xujwUeYxpVSCVGJo6GRilI4ItuwioLpEXFbJ3DWl9AiFhmf7Z2rU/4yn
         4krWVJ3XMaVhfku2yiXFW86cyJgEl2/mnT+/HTimm/ig+gdy9hDqW4QW2fAlYF3y+Pff
         QdjN4vybonFSGOo3qNpu8IsRH3ga8vU4oTN7HHx+NW9tVZVX5SUd9fibe58FvjEsQhOj
         GfETaDv8Ts+ISsJ2yxeqJpQyd6hkY3jzCPdhSqwpJaYLY3r3Wq1imsIxg0TsJoybb/mW
         CyrmiEBrLcPbDzE4NbVcBcKsC/gVtvqmi/Dw3YQQj65Zte+uzmZ87O2UO0UnAc59iPlD
         sLrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:date:mime-version;
        bh=JuMGdO7tj9pfcgeSkM1hIOwSR02/KINreWPYKsu6KZ4=;
        fh=aRb6ToHJKXuoKde4wWc7PYjfX/fFOM2JBM9dXHW/JUQ=;
        b=FY/aqT+JwVZUL8Qpk8dB2H8/3UbKPXZXr4+38mTHD8x/ArI51vwJvZLtEMNicvMwW4
         UpsbzXNuFnDlDpHcgbzmgdR7Vqcgi9MLBMICJlH2ovYeMjPzBCx8TcpKc1ImO8xiP7g+
         ahnhH8iw7Ylq+10s1E9aH1HTr9aSr0JKV3PvMTlOo2GjMUWskiMUTUXP06lPS1YR61TK
         hw0tMuk7IgBsXcNjsRv24Awiir//UvmFt8ha4YSyEQ6YUpopieJ+lEHtt+W0NNsN83zO
         T5xV6oGnY3Bl/Ra74VkgxYEWTRK2rGfgAmfjgS0CerjiomVNfBqt8VHkfSUUNqSVZEQM
         Y8lQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mtulaakbaba8ef0q11u7q55yt.w44w1ua8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.77 as permitted sender) smtp.mailfrom=3MTULaAkbABA8EF0q11u7q55yt.w44w1uA8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f77.google.com (mail-io1-f77.google.com. [209.85.166.77])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d343e360si620400a91.0.2025.04.25.00.09.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Apr 2025 00:09:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mtulaakbaba8ef0q11u7q55yt.w44w1ua8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.77 as permitted sender) client-ip=209.85.166.77;
Received: by mail-io1-f77.google.com with SMTP id ca18e2360f4ac-85b3827969dso230832139f.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Apr 2025 00:09:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWrXfJ6we5Omd1Qjjwh0ZJR0p5WPiktKH+9vNKR5NAsg44B6IDtHmD1vI/E5KS7H6ms4amlLGIyV4=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:221b:b0:3d8:1d2d:60ab with SMTP id
 e9e14a558f8ab-3d93b3c15c1mr12219745ab.3.1745564977827; Fri, 25 Apr 2025
 00:09:37 -0700 (PDT)
Date: Fri, 25 Apr 2025 00:09:37 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <680b3531.050a0220.10d98e.0011.GAE@google.com>
Subject: [syzbot] [mm?] INFO: task hung in exit_mmap (2)
From: syzbot <syzbot+cdd6c0925e12b0af60cc@syzkaller.appspotmail.com>
To: Liam.Howlett@oracle.com, akpm@linux-foundation.org, andrii@kernel.org, 
	ast@kernel.org, dvyukov@google.com, eddyz87@gmail.com, elver@google.com, 
	glider@google.com, jannh@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lorenzo.stoakes@oracle.com, 
	netdev@vger.kernel.org, sdf@google.com, syzkaller-bugs@googlegroups.com, 
	vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3mtulaakbaba8ef0q11u7q55yt.w44w1ua8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.77 as permitted sender) smtp.mailfrom=3MTULaAkbABA8EF0q11u7q55yt.w44w1uA8u7s439u39.s42@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    750d0ac001e8 MAINTAINERS: Add entry for Socfpga DWMAC ethe..
git tree:       net
console output: https://syzkaller.appspot.com/x/log.txt?x=15580ccc580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=2a31f7155996562
dashboard link: https://syzkaller.appspot.com/bug?extid=cdd6c0925e12b0af60cc
compiler:       Debian clang version 15.0.6, Debian LLD 15.0.6
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=1082263f980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=10809ccc580000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/61fe708710bd/disk-750d0ac0.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/7e7cb0c4c97b/vmlinux-750d0ac0.xz
kernel image: https://storage.googleapis.com/syzbot-assets/93c49eac7367/bzImage-750d0ac0.xz

The issue was bisected to:

commit 68ca5d4eebb8c4de246ee5f634eee26bc689562d
Author: Andrii Nakryiko <andrii@kernel.org>
Date:   Tue Mar 19 23:38:50 2024 +0000

    bpf: support BPF cookie in raw tracepoint (raw_tp, tp_btf) programs

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17849a6f980000
final oops:     https://syzkaller.appspot.com/x/report.txt?x=14449a6f980000
console output: https://syzkaller.appspot.com/x/log.txt?x=10449a6f980000

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+cdd6c0925e12b0af60cc@syzkaller.appspotmail.com
Fixes: 68ca5d4eebb8 ("bpf: support BPF cookie in raw tracepoint (raw_tp, tp_btf) programs")

INFO: task syz-executor253:8529 blocked for more than 143 seconds.
      Not tainted 6.15.0-rc2-syzkaller-00258-g750d0ac001e8 #0
      Blocked by coredump.
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor253 state:D stack:24424 pid:8529  tgid:8527  ppid:5850   task_flags:0x40054c flags:0x00004002
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5382 [inline]
 __schedule+0x1b88/0x5240 kernel/sched/core.c:6767
 __schedule_loop kernel/sched/core.c:6845 [inline]
 schedule+0x163/0x360 kernel/sched/core.c:6860
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6917
 rwsem_down_write_slowpath+0xedd/0x1420 kernel/locking/rwsem.c:1176
 __down_write_common kernel/locking/rwsem.c:1304 [inline]
 __down_write kernel/locking/rwsem.c:1313 [inline]
 down_write+0x1da/0x220 kernel/locking/rwsem.c:1578
 mmap_write_lock include/linux/mmap_lock.h:128 [inline]
 exit_mmap+0x305/0xde0 mm/mmap.c:1292
 __mmput+0x115/0x420 kernel/fork.c:1379
 exit_mm+0x221/0x310 kernel/exit.c:589
 do_exit+0x994/0x27f0 kernel/exit.c:940
 do_group_exit+0x207/0x2c0 kernel/exit.c:1102
 get_signal+0x1696/0x1730 kernel/signal.c:3034
 arch_do_signal_or_restart+0x98/0x810 arch/x86/kernel/signal.c:337
 exit_to_user_mode_loop kernel/entry/common.c:111 [inline]
 exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline]
 __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline]
 syscall_exit_to_user_mode+0xce/0x340 kernel/entry/common.c:218
 do_syscall_64+0x100/0x210 arch/x86/entry/syscall_64.c:100
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f0e7faaa6e9
RSP: 002b:00007f0e7fa42218 EFLAGS: 00000246 ORIG_RAX: 00000000000000ca
RAX: fffffffffffffe00 RBX: 00007f0e7fb34338 RCX: 00007f0e7faaa6e9
RDX: 0000000000000000 RSI: 0000000000000080 RDI: 00007f0e7fb34338
RBP: 00007f0e7fb34330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f0e7fb01074
R13: 0000200000000040 R14: 00002000000002c0 R15: 00002000000002c8
 </TASK>

Showing all locks held in the system:
1 lock held by khungtaskd/31:
 #0: ffffffff8ed3df20 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire include/linux/rcupdate.h:331 [inline]
 #0: ffffffff8ed3df20 (rcu_read_lock){....}-{1:3}, at: rcu_read_lock include/linux/rcupdate.h:841 [inline]
 #0: ffffffff8ed3df20 (rcu_read_lock){....}-{1:3}, at: debug_show_all_locks+0x30/0x180 kernel/locking/lockdep.c:6764
2 locks held by dhcpcd/5506:
 #0: ffffffff8edf61b0 (dup_mmap_sem){.+.+}-{0:0}, at: dup_mm kernel/fork.c:1733 [inline]
 #0: ffffffff8edf61b0 (dup_mmap_sem){.+.+}-{0:0}, at: copy_mm+0x1d6/0x22c0 kernel/fork.c:1786
 #1: ffff88805a8a3de0 (&mm->mmap_lock){++++}-{4:4}, at: mmap_write_lock_killable include/linux/mmap_lock.h:146 [inline]
 #1: ffff88805a8a3de0 (&mm->mmap_lock){++++}-{4:4}, at: dup_mmap kernel/fork.c:620 [inline]
 #1: ffff88805a8a3de0 (&mm->mmap_lock){++++}-{4:4}, at: dup_mm kernel/fork.c:1734 [inline]
 #1: ffff88805a8a3de0 (&mm->mmap_lock){++++}-{4:4}, at: copy_mm+0x2a8/0x22c0 kernel/fork.c:1786
2 locks held by getty/5594:
 #0: ffff8880319c50a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x25/0x70 drivers/tty/tty_ldisc.c:243
 #1: ffffc9000332e2f0 (&ldata->atomic_read_lock){+.+.}-{4:4}, at: n_tty_read+0x5bb/0x1700 drivers/tty/n_tty.c:2222
1 lock held by syz-executor253/8529:
 #0: ffff88807b09bde0 (&mm->mmap_lock){++++}-{4:4}, at: mmap_write_lock include/linux/mmap_lock.h:128 [inline]
 #0: ffff88807b09bde0 (&mm->mmap_lock){++++}-{4:4}, at: exit_mmap+0x305/0xde0 mm/mmap.c:1292
1 lock held by dhcpcd/8530:
 #0: ffff8880253947e0 (&mm->mmap_lock){++++}-{4:4}, at: mmap_write_lock_killable include/linux/mmap_lock.h:146 [inline]
 #0: ffff8880253947e0 (&mm->mmap_lock){++++}-{4:4}, at: __vm_munmap+0x213/0x520 mm/vma.c:3010

=============================================

NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 31 Comm: khungtaskd Not tainted 6.15.0-rc2-syzkaller-00258-g750d0ac001e8 #0 PREEMPT(full) 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120
 nmi_cpu_backtrace+0x4ab/0x4e0 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x198/0x320 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:158 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:274 [inline]
 watchdog+0x1058/0x10a0 kernel/hung_task.c:437
 kthread+0x7b7/0x940 kernel/kthread.c:464
 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:153
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
 </TASK>
Sending NMI from CPU 0 to CPUs 1:
NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.15.0-rc2-syzkaller-00258-g750d0ac001e8 #0 PREEMPT(full) 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025
RIP: 0010:pv_native_safe_halt+0x13/0x20 arch/x86/kernel/paravirt.c:81
Code: cc cc cc cc cc cc cc 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 66 90 0f 00 2d 73 8f 18 00 f3 0f 1e fa fb f4 <c3> cc cc cc cc cc cc cc cc cc cc cc cc 90 90 90 90 90 90 90 90 90
RSP: 0018:ffffc90000197dc0 EFLAGS: 000002c2
RAX: 330d1d9510403d00 RBX: ffffffff8197272e RCX: ffffffff8c2fa93c
RDX: 0000000000000001 RSI: ffffffff8e6499b7 RDI: ffffffff8ca1b5a0
RBP: ffffc90000197f20 R08: ffff8880b8732b5b R09: 1ffff110170e656b
R10: dffffc0000000000 R11: ffffed10170e656c R12: 1ffff92000032fd2
R13: 1ffff11003ad9b40 R14: 0000000000000001 R15: dffffc0000000000
FS:  0000000000000000(0000) GS:ffff88812509a000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f6b30e296c0 CR3: 000000000eb38000 CR4: 00000000003526f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <TASK>
 arch_safe_halt arch/x86/include/asm/paravirt.h:107 [inline]
 default_idle+0x13/0x20 arch/x86/kernel/process.c:748
 default_idle_call+0x74/0xb0 kernel/sched/idle.c:117
 cpuidle_idle_call kernel/sched/idle.c:185 [inline]
 do_idle+0x22e/0x5d0 kernel/sched/idle.c:325
 cpu_startup_entry+0x42/0x60 kernel/sched/idle.c:423
 start_secondary+0xfe/0x100 arch/x86/kernel/smpboot.c:315
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/680b3531.050a0220.10d98e.0011.GAE%40google.com.

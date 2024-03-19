Return-Path: <kasan-dev+bncBCQPF57GUQHBB3WT4WXQMGQEWTWE4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CA9587FBD5
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 11:33:20 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-366999e233asf26494885ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 03:33:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710844399; cv=pass;
        d=google.com; s=arc-20160816;
        b=ml+JCcx5IRGmnFUflK0SY/eGyKtuvkCKCjDOZvVOLOPNJ/WV60et1ayZrqSJCL7VBG
         gDvoJ6OePnEjjzqqra3UlotD/FNN0gQSB35GeMIUKYJLPSo3b1XIc4yd+ExsTGAHZ79C
         rlUN8pY0hN8TXd2EX5ebue1cdm5YL/jArGmQOJxWPeSwOc7DoU5wZXHl4k3smuGT1u4a
         HtSBwKiIUCLVM/yHK+iPqI9B5ELY+1wfz0oJkfSG5p46nABia/uyQ2gAGacBygnet5PY
         IL4cdQNWCmQN+INEBux7TmW4omY5gSK6VdrqKkPDRPpFqSOst1I6ahFBddHER9gk2T/9
         Rmnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=9g5/J2rDV1XlP1V590/DTnIeVJ0jtkmkdf2DZo91s4s=;
        fh=8DoUZOzNZo46/rWoK6FX9h1zIb1QKTXUxvUUWgcfpW8=;
        b=tC4fDzp4a1xa759XdhyUo+Z5vx0/bSJBTLytZ0Y5dSZepBbyNQhNmBtYl65wG7+jxH
         9oBrIaeaMXjeUCI5+9x860wBmijDjVBxUlYY3ZK9Wmf6gjDG75BcE7RPGjXiW3mFEf/X
         0Cvac0ZWv7XS+tj0oJKhXOKg2y6tWwzPSbs9r602VLUOFq0t0jE7e80dyaSgmMpzW4ad
         7VZcxkhCZn/u70nmepV+XZTgetTOA/uilzOMUXZg5loHFbfsKft0ewu088LggllNURYP
         B7BSEAVpKp5xiNYl44hOIlWHwoosJnmq0AP2Ke8LWI2+PTJwAe69JB3ud5bdeNG4l2HY
         rj8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 37wn5zqkbanwqwxi8jjcp8nngb.emmejcsqcpamlrclr.amk@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=37Wn5ZQkbANwQWXI8JJCP8NNGB.EMMEJCSQCPAMLRCLR.AMK@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710844399; x=1711449199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9g5/J2rDV1XlP1V590/DTnIeVJ0jtkmkdf2DZo91s4s=;
        b=lpyqv7h9ymSmcqlMf0XQNGtSJlt+AyyFLbTLZNZCZtr7oh+oQf7z2w5COcA9Q0E3fF
         +zJGvk/FcVo/kpd2C1kDou+tNSoYs5lIEjOqwS/oziPYYnrzzlwAqlRqTVvae2coEBEt
         ic1UHjAhTbiyWGqOuS7hH0bHNga57manS3B0Jex00n9/00olrGN+aL2EvHba3TZmjoKg
         /7zeB8Aio9dDmr96oM/tKM9azY82ueEOB82Am/S6x/1Mt5WH7dZGRmvErFAVel24t9Vh
         7bugfk4AE9q002RmyAzcKBQmohUmlKW3S0DY4VEljAPvp/kr9b1yLTGECOMQ72GQ0LTG
         W4/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710844399; x=1711449199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9g5/J2rDV1XlP1V590/DTnIeVJ0jtkmkdf2DZo91s4s=;
        b=go3BNd2pKiqCIg/c530i/Jzew/BtcspiEW8bmf7HKmwyPCuM9uB8vEWHBcWbMY/LuL
         pJ/IdWdgUbygcPBxa53TdWFEXBnoyYVGnEDwrPZMqlcA81MectDbKpJjF0xrm9H/fH+k
         fmUHnNcnQCIDNmKZI41p535i428LsQKNG38GawXN0WCWfk2TK98Nmp254e/RSXVOwD69
         pJfzO4ePtkPZeyd2gRXumr8Wag/PEwfsxZQruQ8L3I7DsAo0EAZ2hWaOBEg1wQWHT7MQ
         efdIMxUKXZDdGaW+hTL0tvDHmSdKyQtz5II1+gFOJzhzOevoicbdJkGJHHCe07d1hURU
         fKTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWffuiYvOjXEc8EJf+jPTdOJkD8nMmu/oIoVU8KRCdxRHfiqEu0CVPJ4p4th34BePxYccHWDzb1ZO+5cy3edEyMZ36MlLEYOg==
X-Gm-Message-State: AOJu0Ywqc4rKDA7z9wBnTT798cQcd2ryw5VpRRJiVUogaS+JZ1wiVDLc
	T61N0YzHPDYSfZJ9e/96HdMqVHezmw77f6GNM4vVZV7HPJM+Aeeb
X-Google-Smtp-Source: AGHT+IE5MNxKi8F2Qggoa7JL8Y2gwRpdi3L8tlrIsOX0DN/XESoLq25alI6BY0ThZoJrlVCH7ZJlZw==
X-Received: by 2002:a05:6e02:2148:b0:366:b3e4:a0e3 with SMTP id d8-20020a056e02214800b00366b3e4a0e3mr3816736ilv.3.1710844398693;
        Tue, 19 Mar 2024 03:33:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17ca:b0:366:a73a:603 with SMTP id
 z10-20020a056e0217ca00b00366a73a0603ls602910ilu.0.-pod-prod-00-us; Tue, 19
 Mar 2024 03:33:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUb2vBxBSuItz4Vj4piNZMziFgeIyNaVOjr7qpxMY1e9ORK+9fopckgqAKmhM4KFxtcfTaq7DbcLN4NbKErSiCw2vmAzPC+TpBYUA==
X-Received: by 2002:a6b:4e11:0:b0:7ce:fb36:1c33 with SMTP id c17-20020a6b4e11000000b007cefb361c33mr1507762iob.9.1710844397573;
        Tue, 19 Mar 2024 03:33:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710844397; cv=none;
        d=google.com; s=arc-20160816;
        b=R3M+oe/O64vkx8GRTnfb3QW4eVs76VeRp9jQK5WSSS7USnJC/Ms2woPo0rzXLwGn+m
         KDcu5Qpto8/J5ajQmF/hVjYAurUCY+biisduxQhLCinBw0en2nkSAZ3c/VHaWA5M3G37
         KS22RIWJM0xN/x3vvdoug58FTqtwai5HF/cl7+3hGOQZYHrzKx+e4z9SpGwffuoolEyR
         MuUGlxhmt2+CyzY7Z/1/582sLxH0WpcdtaN2vZ5yOpOIzYrN/YTit1k680TJFnAwnOQ5
         n/mFw7MMmR8oXY6N3ZDIXxAZNc18Jx0yCrhCVS0tQ0DAy1Ug0PbjQhOl/456sS6YLymK
         0JmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=AfH616evJHoxgc9RlKueSdsKtzrhRnXKCq+xBkHhWYc=;
        fh=t92zFwe5IvVaI//iqRbgaNfIhkMKckg1IuvBeS2F4BY=;
        b=Iay628A1uBxPMDSiv7BPlRFEknD/uAg4Dz7o0JNzv2Tm0T1EuzpMnDOsuGrCEuHi5K
         CjTSey0rXcFfkPjJTb9Nlqo+BTTSKdBfnV51IKkXtVRzXqkKz6+puW2ckYidJGHfOhZP
         4zkNFYbvxVOt/V13T5F7IkcYU96AYYvnR+nlpPAK70SMx2IkOjtD251TXL1IHfopkKyG
         VkicszTT7Cdtad0hWsLrBfRLtyG5k96fuZ2GIm2TnFhPrcw+BpcXt/DRGN4ms5l8zfSE
         DaS8R+TlSWOEyihvvG7lOCMrF+MSxMJrJ2gKeKeFGKIox3V1Ip/0cNDKkxcZATuuFnSq
         eGIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 37wn5zqkbanwqwxi8jjcp8nngb.emmejcsqcpamlrclr.amk@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=37Wn5ZQkbANwQWXI8JJCP8NNGB.EMMEJCSQCPAMLRCLR.AMK@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f71.google.com (mail-io1-f71.google.com. [209.85.166.71])
        by gmr-mx.google.com with ESMTPS id z9-20020a6bc909000000b007cc589ab5c9si705288iof.0.2024.03.19.03.33.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 03:33:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37wn5zqkbanwqwxi8jjcp8nngb.emmejcsqcpamlrclr.amk@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) client-ip=209.85.166.71;
Received: by mail-io1-f71.google.com with SMTP id ca18e2360f4ac-7cc74ea9c20so188307039f.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 03:33:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmq5g7oqD0/t6/gkwEr3EVBktQmxnGELmuGBmza66rqy1o35VD6wkoaRn0TmepFhrRAw9Po22poRaMeuaCUETT1DdqHovZgPl3+g==
MIME-Version: 1.0
X-Received: by 2002:a05:6602:641f:b0:7cc:4c0:65c5 with SMTP id
 gn31-20020a056602641f00b007cc04c065c5mr175800iob.1.1710844397224; Tue, 19 Mar
 2024 03:33:17 -0700 (PDT)
Date: Tue, 19 Mar 2024 03:33:17 -0700
In-Reply-To: <000000000000c0645805b7f982e4@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000901b1c0614010091@google.com>
Subject: Re: [syzbot] [batman?] [bpf?] possible deadlock in lock_timer_base
From: syzbot <syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com>
To: a@unstable.cc, akpm@linux-foundation.org, andrii@kernel.org, 
	ast@kernel.org, b.a.t.m.a.n@lists.open-mesh.org, bpf@vger.kernel.org, 
	christian@brauner.io, daniel@iogearbox.net, davem@davemloft.net, 
	dvyukov@google.com, edumazet@google.com, elver@google.com, glider@google.com, 
	hdanton@sina.com, jakub@cloudflare.com, jannh@google.com, 
	john.fastabend@gmail.com, kasan-dev@googlegroups.com, kuba@kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mareklindner@neomailbox.ch, 
	mark.rutland@arm.com, netdev@vger.kernel.org, pabeni@redhat.com, 
	shakeelb@google.com, sven@narfation.org, sw@simonwunderlich.de, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 37wn5zqkbanwqwxi8jjcp8nngb.emmejcsqcpamlrclr.amk@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.71 as permitted sender) smtp.mailfrom=37Wn5ZQkbANwQWXI8JJCP8NNGB.EMMEJCSQCPAMLRCLR.AMK@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    35c3e2791756 Revert "net: Re-use and set mono_delivery_tim..
git tree:       net
console output: https://syzkaller.appspot.com/x/log.txt?x=10569181180000
kernel config:  https://syzkaller.appspot.com/x/.config?x=6fb1be60a193d440
dashboard link: https://syzkaller.appspot.com/bug?extid=8983d6d4f7df556be565
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=13d9fa4e180000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=137afac9180000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/26b55a26fc12/disk-35c3e279.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/6f39fa55c828/vmlinux-35c3e279.xz
kernel image: https://storage.googleapis.com/syzbot-assets/e1e0501539e6/bzImage-35c3e279.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com

=====================================================
WARNING: HARDIRQ-safe -> HARDIRQ-unsafe lock order detected
6.8.0-syzkaller-05228-g35c3e2791756 #0 Not tainted
-----------------------------------------------------
rcu_preempt/16 [HC0[0]:SC0[2]:HE0:SE0] is trying to acquire:
ffff888021c65020 (&htab->buckets[i].lock){+...}-{2:2}, at: spin_lock_bh include/linux/spinlock.h:356 [inline]
ffff888021c65020 (&htab->buckets[i].lock){+...}-{2:2}, at: sock_hash_delete_elem+0xb0/0x300 net/core/sock_map.c:939

and this task is already holding:
ffff8880b952a758
 (&base->lock){-.-.}-{2:2}, at: lock_timer_base+0x112/0x240 kernel/time/timer.c:1051
which would create a new lock dependency:
 (&base->lock){-.-.}-{2:2} -> (
&htab->buckets[i].lock){+...}-{2:2}

but this new dependency connects a HARDIRQ-irq-safe lock:
 (&base->lock){-.-.}-{2:2}

... which became HARDIRQ-irq-safe at:
  lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
  __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
  _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162
  lock_timer_base+0x112/0x240 kernel/time/timer.c:1051
  add_timer_on+0x1e5/0x5c0 kernel/time/timer.c:1366
  handle_irq_event_percpu kernel/irq/handle.c:195 [inline]
  handle_irq_event+0xad/0x1f0 kernel/irq/handle.c:210
  handle_level_irq+0x3c5/0x6e0 kernel/irq/chip.c:648
  generic_handle_irq_desc include/linux/irqdesc.h:161 [inline]
  handle_irq arch/x86/kernel/irq.c:238 [inline]
  __common_interrupt+0x13a/0x230 arch/x86/kernel/irq.c:257
  common_interrupt+0xa5/0xd0 arch/x86/kernel/irq.c:247
  asm_common_interrupt+0x26/0x40 arch/x86/include/asm/idtentry.h:693
  __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:152 [inline]
  _raw_spin_unlock_irqrestore+0xd8/0x140 kernel/locking/spinlock.c:194
  __setup_irq+0x1277/0x1cf0 kernel/irq/manage.c:1818
  request_threaded_irq+0x2ab/0x380 kernel/irq/manage.c:2202
  request_irq include/linux/interrupt.h:168 [inline]
  setup_default_timer_irq+0x25/0x60 arch/x86/kernel/time.c:70
  x86_late_time_init+0x66/0xc0 arch/x86/kernel/time.c:94
  start_kernel+0x3f3/0x500 init/main.c:1039
  x86_64_start_reservations+0x2a/0x30 arch/x86/kernel/head64.c:509
  x86_64_start_kernel+0x99/0xa0 arch/x86/kernel/head64.c:490
  common_startup_64+0x13e/0x147

to a HARDIRQ-irq-unsafe lock:
 (&htab->buckets[i].lock){+...}-{2:2}

... which became HARDIRQ-irq-unsafe at:
...
  lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
  __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
  _raw_spin_lock_bh+0x35/0x50 kernel/locking/spinlock.c:178
  spin_lock_bh include/linux/spinlock.h:356 [inline]
  sock_hash_free+0x164/0x820 net/core/sock_map.c:1154
  bpf_map_free_deferred+0xe6/0x110 kernel/bpf/syscall.c:734
  process_one_work kernel/workqueue.c:3254 [inline]
  process_scheduled_works+0xa00/0x1770 kernel/workqueue.c:3335
  worker_thread+0x86d/0xd70 kernel/workqueue.c:3416
  kthread+0x2f0/0x390 kernel/kthread.c:388
  ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
  ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243

other info that might help us debug this:

 Possible interrupt unsafe locking scenario:

       CPU0                    CPU1
       ----                    ----
  lock(&htab->buckets[i].lock
);
                               local_irq_disable();
                               lock(&base->lock);
                               lock(&htab->buckets[i].lock
);
  <Interrupt>
    lock(&base->lock);

 *** DEADLOCK ***

2 locks held by rcu_preempt/16:
 #0: 
ffff8880b952a758
 (&base->lock){-.-.}-{2:2}, at: lock_timer_base+0x112/0x240 kernel/time/timer.c:1051
 #1: ffffffff8e131920
 (rcu_read_lock
){....}-{1:2}, at: rcu_lock_acquire include/linux/rcupdate.h:298 [inline]
){....}-{1:2}, at: rcu_read_lock include/linux/rcupdate.h:750 [inline]
){....}-{1:2}, at: __bpf_trace_run kernel/trace/bpf_trace.c:2380 [inline]
){....}-{1:2}, at: bpf_trace_run2+0x114/0x420 kernel/trace/bpf_trace.c:2420

the dependencies between HARDIRQ-irq-safe lock and the holding lock:
-> (&base->lock){-.-.}-{2:2} {
   IN-HARDIRQ-W at:
                    lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
                    __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
                    _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162
                    lock_timer_base+0x112/0x240 kernel/time/timer.c:1051
                    add_timer_on+0x1e5/0x5c0 kernel/time/timer.c:1366
                    handle_irq_event_percpu kernel/irq/handle.c:195 [inline]
                    handle_irq_event+0xad/0x1f0 kernel/irq/handle.c:210
                    handle_level_irq+0x3c5/0x6e0 kernel/irq/chip.c:648
                    generic_handle_irq_desc include/linux/irqdesc.h:161 [inline]
                    handle_irq arch/x86/kernel/irq.c:238 [inline]
                    __common_interrupt+0x13a/0x230 arch/x86/kernel/irq.c:257
                    common_interrupt+0xa5/0xd0 arch/x86/kernel/irq.c:247
                    asm_common_interrupt+0x26/0x40 arch/x86/include/asm/idtentry.h:693
                    __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:152 [inline]
                    _raw_spin_unlock_irqrestore+0xd8/0x140 kernel/locking/spinlock.c:194
                    __setup_irq+0x1277/0x1cf0 kernel/irq/manage.c:1818
                    request_threaded_irq+0x2ab/0x380 kernel/irq/manage.c:2202
                    request_irq include/linux/interrupt.h:168 [inline]
                    setup_default_timer_irq+0x25/0x60 arch/x86/kernel/time.c:70
                    x86_late_time_init+0x66/0xc0 arch/x86/kernel/time.c:94
                    start_kernel+0x3f3/0x500 init/main.c:1039
                    x86_64_start_reservations+0x2a/0x30 arch/x86/kernel/head64.c:509
                    x86_64_start_kernel+0x99/0xa0 arch/x86/kernel/head64.c:490
                    common_startup_64+0x13e/0x147
   IN-SOFTIRQ-W at:
                    lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
                    __raw_spin_lock_irq include/linux/spinlock_api_smp.h:119 [inline]
                    _raw_spin_lock_irq+0xd3/0x120 kernel/locking/spinlock.c:170
                    __run_timer_base+0x103/0x8e0 kernel/time/timer.c:2418
                    run_timer_base kernel/time/timer.c:2428 [inline]
                    run_timer_softirq+0x67/0x170 kernel/time/timer.c:2436
                    __do_softirq+0x2be/0x943 kernel/softirq.c:554
                    invoke_softirq kernel/softirq.c:428 [inline]
                    __irq_exit_rcu+0xf2/0x1c0 kernel/softirq.c:633
                    irq_exit_rcu+0x9/0x30 kernel/softirq.c:645
                    common_interrupt+0xaa/0xd0 arch/x86/kernel/irq.c:247
                    asm_common_interrupt+0x26/0x40 arch/x86/include/asm/idtentry.h:693
                    console_flush_all+0x9cd/0xec0
                    console_unlock+0x13b/0x4d0 kernel/printk/printk.c:3025
                    vprintk_emit+0x509/0x720 kernel/printk/printk.c:2292
                    _printk+0xd5/0x120 kernel/printk/printk.c:2317
                    cpu_select_mitigations+0x3c/0xa0 arch/x86/kernel/cpu/bugs.c:148
                    arch_cpu_finalize_init+0x20/0xa0 arch/x86/kernel/cpu/common.c:2325
                    start_kernel+0x402/0x500 init/main.c:1043
                    x86_64_start_reservations+0x2a/0x30 arch/x86/kernel/head64.c:509
                    x86_64_start_kernel+0x99/0xa0 arch/x86/kernel/head64.c:490
                    common_startup_64+0x13e/0x147
   INITIAL USE
 at:
                   lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
                   __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
                   _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162
                   lock_timer_base+0x112/0x240 kernel/time/timer.c:1051
                   __mod_timer+0x1ca/0xeb0 kernel/time/timer.c:1132
                   queue_delayed_work_on+0x15a/0x260 kernel/workqueue.c:2595
                   queue_delayed_work include/linux/workqueue.h:620 [inline]
                   crng_reseed+0xe7/0x220 drivers/char/random.c:258
                   random_init+0x1a9/0x300 drivers/char/random.c:901
                   start_kernel+0x253/0x500 init/main.c:991
                   x86_64_start_reservations+0x2a/0x30 arch/x86/kernel/head64.c:509
                   x86_64_start_kernel+0x99/0xa0 arch/x86/kernel/head64.c:490
                   common_startup_64+0x13e/0x147
 }
 ... key      at: [<ffffffff945023c0>] init_timer_cpu.__key+0x0/0x20

the dependencies between the lock to be acquired
 and HARDIRQ-irq-unsafe lock:
->
 (&htab->buckets[i].lock
){+...}-{2:2} {
   HARDIRQ-ON-W at:
                    lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
                    __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
                    _raw_spin_lock_bh+0x35/0x50 kernel/locking/spinlock.c:178
                    spin_lock_bh include/linux/spinlock.h:356 [inline]
                    sock_hash_free+0x164/0x820 net/core/sock_map.c:1154
                    bpf_map_free_deferred+0xe6/0x110 kernel/bpf/syscall.c:734
                    process_one_work kernel/workqueue.c:3254 [inline]
                    process_scheduled_works+0xa00/0x1770 kernel/workqueue.c:3335
                    worker_thread+0x86d/0xd70 kernel/workqueue.c:3416
                    kthread+0x2f0/0x390 kernel/kthread.c:388
                    ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
                    ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243
   INITIAL USE
 at:
                   lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
                   __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
                   _raw_spin_lock_bh+0x35/0x50 kernel/locking/spinlock.c:178
                   spin_lock_bh include/linux/spinlock.h:356 [inline]
                   sock_hash_free+0x164/0x820 net/core/sock_map.c:1154
                   bpf_map_free_deferred+0xe6/0x110 kernel/bpf/syscall.c:734
                   process_one_work kernel/workqueue.c:3254 [inline]
                   process_scheduled_works+0xa00/0x1770 kernel/workqueue.c:3335
                   worker_thread+0x86d/0xd70 kernel/workqueue.c:3416
                   kthread+0x2f0/0x390 kernel/kthread.c:388
                   ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
                   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243
 }
 ... key      at: [<ffffffff94882300>] sock_hash_alloc.__key+0x0/0x20
 ... acquired at:
   lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
   __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
   _raw_spin_lock_bh+0x35/0x50 kernel/locking/spinlock.c:178
   spin_lock_bh include/linux/spinlock.h:356 [inline]
   sock_hash_delete_elem+0xb0/0x300 net/core/sock_map.c:939
   bpf_prog_2c29ac5cdc6b1842+0x42/0x46
   bpf_dispatcher_nop_func include/linux/bpf.h:1234 [inline]
   __bpf_prog_run include/linux/filter.h:657 [inline]
   bpf_prog_run include/linux/filter.h:664 [inline]
   __bpf_trace_run kernel/trace/bpf_trace.c:2381 [inline]
   bpf_trace_run2+0x204/0x420 kernel/trace/bpf_trace.c:2420
   trace_timer_start include/trace/events/timer.h:52 [inline]
   enqueue_timer+0x396/0x550 kernel/time/timer.c:663
   internal_add_timer kernel/time/timer.c:688 [inline]
   __mod_timer+0xa0e/0xeb0 kernel/time/timer.c:1183
   schedule_timeout+0x1b9/0x310 kernel/time/timer.c:2571
   rcu_gp_fqs_loop+0x2df/0x1370 kernel/rcu/tree.c:1663
   rcu_gp_kthread+0xa7/0x3b0 kernel/rcu/tree.c:1862
   kthread+0x2f0/0x390 kernel/kthread.c:388
   ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243


stack backtrace:
CPU: 1 PID: 16 Comm: rcu_preempt Not tainted 6.8.0-syzkaller-05228-g35c3e2791756 #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x1e7/0x2e0 lib/dump_stack.c:106
 print_bad_irq_dependency kernel/locking/lockdep.c:2626 [inline]
 check_irq_usage kernel/locking/lockdep.c:2865 [inline]
 check_prev_add kernel/locking/lockdep.c:3138 [inline]
 check_prevs_add kernel/locking/lockdep.c:3253 [inline]
 validate_chain+0x4dc7/0x58e0 kernel/locking/lockdep.c:3869
 __lock_acquire+0x1346/0x1fd0 kernel/locking/lockdep.c:5137
 lock_acquire+0x1e4/0x530 kernel/locking/lockdep.c:5754
 __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
 _raw_spin_lock_bh+0x35/0x50 kernel/locking/spinlock.c:178
 spin_lock_bh include/linux/spinlock.h:356 [inline]
 sock_hash_delete_elem+0xb0/0x300 net/core/sock_map.c:939
 bpf_prog_2c29ac5cdc6b1842+0x42/0x46
 bpf_dispatcher_nop_func include/linux/bpf.h:1234 [inline]
 __bpf_prog_run include/linux/filter.h:657 [inline]
 bpf_prog_run include/linux/filter.h:664 [inline]
 __bpf_trace_run kernel/trace/bpf_trace.c:2381 [inline]
 bpf_trace_run2+0x204/0x420 kernel/trace/bpf_trace.c:2420
 trace_timer_start include/trace/events/timer.h:52 [inline]
 enqueue_timer+0x396/0x550 kernel/time/timer.c:663
 internal_add_timer kernel/time/timer.c:688 [inline]
 __mod_timer+0xa0e/0xeb0 kernel/time/timer.c:1183
 schedule_timeout+0x1b9/0x310 kernel/time/timer.c:2571
 rcu_gp_fqs_loop+0x2df/0x1370 kernel/rcu/tree.c:1663
 rcu_gp_kthread+0xa7/0x3b0 kernel/rcu/tree.c:1862
 kthread+0x2f0/0x390 kernel/kthread.c:388
 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243
 </TASK>


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000901b1c0614010091%40google.com.

Return-Path: <kasan-dev+bncBCQPF57GUQHBBNHT5SYAMGQEWPJ6OVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C42858A3FE1
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Apr 2024 04:04:38 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36b098c3875sf20118145ab.1
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Apr 2024 19:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713060277; cv=pass;
        d=google.com; s=arc-20160816;
        b=daz19N0nIqM0cEP8GGJ+I3doTPqvNFf7yxEhJq7jTXayuzeX9umHoGE8Bdsyrq3RE2
         li9lEx4yz5FMY/phlPrXZ+HhXZdaJIslAoIFOvrJMdu2ZDyWK/ETHCBNKabieIIryLhX
         OZbJZXUARjXPlZBMzwDDaVXh2Vef03hXSsyttZ1WLmXIW/+nzTnkUWOGq5UXwWQSLOsZ
         jOufA9mtiqF9QbySTNCK2KICzbx7IAP7ALOYfbduWEeJW01LkLdWyVkg30CqgaPYvf48
         9PbFSkD0IHERoEZaZFiASGcNSDOOX0okLplH6OTXKuBOevNovPFWDdHqmiW6NoFYd8YN
         ubTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=UHc395aKAysvgYTHc1gpzRTUGOOMaZy/awqU+QtffPg=;
        fh=o/bDKjk7fshqypXC80OB5W8UDlQxyNc90Kh0uVHjkJg=;
        b=vh6mdqFEx8MQ2Q6sFEGsXiM6gjGAhhrVge3yWVw7hmoLVHfRAUVYG6/MUmGQ4Z9AYJ
         GVfjrn8voh+O2urSgrJ9xHcPhbZ10rmCeO6S4XXPso6gTPkcMMk4AALLWr9yX1lt7rUJ
         scyX7WHdUy6U11LwedpI4IE6h9aY7oEQqHT7RQq7ZHAVKIu6d0imx8WaWmyvrc80eYgJ
         aoz/FTqeSeo5sObHaTweiCq+pVQw17++UXMLlAF7yaAoLnZVO581KPZRcWQLZ9rrIVpy
         /9B7NykRILftl7bSDxjuNNV1q7WLYAgeC3QbXvX8kg0ylixKF8Kj4gIjquvRXefIZCW+
         lwCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3sjkbzgkbamk7dezp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3sjkbZgkbAMk7DEzp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713060277; x=1713665077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UHc395aKAysvgYTHc1gpzRTUGOOMaZy/awqU+QtffPg=;
        b=YyrPJqix3ppjXWysMaR6hpis8JI5fQH2kWw7FEsusmWkh4aR1NL9/bNQxy+24m3tF0
         kybomu3RVq0vV2YGW+8k7o0PLoucvT4t0UEhxDHcAptXMxYRF2Eilh/O/bF2ow3OOz0m
         u8kH396hPWwvxokNlGHjuH62X57UyRdAydFDrXW2Pn6sw0DazjyujfA7qdETiiSXiiP2
         Og9nrT73SoizGX9Her5gHyeUTmf06CJcMUETPRV/HdxLyzleVzay+R4O3OmGtUMdbkXO
         4yaabgv1yETADzz3krQOhYthwCXQYYp5OyzTi+KnlYaP5TlaA0a8EVNpszCNXfc+sAy0
         Pjbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713060277; x=1713665077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UHc395aKAysvgYTHc1gpzRTUGOOMaZy/awqU+QtffPg=;
        b=F9gmwCfHQtBErBwO59V6mFdoHTXjqP5PzIYyE9ruQdZBSoPG6anSF6JhfKR2tMIMvh
         Vn1V8CaWSFIc2KryqC6BQ2Bbd52ncBB2gv9eaMZF9X7a7MVOLOqeT/X8p6/y5fZlw4PU
         pphVKfu0AomryNRrtf2YZaqed4bMxJ7TYTN/4lUCb9spUCV9IjdECRiDLZTbYoz9fyaW
         FKUYpSj7NUj1znfyYqGJerDe4S5U0eCkFOv9XFjv4max8Io9+ZaK+RsfzMasxJJO92w4
         jlQYYlKxmk+FM2g0OAwxVlMB8VTRrwToawdj5QRppMeTDsL5oWH6QZaitrwDpLqolOLO
         Z+1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+kG/hPOAVXjILsisM9mmhEjDt8rKqAQjt11dUx2N+w8wVB5NXRHIwokaSCKBnZ8fYoBJnvDlhkfhHRAfeaAVeKbwzuRLa/g==
X-Gm-Message-State: AOJu0YwMREcNcqCx+4ChfCrilhd4MASpR7/DH088YZnPIZZgN6Uy7YJ1
	gIgGiu4whMroRzcvQu4puQbY9NHO6Mq/gnodxwX1UZApVz0CoXQZ
X-Google-Smtp-Source: AGHT+IGtxLmKd3Q8QiAE5S365e2TbfLDb4QL3eVRfWbTEeegodFFT+tXpLcrqzaV1riyIeQtN7hH6A==
X-Received: by 2002:a05:6e02:1546:b0:36a:f9e8:5e4a with SMTP id j6-20020a056e02154600b0036af9e85e4amr9324902ilu.15.1713060277086;
        Sat, 13 Apr 2024 19:04:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10cf:b0:368:7cd7:c115 with SMTP id
 s15-20020a056e0210cf00b003687cd7c115ls1432773ilj.1.-pod-prod-07-us; Sat, 13
 Apr 2024 19:04:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxypHScExn7BtLypASGAtoM4s5sjzQhBF1R2h1RYRbpsts4ri9fw+WcQHJwgDn1sLPDUE1ElEIwCgJ7Hf+4IZSuosQc7eq2PxfRQ==
X-Received: by 2002:a05:6e02:3887:b0:36b:184b:97c2 with SMTP id cn7-20020a056e02388700b0036b184b97c2mr1826365ilb.2.1713060274661;
        Sat, 13 Apr 2024 19:04:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713060274; cv=none;
        d=google.com; s=arc-20160816;
        b=tLIjgXQMmYQX+OQDw0/JXzvnPkw63w8Ch4ObqdowzD/aQmjCYChCerpStUiDCSeUMD
         eJXLeJUp/Tbrna6g6wBNscVzgu99zuVrF5/f2Y7P/nTN3Q4V52yzWj8nVqTW858QPMPV
         jVBEe+t/jtBOCVQaTwCjhqGSW2sIc7oUn+LTcjDREAoR/1jONJqYhIrDmpri3o4SqSqx
         SWzm4TlP7EzEXNgnx3JEws+4gqp1XCCbla2fPLoeLX1GNmtfOs8X+vZcOW+G6OBtQ0Go
         bi7NvpqYhC2JJ0WuSEt6zY15i2iuJo87vSswL+zi1WtI4WhDXquSXqkN9ScVQJHHVPhj
         NDqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=MCFSM1aTc7Bv7FQ0N3Tjzux7zsi15j98rP+EcecD/hk=;
        fh=DBCis6JQ1yCeEIXB23c8ukBMev9QfE0xL5i1FLEK7VA=;
        b=Ns9igEKa4O/7VnNht7Wz9KxO1Dyke/d0j12/FNHiPw1FeY0hGwTqiRR09YU2swgrPb
         HA/GSJ5FEaFU8+V7UhDvfyk2jXNI9Jv7DqVG1nSTBTIf9D3it/XlYUB5qlpgDqSr583L
         1ShH6xVh5QQcpCsmZd3bm1DkY0EDpw+JhViowAyLiJ4zEeJPUTmM0X9PLOtiGcbsCFT5
         sB9u0V5fJ/qIbN/1nJ348XVuh+Zj5kJyhn5w9x00TsXtMtXZEMArQEEROTIOZj87ivMK
         UZAnkySKCMvXmeTxW2AOcDEgXuGPpbN5hW4UEEKbKur6Kuj6E03PVG9CKsRi06gHQR0j
         g75g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3sjkbzgkbamk7dezp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3sjkbZgkbAMk7DEzp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f198.google.com (mail-il1-f198.google.com. [209.85.166.198])
        by gmr-mx.google.com with ESMTPS id u4-20020a92d1c4000000b00369eb657041si461490ilg.5.2024.04.13.19.04.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Apr 2024 19:04:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sjkbzgkbamk7dezp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) client-ip=209.85.166.198;
Received: by mail-il1-f198.google.com with SMTP id e9e14a558f8ab-36b16d8e3a8so2617535ab.0
        for <kasan-dev@googlegroups.com>; Sat, 13 Apr 2024 19:04:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWASOEuh0O+tVcnGSxggls2NtdOVmVOwv/qHyMV9AfUbruh+eNxUA3XvTEdAis+th2CqGg94qcy9iM1Ea0Zi8VPjUCBseuuT2I1bw==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:2199:b0:369:b997:7342 with SMTP id
 j25-20020a056e02219900b00369b9977342mr419685ila.3.1713060274409; Sat, 13 Apr
 2024 19:04:34 -0700 (PDT)
Date: Sat, 13 Apr 2024 19:04:34 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <00000000000022a23c061604edb3@google.com>
Subject: [syzbot] [kasan?] [mm?] INFO: rcu detected stall in __run_timer_base
From: syzbot <syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, keescook@chromium.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3sjkbzgkbamk7dezp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.198 as permitted sender) smtp.mailfrom=3sjkbZgkbAMk7DEzp00t6p44xs.v33v0t97t6r328t28.r31@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    fe46a7dd189e Merge tag 'sound-6.9-rc1' of git://git.kernel..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=15c64113180000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fe78468a74fdc3b7
dashboard link: https://syzkaller.appspot.com/bug?extid=1acbadd9f48eeeacda29
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16435913180000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=111600cb180000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/0f7abe4afac7/disk-fe46a7dd.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/82598d09246c/vmlinux-fe46a7dd.xz
kernel image: https://storage.googleapis.com/syzbot-assets/efa23788c875/bzImage-fe46a7dd.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com

rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu: 	0-...!: (1 GPs behind) idle=d3cc/1/0x4000000000000000 softirq=6440/6443 fqs=2
rcu: 	(detected by 1, t=10506 jiffies, g=7245, q=210 ncpus=2)
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 PID: 5367 Comm: syz-executor780 Not tainted 6.8.0-syzkaller-08951-gfe46a7dd189e #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024
RIP: 0010:lockdep_recursion_finish kernel/locking/lockdep.c:467 [inline]
RIP: 0010:lock_release+0x5c0/0x9d0 kernel/locking/lockdep.c:5776
Code: 00 fc ff df 4c 8b 64 24 08 48 8b 5c 24 28 49 89 dd 4c 8d b4 24 90 00 00 00 48 c7 c7 60 d3 aa 8b e8 d5 9c 02 0a b8 ff ff ff ff <65> 0f c1 05 28 c5 90 7e 83 f8 01 0f 85 9a 00 00 00 4c 89 f3 48 c1
RSP: 0000:ffffc90000007720 EFLAGS: 00000082
RAX: 00000000ffffffff RBX: 0000000000000046 RCX: ffffc90000007703
RDX: 0000000000000001 RSI: ffffffff8baad360 RDI: ffffffff8bfed300
RBP: ffffc90000007860 R08: ffffffff8f873a6f R09: 1ffffffff1f0e74d
R10: dffffc0000000000 R11: fffffbfff1f0e74e R12: 1ffff92000000ef0
R13: 0000000000000046 R14: ffffc900000077b0 R15: dffffc0000000000
FS:  0000555594caf380(0000) GS:ffff8880b9400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020000600 CR3: 0000000023676000 CR4: 0000000000350ef0
Call Trace:
 <NMI>
 </NMI>
 <IRQ>
 rcu_lock_release include/linux/rcupdate.h:308 [inline]
 rcu_read_unlock include/linux/rcupdate.h:783 [inline]
 advance_sched+0xb37/0xca0 net/sched/sch_taprio.c:987
 __run_hrtimer kernel/time/hrtimer.c:1692 [inline]
 __hrtimer_run_queues+0x597/0xd00 kernel/time/hrtimer.c:1756
 hrtimer_interrupt+0x396/0x990 kernel/time/hrtimer.c:1818
 local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1032 [inline]
 __sysvec_apic_timer_interrupt+0x109/0x3a0 arch/x86/kernel/apic/apic.c:1049
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1043 [inline]
 sysvec_apic_timer_interrupt+0x52/0xc0 arch/x86/kernel/apic/apic.c:1043
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
RIP: 0010:__raw_spin_unlock_irq include/linux/spinlock_api_smp.h:160 [inline]
RIP: 0010:_raw_spin_unlock_irq+0x29/0x50 kernel/locking/spinlock.c:202
Code: 90 f3 0f 1e fa 53 48 89 fb 48 83 c7 18 48 8b 74 24 08 e8 0a b4 f2 f5 48 89 df e8 c2 f3 f3 f5 e8 1d 19 1d f6 fb bf 01 00 00 00 <e8> 52 e0 e5 f5 65 8b 05 a3 c4 84 74 85 c0 74 06 5b e9 71 40 00 00
RSP: 0000:ffffc90000007cb0 EFLAGS: 00000282
RAX: 49e89c1a0716e600 RBX: ffff8880b942a740 RCX: ffffffff81720c2a
RDX: dffffc0000000000 RSI: ffffffff8baac1e0 RDI: 0000000000000001
RBP: ffffc90000007e10 R08: ffffffff92ce5537 R09: 1ffffffff259caa6
R10: dffffc0000000000 R11: fffffbfff259caa7 R12: ffff8880b942a788
R13: ffffc90000007d60 R14: dffffc0000000000 R15: 00000000ffffdaa5
 __run_timer_base+0x1c0/0x8e0 kernel/time/timer.c:2420
 run_timer_base kernel/time/timer.c:2428 [inline]
 run_timer_softirq+0xb7/0x170 kernel/time/timer.c:2438
 __do_softirq+0x2be/0x943 kernel/softirq.c:554
 invoke_softirq kernel/softirq.c:428 [inline]
 __irq_exit_rcu+0xf2/0x1c0 kernel/softirq.c:633
 irq_exit_rcu+0x9/0x30 kernel/softirq.c:645
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1043 [inline]
 sysvec_apic_timer_interrupt+0xa6/0xc0 arch/x86/kernel/apic/apic.c:1043
 </IRQ>
 <TASK>
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
RIP: 0010:srso_safe_ret+0x0/0x20 arch/x86/lib/retpoline.S:208
Code: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 48 b8 <48> 8d 64 24 08 c3 cc cc 0f ae e8 e8 f0 ff ff ff 0f 0b 66 2e 0f 1f
RSP: 0000:ffffc90004907030 EFLAGS: 00000293
RAX: ffffffff814095ec RBX: 0000000000000000 RCX: ffff888028fe0000
RDX: 0000000000000000 RSI: ffffffff8140c1eb RDI: ffffffff8140c035
RBP: 1ffff92000920e30 R08: ffffffff81409480 R09: 0000000000000000
R10: ffffc90004907180 R11: fffff52000920e3c R12: ffffffff8f9755b0
R13: dffffc0000000000 R14: 1ffff92000920e30 R15: ffffffff9008ea3e
 srso_return_thunk+0x5/0x5f arch/x86/lib/retpoline.S:222
 unwind_next_frame+0x67c/0x2a00 arch/x86/kernel/unwind_orc.c:495
 __unwind_start+0x641/0x7c0 arch/x86/kernel/unwind_orc.c:760
 unwind_start arch/x86/include/asm/unwind.h:64 [inline]
 arch_stack_walk+0x103/0x1b0 arch/x86/kernel/stacktrace.c:24
 stack_trace_save+0x118/0x1d0 kernel/stacktrace.c:122
 save_stack+0xfb/0x1f0 mm/page_owner.c:129
 __set_page_owner+0x29/0x380 mm/page_owner.c:195
 set_page_owner include/linux/page_owner.h:31 [inline]
 post_alloc_hook+0x1ea/0x210 mm/page_alloc.c:1533
 prep_new_page mm/page_alloc.c:1540 [inline]
 get_page_from_freelist+0x33ea/0x3580 mm/page_alloc.c:3311
 __alloc_pages+0x256/0x680 mm/page_alloc.c:4569
 alloc_pages_mpol+0x3de/0x650 mm/mempolicy.c:2133
 pagetable_alloc include/linux/mm.h:2842 [inline]
 __pud_alloc_one include/asm-generic/pgalloc.h:169 [inline]
 pud_alloc_one include/asm-generic/pgalloc.h:189 [inline]
 __pud_alloc+0x93/0x4b0 mm/memory.c:5692
 pud_alloc include/linux/mm.h:2799 [inline]
 __handle_mm_fault+0x4472/0x72d0 mm/memory.c:5236
 handle_mm_fault+0x3c2/0x8a0 mm/memory.c:5470
 do_user_addr_fault arch/x86/mm/fault.c:1413 [inline]
 handle_page_fault arch/x86/mm/fault.c:1505 [inline]
 exc_page_fault+0x2a8/0x890 arch/x86/mm/fault.c:1563
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0033:0x7f37687f9bcc
Code: 00 00 e8 67 52 03 00 48 83 f8 ff 74 07 48 89 05 3a 15 0b 00 31 d2 b9 00 06 00 20 bf 10 00 00 00 48 b8 74 65 61 6d 30 00 00 00 <48> 89 04 25 00 06 00 20 31 c0 48 89 14 25 08 06 00 20 48 8b 35 0b
RSP: 002b:00007ffc3f74a370 EFLAGS: 00010246
RAX: 000000306d616574 RBX: 0000000000000000 RCX: 0000000020000600
RDX: 0000000000000000 RSI: 0000000800000003 RDI: 0000000000000010
RBP: 00000000000f4240 R08: 0000000000000000 R09: 0000000100000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffc3f74a3c0
R13: 000000000003239a R14: 00007ffc3f74a38c R15: 0000000000000003
 </TASK>
INFO: NMI handler (nmi_cpu_backtrace_handler) took too long to run: 4.146 msecs
rcu: rcu_preempt kthread starved for 10495 jiffies! g7245 f0x0 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=1
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:26256 pid:16    tgid:16    ppid:2      flags:0x00004000
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5409 [inline]
 __schedule+0x17d3/0x4a20 kernel/sched/core.c:6736
 __schedule_loop kernel/sched/core.c:6813 [inline]
 schedule+0x14b/0x320 kernel/sched/core.c:6828
 schedule_timeout+0x1be/0x310 kernel/time/timer.c:2572
 rcu_gp_fqs_loop+0x2df/0x1370 kernel/rcu/tree.c:1663
 rcu_gp_kthread+0xa7/0x3b0 kernel/rcu/tree.c:1862
 kthread+0x2f2/0x390 kernel/kthread.c:388
 ret_from_fork+0x4d/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243
 </TASK>
rcu: Stack dump where RCU GP kthread last ran:
CPU: 1 PID: 61 Comm: kworker/u8:4 Not tainted 6.8.0-syzkaller-08951-gfe46a7dd189e #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024
Workqueue: events_unbound toggle_allocation_gate
RIP: 0010:csd_lock_wait kernel/smp.c:311 [inline]
RIP: 0010:smp_call_function_many_cond+0x1855/0x2960 kernel/smp.c:855
Code: 89 e6 83 e6 01 31 ff e8 d9 d5 0b 00 41 83 e4 01 49 bc 00 00 00 00 00 fc ff df 75 07 e8 84 d1 0b 00 eb 38 f3 90 42 0f b6 04 23 <84> c0 75 11 41 f7 45 00 01 00 00 00 74 1e e8 68 d1 0b 00 eb e4 44
RSP: 0018:ffffc900015c76e0 EFLAGS: 00000293
RAX: 0000000000000000 RBX: 1ffff11017288c0d RCX: ffff88801aadbc00
RDX: 0000000000000000 RSI: 0000000000000001 RDI: 0000000000000000
RBP: ffffc900015c78e0 R08: ffffffff818923b7 R09: 1ffffffff259caa0
R10: dffffc0000000000 R11: fffffbfff259caa1 R12: dffffc0000000000
R13: ffff8880b9446068 R14: ffff8880b953f480 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000555594cafca8 CR3: 000000000df32000 CR4: 0000000000350ef0
Call Trace:
 <IRQ>
 </IRQ>
 <TASK>
 on_each_cpu_cond_mask+0x3f/0x80 kernel/smp.c:1023
 on_each_cpu include/linux/smp.h:71 [inline]
 text_poke_sync arch/x86/kernel/alternative.c:2086 [inline]
 text_poke_bp_batch+0x352/0xb30 arch/x86/kernel/alternative.c:2296
 text_poke_flush arch/x86/kernel/alternative.c:2487 [inline]
 text_poke_finish+0x30/0x50 arch/x86/kernel/alternative.c:2494
 arch_jump_label_transform_apply+0x1c/0x30 arch/x86/kernel/jump_label.c:146
 static_key_enable_cpuslocked+0x136/0x260 kernel/jump_label.c:205
 static_key_enable+0x1a/0x20 kernel/jump_label.c:218
 toggle_allocation_gate+0xb5/0x250 mm/kfence/core.c:826
 process_one_work kernel/workqueue.c:3254 [inline]
 process_scheduled_works+0xa02/0x1770 kernel/workqueue.c:3335
 worker_thread+0x86d/0xd70 kernel/workqueue.c:3416
 kthread+0x2f2/0x390 kernel/kthread.c:388
 ret_from_fork+0x4d/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:243
 </TASK>


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000022a23c061604edb3%40google.com.

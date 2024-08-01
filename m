Return-Path: <kasan-dev+bncBCQPF57GUQHBBLNZWC2QMGQEB4LVHFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A8C9454F5
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 01:39:26 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e0872023b7dsf11704734276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2024 16:39:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722555565; cv=pass;
        d=google.com; s=arc-20160816;
        b=v24aAUR9agm1grwM+I3QEay/hoHoQsNIhxVvBNaskX+fQB4LAx/ggutVXLbrJnJku2
         OjMNDko1dZs97wJtZWLEFSzF9Zga6Xuyb9jDrEcRt67pYPxPBIQDnnkVR5USNlHWIW97
         CuzKYoZwpnmt+CAo570OSU7QbAcGm6cuFbWXX8P4i0rC2O4cYswguwLEC7aOK3fZjrlJ
         H89lAk8r+3ruWv4tSFUt+rWm+qHjJK/zcZUktvqXazEmLIowi+aFqY5KI5j/59u013YW
         uInfWo3GM98T/Or0iQvzOrv6O9TAe0paxXTkjry7rAtUDmYjI0mbaI92C3CIsfDT2Zqs
         FEDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=Wc818b4uTJq/3xwUoJCUGtIJDqTFUC8Bx80gC13E0hA=;
        fh=z2YYoqJRbEqWRma9a8fUtpSqlNhrkhELVVBE2MNeRhs=;
        b=xfwjZJn+OAbuS5zBgM2mk9U7O4LR31VOCxFdjSz5TmmMgRSofyHAUaLJVwj+Q/tUJZ
         YGZFQ7LiCr62Tvw49eQ3h2EQ9sh1j480ijvnfTuXIfSvNAa40/f9MONT9ZjNDLEEEjOf
         ZNzx1tmKTRhw781r3+vN/7L7bZsfZXi9wu4Ma2vBwnfBLEyeycUPX7C7hZLELDJA3yoQ
         4dgN+e8gdiPgAnyZEoTQ1byPZ62QOkjhrb/E2m2jp5No0l1eYoPDwdcDMCTs14FAWM5n
         tF+n+BHOVZ5bt+AZiQu9Q7bVIaEef97Vh5CN9n2XrTeoPiwHqiOB4qoO5Du4yQYl3wwu
         nLZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rbyszgkbaneflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3rBysZgkbANEFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722555565; x=1723160365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Wc818b4uTJq/3xwUoJCUGtIJDqTFUC8Bx80gC13E0hA=;
        b=VsVniDVjC0rRmtJdDE+7lYFyNkPsyN9ZBnwfYoq0MHn0RXHXn5vmfQ4xKQgIC2INAx
         Rk7yOZLPirNJar7w5LdbxM/V5PieWgpHRrR2HYBBJDE0HVcOIT16Yt5gH7wGsHbVGHQm
         9NfEoKoNqEWgwgEg/v3XVGkqs2UUTQKhRbSIYZS7qXEJQlOou8nou7AvXN33diypZWRl
         iPwSpyxNT42q0dgC7hDCoVPCoB9j+3zA/h5R2LayrnMqYaa8xLwqPNJSw1k7v6TQ7r7a
         nEHPoMntyVsAsIOZEx+vVjW2mK9JDIY7XHmiZFCXhW4iDvCQkcNGw/hjcCbIERoQ6lGs
         /FFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722555565; x=1723160365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wc818b4uTJq/3xwUoJCUGtIJDqTFUC8Bx80gC13E0hA=;
        b=ZW6yZqN725W6//0/paR6TZ1Fqy5EqS/GVod33WlBxixKddFzICiLM3CZmMlNLBsz51
         AYHeAWdl0FTXJOjQ9uROvo3Nb9RQjYHctvwEOjiBqtplw5gdtLu3QK2J8YS9SUfSYYMn
         isy8ImcmbdBLwKJSebop8bIOmLaU9GNlmwghikNnKXYAwJSKOP/27dEEYV9ReO573oQh
         FjByGeufMOYcnwAvbRua+8jKgGl71XIyz1FY9o54MFbbzHSFNEoZVaJGU9fXsaILP+In
         9hSiDTXEpI/PMVePStW1yxXiU5ElDhUoCvBBJ+dQvDf0m4VX6FsTQa8i4UnQfq+nATji
         cu7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXar9PvsZpvI4UqqPjW4Kymj9+dAoVYLCfJjXhMFkAYTEYof1g3/4EjvCizIhFJSa/u022XVs4R8EU7vmLPY5qM3UIL0yTo2g==
X-Gm-Message-State: AOJu0Yy9esZVPQfqrpqgEpRw2ArzD5WrJFYpF9E7iXDP15Q7R4AXy615
	3gmp2p9TMo1+I1mtfGWo6vPpc2mrscqpo2saBTADQbm6iOAWIXbe
X-Google-Smtp-Source: AGHT+IE4ccvDsgMbgHNb2rfBpXmM4xxWY1lyJutCrIxo3Pbr2F37l26BV2vpEa/kwoCF/8MQOIewRw==
X-Received: by 2002:a25:df10:0:b0:e0b:3725:f091 with SMTP id 3f1490d57ef6-e0bde38af90mr2071395276.20.1722555565424;
        Thu, 01 Aug 2024 16:39:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9a85:0:b0:e0b:e5b2:98ba with SMTP id 3f1490d57ef6-e0be5b29d90ls190774276.0.-pod-prod-04-us;
 Thu, 01 Aug 2024 16:39:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1sARWKN12E0Tu3yQ+ii06TKIUEEmUqlVKYuCste0DxUV6eCBwRfzIX8BDnSs4nSFi5dWSW3eahOvRIPE/ldjp+rbBtKl3nN2wAg==
X-Received: by 2002:a05:6902:120d:b0:e0b:29c1:21af with SMTP id 3f1490d57ef6-e0bde2f0114mr2008337276.4.1722555564536;
        Thu, 01 Aug 2024 16:39:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722555564; cv=none;
        d=google.com; s=arc-20160816;
        b=bnBJfk5OocYBXoxgV+lAYyMAf11SVHfL2lGBk8PWSKtk9pyxPAUPFiJdfnGkqivZlr
         OicySB1R44et35ZWYGeQybIGN4vcdjkTdB9/6sU75+B6PPxbwV1Ijq+uHQFXV0pGd5Fj
         BpYJvGSvtYbZ8XPFDES/+O/YcHc3r76b7dSu7Pb2ZUswkeUvYvHLLO2G3UX7zvK1Va7/
         Jh54YaBlrjA5lv2Qu4ERBc/FmXDxhSLNgmIjJ5loh8u7wy/DWce27dgTM5ge1A5PEr1+
         ++tnmbR2qonbnx6b0IqhxKp6d5d3Ln3LSuhWG21tfWnUo9fjouf3w65s3Sa6YIHEVPJU
         FTaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=GsTIWpJR0+r62QX7gypMcATU+M6juxm2SQQS95KAVjs=;
        fh=n1mPC4R039cwhRMQxyUu9otPdNQXOOoxJLTVTNrf6ZE=;
        b=XdWhozVH5Tx+nYPAEzIvf+tA6UGSjgpMOKYFYrHYF8dLMZRdmt6rZjSM3L0yQhhyyh
         wyGsyE7R9Tnexd4HEJnWmKhze/sWzKJHk/n/EZeR1BZuP4HdyvnCQFsQAyCdlFizXL8G
         lMPgUBrIPRnxRqUPNxU7dvqBs8Jul9giElb8hxHAyPUpctiuZQEKaA0CH1umoo4xBq1E
         oov85bQD7dNd4ufIpj9zLfhELCrnAoe7DWr5xgfVF8u61nV9zZRiMeBHtjH6p7AVjOv5
         sukTXY3E7EDriQclzV7E7uHWBr9zBeSZ/VfjL7bZsrOXcPjQSX7+sh9mifcwTNQYtEar
         pO8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rbyszgkbaneflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3rBysZgkbANEFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f197.google.com (mail-il1-f197.google.com. [209.85.166.197])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e0be55bb03fsi15451276.4.2024.08.01.16.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Aug 2024 16:39:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbyszgkbaneflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) client-ip=209.85.166.197;
Received: by mail-il1-f197.google.com with SMTP id e9e14a558f8ab-3983ed13f0bso110423065ab.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Aug 2024 16:39:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1YzY6s8jHYIEytugF87UMH/BI40k1n1erLPVCmNEXouUed6eLJ3SxTZPQofwOxOEyO9a5t4n7wSE3tCY3Ov6sMmA1tBQDjgvTWQ==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1d0b:b0:396:ec3b:df65 with SMTP id
 e9e14a558f8ab-39b1fc356damr1137845ab.4.1722555564014; Thu, 01 Aug 2024
 16:39:24 -0700 (PDT)
Date: Thu, 01 Aug 2024 16:39:23 -0700
In-Reply-To: <000000000000a8c856061ae85e20@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000007fca5d061ea7b850@google.com>
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs (2)
From: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>
To: andreyknvl@gmail.com, bp@alien8.de, dave.hansen@linux.intel.com, 
	dvyukov@google.com, elver@google.com, glider@google.com, hpa@zytor.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mingo@redhat.com, penguin-kernel@i-love.sakura.ne.jp, 
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3rbyszgkbaneflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.197 as permitted sender) smtp.mailfrom=3rBysZgkbANEFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    931a3b3bccc9 Add linux-next specific files for 20240729
git tree:       linux-next
console output: https://syzkaller.appspot.com/x/log.txt?x=10f2388d980000
kernel config:  https://syzkaller.appspot.com/x/.config?x=91dc4a647da4c251
dashboard link: https://syzkaller.appspot.com/bug?extid=e9be5674af5e3a0b9ecc
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16efaf11980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=10f437f1980000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/6b83209c369b/disk-931a3b3b.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/a5b0c2d893d4/vmlinux-931a3b3b.xz
kernel image: https://storage.googleapis.com/syzbot-assets/5b3ee6d54a9b/bzImage-931a3b3b.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com

RIP: 0010:minstrel_ht_fill_rate_array net/mac80211/rc80211_minstrel_ht.c:1883 [inline]
RIP: 0010:minstrel_ht_init_cck_rates net/mac80211/rc80211_minstrel_ht.c:1909 [inline]
RIP: 0010:minstrel_ht_alloc+0x299/0x860 net/mac80211/rc80211_minstrel_ht.c:1962
Code: 4c 24 08 45 31 ed 4c 89 f8 48 c1 e8 03 42 0f b6 04 30 84 c0 0f 85 f1 00 00 00 41 8b 6c 24 fc 21 dd 89 ef 89 de e8 17 f5 48 f6 <39> dd 75 4c 49 8d 7f 04 48 89 f8 48 c1 e8 03 42 0f b6 04 30 84 c0
RSP: dc9b:0000000000000007 EFLAGS: 00000007 ORIG_RAX: ffffc90003606e70
==================================================================
BUG: KASAN: stack-out-of-bounds in __show_regs+0xc1/0x610 arch/x86/kernel/process_64.c:83
Read of size 8 at addr ffffc90003606ea0 by task swapper/0/0

CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.11.0-rc1-next-20240729-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 06/27/2024
Call Trace:
 <IRQ>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120
 print_address_description mm/kasan/report.c:377 [inline]
 print_report+0x169/0x550 mm/kasan/report.c:488
 kasan_report+0x143/0x180 mm/kasan/report.c:601
 __show_regs+0xc1/0x610 arch/x86/kernel/process_64.c:83
 show_trace_log_lvl+0x3d4/0x520 arch/x86/kernel/dumpstack.c:301
 sched_show_task+0x506/0x6d0 kernel/sched/core.c:7512
 report_rtnl_holders+0x327/0x400 net/core/rtnetlink.c:110
 call_timer_fn+0x18e/0x650 kernel/time/timer.c:1792
 expire_timers kernel/time/timer.c:1843 [inline]
 __run_timers kernel/time/timer.c:2417 [inline]
 __run_timer_base+0x66a/0x8e0 kernel/time/timer.c:2428
 run_timer_base kernel/time/timer.c:2437 [inline]
 run_timer_softirq+0xb7/0x170 kernel/time/timer.c:2447
 handle_softirqs+0x2c4/0x970 kernel/softirq.c:554
 __do_softirq kernel/softirq.c:588 [inline]
 invoke_softirq kernel/softirq.c:428 [inline]
 __irq_exit_rcu+0xf4/0x1c0 kernel/softirq.c:637
 irq_exit_rcu+0x9/0x30 kernel/softirq.c:649
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1043 [inline]
 sysvec_apic_timer_interrupt+0xa6/0xc0 arch/x86/kernel/apic/apic.c:1043
 </IRQ>
 <TASK>
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
RIP: 0010:flush_smp_call_function_queue+0x23f/0x2a0 kernel/smp.c:592
Code: 00 4d 85 f6 75 16 e8 40 4f 0c 00 eb 15 e8 39 4f 0c 00 e8 c4 19 32 0a 4d 85 f6 74 ea e8 2a 4f 0c 00 fb 48 c7 04 24 0e 36 e0 45 <4b> c7 04 27 00 00 00 00 66 43 c7 44 27 09 00 00 43 c6 44 27 0b 00
RSP: 0018:ffffffff8e607cc0 EFLAGS: 00000293
RAX: ffffffff81877c36 RBX: 0000000000000000 RCX: ffffffff8e694680
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
RBP: ffffffff8e607d70 R08: ffffffff81877c0c R09: 1ffffffff202faed
R10: dffffc0000000000 R11: fffffbfff202faee R12: 1ffffffff1cc0f98
R13: 0000000000000046 R14: 0000000000000200 R15: dffffc0000000000
 do_idle+0x565/0x5d0 kernel/sched/idle.c:353
 cpu_startup_entry+0x42/0x60 kernel/sched/idle.c:424
 rest_init+0x2dc/0x300 init/main.c:747
 start_kernel+0x47a/0x500 init/main.c:1103
 x86_64_start_reservations+0x2a/0x30 arch/x86/kernel/head64.c:507
 x86_64_start_kernel+0x9f/0xa0 arch/x86/kernel/head64.c:488
 common_startup_64+0x13e/0x147
 </TASK>

The buggy address belongs to the virtual mapping at
 [ffffc90003600000, ffffc90003609000) created by:
 copy_process+0x5d1/0x3d90 kernel/fork.c:2206

The buggy address belongs to the physical page:
page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x7fbc5
flags: 0xfff00000000000(node=0|zone=1|lastcpupid=0x7ff)
raw: 00fff00000000000 0000000000000000 dead000000000122 0000000000000000
raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected
page_owner tracks the page as allocated
page last allocated via order 0, migratetype Unmovable, gfp_mask 0x2dc2(GFP_KERNEL|__GFP_HIGHMEM|__GFP_NOWARN|__GFP_ZERO), pid 5241, tgid 5241 (syz-executor243), ts 226123633416, free_ts 218311192673
 set_page_owner include/linux/page_owner.h:32 [inline]
 post_alloc_hook+0x1f3/0x230 mm/page_alloc.c:1493
 prep_new_page mm/page_alloc.c:1501 [inline]
 get_page_from_freelist+0x2e4c/0x2f10 mm/page_alloc.c:3442
 __alloc_pages_noprof+0x256/0x6c0 mm/page_alloc.c:4700
 alloc_pages_mpol_noprof+0x3e8/0x680 mm/mempolicy.c:2263
 vm_area_alloc_pages mm/vmalloc.c:3584 [inline]
 __vmalloc_area_node mm/vmalloc.c:3660 [inline]
 __vmalloc_node_range_noprof+0x971/0x1460 mm/vmalloc.c:3841
 alloc_thread_stack_node kernel/fork.c:314 [inline]
 dup_task_struct+0x444/0x8c0 kernel/fork.c:1115
 copy_process+0x5d1/0x3d90 kernel/fork.c:2206
 kernel_clone+0x226/0x8f0 kernel/fork.c:2788
 __do_sys_clone kernel/fork.c:2931 [inline]
 __se_sys_clone kernel/fork.c:2915 [inline]
 __x64_sys_clone+0x258/0x2a0 kernel/fork.c:2915
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
page last free pid 5231 tgid 5231 stack trace:
 reset_page_owner include/linux/page_owner.h:25 [inline]
 free_pages_prepare mm/page_alloc.c:1094 [inline]
 free_unref_page+0xd22/0xea0 mm/page_alloc.c:2612
 __folio_put+0x2c8/0x440 mm/swap.c:128
 pipe_buf_release include/linux/pipe_fs_i.h:219 [inline]
 pipe_update_tail fs/pipe.c:224 [inline]
 pipe_read+0x6f2/0x13e0 fs/pipe.c:344
 new_sync_read fs/read_write.c:395 [inline]
 vfs_read+0x9bd/0xbc0 fs/read_write.c:476
 ksys_read+0x1a0/0x2c0 fs/read_write.c:619
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f

Memory state around the buggy address:
 ffffc90003606d80: 00 f3 f3 f3 f3 f3 f3 f3 00 00 00 00 00 00 00 00
 ffffc90003606e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>ffffc90003606e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                               ^
 ffffc90003606f00: f1 f1 f1 f1 00 00 00 00 00 00 00 00 f3 f3 f3 f3
 ffffc90003606f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
==================================================================
----------------
Code disassembly (best guess):
   0:	4c 24 08             	rex.WR and $0x8,%al
   3:	45 31 ed             	xor    %r13d,%r13d
   6:	4c 89 f8             	mov    %r15,%rax
   9:	48 c1 e8 03          	shr    $0x3,%rax
   d:	42 0f b6 04 30       	movzbl (%rax,%r14,1),%eax
  12:	84 c0                	test   %al,%al
  14:	0f 85 f1 00 00 00    	jne    0x10b
  1a:	41 8b 6c 24 fc       	mov    -0x4(%r12),%ebp
  1f:	21 dd                	and    %ebx,%ebp
  21:	89 ef                	mov    %ebp,%edi
  23:	89 de                	mov    %ebx,%esi
  25:	e8 17 f5 48 f6       	call   0xf648f541
* 2a:	39 dd                	cmp    %ebx,%ebp <-- trapping instruction
  2c:	75 4c                	jne    0x7a
  2e:	49 8d 7f 04          	lea    0x4(%r15),%rdi
  32:	48 89 f8             	mov    %rdi,%rax
  35:	48 c1 e8 03          	shr    $0x3,%rax
  39:	42 0f b6 04 30       	movzbl (%rax,%r14,1),%eax
  3e:	84 c0                	test   %al,%al


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000007fca5d061ea7b850%40google.com.

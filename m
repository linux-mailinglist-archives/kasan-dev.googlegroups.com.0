Return-Path: <kasan-dev+bncBCQPF57GUQHBBYOER3XQKGQENP7C3BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C18F10E183
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Dec 2019 12:22:10 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 10sf16752983ois.18
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Dec 2019 03:22:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575199329; cv=pass;
        d=google.com; s=arc-20160816;
        b=k0SPaygyWDs0jjJdbAMdtH0xRV6g2j6LMLNJzw2orogIGyLWJwaIojkhLQ9IZih985
         fh7pZJk0h6OFQsnKZ7Oeuzdkocg3+fKKfijGNf5SxcQbQ51hlpkGPyMwJOr6y6oSvq1o
         uvqWr1vmUxtlJh2MjBq3ftWaphNA1ZNyca5L2eED4x8OOeLJ+lkkH+xpAga7kaiMoyUM
         ZlkE38Mq0FfMo6AFQP6p1KIwKGYd/rNAxeebZQtxWseNQrNtj1hAtmBHgGY390654/4B
         pxJ8pHjB6PfXIwwImdf9KfgQa15fxLjVwdGWSSEMUXuqr8jg4PexGdV+DEwgOy7jkesg
         AkCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=zy31lFyYNGh+Gtbw61Dy9bSMYHiSekyId21bkEME6Uw=;
        b=NDEraBrk+s3cGYFNpU1Sqjgq9qGDa6bcPv7jUobO+0Y6wgyJh2PCqebC9bAv0tuS3n
         J/7WDvBlJ6WRX63L7smsMJ/zvUApMh6u/sBP2bwGiBYT8vNJkLrojM+Waj6yf9pW/iL7
         lqUHJpaZVVW5A7QmVlPakea1EiekZkTt/lAp8Vv5QKRc/PBgzxAJVGeB97fUSqT4s950
         0oRZ0Fq5UW3AIhDd7cLpYhfXgYVlbZND2WXGxVPzPn0PT8XSu9+BkddGgg2CnVdPXpbE
         YcTp9ri3Lc3qM57zkTMjod2XJIOed5n+KXqjHClF4qVXl4BGvtYSq12anU0dpJq1ps/T
         oZZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3ykljxqkbackxdepfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3YKLjXQkbACkXdePFQQJWFUUNI.LTTLQJZXJWHTSYJSY.HTR@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zy31lFyYNGh+Gtbw61Dy9bSMYHiSekyId21bkEME6Uw=;
        b=BN8RBT4Lj4Uwa0sxmSsACgNqkZ+mhWdsrls7ZOhra5Ef0bhvURI/Kj2ABIVfDPLdSP
         2NplDUq3RkmJ8gLRbQGAynEGqL+3UdmCbaGQzGYrtgp0u+bkVo+RkO1a7wgKgnbtfLHe
         +yKVOHt2YoA+zK8h5Zsd0ZdYykKW02nevxt45hvXPb+EYxso3ccK/sYTvmKR/xIvAIc0
         AQZrdbBBt00TB7bt9g5EdHJeqYMpOFm13ofRoeWEY/4JwF74cutrECz0Lq6Ty3xYGRvc
         TX4llIIZMmPIDMKJs2FAtd7Ue4OyzOqUfL3De1itMD9VdVjFKq1CavqqVIRWe0U+ovml
         l0wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zy31lFyYNGh+Gtbw61Dy9bSMYHiSekyId21bkEME6Uw=;
        b=kIT0JxatO+1SgSxwi0IJmvtbuGYC3RJZl4dEtEa/GBghKbx/XIx4+fdwmnQ7CGrAz7
         rxIYOOI2pRTVsR51LL1wP4ga4ed+ByO4yIaBFD0RWyop8pOmm3B5J8hoW14ZPVTJc2r1
         YX+BNv3RDaxP/Q1m+uTZ8aZRvvyJ3m8csmbUtpXVNDTbY9JmwAbvhguxJ3gDFRaF2zQT
         nZlr7KPqx4DhsCTfIT7gMJ1JivRsxjMBi+WXJhVLUpeYpRlFnBGn4deQiHSqvOX+BlJW
         UtL8p5P4TuMZN5xYd9NKzIQikeGi3TPSL5WcTXrmqBjc5WvA0FzlXdMs8+PzFYFEKRDi
         WgYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFm26Hlf5Fh5SYJB1IeEBzy46eDnw0Zr9CpP5rGImwZ/DwYvch
	6zEScVrLkc0TXCmvUdDj4Lk=
X-Google-Smtp-Source: APXvYqxybcQZ66u4K1gGKA+bMId13aSGMNu+g8GOrgX8fLELzIUQ+mJ+EjjTleZC6tmMgtuJiCn3XA==
X-Received: by 2002:a9d:7f16:: with SMTP id j22mr1692778otq.256.1575199329238;
        Sun, 01 Dec 2019 03:22:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3987:: with SMTP id y7ls5213991otb.8.gmail; Sun, 01 Dec
 2019 03:22:08 -0800 (PST)
X-Received: by 2002:a9d:7ccc:: with SMTP id r12mr4403412otn.22.1575199328874;
        Sun, 01 Dec 2019 03:22:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575199328; cv=none;
        d=google.com; s=arc-20160816;
        b=HILNnNEgej7eYUGxDGTGfnlY5lu07bxMswc1ZOdSbZDPFGiuKY9LaApTXKDDpbEmvI
         N1yxuYftbWFMpyWbyTv3VmpZsvwYvw0363h3yEqfl7gg2v7uFf+u5k7Q6cRIdN3kcbcP
         Z6ZQ50MJlkxmib0CxEpNKF1H2OGDcpheTUpESl1zsPnofuvGmPygEfzvilBT0v5g2t/L
         0LF3VSB/vswW2fVyzIvymH3DPBRDJOamcA2v1WPiboHAiSa/8iIxv8WFEbmIzHCiBtn9
         a7wdpQFzGIn/b2yUrUyxijGJ2b8hNVrCJIaLI9XwX1CZcteBIiSeCzVcVP3Uyi+wcHWi
         YrpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=59tOo+S299CeDluWylHOhMRAIUwsgcblBa37pT8fvnY=;
        b=ucmllLK1GU1bEkfJlo9xkBbOleBH+U5xXlupTzvMJVk8KmWwNSRikq6lCcMDH/aBPw
         GTB6EyImqqvnhDmYtndWWu4lLNhwT+8y26AKRdTA1vw4AVLECnRDyyjBc5E0hxMU23cG
         PFmr0HY80+PHvfaGguevELSObVu5GL7HRlEflt9ARO/ZIjvnBWQQLr9va6IoUk41vNaH
         idXjVorMlHn1QdQX3WB1rQu9zXHT2fULlSENkN96zxWIwxVGvwpEFH4aEfmSNnBXYFDt
         Zz7BP9tv/tUPk3YF23tLDEMwMLeA1UzCfvPUinQxosE3VPmSaGZkYjMjZhMKxDxT2imP
         Ml7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3ykljxqkbackxdepfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3YKLjXQkbACkXdePFQQJWFUUNI.LTTLQJZXJWHTSYJSY.HTR@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id l76si326546oih.3.2019.12.01.03.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Dec 2019 03:22:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ykljxqkbackxdepfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id l13so13336767ils.1
        for <kasan-dev@googlegroups.com>; Sun, 01 Dec 2019 03:22:08 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a6b:7a48:: with SMTP id k8mr7608690iop.138.1575199328570;
 Sun, 01 Dec 2019 03:22:08 -0800 (PST)
Date: Sun, 01 Dec 2019 03:22:08 -0800
In-Reply-To: <000000000000c280ba05988b6242@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000006e19cd0598a2ac48@google.com>
Subject: Re: BUG: sleeping function called from invalid context in __alloc_pages_nodemask
From: syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, aryabinin@virtuozzo.com, 
	christophe.leroy@c-s.fr, dja@axtens.net, dvyukov@google.com, 
	glider@google.com, gor@linux.ibm.com, hdanton@sina.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mark.rutland@arm.com, penguin-kernel@I-love.SAKURA.ne.jp, 
	syzkaller-bugs@googlegroups.com, urezki@gmail.com
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3ykljxqkbackxdepfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=3YKLjXQkbACkXdePFQQJWFUUNI.LTTLQJZXJWHTSYJSY.HTR@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot has found a reproducer for the following crash on:

HEAD commit:    419593da Add linux-next specific files for 20191129
git tree:       linux-next
console output: https://syzkaller.appspot.com/x/log.txt?x=168e202ee00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=162234a2e00000

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com

BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 9071, name:  
kworker/0:3
4 locks held by kworker/0:3/9071:
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: __write_once_size  
include/linux/compiler.h:247 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: arch_atomic64_set  
arch/x86/include/asm/atomic64_64.h:34 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic64_set  
include/asm-generic/atomic-instrumented.h:868 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic_long_set  
include/asm-generic/atomic-long.h:40 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: set_work_data  
kernel/workqueue.c:615 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:  
set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:  
process_one_work+0x88b/0x1740 kernel/workqueue.c:2235
  #1: ffffc900021a7dc0 (pcpu_balance_work){+.+.}, at:  
process_one_work+0x8c1/0x1740 kernel/workqueue.c:2239
  #2: ffffffff8983ff20 (pcpu_alloc_mutex){+.+.}, at:  
pcpu_balance_workfn+0xb7/0x1310 mm/percpu.c:1845
  #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at: spin_lock  
include/linux/spinlock.h:338 [inline]
  #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at:  
pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
Preemption disabled at:
[<ffffffff81a89ce7>] spin_lock include/linux/spinlock.h:338 [inline]
[<ffffffff81a89ce7>] pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
CPU: 0 PID: 9071 Comm: kworker/0:3 Not tainted  
5.4.0-next-20191129-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS  
Google 01/01/2011
Workqueue: events pcpu_balance_workfn
Call Trace:
  __dump_stack lib/dump_stack.c:77 [inline]
  dump_stack+0x197/0x210 lib/dump_stack.c:118
  ___might_sleep.cold+0x1fb/0x23e kernel/sched/core.c:6800
  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
  __alloc_pages_nodemask+0x523/0x910 mm/page_alloc.c:4730
  alloc_pages_current+0x107/0x210 mm/mempolicy.c:2211
  alloc_pages include/linux/gfp.h:532 [inline]
  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
  kasan_populate_vmalloc_pte+0x2f/0x1c0 mm/kasan/common.c:753
  apply_to_pte_range mm/memory.c:2041 [inline]
  apply_to_pmd_range mm/memory.c:2068 [inline]
  apply_to_pud_range mm/memory.c:2088 [inline]
  apply_to_p4d_range mm/memory.c:2108 [inline]
  apply_to_page_range+0x445/0x700 mm/memory.c:2133
  kasan_populate_vmalloc+0x68/0x90 mm/kasan/common.c:791
  pcpu_get_vm_areas+0x3c77/0x3f00 mm/vmalloc.c:3439
  pcpu_create_chunk+0x24e/0x7f0 mm/percpu-vm.c:340
  pcpu_balance_workfn+0xf1b/0x1310 mm/percpu.c:1934
  process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
  worker_thread+0x98/0xe40 kernel/workqueue.c:2410
  kthread+0x361/0x430 kernel/kthread.c:255
  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000006e19cd0598a2ac48%40google.com.

Return-Path: <kasan-dev+bncBDV37XP3XYDRB2WF5LVAKGQE2DM77SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B487924DD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 15:23:54 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id a17sf5286405wrw.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 06:23:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566221034; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rojb3Ml+Ciq9/vuxu4YqYUcFzVNtyGBd542XYzerhZ3yNoxdd4M/gyCCc4zMOPGN7H
         X1OqdpwRV9D3ncvvEB1fbQ8Neuwm5CWbW52lMVuEaY+Od8OTLCSsXe9540X7xap02ouq
         JD6UvVCoWZECngR1qkR8MUeqN/7FH2FiS7Ibd8yTpfVnFuECbhENpETC8uaFY74ygWKs
         CZf+vI4Ah06uTwpeQQwi86VAQucaV2QubIhjG4JAXs+SfkIubbkymPlGZ1uJiDnVLHul
         b0uZ6X4cqQj0A5789Dm5KKaGGQazdLaCZpNkUnux50ZdgJJM5oMp6GslIXQSIvtoanqU
         u2TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Y/OcYMQ2mbu3wAyRR1TEkU/dYKdf3TqiXhpayV+dyQQ=;
        b=z7J4JobvVhvuskbRti7ruZ6I9yXpnyg+b7/4+akL4c8qI9cI01SyZo2Bm8VbpT8KSZ
         JdAa35XcGPcynHmWZm7OpVvDyI/41Zu1yjGosPBathyWL67bYFBblxTXTI1TZ3YbyhhM
         RzrDqnb4agY2DJK4I0f5k8K+OWrVKkDVG9Z0fXHkOMTF8DpL1xbWGh6Wxh9V7B7M2imW
         CLt3+XQCDUeISBYRez3SslMxWVjWN4BUeJyBGX0epBAO5+cbLFgc5J50gfXFrGRV6UoH
         u+R4t7Yq11oyctYz/CW+PKuOFQ0ZVGC9iE/1Z5J8g2L8wV+kxlVJ0EKFOafq3eWTQ8xe
         0vEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y/OcYMQ2mbu3wAyRR1TEkU/dYKdf3TqiXhpayV+dyQQ=;
        b=ergbO3Gr1jPk6KcMRiqNw2Zfy2Csf9wWMLZqEf47Xcw0a9greEOos9jvAnrN3tugw+
         0/zcgXi7zwUmFG2cLc1Uscca25LUlBNtXPhA6TcX1/nClEnqi6Z9FtXh2Ljlr2N6EZF6
         6tKgNm0YJXPSoMJoRPMZrO2ewEc4Z8ueUw8sVRPbXyVIZAt4W7l4n5Nr1qu3E2HCqipA
         zSrNvOIc7187SYLkCikZQrjUy+IFrpy3qjs2JgqvzuZyGjKdRizGhLDdrAfmJv8pMu1H
         UYDfinTh8q6JbImFn6Q0qdLNCtmU21/z5ecB3Ygnov9SZzWXyVYwNAyTKkAYt2J1Eg5H
         nWTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y/OcYMQ2mbu3wAyRR1TEkU/dYKdf3TqiXhpayV+dyQQ=;
        b=iaPT+rSUhghU/P4jyCPbkIIvHRI5GVJJldPVNSKe/oKchkKgdgfICnrIotbNdSav4N
         sxN6fB1UQ67p5XSZOsK7pvdKkBDKoZzBJUjxuDpKyzKA3fIX9ha/kdvpu9S0LB8UQEE4
         WiXhZMCRBsOdFhoOSucMWHOVwq92RMKHtMq3Os5y1EZHWSo1gkTYXCz9evTuxuBhXqpz
         jxLX0aEC+1RQh1UXEVLgjXiQ3PChZWPlKWaDyEKWK9g1BinTz3/EnrDHKYTaa0jnnYOB
         mZdqbtUoqpENYWDtZJg8iZtXH1Eyn3JIyQtl1JTt8BWn9IteKN8dAKauVvCyu/ryhycx
         kvDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV0K3+oFHZwOl6TQFNrprzHgPHzpQF9+gDKnmm9E4S/uUWSPHwQ
	ZR/MdwXvxuSSLcKkxKpP+IY=
X-Google-Smtp-Source: APXvYqyVBLey/eDH9q9aFBqQuO9BMSlgZgju59+bYb1wmHbdHMW+7zxT25WvrCRfk/5GJzlaA6rHxA==
X-Received: by 2002:adf:b64b:: with SMTP id i11mr28047330wre.114.1566221034328;
        Mon, 19 Aug 2019 06:23:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cc01:: with SMTP id f1ls782746wmh.4.canary-gmail; Mon,
 19 Aug 2019 06:23:53 -0700 (PDT)
X-Received: by 2002:a1c:9950:: with SMTP id b77mr21064934wme.46.1566221033088;
        Mon, 19 Aug 2019 06:23:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566221033; cv=none;
        d=google.com; s=arc-20160816;
        b=Gmk7FzENm66lebLY2Ic4GYg4mEYhkFJa1JIN5pXu8jCsaDFfxSdcEkgUmeQfpamEZa
         qvs3uw6UbCU6GZwHN/LnUbkUg4nsljiUjhIsqJo97R+6KY4x6owHt/v3OrPFWrWI+v24
         F5Mn5WoJXP6WYUSMLaZOOhlEHaabmMLEk40BF77Fr180aDqPrLMBpSXqC7HyrT+Ozp6m
         UIiPiiT1WR+L60G7dCR/Pm060tpOjXBUBgWDrCChE1kMHyRv6+vUVxeD2YYBmDrkXc7v
         EaL+DzgzjY6LifoUW4UkNxfgG0dmaY7jAHlHPiimFd2a8M6dWEJR0JAe0bTVecUw7Q3X
         iDzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Crw0vQ6IDxNH6aDGB2qTbwU8Ff46hOr5FSxlWZRuy8A=;
        b=hK11YT+L+6zcd0fZkz87mkfOvZDmXsNj6xb2UGC2DtFvmktL0S4wx6iDlSWhn8bDQa
         w94x1Q43r5QSAJ0EIzWOSw7e8tNS4HrmIJcp6/92fbbtSBzGvZRPKptQMMmydLenhZGd
         ayTtk5ocHlh0zdtqE1MriTZ0hdab5f2JfVbKc8pyvauoQR5mNY76s2CfbDn2tiDhxHCo
         MZjGIlSWy3F7WPEGoNpq0G93l/1dTpYV3C4WQJFZdr7K7n+VI3bS7kaH95REkwz7AVWr
         zoaAdKGcPsZTMlx9MXzR8u5huhu7JdnjlOll6yRGhWTZxVRxPIZxA2gJ6KZmd5HD1oJo
         iLLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w17si520076wmk.1.2019.08.19.06.23.52
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 06:23:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0A3FD28;
	Mon, 19 Aug 2019 06:23:52 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 22D863F777;
	Mon, 19 Aug 2019 06:23:50 -0700 (PDT)
Date: Mon, 19 Aug 2019 14:23:48 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>, wsd_upstream@mediatek.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819132347.GB9927@lakrids.cambridge.arm.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > but it will modify pointer tag into 0xff, so there is a false positive.
> > 
> > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > its original pointer tag in order to avoid kasan report an incorrect
> > memory corruption.
> 
> Hmm. Which tree did you see this on? We've recently queued a load of fixes
> in this area, but I /thought/ they were only needed after the support for
> 52-bit virtual addressing in the kernel.

I'm seeing similar issues in the virtio blk code (splat below), atop of
the arm64 for-next/core branch. I think this is a latent issue, and
people are only just starting to test with KASAN_SW_TAGS.

It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
virt->page->virt, losing the per-object tag in the process.

Our page_to_virt() seems to get a per-page tag, but this only makes
sense if you're dealing with the page allocator, rather than something
like SLUB which carves a page into smaller objects giving each object a
distinct tag.

Any round-trip of a pointer from SLUB is going to lose the per-object
tag.

Thanks,
Mark.

==================================================================
BUG: KASAN: double-free or invalid-free in virtblk_request_done+0x128/0x1d8 drivers/block/virtio_blk.c:215
Pointer tag: [ff], memory tag: [a8]

CPU: 0 PID: 19116 Comm: syz-executor.0 Not tainted 5.3.0-rc3-00075-gcb38552 #1
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x3c0 arch/arm64/include/asm/stacktrace.h:166
 show_stack+0x24/0x30 arch/arm64/kernel/traps.c:138
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x138/0x1f4 lib/dump_stack.c:113
 print_address_description+0x7c/0x328 mm/kasan/report.c:351
 kasan_report_invalid_free+0x80/0xe0 mm/kasan/report.c:444
 __kasan_slab_free+0x1a8/0x208 mm/kasan/common.c:56
 kasan_slab_free+0xc/0x18 mm/kasan/common.c:457
 slab_free_hook mm/slub.c:1423 [inline]
 slab_free_freelist_hook mm/slub.c:1474 [inline]
 slab_free mm/slub.c:3016 [inline]
 kfree+0x254/0x9dc mm/slub.c:3957
 virtblk_request_done+0x128/0x1d8 drivers/block/virtio_blk.c:215
 blk_done_softirq+0x3dc/0x49c block/blk-softirq.c:37
 __do_softirq+0xa90/0x1504 kernel/softirq.c:292
 do_softirq_own_stack include/linux/interrupt.h:549 [inline]
 invoke_softirq kernel/softirq.c:380 [inline]
 irq_exit+0x3b0/0x4f8 kernel/softirq.c:413
 __handle_domain_irq+0x150/0x250 kernel/irq/irqdesc.c:671
 atomic_read include/asm-generic/atomic-instrumented.h:26 [inline]
 static_key_count include/linux/jump_label.h:254 [inline]
 cpus_have_const_cap arch/arm64/include/asm/cpufeature.h:410 [inline]
 gic_read_iar drivers/irqchip/irq-gic-v3.c:152 [inline]
 gic_handle_irq+0x244/0x4ac drivers/irqchip/irq-gic-v3.c:490
 el1_irq+0xbc/0x140 arch/arm64/kernel/entry.S:670
 ktime_add_safe kernel/time/hrtimer.c:321 [inline]
 hrtimer_set_expires_range_ns include/linux/hrtimer.h:235 [inline]
 hrtimer_nanosleep kernel/time/hrtimer.c:1732 [inline]
 __do_sys_nanosleep kernel/time/hrtimer.c:1767 [inline]
 __se_sys_nanosleep kernel/time/hrtimer.c:1754 [inline]
 __arm64_sys_nanosleep+0x344/0x554 kernel/time/hrtimer.c:1754
 __invoke_syscall arch/arm64/kernel/syscall.c:36 [inline]
 invoke_syscall arch/arm64/kernel/syscall.c:48 [inline]
 el0_svc_common arch/arm64/kernel/syscall.c:114 [inline]
 el0_svc_handler+0x300/0x540 arch/arm64/kernel/syscall.c:160
 el0_svc+0x8/0xc arch/arm64/kernel/entry.S:1006

Allocated by task 170:
 save_stack mm/kasan/common.c:69 [inline]
 set_track mm/kasan/common.c:77 [inline]
 __kasan_kmalloc+0x114/0x1d0 mm/kasan/common.c:487
 kasan_kmalloc+0x10/0x18 mm/kasan/common.c:501
 __kmalloc+0x1f0/0x48c mm/slub.c:3811
 kmalloc_array include/linux/slab.h:676 [inline]
 virtblk_setup_discard_write_zeroes drivers/block/virtio_blk.c:188 [inline]
 virtio_queue_rq+0x948/0xe48 drivers/block/virtio_blk.c:322
 blk_mq_dispatch_rq_list+0x914/0x16fc block/blk-mq.c:1257
 blk_mq_do_dispatch_sched+0x374/0x4d8 block/blk-mq-sched.c:115
 blk_mq_sched_dispatch_requests+0x4d0/0x68c block/blk-mq-sched.c:216
 __blk_mq_run_hw_queue+0x22c/0x35c block/blk-mq.c:1387
 blk_mq_run_work_fn+0x64/0x78 block/blk-mq.c:1620
 process_one_work+0x10bc/0x1df0 kernel/workqueue.c:2269
 worker_thread+0x1124/0x17bc kernel/workqueue.c:2415
 kthread+0x3c0/0x3d0 kernel/kthread.c:255
 ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:1164

Freed by task 17121:
 save_stack mm/kasan/common.c:69 [inline]
 set_track mm/kasan/common.c:77 [inline]
 __kasan_slab_free+0x138/0x208 mm/kasan/common.c:449
 kasan_slab_free+0xc/0x18 mm/kasan/common.c:457
 slab_free_hook mm/slub.c:1423 [inline]
 slab_free_freelist_hook mm/slub.c:1474 [inline]
 slab_free mm/slub.c:3016 [inline]
 kfree+0x254/0x9dc mm/slub.c:3957
 kvfree+0x54/0x60 mm/util.c:488
 __vunmap+0xa3c/0xafc mm/vmalloc.c:2255
 __vfree mm/vmalloc.c:2299 [inline]
 vfree+0xe4/0x1c4 mm/vmalloc.c:2329
 copy_entries_to_user net/ipv6/netfilter/ip6_tables.c:883 [inline]
 get_entries net/ipv6/netfilter/ip6_tables.c:1041 [inline]
 do_ip6t_get_ctl+0xf78/0x1804 net/ipv6/netfilter/ip6_tables.c:1709
 nf_sockopt net/netfilter/nf_sockopt.c:104 [inline]
 nf_getsockopt+0x238/0x258 net/netfilter/nf_sockopt.c:122
 ipv6_getsockopt+0x3374/0x40c4 net/ipv6/ipv6_sockglue.c:1400
 tcp_getsockopt+0x214/0x54e0 net/ipv4/tcp.c:3662
 sock_common_getsockopt+0xc8/0xf4 net/core/sock.c:3089
 __sys_getsockopt net/socket.c:2129 [inline]
 __do_sys_getsockopt net/socket.c:2144 [inline]
 __se_sys_getsockopt net/socket.c:2141 [inline]
 __arm64_sys_getsockopt+0x240/0x308 net/socket.c:2141
 __invoke_syscall arch/arm64/kernel/syscall.c:36 [inline]
 invoke_syscall arch/arm64/kernel/syscall.c:48 [inline]
 el0_svc_common arch/arm64/kernel/syscall.c:114 [inline]
 el0_svc_handler+0x300/0x540 arch/arm64/kernel/syscall.c:160
 el0_svc+0x8/0xc arch/arm64/kernel/entry.S:1006

The buggy address belongs to the object at ffff00005338eb80
 which belongs to the cache kmalloc-128 of size 128
The buggy address is located 0 bytes inside of
 128-byte region [ffff00005338eb80, ffff00005338ec00)
The buggy address belongs to the page:
page:ffffffdffff4ce00 refcount:1 mapcount:0 mapping:e5ff0000576b0480 index:0x29ff000053388f00
flags: 0xffffff000000200(slab)
raw: 0ffffff000000200 ffffffdffff00108 5eff0000576afd40 e5ff0000576b0480
raw: 29ff000053388f00 000000000066005d 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff00005338e900: 34 34 34 34 34 34 34 34 fe fe fe fe fe fe fe fe
 ffff00005338ea00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>ffff00005338eb00: fe fe fe fe fe fe fe fe a8 fe fe fe fe fe fe fe
                                           ^
 ffff00005338ec00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
 ffff00005338ed00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
==================================================================

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819132347.GB9927%40lakrids.cambridge.arm.com.

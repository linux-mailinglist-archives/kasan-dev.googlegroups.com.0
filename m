Return-Path: <kasan-dev+bncBCAJFDXE4QGBBLNJR62QMGQEKHWV6RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C401493D73A
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 18:54:07 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5d1f7855cd7sf1019778eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 09:54:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722012846; cv=pass;
        d=google.com; s=arc-20160816;
        b=oqynV4TTvXh+FWHIGyM6n/ACKuKP3ySi9022902MzH4AxfAiLMdI5MmeTqgpkj3F0C
         terCGds3/GFM5+35z8vl8kmUWRT7070ESeq0xzUkMnx022ZazlzAsnf0sp0vBzosTZk5
         GnlrEPp5rqNTMIxWS4c31l4T/CsKC5f1Nfxd22KmRtOw9wvxoq7s5vk1c/PF9DdnW5V0
         SefuE348rTAoLCGc7FYqnubZN42/GkipPOh4KobrkMbEHvcfqLUQ/mHDmyxNUE2tjtOB
         8Qt5MIj8smt3G7FWpzsegfd8QIta27n8k5oid0cFiMrTQrniQksGLuN3sWwOEImHa8+/
         gmPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=AoHiQczncsdg/LOWJ0z43zsLL1NhAnrdpwVsXUOfSu8=;
        fh=9Z6IbpSdZWjXwZbxxPJBqjsC+zujlyozgGmNVpJMc3Y=;
        b=NXs+OINC0o2n/Du2AdsnfoDcCpgBImshYUxDNwTa9xk6/aS/uVjNzIcR+m52dAU6O8
         lgRiQCokdpbdl2V2ieJyuwrdO1or+eybI0rn48XLhGJitJPn+dwj+Eg6YOEutcbYPiGd
         LexT4lkmsLO66jDl7pWrRdYdx0L1XUZ4PwOOZtc5uzeifX8VP34PirzbiagGeUdpqxo8
         zP/FazCALsy7WygFc731AxC1Sv9n3vccrQDEtNbdojnW1KyiwbQ3FtdEBdECHFK8gZP0
         usE+ZLsiH15uiP3CfOWFTdTROCs+Z15+3g2ZYc1RhB491+Tju6ugCRJUG+TIZyEfQCSG
         +xUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SFBCIBIE;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722012846; x=1722617646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AoHiQczncsdg/LOWJ0z43zsLL1NhAnrdpwVsXUOfSu8=;
        b=EqfGMGHyRuInyrrB9uWL8YCKyPe809j5gEKA4yZ1FZbYJ0BRc1x9VDgBLXcaPWiAaG
         OKJoUYUS9sIzOah953c/dimZWqetXSuM6tvJvm3kAZ0bby5/6FubXXVACbDvLJjjt6x5
         12tz50lmLLffYFixG77qXsjhzKST9gDKxpmoPz0DPh8GOVtTp1jEYUqLVMSiKPa0ABeN
         rBjJurMc7hIH4iK65LROHu5fhCUBvYbPTmboppezbN7fEx+HlWs7VDAJtNJS/FlQZQ+I
         BIVnS749E/0QZKRUXUgTQnH3qU/KoFDse+Ne/h0kSeYOYba6RpEZ32mC5vXFjTNhE+JB
         lILA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722012846; x=1722617646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AoHiQczncsdg/LOWJ0z43zsLL1NhAnrdpwVsXUOfSu8=;
        b=k3xbgTiwYuKtGKRxr3buKd4qfisDtnWmuRIUrzaSHwUHloMdCwg0VBnB2RZcgFv7se
         fUZFugCJjWfrY29jMku0oA5iDft3j47YDUMd1zUdr21YNlXiCHwHDUUAc1qWDc7m4Mhr
         kxTelBohcUweIZMZpV+/tZrtDi4Nl3shWmNwbGg1fQ44HvbHbZeZv+jd+Jgo9izK2m8M
         HvH32Z0CFDyPhi7nzyftFHkFlDQ94IiCGzIh2BHKIcsVBTIa7yJFQ3EViAXs1qQhQjn5
         hzivJaZt5+AyOffjXxyzNZSZfiP8TR7msaMLqSoj4d5mMLkICQCUxhqATESPswf6FZoP
         Hp2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722012846; x=1722617646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AoHiQczncsdg/LOWJ0z43zsLL1NhAnrdpwVsXUOfSu8=;
        b=dVoxbfas6pH2UaGzURlC2uz2BYpXaGrrBmrtoz/CjM2f/ArYe2X3Ezc+p1Q4gPSglv
         Ns1kL0+5pS/6kuv+6LsLcKaT35ZL82hw5N8AKV+dRLc6uUnhKLyzDes0VIXmP18Jj6Ec
         zPNampibtOPGMP9qoUx40Qyfw2sb589JE1daJ+qtykHERdX8C30IiHts5N6lc96qwhNq
         /cOcu/uJInII3ufuJGOnVi2MXDeFQ7aP0BuC+rMjzn+T53wG8021GtX2PFuwzqhiskp/
         5YZJpVec5CMo9Ohc1m9xZxW2Nxa0fN3MQbgtgLLWTz77ducR82z0qlWHSgRFsfoS6BDa
         AxDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDye2wjN8l91USPnXtb8y3Xen2AHNRQlKzfBXPoW0tAAU/lo6PWL2GpVHrDIv3AUKfN4fsoxvIAgB3FjY6Vk0/g31FGGmFgg==
X-Gm-Message-State: AOJu0YyCTNc2crR9Nw/0Hsr0ppefcL4ZEXc1sXcpSzPSdJNb9fCDf0hq
	ls8AZ/LfJ7S/hlJmjwYVs/KY4G2ugCZiC26Unbd853e66opf5tqQ
X-Google-Smtp-Source: AGHT+IGbdQjmfGSiKqCWc8veF4QRe9xzmCOL9eJGqbQ87Olinl3uJ+eZwXciCTDHSFnRjkGk1mUPHA==
X-Received: by 2002:a05:6820:1689:b0:5c6:9320:2df6 with SMTP id 006d021491bc7-5d5d0ef20demr174769eaf.7.1722012845998;
        Fri, 26 Jul 2024 09:54:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d9d4:0:b0:5b9:d066:ebff with SMTP id 006d021491bc7-5d5ae914365ls2077297eaf.2.-pod-prod-02-us;
 Fri, 26 Jul 2024 09:54:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZzLe8Z/94xAlNV543aLXIIJGzebN5go5DsICeweJuXjwwloEUGVMxj2WSqRNr/iQoaG1BtKnjAxOgrvb0L61NHa/jzrY1oWRJrA==
X-Received: by 2002:a05:6820:820:b0:5c4:3f91:7e14 with SMTP id 006d021491bc7-5d5d0ea8964mr238715eaf.3.1722012844670;
        Fri, 26 Jul 2024 09:54:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722012844; cv=none;
        d=google.com; s=arc-20160816;
        b=jO2VL2i2W62SEyPmXf5QmsUQvvu4GC7uBl8LLQuDn/NMhbYKz+Ha7smgxWb7t3eIW6
         dbQL2co3ql6tJJWrp4W6KsnBnVt0hWgkGCABaF8dfdO2KpJYsTaXjk+lC2U4vypO2Vvf
         7eqAxpRI7Aq5rbaU8IkN3hNVocJADnQK7tPfJ9B2cRP8jLGzNybF9vYSJK4GXeTiN9qH
         o6d6r+Efb5ZkRLfvrfl3q7kB2Hm85oQl0x2w61IeDmiQcCuYUGpSccDBR0UgontxbiuL
         FiB0bHbF+wFm3xf0CJ4171qqVDfqF5nAYKMyzGzUUuxxmE1I/2v63vAAAwAiz341txAf
         Qn/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=o4t2bj9tP9eNdb8RTP1Rkd3tr4D6cDtGqwUT49U/h94=;
        fh=8y3Vv5vzCEv06LZjtLEY+w37zdMmAoGahqD7WAIer/c=;
        b=UEg2nopjRviviJMadSc31yJzCEqrq4gHOIzBetBZ2/QXSY2Nx3ZRWc06+KoQzv/5YI
         LWSijE5mJhiK1JkV+NPN7UtFyORlCtAXlF+B+gWHU8ZWC0BezYpL4+E91xQ90kcdtEDs
         jpR5sSaZrSiaFCQptaxV2tmGU9ENQ0GK7E5jnWMRHDMyx4ip8TYpQykFDPGpNVLYsnPi
         S0fJHxY2fDs7zZrTSpb51vJ5xbGQnycPzHSBIGtemb64B+cbbPTfQeoqQGYt5CHAAPEE
         mgTww/SngaUzq0rdIFI9R1LMUD+rO46UhWbKdE14D0Zd/YfUn20rs5jrrpwJegcmlW+W
         0hjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SFBCIBIE;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5d5b36266a1si197123eaf.1.2024.07.26.09.54.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 09:54:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1fd66cddd07so7659985ad.2
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 09:54:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUhjFJiGR4JD6BsUaf1O/nBOcocuH7uVGESFyfFW71+DIbYzXzTs0Zh8KNDT8Lm2GVgYl1gmQrm5anfmQS1/kcRgfpIO0HfrG9RQ==
X-Received: by 2002:a17:903:2284:b0:1fd:9b96:32d4 with SMTP id d9443c01a7336-1ff048e6ff9mr2338855ad.51.1722012844009;
        Fri, 26 Jul 2024 09:54:04 -0700 (PDT)
Received: from AHUANG12-3ZHH9X.lenovo.com (220-143-223-167.dynamic-ip.hinet.net. [220.143.223.167])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1fed8000ecasm34897805ad.309.2024.07.26.09.54.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Jul 2024 09:54:03 -0700 (PDT)
From: Adrian Huang <adrianhuang0701@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@infradead.org>,
	Baoquan He <bhe@redhat.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Adrian Huang <ahuang12@lenovo.com>,
	Jiwei Sun <sunjw10@lenovo.com>
Subject: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN shadow virtual address into one operation
Date: Sat, 27 Jul 2024 00:52:46 +0800
Message-Id: <20240726165246.31326-1-ahuang12@lenovo.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SFBCIBIE;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

From: Adrian Huang <ahuang12@lenovo.com>

When compiling kernel source 'make -j $(nproc)' with the up-and-running
KASAN-enabled kernel on a 256-core machine, the following soft lockup
is shown:

watchdog: BUG: soft lockup - CPU#28 stuck for 22s! [kworker/28:1:1760]
CPU: 28 PID: 1760 Comm: kworker/28:1 Kdump: loaded Not tainted 6.10.0-rc5 #95
Workqueue: events drain_vmap_area_work
RIP: 0010:smp_call_function_many_cond+0x1d8/0xbb0
Code: 38 c8 7c 08 84 c9 0f 85 49 08 00 00 8b 45 08 a8 01 74 2e 48 89 f1 49 89 f7 48 c1 e9 03 41 83 e7 07 4c 01 e9 41 83 c7 03 f3 90 <0f> b6 01 41 38 c7 7c 08 84 c0 0f 85 d4 06 00 00 8b 45 08 a8 01 75
RSP: 0018:ffffc9000cb3fb60 EFLAGS: 00000202
RAX: 0000000000000011 RBX: ffff8883bc4469c0 RCX: ffffed10776e9949
RDX: 0000000000000002 RSI: ffff8883bb74ca48 RDI: ffffffff8434dc50
RBP: ffff8883bb74ca40 R08: ffff888103585dc0 R09: ffff8884533a1800
R10: 0000000000000004 R11: ffffffffffffffff R12: ffffed1077888d39
R13: dffffc0000000000 R14: ffffed1077888d38 R15: 0000000000000003
FS:  0000000000000000(0000) GS:ffff8883bc400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00005577b5c8d158 CR3: 0000000004850000 CR4: 0000000000350ef0
Call Trace:
 <IRQ>
 ? watchdog_timer_fn+0x2cd/0x390
 ? __pfx_watchdog_timer_fn+0x10/0x10
 ? __hrtimer_run_queues+0x300/0x6d0
 ? sched_clock_cpu+0x69/0x4e0
 ? __pfx___hrtimer_run_queues+0x10/0x10
 ? srso_return_thunk+0x5/0x5f
 ? ktime_get_update_offsets_now+0x7f/0x2a0
 ? srso_return_thunk+0x5/0x5f
 ? srso_return_thunk+0x5/0x5f
 ? hrtimer_interrupt+0x2ca/0x760
 ? __sysvec_apic_timer_interrupt+0x8c/0x2b0
 ? sysvec_apic_timer_interrupt+0x6a/0x90
 </IRQ>
 <TASK>
 ? asm_sysvec_apic_timer_interrupt+0x16/0x20
 ? smp_call_function_many_cond+0x1d8/0xbb0
 ? __pfx_do_kernel_range_flush+0x10/0x10
 on_each_cpu_cond_mask+0x20/0x40
 flush_tlb_kernel_range+0x19b/0x250
 ? srso_return_thunk+0x5/0x5f
 ? kasan_release_vmalloc+0xa7/0xc0
 purge_vmap_node+0x357/0x820
 ? __pfx_purge_vmap_node+0x10/0x10
 __purge_vmap_area_lazy+0x5b8/0xa10
 drain_vmap_area_work+0x21/0x30
 process_one_work+0x661/0x10b0
 worker_thread+0x844/0x10e0
 ? srso_return_thunk+0x5/0x5f
 ? __kthread_parkme+0x82/0x140
 ? __pfx_worker_thread+0x10/0x10
 kthread+0x2a5/0x370
 ? __pfx_kthread+0x10/0x10
 ret_from_fork+0x30/0x70
 ? __pfx_kthread+0x10/0x10
 ret_from_fork_asm+0x1a/0x30
 </TASK>

Debugging Analysis:

  1. The following ftrace log shows that the lockup CPU spends too much
     time iterating vmap_nodes and flushing TLB when purging vm_area
     structures. (Some info is trimmed).

     kworker: funcgraph_entry:              |  drain_vmap_area_work() {
     kworker: funcgraph_entry:              |   mutex_lock() {
     kworker: funcgraph_entry:  1.092 us    |     __cond_resched();
     kworker: funcgraph_exit:   3.306 us    |   }
     ...                                        ...
     kworker: funcgraph_entry:              |    flush_tlb_kernel_range() {
     ...                                          ...
     kworker: funcgraph_exit: # 7533.649 us |    }
     ...                                         ...
     kworker: funcgraph_entry:  2.344 us    |   mutex_unlock();
     kworker: funcgraph_exit: $ 23871554 us | }

     The drain_vmap_area_work() spends over 23 seconds.

     There are 2805 flush_tlb_kernel_range() calls in the ftrace log.
       * One is called in __purge_vmap_area_lazy().
       * Others are called by purge_vmap_node->kasan_release_vmalloc.
         purge_vmap_node() iteratively releases kasan vmalloc
         allocations and flushes TLB for each vmap_area.
           - [Rough calculation] Each flush_tlb_kernel_range() runs
             about 7.5ms.
               -- 2804 * 7.5ms = 21.03 seconds.
               -- That's why a soft lock is triggered.

  2. Extending the soft lockup time can work around the issue (For example,
     # echo 60 > /proc/sys/kernel/watchdog_thresh). This confirms the
     above-mentioned speculation: drain_vmap_area_work() spends too much
     time.

If we combine all TLB flush operations of the KASAN shadow virtual
address into one operation in the call path
'purge_vmap_node()->kasan_release_vmalloc()', the running time of
drain_vmap_area_work() can be saved greatly. The idea is from the
flush_tlb_kernel_range() call in __purge_vmap_area_lazy(). And, the
soft lockup won't not be triggered.

Here is the test result based on 6.10:

[6.10 wo/ the patch]
  1. ftrace latency profiling (record a trace if the latency > 20s).
     echo 20000000 > /sys/kernel/debug/tracing/tracing_thresh
     echo drain_vmap_area_work > /sys/kernel/debug/tracing/set_graph_function
     echo function_graph > /sys/kernel/debug/tracing/current_tracer
     echo 1 > /sys/kernel/debug/tracing/tracing_on

  2. Run `make -j $(nproc)` to compile the kernel source

  3. Once the soft lockup is reproduced, check the ftrace log:
     cat /sys/kernel/debug/tracing/trace
        # tracer: function_graph
        #
        # CPU  DURATION                  FUNCTION CALLS
        # |     |   |                     |   |   |   |
          76) $ 50412985 us |    } /* __purge_vmap_area_lazy */
          76) $ 50412997 us |  } /* drain_vmap_area_work */
          76) $ 29165911 us |    } /* __purge_vmap_area_lazy */
          76) $ 29165926 us |  } /* drain_vmap_area_work */
          91) $ 53629423 us |    } /* __purge_vmap_area_lazy */
          91) $ 53629434 us |  } /* drain_vmap_area_work */
          91) $ 28121014 us |    } /* __purge_vmap_area_lazy */
          91) $ 28121026 us |  } /* drain_vmap_area_work */

[6.10 w/ the patch]
  1. Repeat step 1-2 in "[6.10 wo/ the patch]"

  2. The soft lockup is not triggered and ftrace log is empty.
     cat /sys/kernel/debug/tracing/trace
     # tracer: function_graph
     #
     # CPU  DURATION                  FUNCTION CALLS
     # |     |   |                     |   |   |   |

  3. Setting 'tracing_thresh' to 10/5 seconds does not get any ftrace
     log.

  4. Setting 'tracing_thresh' to 1 second gets ftrace log.
     cat /sys/kernel/debug/tracing/trace
     # tracer: function_graph
     #
     # CPU  DURATION                  FUNCTION CALLS
     # |     |   |                     |   |   |   |
       23) $ 1074942 us  |    } /* __purge_vmap_area_lazy */
       23) $ 1074950 us  |  } /* drain_vmap_area_work */

  The worst execution time of drain_vmap_area_work() is about 1 second.

Link: https://lore.kernel.org/lkml/ZqFlawuVnOMY2k3E@pc638.lan/
Fixes: 282631cb2447 ("mm: vmalloc: remove global purge_vmap_area_root rb-tree")
Signed-off-by: Adrian Huang <ahuang12@lenovo.com>
Co-developed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
Signed-off-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
Tested-by: Jiwei Sun <sunjw10@lenovo.com>
---
 include/linux/kasan.h | 12 +++++++++---
 mm/kasan/shadow.c     | 14 ++++++++++----
 mm/vmalloc.c          | 34 ++++++++++++++++++++++++++--------
 3 files changed, 45 insertions(+), 15 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..2adea4fef153 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -29,6 +29,9 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 #define KASAN_VMALLOC_VM_ALLOC		((__force kasan_vmalloc_flags_t)0x02u)
 #define KASAN_VMALLOC_PROT_NORMAL	((__force kasan_vmalloc_flags_t)0x04u)
 
+#define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
+#define KASAN_VMALLOC_TLB_FLUSH  0x2 /* TLB flush */
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
@@ -511,7 +514,8 @@ void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
-			   unsigned long free_region_end);
+			   unsigned long free_region_end,
+			   unsigned long flags);
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -526,7 +530,8 @@ static inline int kasan_populate_vmalloc(unsigned long start,
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) { }
+					 unsigned long free_region_end,
+					 unsigned long flags) { }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -561,7 +566,8 @@ static inline int kasan_populate_vmalloc(unsigned long start,
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) { }
+					 unsigned long free_region_end,
+					 unsigned long flags) { }
 
 static inline void *kasan_unpoison_vmalloc(const void *start,
 					   unsigned long size,
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d6210ca48dda..88d1c9dcb507 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -489,7 +489,8 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
  */
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
-			   unsigned long free_region_end)
+			   unsigned long free_region_end,
+			   unsigned long flags)
 {
 	void *shadow_start, *shadow_end;
 	unsigned long region_start, region_end;
@@ -522,12 +523,17 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			__memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
 			return;
 		}
-		apply_to_existing_page_range(&init_mm,
+
+
+		if (flags & KASAN_VMALLOC_PAGE_RANGE)
+			apply_to_existing_page_range(&init_mm,
 					     (unsigned long)shadow_start,
 					     size, kasan_depopulate_vmalloc_pte,
 					     NULL);
-		flush_tlb_kernel_range((unsigned long)shadow_start,
-				       (unsigned long)shadow_end);
+
+		if (flags & KASAN_VMALLOC_TLB_FLUSH)
+			flush_tlb_kernel_range((unsigned long)shadow_start,
+					       (unsigned long)shadow_end);
 	}
 }
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index e34ea860153f..bc21d821d506 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2186,6 +2186,25 @@ decay_va_pool_node(struct vmap_node *vn, bool full_decay)
 	reclaim_list_global(&decay_list);
 }
 
+static void
+kasan_release_vmalloc_node(struct vmap_node *vn)
+{
+	struct vmap_area *va;
+	unsigned long start, end;
+
+	start = list_first_entry(&vn->purge_list, struct vmap_area, list)->va_start;
+	end = list_last_entry(&vn->purge_list, struct vmap_area, list)->va_end;
+
+	list_for_each_entry(va, &vn->purge_list, list) {
+		if (is_vmalloc_or_module_addr((void *) va->va_start))
+			kasan_release_vmalloc(va->va_start, va->va_end,
+				va->va_start, va->va_end,
+				KASAN_VMALLOC_PAGE_RANGE);
+	}
+
+	kasan_release_vmalloc(start, end, start, end, KASAN_VMALLOC_TLB_FLUSH);
+}
+
 static void purge_vmap_node(struct work_struct *work)
 {
 	struct vmap_node *vn = container_of(work,
@@ -2193,20 +2212,17 @@ static void purge_vmap_node(struct work_struct *work)
 	struct vmap_area *va, *n_va;
 	LIST_HEAD(local_list);
 
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_release_vmalloc_node(vn);
+
 	vn->nr_purged = 0;
 
 	list_for_each_entry_safe(va, n_va, &vn->purge_list, list) {
 		unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
-		unsigned long orig_start = va->va_start;
-		unsigned long orig_end = va->va_end;
 		unsigned int vn_id = decode_vn_id(va->flags);
 
 		list_del_init(&va->list);
 
-		if (is_vmalloc_or_module_addr((void *)orig_start))
-			kasan_release_vmalloc(orig_start, orig_end,
-					      va->va_start, va->va_end);
-
 		atomic_long_sub(nr, &vmap_lazy_nr);
 		vn->nr_purged++;
 
@@ -4726,7 +4742,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 				&free_vmap_area_list);
 		if (va)
 			kasan_release_vmalloc(orig_start, orig_end,
-				va->va_start, va->va_end);
+				va->va_start, va->va_end,
+				KASAN_VMALLOC_PAGE_RANGE | KASAN_VMALLOC_TLB_FLUSH);
 		vas[area] = NULL;
 	}
 
@@ -4776,7 +4793,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 				&free_vmap_area_list);
 		if (va)
 			kasan_release_vmalloc(orig_start, orig_end,
-				va->va_start, va->va_end);
+				va->va_start, va->va_end,
+				KASAN_VMALLOC_PAGE_RANGE | KASAN_VMALLOC_TLB_FLUSH);
 		vas[area] = NULL;
 		kfree(vms[area]);
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240726165246.31326-1-ahuang12%40lenovo.com.

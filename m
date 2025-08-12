Return-Path: <kasan-dev+bncBCKPFB7SXUERB6HQ5TCAMGQED7PGTKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EB13B22753
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:03 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-243013cd91bsf6485965ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003001; cv=pass;
        d=google.com; s=arc-20240605;
        b=GrO/r2jUiQrfN+2ADiv9qxdKHZKHK81s4d5OgvcwUhle2T/x411ohqcz7krltQ3jXe
         8jlRs4E9Zd1h1NFadZBWxnDgLnt6sR9My8J3+3Oqnr/Kg9uKk2+2m6p0fbYx8392K91B
         H73jph1iHgga67+vFKvA5CAk/xZCfVFhNWp8gz1vLkKLYSOeReNqDgWxClxFg5cDIBo1
         ZUE78rUl86SJOONUYxmFtsqAMfKvMOV/nBvyEzCVHkrA+iv7Y7LBno/xS85cxATfx72K
         9GcThLbL4w9LH24abob7I6TQGnzROGlrznHJNjN6DLEbtyOsbPh4DhFsRr3Xle4Ha2ze
         BSmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=26im9GN3gxzY3Ov5FOrsy9B0S0xiQHXTIJ9p9EbPp7k=;
        fh=bBkNG16Z3n9ji3AOcvWqe+PPw3CLu4fxbjG1uJ97gx8=;
        b=cpuAoisqlHowGFMrayK0WufKOqlz6j5jYiGbeBAv300jevoriOSYzxwgJ+l3TUW2o5
         RqKQi7UnIFJn6vUNgGGaFCf5g30nROZvzdEOR4XLfVjLkahD2SxFVR1UGIbrUccKrsm6
         838m5JXqWl/MYyM+M3e4NGbuD9YlUJqr+R75Bxp16sw5ijN8RkA24IkRbzskKmqubikp
         OKaCmvISqGP9zggSqyLCUupF6IXqiaSIMtFfdm6/HT9lHtMKjByuydDqCUbuLx1hExWJ
         v9z5X9GmVD3jqFobFA29Ejb0FBMtmXtObjfb+/6VYeFymPbi1qeUB3pkz1mGlVXMpIDr
         OD/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Aj4cGhxE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003001; x=1755607801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=26im9GN3gxzY3Ov5FOrsy9B0S0xiQHXTIJ9p9EbPp7k=;
        b=ZkrxVhRmV30Rp3jpEMf7QQSJ2Z0GzdjTtSaapETVJQb10zsN0amjoI+vOkBQs531o0
         2GYJPArYhWF5rbhBcXxrtWOGy7egtHxQXThnbNifoKIEyQB8mfoPnp2pTwbQ9qdb2ZmF
         oGxikvGF4MdCMsaoXLCBDT6QFSrEck2C4NzrWDYwUEdZhtvJpe+wmmLkue544k3lwXhn
         u4C88V6gEj93sOVdQiF9+zE95PrwQTmyjlElxg0nrMwtuT+bYeGhL62T+Qv5zGtZC+m1
         aaxBijSR0rvv4g2zFpBIndpuJE3HqVnLHRcBhZfkkVhiHzhe4Zsjn2eGO9k+9I9wkJ9R
         hD5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003001; x=1755607801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=26im9GN3gxzY3Ov5FOrsy9B0S0xiQHXTIJ9p9EbPp7k=;
        b=Y7dZxDKBsLk6DkiqbFUPuOaxMRalKS/og099zjyCGkv6GH1POxjTfMRSXKr8SsFa8N
         U1EqIrpnSkRSqbs2FKyc+b8E4KUpBu6tAdUF7RvmVHzlVTXAcu8hRzl/3GulgV3lRvnD
         FkoVJkVYlT7tN1Upxyq2Ez3uJM6PruvSNiKmuuedMO7NdP71q+kEefKuKnMNGW4c02vn
         KkbODqdH1m9t8zfpRtjnGt32DhYqotKwR1Lua/VBuzt61tHTVJTerpS/Q0J8BWz5LNpt
         K3T9h/y5XmLiZ+IvBcc2f9tq5Ch4/WV2AVSXNeEj3SBne9/SC1YBG26xoWlONuF/4lK9
         yPtg==
X-Forwarded-Encrypted: i=2; AJvYcCWT4308wddZyaWMWf6rfjvLIXzNnmhBElU8ZpNvV0CSaVFeOtI44V/RApvHZAD/xvODGgfE6g==@lfdr.de
X-Gm-Message-State: AOJu0YwLFPBOq8qwe4gWi1PyV6IbNeZBkYA/bGyGeWbJg1ue6M0gHUxi
	0o1+Qoo0bvF7roQweWajRmlxhDen0taVjlNTE21n/JMWkCOqDLZzRvPG
X-Google-Smtp-Source: AGHT+IHX8loXEpwePm9vYVtCqhoz0FiWqaBVqkeWqq4vKCHM776/oXHjmAghHsdgoV6qnO19alC9qg==
X-Received: by 2002:a17:903:3d07:b0:240:2eae:aecb with SMTP id d9443c01a7336-242fc39c641mr42362375ad.43.1755003000709;
        Tue, 12 Aug 2025 05:50:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdngr2OhLC5h07UCfsZsa66n/zjT9P7gUc0YRtBla3Z1A==
Received: by 2002:a17:902:ef4d:b0:234:9fce:56ab with SMTP id
 d9443c01a7336-242afcc7987ls55653975ad.1.-pod-prod-04-us; Tue, 12 Aug 2025
 05:49:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcm+RBFXuSr/iGRZ353JDc9XCTdKuaEw0/DLHzhf4855Gvgn71VKWUExy8+JwWV33nd0NcQ4A7AgI=@googlegroups.com
X-Received: by 2002:a17:903:2a8b:b0:240:6fc0:342c with SMTP id d9443c01a7336-242fc29a26emr47576685ad.11.1755002999355;
        Tue, 12 Aug 2025 05:49:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755002999; cv=none;
        d=google.com; s=arc-20240605;
        b=BR/vFmP+0dJvLhraiWUgtvuj46mwg1+txw97UDG1XUWu4OO0CwkGIsNoJA/K0NMdnC
         Pn47n9NFWimJRIKd6Of9rhjWGcacW3e1RJLMQPMFhkuMiKcGSDR4j5eWvzLUD3xRlH7f
         peEWIAjFSvJH+rYzJyDE0CkK32o/YuKV56SuC41s+AgTsnWkAcvE7+2OkhQqeZ9lydZR
         17flNr8U6l95y7D2D4DYKq/vOV8RaH4XoSjWSnqTdl8CQ1MTf1xaCTIIrKYxulUWl21T
         Ny30WLQ8vYe9UBsRQgLeTmjIuUPnpVurdWry123TTPd9vXmGH3MdJxWiqYYzS7mI9ucu
         4AcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3ZE38hmpc99A2k7OXVLbkRVM4tCEFDqNHUDB9CwwXLA=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=e0Rpa0g5L/gn23s9M/H6BIsKkQPdrrlKegwJ5ObSjpwYW6lylmq5vc2lSFDWbLrSxT
         qzo6wwFiylCMUMK5+86JxXGWT8SKrEgWeUX9Cqt8Koe0z2ZcxS9neWtvYXpujWoo+ctH
         5a4fEp4442+bZXLb2IItqCQc8mWgVdJSNrqGJIyFNR7nnA46XB0zoGAzbgz5S1Hsh82f
         XxE2CQ0gyQs88Q3RenLQIP4zk5EXDtBw+59ATP9BGmuI2RpCJXBdRNj0ubzR2lPggOYl
         1USMW90ZTAsQ6yeotQT3IQEAUrdgoCzyXZbFHNySBNk4741WvB9AqiDCoD2ML4yJcVSe
         tMfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Aj4cGhxE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si13854505ad.5.2025.08.12.05.49.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:49:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-659-o8yLrza-Pk6ODkq5WeTjFQ-1; Tue,
 12 Aug 2025 08:49:55 -0400
X-MC-Unique: o8yLrza-Pk6ODkq5WeTjFQ-1
X-Mimecast-MFC-AGG-ID: o8yLrza-Pk6ODkq5WeTjFQ_1755002993
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C3BB119560AF;
	Tue, 12 Aug 2025 12:49:51 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id CCF6730001A1;
	Tue, 12 Aug 2025 12:49:44 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
Date: Tue, 12 Aug 2025 20:49:29 +0800
Message-ID: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Aj4cGhxE;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Currently only hw_tags mode of kasan can be enabled or disabled with
kernel parameter kasan=on|off for built kernel. For kasan generic and
sw_tags mode, there's no way to disable them once kernel is built.
This is not convenient sometime, e.g in system kdump is configured.
When the 1st kernel has KASAN enabled and crash triggered to switch to
kdump kernel, the generic or sw_tags mode will cost much extra memory
for kasan shadow while in fact it's meaningless to have kasan in kdump
kernel.

So this patchset moves the kasan=on|off out of hw_tags scope and into
common code to make it visible in generic and sw_tags mode too. Then we
can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
kasan.

Changelog:
====
v1->v2:
- Add __ro_after_init for __ro_after_init, and remove redundant blank
  lines in mm/kasan/common.c. Thanks to Marco.
- Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
  this is found out by SeongJae and Lorenzo, and also reported by LKP
  report, thanks to them.
- Add a missing kasan_enabled() checking in kasan_report(). This will
  cause below KASAN report info even though kasan=off is set:
     ==================================================================
     BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
     Read of size 4 at addr ffff00005f747778 by task swapper/0/1
     
     CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMPT(voluntary) 
     Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2.10.20220810) 09/30/2022
     Call trace:
      show_stack+0x30/0x90 (C)
      dump_stack_lvl+0x7c/0xa0
      print_address_description.constprop.0+0x90/0x310
      print_report+0x104/0x1f0
      kasan_report+0xc8/0x110
      __asan_report_load4_noabort+0x20/0x30
      tick_program_event+0x130/0x150
      ......snip...
     ==================================================================

- Add jump_label_init() calling before kasan_init() in setup_arch() in these
  architectures: xtensa, arm. Because they currenly rely on
  jump_label_init() in main() which is a little late. Then the early static
  key kasan_flag_enabled in kasan_init() won't work.

- In UML architecture, change to enable kasan_flag_enabled in arch_mm_preinit()
  because kasan_init() is enabled before main(), there's no chance to operate
  on static key in kasan_init().

Test:
=====
In v1, I took test on x86_64 for generic mode, and on arm64 for
generic, sw_tags and hw_tags mode. All of them works well.

In v2, I only tested on arm64 for generic, sw_tags and hw_tags mode, it
works. For powerpc, I got a BOOK3S/64 machine, while it says
'KASAN not enabled as it requires radix' and KASAN is disabled. Will
look for other POWER machine to test this.
====

Baoquan He (12):
  mm/kasan: add conditional checks in functions to return directly if
    kasan is disabled
  mm/kasan: move kasan= code to common place
  mm/kasan/sw_tags: don't initialize kasan if it's disabled
  arch/arm: don't initialize kasan if it's disabled
  arch/arm64: don't initialize kasan if it's disabled
  arch/loongarch: don't initialize kasan if it's disabled
  arch/powerpc: don't initialize kasan if it's disabled
  arch/riscv: don't initialize kasan if it's disabled
  arch/x86: don't initialize kasan if it's disabled
  arch/xtensa: don't initialize kasan if it's disabled
  arch/um: don't initialize kasan if it's disabled
  mm/kasan: make kasan=on|off take effect for all three modes

 arch/arm/kernel/setup.c                |  6 +++++
 arch/arm/mm/kasan_init.c               |  6 +++++
 arch/arm64/mm/kasan_init.c             |  7 ++++++
 arch/loongarch/mm/kasan_init.c         |  5 ++++
 arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
 arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
 arch/riscv/mm/kasan_init.c             |  6 +++++
 arch/um/kernel/mem.c                   |  6 +++++
 arch/x86/mm/kasan_init_64.c            |  6 +++++
 arch/xtensa/kernel/setup.c             |  1 +
 arch/xtensa/mm/kasan_init.c            |  6 +++++
 include/linux/kasan-enabled.h          | 18 ++++++-------
 mm/kasan/common.c                      | 25 ++++++++++++++++++
 mm/kasan/generic.c                     | 20 +++++++++++++--
 mm/kasan/hw_tags.c                     | 35 ++------------------------
 mm/kasan/init.c                        |  6 +++++
 mm/kasan/quarantine.c                  |  3 +++
 mm/kasan/report.c                      |  4 ++-
 mm/kasan/shadow.c                      | 23 ++++++++++++++++-
 mm/kasan/sw_tags.c                     |  9 +++++++
 21 files changed, 165 insertions(+), 47 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-1-bhe%40redhat.com.

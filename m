Return-Path: <kasan-dev+bncBC4LXIPCY4NRBRNAYD4AKGQEHXGGLHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FFB7221E5E
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jul 2020 10:31:05 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id x186sf3999667pfd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jul 2020 01:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594888262; cv=pass;
        d=google.com; s=arc-20160816;
        b=KgQduR+GB5/pJe+CZCrl5cyBkj2/Kv9e93HZPX7lwrextoh/KGeoEIY+YxZJVNN4HP
         Sv8eGsMNwuCFZD5/GHF4RkLVX8voGhPaEOGQJq4FsraTNxABYKDZiwLWi4J/nFEePZFD
         M44NM7xvk1cHVqKRwnrmOrB60Xzw3MgGj2tbBwT6ENlqGLN878O40IU1w9/yLgcf3IO5
         HYzJ19GWtnlQynwQ/NIo5Y1bY6dTzr5qyD+Rf7ETPAXPRlvGBp5EM1iYUhhPtCvp3fTx
         3ir6G5JNDFuoheErxfl1b/FRu3CW6fGFwQs5EhS15UP8yCoK7VZuUwYQDOb2gbnbNHg/
         1zJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:ironport-sdr
         :ironport-sdr:sender:dkim-signature;
        bh=f+ePp4Euh0EBcW4SwU+y2FBUyyr6yfgu0kS/CfFZHKc=;
        b=aCjtoKEZXBYznkKHu67kkicxo1/WT+aaeE5y9TlHy6b8ThsGDvjL7L/taYJo9gH70b
         NQYANxxGT8wwGEaaBw2cTbD/fuFifBNb6PLsdRhO9eyJky5p5tZhacaGsev5V3KdWNLz
         g8Kltbg2n7BAZ9Y018fPtum78Rpv2iXChjJZgwYcHst4LoeTxmUP/Q1PDwqUjqr5HOi3
         DhGA/EisHPmqbZ5hEb53bi4m7KYLebxXyfPIcSuGM4wQPw6capgA/kVyOAzEp9CH4LuH
         dt8KY5Z79T7gnABNgrufCoE9E682wxle/5YphvDT+2S+AKNvroEuy+g2LTsXNK/UKMEc
         GTIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f+ePp4Euh0EBcW4SwU+y2FBUyyr6yfgu0kS/CfFZHKc=;
        b=cGFtu2gqUOSl8zGphLmx3ImNIn07AmQEh31YMwcMFi1z2tkNTC34Q8PSzkTb72gcUv
         ri229ETKzztn1xwUCGNFzBOliBCtxstXVatdQTQe8Ie3bACsGXAWuwKE/Aw6Tls76GP5
         yqNoQ3hoVouek6Bu/3oAQk8R9LQOKjO4yKBenxkvM4VnboupHfqYyXBt+C7ziMHbdlnL
         TKXwskW1nOpgMVZJDE+YI0l/zq9oBg1+Rmuk5wOSQjHWlW731WN76V2HTrcfNsO9l3iU
         X6yHaWQN5KXqD+Pi26s7AnSwyXEWT827P5ikJDIGmdpe96vHiN+n31nFHycNkmJB0OBo
         7cZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:date:from:to:cc
         :subject:message-id:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f+ePp4Euh0EBcW4SwU+y2FBUyyr6yfgu0kS/CfFZHKc=;
        b=dBGl6TdDOvQv9BaAQrJPBEa6YDsTkrbuwHyrSlw3jr+grtb1isdXwEUiQtg+XBv6MI
         cPcry1EkxDKWZKFTxosS75XbcZHt/92uPZzEUkjsV33RS61173c802dIlFp0/hFYa3wi
         ZGQBi2z3NUN1ZkOoMsV/4xpK0fHc1DLEvXYTIG2Ksj8/MD6rNviN/ENb5hhXg4r5EeQg
         dBfKmUvkoQiX+tLglmbPwvyDLRjs0TQexv7uaK1hi+a6/OtLoqH7ENxEq/nZynA+0sXK
         lVJfYPKp/1mNBJotG7MDcJFAT9jyIx8G6BgeUBre28NgjWzeZu2DM1vQrVxB9/5ZWFnT
         /B3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53195iaiiidbBesa7M3jIwiEnGBpm601filB2MjdcVnro/McLvV4
	ArTM2NNrlPVNrABAxBdSspQ=
X-Google-Smtp-Source: ABdhPJzVzcbB5z080LUaiI+yC6e0xvHDq4lGlui09n7OOVTagVrcyHN4fMHC7fUJRwLgHaN6J14DnQ==
X-Received: by 2002:a17:90a:c70e:: with SMTP id o14mr4029698pjt.70.1594888261071;
        Thu, 16 Jul 2020 01:31:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a16:: with SMTP id w22ls2506997pjn.1.canary-gmail;
 Thu, 16 Jul 2020 01:31:00 -0700 (PDT)
X-Received: by 2002:a17:902:6194:: with SMTP id u20mr2759663plj.333.1594888260323;
        Thu, 16 Jul 2020 01:31:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594888260; cv=none;
        d=google.com; s=arc-20160816;
        b=IKEYzLSrbDTbC9Exdh3f8UvqxtxAnay4C6aM+muMCKIKqJ2F07yHt/87eL6U5HA7wC
         bO6cnEBsmbq6Lx04J7JFdvAQQdv/5x70osDNZGxeyUTlM3/wdeKSdFXuYcq8A+JA+ftm
         z6SMDfQuWXAX+JLcTYxFY7ZNO20LRNKzdKcekB+ktiynoQlBoFy1EH1wm05WAJ7k7lDS
         ZQw94Al5IHrfYXHX+PIrMvjDYb3wva42miFBT2g9O6mW8XTIaNy3IbJO4YQam8kMnOUb
         P+a3UCwDk81KZKzRm56HNS1Ev1RQoTo0TesindRF9Hvd0EuetqxucV/MEOKR2oPiSXZc
         ilvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:ironport-sdr:ironport-sdr;
        bh=Dt2VACZkUWDW9dZ/RPpPpF0prkMpkIwOt2q0uT40mbA=;
        b=YmQPRH43zWGHpZV27cbJ9VTf951RukI1/B/BMoIGIx3/MtphS9P/572qE4X3mBFMPO
         L85RmzibVOXWzpK/yU4gtYVoOMv/EXpbYIlJYj9lb2PItYHNDgGwCieVZIVN+q7fz38k
         4cMdEsPW17KBesmO4TpM1pAEe2g7LK4WAG2EoBpcLBs5Sv9CkhcDs8ddRh9pyPcTV13m
         GXSU9zUotIF8VVjQyeVaI0CjzA7wcu0f7CDIMDEdS5nB3QrBEBZbTodqDKABI+aAwfLW
         o38k2HCD6UnQkHZMZBh6eFkk9NE09pjveiLQ4y6HNuQy6DGLccpqC4xcR06/kYr5QOX3
         0nFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id d16si307729pgk.2.2020.07.16.01.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Jul 2020 01:31:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
IronPort-SDR: esYHEaU/58rmYQXdwXL5OEvor9bTD5S/9ZoRJCV3VXPzFWRGWnWSCrMeRNzXsZCuHYM/Gc5slo
 Qf5GDbJVHRSA==
X-IronPort-AV: E=McAfee;i="6000,8403,9683"; a="147335118"
X-IronPort-AV: E=Sophos;i="5.75,358,1589266800"; 
   d="xz'?gz'50?scan'50,208,50";a="147335118"
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Jul 2020 01:30:52 -0700
IronPort-SDR: rT5OIJtfqSS3lrwO3kw1rdbOPsXN63N1Ui7dElxnQlISAk5yf6jyk1U4IUKRBx6tWFExbbqN0Q
 8l6dCD1vHnGw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.75,358,1589266800"; 
   d="xz'?gz'50?scan'50,208,50";a="486531022"
Received: from shao2-debian.sh.intel.com (HELO localhost) ([10.239.13.3])
  by fmsmga005.fm.intel.com with ESMTP; 16 Jul 2020 01:30:48 -0700
Date: Thu, 16 Jul 2020 16:30:21 +0800
From: kernel test robot <lkp@intel.com>
To: Daniel Axtens <dja@axtens.net>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	LKP <lkp@lists.01.org>
Subject: 0609ae011d ("x86/kasan: support KASAN_VMALLOC"): [   22.842515] BUG:
 stack guard page was hit at (____ptrval____) (stack is
 (____ptrval____)..(____ptrval____))
Message-ID: <20200716083021.GG3874@shao2-debian>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="vQ3nNXu39BMSLhj/"
Content-Disposition: inline
User-Agent: Heirloom mailx 12.5 6/20/10
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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


--vQ3nNXu39BMSLhj/
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Greetings,

0day kernel testing robot got the below dmesg and the first bad commit is

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git master

commit 0609ae011deb41c9629b7f5fd626dfa1ac9d16b0
Author:     Daniel Axtens <dja@axtens.net>
AuthorDate: Sat Nov 30 17:55:00 2019 -0800
Commit:     Linus Torvalds <torvalds@linux-foundation.org>
CommitDate: Sun Dec 1 12:59:06 2019 -0800

    x86/kasan: support KASAN_VMALLOC
    
    In the case where KASAN directly allocates memory to back vmalloc space,
    don't map the early shadow page over it.
    
    We prepopulate pgds/p4ds for the range that would otherwise be empty.
    This is required to get it synced to hardware on boot, allowing the
    lower levels of the page tables to be filled dynamically.
    
    Link: http://lkml.kernel.org/r/20191031093909.9228-5-dja@axtens.net
    Signed-off-by: Daniel Axtens <dja@axtens.net>
    Acked-by: Dmitry Vyukov <dvyukov@google.com>
    Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
    Cc: Alexander Potapenko <glider@google.com>
    Cc: Christophe Leroy <christophe.leroy@c-s.fr>
    Cc: Mark Rutland <mark.rutland@arm.com>
    Cc: Vasily Gorbik <gor@linux.ibm.com>
    Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
    Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>

eafb149ed7  fork: support VMAP_STACK with KASAN_VMALLOC
0609ae011d  x86/kasan: support KASAN_VMALLOC
+--------------------------------------------------------------------------------------------------------+------------+------------+
|                                                                                                        | eafb149ed7 | 0609ae011d |
+--------------------------------------------------------------------------------------------------------+------------+------------+
| boot_successes                                                                                         | 42         | 0          |
| boot_failures                                                                                          | 72         | 30         |
| PANIC:double_fault                                                                                     | 66         | 13         |
| RIP:do_async_page_fault                                                                                | 6          | 2          |
| Kernel_panic-not_syncing:Machine_halted                                                                | 66         | 13         |
| WARNING:at_kernel/locking/mutex.c:#mutex_trylock                                                       | 66         | 13         |
| RIP:mutex_trylock                                                                                      | 66         | 13         |
| WARNING:at_kernel/locking/mutex.c:#mutex_unlock                                                        | 66         | 13         |
| RIP:mutex_unlock                                                                                       | 66         | 13         |
| RIP:error_entry                                                                                        | 60         | 28         |
| BUG:kernel_reboot-without-warning_in_early-boot_stage,last_printk:Probing_EDD(edd=off_to_disable)...ok | 5          |            |
| BUG:kernel_hang_in_early-boot_stage,last_printk:Probing_EDD(edd=off_to_disable)...ok                   | 1          |            |
| BUG:stack_guard_page_was_hit_at(____ptrval____)(stack_is(____ptrval____)..(____ptrval____))            | 0          | 17         |
| RIP:free_reserved_area                                                                                 | 0          | 1          |
| Kernel_panic-not_syncing:Fatal_exception                                                               | 0          | 17         |
| RIP:memset_erms                                                                                        | 0          | 1          |
+--------------------------------------------------------------------------------------------------------+------------+------------+

If you fix the issue, kindly add following tag
Reported-by: kernel test robot <lkp@intel.com>

[   22.738580] kmemleak: Kernel memory leak detector initialized (mem pool available: 13997)
[   22.741160] kmemleak: Automatic memory scanning thread started
[   22.828498] Freeing unused decrypted memory: 2040K
[   22.839286] Freeing unused kernel image (initmem) memory: 1412K
[   22.840468] Write protecting the kernel read-only data: 45056k
[   22.842515] BUG: stack guard page was hit at (____ptrval____) (stack is (____ptrval____)..(____ptrval____))
[   22.844311] kernel stack overflow (double-fault): 0000 [#1] KASAN PTI
[   22.845514] CPU: 0 PID: 1 Comm: swapper Not tainted 5.4.0-09149-g0609ae011deb4 #1
[   22.848662] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
[   22.850781] RIP: 0010:do_async_page_fault+0x0/0x40
[   22.851668] Code: 05 f5 cf a0 02 85 c0 74 11 8b 05 ab cf a0 02 c7 05 a1 cf a0 02 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 <e8> cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 c7
[   22.855042] RSP: 0000:ffffc90000018000 EFLAGS: 00010046
[   22.856364] RAX: 0000000082c00ab0 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.857650] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018008
[   22.858917] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.860063] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.861244] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.862505] FS:  0000000000000000(0000) GS:ffffffff83c6f000(0000) knlGS:0000000000000000
[   22.863928] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   22.864971] CR2: ffffc90000017ff8 CR3: 0000000003c36001 CR4: 00000000000606f0
[   22.866465] Call Trace:
[   22.867852]  async_page_fault+0x2c/0x40
[   22.868637] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.869426] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.872742] RSP: 0000:ffffc900000180b0 EFLAGS: 00010002
[   22.873651] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.874930] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000180b8
[   22.876228] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.877517] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.878832] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.880404]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.881405]  async_page_fault+0x2c/0x40
[   22.882137] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.882986] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.886666] RSP: 0000:ffffc90000018160 EFLAGS: 00010002
[   22.887660] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.888960] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018168
[   22.890255] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.891858] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.893549] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.895452]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.896716]  async_page_fault+0x2c/0x40
[   22.897448] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.898685] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.902622] RSP: 0000:ffffc90000018210 EFLAGS: 00010002
[   22.903910] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.905511] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018218
[   22.907311] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.909055] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.910453] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.912034]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.913034]  async_page_fault+0x2c/0x40
[   22.913961] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.915074] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.919044] RSP: 0000:ffffc900000182c0 EFLAGS: 00010002
[   22.920394] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.921863] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000182c8
[   22.923594] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.924996] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.926596] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.928007]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.929077]  async_page_fault+0x2c/0x40
[   22.929978] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.931235] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.934922] RSP: 0000:ffffc90000018370 EFLAGS: 00010002
[   22.935946] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.937329] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018378
[   22.938909] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.940069] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.941222] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.942631]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.944098]  async_page_fault+0x2c/0x40
[   22.944858] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.945708] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.950049] RSP: 0000:ffffc90000018420 EFLAGS: 00010002
[   22.951335] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.952790] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018428
[   22.954565] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.956136] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.957795] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.959533]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.960695]  async_page_fault+0x2c/0x40
[   22.961847] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.965206] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.969159] RSP: 0000:ffffc900000184d0 EFLAGS: 00010002
[   22.970477] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.972162] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000184d8
[   22.973592] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.975083] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.976719] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.978443]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.979694]  async_page_fault+0x2c/0x40
[   22.980808] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.982063] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   22.986407] RSP: 0000:ffffc90000018580 EFLAGS: 00010002
[   22.987516] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   22.988771] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018588
[   22.990183] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   22.992038] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   22.993940] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   22.995835]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   22.997002]  async_page_fault+0x2c/0x40
[   22.997993] RIP: 0010:do_async_page_fault+0x15/0x40
[   22.999165] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.003117] RSP: 0000:ffffc90000018630 EFLAGS: 00010002
[   23.004212] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.005569] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018638
[   23.007575] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.008857] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.010439] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.012293]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.013672]  async_page_fault+0x2c/0x40
[   23.014726] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.015910] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.020420] RSP: 0000:ffffc900000186e0 EFLAGS: 00010002
[   23.021668] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.023181] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000186e8
[   23.024797] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.026184] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.027809] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.029340]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.030578]  async_page_fault+0x2c/0x40
[   23.031400] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.032537] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.036502] RSP: 0000:ffffc90000018790 EFLAGS: 00010002
[   23.037403] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.038847] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018798
[   23.040090] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.041462] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.045835] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.047135]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.048256]  async_page_fault+0x2c/0x40
[   23.049096] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.050025] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.053505] RSP: 0000:ffffc90000018840 EFLAGS: 00010002
[   23.054424] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.055677] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018848
[   23.057083] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.058433] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.059762] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.061467]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.062836]  async_page_fault+0x2c/0x40
[   23.063527] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.064457] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.068286] RSP: 0000:ffffc900000188f0 EFLAGS: 00010002
[   23.069300] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.070446] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000188f8
[   23.071636] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.072839] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.074006] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.075312]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.076288]  async_page_fault+0x2c/0x40
[   23.076939] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.077789] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.080999] RSP: 0000:ffffc900000189a0 EFLAGS: 00010002
[   23.081903] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.083168] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc900000189a8
[   23.084333] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.085654] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.086958] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.088157]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.089089]  async_page_fault+0x2c/0x40
[   23.089775] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.090571] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.093806] RSP: 0000:ffffc90000018a50 EFLAGS: 00010002
[   23.094913] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.096109] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018a58
[   23.097482] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.100820] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.102051] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.103241]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.104372]  async_page_fault+0x2c/0x40
[   23.105002] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.105904] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.109210] RSP: 0000:ffffc90000018b00 EFLAGS: 00010002
[   23.110113] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.111577] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018b08
[   23.112800] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.113965] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.115392] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.116591]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.117634]  async_page_fault+0x2c/0x40
[   23.118433] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.119439] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.122680] RSP: 0000:ffffc90000018bb0 EFLAGS: 00010002
[   23.123751] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.124974] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018bb8
[   23.126372] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.127524] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.128732] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.130228]  ? restore_regs_and_return_to_kernel+0x2c/0x2c
[   23.131140]  async_page_fault+0x2c/0x40
[   23.131948] RIP: 0010:do_async_page_fault+0x15/0x40
[   23.132886] Code: 00 00 00 00 c3 31 c0 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 e8 cb 43 b4 01 8b 05 c5 cf a0 02 85 c0 74 21 8b 05 7b cf a0 02 <c7> 05 71 cf a0 02 00 00 00 00 83 f8 01 74 11 83 f8 02 75 07 89 d7
[   23.136283] RSP: 0000:ffffc90000018c60 EFLAGS: 00010002
[   23.137285] RAX: 0000000000000002 RBX: 0000000000000000 RCX: ffffffff82c00ab0
[   23.138495] RDX: ffffffff83aca100 RSI: 0000000000000003 RDI: ffffc90000018c68
[   23.139723] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   23.140805] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff83aca100
[   23.142024] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   23.143135]  ? restore_regs_and_return_to_kernel+0x2c/0x2c

                                                          # HH:MM RESULT GOOD BAD GOOD_BUT_DIRTY DIRTY_NOT_BAD
git bisect start v5.5 v5.4 --
git bisect  bad ae4b064e2a616b545acf02b8f50cc513b32c7522  # 15:32  B      3     1    3   3  Merge tag 'afs-fixes-20191211' of git://git.kernel.org/pub/scm/linux/kernel/git/dhowells/linux-fs
git bisect good 0da522107e5d9c000a4871d52e570912aa1225a2  # 16:44  G     19     0    8   8  Merge tag 'compat-ioctl-5.5' of git://git.kernel.org:/pub/scm/linux/kernel/git/arnd/playground
git bisect  bad aedc0650f9135f3b92b39cbed1a8fe98d8088825  # 17:13  B      1     3    1   1  Merge tag 'for-linus' of git://git.kernel.org/pub/scm/virt/kvm/kvm
git bisect  bad 937d6eefc716a9071f0e3bada19200de1bb9d048  # 19:31  B      3     1    3   3  Merge tag 'docs-5.5a' of git://git.lwn.net/linux
git bisect good 5e3b06d3bbdfb875ec6ad5e5fa5d86b0e79ea065  # 21:17  G     18     0   11  11  Merge tag 'rproc-v5.5' of git://git.kernel.org/pub/scm/linux/kernel/git/andersson/remoteproc
git bisect good e5b3fc125d768eacd73bb4dc5019f0ce95635af4  # 22:26  G     18     0   14  14  Merge branch 'x86-urgent-for-linus' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
git bisect  bad a5255bc31673c72e264d837cd13cd3085d72cb58  # 23:13  B      1     2    1   1  Merge tag 'dmaengine-5.5-rc1' of git://git.infradead.org/users/vkoul/slave-dma
git bisect good c3bfc5dd73c6f519ff0636d4e709515f06edef78  # 00:19  G     18     0   12  12  Merge git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net
git bisect  bad 596cf45cbf6e4fa7bcb0df33e373a7d062b644b5  # 00:44  B      4     5    4   4  Merge branch 'akpm' (patches from Andrew)
git bisect good 746dd4012d215b53152f0001a48856e41ea31730  # 01:45  G     18     0    9   9  selftests: vm: add fragment CONFIG_TEST_VMALLOC
git bisect  bad 997cdcb068eb58d37f9f9b1d219368000066d272  # 02:14  B      1     5    1   1  powerpc/mm: remove pmd_huge/pud_huge stubs and include hugetlb.h
git bisect  bad d2af339706be318dadcbe14c8935426ff401d7b1  # 02:44  B      9     3    9   9  mm: vmscan: replace shrink_node() loop with a retry jump
git bisect good eafb149ed73a8bb8359c0ce027b98acd4e95b070  # 04:33  G     28     0   23  23  fork: support VMAP_STACK with KASAN_VMALLOC
git bisect  bad 5e27a2df03b8933aa7c1579816ecb6a071bb0e0d  # 05:37  B      2     1    2   2  mm/page_alloc: add alloc_contig_pages()
git bisect  bad 0609ae011deb41c9629b7f5fd626dfa1ac9d16b0  # 06:33  B      3     2    3   3  x86/kasan: support KASAN_VMALLOC
# first bad commit: [0609ae011deb41c9629b7f5fd626dfa1ac9d16b0] x86/kasan: support KASAN_VMALLOC
git bisect good eafb149ed73a8bb8359c0ce027b98acd4e95b070  # 07:11  G     84     0   49  72  fork: support VMAP_STACK with KASAN_VMALLOC
# extra tests with debug options
# extra tests on head commit of linus/master
# 119: [994e99a96c9b502b3f6ee411457007cd52051cf5] Merge tag 'platform-drivers-x86-v5.8-2' of git://git.infradead.org/linux-platform-drivers-x86 into master
# extra tests on linus/master
# duplicated: [994e99a96c9b502b3f6ee411457007cd52051cf5] Merge tag 'platform-drivers-x86-v5.8-2' of git://git.infradead.org/linux-platform-drivers-x86 into master
# extra tests on linux-next/master
# 119: [ca0e494af5edb59002665bf12871e94b4163a257] Add linux-next specific files for 20200715

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/lkp@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200716083021.GG3874%40shao2-debian.

--vQ3nNXu39BMSLhj/
Content-Type: application/gzip
Content-Disposition: attachment; filename="dmesg-yocto-vm-yocto-11:20200716063439:x86_64-randconfig-r022-20200715:5.4.0-09149-g0609ae011deb4:1.gz"
Content-Transfer-Encoding: base64

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
2m+//AGbZ/8DJ7idQtMIAwA=

--vQ3nNXu39BMSLhj/
Content-Type: application/gzip
Content-Disposition: attachment; filename="dmesg-yocto-vm-yocto-12:20200716064026:x86_64-randconfig-r022-20200715:5.4.0-09148-geafb149ed73a8b:1.gz"
Content-Transfer-Encoding: base64

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

--vQ3nNXu39BMSLhj/
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename="reproduce-yocto-vm-yocto-11:20200716063439:x86_64-randconfig-r022-20200715:5.4.0-09149-g0609ae011deb4:1"

#!/bin/bash

kernel=$1
initrd=yocto-x86_64-trinity.cgz

wget --no-clobber https://download.01.org/0day-ci/lkp-qemu/osimage/yocto/$initrd

kvm=(
	qemu-system-x86_64
	-enable-kvm
	-cpu Haswell,+smep,+smap
	-kernel $kernel
	-initrd $initrd
	-m 16384
	-smp 2
	-device e1000,netdev=net0
	-netdev user,id=net0,hostfwd=tcp::32032-:22
	-boot order=nc
	-no-reboot
	-watchdog i6300esb
	-watchdog-action debug
	-rtc base=localtime
	-serial stdio
	-display none
	-monitor null
)

append=(
	root=/dev/ram0
	hung_task_panic=1
	debug
	apic=debug
	sysrq_always_enabled
	rcupdate.rcu_cpu_stall_timeout=100
	net.ifnames=0
	printk.devkmsg=on
	panic=-1
	softlockup_panic=1
	nmi_watchdog=panic
	oops=panic
	load_ramdisk=2
	prompt_ramdisk=0
	drbd.minor_count=8
	systemd.log_level=err
	ignore_loglevel
	console=tty0
	earlyprintk=ttyS0,115200
	console=ttyS0,115200
	vga=normal
	rw
	rcuperf.shutdown=0
	watchdog_thresh=60
)

"${kvm[@]}" -append "${append[*]}"

--vQ3nNXu39BMSLhj/
Content-Type: application/x-xz
Content-Disposition: attachment; filename="ca0882e5aaa13ab7eaf1e5d85f8faadd1d520973:clang-11:x86_64-randconfig-r022-20200715:BUG:stack_guard_page_was_hit_at_____ptrval______stack_is_____ptrval_____.._____ptrval______.xz"
Content-Transfer-Encoding: base64

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
RjqXVgABiYYB9OoNTQ8dFLHEZ/sCAAAAAARZWg==

--vQ3nNXu39BMSLhj/
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename="config-5.4.0-09149-g0609ae011deb4"

#
# Automatically generated file; DO NOT EDIT.
# Linux/x86_64 5.4.0 Kernel Configuration
#

#
# Compiler: clang version 11.0.0 (git://gitmirror/llvm_project 02946de3802d3bc65bc9f2eb9b8d4969b5a7add8)
#
CONFIG_GCC_VERSION=0
CONFIG_CC_IS_CLANG=y
CONFIG_CLANG_VERSION=110000
CONFIG_CC_CAN_LINK=y
CONFIG_CC_HAS_ASM_GOTO=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_EXTABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_BROKEN_ON_SMP=y
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
# CONFIG_HEADER_TEST is not set
CONFIG_LOCALVERSION=""
CONFIG_LOCALVERSION_AUTO=y
CONFIG_BUILD_SALT=""
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_BZIP2=y
CONFIG_HAVE_KERNEL_LZMA=y
CONFIG_HAVE_KERNEL_XZ=y
CONFIG_HAVE_KERNEL_LZO=y
CONFIG_HAVE_KERNEL_LZ4=y
# CONFIG_KERNEL_GZIP is not set
# CONFIG_KERNEL_BZIP2 is not set
CONFIG_KERNEL_LZMA=y
# CONFIG_KERNEL_XZ is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
CONFIG_DEFAULT_HOSTNAME="(none)"
# CONFIG_SWAP is not set
# CONFIG_SYSVIPC is not set
# CONFIG_POSIX_MQUEUE is not set
CONFIG_CROSS_MEMORY_ATTACH=y
# CONFIG_USELIB is not set
# CONFIG_AUDIT is not set
CONFIG_HAVE_ARCH_AUDITSYSCALL=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_CHIP=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_SIM=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_GENERIC_MSI_IRQ_DOMAIN=y
CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=y
CONFIG_GENERIC_IRQ_RESERVATION_MODE=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
# CONFIG_GENERIC_IRQ_DEBUGFS is not set
# end of IRQ subsystem

CONFIG_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_CLOCKSOURCE_DATA=y
CONFIG_ARCH_CLOCKSOURCE_INIT=y
CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=y
CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=y
CONFIG_GENERIC_CMOS_UPDATE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
CONFIG_NO_HZ_IDLE=y
# CONFIG_NO_HZ is not set
CONFIG_HIGH_RES_TIMERS=y
# end of Timers subsystem

# CONFIG_PREEMPT_NONE is not set
CONFIG_PREEMPT_VOLUNTARY=y
# CONFIG_PREEMPT is not set
CONFIG_PREEMPT_COUNT=y

#
# CPU/Task time and stats accounting
#
CONFIG_TICK_CPU_ACCOUNTING=y
# CONFIG_VIRT_CPU_ACCOUNTING_GEN is not set
# CONFIG_IRQ_TIME_ACCOUNTING is not set
# CONFIG_BSD_PROCESS_ACCT is not set
# CONFIG_TASKSTATS is not set
CONFIG_PSI=y
# CONFIG_PSI_DEFAULT_DISABLED is not set
# end of CPU/Task time and stats accounting

#
# RCU Subsystem
#
CONFIG_TINY_RCU=y
CONFIG_RCU_EXPERT=y
CONFIG_SRCU=y
CONFIG_TINY_SRCU=y
# end of RCU Subsystem

CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_IKHEADERS=y
CONFIG_LOG_BUF_SHIFT=20
CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=13
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=y

#
# Scheduler features
#
# end of Scheduler features

CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_CC_HAS_INT128=y
CONFIG_ARCH_SUPPORTS_INT128=y
CONFIG_CGROUPS=y
# CONFIG_MEMCG is not set
CONFIG_BLK_CGROUP=y
# CONFIG_CGROUP_SCHED is not set
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_FREEZER=y
# CONFIG_CGROUP_DEVICE is not set
# CONFIG_CGROUP_CPUACCT is not set
# CONFIG_CGROUP_PERF is not set
# CONFIG_CGROUP_BPF is not set
CONFIG_CGROUP_DEBUG=y
# CONFIG_NAMESPACES is not set
CONFIG_CHECKPOINT_RESTORE=y
# CONFIG_SCHED_AUTOGROUP is not set
# CONFIG_SYSFS_DEPRECATED is not set
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
# CONFIG_RD_XZ is not set
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_SYSCTL=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_HAVE_PCSPKR_PLATFORM=y
CONFIG_BPF=y
CONFIG_EXPERT=y
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_SYSFS_SYSCALL=y
# CONFIG_SYSCTL_SYSCALL is not set
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_PRINTK_NMI=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
CONFIG_PCSPKR_PLATFORM=y
# CONFIG_BASE_FULL is not set
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
# CONFIG_AIO is not set
CONFIG_IO_URING=y
# CONFIG_ADVISE_SYSCALLS is not set
CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_BPF_SYSCALL=y
# CONFIG_USERFAULTFD is not set
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
# CONFIG_RSEQ is not set
# CONFIG_EMBEDDED is not set
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_PERF_USE_VMALLOC=y
CONFIG_PC104=y

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
CONFIG_DEBUG_PERF_USE_VMALLOC=y
# end of Kernel Performance Events And Counters

# CONFIG_VM_EVENT_COUNTERS is not set
CONFIG_SLUB_DEBUG=y
# CONFIG_COMPAT_BRK is not set
# CONFIG_SLAB is not set
CONFIG_SLUB=y
# CONFIG_SLOB is not set
CONFIG_SLAB_MERGE_DEFAULT=y
# CONFIG_SLAB_FREELIST_RANDOM is not set
# CONFIG_SLAB_FREELIST_HARDENED is not set
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y
# end of General setup

CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_INSTRUCTION_DECODER=y
CONFIG_OUTPUT_FORMAT="elf64-x86-64"
CONFIG_ARCH_DEFCONFIG="arch/x86/configs/x86_64_defconfig"
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_MMU=y
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_GENERIC_ISA_DMA=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_ARCH_MAY_HAVE_PC_FDC=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_ARCH_HAS_CPU_RELAX=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_FILTER_PGPROT=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_SUSPEND_POSSIBLE=y
CONFIG_ARCH_WANT_GENERAL_HUGETLB=y
CONFIG_ZONE_DMA32=y
CONFIG_AUDIT_ARCH=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_DYNAMIC_PHYSICAL_MASK=y
CONFIG_PGTABLE_LEVELS=5
CONFIG_CC_HAS_SANE_STACKPROTECTOR=y

#
# Processor type and features
#
# CONFIG_ZONE_DMA is not set
# CONFIG_SMP is not set
CONFIG_X86_FEATURE_NAMES=y
# CONFIG_X86_X2APIC is not set
CONFIG_X86_MPPARSE=y
# CONFIG_GOLDFISH is not set
# CONFIG_RETPOLINE is not set
CONFIG_X86_CPU_RESCTRL=y
CONFIG_X86_EXTENDED_PLATFORM=y
# CONFIG_X86_GOLDFISH is not set
# CONFIG_X86_INTEL_MID is not set
# CONFIG_X86_INTEL_LPSS is not set
# CONFIG_X86_AMD_PLATFORM_DEVICE is not set
CONFIG_IOSF_MBI=y
CONFIG_IOSF_MBI_DEBUG=y
CONFIG_X86_SUPPORTS_MEMORY_FAILURE=y
# CONFIG_SCHED_OMIT_FRAME_POINTER is not set
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
# CONFIG_PARAVIRT_DEBUG is not set
# CONFIG_XEN is not set
CONFIG_KVM_GUEST=y
CONFIG_ARCH_CPUIDLE_HALTPOLL=y
# CONFIG_PVH is not set
# CONFIG_KVM_DEBUG_FS is not set
# CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
CONFIG_PARAVIRT_CLOCK=y
# CONFIG_JAILHOUSE_GUEST is not set
# CONFIG_ACRN_GUEST is not set
# CONFIG_MK8 is not set
# CONFIG_MPSC is not set
# CONFIG_MCORE2 is not set
# CONFIG_MATOM is not set
CONFIG_GENERIC_CPU=y
CONFIG_X86_INTERNODE_CACHE_SHIFT=6
CONFIG_X86_L1_CACHE_SHIFT=6
CONFIG_X86_TSC=y
CONFIG_X86_CMPXCHG64=y
CONFIG_X86_CMOV=y
CONFIG_X86_MINIMUM_CPU_FAMILY=64
CONFIG_X86_DEBUGCTLMSR=y
# CONFIG_PROCESSOR_SELECT is not set
CONFIG_CPU_SUP_INTEL=y
CONFIG_CPU_SUP_AMD=y
CONFIG_CPU_SUP_HYGON=y
CONFIG_CPU_SUP_CENTAUR=y
CONFIG_CPU_SUP_ZHAOXIN=y
CONFIG_HPET_TIMER=y
CONFIG_DMI=y
# CONFIG_GART_IOMMU is not set
CONFIG_NR_CPUS_RANGE_BEGIN=1
CONFIG_NR_CPUS_RANGE_END=1
CONFIG_NR_CPUS_DEFAULT=1
CONFIG_NR_CPUS=1
CONFIG_UP_LATE_INIT=y
CONFIG_X86_LOCAL_APIC=y
CONFIG_X86_IO_APIC=y
# CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS is not set
CONFIG_X86_MCE=y
# CONFIG_X86_MCELOG_LEGACY is not set
CONFIG_X86_MCE_INTEL=y
# CONFIG_X86_MCE_AMD is not set
CONFIG_X86_MCE_THRESHOLD=y
CONFIG_X86_MCE_INJECT=m
CONFIG_X86_THERMAL_VECTOR=y

#
# Performance monitoring
#
# CONFIG_PERF_EVENTS_INTEL_UNCORE is not set
# CONFIG_PERF_EVENTS_INTEL_RAPL is not set
# CONFIG_PERF_EVENTS_INTEL_CSTATE is not set
# CONFIG_PERF_EVENTS_AMD_POWER is not set
# end of Performance monitoring

CONFIG_X86_VSYSCALL_EMULATION=y
CONFIG_X86_IOPL_IOPERM=y
CONFIG_I8K=y
# CONFIG_MICROCODE is not set
CONFIG_X86_MSR=y
# CONFIG_X86_CPUID is not set
CONFIG_X86_5LEVEL=y
CONFIG_X86_DIRECT_GBPAGES=y
CONFIG_X86_CPA_STATISTICS=y
CONFIG_AMD_MEM_ENCRYPT=y
# CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT is not set
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_ARCH_SPARSEMEM_DEFAULT=y
CONFIG_ARCH_SELECT_MEMORY_MODEL=y
CONFIG_ARCH_MEMORY_PROBE=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
# CONFIG_X86_PMEM_LEGACY is not set
CONFIG_X86_CHECK_BIOS_CORRUPTION=y
# CONFIG_X86_BOOTPARAM_MEMORY_CORRUPTION_CHECK is not set
CONFIG_X86_RESERVE_LOW=64
CONFIG_MTRR=y
# CONFIG_MTRR_SANITIZER is not set
# CONFIG_X86_PAT is not set
# CONFIG_ARCH_RANDOM is not set
# CONFIG_X86_SMAP is not set
# CONFIG_X86_UMIP is not set
# CONFIG_X86_INTEL_MPX is not set
# CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS is not set
CONFIG_X86_INTEL_TSX_MODE_OFF=y
# CONFIG_X86_INTEL_TSX_MODE_ON is not set
# CONFIG_X86_INTEL_TSX_MODE_AUTO is not set
# CONFIG_EFI is not set
CONFIG_SECCOMP=y
# CONFIG_HZ_100 is not set
# CONFIG_HZ_250 is not set
CONFIG_HZ_300=y
# CONFIG_HZ_1000 is not set
CONFIG_HZ=300
CONFIG_SCHED_HRTICK=y
CONFIG_KEXEC=y
# CONFIG_KEXEC_FILE is not set
# CONFIG_CRASH_DUMP is not set
CONFIG_PHYSICAL_START=0x1000000
# CONFIG_RELOCATABLE is not set
CONFIG_PHYSICAL_ALIGN=0x200000
CONFIG_DYNAMIC_MEMORY_LAYOUT=y
# CONFIG_COMPAT_VDSO is not set
CONFIG_LEGACY_VSYSCALL_EMULATE=y
# CONFIG_LEGACY_VSYSCALL_XONLY is not set
# CONFIG_LEGACY_VSYSCALL_NONE is not set
# CONFIG_CMDLINE_BOOL is not set
# CONFIG_MODIFY_LDT_SYSCALL is not set
CONFIG_HAVE_LIVEPATCH=y
# end of Processor type and features

CONFIG_ARCH_HAS_ADD_PAGES=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y

#
# Power management and ACPI options
#
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
# CONFIG_SUSPEND_SKIP_SYNC is not set
CONFIG_PM_SLEEP=y
CONFIG_PM_AUTOSLEEP=y
CONFIG_PM_WAKELOCKS=y
CONFIG_PM_WAKELOCKS_LIMIT=100
CONFIG_PM_WAKELOCKS_GC=y
CONFIG_PM=y
# CONFIG_PM_DEBUG is not set
CONFIG_PM_CLK=y
CONFIG_PM_GENERIC_DOMAINS=y
# CONFIG_WQ_POWER_EFFICIENT_DEFAULT is not set
CONFIG_PM_GENERIC_DOMAINS_SLEEP=y
CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_LEGACY_TABLES_LOOKUP=y
CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=y
CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=y
# CONFIG_ACPI_DEBUGGER is not set
CONFIG_ACPI_SPCR_TABLE=y
CONFIG_ACPI_LPIT=y
CONFIG_ACPI_SLEEP=y
# CONFIG_ACPI_PROCFS_POWER is not set
CONFIG_ACPI_REV_OVERRIDE_POSSIBLE=y
# CONFIG_ACPI_EC_DEBUGFS is not set
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=m
CONFIG_ACPI_FAN=y
# CONFIG_ACPI_TAD is not set
# CONFIG_ACPI_DOCK is not set
CONFIG_ACPI_CPU_FREQ_PSS=y
CONFIG_ACPI_PROCESSOR_CSTATE=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_PROCESSOR=y
# CONFIG_ACPI_IPMI is not set
# CONFIG_ACPI_PROCESSOR_AGGREGATOR is not set
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_CUSTOM_DSDT_FILE=""
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
# CONFIG_ACPI_DEBUG is not set
# CONFIG_ACPI_PCI_SLOT is not set
# CONFIG_ACPI_CONTAINER is not set
# CONFIG_ACPI_HOTPLUG_MEMORY is not set
CONFIG_ACPI_HOTPLUG_IOAPIC=y
# CONFIG_ACPI_SBS is not set
# CONFIG_ACPI_HED is not set
# CONFIG_ACPI_CUSTOM_METHOD is not set
# CONFIG_ACPI_REDUCED_HARDWARE_ONLY is not set
# CONFIG_ACPI_NFIT is not set
CONFIG_HAVE_ACPI_APEI=y
CONFIG_HAVE_ACPI_APEI_NMI=y
# CONFIG_ACPI_APEI is not set
# CONFIG_DPTF_POWER is not set
# CONFIG_PMIC_OPREGION is not set
# CONFIG_ACPI_CONFIGFS is not set
CONFIG_X86_PM_TIMER=y
# CONFIG_SFI is not set

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
# CONFIG_CPU_FREQ_STAT is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
CONFIG_CPU_FREQ_DEFAULT_GOV_ONDEMAND=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_CONSERVATIVE is not set
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
# CONFIG_CPU_FREQ_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_GOV_USERSPACE is not set
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y

#
# CPU frequency scaling drivers
#
# CONFIG_X86_INTEL_PSTATE is not set
# CONFIG_X86_PCC_CPUFREQ is not set
# CONFIG_X86_ACPI_CPUFREQ is not set
# CONFIG_X86_SPEEDSTEP_CENTRINO is not set
CONFIG_X86_P4_CLOCKMOD=m

#
# shared options
#
CONFIG_X86_SPEEDSTEP_LIB=m
# end of CPU Frequency scaling

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
# CONFIG_CPU_IDLE_GOV_LADDER is not set
CONFIG_CPU_IDLE_GOV_MENU=y
# CONFIG_CPU_IDLE_GOV_TEO is not set
# CONFIG_CPU_IDLE_GOV_HALTPOLL is not set
CONFIG_HALTPOLL_CPUIDLE=y
# end of CPU Idle

# CONFIG_INTEL_IDLE is not set
# end of Power management and ACPI options

#
# Bus options (PCI etc.)
#
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_MMCONF_FAM10H=y
CONFIG_PCI_CNB20LE_QUIRK=y
CONFIG_ISA_BUS=y
CONFIG_ISA_DMA_API=y
CONFIG_AMD_NB=y
CONFIG_X86_SYSFB=y
# end of Bus options (PCI etc.)

#
# Binary Emulations
#
CONFIG_IA32_EMULATION=y
CONFIG_X86_X32=y
CONFIG_COMPAT_32=y
CONFIG_COMPAT=y
CONFIG_COMPAT_FOR_U64_ALIGNMENT=y
# end of Binary Emulations

CONFIG_X86_DEV_DMA_OPS=y

#
# Firmware Drivers
#
CONFIG_EDD=y
# CONFIG_EDD_OFF is not set
# CONFIG_FIRMWARE_MEMMAP is not set
# CONFIG_DMIID is not set
CONFIG_DMI_SYSFS=y
CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=y
# CONFIG_ISCSI_IBFT is not set
CONFIG_FW_CFG_SYSFS=m
# CONFIG_FW_CFG_SYSFS_CMDLINE is not set
CONFIG_GOOGLE_FIRMWARE=y
# CONFIG_GOOGLE_SMI is not set
# CONFIG_GOOGLE_COREBOOT_TABLE is not set
# CONFIG_GOOGLE_MEMCONSOLE_X86_LEGACY is not set
CONFIG_EFI_EARLYCON=y

#
# Tegra firmware driver
#
# end of Tegra firmware driver
# end of Firmware Drivers

CONFIG_HAVE_KVM=y
CONFIG_VIRTUALIZATION=y
# CONFIG_KVM is not set
# CONFIG_VHOST_NET is not set
# CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set

#
# General architecture-dependent options
#
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
CONFIG_OPROFILE=y
# CONFIG_OPROFILE_EVENT_MULTIPLEX is not set
CONFIG_HAVE_OPROFILE=y
CONFIG_OPROFILE_NMI_TIMER=y
# CONFIG_KPROBES is not set
# CONFIG_JUMP_LABEL is not set
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_ARCH_USE_BUILTIN_BSWAP=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_SET_DIRECT_MAP=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=y
CONFIG_HAVE_ASM_MODVERSIONS=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=y
CONFIG_HAVE_CLK=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=y
CONFIG_HAVE_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=y
CONFIG_HAVE_RCU_TABLE_FREE=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_ARCH_WANT_OLD_COMPAT_IPC=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP_FILTER=y
CONFIG_HAVE_ARCH_STACKLEAK=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_CC_HAS_STACKPROTECTOR_NONE=y
# CONFIG_STACKPROTECTOR is not set
CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=y
CONFIG_HAVE_CONTEXT_TRACKING=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_MOVE_PMD=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_HAVE_ARCH_SOFT_DIRTY=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_HAVE_EXIT_THREAD=y
CONFIG_ARCH_MMAP_RND_BITS=28
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=8
CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=y
CONFIG_HAVE_COPY_THREAD_TLS=y
CONFIG_HAVE_STACK_VALIDATION=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_ISA_BUS_API=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_64BIT_TIME=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_VMAP_STACK=y
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y
CONFIG_LOCK_EVENT_COUNTS=y
CONFIG_ARCH_HAS_MEM_ENCRYPT=y

#
# GCOV-based kernel profiling
#
CONFIG_GCOV_KERNEL=y
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
# CONFIG_GCOV_PROFILE_ALL is not set
# end of GCOV-based kernel profiling

CONFIG_HAVE_GCC_PLUGINS=y
# end of General architecture-dependent options

CONFIG_RT_MUTEXES=y
CONFIG_BASE_SMALL=1
CONFIG_MODULES=y
# CONFIG_MODULE_FORCE_LOAD is not set
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULE_FORCE_UNLOAD=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
# CONFIG_MODULE_SIG is not set
# CONFIG_MODULE_COMPRESS is not set
# CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS is not set
CONFIG_UNUSED_SYMBOLS=y
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLK_RQ_ALLOC_TIME=y
CONFIG_BLK_SCSI_REQUEST=y
CONFIG_BLK_DEV_BSG=y
CONFIG_BLK_DEV_BSGLIB=y
CONFIG_BLK_DEV_INTEGRITY=y
# CONFIG_BLK_DEV_ZONED is not set
# CONFIG_BLK_DEV_THROTTLING is not set
# CONFIG_BLK_CMDLINE_PARSER is not set
# CONFIG_BLK_WBT is not set
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_IOCOST=y
# CONFIG_BLK_DEBUG_FS is not set
# CONFIG_BLK_SED_OPAL is not set

#
# Partition Types
#
# CONFIG_PARTITION_ADVANCED is not set
CONFIG_MSDOS_PARTITION=y
CONFIG_EFI_PARTITION=y
# end of Partition Types

CONFIG_BLOCK_COMPAT=y
CONFIG_BLK_MQ_PCI=y
CONFIG_BLK_PM=y

#
# IO Schedulers
#
CONFIG_MQ_IOSCHED_DEADLINE=m
# CONFIG_MQ_IOSCHED_KYBER is not set
CONFIG_IOSCHED_BFQ=y
# CONFIG_BFQ_GROUP_IOSCHED is not set
# end of IO Schedulers

CONFIG_ASN1=y
CONFIG_INLINE_SPIN_UNLOCK_IRQ=y
CONFIG_INLINE_READ_UNLOCK=y
CONFIG_INLINE_READ_UNLOCK_IRQ=y
CONFIG_INLINE_WRITE_UNLOCK=y
CONFIG_INLINE_WRITE_UNLOCK_IRQ=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ELFCORE=y
# CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS is not set
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=y
CONFIG_COREDUMP=y
# end of Executable file formats

#
# Memory Management options
#
CONFIG_SELECT_MEMORY_MODEL=y
CONFIG_SPARSEMEM_MANUAL=y
CONFIG_SPARSEMEM=y
CONFIG_HAVE_MEMORY_PRESENT=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_MEMBLOCK_NODE_MAP=y
CONFIG_HAVE_FAST_GUP=y
CONFIG_MEMORY_ISOLATION=y
CONFIG_HAVE_BOOTMEM_INFO_NODE=y
CONFIG_MEMORY_HOTPLUG=y
CONFIG_MEMORY_HOTPLUG_SPARSE=y
# CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE is not set
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_SPLIT_PTLOCK_CPUS=4
# CONFIG_COMPACTION is not set
CONFIG_MIGRATION=y
CONFIG_CONTIG_ALLOC=y
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_VIRT_TO_BUS=y
CONFIG_MMU_NOTIFIER=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
CONFIG_MEMORY_FAILURE=y
# CONFIG_HWPOISON_INJECT is not set
# CONFIG_TRANSPARENT_HUGEPAGE is not set
CONFIG_ARCH_WANTS_THP_SWAP=y
CONFIG_NEED_PER_CPU_KM=y
# CONFIG_CLEANCACHE is not set
CONFIG_CMA=y
CONFIG_CMA_DEBUG=y
CONFIG_CMA_DEBUGFS=y
CONFIG_CMA_AREAS=7
# CONFIG_MEM_SOFT_DIRTY is not set
CONFIG_ZPOOL=m
# CONFIG_ZBUD is not set
CONFIG_Z3FOLD=m
# CONFIG_ZSMALLOC is not set
CONFIG_GENERIC_EARLY_IOREMAP=y
# CONFIG_IDLE_PAGE_TRACKING is not set
CONFIG_ARCH_HAS_PTE_DEVMAP=y
CONFIG_ZONE_DEVICE=y
CONFIG_DEV_PAGEMAP_OPS=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_FRAME_VECTOR=y
CONFIG_PERCPU_STATS=y
CONFIG_GUP_BENCHMARK=y
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_MAPPING_DIRTY_HELPERS=y
# end of Memory Management options

CONFIG_NET=y

#
# Networking options
#
# CONFIG_PACKET is not set
CONFIG_UNIX=y
CONFIG_UNIX_SCM=y
# CONFIG_UNIX_DIAG is not set
# CONFIG_TLS is not set
# CONFIG_XFRM_USER is not set
# CONFIG_NET_KEY is not set
# CONFIG_XDP_SOCKETS is not set
CONFIG_INET=y
# CONFIG_IP_MULTICAST is not set
# CONFIG_IP_ADVANCED_ROUTER is not set
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
# CONFIG_IP_PNP_BOOTP is not set
# CONFIG_IP_PNP_RARP is not set
# CONFIG_NET_IPIP is not set
# CONFIG_NET_IPGRE_DEMUX is not set
CONFIG_NET_IP_TUNNEL=y
# CONFIG_SYN_COOKIES is not set
# CONFIG_NET_IPVTI is not set
# CONFIG_NET_FOU is not set
# CONFIG_NET_FOU_IP_TUNNELS is not set
# CONFIG_INET_AH is not set
# CONFIG_INET_ESP is not set
# CONFIG_INET_IPCOMP is not set
CONFIG_INET_TUNNEL=y
CONFIG_INET_DIAG=y
CONFIG_INET_TCP_DIAG=y
# CONFIG_INET_UDP_DIAG is not set
# CONFIG_INET_RAW_DIAG is not set
# CONFIG_INET_DIAG_DESTROY is not set
# CONFIG_TCP_CONG_ADVANCED is not set
CONFIG_TCP_CONG_CUBIC=y
CONFIG_DEFAULT_TCP_CONG="cubic"
# CONFIG_TCP_MD5SIG is not set
CONFIG_IPV6=y
# CONFIG_IPV6_ROUTER_PREF is not set
# CONFIG_IPV6_OPTIMISTIC_DAD is not set
# CONFIG_INET6_AH is not set
# CONFIG_INET6_ESP is not set
# CONFIG_INET6_IPCOMP is not set
# CONFIG_IPV6_MIP6 is not set
# CONFIG_IPV6_VTI is not set
CONFIG_IPV6_SIT=y
# CONFIG_IPV6_SIT_6RD is not set
CONFIG_IPV6_NDISC_NODETYPE=y
# CONFIG_IPV6_TUNNEL is not set
# CONFIG_IPV6_MULTIPLE_TABLES is not set
# CONFIG_IPV6_MROUTE is not set
# CONFIG_IPV6_SEG6_LWTUNNEL is not set
# CONFIG_IPV6_SEG6_HMAC is not set
# CONFIG_NETWORK_SECMARK is not set
# CONFIG_NETWORK_PHY_TIMESTAMPING is not set
# CONFIG_NETFILTER is not set
# CONFIG_BPFILTER is not set
# CONFIG_IP_DCCP is not set
# CONFIG_IP_SCTP is not set
# CONFIG_RDS is not set
# CONFIG_TIPC is not set
# CONFIG_ATM is not set
# CONFIG_L2TP is not set
# CONFIG_BRIDGE is not set
CONFIG_HAVE_NET_DSA=y
# CONFIG_NET_DSA is not set
# CONFIG_VLAN_8021Q is not set
# CONFIG_DECNET is not set
# CONFIG_LLC2 is not set
# CONFIG_ATALK is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_PHONET is not set
# CONFIG_6LOWPAN is not set
# CONFIG_IEEE802154 is not set
# CONFIG_NET_SCHED is not set
# CONFIG_DCB is not set
CONFIG_DNS_RESOLVER=m
# CONFIG_BATMAN_ADV is not set
# CONFIG_OPENVSWITCH is not set
# CONFIG_VSOCKETS is not set
# CONFIG_NETLINK_DIAG is not set
# CONFIG_MPLS is not set
# CONFIG_NET_NSH is not set
# CONFIG_HSR is not set
# CONFIG_NET_SWITCHDEV is not set
# CONFIG_NET_L3_MASTER_DEV is not set
# CONFIG_NET_NCSI is not set
# CONFIG_CGROUP_NET_PRIO is not set
# CONFIG_CGROUP_NET_CLASSID is not set
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
# CONFIG_BPF_JIT is not set

#
# Network testing
#
# CONFIG_NET_PKTGEN is not set
# CONFIG_NET_DROP_MONITOR is not set
# end of Network testing
# end of Networking options

# CONFIG_HAMRADIO is not set
# CONFIG_CAN is not set
# CONFIG_BT is not set
# CONFIG_AF_RXRPC is not set
# CONFIG_AF_KCM is not set
CONFIG_WIRELESS=y
# CONFIG_CFG80211 is not set

#
# CFG80211 needs to be enabled for MAC80211
#
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
# CONFIG_WIMAX is not set
# CONFIG_RFKILL is not set
CONFIG_NET_9P=y
# CONFIG_NET_9P_DEBUG is not set
# CONFIG_CAIF is not set
# CONFIG_CEPH_LIB is not set
# CONFIG_NFC is not set
# CONFIG_PSAMPLE is not set
# CONFIG_NET_IFE is not set
# CONFIG_LWTUNNEL is not set
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
# CONFIG_FAILOVER is not set
CONFIG_HAVE_EBPF_JIT=y

#
# Device Drivers
#
CONFIG_HAVE_EISA=y
CONFIG_EISA=y
CONFIG_EISA_VLB_PRIMING=y
CONFIG_EISA_PCI_EISA=y
CONFIG_EISA_VIRTUAL_ROOT=y
# CONFIG_EISA_NAMES is not set
CONFIG_HAVE_PCI=y
CONFIG_PCI=y
CONFIG_PCI_DOMAINS=y
# CONFIG_PCIEPORTBUS is not set
CONFIG_PCI_MSI=y
CONFIG_PCI_MSI_IRQ_DOMAIN=y
CONFIG_PCI_QUIRKS=y
# CONFIG_PCI_DEBUG is not set
CONFIG_PCI_STUB=m
CONFIG_PCI_LOCKLESS_CONFIG=y
# CONFIG_PCI_IOV is not set
# CONFIG_PCI_PRI is not set
# CONFIG_PCI_PASID is not set
CONFIG_PCI_P2PDMA=y
CONFIG_PCI_LABEL=y
# CONFIG_HOTPLUG_PCI is not set

#
# PCI controller drivers
#

#
# Cadence PCIe controllers support
#
# end of Cadence PCIe controllers support

CONFIG_VMD=y

#
# DesignWare PCI Core Support
#
CONFIG_PCIE_DW=y
CONFIG_PCIE_DW_HOST=y
CONFIG_PCIE_DW_PLAT=y
CONFIG_PCIE_DW_PLAT_HOST=y
# CONFIG_PCI_MESON is not set
# end of DesignWare PCI Core Support
# end of PCI controller drivers

#
# PCI Endpoint
#
# CONFIG_PCI_ENDPOINT is not set
# end of PCI Endpoint

#
# PCI switch controller drivers
#
CONFIG_PCI_SW_SWITCHTEC=y
# end of PCI switch controller drivers

CONFIG_PCCARD=m
CONFIG_PCMCIA=m
CONFIG_PCMCIA_LOAD_CIS=y
# CONFIG_CARDBUS is not set

#
# PC-card bridges
#
# CONFIG_YENTA is not set
# CONFIG_PD6729 is not set
CONFIG_I82092=m
CONFIG_PCCARD_NONSTATIC=y
# CONFIG_RAPIDIO is not set

#
# Generic Driver Options
#
# CONFIG_UEVENT_HELPER is not set
CONFIG_DEVTMPFS=y
# CONFIG_DEVTMPFS_MOUNT is not set
# CONFIG_STANDALONE is not set
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_PAGED_BUF=y
CONFIG_EXTRA_FIRMWARE=""
CONFIG_FW_LOADER_USER_HELPER=y
# CONFIG_FW_LOADER_USER_HELPER_FALLBACK is not set
# CONFIG_FW_LOADER_COMPRESS is not set
# CONFIG_FW_CACHE is not set
# end of Firmware loader

# CONFIG_ALLOW_DEV_COREDUMP is not set
# CONFIG_DEBUG_DRIVER is not set
CONFIG_DEBUG_DEVRES=y
# CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
CONFIG_TEST_ASYNC_DRIVER_PROBE=m
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_REGMAP=y
CONFIG_REGMAP_I2C=y
CONFIG_REGMAP_SPI=y
CONFIG_REGMAP_SPMI=m
CONFIG_REGMAP_MMIO=y
CONFIG_REGMAP_IRQ=y
CONFIG_REGMAP_I3C=m
CONFIG_DMA_SHARED_BUFFER=y
CONFIG_DMA_FENCE_TRACE=y
# end of Generic Driver Options

#
# Bus devices
#
# end of Bus devices

# CONFIG_CONNECTOR is not set
CONFIG_GNSS=m
CONFIG_GNSS_SERIAL=m
CONFIG_GNSS_MTK_SERIAL=m
# CONFIG_GNSS_SIRF_SERIAL is not set
CONFIG_GNSS_UBX_SERIAL=m
CONFIG_MTD=m
CONFIG_MTD_TESTS=m

#
# Partition parsers
#
CONFIG_MTD_AR7_PARTS=m
# CONFIG_MTD_CMDLINE_PARTS is not set
CONFIG_MTD_REDBOOT_PARTS=m
CONFIG_MTD_REDBOOT_DIRECTORY_BLOCK=-1
# CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED is not set
CONFIG_MTD_REDBOOT_PARTS_READONLY=y
# end of Partition parsers

#
# User Modules And Translation Layers
#
CONFIG_MTD_BLKDEVS=m
# CONFIG_MTD_BLOCK is not set
# CONFIG_MTD_BLOCK_RO is not set
CONFIG_FTL=m
# CONFIG_NFTL is not set
# CONFIG_INFTL is not set
CONFIG_RFD_FTL=m
CONFIG_SSFDC=m
# CONFIG_SM_FTL is not set
CONFIG_MTD_OOPS=m
# CONFIG_MTD_PARTITIONED_MASTER is not set

#
# RAM/ROM/Flash chip drivers
#
CONFIG_MTD_CFI=m
CONFIG_MTD_JEDECPROBE=m
CONFIG_MTD_GEN_PROBE=m
CONFIG_MTD_CFI_ADV_OPTIONS=y
# CONFIG_MTD_CFI_NOSWAP is not set
# CONFIG_MTD_CFI_BE_BYTE_SWAP is not set
CONFIG_MTD_CFI_LE_BYTE_SWAP=y
# CONFIG_MTD_CFI_GEOMETRY is not set
CONFIG_MTD_MAP_BANK_WIDTH_1=y
CONFIG_MTD_MAP_BANK_WIDTH_2=y
CONFIG_MTD_MAP_BANK_WIDTH_4=y
CONFIG_MTD_CFI_I1=y
CONFIG_MTD_CFI_I2=y
CONFIG_MTD_OTP=y
CONFIG_MTD_CFI_INTELEXT=m
CONFIG_MTD_CFI_AMDSTD=m
# CONFIG_MTD_CFI_STAA is not set
CONFIG_MTD_CFI_UTIL=m
CONFIG_MTD_RAM=m
# CONFIG_MTD_ROM is not set
CONFIG_MTD_ABSENT=m
# end of RAM/ROM/Flash chip drivers

#
# Mapping drivers for chip access
#
CONFIG_MTD_COMPLEX_MAPPINGS=y
CONFIG_MTD_PHYSMAP=m
CONFIG_MTD_PHYSMAP_COMPAT=y
CONFIG_MTD_PHYSMAP_START=0x8000000
CONFIG_MTD_PHYSMAP_LEN=0
CONFIG_MTD_PHYSMAP_BANKWIDTH=2
# CONFIG_MTD_PHYSMAP_GPIO_ADDR is not set
CONFIG_MTD_SBC_GXX=m
# CONFIG_MTD_AMD76XROM is not set
CONFIG_MTD_ICHXROM=m
CONFIG_MTD_ESB2ROM=m
CONFIG_MTD_CK804XROM=m
# CONFIG_MTD_SCB2_FLASH is not set
CONFIG_MTD_NETtel=m
CONFIG_MTD_L440GX=m
CONFIG_MTD_PCI=m
CONFIG_MTD_PCMCIA=m
# CONFIG_MTD_PCMCIA_ANONYMOUS is not set
CONFIG_MTD_INTEL_VR_NOR=m
# CONFIG_MTD_PLATRAM is not set
# end of Mapping drivers for chip access

#
# Self-contained MTD device drivers
#
CONFIG_MTD_PMC551=m
# CONFIG_MTD_PMC551_BUGFIX is not set
CONFIG_MTD_PMC551_DEBUG=y
CONFIG_MTD_DATAFLASH=m
CONFIG_MTD_DATAFLASH_WRITE_VERIFY=y
CONFIG_MTD_DATAFLASH_OTP=y
# CONFIG_MTD_MCHP23K256 is not set
# CONFIG_MTD_SST25L is not set
CONFIG_MTD_SLRAM=m
CONFIG_MTD_PHRAM=m
CONFIG_MTD_MTDRAM=m
CONFIG_MTDRAM_TOTAL_SIZE=4096
CONFIG_MTDRAM_ERASE_SIZE=128
CONFIG_MTD_BLOCK2MTD=m

#
# Disk-On-Chip Device Drivers
#
CONFIG_MTD_DOCG3=m
CONFIG_BCH_CONST_M=14
CONFIG_BCH_CONST_T=4
# end of Self-contained MTD device drivers

CONFIG_MTD_NAND_CORE=m
# CONFIG_MTD_ONENAND is not set
CONFIG_MTD_NAND_ECC_SW_HAMMING=m
CONFIG_MTD_NAND_ECC_SW_HAMMING_SMC=y
CONFIG_MTD_RAW_NAND=m
CONFIG_MTD_NAND_ECC_SW_BCH=y

#
# Raw/parallel NAND flash controllers
#
# CONFIG_MTD_NAND_DENALI_PCI is not set
CONFIG_MTD_NAND_CAFE=m
# CONFIG_MTD_NAND_MXIC is not set
# CONFIG_MTD_NAND_GPIO is not set
# CONFIG_MTD_NAND_PLATFORM is not set

#
# Misc
#
CONFIG_MTD_SM_COMMON=m
CONFIG_MTD_NAND_NANDSIM=m
CONFIG_MTD_NAND_RICOH=m
CONFIG_MTD_NAND_DISKONCHIP=m
# CONFIG_MTD_NAND_DISKONCHIP_PROBE_ADVANCED is not set
CONFIG_MTD_NAND_DISKONCHIP_PROBE_ADDRESS=0
# CONFIG_MTD_NAND_DISKONCHIP_BBTWRITE is not set
CONFIG_MTD_SPI_NAND=m

#
# LPDDR & LPDDR2 PCM memory drivers
#
CONFIG_MTD_LPDDR=m
CONFIG_MTD_QINFO_PROBE=m
# end of LPDDR & LPDDR2 PCM memory drivers

# CONFIG_MTD_SPI_NOR is not set
CONFIG_MTD_UBI=m
CONFIG_MTD_UBI_WL_THRESHOLD=4096
CONFIG_MTD_UBI_BEB_LIMIT=20
# CONFIG_MTD_UBI_FASTMAP is not set
CONFIG_MTD_UBI_GLUEBI=m
# CONFIG_MTD_UBI_BLOCK is not set
CONFIG_MTD_HYPERBUS=m
# CONFIG_OF is not set
CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=y
CONFIG_PARPORT=y
# CONFIG_PARPORT_PC is not set
CONFIG_PARPORT_AX88796=y
CONFIG_PARPORT_1284=y
CONFIG_PARPORT_NOT_PC=y
CONFIG_PNP=y
CONFIG_PNP_DEBUG_MESSAGES=y

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
# CONFIG_BLK_DEV_NULL_BLK is not set
# CONFIG_BLK_DEV_FD is not set
# CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
# CONFIG_BLK_DEV_UMEM is not set
# CONFIG_BLK_DEV_LOOP is not set
# CONFIG_BLK_DEV_DRBD is not set
# CONFIG_BLK_DEV_NBD is not set
# CONFIG_BLK_DEV_SKD is not set
# CONFIG_BLK_DEV_SX8 is not set
# CONFIG_BLK_DEV_RAM is not set
# CONFIG_CDROM_PKTCDVD is not set
# CONFIG_ATA_OVER_ETH is not set
# CONFIG_BLK_DEV_RBD is not set
# CONFIG_BLK_DEV_RSXX is not set

#
# NVME Support
#
CONFIG_NVME_CORE=y
CONFIG_BLK_DEV_NVME=y
CONFIG_NVME_MULTIPATH=y
# CONFIG_NVME_HWMON is not set
CONFIG_NVME_FABRICS=m
# CONFIG_NVME_FC is not set
# CONFIG_NVME_TCP is not set
CONFIG_NVME_TARGET=m
CONFIG_NVME_TARGET_LOOP=m
CONFIG_NVME_TARGET_FC=m
# CONFIG_NVME_TARGET_TCP is not set
# end of NVME Support

#
# Misc devices
#
CONFIG_AD525X_DPOT=m
# CONFIG_AD525X_DPOT_I2C is not set
# CONFIG_AD525X_DPOT_SPI is not set
CONFIG_DUMMY_IRQ=y
# CONFIG_IBM_ASM is not set
CONFIG_PHANTOM=y
CONFIG_TIFM_CORE=y
CONFIG_TIFM_7XX1=m
CONFIG_ICS932S401=y
# CONFIG_ENCLOSURE_SERVICES is not set
CONFIG_HP_ILO=y
# CONFIG_APDS9802ALS is not set
# CONFIG_ISL29003 is not set
CONFIG_ISL29020=y
CONFIG_SENSORS_TSL2550=y
CONFIG_SENSORS_BH1770=m
# CONFIG_SENSORS_APDS990X is not set
CONFIG_HMC6352=m
CONFIG_DS1682=y
# CONFIG_VMWARE_BALLOON is not set
CONFIG_LATTICE_ECP3_CONFIG=y
# CONFIG_SRAM is not set
# CONFIG_PCI_ENDPOINT_TEST is not set
CONFIG_XILINX_SDFEC=m
CONFIG_MISC_RTSX=m
# CONFIG_PVPANIC is not set
# CONFIG_C2PORT is not set

#
# EEPROM support
#
CONFIG_EEPROM_AT24=y
CONFIG_EEPROM_AT25=m
# CONFIG_EEPROM_LEGACY is not set
CONFIG_EEPROM_MAX6875=m
CONFIG_EEPROM_93CX6=y
CONFIG_EEPROM_93XX46=y
# CONFIG_EEPROM_IDT_89HPESX is not set
# CONFIG_EEPROM_EE1004 is not set
# end of EEPROM support

CONFIG_CB710_CORE=m
# CONFIG_CB710_DEBUG is not set
CONFIG_CB710_DEBUG_ASSUMPTIONS=y

#
# Texas Instruments shared transport line discipline
#
# CONFIG_TI_ST is not set
# end of Texas Instruments shared transport line discipline

# CONFIG_SENSORS_LIS3_I2C is not set
# CONFIG_ALTERA_STAPL is not set
CONFIG_INTEL_MEI=y
CONFIG_INTEL_MEI_ME=m
CONFIG_INTEL_MEI_TXE=y
# CONFIG_INTEL_MEI_HDCP is not set
CONFIG_VMWARE_VMCI=m

#
# Intel MIC & related support
#
CONFIG_INTEL_MIC_BUS=y
CONFIG_SCIF_BUS=m
# CONFIG_VOP_BUS is not set
CONFIG_SCIF=m
# CONFIG_MIC_COSM is not set
# end of Intel MIC & related support

CONFIG_GENWQE=m
CONFIG_GENWQE_PLATFORM_ERROR_RECOVERY=0
# CONFIG_ECHO is not set
CONFIG_MISC_ALCOR_PCI=m
CONFIG_MISC_RTSX_PCI=m
CONFIG_HABANA_AI=y
# end of Misc devices

CONFIG_HAVE_IDE=y
CONFIG_IDE=y

#
# Please see Documentation/ide/ide.rst for help/info on IDE drives
#
CONFIG_IDE_XFER_MODE=y
CONFIG_IDE_TIMINGS=y
CONFIG_IDE_ATAPI=y
# CONFIG_BLK_DEV_IDE_SATA is not set
CONFIG_IDE_GD=m
CONFIG_IDE_GD_ATA=y
CONFIG_IDE_GD_ATAPI=y
CONFIG_BLK_DEV_IDECS=m
# CONFIG_BLK_DEV_IDECD is not set
CONFIG_BLK_DEV_IDETAPE=y
# CONFIG_BLK_DEV_IDEACPI is not set
CONFIG_IDE_TASK_IOCTL=y
CONFIG_IDE_PROC_FS=y

#
# IDE chipset support/bugfixes
#
# CONFIG_IDE_GENERIC is not set
CONFIG_BLK_DEV_PLATFORM=y
CONFIG_BLK_DEV_CMD640=y
CONFIG_BLK_DEV_CMD640_ENHANCED=y
# CONFIG_BLK_DEV_IDEPNP is not set
CONFIG_BLK_DEV_IDEDMA_SFF=y

#
# PCI IDE chipsets support
#
CONFIG_BLK_DEV_IDEPCI=y
CONFIG_IDEPCI_PCIBUS_ORDER=y
# CONFIG_BLK_DEV_OFFBOARD is not set
CONFIG_BLK_DEV_GENERIC=m
# CONFIG_BLK_DEV_OPTI621 is not set
CONFIG_BLK_DEV_RZ1000=m
CONFIG_BLK_DEV_IDEDMA_PCI=y
CONFIG_BLK_DEV_AEC62XX=m
# CONFIG_BLK_DEV_ALI15X3 is not set
CONFIG_BLK_DEV_AMD74XX=y
CONFIG_BLK_DEV_ATIIXP=m
CONFIG_BLK_DEV_CMD64X=m
CONFIG_BLK_DEV_TRIFLEX=m
CONFIG_BLK_DEV_HPT366=m
# CONFIG_BLK_DEV_JMICRON is not set
CONFIG_BLK_DEV_PIIX=y
# CONFIG_BLK_DEV_IT8172 is not set
CONFIG_BLK_DEV_IT8213=m
CONFIG_BLK_DEV_IT821X=m
# CONFIG_BLK_DEV_NS87415 is not set
# CONFIG_BLK_DEV_PDC202XX_OLD is not set
CONFIG_BLK_DEV_PDC202XX_NEW=y
CONFIG_BLK_DEV_SVWKS=m
# CONFIG_BLK_DEV_SIIMAGE is not set
CONFIG_BLK_DEV_SIS5513=y
CONFIG_BLK_DEV_SLC90E66=m
CONFIG_BLK_DEV_TRM290=y
CONFIG_BLK_DEV_VIA82CXXX=m
CONFIG_BLK_DEV_TC86C001=y
CONFIG_BLK_DEV_IDEDMA=y

#
# SCSI device support
#
CONFIG_SCSI_MOD=m
CONFIG_RAID_ATTRS=m
CONFIG_SCSI=m
CONFIG_SCSI_DMA=y
CONFIG_SCSI_PROC_FS=y

#
# SCSI support type (disk, tape, CD-ROM)
#
# CONFIG_BLK_DEV_SD is not set
CONFIG_CHR_DEV_ST=m
# CONFIG_BLK_DEV_SR is not set
# CONFIG_CHR_DEV_SG is not set
# CONFIG_CHR_DEV_SCH is not set
CONFIG_SCSI_CONSTANTS=y
# CONFIG_SCSI_LOGGING is not set
# CONFIG_SCSI_SCAN_ASYNC is not set

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=m
# CONFIG_SCSI_FC_ATTRS is not set
# CONFIG_SCSI_ISCSI_ATTRS is not set
CONFIG_SCSI_SAS_ATTRS=m
CONFIG_SCSI_SAS_LIBSAS=m
# CONFIG_SCSI_SAS_ATA is not set
CONFIG_SCSI_SAS_HOST_SMP=y
# CONFIG_SCSI_SRP_ATTRS is not set
# end of SCSI Transports

CONFIG_SCSI_LOWLEVEL=y
# CONFIG_ISCSI_TCP is not set
CONFIG_ISCSI_BOOT_SYSFS=m
# CONFIG_SCSI_CXGB3_ISCSI is not set
# CONFIG_SCSI_CXGB4_ISCSI is not set
# CONFIG_SCSI_BNX2_ISCSI is not set
# CONFIG_BE2ISCSI is not set
# CONFIG_BLK_DEV_3W_XXXX_RAID is not set
CONFIG_SCSI_HPSA=m
# CONFIG_SCSI_3W_9XXX is not set
# CONFIG_SCSI_3W_SAS is not set
CONFIG_SCSI_ACARD=m
CONFIG_SCSI_AHA1740=m
# CONFIG_SCSI_AACRAID is not set
CONFIG_SCSI_AIC7XXX=m
CONFIG_AIC7XXX_CMDS_PER_DEVICE=32
CONFIG_AIC7XXX_RESET_DELAY_MS=5000
CONFIG_AIC7XXX_DEBUG_ENABLE=y
CONFIG_AIC7XXX_DEBUG_MASK=0
# CONFIG_AIC7XXX_REG_PRETTY_PRINT is not set
CONFIG_SCSI_AIC79XX=m
CONFIG_AIC79XX_CMDS_PER_DEVICE=32
CONFIG_AIC79XX_RESET_DELAY_MS=5000
# CONFIG_AIC79XX_DEBUG_ENABLE is not set
CONFIG_AIC79XX_DEBUG_MASK=0
CONFIG_AIC79XX_REG_PRETTY_PRINT=y
CONFIG_SCSI_AIC94XX=m
# CONFIG_AIC94XX_DEBUG is not set
CONFIG_SCSI_MVSAS=m
# CONFIG_SCSI_MVSAS_DEBUG is not set
# CONFIG_SCSI_MVSAS_TASKLET is not set
CONFIG_SCSI_MVUMI=m
# CONFIG_SCSI_DPT_I2O is not set
# CONFIG_SCSI_ADVANSYS is not set
CONFIG_SCSI_ARCMSR=m
CONFIG_SCSI_ESAS2R=m
# CONFIG_MEGARAID_NEWGEN is not set
CONFIG_MEGARAID_LEGACY=m
# CONFIG_MEGARAID_SAS is not set
CONFIG_SCSI_MPT3SAS=m
CONFIG_SCSI_MPT2SAS_MAX_SGE=128
CONFIG_SCSI_MPT3SAS_MAX_SGE=128
CONFIG_SCSI_MPT2SAS=m
CONFIG_SCSI_SMARTPQI=m
CONFIG_SCSI_UFSHCD=m
CONFIG_SCSI_UFSHCD_PCI=m
# CONFIG_SCSI_UFS_DWC_TC_PCI is not set
CONFIG_SCSI_UFSHCD_PLATFORM=m
CONFIG_SCSI_UFS_CDNS_PLATFORM=m
# CONFIG_SCSI_UFS_DWC_TC_PLATFORM is not set
CONFIG_SCSI_UFS_BSG=y
CONFIG_SCSI_HPTIOP=m
# CONFIG_SCSI_BUSLOGIC is not set
CONFIG_SCSI_MYRB=m
CONFIG_SCSI_MYRS=m
# CONFIG_VMWARE_PVSCSI is not set
CONFIG_SCSI_SNIC=m
# CONFIG_SCSI_SNIC_DEBUG_FS is not set
CONFIG_SCSI_DMX3191D=m
CONFIG_SCSI_FDOMAIN=m
CONFIG_SCSI_FDOMAIN_PCI=m
# CONFIG_SCSI_GDTH is not set
# CONFIG_SCSI_ISCI is not set
CONFIG_SCSI_IPS=m
CONFIG_SCSI_INITIO=m
CONFIG_SCSI_INIA100=m
CONFIG_SCSI_STEX=m
CONFIG_SCSI_SYM53C8XX_2=m
CONFIG_SCSI_SYM53C8XX_DMA_ADDRESSING_MODE=1
CONFIG_SCSI_SYM53C8XX_DEFAULT_TAGS=16
CONFIG_SCSI_SYM53C8XX_MAX_TAGS=64
CONFIG_SCSI_SYM53C8XX_MMIO=y
CONFIG_SCSI_IPR=m
# CONFIG_SCSI_IPR_TRACE is not set
CONFIG_SCSI_IPR_DUMP=y
CONFIG_SCSI_QLOGIC_1280=m
# CONFIG_SCSI_QLA_ISCSI is not set
CONFIG_SCSI_SIM710=m
CONFIG_SCSI_DC395x=m
CONFIG_SCSI_AM53C974=m
# CONFIG_SCSI_WD719X is not set
# CONFIG_SCSI_DEBUG is not set
# CONFIG_SCSI_PMCRAID is not set
CONFIG_SCSI_PM8001=m
CONFIG_SCSI_LOWLEVEL_PCMCIA=y
CONFIG_PCMCIA_AHA152X=m
# CONFIG_PCMCIA_FDOMAIN is not set
CONFIG_PCMCIA_QLOGIC=m
CONFIG_PCMCIA_SYM53C500=m
# CONFIG_SCSI_DH is not set
# end of SCSI device support

CONFIG_ATA=m
# CONFIG_ATA_VERBOSE_ERROR is not set
CONFIG_ATA_ACPI=y
# CONFIG_SATA_ZPODD is not set
# CONFIG_SATA_PMP is not set

#
# Controllers with non-SFF native interface
#
# CONFIG_SATA_AHCI is not set
CONFIG_SATA_AHCI_PLATFORM=m
# CONFIG_SATA_INIC162X is not set
CONFIG_SATA_ACARD_AHCI=m
CONFIG_SATA_SIL24=m
# CONFIG_ATA_SFF is not set
# CONFIG_MD is not set
# CONFIG_TARGET_CORE is not set
# CONFIG_FUSION is not set

#
# IEEE 1394 (FireWire) support
#
# CONFIG_FIREWIRE is not set
# CONFIG_FIREWIRE_NOSY is not set
# end of IEEE 1394 (FireWire) support

# CONFIG_MACINTOSH_DRIVERS is not set
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
# CONFIG_BONDING is not set
# CONFIG_DUMMY is not set
# CONFIG_EQUALIZER is not set
# CONFIG_NET_FC is not set
# CONFIG_NET_TEAM is not set
# CONFIG_MACVLAN is not set
# CONFIG_IPVLAN is not set
# CONFIG_VXLAN is not set
# CONFIG_GENEVE is not set
# CONFIG_GTP is not set
# CONFIG_MACSEC is not set
# CONFIG_NETCONSOLE is not set
# CONFIG_NTB_NETDEV is not set
# CONFIG_TUN is not set
# CONFIG_TUN_VNET_CROSS_LE is not set
# CONFIG_VETH is not set
# CONFIG_NLMON is not set
# CONFIG_ARCNET is not set

#
# Distributed Switch Architecture drivers
#
# end of Distributed Switch Architecture drivers

CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_3COM=y
# CONFIG_EL3 is not set
# CONFIG_PCMCIA_3C574 is not set
# CONFIG_PCMCIA_3C589 is not set
# CONFIG_VORTEX is not set
# CONFIG_TYPHOON is not set
CONFIG_NET_VENDOR_ADAPTEC=y
# CONFIG_ADAPTEC_STARFIRE is not set
CONFIG_NET_VENDOR_AGERE=y
# CONFIG_ET131X is not set
CONFIG_NET_VENDOR_ALACRITECH=y
# CONFIG_SLICOSS is not set
CONFIG_NET_VENDOR_ALTEON=y
# CONFIG_ACENIC is not set
# CONFIG_ALTERA_TSE is not set
CONFIG_NET_VENDOR_AMAZON=y
# CONFIG_ENA_ETHERNET is not set
CONFIG_NET_VENDOR_AMD=y
# CONFIG_AMD8111_ETH is not set
# CONFIG_PCNET32 is not set
# CONFIG_PCMCIA_NMCLAN is not set
# CONFIG_AMD_XGBE is not set
CONFIG_NET_VENDOR_AQUANTIA=y
# CONFIG_AQTION is not set
CONFIG_NET_VENDOR_ARC=y
CONFIG_NET_VENDOR_ATHEROS=y
# CONFIG_ATL2 is not set
# CONFIG_ATL1 is not set
# CONFIG_ATL1E is not set
# CONFIG_ATL1C is not set
# CONFIG_ALX is not set
CONFIG_NET_VENDOR_AURORA=y
# CONFIG_AURORA_NB8800 is not set
CONFIG_NET_VENDOR_BROADCOM=y
# CONFIG_B44 is not set
# CONFIG_BCMGENET is not set
# CONFIG_BNX2 is not set
# CONFIG_CNIC is not set
# CONFIG_TIGON3 is not set
# CONFIG_BNX2X is not set
# CONFIG_SYSTEMPORT is not set
# CONFIG_BNXT is not set
CONFIG_NET_VENDOR_BROCADE=y
# CONFIG_BNA is not set
CONFIG_NET_VENDOR_CADENCE=y
# CONFIG_MACB is not set
CONFIG_NET_VENDOR_CAVIUM=y
# CONFIG_THUNDER_NIC_PF is not set
# CONFIG_THUNDER_NIC_VF is not set
# CONFIG_THUNDER_NIC_BGX is not set
# CONFIG_THUNDER_NIC_RGX is not set
# CONFIG_CAVIUM_PTP is not set
# CONFIG_LIQUIDIO is not set
# CONFIG_LIQUIDIO_VF is not set
CONFIG_NET_VENDOR_CHELSIO=y
# CONFIG_CHELSIO_T1 is not set
# CONFIG_CHELSIO_T3 is not set
# CONFIG_CHELSIO_T4 is not set
# CONFIG_CHELSIO_T4VF is not set
CONFIG_NET_VENDOR_CIRRUS=y
# CONFIG_CS89x0 is not set
CONFIG_NET_VENDOR_CISCO=y
# CONFIG_ENIC is not set
CONFIG_NET_VENDOR_CORTINA=y
# CONFIG_CX_ECAT is not set
# CONFIG_DNET is not set
CONFIG_NET_VENDOR_DEC=y
# CONFIG_NET_TULIP is not set
CONFIG_NET_VENDOR_DLINK=y
# CONFIG_DL2K is not set
# CONFIG_SUNDANCE is not set
CONFIG_NET_VENDOR_EMULEX=y
# CONFIG_BE2NET is not set
CONFIG_NET_VENDOR_EZCHIP=y
CONFIG_NET_VENDOR_FUJITSU=y
# CONFIG_PCMCIA_FMVJ18X is not set
CONFIG_NET_VENDOR_GOOGLE=y
# CONFIG_GVE is not set
CONFIG_NET_VENDOR_HUAWEI=y
# CONFIG_HINIC is not set
CONFIG_NET_VENDOR_I825XX=y
CONFIG_NET_VENDOR_INTEL=y
# CONFIG_E100 is not set
CONFIG_E1000=y
# CONFIG_E1000E is not set
# CONFIG_IGB is not set
# CONFIG_IGBVF is not set
# CONFIG_IXGB is not set
# CONFIG_IXGBE is not set
# CONFIG_IXGBEVF is not set
# CONFIG_I40E is not set
# CONFIG_I40EVF is not set
# CONFIG_ICE is not set
# CONFIG_FM10K is not set
# CONFIG_IGC is not set
# CONFIG_JME is not set
CONFIG_NET_VENDOR_MARVELL=y
# CONFIG_MVMDIO is not set
# CONFIG_SKGE is not set
# CONFIG_SKY2 is not set
CONFIG_NET_VENDOR_MELLANOX=y
# CONFIG_MLX4_EN is not set
# CONFIG_MLX5_CORE is not set
# CONFIG_MLXSW_CORE is not set
# CONFIG_MLXFW is not set
CONFIG_NET_VENDOR_MICREL=y
# CONFIG_KS8842 is not set
# CONFIG_KS8851 is not set
# CONFIG_KS8851_MLL is not set
# CONFIG_KSZ884X_PCI is not set
CONFIG_NET_VENDOR_MICROCHIP=y
# CONFIG_ENC28J60 is not set
# CONFIG_ENCX24J600 is not set
# CONFIG_LAN743X is not set
CONFIG_NET_VENDOR_MICROSEMI=y
CONFIG_NET_VENDOR_MYRI=y
# CONFIG_MYRI10GE is not set
# CONFIG_FEALNX is not set
CONFIG_NET_VENDOR_NATSEMI=y
# CONFIG_NATSEMI is not set
# CONFIG_NS83820 is not set
CONFIG_NET_VENDOR_NETERION=y
# CONFIG_S2IO is not set
# CONFIG_VXGE is not set
CONFIG_NET_VENDOR_NETRONOME=y
# CONFIG_NFP is not set
CONFIG_NET_VENDOR_NI=y
# CONFIG_NI_XGE_MANAGEMENT_ENET is not set
CONFIG_NET_VENDOR_8390=y
# CONFIG_PCMCIA_AXNET is not set
# CONFIG_NE2K_PCI is not set
# CONFIG_PCMCIA_PCNET is not set
CONFIG_NET_VENDOR_NVIDIA=y
# CONFIG_FORCEDETH is not set
CONFIG_NET_VENDOR_OKI=y
# CONFIG_ETHOC is not set
CONFIG_NET_VENDOR_PACKET_ENGINES=y
# CONFIG_HAMACHI is not set
# CONFIG_YELLOWFIN is not set
CONFIG_NET_VENDOR_PENSANDO=y
# CONFIG_IONIC is not set
CONFIG_NET_VENDOR_QLOGIC=y
# CONFIG_QLA3XXX is not set
# CONFIG_QLCNIC is not set
# CONFIG_NETXEN_NIC is not set
# CONFIG_QED is not set
CONFIG_NET_VENDOR_QUALCOMM=y
# CONFIG_QCOM_EMAC is not set
# CONFIG_RMNET is not set
CONFIG_NET_VENDOR_RDC=y
# CONFIG_R6040 is not set
CONFIG_NET_VENDOR_REALTEK=y
# CONFIG_ATP is not set
# CONFIG_8139CP is not set
# CONFIG_8139TOO is not set
# CONFIG_R8169 is not set
CONFIG_NET_VENDOR_RENESAS=y
CONFIG_NET_VENDOR_ROCKER=y
CONFIG_NET_VENDOR_SAMSUNG=y
# CONFIG_SXGBE_ETH is not set
CONFIG_NET_VENDOR_SEEQ=y
CONFIG_NET_VENDOR_SOLARFLARE=y
# CONFIG_SFC is not set
# CONFIG_SFC_FALCON is not set
CONFIG_NET_VENDOR_SILAN=y
# CONFIG_SC92031 is not set
CONFIG_NET_VENDOR_SIS=y
# CONFIG_SIS900 is not set
# CONFIG_SIS190 is not set
CONFIG_NET_VENDOR_SMSC=y
# CONFIG_PCMCIA_SMC91C92 is not set
# CONFIG_EPIC100 is not set
# CONFIG_SMSC911X is not set
# CONFIG_SMSC9420 is not set
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_NET_VENDOR_STMICRO=y
# CONFIG_STMMAC_ETH is not set
CONFIG_NET_VENDOR_SUN=y
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNGEM is not set
# CONFIG_CASSINI is not set
# CONFIG_NIU is not set
CONFIG_NET_VENDOR_SYNOPSYS=y
# CONFIG_DWC_XLGMAC is not set
CONFIG_NET_VENDOR_TEHUTI=y
# CONFIG_TEHUTI is not set
CONFIG_NET_VENDOR_TI=y
# CONFIG_TI_CPSW_PHY_SEL is not set
# CONFIG_TLAN is not set
CONFIG_NET_VENDOR_VIA=y
# CONFIG_VIA_RHINE is not set
# CONFIG_VIA_VELOCITY is not set
CONFIG_NET_VENDOR_WIZNET=y
# CONFIG_WIZNET_W5100 is not set
# CONFIG_WIZNET_W5300 is not set
CONFIG_NET_VENDOR_XILINX=y
# CONFIG_XILINX_AXI_EMAC is not set
# CONFIG_XILINX_LL_TEMAC is not set
CONFIG_NET_VENDOR_XIRCOM=y
# CONFIG_PCMCIA_XIRC2PS is not set
# CONFIG_FDDI is not set
# CONFIG_HIPPI is not set
# CONFIG_NET_SB1000 is not set
# CONFIG_MDIO_DEVICE is not set
# CONFIG_PHYLIB is not set
# CONFIG_MICREL_KS8995MA is not set
# CONFIG_PLIP is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set

#
# Host-side USB support is needed for USB Network Adapter support
#
CONFIG_WLAN=y
# CONFIG_WIRELESS_WDS is not set
CONFIG_WLAN_VENDOR_ADMTEK=y
CONFIG_WLAN_VENDOR_ATH=y
# CONFIG_ATH_DEBUG is not set
# CONFIG_ATH5K_PCI is not set
CONFIG_WLAN_VENDOR_ATMEL=y
CONFIG_WLAN_VENDOR_BROADCOM=y
CONFIG_WLAN_VENDOR_CISCO=y
CONFIG_WLAN_VENDOR_INTEL=y
CONFIG_WLAN_VENDOR_INTERSIL=y
# CONFIG_HOSTAP is not set
# CONFIG_PRISM54 is not set
CONFIG_WLAN_VENDOR_MARVELL=y
CONFIG_WLAN_VENDOR_MEDIATEK=y
CONFIG_WLAN_VENDOR_RALINK=y
CONFIG_WLAN_VENDOR_REALTEK=y
CONFIG_WLAN_VENDOR_RSI=y
CONFIG_WLAN_VENDOR_ST=y
CONFIG_WLAN_VENDOR_TI=y
CONFIG_WLAN_VENDOR_ZYDAS=y
CONFIG_WLAN_VENDOR_QUANTENNA=y
# CONFIG_PCMCIA_RAYCS is not set

#
# Enable WiMAX (Networking options) to see the WiMAX drivers
#
# CONFIG_WAN is not set
# CONFIG_VMXNET3 is not set
# CONFIG_FUJITSU_ES is not set
# CONFIG_NETDEVSIM is not set
# CONFIG_NET_FAILOVER is not set
# CONFIG_ISDN is not set
CONFIG_NVM=y
# CONFIG_NVM_PBLK is not set

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=m
# CONFIG_INPUT_FF_MEMLESS is not set
# CONFIG_INPUT_POLLDEV is not set
# CONFIG_INPUT_SPARSEKMAP is not set
# CONFIG_INPUT_MATRIXKMAP is not set

#
# Userland interfaces
#
# CONFIG_INPUT_MOUSEDEV is not set
# CONFIG_INPUT_JOYDEV is not set
# CONFIG_INPUT_EVDEV is not set
# CONFIG_INPUT_EVBUG is not set

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
# CONFIG_KEYBOARD_ADC is not set
# CONFIG_KEYBOARD_ADP5588 is not set
# CONFIG_KEYBOARD_ADP5589 is not set
CONFIG_KEYBOARD_ATKBD=y
# CONFIG_KEYBOARD_QT1050 is not set
# CONFIG_KEYBOARD_QT1070 is not set
# CONFIG_KEYBOARD_QT2160 is not set
# CONFIG_KEYBOARD_DLINK_DIR685 is not set
# CONFIG_KEYBOARD_LKKBD is not set
# CONFIG_KEYBOARD_GPIO is not set
# CONFIG_KEYBOARD_GPIO_POLLED is not set
# CONFIG_KEYBOARD_TCA6416 is not set
# CONFIG_KEYBOARD_TCA8418 is not set
# CONFIG_KEYBOARD_MATRIX is not set
# CONFIG_KEYBOARD_LM8323 is not set
# CONFIG_KEYBOARD_LM8333 is not set
# CONFIG_KEYBOARD_MAX7359 is not set
# CONFIG_KEYBOARD_MCS is not set
# CONFIG_KEYBOARD_MPR121 is not set
# CONFIG_KEYBOARD_NEWTON is not set
# CONFIG_KEYBOARD_OPENCORES is not set
# CONFIG_KEYBOARD_SAMSUNG is not set
# CONFIG_KEYBOARD_STOWAWAY is not set
# CONFIG_KEYBOARD_SUNKBD is not set
# CONFIG_KEYBOARD_TM2_TOUCHKEY is not set
# CONFIG_KEYBOARD_TWL4030 is not set
# CONFIG_KEYBOARD_XTKBD is not set
# CONFIG_KEYBOARD_CROS_EC is not set
# CONFIG_KEYBOARD_MTK_PMIC is not set
CONFIG_INPUT_MOUSE=y
CONFIG_MOUSE_PS2=y
CONFIG_MOUSE_PS2_ALPS=y
CONFIG_MOUSE_PS2_BYD=y
CONFIG_MOUSE_PS2_LOGIPS2PP=y
CONFIG_MOUSE_PS2_SYNAPTICS=y
CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=y
CONFIG_MOUSE_PS2_CYPRESS=y
CONFIG_MOUSE_PS2_LIFEBOOK=y
CONFIG_MOUSE_PS2_TRACKPOINT=y
# CONFIG_MOUSE_PS2_ELANTECH is not set
# CONFIG_MOUSE_PS2_SENTELIC is not set
# CONFIG_MOUSE_PS2_TOUCHKIT is not set
CONFIG_MOUSE_PS2_FOCALTECH=y
# CONFIG_MOUSE_PS2_VMMOUSE is not set
CONFIG_MOUSE_PS2_SMBUS=y
# CONFIG_MOUSE_SERIAL is not set
# CONFIG_MOUSE_APPLETOUCH is not set
# CONFIG_MOUSE_BCM5974 is not set
# CONFIG_MOUSE_CYAPA is not set
# CONFIG_MOUSE_ELAN_I2C is not set
# CONFIG_MOUSE_VSXXXAA is not set
# CONFIG_MOUSE_GPIO is not set
# CONFIG_MOUSE_SYNAPTICS_I2C is not set
# CONFIG_MOUSE_SYNAPTICS_USB is not set
# CONFIG_INPUT_JOYSTICK is not set
# CONFIG_INPUT_TABLET is not set
# CONFIG_INPUT_TOUCHSCREEN is not set
# CONFIG_INPUT_MISC is not set
# CONFIG_RMI4_CORE is not set

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=y
CONFIG_SERIO_I8042=y
CONFIG_SERIO_SERPORT=y
# CONFIG_SERIO_CT82C710 is not set
# CONFIG_SERIO_PARKBD is not set
# CONFIG_SERIO_PCIPS2 is not set
CONFIG_SERIO_LIBPS2=y
# CONFIG_SERIO_RAW is not set
# CONFIG_SERIO_ALTERA_PS2 is not set
# CONFIG_SERIO_PS2MULT is not set
# CONFIG_SERIO_ARC_PS2 is not set
# CONFIG_SERIO_GPIO_PS2 is not set
# CONFIG_USERIO is not set
CONFIG_GAMEPORT=y
CONFIG_GAMEPORT_NS558=y
CONFIG_GAMEPORT_L4=y
CONFIG_GAMEPORT_EMU10K1=y
CONFIG_GAMEPORT_FM801=y
# end of Hardware I/O ports
# end of Input device support

#
# Character devices
#
CONFIG_TTY=y
# CONFIG_VT is not set
CONFIG_UNIX98_PTYS=y
CONFIG_LEGACY_PTYS=y
CONFIG_LEGACY_PTY_COUNT=256
# CONFIG_SERIAL_NONSTANDARD is not set
# CONFIG_NOZOMI is not set
# CONFIG_N_GSM is not set
# CONFIG_TRACE_SINK is not set
# CONFIG_NULL_TTY is not set
CONFIG_LDISC_AUTOLOAD=y
CONFIG_DEVMEM=y
# CONFIG_DEVKMEM is not set

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_DEPRECATED_OPTIONS=y
CONFIG_SERIAL_8250_PNP=y
# CONFIG_SERIAL_8250_FINTEK is not set
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=y
# CONFIG_SERIAL_8250_CS is not set
CONFIG_SERIAL_8250_NR_UARTS=4
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
# CONFIG_SERIAL_8250_EXTENDED is not set
CONFIG_SERIAL_8250_DWLIB=y
# CONFIG_SERIAL_8250_DW is not set
# CONFIG_SERIAL_8250_RT288X is not set
CONFIG_SERIAL_8250_LPSS=y
CONFIG_SERIAL_8250_MID=y

#
# Non-8250 serial port support
#
# CONFIG_SERIAL_MAX3100 is not set
# CONFIG_SERIAL_MAX310X is not set
# CONFIG_SERIAL_UARTLITE is not set
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
# CONFIG_SERIAL_JSM is not set
# CONFIG_SERIAL_SCCNXP is not set
# CONFIG_SERIAL_SC16IS7XX is not set
# CONFIG_SERIAL_ALTERA_JTAGUART is not set
# CONFIG_SERIAL_ALTERA_UART is not set
# CONFIG_SERIAL_IFX6X60 is not set
# CONFIG_SERIAL_ARC is not set
# CONFIG_SERIAL_RP2 is not set
# CONFIG_SERIAL_FSL_LPUART is not set
# CONFIG_SERIAL_FSL_LINFLEXUART is not set
# end of Serial drivers

CONFIG_SERIAL_MCTRL_GPIO=y
CONFIG_SERIAL_DEV_BUS=m
# CONFIG_TTY_PRINTK is not set
CONFIG_PRINTER=m
CONFIG_LP_CONSOLE=y
CONFIG_PPDEV=y
CONFIG_IPMI_HANDLER=m
CONFIG_IPMI_DMI_DECODE=y
CONFIG_IPMI_PLAT_DATA=y
# CONFIG_IPMI_PANIC_EVENT is not set
CONFIG_IPMI_DEVICE_INTERFACE=m
CONFIG_IPMI_SI=m
# CONFIG_IPMI_SSIF is not set
CONFIG_IPMI_WATCHDOG=m
CONFIG_IPMI_POWEROFF=m
# CONFIG_IPMB_DEVICE_INTERFACE is not set
# CONFIG_HW_RANDOM is not set
CONFIG_NVRAM=y
CONFIG_APPLICOM=y

#
# PCMCIA character devices
#
# CONFIG_SYNCLINK_CS is not set
CONFIG_CARDMAN_4000=m
CONFIG_CARDMAN_4040=m
# CONFIG_SCR24X is not set
# CONFIG_IPWIRELESS is not set
# end of PCMCIA character devices

# CONFIG_MWAVE is not set
# CONFIG_RAW_DRIVER is not set
# CONFIG_HPET is not set
CONFIG_HANGCHECK_TIMER=y
CONFIG_TCG_TPM=m
CONFIG_TCG_TIS_CORE=m
CONFIG_TCG_TIS=m
CONFIG_TCG_TIS_SPI=m
# CONFIG_TCG_TIS_SPI_CR50 is not set
CONFIG_TCG_TIS_I2C_ATMEL=m
# CONFIG_TCG_TIS_I2C_INFINEON is not set
CONFIG_TCG_TIS_I2C_NUVOTON=m
CONFIG_TCG_NSC=m
CONFIG_TCG_ATMEL=m
# CONFIG_TCG_INFINEON is not set
# CONFIG_TCG_CRB is not set
CONFIG_TCG_VTPM_PROXY=m
CONFIG_TCG_TIS_ST33ZP24=m
# CONFIG_TCG_TIS_ST33ZP24_I2C is not set
CONFIG_TCG_TIS_ST33ZP24_SPI=m
# CONFIG_TELCLOCK is not set
# CONFIG_DEVPORT is not set
# CONFIG_XILLYBUS is not set
# end of Character devices

# CONFIG_RANDOM_TRUST_CPU is not set
CONFIG_RANDOM_TRUST_BOOTLOADER=y

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
# CONFIG_I2C_COMPAT is not set
CONFIG_I2C_CHARDEV=y
CONFIG_I2C_MUX=m

#
# Multiplexer I2C Chip support
#
CONFIG_I2C_MUX_GPIO=m
CONFIG_I2C_MUX_LTC4306=m
CONFIG_I2C_MUX_PCA9541=m
CONFIG_I2C_MUX_PCA954x=m
# CONFIG_I2C_MUX_REG is not set
CONFIG_I2C_MUX_MLXCPLD=m
# end of Multiplexer I2C Chip support

CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=y
CONFIG_I2C_ALGOBIT=y
CONFIG_I2C_ALGOPCA=m

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
CONFIG_I2C_ALI1535=m
CONFIG_I2C_ALI1563=m
CONFIG_I2C_ALI15X3=y
CONFIG_I2C_AMD756=m
CONFIG_I2C_AMD756_S4882=m
CONFIG_I2C_AMD8111=m
# CONFIG_I2C_AMD_MP2 is not set
# CONFIG_I2C_I801 is not set
CONFIG_I2C_ISCH=y
# CONFIG_I2C_ISMT is not set
CONFIG_I2C_PIIX4=m
CONFIG_I2C_NFORCE2=m
CONFIG_I2C_NFORCE2_S4985=m
CONFIG_I2C_NVIDIA_GPU=y
CONFIG_I2C_SIS5595=m
CONFIG_I2C_SIS630=m
# CONFIG_I2C_SIS96X is not set
# CONFIG_I2C_VIA is not set
# CONFIG_I2C_VIAPRO is not set

#
# ACPI drivers
#
# CONFIG_I2C_SCMI is not set

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
# CONFIG_I2C_CBUS_GPIO is not set
CONFIG_I2C_DESIGNWARE_CORE=y
CONFIG_I2C_DESIGNWARE_PLATFORM=y
CONFIG_I2C_DESIGNWARE_SLAVE=y
CONFIG_I2C_DESIGNWARE_PCI=y
# CONFIG_I2C_DESIGNWARE_BAYTRAIL is not set
CONFIG_I2C_EMEV2=m
# CONFIG_I2C_GPIO is not set
CONFIG_I2C_OCORES=m
CONFIG_I2C_PCA_PLATFORM=m
# CONFIG_I2C_SIMTEC is not set
# CONFIG_I2C_XILINX is not set

#
# External I2C/SMBus adapter drivers
#
CONFIG_I2C_PARPORT=y
# CONFIG_I2C_PARPORT_LIGHT is not set
# CONFIG_I2C_TAOS_EVM is not set

#
# Other I2C/SMBus bus drivers
#
CONFIG_I2C_MLXCPLD=m
CONFIG_I2C_CROS_EC_TUNNEL=y
# end of I2C Hardware Bus support

CONFIG_I2C_STUB=m
CONFIG_I2C_SLAVE=y
CONFIG_I2C_SLAVE_EEPROM=m
# CONFIG_I2C_DEBUG_CORE is not set
# CONFIG_I2C_DEBUG_ALGO is not set
# CONFIG_I2C_DEBUG_BUS is not set
# end of I2C support

CONFIG_I3C=y
CONFIG_CDNS_I3C_MASTER=m
# CONFIG_DW_I3C_MASTER is not set
CONFIG_SPI=y
CONFIG_SPI_DEBUG=y
CONFIG_SPI_MASTER=y
CONFIG_SPI_MEM=y

#
# SPI Master Controller Drivers
#
CONFIG_SPI_ALTERA=m
# CONFIG_SPI_AXI_SPI_ENGINE is not set
CONFIG_SPI_BITBANG=y
CONFIG_SPI_BUTTERFLY=y
CONFIG_SPI_CADENCE=y
CONFIG_SPI_DESIGNWARE=m
CONFIG_SPI_DW_PCI=m
CONFIG_SPI_DW_MMIO=m
# CONFIG_SPI_NXP_FLEXSPI is not set
# CONFIG_SPI_GPIO is not set
# CONFIG_SPI_LM70_LLP is not set
CONFIG_SPI_OC_TINY=y
CONFIG_SPI_PXA2XX=m
CONFIG_SPI_PXA2XX_PCI=m
CONFIG_SPI_ROCKCHIP=m
CONFIG_SPI_SC18IS602=y
CONFIG_SPI_SIFIVE=y
CONFIG_SPI_MXIC=m
CONFIG_SPI_XCOMM=y
CONFIG_SPI_XILINX=y
CONFIG_SPI_ZYNQMP_GQSPI=y

#
# SPI Protocol Masters
#
# CONFIG_SPI_SPIDEV is not set
# CONFIG_SPI_LOOPBACK_TEST is not set
CONFIG_SPI_TLE62X0=m
# CONFIG_SPI_SLAVE is not set
CONFIG_SPMI=m
CONFIG_HSI=y
CONFIG_HSI_BOARDINFO=y

#
# HSI controllers
#

#
# HSI clients
#
# CONFIG_HSI_CHAR is not set
CONFIG_PPS=y
# CONFIG_PPS_DEBUG is not set

#
# PPS clients support
#
CONFIG_PPS_CLIENT_KTIMER=m
# CONFIG_PPS_CLIENT_LDISC is not set
CONFIG_PPS_CLIENT_PARPORT=y
# CONFIG_PPS_CLIENT_GPIO is not set

#
# PPS generators support
#

#
# PTP clock support
#
# CONFIG_PTP_1588_CLOCK is not set

#
# Enable PHYLIB and NETWORK_PHY_TIMESTAMPING to see the additional clocks.
#
# end of PTP clock support

CONFIG_PINCTRL=y
CONFIG_PINMUX=y
CONFIG_PINCONF=y
CONFIG_GENERIC_PINCONF=y
# CONFIG_DEBUG_PINCTRL is not set
CONFIG_PINCTRL_AMD=y
# CONFIG_PINCTRL_MCP23S08 is not set
# CONFIG_PINCTRL_SX150X is not set
# CONFIG_PINCTRL_BAYTRAIL is not set
# CONFIG_PINCTRL_CHERRYVIEW is not set
# CONFIG_PINCTRL_BROXTON is not set
# CONFIG_PINCTRL_CANNONLAKE is not set
# CONFIG_PINCTRL_CEDARFORK is not set
# CONFIG_PINCTRL_DENVERTON is not set
# CONFIG_PINCTRL_GEMINILAKE is not set
# CONFIG_PINCTRL_ICELAKE is not set
# CONFIG_PINCTRL_LEWISBURG is not set
# CONFIG_PINCTRL_SUNRISEPOINT is not set
# CONFIG_PINCTRL_TIGERLAKE is not set
CONFIG_PINCTRL_MADERA=m
CONFIG_PINCTRL_CS47L35=y
CONFIG_PINCTRL_CS47L85=y
CONFIG_PINCTRL_CS47L92=y
# CONFIG_PINCTRL_EQUILIBRIUM is not set
CONFIG_GPIOLIB=y
CONFIG_GPIOLIB_FASTPATH_LIMIT=512
CONFIG_GPIO_ACPI=y
CONFIG_GPIOLIB_IRQCHIP=y
# CONFIG_DEBUG_GPIO is not set
CONFIG_GPIO_SYSFS=y
CONFIG_GPIO_GENERIC=y
CONFIG_GPIO_MAX730X=y

#
# Memory mapped GPIO drivers
#
# CONFIG_GPIO_AMDPT is not set
CONFIG_GPIO_DWAPB=m
# CONFIG_GPIO_EXAR is not set
CONFIG_GPIO_GENERIC_PLATFORM=y
CONFIG_GPIO_ICH=m
# CONFIG_GPIO_LYNXPOINT is not set
# CONFIG_GPIO_MB86S7X is not set
CONFIG_GPIO_VX855=m
# CONFIG_GPIO_XILINX is not set
# CONFIG_GPIO_AMD_FCH is not set
# end of Memory mapped GPIO drivers

#
# Port-mapped I/O GPIO drivers
#
CONFIG_GPIO_104_DIO_48E=y
CONFIG_GPIO_104_IDIO_16=y
CONFIG_GPIO_104_IDI_48=m
# CONFIG_GPIO_F7188X is not set
# CONFIG_GPIO_GPIO_MM is not set
CONFIG_GPIO_IT87=y
CONFIG_GPIO_SCH=y
CONFIG_GPIO_SCH311X=y
CONFIG_GPIO_WINBOND=m
CONFIG_GPIO_WS16C48=m
# end of Port-mapped I/O GPIO drivers

#
# I2C GPIO expanders
#
# CONFIG_GPIO_ADP5588 is not set
CONFIG_GPIO_MAX7300=y
CONFIG_GPIO_MAX732X=y
# CONFIG_GPIO_MAX732X_IRQ is not set
CONFIG_GPIO_PCA953X=m
# CONFIG_GPIO_PCF857X is not set
CONFIG_GPIO_TPIC2810=m
# end of I2C GPIO expanders

#
# MFD GPIO expanders
#
CONFIG_GPIO_ARIZONA=y
CONFIG_GPIO_BD9571MWV=m
CONFIG_GPIO_DA9052=y
CONFIG_GPIO_JANZ_TTL=m
CONFIG_GPIO_LP3943=m
CONFIG_GPIO_LP873X=m
CONFIG_GPIO_MADERA=m
# CONFIG_GPIO_TPS65912 is not set
# CONFIG_GPIO_TWL4030 is not set
# CONFIG_GPIO_WM831X is not set
CONFIG_GPIO_WM8350=y
CONFIG_GPIO_WM8994=m
# end of MFD GPIO expanders

#
# PCI GPIO expanders
#
CONFIG_GPIO_AMD8111=y
# CONFIG_GPIO_BT8XX is not set
# CONFIG_GPIO_ML_IOH is not set
CONFIG_GPIO_PCI_IDIO_16=y
CONFIG_GPIO_PCIE_IDIO_24=y
CONFIG_GPIO_RDC321X=y
# end of PCI GPIO expanders

#
# SPI GPIO expanders
#
CONFIG_GPIO_MAX3191X=m
CONFIG_GPIO_MAX7301=m
# CONFIG_GPIO_MC33880 is not set
CONFIG_GPIO_PISOSR=m
# CONFIG_GPIO_XRA1403 is not set
# end of SPI GPIO expanders

CONFIG_GPIO_MOCKUP=y
CONFIG_W1=y

#
# 1-wire Bus Masters
#
CONFIG_W1_MASTER_MATROX=y
CONFIG_W1_MASTER_DS2482=y
CONFIG_W1_MASTER_DS1WM=y
CONFIG_W1_MASTER_GPIO=y
CONFIG_W1_MASTER_SGI=y
# end of 1-wire Bus Masters

#
# 1-wire Slaves
#
# CONFIG_W1_SLAVE_THERM is not set
CONFIG_W1_SLAVE_SMEM=m
CONFIG_W1_SLAVE_DS2405=m
CONFIG_W1_SLAVE_DS2408=m
CONFIG_W1_SLAVE_DS2408_READBACK=y
CONFIG_W1_SLAVE_DS2413=m
CONFIG_W1_SLAVE_DS2406=m
CONFIG_W1_SLAVE_DS2423=y
# CONFIG_W1_SLAVE_DS2805 is not set
CONFIG_W1_SLAVE_DS2430=m
CONFIG_W1_SLAVE_DS2431=m
CONFIG_W1_SLAVE_DS2433=m
CONFIG_W1_SLAVE_DS2433_CRC=y
# CONFIG_W1_SLAVE_DS2438 is not set
CONFIG_W1_SLAVE_DS250X=m
CONFIG_W1_SLAVE_DS2780=y
CONFIG_W1_SLAVE_DS2781=m
# CONFIG_W1_SLAVE_DS28E04 is not set
CONFIG_W1_SLAVE_DS28E17=m
# end of 1-wire Slaves

CONFIG_POWER_AVS=y
CONFIG_POWER_RESET=y
# CONFIG_POWER_RESET_RESTART is not set
CONFIG_POWER_SUPPLY=y
# CONFIG_POWER_SUPPLY_DEBUG is not set
CONFIG_POWER_SUPPLY_HWMON=y
CONFIG_PDA_POWER=m
CONFIG_GENERIC_ADC_BATTERY=m
CONFIG_WM831X_BACKUP=y
CONFIG_WM831X_POWER=m
# CONFIG_WM8350_POWER is not set
# CONFIG_TEST_POWER is not set
CONFIG_CHARGER_ADP5061=y
# CONFIG_BATTERY_DS2760 is not set
CONFIG_BATTERY_DS2780=y
# CONFIG_BATTERY_DS2781 is not set
CONFIG_BATTERY_DS2782=m
# CONFIG_BATTERY_SBS is not set
# CONFIG_CHARGER_SBS is not set
CONFIG_MANAGER_SBS=m
CONFIG_BATTERY_BQ27XXX=y
CONFIG_BATTERY_BQ27XXX_I2C=y
# CONFIG_BATTERY_BQ27XXX_HDQ is not set
CONFIG_BATTERY_BQ27XXX_DT_UPDATES_NVM=y
CONFIG_BATTERY_DA9052=m
CONFIG_CHARGER_DA9150=m
CONFIG_BATTERY_DA9150=m
# CONFIG_AXP20X_POWER is not set
CONFIG_AXP288_FUEL_GAUGE=m
CONFIG_BATTERY_MAX17040=m
CONFIG_BATTERY_MAX17042=m
# CONFIG_BATTERY_MAX1721X is not set
CONFIG_CHARGER_PCF50633=m
# CONFIG_CHARGER_MAX8903 is not set
# CONFIG_CHARGER_TWL4030 is not set
CONFIG_CHARGER_LP8727=m
# CONFIG_CHARGER_GPIO is not set
CONFIG_CHARGER_MANAGER=y
CONFIG_CHARGER_LT3651=m
# CONFIG_CHARGER_MAX77693 is not set
# CONFIG_CHARGER_BQ2415X is not set
CONFIG_CHARGER_BQ24190=m
# CONFIG_CHARGER_BQ24257 is not set
CONFIG_CHARGER_BQ24735=y
CONFIG_CHARGER_BQ25890=m
CONFIG_CHARGER_SMB347=y
CONFIG_CHARGER_TPS65090=m
CONFIG_BATTERY_GAUGE_LTC2941=m
# CONFIG_CHARGER_RT9455 is not set
CONFIG_CHARGER_CROS_USBPD=m
CONFIG_HWMON=y
CONFIG_HWMON_VID=y
CONFIG_HWMON_DEBUG_CHIP=y

#
# Native drivers
#
CONFIG_SENSORS_ABITUGURU=y
CONFIG_SENSORS_ABITUGURU3=y
CONFIG_SENSORS_AD7314=y
CONFIG_SENSORS_AD7414=y
# CONFIG_SENSORS_AD7418 is not set
# CONFIG_SENSORS_ADM1021 is not set
# CONFIG_SENSORS_ADM1025 is not set
CONFIG_SENSORS_ADM1026=y
CONFIG_SENSORS_ADM1029=y
# CONFIG_SENSORS_ADM1031 is not set
# CONFIG_SENSORS_ADM9240 is not set
CONFIG_SENSORS_ADT7X10=m
CONFIG_SENSORS_ADT7310=m
CONFIG_SENSORS_ADT7410=m
CONFIG_SENSORS_ADT7411=y
CONFIG_SENSORS_ADT7462=m
# CONFIG_SENSORS_ADT7470 is not set
# CONFIG_SENSORS_ADT7475 is not set
# CONFIG_SENSORS_AS370 is not set
CONFIG_SENSORS_ASC7621=m
# CONFIG_SENSORS_K8TEMP is not set
CONFIG_SENSORS_K10TEMP=y
CONFIG_SENSORS_FAM15H_POWER=m
# CONFIG_SENSORS_APPLESMC is not set
CONFIG_SENSORS_ASB100=y
CONFIG_SENSORS_ASPEED=y
CONFIG_SENSORS_ATXP1=m
CONFIG_SENSORS_DS620=m
CONFIG_SENSORS_DS1621=m
CONFIG_SENSORS_DELL_SMM=y
# CONFIG_SENSORS_DA9052_ADC is not set
CONFIG_SENSORS_I5K_AMB=y
# CONFIG_SENSORS_F71805F is not set
# CONFIG_SENSORS_F71882FG is not set
CONFIG_SENSORS_F75375S=m
# CONFIG_SENSORS_MC13783_ADC is not set
CONFIG_SENSORS_FSCHMD=y
CONFIG_SENSORS_FTSTEUTATES=y
# CONFIG_SENSORS_GL518SM is not set
# CONFIG_SENSORS_GL520SM is not set
CONFIG_SENSORS_G760A=y
CONFIG_SENSORS_G762=m
CONFIG_SENSORS_HIH6130=y
CONFIG_SENSORS_IBMAEM=m
CONFIG_SENSORS_IBMPEX=m
CONFIG_SENSORS_IIO_HWMON=m
# CONFIG_SENSORS_I5500 is not set
# CONFIG_SENSORS_CORETEMP is not set
CONFIG_SENSORS_IT87=m
CONFIG_SENSORS_JC42=y
# CONFIG_SENSORS_POWR1220 is not set
CONFIG_SENSORS_LINEAGE=y
CONFIG_SENSORS_LTC2945=m
CONFIG_SENSORS_LTC2947=y
CONFIG_SENSORS_LTC2947_I2C=y
CONFIG_SENSORS_LTC2947_SPI=y
CONFIG_SENSORS_LTC2990=y
CONFIG_SENSORS_LTC4151=y
# CONFIG_SENSORS_LTC4215 is not set
# CONFIG_SENSORS_LTC4222 is not set
# CONFIG_SENSORS_LTC4245 is not set
# CONFIG_SENSORS_LTC4260 is not set
CONFIG_SENSORS_LTC4261=y
# CONFIG_SENSORS_MAX1111 is not set
CONFIG_SENSORS_MAX16065=y
CONFIG_SENSORS_MAX1619=m
# CONFIG_SENSORS_MAX1668 is not set
CONFIG_SENSORS_MAX197=m
CONFIG_SENSORS_MAX31722=m
# CONFIG_SENSORS_MAX6621 is not set
CONFIG_SENSORS_MAX6639=y
CONFIG_SENSORS_MAX6642=m
CONFIG_SENSORS_MAX6650=m
# CONFIG_SENSORS_MAX6697 is not set
CONFIG_SENSORS_MAX31790=m
CONFIG_SENSORS_MCP3021=y
# CONFIG_SENSORS_MLXREG_FAN is not set
CONFIG_SENSORS_TC654=y
CONFIG_SENSORS_MENF21BMC_HWMON=m
# CONFIG_SENSORS_ADCXX is not set
CONFIG_SENSORS_LM63=y
CONFIG_SENSORS_LM70=m
CONFIG_SENSORS_LM73=m
# CONFIG_SENSORS_LM75 is not set
CONFIG_SENSORS_LM77=m
CONFIG_SENSORS_LM78=m
CONFIG_SENSORS_LM80=m
CONFIG_SENSORS_LM83=y
# CONFIG_SENSORS_LM85 is not set
CONFIG_SENSORS_LM87=m
# CONFIG_SENSORS_LM90 is not set
# CONFIG_SENSORS_LM92 is not set
CONFIG_SENSORS_LM93=m
# CONFIG_SENSORS_LM95234 is not set
CONFIG_SENSORS_LM95241=y
# CONFIG_SENSORS_LM95245 is not set
# CONFIG_SENSORS_PC87360 is not set
CONFIG_SENSORS_PC87427=m
CONFIG_SENSORS_NTC_THERMISTOR=y
CONFIG_SENSORS_NCT6683=m
CONFIG_SENSORS_NCT6775=m
CONFIG_SENSORS_NCT7802=m
CONFIG_SENSORS_NCT7904=y
CONFIG_SENSORS_NPCM7XX=y
CONFIG_SENSORS_PCF8591=m
CONFIG_PMBUS=m
# CONFIG_SENSORS_PMBUS is not set
# CONFIG_SENSORS_ADM1275 is not set
CONFIG_SENSORS_BEL_PFE=m
# CONFIG_SENSORS_IBM_CFFPS is not set
CONFIG_SENSORS_INSPUR_IPSPS=m
CONFIG_SENSORS_IR35221=m
CONFIG_SENSORS_IR38064=m
CONFIG_SENSORS_IRPS5401=m
CONFIG_SENSORS_ISL68137=m
# CONFIG_SENSORS_LM25066 is not set
# CONFIG_SENSORS_LTC2978 is not set
CONFIG_SENSORS_LTC3815=m
CONFIG_SENSORS_MAX16064=m
CONFIG_SENSORS_MAX20751=m
# CONFIG_SENSORS_MAX31785 is not set
# CONFIG_SENSORS_MAX34440 is not set
CONFIG_SENSORS_MAX8688=m
# CONFIG_SENSORS_PXE1610 is not set
CONFIG_SENSORS_TPS40422=m
CONFIG_SENSORS_TPS53679=m
# CONFIG_SENSORS_UCD9000 is not set
CONFIG_SENSORS_UCD9200=m
CONFIG_SENSORS_ZL6100=m
CONFIG_SENSORS_SHT15=m
CONFIG_SENSORS_SHT21=m
CONFIG_SENSORS_SHT3x=m
# CONFIG_SENSORS_SHTC1 is not set
CONFIG_SENSORS_SIS5595=m
CONFIG_SENSORS_DME1737=m
CONFIG_SENSORS_EMC1403=m
CONFIG_SENSORS_EMC2103=y
# CONFIG_SENSORS_EMC6W201 is not set
# CONFIG_SENSORS_SMSC47M1 is not set
CONFIG_SENSORS_SMSC47M192=m
CONFIG_SENSORS_SMSC47B397=m
# CONFIG_SENSORS_SCH5627 is not set
# CONFIG_SENSORS_SCH5636 is not set
CONFIG_SENSORS_STTS751=y
CONFIG_SENSORS_SMM665=y
CONFIG_SENSORS_ADC128D818=y
CONFIG_SENSORS_ADS7828=m
CONFIG_SENSORS_ADS7871=m
# CONFIG_SENSORS_AMC6821 is not set
# CONFIG_SENSORS_INA209 is not set
CONFIG_SENSORS_INA2XX=m
# CONFIG_SENSORS_INA3221 is not set
# CONFIG_SENSORS_TC74 is not set
CONFIG_SENSORS_THMC50=m
# CONFIG_SENSORS_TMP102 is not set
# CONFIG_SENSORS_TMP103 is not set
# CONFIG_SENSORS_TMP108 is not set
CONFIG_SENSORS_TMP401=y
CONFIG_SENSORS_TMP421=y
# CONFIG_SENSORS_TMP513 is not set
CONFIG_SENSORS_VIA_CPUTEMP=m
# CONFIG_SENSORS_VIA686A is not set
CONFIG_SENSORS_VT1211=y
CONFIG_SENSORS_VT8231=m
# CONFIG_SENSORS_W83773G is not set
CONFIG_SENSORS_W83781D=y
# CONFIG_SENSORS_W83791D is not set
CONFIG_SENSORS_W83792D=y
CONFIG_SENSORS_W83793=y
CONFIG_SENSORS_W83795=m
# CONFIG_SENSORS_W83795_FANCTRL is not set
CONFIG_SENSORS_W83L785TS=y
# CONFIG_SENSORS_W83L786NG is not set
CONFIG_SENSORS_W83627HF=m
# CONFIG_SENSORS_W83627EHF is not set
CONFIG_SENSORS_WM831X=y
CONFIG_SENSORS_WM8350=m

#
# ACPI drivers
#
# CONFIG_SENSORS_ACPI_POWER is not set
# CONFIG_SENSORS_ATK0110 is not set
CONFIG_THERMAL=y
# CONFIG_THERMAL_STATISTICS is not set
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_WRITABLE_TRIPS=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
# CONFIG_THERMAL_DEFAULT_GOV_POWER_ALLOCATOR is not set
# CONFIG_THERMAL_GOV_FAIR_SHARE is not set
CONFIG_THERMAL_GOV_STEP_WISE=y
# CONFIG_THERMAL_GOV_BANG_BANG is not set
CONFIG_THERMAL_GOV_USER_SPACE=y
# CONFIG_THERMAL_GOV_POWER_ALLOCATOR is not set
# CONFIG_CLOCK_THERMAL is not set
# CONFIG_DEVFREQ_THERMAL is not set
# CONFIG_THERMAL_EMULATION is not set

#
# Intel thermal drivers
#
# CONFIG_INTEL_POWERCLAMP is not set
CONFIG_X86_PKG_TEMP_THERMAL=m
# CONFIG_INTEL_SOC_DTS_THERMAL is not set

#
# ACPI INT340X thermal drivers
#
# CONFIG_INT340X_THERMAL is not set
# end of ACPI INT340X thermal drivers

# CONFIG_INTEL_PCH_THERMAL is not set
# end of Intel thermal drivers

# CONFIG_GENERIC_ADC_THERMAL is not set
CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_CORE=y
CONFIG_WATCHDOG_NOWAYOUT=y
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_OPEN_TIMEOUT=0
CONFIG_WATCHDOG_SYSFS=y

#
# Watchdog Pretimeout Governors
#
# CONFIG_WATCHDOG_PRETIMEOUT_GOV is not set

#
# Watchdog Device Drivers
#
# CONFIG_SOFT_WATCHDOG is not set
CONFIG_DA9052_WATCHDOG=y
# CONFIG_DA9063_WATCHDOG is not set
# CONFIG_DA9062_WATCHDOG is not set
# CONFIG_MENF21BMC_WATCHDOG is not set
# CONFIG_WDAT_WDT is not set
CONFIG_WM831X_WATCHDOG=y
CONFIG_WM8350_WATCHDOG=y
# CONFIG_XILINX_WATCHDOG is not set
# CONFIG_ZIIRAVE_WATCHDOG is not set
CONFIG_MLX_WDT=y
# CONFIG_CADENCE_WATCHDOG is not set
# CONFIG_DW_WATCHDOG is not set
CONFIG_TWL4030_WATCHDOG=y
# CONFIG_MAX63XX_WATCHDOG is not set
CONFIG_RETU_WATCHDOG=m
CONFIG_ACQUIRE_WDT=m
# CONFIG_ADVANTECH_WDT is not set
CONFIG_ALIM1535_WDT=m
CONFIG_ALIM7101_WDT=y
CONFIG_EBC_C384_WDT=y
CONFIG_F71808E_WDT=y
CONFIG_SP5100_TCO=y
CONFIG_SBC_FITPC2_WATCHDOG=m
# CONFIG_EUROTECH_WDT is not set
CONFIG_IB700_WDT=y
CONFIG_IBMASR=m
# CONFIG_WAFER_WDT is not set
# CONFIG_I6300ESB_WDT is not set
CONFIG_IE6XX_WDT=y
# CONFIG_ITCO_WDT is not set
CONFIG_IT8712F_WDT=m
CONFIG_IT87_WDT=m
CONFIG_HP_WATCHDOG=y
CONFIG_HPWDT_NMI_DECODING=y
CONFIG_SC1200_WDT=y
CONFIG_PC87413_WDT=y
CONFIG_NV_TCO=y
CONFIG_60XX_WDT=m
CONFIG_CPU5_WDT=m
CONFIG_SMSC_SCH311X_WDT=m
# CONFIG_SMSC37B787_WDT is not set
# CONFIG_TQMX86_WDT is not set
CONFIG_VIA_WDT=m
CONFIG_W83627HF_WDT=m
CONFIG_W83877F_WDT=m
# CONFIG_W83977F_WDT is not set
CONFIG_MACHZ_WDT=m
CONFIG_SBC_EPX_C3_WATCHDOG=m
CONFIG_INTEL_MEI_WDT=y
# CONFIG_NI903X_WDT is not set
# CONFIG_NIC7018_WDT is not set
CONFIG_MEN_A21_WDT=m

#
# PCI-based Watchdog Cards
#
# CONFIG_PCIPCWATCHDOG is not set
CONFIG_WDTPCI=m
CONFIG_SSB_POSSIBLE=y
CONFIG_SSB=m
CONFIG_SSB_SPROM=y
CONFIG_SSB_PCIHOST_POSSIBLE=y
CONFIG_SSB_PCIHOST=y
CONFIG_SSB_PCMCIAHOST_POSSIBLE=y
CONFIG_SSB_PCMCIAHOST=y
CONFIG_SSB_SDIOHOST_POSSIBLE=y
CONFIG_SSB_SDIOHOST=y
CONFIG_SSB_DRIVER_PCICORE_POSSIBLE=y
# CONFIG_SSB_DRIVER_PCICORE is not set
# CONFIG_SSB_DRIVER_GPIO is not set
CONFIG_BCMA_POSSIBLE=y
CONFIG_BCMA=m
CONFIG_BCMA_HOST_PCI_POSSIBLE=y
CONFIG_BCMA_HOST_PCI=y
CONFIG_BCMA_HOST_SOC=y
CONFIG_BCMA_DRIVER_PCI=y
# CONFIG_BCMA_SFLASH is not set
# CONFIG_BCMA_DRIVER_GMAC_CMN is not set
CONFIG_BCMA_DRIVER_GPIO=y
CONFIG_BCMA_DEBUG=y

#
# Multifunction device drivers
#
CONFIG_MFD_CORE=y
CONFIG_MFD_AS3711=y
# CONFIG_PMIC_ADP5520 is not set
# CONFIG_MFD_AAT2870_CORE is not set
CONFIG_MFD_BCM590XX=m
CONFIG_MFD_BD9571MWV=y
CONFIG_MFD_AXP20X=y
CONFIG_MFD_AXP20X_I2C=y
CONFIG_MFD_CROS_EC_DEV=m
CONFIG_MFD_MADERA=m
CONFIG_MFD_MADERA_I2C=m
CONFIG_MFD_MADERA_SPI=m
# CONFIG_MFD_CS47L15 is not set
CONFIG_MFD_CS47L35=y
CONFIG_MFD_CS47L85=y
# CONFIG_MFD_CS47L90 is not set
CONFIG_MFD_CS47L92=y
# CONFIG_PMIC_DA903X is not set
CONFIG_PMIC_DA9052=y
CONFIG_MFD_DA9052_SPI=y
CONFIG_MFD_DA9052_I2C=y
# CONFIG_MFD_DA9055 is not set
CONFIG_MFD_DA9062=m
CONFIG_MFD_DA9063=y
CONFIG_MFD_DA9150=y
CONFIG_MFD_MC13XXX=m
CONFIG_MFD_MC13XXX_SPI=m
# CONFIG_MFD_MC13XXX_I2C is not set
CONFIG_HTC_PASIC3=m
CONFIG_HTC_I2CPLD=y
CONFIG_MFD_INTEL_QUARK_I2C_GPIO=m
CONFIG_LPC_ICH=m
CONFIG_LPC_SCH=y
# CONFIG_INTEL_SOC_PMIC is not set
# CONFIG_INTEL_SOC_PMIC_CHTWC is not set
# CONFIG_INTEL_SOC_PMIC_CHTDC_TI is not set
# CONFIG_MFD_INTEL_LPSS_ACPI is not set
# CONFIG_MFD_INTEL_LPSS_PCI is not set
CONFIG_MFD_JANZ_CMODIO=m
# CONFIG_MFD_KEMPLD is not set
CONFIG_MFD_88PM800=y
CONFIG_MFD_88PM805=m
# CONFIG_MFD_88PM860X is not set
# CONFIG_MFD_MAX14577 is not set
CONFIG_MFD_MAX77693=m
CONFIG_MFD_MAX77843=y
CONFIG_MFD_MAX8907=y
# CONFIG_MFD_MAX8925 is not set
# CONFIG_MFD_MAX8997 is not set
# CONFIG_MFD_MAX8998 is not set
CONFIG_MFD_MT6397=m
CONFIG_MFD_MENF21BMC=m
CONFIG_EZX_PCAP=y
CONFIG_MFD_RETU=y
CONFIG_MFD_PCF50633=y
CONFIG_PCF50633_ADC=y
CONFIG_PCF50633_GPIO=m
CONFIG_MFD_RDC321X=y
# CONFIG_MFD_RT5033 is not set
# CONFIG_MFD_RC5T583 is not set
# CONFIG_MFD_SEC_CORE is not set
CONFIG_MFD_SI476X_CORE=y
CONFIG_MFD_SM501=y
# CONFIG_MFD_SM501_GPIO is not set
CONFIG_MFD_SKY81452=m
# CONFIG_MFD_SMSC is not set
CONFIG_ABX500_CORE=y
CONFIG_AB3100_CORE=y
CONFIG_AB3100_OTP=m
CONFIG_MFD_SYSCON=y
# CONFIG_MFD_TI_AM335X_TSCADC is not set
CONFIG_MFD_LP3943=m
# CONFIG_MFD_LP8788 is not set
CONFIG_MFD_TI_LMU=y
# CONFIG_MFD_PALMAS is not set
CONFIG_TPS6105X=m
# CONFIG_TPS65010 is not set
# CONFIG_TPS6507X is not set
# CONFIG_MFD_TPS65086 is not set
CONFIG_MFD_TPS65090=y
# CONFIG_MFD_TPS68470 is not set
CONFIG_MFD_TI_LP873X=m
# CONFIG_MFD_TPS6586X is not set
# CONFIG_MFD_TPS65910 is not set
CONFIG_MFD_TPS65912=m
CONFIG_MFD_TPS65912_I2C=m
# CONFIG_MFD_TPS65912_SPI is not set
CONFIG_MFD_TPS80031=y
CONFIG_TWL4030_CORE=y
CONFIG_MFD_TWL4030_AUDIO=y
# CONFIG_TWL6040_CORE is not set
CONFIG_MFD_WL1273_CORE=m
CONFIG_MFD_LM3533=y
# CONFIG_MFD_TQMX86 is not set
CONFIG_MFD_VX855=y
CONFIG_MFD_ARIZONA=y
CONFIG_MFD_ARIZONA_I2C=m
CONFIG_MFD_ARIZONA_SPI=m
# CONFIG_MFD_CS47L24 is not set
CONFIG_MFD_WM5102=y
CONFIG_MFD_WM5110=y
CONFIG_MFD_WM8997=y
# CONFIG_MFD_WM8998 is not set
# CONFIG_MFD_WM8400 is not set
CONFIG_MFD_WM831X=y
# CONFIG_MFD_WM831X_I2C is not set
CONFIG_MFD_WM831X_SPI=y
CONFIG_MFD_WM8350=y
CONFIG_MFD_WM8350_I2C=y
CONFIG_MFD_WM8994=m
# CONFIG_RAVE_SP_CORE is not set
# end of Multifunction device drivers

CONFIG_REGULATOR=y
# CONFIG_REGULATOR_DEBUG is not set
CONFIG_REGULATOR_FIXED_VOLTAGE=y
CONFIG_REGULATOR_VIRTUAL_CONSUMER=m
# CONFIG_REGULATOR_USERSPACE_CONSUMER is not set
CONFIG_REGULATOR_88PG86X=m
CONFIG_REGULATOR_88PM800=m
CONFIG_REGULATOR_ACT8865=y
# CONFIG_REGULATOR_AD5398 is not set
CONFIG_REGULATOR_ANATOP=y
CONFIG_REGULATOR_AB3100=m
CONFIG_REGULATOR_AS3711=y
# CONFIG_REGULATOR_AXP20X is not set
CONFIG_REGULATOR_BCM590XX=m
CONFIG_REGULATOR_BD9571MWV=m
CONFIG_REGULATOR_DA9052=y
CONFIG_REGULATOR_DA9062=m
CONFIG_REGULATOR_DA9210=y
CONFIG_REGULATOR_DA9211=m
CONFIG_REGULATOR_FAN53555=m
CONFIG_REGULATOR_GPIO=m
# CONFIG_REGULATOR_ISL9305 is not set
# CONFIG_REGULATOR_ISL6271A is not set
CONFIG_REGULATOR_LM363X=m
CONFIG_REGULATOR_LP3971=m
CONFIG_REGULATOR_LP3972=y
CONFIG_REGULATOR_LP872X=y
CONFIG_REGULATOR_LP8755=y
CONFIG_REGULATOR_LTC3589=m
CONFIG_REGULATOR_LTC3676=m
# CONFIG_REGULATOR_MAX1586 is not set
# CONFIG_REGULATOR_MAX8649 is not set
CONFIG_REGULATOR_MAX8660=m
CONFIG_REGULATOR_MAX8907=m
CONFIG_REGULATOR_MAX8952=y
# CONFIG_REGULATOR_MAX77693 is not set
# CONFIG_REGULATOR_MC13783 is not set
# CONFIG_REGULATOR_MC13892 is not set
# CONFIG_REGULATOR_MT6311 is not set
CONFIG_REGULATOR_MT6323=m
CONFIG_REGULATOR_MT6397=m
CONFIG_REGULATOR_PCAP=m
CONFIG_REGULATOR_PCF50633=y
CONFIG_REGULATOR_PFUZE100=y
CONFIG_REGULATOR_PV88060=y
CONFIG_REGULATOR_PV88080=y
# CONFIG_REGULATOR_PV88090 is not set
CONFIG_REGULATOR_QCOM_SPMI=m
CONFIG_REGULATOR_SKY81452=m
CONFIG_REGULATOR_SLG51000=m
CONFIG_REGULATOR_TPS51632=y
CONFIG_REGULATOR_TPS6105X=m
# CONFIG_REGULATOR_TPS62360 is not set
# CONFIG_REGULATOR_TPS65023 is not set
CONFIG_REGULATOR_TPS6507X=m
# CONFIG_REGULATOR_TPS65090 is not set
CONFIG_REGULATOR_TPS65132=y
CONFIG_REGULATOR_TPS6524X=y
CONFIG_REGULATOR_TPS65912=m
CONFIG_REGULATOR_TPS80031=y
CONFIG_REGULATOR_TWL4030=m
# CONFIG_REGULATOR_WM831X is not set
# CONFIG_REGULATOR_WM8350 is not set
# CONFIG_REGULATOR_WM8994 is not set
CONFIG_CEC_CORE=y
CONFIG_CEC_NOTIFIER=y
# CONFIG_RC_CORE is not set
CONFIG_MEDIA_SUPPORT=y

#
# Multimedia core support
#
# CONFIG_MEDIA_CAMERA_SUPPORT is not set
CONFIG_MEDIA_ANALOG_TV_SUPPORT=y
# CONFIG_MEDIA_DIGITAL_TV_SUPPORT is not set
CONFIG_MEDIA_RADIO_SUPPORT=y
CONFIG_MEDIA_SDR_SUPPORT=y
# CONFIG_MEDIA_CEC_SUPPORT is not set
CONFIG_MEDIA_CONTROLLER=y
CONFIG_VIDEO_DEV=y
CONFIG_VIDEO_V4L2_SUBDEV_API=y
CONFIG_VIDEO_V4L2=y
CONFIG_VIDEO_V4L2_I2C=y
# CONFIG_VIDEO_ADV_DEBUG is not set
CONFIG_VIDEO_FIXED_MINOR_RANGES=y
CONFIG_V4L2_FLASH_LED_CLASS=m
CONFIG_V4L2_FWNODE=y

#
# Media drivers
#
# CONFIG_MEDIA_PCI_SUPPORT is not set
# CONFIG_SDR_PLATFORM_DRIVERS is not set

#
# Supported MMC/SDIO adapters
#
CONFIG_RADIO_ADAPTERS=y
CONFIG_RADIO_SI470X=y
# CONFIG_I2C_SI470X is not set
CONFIG_RADIO_SI4713=y
# CONFIG_PLATFORM_SI4713 is not set
CONFIG_I2C_SI4713=y
# CONFIG_RADIO_MAXIRADIO is not set
CONFIG_RADIO_TEA5764=y
# CONFIG_RADIO_TEA5764_XTAL is not set
CONFIG_RADIO_SAA7706H=y
CONFIG_RADIO_TEF6862=y
# CONFIG_RADIO_WL1273 is not set

#
# Texas Instruments WL128x FM driver (ST based)
#
# end of Texas Instruments WL128x FM driver (ST based)

CONFIG_VIDEOBUF2_CORE=m
CONFIG_VIDEOBUF2_V4L2=m
CONFIG_VIDEOBUF2_MEMOPS=m
CONFIG_VIDEOBUF2_VMALLOC=m

#
# Media ancillary drivers (tuners, sensors, i2c, spi, frontends)
#
# CONFIG_MEDIA_SUBDRV_AUTOSELECT is not set
CONFIG_MEDIA_ATTACH=y

#
# I2C Encoders, decoders, sensors and other helper chips
#

#
# Audio decoders, processors and mixers
#
# CONFIG_VIDEO_TVAUDIO is not set
CONFIG_VIDEO_TDA7432=m
# CONFIG_VIDEO_TDA9840 is not set
# CONFIG_VIDEO_TEA6415C is not set
# CONFIG_VIDEO_TEA6420 is not set
# CONFIG_VIDEO_MSP3400 is not set
CONFIG_VIDEO_CS3308=y
CONFIG_VIDEO_CS5345=y
CONFIG_VIDEO_CS53L32A=y
CONFIG_VIDEO_TLV320AIC23B=m
# CONFIG_VIDEO_UDA1342 is not set
CONFIG_VIDEO_WM8775=y
CONFIG_VIDEO_WM8739=m
CONFIG_VIDEO_VP27SMPX=m
CONFIG_VIDEO_SONY_BTF_MPX=m

#
# RDS decoders
#
CONFIG_VIDEO_SAA6588=m

#
# Video decoders
#
# CONFIG_VIDEO_ADV7180 is not set
CONFIG_VIDEO_ADV7183=m
# CONFIG_VIDEO_ADV7604 is not set
CONFIG_VIDEO_ADV7842=m
CONFIG_VIDEO_ADV7842_CEC=y
CONFIG_VIDEO_BT819=m
# CONFIG_VIDEO_BT856 is not set
CONFIG_VIDEO_BT866=y
# CONFIG_VIDEO_KS0127 is not set
CONFIG_VIDEO_ML86V7667=m
CONFIG_VIDEO_SAA7110=y
CONFIG_VIDEO_SAA711X=m
CONFIG_VIDEO_TC358743=m
CONFIG_VIDEO_TC358743_CEC=y
CONFIG_VIDEO_TVP514X=y
# CONFIG_VIDEO_TVP5150 is not set
# CONFIG_VIDEO_TVP7002 is not set
CONFIG_VIDEO_TW2804=y
CONFIG_VIDEO_TW9903=y
CONFIG_VIDEO_TW9906=m
# CONFIG_VIDEO_TW9910 is not set
CONFIG_VIDEO_VPX3220=y

#
# Video and audio decoders
#
# CONFIG_VIDEO_SAA717X is not set
CONFIG_VIDEO_CX25840=y

#
# Video encoders
#
# CONFIG_VIDEO_SAA7127 is not set
CONFIG_VIDEO_SAA7185=y
# CONFIG_VIDEO_ADV7170 is not set
CONFIG_VIDEO_ADV7175=m
CONFIG_VIDEO_ADV7343=y
CONFIG_VIDEO_ADV7393=y
CONFIG_VIDEO_ADV7511=y
CONFIG_VIDEO_ADV7511_CEC=y
# CONFIG_VIDEO_AD9389B is not set
CONFIG_VIDEO_AK881X=m
CONFIG_VIDEO_THS8200=m

#
# Camera sensor devices
#

#
# Lens drivers
#

#
# Flash devices
#

#
# Video improvement chips
#
# CONFIG_VIDEO_UPD64031A is not set
# CONFIG_VIDEO_UPD64083 is not set

#
# Audio/Video compression chips
#
CONFIG_VIDEO_SAA6752HS=m

#
# SDR tuner chips
#
CONFIG_SDR_MAX2175=m

#
# Miscellaneous helper chips
#
CONFIG_VIDEO_THS7303=y
# CONFIG_VIDEO_M52790 is not set
CONFIG_VIDEO_I2C=m
# end of I2C Encoders, decoders, sensors and other helper chips

#
# SPI helper chips
#
CONFIG_VIDEO_GS1662=y
# end of SPI helper chips

#
# Media SPI Adapters
#
# end of Media SPI Adapters

CONFIG_MEDIA_TUNER=y

#
# Customize TV tuners
#
# CONFIG_MEDIA_TUNER_SIMPLE is not set
CONFIG_MEDIA_TUNER_TDA18250=y
CONFIG_MEDIA_TUNER_TDA8290=m
CONFIG_MEDIA_TUNER_TDA827X=y
CONFIG_MEDIA_TUNER_TDA18271=m
CONFIG_MEDIA_TUNER_TDA9887=m
CONFIG_MEDIA_TUNER_TEA5761=y
# CONFIG_MEDIA_TUNER_TEA5767 is not set
CONFIG_MEDIA_TUNER_MSI001=m
CONFIG_MEDIA_TUNER_MT20XX=y
# CONFIG_MEDIA_TUNER_MT2060 is not set
# CONFIG_MEDIA_TUNER_MT2063 is not set
# CONFIG_MEDIA_TUNER_MT2266 is not set
# CONFIG_MEDIA_TUNER_MT2131 is not set
# CONFIG_MEDIA_TUNER_QT1010 is not set
# CONFIG_MEDIA_TUNER_XC2028 is not set
CONFIG_MEDIA_TUNER_XC5000=y
CONFIG_MEDIA_TUNER_XC4000=m
CONFIG_MEDIA_TUNER_MXL5005S=m
CONFIG_MEDIA_TUNER_MXL5007T=m
CONFIG_MEDIA_TUNER_MC44S803=m
CONFIG_MEDIA_TUNER_MAX2165=m
CONFIG_MEDIA_TUNER_TDA18218=m
CONFIG_MEDIA_TUNER_FC0011=y
# CONFIG_MEDIA_TUNER_FC0012 is not set
CONFIG_MEDIA_TUNER_FC0013=y
# CONFIG_MEDIA_TUNER_TDA18212 is not set
CONFIG_MEDIA_TUNER_E4000=y
CONFIG_MEDIA_TUNER_FC2580=y
CONFIG_MEDIA_TUNER_M88RS6000T=y
CONFIG_MEDIA_TUNER_TUA9001=y
# CONFIG_MEDIA_TUNER_SI2157 is not set
# CONFIG_MEDIA_TUNER_IT913X is not set
CONFIG_MEDIA_TUNER_R820T=m
CONFIG_MEDIA_TUNER_MXL301RF=y
CONFIG_MEDIA_TUNER_QM1D1C0042=y
CONFIG_MEDIA_TUNER_QM1D1B0004=y
# end of Customize TV tuners

#
# Customise DVB Frontends
#

#
# Tools to develop new frontends
#
# end of Customise DVB Frontends

#
# Graphics support
#
# CONFIG_AGP is not set
CONFIG_INTEL_GTT=m
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=16
# CONFIG_VGA_SWITCHEROO is not set
CONFIG_DRM=m
CONFIG_DRM_MIPI_DBI=m
CONFIG_DRM_MIPI_DSI=y
CONFIG_DRM_DP_AUX_CHARDEV=y
CONFIG_DRM_DEBUG_SELFTEST=m
CONFIG_DRM_KMS_HELPER=m
CONFIG_DRM_KMS_FB_HELPER=y
CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS=y
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
# CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM is not set
CONFIG_DRM_LOAD_EDID_FIRMWARE=y
CONFIG_DRM_DP_CEC=y
CONFIG_DRM_TTM=m
CONFIG_DRM_TTM_DMA_PAGE_POOL=y
CONFIG_DRM_VRAM_HELPER=m
CONFIG_DRM_TTM_HELPER=m
CONFIG_DRM_GEM_CMA_HELPER=y
CONFIG_DRM_KMS_CMA_HELPER=y
CONFIG_DRM_GEM_SHMEM_HELPER=y
CONFIG_DRM_SCHED=m

#
# I2C encoder or helper chips
#
CONFIG_DRM_I2C_CH7006=m
# CONFIG_DRM_I2C_SIL164 is not set
# CONFIG_DRM_I2C_NXP_TDA998X is not set
CONFIG_DRM_I2C_NXP_TDA9950=m
# end of I2C encoder or helper chips

#
# ARM devices
#
# end of ARM devices

CONFIG_DRM_RADEON=m
# CONFIG_DRM_RADEON_USERPTR is not set
CONFIG_DRM_AMDGPU=m
# CONFIG_DRM_AMDGPU_SI is not set
# CONFIG_DRM_AMDGPU_CIK is not set
# CONFIG_DRM_AMDGPU_USERPTR is not set
# CONFIG_DRM_AMDGPU_GART_DEBUGFS is not set

#
# ACP (Audio CoProcessor) Configuration
#
CONFIG_DRM_AMD_ACP=y
# end of ACP (Audio CoProcessor) Configuration

#
# Display Engine Configuration
#
CONFIG_DRM_AMD_DC=y
CONFIG_DRM_AMD_DC_DCN1_0=y
CONFIG_DRM_AMD_DC_DCN2_0=y
# CONFIG_DRM_AMD_DC_DCN2_1 is not set
CONFIG_DRM_AMD_DC_DSC_SUPPORT=y
# CONFIG_DRM_AMD_DC_HDCP is not set
CONFIG_DEBUG_KERNEL_DC=y
# end of Display Engine Configuration

CONFIG_HSA_AMD=y
CONFIG_DRM_NOUVEAU=m
# CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT is not set
CONFIG_NOUVEAU_DEBUG=5
CONFIG_NOUVEAU_DEBUG_DEFAULT=3
CONFIG_NOUVEAU_DEBUG_MMU=y
CONFIG_DRM_NOUVEAU_BACKLIGHT=y
CONFIG_DRM_I915=m
# CONFIG_DRM_I915_ALPHA_SUPPORT is not set
CONFIG_DRM_I915_FORCE_PROBE=""
# CONFIG_DRM_I915_CAPTURE_ERROR is not set
CONFIG_DRM_I915_USERPTR=y
# CONFIG_DRM_I915_GVT is not set

#
# drm/i915 Debugging
#
# CONFIG_DRM_I915_WERROR is not set
CONFIG_DRM_I915_DEBUG=y
CONFIG_DRM_I915_DEBUG_MMIO=y
CONFIG_DRM_I915_SW_FENCE_DEBUG_OBJECTS=y
# CONFIG_DRM_I915_SW_FENCE_CHECK_DAG is not set
# CONFIG_DRM_I915_DEBUG_GUC is not set
CONFIG_DRM_I915_SELFTEST=y
CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y
CONFIG_DRM_I915_DEBUG_VBLANK_EVADE=y
CONFIG_DRM_I915_DEBUG_RUNTIME_PM=y
# end of drm/i915 Debugging

#
# drm/i915 Profile Guided Optimisation
#
CONFIG_DRM_I915_USERFAULT_AUTOSUSPEND=250
CONFIG_DRM_I915_HEARTBEAT_INTERVAL=2500
CONFIG_DRM_I915_PREEMPT_TIMEOUT=640
CONFIG_DRM_I915_SPIN_REQUEST=5
CONFIG_DRM_I915_STOP_TIMEOUT=100
CONFIG_DRM_I915_TIMESLICE_DURATION=1
# end of drm/i915 Profile Guided Optimisation

CONFIG_DRM_VGEM=m
# CONFIG_DRM_VKMS is not set
CONFIG_DRM_VMWGFX=m
# CONFIG_DRM_VMWGFX_FBCON is not set
# CONFIG_DRM_GMA500 is not set
# CONFIG_DRM_UDL is not set
CONFIG_DRM_AST=m
CONFIG_DRM_MGAG200=m
CONFIG_DRM_CIRRUS_QEMU=m
CONFIG_DRM_QXL=m
# CONFIG_DRM_BOCHS is not set
CONFIG_DRM_PANEL=y

#
# Display Panels
#
CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN=m
# end of Display Panels

CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y

#
# Display Interface Bridges
#
# CONFIG_DRM_ANALOGIX_ANX78XX is not set
# end of Display Interface Bridges

# CONFIG_DRM_ETNAVIV is not set
# CONFIG_TINYDRM_HX8357D is not set
# CONFIG_TINYDRM_ILI9225 is not set
# CONFIG_TINYDRM_ILI9341 is not set
CONFIG_TINYDRM_MI0283QT=m
# CONFIG_TINYDRM_REPAPER is not set
# CONFIG_TINYDRM_ST7586 is not set
CONFIG_TINYDRM_ST7735R=m
CONFIG_DRM_VBOXVIDEO=m
# CONFIG_DRM_LEGACY is not set
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=m
CONFIG_DRM_LIB_RANDOM=y

#
# Frame buffer Devices
#
CONFIG_FB_CMDLINE=y
CONFIG_FB_NOTIFY=y
CONFIG_FB=m
# CONFIG_FIRMWARE_EDID is not set
CONFIG_FB_DDC=m
CONFIG_FB_CFB_FILLRECT=m
CONFIG_FB_CFB_COPYAREA=m
CONFIG_FB_CFB_IMAGEBLIT=m
CONFIG_FB_SYS_FILLRECT=m
CONFIG_FB_SYS_COPYAREA=m
CONFIG_FB_SYS_IMAGEBLIT=m
# CONFIG_FB_FOREIGN_ENDIAN is not set
CONFIG_FB_SYS_FOPS=m
CONFIG_FB_DEFERRED_IO=y
CONFIG_FB_SVGALIB=m
CONFIG_FB_BACKLIGHT=m
CONFIG_FB_MODE_HELPERS=y
CONFIG_FB_TILEBLITTING=y

#
# Frame buffer hardware drivers
#
CONFIG_FB_CIRRUS=m
# CONFIG_FB_PM2 is not set
# CONFIG_FB_CYBER2000 is not set
CONFIG_FB_ARC=m
# CONFIG_FB_VGA16 is not set
# CONFIG_FB_N411 is not set
CONFIG_FB_HGA=m
CONFIG_FB_OPENCORES=m
# CONFIG_FB_S1D13XXX is not set
CONFIG_FB_NVIDIA=m
CONFIG_FB_NVIDIA_I2C=y
# CONFIG_FB_NVIDIA_DEBUG is not set
# CONFIG_FB_NVIDIA_BACKLIGHT is not set
# CONFIG_FB_RIVA is not set
CONFIG_FB_I740=m
CONFIG_FB_LE80578=m
CONFIG_FB_CARILLO_RANCH=m
CONFIG_FB_MATROX=m
CONFIG_FB_MATROX_MILLENIUM=y
CONFIG_FB_MATROX_MYSTIQUE=y
CONFIG_FB_MATROX_G=y
CONFIG_FB_MATROX_I2C=m
CONFIG_FB_MATROX_MAVEN=m
CONFIG_FB_RADEON=m
# CONFIG_FB_RADEON_I2C is not set
# CONFIG_FB_RADEON_BACKLIGHT is not set
# CONFIG_FB_RADEON_DEBUG is not set
CONFIG_FB_ATY128=m
CONFIG_FB_ATY128_BACKLIGHT=y
CONFIG_FB_ATY=m
# CONFIG_FB_ATY_CT is not set
# CONFIG_FB_ATY_GX is not set
# CONFIG_FB_ATY_BACKLIGHT is not set
CONFIG_FB_S3=m
CONFIG_FB_S3_DDC=y
CONFIG_FB_SAVAGE=m
# CONFIG_FB_SAVAGE_I2C is not set
# CONFIG_FB_SAVAGE_ACCEL is not set
# CONFIG_FB_SIS is not set
CONFIG_FB_VIA=m
CONFIG_FB_VIA_DIRECT_PROCFS=y
# CONFIG_FB_VIA_X_COMPATIBILITY is not set
CONFIG_FB_NEOMAGIC=m
# CONFIG_FB_KYRO is not set
CONFIG_FB_3DFX=m
# CONFIG_FB_3DFX_ACCEL is not set
# CONFIG_FB_3DFX_I2C is not set
# CONFIG_FB_VOODOO1 is not set
CONFIG_FB_VT8623=m
CONFIG_FB_TRIDENT=m
# CONFIG_FB_ARK is not set
# CONFIG_FB_PM3 is not set
CONFIG_FB_CARMINE=m
CONFIG_FB_CARMINE_DRAM_EVAL=y
# CONFIG_CARMINE_DRAM_CUSTOM is not set
CONFIG_FB_SM501=m
CONFIG_FB_IBM_GXT4500=m
CONFIG_FB_VIRTUAL=m
# CONFIG_FB_METRONOME is not set
# CONFIG_FB_MB862XX is not set
CONFIG_FB_SM712=m
# end of Frame buffer Devices

#
# Backlight & LCD device support
#
CONFIG_LCD_CLASS_DEVICE=y
# CONFIG_LCD_L4F00242T03 is not set
# CONFIG_LCD_LMS283GF05 is not set
CONFIG_LCD_LTV350QV=m
CONFIG_LCD_ILI922X=y
# CONFIG_LCD_ILI9320 is not set
CONFIG_LCD_TDO24M=m
# CONFIG_LCD_VGG2432A4 is not set
# CONFIG_LCD_PLATFORM is not set
# CONFIG_LCD_AMS369FG06 is not set
CONFIG_LCD_LMS501KF03=m
# CONFIG_LCD_HX8357 is not set
CONFIG_LCD_OTM3225A=y
CONFIG_BACKLIGHT_CLASS_DEVICE=m
CONFIG_BACKLIGHT_GENERIC=m
CONFIG_BACKLIGHT_LM3533=m
CONFIG_BACKLIGHT_CARILLO_RANCH=m
CONFIG_BACKLIGHT_DA9052=m
# CONFIG_BACKLIGHT_APPLE is not set
# CONFIG_BACKLIGHT_PM8941_WLED is not set
CONFIG_BACKLIGHT_SAHARA=m
# CONFIG_BACKLIGHT_WM831X is not set
# CONFIG_BACKLIGHT_ADP8860 is not set
CONFIG_BACKLIGHT_ADP8870=m
# CONFIG_BACKLIGHT_PCF50633 is not set
CONFIG_BACKLIGHT_LM3639=m
CONFIG_BACKLIGHT_PANDORA=m
# CONFIG_BACKLIGHT_SKY81452 is not set
CONFIG_BACKLIGHT_AS3711=m
# CONFIG_BACKLIGHT_GPIO is not set
# CONFIG_BACKLIGHT_LV5207LP is not set
CONFIG_BACKLIGHT_BD6107=m
CONFIG_BACKLIGHT_ARCXCNN=m
# end of Backlight & LCD device support

CONFIG_VGASTATE=m
CONFIG_HDMI=y
CONFIG_LOGO=y
# CONFIG_LOGO_LINUX_MONO is not set
CONFIG_LOGO_LINUX_VGA16=y
CONFIG_LOGO_LINUX_CLUT224=y
# end of Graphics support

# CONFIG_SOUND is not set

#
# HID support
#
CONFIG_HID=y
# CONFIG_HID_BATTERY_STRENGTH is not set
# CONFIG_HIDRAW is not set
# CONFIG_UHID is not set
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
# CONFIG_HID_A4TECH is not set
# CONFIG_HID_ACRUX is not set
# CONFIG_HID_APPLE is not set
# CONFIG_HID_ASUS is not set
# CONFIG_HID_AUREAL is not set
# CONFIG_HID_BELKIN is not set
# CONFIG_HID_CHERRY is not set
# CONFIG_HID_CHICONY is not set
# CONFIG_HID_COUGAR is not set
# CONFIG_HID_MACALLY is not set
# CONFIG_HID_CMEDIA is not set
# CONFIG_HID_CYPRESS is not set
# CONFIG_HID_DRAGONRISE is not set
# CONFIG_HID_EMS_FF is not set
# CONFIG_HID_ELECOM is not set
# CONFIG_HID_EZKEY is not set
# CONFIG_HID_GEMBIRD is not set
# CONFIG_HID_GFRM is not set
# CONFIG_HID_KEYTOUCH is not set
# CONFIG_HID_KYE is not set
# CONFIG_HID_WALTOP is not set
# CONFIG_HID_VIEWSONIC is not set
# CONFIG_HID_GYRATION is not set
# CONFIG_HID_ICADE is not set
# CONFIG_HID_ITE is not set
# CONFIG_HID_JABRA is not set
# CONFIG_HID_TWINHAN is not set
# CONFIG_HID_KENSINGTON is not set
# CONFIG_HID_LCPOWER is not set
# CONFIG_HID_LED is not set
# CONFIG_HID_LENOVO is not set
# CONFIG_HID_LOGITECH is not set
# CONFIG_HID_MAGICMOUSE is not set
# CONFIG_HID_MALTRON is not set
# CONFIG_HID_MAYFLASH is not set
# CONFIG_HID_REDRAGON is not set
# CONFIG_HID_MICROSOFT is not set
# CONFIG_HID_MONTEREY is not set
# CONFIG_HID_MULTITOUCH is not set
# CONFIG_HID_NTI is not set
# CONFIG_HID_ORTEK is not set
# CONFIG_HID_PANTHERLORD is not set
# CONFIG_HID_PETALYNX is not set
# CONFIG_HID_PICOLCD is not set
# CONFIG_HID_PLANTRONICS is not set
# CONFIG_HID_PRIMAX is not set
# CONFIG_HID_SAITEK is not set
# CONFIG_HID_SAMSUNG is not set
# CONFIG_HID_SPEEDLINK is not set
# CONFIG_HID_STEAM is not set
# CONFIG_HID_STEELSERIES is not set
# CONFIG_HID_SUNPLUS is not set
# CONFIG_HID_RMI is not set
# CONFIG_HID_GREENASIA is not set
# CONFIG_HID_SMARTJOYPLUS is not set
# CONFIG_HID_TIVO is not set
# CONFIG_HID_TOPSEED is not set
# CONFIG_HID_THINGM is not set
# CONFIG_HID_THRUSTMASTER is not set
# CONFIG_HID_UDRAW_PS3 is not set
# CONFIG_HID_WIIMOTE is not set
# CONFIG_HID_XINMO is not set
# CONFIG_HID_ZEROPLUS is not set
# CONFIG_HID_ZYDACRON is not set
# CONFIG_HID_SENSOR_HUB is not set
# CONFIG_HID_ALPS is not set
# end of Special HID drivers

#
# I2C HID support
#
# CONFIG_I2C_HID is not set
# end of I2C HID support

#
# Intel ISH HID support
#
# CONFIG_INTEL_ISH_HID is not set
# end of Intel ISH HID support
# end of HID support

CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
# CONFIG_USB_LED_TRIG is not set
# CONFIG_USB_ULPI_BUS is not set
# CONFIG_USB_CONN_GPIO is not set
CONFIG_USB_ARCH_HAS_HCD=y
# CONFIG_USB is not set
CONFIG_USB_PCI=y

#
# USB port drivers
#

#
# USB Physical Layer drivers
#
# CONFIG_NOP_USB_XCEIV is not set
# CONFIG_USB_GPIO_VBUS is not set
# CONFIG_TAHVO_USB is not set
# end of USB Physical Layer drivers

# CONFIG_USB_GADGET is not set
# CONFIG_TYPEC is not set
# CONFIG_USB_ROLE_SWITCH is not set
CONFIG_MMC=m
CONFIG_MMC_BLOCK=m
CONFIG_MMC_BLOCK_MINORS=8
# CONFIG_SDIO_UART is not set
CONFIG_MMC_TEST=m

#
# MMC/SD/SDIO Host Controller Drivers
#
CONFIG_MMC_DEBUG=y
CONFIG_MMC_SDHCI=m
# CONFIG_MMC_SDHCI_PCI is not set
# CONFIG_MMC_SDHCI_ACPI is not set
# CONFIG_MMC_SDHCI_PLTFM is not set
# CONFIG_MMC_WBSD is not set
CONFIG_MMC_ALCOR=m
CONFIG_MMC_TIFM_SD=m
CONFIG_MMC_SPI=m
CONFIG_MMC_SDRICOH_CS=m
CONFIG_MMC_CB710=m
# CONFIG_MMC_VIA_SDMMC is not set
# CONFIG_MMC_USDHI6ROL0 is not set
# CONFIG_MMC_REALTEK_PCI is not set
# CONFIG_MMC_CQHCI is not set
CONFIG_MMC_TOSHIBA_PCI=m
CONFIG_MMC_MTK=m
CONFIG_MEMSTICK=y
# CONFIG_MEMSTICK_DEBUG is not set

#
# MemoryStick drivers
#
CONFIG_MEMSTICK_UNSAFE_RESUME=y
# CONFIG_MSPRO_BLOCK is not set
CONFIG_MS_BLOCK=y

#
# MemoryStick Host Controller Drivers
#
CONFIG_MEMSTICK_TIFM_MS=y
CONFIG_MEMSTICK_JMICRON_38X=m
# CONFIG_MEMSTICK_R592 is not set
CONFIG_MEMSTICK_REALTEK_PCI=m
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=m
CONFIG_LEDS_CLASS_FLASH=m
# CONFIG_LEDS_BRIGHTNESS_HW_CHANGED is not set

#
# LED drivers
#
# CONFIG_LEDS_APU is not set
CONFIG_LEDS_AS3645A=m
CONFIG_LEDS_LM3530=m
CONFIG_LEDS_LM3532=m
CONFIG_LEDS_LM3533=m
CONFIG_LEDS_LM3642=m
CONFIG_LEDS_LM3601X=m
CONFIG_LEDS_MT6323=m
# CONFIG_LEDS_PCA9532 is not set
CONFIG_LEDS_GPIO=m
CONFIG_LEDS_LP3944=m
CONFIG_LEDS_LP3952=m
CONFIG_LEDS_LP55XX_COMMON=m
CONFIG_LEDS_LP5521=m
# CONFIG_LEDS_LP5523 is not set
# CONFIG_LEDS_LP5562 is not set
CONFIG_LEDS_LP8501=m
# CONFIG_LEDS_CLEVO_MAIL is not set
CONFIG_LEDS_PCA955X=m
# CONFIG_LEDS_PCA955X_GPIO is not set
CONFIG_LEDS_PCA963X=m
CONFIG_LEDS_WM831X_STATUS=m
# CONFIG_LEDS_WM8350 is not set
CONFIG_LEDS_DA9052=m
# CONFIG_LEDS_DAC124S085 is not set
CONFIG_LEDS_REGULATOR=m
# CONFIG_LEDS_BD2802 is not set
CONFIG_LEDS_INTEL_SS4200=m
CONFIG_LEDS_MC13783=m
CONFIG_LEDS_TCA6507=m
# CONFIG_LEDS_TLC591XX is not set
CONFIG_LEDS_LM355x=m
# CONFIG_LEDS_MENF21BMC is not set

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
# CONFIG_LEDS_BLINKM is not set
CONFIG_LEDS_MLXCPLD=m
CONFIG_LEDS_MLXREG=m
CONFIG_LEDS_USER=m
# CONFIG_LEDS_NIC78BX is not set
CONFIG_LEDS_TI_LMU_COMMON=m
# CONFIG_LEDS_LM36274 is not set

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
# CONFIG_LEDS_TRIGGER_TIMER is not set
CONFIG_LEDS_TRIGGER_ONESHOT=y
CONFIG_LEDS_TRIGGER_DISK=y
CONFIG_LEDS_TRIGGER_MTD=y
# CONFIG_LEDS_TRIGGER_HEARTBEAT is not set
CONFIG_LEDS_TRIGGER_BACKLIGHT=y
# CONFIG_LEDS_TRIGGER_CPU is not set
# CONFIG_LEDS_TRIGGER_ACTIVITY is not set
CONFIG_LEDS_TRIGGER_GPIO=y
CONFIG_LEDS_TRIGGER_DEFAULT_ON=m

#
# iptables trigger is under Netfilter config (LED target)
#
CONFIG_LEDS_TRIGGER_TRANSIENT=m
CONFIG_LEDS_TRIGGER_CAMERA=m
CONFIG_LEDS_TRIGGER_PANIC=y
# CONFIG_LEDS_TRIGGER_NETDEV is not set
CONFIG_LEDS_TRIGGER_PATTERN=y
CONFIG_LEDS_TRIGGER_AUDIO=y
# CONFIG_ACCESSIBILITY is not set
# CONFIG_INFINIBAND is not set
CONFIG_EDAC_ATOMIC_SCRUB=y
CONFIG_EDAC_SUPPORT=y
# CONFIG_EDAC is not set
CONFIG_RTC_LIB=y
CONFIG_RTC_MC146818_LIB=y
# CONFIG_RTC_CLASS is not set
CONFIG_DMADEVICES=y
# CONFIG_DMADEVICES_DEBUG is not set

#
# DMA Devices
#
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
# CONFIG_ALTERA_MSGDMA is not set
CONFIG_INTEL_IDMA64=y
CONFIG_INTEL_IOATDMA=y
# CONFIG_INTEL_MIC_X100_DMA is not set
# CONFIG_QCOM_HIDMA_MGMT is not set
CONFIG_QCOM_HIDMA=m
CONFIG_DW_DMAC_CORE=y
CONFIG_DW_DMAC=m
# CONFIG_DW_DMAC_PCI is not set
CONFIG_DW_EDMA=y
# CONFIG_DW_EDMA_PCIE is not set
CONFIG_HSU_DMA=y

#
# DMA Clients
#
CONFIG_ASYNC_TX_DMA=y
CONFIG_DMATEST=m
CONFIG_DMA_ENGINE_RAID=y

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
CONFIG_SW_SYNC=y
CONFIG_UDMABUF=y
CONFIG_DMABUF_SELFTESTS=m
# end of DMABUF options

CONFIG_DCA=y
CONFIG_AUXDISPLAY=y
# CONFIG_HD44780 is not set
CONFIG_IMG_ASCII_LCD=m
CONFIG_PARPORT_PANEL=m
CONFIG_PANEL_PARPORT=0
CONFIG_PANEL_PROFILE=5
CONFIG_PANEL_CHANGE_MESSAGE=y
CONFIG_PANEL_BOOT_MESSAGE=""
# CONFIG_CHARLCD_BL_OFF is not set
# CONFIG_CHARLCD_BL_ON is not set
CONFIG_CHARLCD_BL_FLASH=y
CONFIG_PANEL=m
CONFIG_CHARLCD=m
CONFIG_UIO=m
# CONFIG_UIO_CIF is not set
CONFIG_UIO_PDRV_GENIRQ=m
CONFIG_UIO_DMEM_GENIRQ=m
CONFIG_UIO_AEC=m
CONFIG_UIO_SERCOS3=m
# CONFIG_UIO_PCI_GENERIC is not set
CONFIG_UIO_NETX=m
CONFIG_UIO_PRUSS=m
CONFIG_UIO_MF624=m
# CONFIG_VIRT_DRIVERS is not set
# CONFIG_VIRTIO_MENU is not set

#
# Microsoft Hyper-V guest support
#
# CONFIG_HYPERV is not set
# end of Microsoft Hyper-V guest support

# CONFIG_GREYBUS is not set
# CONFIG_STAGING is not set
CONFIG_X86_PLATFORM_DEVICES=y
# CONFIG_ACER_WMI is not set
# CONFIG_ACER_WIRELESS is not set
# CONFIG_ACERHDF is not set
# CONFIG_ALIENWARE_WMI is not set
# CONFIG_ASUS_LAPTOP is not set
# CONFIG_DCDBAS is not set
# CONFIG_DELL_SMBIOS is not set
# CONFIG_DELL_WMI_AIO is not set
# CONFIG_DELL_WMI_LED is not set
# CONFIG_DELL_SMO8800 is not set
# CONFIG_DELL_RBU is not set
# CONFIG_FUJITSU_LAPTOP is not set
# CONFIG_FUJITSU_TABLET is not set
# CONFIG_GPD_POCKET_FAN is not set
# CONFIG_HP_ACCEL is not set
# CONFIG_HP_WIRELESS is not set
# CONFIG_HP_WMI is not set
# CONFIG_LG_LAPTOP is not set
# CONFIG_PANASONIC_LAPTOP is not set
# CONFIG_SURFACE3_WMI is not set
# CONFIG_THINKPAD_ACPI is not set
# CONFIG_SENSORS_HDAPS is not set
# CONFIG_INTEL_MENLOW is not set
# CONFIG_ASUS_WIRELESS is not set
CONFIG_ACPI_WMI=m
CONFIG_WMI_BMOF=m
# CONFIG_INTEL_WMI_THUNDERBOLT is not set
# CONFIG_XIAOMI_WMI is not set
# CONFIG_MSI_WMI is not set
# CONFIG_PEAQ_WMI is not set
# CONFIG_TOPSTAR_LAPTOP is not set
# CONFIG_ACPI_TOSHIBA is not set
# CONFIG_TOSHIBA_BT_RFKILL is not set
# CONFIG_TOSHIBA_HAPS is not set
# CONFIG_TOSHIBA_WMI is not set
# CONFIG_ACPI_CMPC is not set
# CONFIG_INTEL_INT0002_VGPIO is not set
# CONFIG_INTEL_HID_EVENT is not set
# CONFIG_INTEL_VBTN is not set
# CONFIG_INTEL_IPS is not set
# CONFIG_INTEL_PMC_CORE is not set
# CONFIG_IBM_RTL is not set
# CONFIG_SAMSUNG_LAPTOP is not set
CONFIG_MXM_WMI=m
# CONFIG_SAMSUNG_Q10 is not set
# CONFIG_APPLE_GMUX is not set
# CONFIG_INTEL_RST is not set
# CONFIG_INTEL_SMARTCONNECT is not set
# CONFIG_INTEL_PMC_IPC is not set
# CONFIG_SURFACE_PRO3_BUTTON is not set
# CONFIG_INTEL_PUNIT_IPC is not set
# CONFIG_MLX_PLATFORM is not set
# CONFIG_I2C_MULTI_INSTANTIATE is not set
# CONFIG_INTEL_ATOMISP2_PM is not set
# CONFIG_HUAWEI_WMI is not set
# CONFIG_PCENGINES_APU2 is not set

#
# Intel Speed Select Technology interface support
#
# CONFIG_INTEL_SPEED_SELECT_INTERFACE is not set
# end of Intel Speed Select Technology interface support

CONFIG_PMC_ATOM=y
CONFIG_MFD_CROS_EC=m
CONFIG_CHROME_PLATFORMS=y
CONFIG_CHROMEOS_LAPTOP=y
CONFIG_CHROMEOS_PSTORE=m
# CONFIG_CHROMEOS_TBMC is not set
CONFIG_CROS_EC=y
CONFIG_CROS_EC_I2C=m
CONFIG_CROS_EC_SPI=y
# CONFIG_CROS_EC_LPC is not set
CONFIG_CROS_EC_PROTO=y
# CONFIG_CROS_KBD_LED_BACKLIGHT is not set
# CONFIG_CROS_EC_CHARDEV is not set
CONFIG_CROS_EC_LIGHTBAR=m
# CONFIG_CROS_EC_DEBUGFS is not set
# CONFIG_CROS_EC_SYSFS is not set
CONFIG_CROS_USBPD_LOGGER=m
CONFIG_MELLANOX_PLATFORM=y
# CONFIG_MLXREG_HOTPLUG is not set
CONFIG_MLXREG_IO=y
CONFIG_CLKDEV_LOOKUP=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y

#
# Common Clock Framework
#
# CONFIG_COMMON_CLK_WM831X is not set
CONFIG_COMMON_CLK_MAX9485=y
CONFIG_COMMON_CLK_SI5341=y
# CONFIG_COMMON_CLK_SI5351 is not set
CONFIG_COMMON_CLK_SI544=y
CONFIG_COMMON_CLK_CDCE706=y
CONFIG_COMMON_CLK_CS2000_CP=y
# end of Common Clock Framework

# CONFIG_HWSPINLOCK is not set

#
# Clock Source drivers
#
CONFIG_CLKEVT_I8253=y
CONFIG_I8253_LOCK=y
CONFIG_CLKBLD_I8253=y
# end of Clock Source drivers

CONFIG_MAILBOX=y
# CONFIG_PCC is not set
CONFIG_ALTERA_MBOX=y
CONFIG_IOMMU_IOVA=m
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
# end of Generic IOMMU Pagetable Support

# CONFIG_IOMMU_DEBUGFS is not set
# CONFIG_AMD_IOMMU is not set
# CONFIG_INTEL_IOMMU is not set
# CONFIG_IRQ_REMAP is not set

#
# Remoteproc drivers
#
# CONFIG_REMOTEPROC is not set
# end of Remoteproc drivers

#
# Rpmsg drivers
#
# CONFIG_RPMSG_QCOM_GLINK_RPM is not set
# CONFIG_RPMSG_VIRTIO is not set
# end of Rpmsg drivers

# CONFIG_SOUNDWIRE is not set

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#
# end of Amlogic SoC drivers

#
# Aspeed SoC drivers
#
# end of Aspeed SoC drivers

#
# Broadcom SoC drivers
#
# end of Broadcom SoC drivers

#
# NXP/Freescale QorIQ SoC drivers
#
# end of NXP/Freescale QorIQ SoC drivers

#
# i.MX SoC drivers
#
# end of i.MX SoC drivers

#
# Qualcomm SoC drivers
#
# end of Qualcomm SoC drivers

CONFIG_SOC_TI=y

#
# Xilinx SoC drivers
#
# CONFIG_XILINX_VCU is not set
# end of Xilinx SoC drivers
# end of SOC (System On Chip) specific Drivers

CONFIG_PM_DEVFREQ=y

#
# DEVFREQ Governors
#
CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=y
# CONFIG_DEVFREQ_GOV_PERFORMANCE is not set
CONFIG_DEVFREQ_GOV_POWERSAVE=y
# CONFIG_DEVFREQ_GOV_USERSPACE is not set
CONFIG_DEVFREQ_GOV_PASSIVE=y

#
# DEVFREQ Drivers
#
CONFIG_PM_DEVFREQ_EVENT=y
CONFIG_EXTCON=y

#
# Extcon Device Drivers
#
# CONFIG_EXTCON_ADC_JACK is not set
# CONFIG_EXTCON_AXP288 is not set
# CONFIG_EXTCON_FSA9480 is not set
CONFIG_EXTCON_GPIO=m
# CONFIG_EXTCON_INTEL_INT3496 is not set
# CONFIG_EXTCON_MAX3355 is not set
# CONFIG_EXTCON_MAX77693 is not set
# CONFIG_EXTCON_MAX77843 is not set
# CONFIG_EXTCON_PTN5150 is not set
# CONFIG_EXTCON_RT8973A is not set
CONFIG_EXTCON_SM5502=y
CONFIG_EXTCON_USB_GPIO=m
CONFIG_EXTCON_USBC_CROS_EC=m
CONFIG_MEMORY=y
CONFIG_IIO=m
CONFIG_IIO_BUFFER=y
CONFIG_IIO_BUFFER_CB=m
CONFIG_IIO_BUFFER_HW_CONSUMER=m
CONFIG_IIO_KFIFO_BUF=m
CONFIG_IIO_TRIGGERED_BUFFER=m
CONFIG_IIO_CONFIGFS=m
CONFIG_IIO_TRIGGER=y
CONFIG_IIO_CONSUMERS_PER_TRIGGER=2
CONFIG_IIO_SW_DEVICE=m
# CONFIG_IIO_SW_TRIGGER is not set

#
# Accelerometers
#
CONFIG_ADIS16201=m
CONFIG_ADIS16209=m
CONFIG_ADXL345=m
CONFIG_ADXL345_I2C=m
CONFIG_ADXL345_SPI=m
CONFIG_ADXL372=m
CONFIG_ADXL372_SPI=m
CONFIG_ADXL372_I2C=m
CONFIG_BMA180=m
CONFIG_BMA220=m
# CONFIG_BMC150_ACCEL is not set
CONFIG_DA280=m
CONFIG_DA311=m
# CONFIG_DMARD09 is not set
# CONFIG_DMARD10 is not set
CONFIG_IIO_CROS_EC_ACCEL_LEGACY=m
CONFIG_IIO_ST_ACCEL_3AXIS=m
CONFIG_IIO_ST_ACCEL_I2C_3AXIS=m
CONFIG_IIO_ST_ACCEL_SPI_3AXIS=m
CONFIG_KXSD9=m
CONFIG_KXSD9_SPI=m
# CONFIG_KXSD9_I2C is not set
CONFIG_KXCJK1013=m
CONFIG_MC3230=m
CONFIG_MMA7455=m
CONFIG_MMA7455_I2C=m
CONFIG_MMA7455_SPI=m
# CONFIG_MMA7660 is not set
CONFIG_MMA8452=m
CONFIG_MMA9551_CORE=m
CONFIG_MMA9551=m
CONFIG_MMA9553=m
CONFIG_MXC4005=m
# CONFIG_MXC6255 is not set
# CONFIG_SCA3000 is not set
# CONFIG_STK8312 is not set
CONFIG_STK8BA50=m
# end of Accelerometers

#
# Analog to digital converters
#
CONFIG_AD_SIGMA_DELTA=m
CONFIG_AD7124=m
# CONFIG_AD7266 is not set
# CONFIG_AD7291 is not set
CONFIG_AD7292=m
CONFIG_AD7298=m
CONFIG_AD7476=m
# CONFIG_AD7606_IFACE_PARALLEL is not set
# CONFIG_AD7606_IFACE_SPI is not set
CONFIG_AD7766=m
CONFIG_AD7768_1=m
CONFIG_AD7780=m
CONFIG_AD7791=m
CONFIG_AD7793=m
CONFIG_AD7887=m
CONFIG_AD7923=m
# CONFIG_AD7949 is not set
CONFIG_AD799X=m
# CONFIG_AXP20X_ADC is not set
CONFIG_AXP288_ADC=m
# CONFIG_CC10001_ADC is not set
CONFIG_DA9150_GPADC=m
# CONFIG_HI8435 is not set
# CONFIG_HX711 is not set
CONFIG_INA2XX_ADC=m
CONFIG_LTC2471=m
CONFIG_LTC2485=m
CONFIG_LTC2497=m
# CONFIG_MAX1027 is not set
# CONFIG_MAX11100 is not set
# CONFIG_MAX1118 is not set
# CONFIG_MAX1363 is not set
CONFIG_MAX9611=m
CONFIG_MCP320X=m
CONFIG_MCP3422=m
# CONFIG_MCP3911 is not set
CONFIG_NAU7802=m
CONFIG_QCOM_VADC_COMMON=m
CONFIG_QCOM_SPMI_IADC=m
CONFIG_QCOM_SPMI_VADC=m
CONFIG_QCOM_SPMI_ADC5=m
# CONFIG_STX104 is not set
CONFIG_TI_ADC081C=m
CONFIG_TI_ADC0832=m
CONFIG_TI_ADC084S021=m
# CONFIG_TI_ADC12138 is not set
CONFIG_TI_ADC108S102=m
CONFIG_TI_ADC128S052=m
CONFIG_TI_ADC161S626=m
CONFIG_TI_ADS1015=m
CONFIG_TI_ADS7950=m
CONFIG_TI_TLC4541=m
# CONFIG_TWL4030_MADC is not set
CONFIG_TWL6030_GPADC=m
CONFIG_XILINX_XADC=m
# end of Analog to digital converters

#
# Analog Front Ends
#
# end of Analog Front Ends

#
# Amplifiers
#
CONFIG_AD8366=m
# end of Amplifiers

#
# Chemical Sensors
#
CONFIG_ATLAS_PH_SENSOR=m
# CONFIG_BME680 is not set
CONFIG_CCS811=m
# CONFIG_IAQCORE is not set
# CONFIG_PMS7003 is not set
# CONFIG_SENSIRION_SGP30 is not set
# CONFIG_SPS30 is not set
CONFIG_VZ89X=m
# end of Chemical Sensors

CONFIG_IIO_CROS_EC_SENSORS_CORE=m
CONFIG_IIO_CROS_EC_SENSORS=m
# CONFIG_IIO_CROS_EC_SENSORS_LID_ANGLE is not set

#
# Hid Sensor IIO Common
#
# end of Hid Sensor IIO Common

CONFIG_IIO_MS_SENSORS_I2C=m

#
# SSP Sensor Common
#
CONFIG_IIO_SSP_SENSORS_COMMONS=m
CONFIG_IIO_SSP_SENSORHUB=m
# end of SSP Sensor Common

CONFIG_IIO_ST_SENSORS_I2C=m
CONFIG_IIO_ST_SENSORS_SPI=m
CONFIG_IIO_ST_SENSORS_CORE=m

#
# Digital to analog converters
#
CONFIG_AD5064=m
CONFIG_AD5360=m
CONFIG_AD5380=m
# CONFIG_AD5421 is not set
# CONFIG_AD5446 is not set
CONFIG_AD5449=m
# CONFIG_AD5592R is not set
# CONFIG_AD5593R is not set
CONFIG_AD5504=m
CONFIG_AD5624R_SPI=m
CONFIG_LTC1660=m
CONFIG_LTC2632=m
CONFIG_AD5686=m
CONFIG_AD5686_SPI=m
CONFIG_AD5696_I2C=m
CONFIG_AD5755=m
CONFIG_AD5758=m
# CONFIG_AD5761 is not set
# CONFIG_AD5764 is not set
# CONFIG_AD5791 is not set
CONFIG_AD7303=m
CONFIG_CIO_DAC=m
CONFIG_AD8801=m
CONFIG_DS4424=m
# CONFIG_M62332 is not set
CONFIG_MAX517=m
CONFIG_MCP4725=m
# CONFIG_MCP4922 is not set
CONFIG_TI_DAC082S085=m
CONFIG_TI_DAC5571=m
CONFIG_TI_DAC7311=m
# CONFIG_TI_DAC7612 is not set
# end of Digital to analog converters

#
# IIO dummy driver
#
# CONFIG_IIO_SIMPLE_DUMMY is not set
# end of IIO dummy driver

#
# Frequency Synthesizers DDS/PLL
#

#
# Clock Generator/Distribution
#
CONFIG_AD9523=m
# end of Clock Generator/Distribution

#
# Phase-Locked Loop (PLL) frequency synthesizers
#
# CONFIG_ADF4350 is not set
CONFIG_ADF4371=m
# end of Phase-Locked Loop (PLL) frequency synthesizers
# end of Frequency Synthesizers DDS/PLL

#
# Digital gyroscope sensors
#
CONFIG_ADIS16080=m
CONFIG_ADIS16130=m
# CONFIG_ADIS16136 is not set
CONFIG_ADIS16260=m
# CONFIG_ADXRS450 is not set
# CONFIG_BMG160 is not set
# CONFIG_FXAS21002C is not set
CONFIG_MPU3050=m
CONFIG_MPU3050_I2C=m
CONFIG_IIO_ST_GYRO_3AXIS=m
CONFIG_IIO_ST_GYRO_I2C_3AXIS=m
CONFIG_IIO_ST_GYRO_SPI_3AXIS=m
CONFIG_ITG3200=m
# end of Digital gyroscope sensors

#
# Health Sensors
#

#
# Heart Rate Monitors
#
CONFIG_AFE4403=m
CONFIG_AFE4404=m
CONFIG_MAX30100=m
# CONFIG_MAX30102 is not set
# end of Heart Rate Monitors
# end of Health Sensors

#
# Humidity sensors
#
CONFIG_AM2315=m
CONFIG_DHT11=m
# CONFIG_HDC100X is not set
CONFIG_HTS221=m
CONFIG_HTS221_I2C=m
CONFIG_HTS221_SPI=m
CONFIG_HTU21=m
# CONFIG_SI7005 is not set
CONFIG_SI7020=m
# end of Humidity sensors

#
# Inertial measurement units
#
CONFIG_ADIS16400=m
CONFIG_ADIS16460=m
# CONFIG_ADIS16480 is not set
CONFIG_BMI160=m
CONFIG_BMI160_I2C=m
# CONFIG_BMI160_SPI is not set
CONFIG_FXOS8700=m
CONFIG_FXOS8700_I2C=m
CONFIG_FXOS8700_SPI=m
CONFIG_KMX61=m
CONFIG_INV_MPU6050_IIO=m
CONFIG_INV_MPU6050_I2C=m
# CONFIG_INV_MPU6050_SPI is not set
CONFIG_IIO_ST_LSM6DSX=m
CONFIG_IIO_ST_LSM6DSX_I2C=m
CONFIG_IIO_ST_LSM6DSX_SPI=m
CONFIG_IIO_ST_LSM6DSX_I3C=m
# end of Inertial measurement units

CONFIG_IIO_ADIS_LIB=m
CONFIG_IIO_ADIS_LIB_BUFFER=y

#
# Light sensors
#
# CONFIG_ACPI_ALS is not set
CONFIG_ADJD_S311=m
CONFIG_ADUX1020=m
# CONFIG_AL3320A is not set
CONFIG_APDS9300=m
CONFIG_APDS9960=m
CONFIG_BH1750=m
CONFIG_BH1780=m
CONFIG_CM32181=m
# CONFIG_CM3232 is not set
CONFIG_CM3323=m
CONFIG_CM36651=m
# CONFIG_IIO_CROS_EC_LIGHT_PROX is not set
CONFIG_GP2AP020A00F=m
# CONFIG_SENSORS_ISL29018 is not set
CONFIG_SENSORS_ISL29028=m
# CONFIG_ISL29125 is not set
CONFIG_JSA1212=m
# CONFIG_RPR0521 is not set
CONFIG_SENSORS_LM3533=m
CONFIG_LTR501=m
CONFIG_LV0104CS=m
CONFIG_MAX44000=m
# CONFIG_MAX44009 is not set
CONFIG_NOA1305=m
CONFIG_OPT3001=m
CONFIG_PA12203001=m
CONFIG_SI1133=m
# CONFIG_SI1145 is not set
CONFIG_STK3310=m
# CONFIG_ST_UVIS25 is not set
CONFIG_TCS3414=m
CONFIG_TCS3472=m
# CONFIG_SENSORS_TSL2563 is not set
CONFIG_TSL2583=m
CONFIG_TSL2772=m
# CONFIG_TSL4531 is not set
# CONFIG_US5182D is not set
CONFIG_VCNL4000=m
CONFIG_VCNL4035=m
CONFIG_VEML6030=m
CONFIG_VEML6070=m
CONFIG_VL6180=m
# CONFIG_ZOPT2201 is not set
# end of Light sensors

#
# Magnetometer sensors
#
CONFIG_AK8975=m
# CONFIG_AK09911 is not set
CONFIG_BMC150_MAGN=m
# CONFIG_BMC150_MAGN_I2C is not set
CONFIG_BMC150_MAGN_SPI=m
CONFIG_MAG3110=m
CONFIG_MMC35240=m
# CONFIG_IIO_ST_MAGN_3AXIS is not set
CONFIG_SENSORS_HMC5843=m
CONFIG_SENSORS_HMC5843_I2C=m
CONFIG_SENSORS_HMC5843_SPI=m
CONFIG_SENSORS_RM3100=m
CONFIG_SENSORS_RM3100_I2C=m
# CONFIG_SENSORS_RM3100_SPI is not set
# end of Magnetometer sensors

#
# Multiplexers
#
# end of Multiplexers

#
# Inclinometer sensors
#
# end of Inclinometer sensors

#
# Triggers - standalone
#
CONFIG_IIO_INTERRUPT_TRIGGER=m
CONFIG_IIO_SYSFS_TRIGGER=m
# end of Triggers - standalone

#
# Digital potentiometers
#
CONFIG_AD5272=m
# CONFIG_DS1803 is not set
CONFIG_MAX5432=m
CONFIG_MAX5481=m
# CONFIG_MAX5487 is not set
CONFIG_MCP4018=m
CONFIG_MCP4131=m
CONFIG_MCP4531=m
CONFIG_MCP41010=m
CONFIG_TPL0102=m
# end of Digital potentiometers

#
# Digital potentiostats
#
CONFIG_LMP91000=m
# end of Digital potentiostats

#
# Pressure sensors
#
# CONFIG_ABP060MG is not set
# CONFIG_BMP280 is not set
CONFIG_IIO_CROS_EC_BARO=m
CONFIG_DPS310=m
CONFIG_HP03=m
CONFIG_MPL115=m
CONFIG_MPL115_I2C=m
# CONFIG_MPL115_SPI is not set
CONFIG_MPL3115=m
CONFIG_MS5611=m
# CONFIG_MS5611_I2C is not set
CONFIG_MS5611_SPI=m
CONFIG_MS5637=m
CONFIG_IIO_ST_PRESS=m
CONFIG_IIO_ST_PRESS_I2C=m
CONFIG_IIO_ST_PRESS_SPI=m
CONFIG_T5403=m
CONFIG_HP206C=m
# CONFIG_ZPA2326 is not set
# end of Pressure sensors

#
# Lightning sensors
#
CONFIG_AS3935=m
# end of Lightning sensors

#
# Proximity and distance sensors
#
CONFIG_ISL29501=m
# CONFIG_LIDAR_LITE_V2 is not set
CONFIG_MB1232=m
CONFIG_RFD77402=m
# CONFIG_SRF04 is not set
CONFIG_SX9500=m
CONFIG_SRF08=m
# CONFIG_VL53L0X_I2C is not set
# end of Proximity and distance sensors

#
# Resolver to digital converters
#
# CONFIG_AD2S90 is not set
CONFIG_AD2S1200=m
# end of Resolver to digital converters

#
# Temperature sensors
#
CONFIG_LTC2983=m
CONFIG_MAXIM_THERMOCOUPLE=m
CONFIG_MLX90614=m
CONFIG_MLX90632=m
CONFIG_TMP006=m
CONFIG_TMP007=m
CONFIG_TSYS01=m
CONFIG_TSYS02D=m
CONFIG_MAX31856=m
# end of Temperature sensors

CONFIG_NTB=m
# CONFIG_NTB_MSI is not set
# CONFIG_NTB_AMD is not set
CONFIG_NTB_IDT=m
CONFIG_NTB_INTEL=m
# CONFIG_NTB_SWITCHTEC is not set
CONFIG_NTB_PINGPONG=m
CONFIG_NTB_TOOL=m
CONFIG_NTB_PERF=m
CONFIG_NTB_TRANSPORT=m
CONFIG_VME_BUS=y

#
# VME Bridge Drivers
#
CONFIG_VME_CA91CX42=y
CONFIG_VME_TSI148=y
CONFIG_VME_FAKE=m

#
# VME Board Drivers
#
# CONFIG_VMIVME_7805 is not set

#
# VME Device Drivers
#
# CONFIG_PWM is not set

#
# IRQ chip support
#
CONFIG_MADERA_IRQ=m
# end of IRQ chip support

CONFIG_IPACK_BUS=m
CONFIG_BOARD_TPCI200=m
# CONFIG_SERIAL_IPOCTAL is not set
CONFIG_RESET_CONTROLLER=y
CONFIG_RESET_TI_SYSCON=y

#
# PHY Subsystem
#
CONFIG_GENERIC_PHY=y
# CONFIG_BCM_KONA_USB2_PHY is not set
# CONFIG_PHY_PXA_28NM_HSIC is not set
# CONFIG_PHY_PXA_28NM_USB2 is not set
# CONFIG_PHY_CPCAP_USB is not set
# end of PHY Subsystem

CONFIG_POWERCAP=y
CONFIG_INTEL_RAPL_CORE=y
CONFIG_INTEL_RAPL=y
# CONFIG_IDLE_INJECT is not set
# CONFIG_MCB is not set

#
# Performance monitor support
#
# end of Performance monitor support

CONFIG_RAS=y
CONFIG_RAS_CEC=y
# CONFIG_RAS_CEC_DEBUG is not set
# CONFIG_THUNDERBOLT is not set

#
# Android
#
# CONFIG_ANDROID is not set
# end of Android

# CONFIG_LIBNVDIMM is not set
CONFIG_DAX=y
CONFIG_NVMEM=y
CONFIG_NVMEM_SYSFS=y

#
# HW tracing support
#
# CONFIG_STM is not set
# CONFIG_INTEL_TH is not set
# end of HW tracing support

CONFIG_FPGA=y
# CONFIG_ALTERA_PR_IP_CORE is not set
CONFIG_FPGA_MGR_ALTERA_PS_SPI=m
CONFIG_FPGA_MGR_ALTERA_CVP=y
CONFIG_FPGA_MGR_XILINX_SPI=m
CONFIG_FPGA_MGR_MACHXO2_SPI=y
CONFIG_FPGA_BRIDGE=y
# CONFIG_ALTERA_FREEZE_BRIDGE is not set
CONFIG_XILINX_PR_DECOUPLER=y
CONFIG_FPGA_REGION=m
CONFIG_FPGA_DFL=m
# CONFIG_FPGA_DFL_FME is not set
# CONFIG_FPGA_DFL_AFU is not set
# CONFIG_FPGA_DFL_PCI is not set
CONFIG_PM_OPP=y
# CONFIG_UNISYS_VISORBUS is not set
# CONFIG_SIOX is not set
CONFIG_SLIMBUS=m
# CONFIG_SLIM_QCOM_CTRL is not set
# CONFIG_INTERCONNECT is not set
CONFIG_COUNTER=y
CONFIG_104_QUAD_8=m
# end of Device Drivers

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
# CONFIG_VALIDATE_FS_PARSER is not set
CONFIG_FS_IOMAP=y
CONFIG_EXT2_FS=m
CONFIG_EXT2_FS_XATTR=y
CONFIG_EXT2_FS_POSIX_ACL=y
CONFIG_EXT2_FS_SECURITY=y
CONFIG_EXT3_FS=y
# CONFIG_EXT3_FS_POSIX_ACL is not set
CONFIG_EXT3_FS_SECURITY=y
CONFIG_EXT4_FS=y
# CONFIG_EXT4_FS_POSIX_ACL is not set
CONFIG_EXT4_FS_SECURITY=y
# CONFIG_EXT4_DEBUG is not set
CONFIG_JBD2=y
CONFIG_JBD2_DEBUG=y
CONFIG_FS_MBCACHE=y
CONFIG_REISERFS_FS=y
CONFIG_REISERFS_CHECK=y
# CONFIG_REISERFS_PROC_INFO is not set
CONFIG_REISERFS_FS_XATTR=y
CONFIG_REISERFS_FS_POSIX_ACL=y
CONFIG_REISERFS_FS_SECURITY=y
CONFIG_JFS_FS=m
CONFIG_JFS_POSIX_ACL=y
# CONFIG_JFS_SECURITY is not set
# CONFIG_JFS_DEBUG is not set
# CONFIG_JFS_STATISTICS is not set
CONFIG_XFS_FS=m
CONFIG_XFS_QUOTA=y
# CONFIG_XFS_POSIX_ACL is not set
CONFIG_XFS_RT=y
# CONFIG_XFS_ONLINE_SCRUB is not set
CONFIG_XFS_DEBUG=y
# CONFIG_XFS_ASSERT_FATAL is not set
CONFIG_GFS2_FS=y
# CONFIG_OCFS2_FS is not set
# CONFIG_BTRFS_FS is not set
# CONFIG_NILFS2_FS is not set
CONFIG_F2FS_FS=y
# CONFIG_F2FS_STAT_FS is not set
CONFIG_F2FS_FS_XATTR=y
CONFIG_F2FS_FS_POSIX_ACL=y
CONFIG_F2FS_FS_SECURITY=y
# CONFIG_F2FS_CHECK_FS is not set
CONFIG_F2FS_IO_TRACE=y
CONFIG_F2FS_FAULT_INJECTION=y
CONFIG_FS_DAX=y
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
CONFIG_EXPORTFS_BLOCK_OPS=y
CONFIG_FILE_LOCKING=y
CONFIG_MANDATORY_FILE_LOCKING=y
# CONFIG_FS_ENCRYPTION is not set
# CONFIG_FS_VERITY is not set
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_QUOTA=y
# CONFIG_QUOTA_NETLINK_INTERFACE is not set
CONFIG_PRINT_QUOTA_WARNING=y
# CONFIG_QUOTA_DEBUG is not set
CONFIG_QUOTA_TREE=m
# CONFIG_QFMT_V1 is not set
CONFIG_QFMT_V2=m
CONFIG_QUOTACTL=y
CONFIG_QUOTACTL_COMPAT=y
CONFIG_AUTOFS4_FS=m
CONFIG_AUTOFS_FS=m
# CONFIG_FUSE_FS is not set
CONFIG_OVERLAY_FS=m
CONFIG_OVERLAY_FS_REDIRECT_DIR=y
CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y
# CONFIG_OVERLAY_FS_INDEX is not set
CONFIG_OVERLAY_FS_XINO_AUTO=y
# CONFIG_OVERLAY_FS_METACOPY is not set

#
# Caches
#
CONFIG_FSCACHE=m
# CONFIG_FSCACHE_STATS is not set
# CONFIG_FSCACHE_HISTOGRAM is not set
CONFIG_FSCACHE_DEBUG=y
# CONFIG_FSCACHE_OBJECT_LIST is not set
# CONFIG_CACHEFILES is not set
# end of Caches

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=m
CONFIG_JOLIET=y
# CONFIG_ZISOFS is not set
CONFIG_UDF_FS=m
# end of CD-ROM/DVD Filesystems

#
# DOS/FAT/NT Filesystems
#
CONFIG_FAT_FS=y
CONFIG_MSDOS_FS=m
CONFIG_VFAT_FS=y
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="iso8859-1"
CONFIG_FAT_DEFAULT_UTF8=y
CONFIG_NTFS_FS=m
# CONFIG_NTFS_DEBUG is not set
# CONFIG_NTFS_RW is not set
# end of DOS/FAT/NT Filesystems

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
# CONFIG_PROC_KCORE is not set
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
CONFIG_PROC_CHILDREN=y
CONFIG_PROC_PID_ARCH_STATUS=y
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
# CONFIG_HUGETLBFS is not set
CONFIG_MEMFD_CREATE=y
CONFIG_ARCH_HAS_GIGANTIC_PAGE=y
CONFIG_CONFIGFS_FS=m
# end of Pseudo filesystems

# CONFIG_MISC_FILESYSTEMS is not set
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=y
CONFIG_NFS_V2=y
CONFIG_NFS_V3=y
# CONFIG_NFS_V3_ACL is not set
CONFIG_NFS_V4=m
# CONFIG_NFS_SWAP is not set
# CONFIG_NFS_V4_1 is not set
# CONFIG_ROOT_NFS is not set
# CONFIG_NFS_USE_LEGACY_DNS is not set
CONFIG_NFS_USE_KERNEL_DNS=y
# CONFIG_NFSD is not set
CONFIG_GRACE_PERIOD=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NFS_COMMON=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=m
# CONFIG_SUNRPC_DEBUG is not set
# CONFIG_CEPH_FS is not set
CONFIG_CIFS=m
# CONFIG_CIFS_STATS2 is not set
CONFIG_CIFS_ALLOW_INSECURE_LEGACY=y
# CONFIG_CIFS_WEAK_PW_HASH is not set
# CONFIG_CIFS_UPCALL is not set
# CONFIG_CIFS_XATTR is not set
CONFIG_CIFS_DEBUG=y
# CONFIG_CIFS_DEBUG2 is not set
# CONFIG_CIFS_DEBUG_DUMP_KEYS is not set
# CONFIG_CIFS_DFS_UPCALL is not set
# CONFIG_CIFS_FSCACHE is not set
# CONFIG_CODA_FS is not set
# CONFIG_AFS_FS is not set
# CONFIG_9P_FS is not set
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="iso8859-1"
# CONFIG_NLS_CODEPAGE_437 is not set
CONFIG_NLS_CODEPAGE_737=y
CONFIG_NLS_CODEPAGE_775=y
CONFIG_NLS_CODEPAGE_850=m
CONFIG_NLS_CODEPAGE_852=m
# CONFIG_NLS_CODEPAGE_855 is not set
# CONFIG_NLS_CODEPAGE_857 is not set
CONFIG_NLS_CODEPAGE_860=m
# CONFIG_NLS_CODEPAGE_861 is not set
CONFIG_NLS_CODEPAGE_862=y
CONFIG_NLS_CODEPAGE_863=y
CONFIG_NLS_CODEPAGE_864=m
CONFIG_NLS_CODEPAGE_865=m
CONFIG_NLS_CODEPAGE_866=m
CONFIG_NLS_CODEPAGE_869=y
CONFIG_NLS_CODEPAGE_936=y
CONFIG_NLS_CODEPAGE_950=m
CONFIG_NLS_CODEPAGE_932=y
CONFIG_NLS_CODEPAGE_949=m
CONFIG_NLS_CODEPAGE_874=m
CONFIG_NLS_ISO8859_8=y
CONFIG_NLS_CODEPAGE_1250=y
# CONFIG_NLS_CODEPAGE_1251 is not set
CONFIG_NLS_ASCII=y
# CONFIG_NLS_ISO8859_1 is not set
CONFIG_NLS_ISO8859_2=m
CONFIG_NLS_ISO8859_3=y
CONFIG_NLS_ISO8859_4=m
# CONFIG_NLS_ISO8859_5 is not set
CONFIG_NLS_ISO8859_6=y
CONFIG_NLS_ISO8859_7=m
CONFIG_NLS_ISO8859_9=m
# CONFIG_NLS_ISO8859_13 is not set
CONFIG_NLS_ISO8859_14=m
# CONFIG_NLS_ISO8859_15 is not set
# CONFIG_NLS_KOI8_R is not set
CONFIG_NLS_KOI8_U=m
# CONFIG_NLS_MAC_ROMAN is not set
CONFIG_NLS_MAC_CELTIC=y
CONFIG_NLS_MAC_CENTEURO=y
CONFIG_NLS_MAC_CROATIAN=y
CONFIG_NLS_MAC_CYRILLIC=m
# CONFIG_NLS_MAC_GAELIC is not set
CONFIG_NLS_MAC_GREEK=y
CONFIG_NLS_MAC_ICELAND=m
# CONFIG_NLS_MAC_INUIT is not set
CONFIG_NLS_MAC_ROMANIAN=y
# CONFIG_NLS_MAC_TURKISH is not set
CONFIG_NLS_UTF8=y
# CONFIG_DLM is not set
CONFIG_UNICODE=y
# CONFIG_UNICODE_NORMALIZATION_SELFTEST is not set
CONFIG_IO_WQ=y
# end of File systems

#
# Security options
#
CONFIG_KEYS=y
CONFIG_KEYS_COMPAT=y
# CONFIG_KEYS_REQUEST_CACHE is not set
CONFIG_PERSISTENT_KEYRINGS=y
# CONFIG_BIG_KEYS is not set
# CONFIG_TRUSTED_KEYS is not set
CONFIG_ENCRYPTED_KEYS=m
CONFIG_KEY_DH_OPERATIONS=y
# CONFIG_SECURITY_DMESG_RESTRICT is not set
# CONFIG_SECURITY is not set
CONFIG_SECURITYFS=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_FALLBACK=y
CONFIG_HARDENED_USERCOPY_PAGESPAN=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH="/sbin/usermode-helper"
CONFIG_DEFAULT_SECURITY_DAC=y
CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,bpf"

#
# Kernel hardening options
#

#
# Memory initialization
#
CONFIG_CC_HAS_AUTO_VAR_INIT=y
# CONFIG_INIT_STACK_NONE is not set
CONFIG_INIT_STACK_ALL=y
# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
# end of Memory initialization
# end of Kernel hardening options
# end of Security options

CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_SKCIPHER=y
CONFIG_CRYPTO_SKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_KPP=y
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
# CONFIG_CRYPTO_USER is not set
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_GF128MUL=m
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_NULL2=y
CONFIG_CRYPTO_CRYPTD=y
CONFIG_CRYPTO_AUTHENC=m
CONFIG_CRYPTO_TEST=m
CONFIG_CRYPTO_SIMD=y
CONFIG_CRYPTO_GLUE_HELPER_X86=y

#
# Public-key cryptography
#
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_DH=y
CONFIG_CRYPTO_ECC=y
CONFIG_CRYPTO_ECDH=y
# CONFIG_CRYPTO_ECRDSA is not set
CONFIG_CRYPTO_CURVE25519=y
CONFIG_CRYPTO_CURVE25519_X86=m

#
# Authenticated Encryption with Associated Data
#
CONFIG_CRYPTO_CCM=m
CONFIG_CRYPTO_GCM=m
# CONFIG_CRYPTO_CHACHA20POLY1305 is not set
CONFIG_CRYPTO_AEGIS128=y
# CONFIG_CRYPTO_AEGIS128_AESNI_SSE2 is not set
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=y

#
# Block modes
#
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CFB=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_CTS=m
CONFIG_CRYPTO_ECB=m
CONFIG_CRYPTO_LRW=m
CONFIG_CRYPTO_OFB=m
CONFIG_CRYPTO_PCBC=m
CONFIG_CRYPTO_XTS=m
CONFIG_CRYPTO_KEYWRAP=y
CONFIG_CRYPTO_NHPOLY1305=m
CONFIG_CRYPTO_NHPOLY1305_SSE2=m
# CONFIG_CRYPTO_NHPOLY1305_AVX2 is not set
# CONFIG_CRYPTO_ADIANTUM is not set
CONFIG_CRYPTO_ESSIV=m

#
# Hash modes
#
CONFIG_CRYPTO_CMAC=m
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_XCBC=y
# CONFIG_CRYPTO_VMAC is not set

#
# Digest
#
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_CRC32C_INTEL=y
CONFIG_CRYPTO_CRC32=y
# CONFIG_CRYPTO_CRC32_PCLMUL is not set
CONFIG_CRYPTO_XXHASH=m
CONFIG_CRYPTO_BLAKE2B=y
CONFIG_CRYPTO_BLAKE2S=m
CONFIG_CRYPTO_BLAKE2S_X86=m
CONFIG_CRYPTO_CRCT10DIF=y
CONFIG_CRYPTO_CRCT10DIF_PCLMUL=y
CONFIG_CRYPTO_GHASH=m
CONFIG_CRYPTO_POLY1305=y
CONFIG_CRYPTO_POLY1305_X86_64=m
CONFIG_CRYPTO_MD4=m
CONFIG_CRYPTO_MD5=m
# CONFIG_CRYPTO_MICHAEL_MIC is not set
CONFIG_CRYPTO_RMD128=m
CONFIG_CRYPTO_RMD160=y
# CONFIG_CRYPTO_RMD256 is not set
# CONFIG_CRYPTO_RMD320 is not set
# CONFIG_CRYPTO_SHA1 is not set
# CONFIG_CRYPTO_SHA1_SSSE3 is not set
CONFIG_CRYPTO_SHA256_SSSE3=m
# CONFIG_CRYPTO_SHA512_SSSE3 is not set
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=m
CONFIG_CRYPTO_SM3=m
# CONFIG_CRYPTO_STREEBOG is not set
# CONFIG_CRYPTO_TGR192 is not set
CONFIG_CRYPTO_WP512=y
# CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL is not set

#
# Ciphers
#
CONFIG_CRYPTO_AES=y
# CONFIG_CRYPTO_AES_TI is not set
CONFIG_CRYPTO_AES_NI_INTEL=y
CONFIG_CRYPTO_ANUBIS=m
CONFIG_CRYPTO_ARC4=y
CONFIG_CRYPTO_BLOWFISH=y
CONFIG_CRYPTO_BLOWFISH_COMMON=y
CONFIG_CRYPTO_BLOWFISH_X86_64=m
CONFIG_CRYPTO_CAMELLIA=y
CONFIG_CRYPTO_CAMELLIA_X86_64=y
# CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64 is not set
# CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64 is not set
CONFIG_CRYPTO_CAST_COMMON=y
# CONFIG_CRYPTO_CAST5 is not set
# CONFIG_CRYPTO_CAST5_AVX_X86_64 is not set
CONFIG_CRYPTO_CAST6=y
CONFIG_CRYPTO_CAST6_AVX_X86_64=m
CONFIG_CRYPTO_DES=m
# CONFIG_CRYPTO_DES3_EDE_X86_64 is not set
# CONFIG_CRYPTO_FCRYPT is not set
CONFIG_CRYPTO_KHAZAD=m
# CONFIG_CRYPTO_SALSA20 is not set
CONFIG_CRYPTO_CHACHA20=m
CONFIG_CRYPTO_CHACHA20_X86_64=y
CONFIG_CRYPTO_SEED=m
CONFIG_CRYPTO_SERPENT=m
CONFIG_CRYPTO_SERPENT_SSE2_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX2_X86_64=m
CONFIG_CRYPTO_SM4=y
CONFIG_CRYPTO_TEA=m
CONFIG_CRYPTO_TWOFISH=m
CONFIG_CRYPTO_TWOFISH_COMMON=y
CONFIG_CRYPTO_TWOFISH_X86_64=y
CONFIG_CRYPTO_TWOFISH_X86_64_3WAY=y
CONFIG_CRYPTO_TWOFISH_AVX_X86_64=y

#
# Compression
#
CONFIG_CRYPTO_DEFLATE=y
# CONFIG_CRYPTO_LZO is not set
# CONFIG_CRYPTO_842 is not set
# CONFIG_CRYPTO_LZ4 is not set
CONFIG_CRYPTO_LZ4HC=m
CONFIG_CRYPTO_ZSTD=y

#
# Random Number Generation
#
CONFIG_CRYPTO_ANSI_CPRNG=y
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
# CONFIG_CRYPTO_DRBG_HASH is not set
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
# CONFIG_CRYPTO_USER_API_HASH is not set
# CONFIG_CRYPTO_USER_API_SKCIPHER is not set
# CONFIG_CRYPTO_USER_API_RNG is not set
# CONFIG_CRYPTO_USER_API_AEAD is not set
CONFIG_CRYPTO_HASH_INFO=y

#
# Crypto library routines
#
CONFIG_CRYPTO_LIB_AES=y
CONFIG_CRYPTO_LIB_ARC4=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_BLAKE2S=m
CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=m
CONFIG_CRYPTO_LIB_BLAKE2S=m
CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=y
CONFIG_CRYPTO_LIB_CHACHA_GENERIC=y
CONFIG_CRYPTO_LIB_CHACHA=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CURVE25519=m
CONFIG_CRYPTO_LIB_CURVE25519_GENERIC=y
CONFIG_CRYPTO_LIB_CURVE25519=m
CONFIG_CRYPTO_LIB_DES=m
CONFIG_CRYPTO_LIB_POLY1305_RSIZE=4
CONFIG_CRYPTO_ARCH_HAVE_LIB_POLY1305=m
CONFIG_CRYPTO_LIB_POLY1305_GENERIC=y
CONFIG_CRYPTO_LIB_POLY1305=m
CONFIG_CRYPTO_LIB_CHACHA20POLY1305=m
CONFIG_CRYPTO_LIB_SHA256=y
# CONFIG_CRYPTO_HW is not set
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS8_PRIVATE_KEY_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y

#
# Certificates for signature checking
#
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
# CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
CONFIG_SECONDARY_TRUSTED_KEYRING=y
# CONFIG_SYSTEM_BLACKLIST_KEYRING is not set
# end of Certificates for signature checking

CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_PACKING=y
CONFIG_BITREVERSE=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_GENERIC_FIND_FIRST_BIT=y
CONFIG_CORDIC=y
CONFIG_PRIME_NUMBERS=m
CONFIG_RATIONAL=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_GENERIC_IOMAP=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
# CONFIG_CRC_CCITT is not set
CONFIG_CRC16=y
CONFIG_CRC_T10DIF=y
CONFIG_CRC_ITU_T=y
CONFIG_CRC32=y
# CONFIG_CRC32_SELFTEST is not set
# CONFIG_CRC32_SLICEBY8 is not set
# CONFIG_CRC32_SLICEBY4 is not set
CONFIG_CRC32_SARWATE=y
# CONFIG_CRC32_BIT is not set
CONFIG_CRC64=y
# CONFIG_CRC4 is not set
CONFIG_CRC7=m
CONFIG_LIBCRC32C=y
CONFIG_CRC8=m
CONFIG_XXHASH=y
CONFIG_RANDOM32_SELFTEST=y
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4HC_COMPRESS=m
CONFIG_LZ4_DECOMPRESS=y
CONFIG_ZSTD_COMPRESS=y
CONFIG_ZSTD_DECOMPRESS=y
CONFIG_XZ_DEC=m
# CONFIG_XZ_DEC_X86 is not set
# CONFIG_XZ_DEC_POWERPC is not set
# CONFIG_XZ_DEC_IA64 is not set
# CONFIG_XZ_DEC_ARM is not set
# CONFIG_XZ_DEC_ARMTHUMB is not set
CONFIG_XZ_DEC_SPARC=y
CONFIG_XZ_DEC_BCJ=y
CONFIG_XZ_DEC_TEST=m
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_REED_SOLOMON=m
CONFIG_REED_SOLOMON_DEC16=y
CONFIG_BCH=m
CONFIG_INTERVAL_TREE=y
CONFIG_XARRAY_MULTI=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_ARCH_HAS_FORCE_DMA_UNENCRYPTED=y
CONFIG_SWIOTLB=y
# CONFIG_DMA_CMA is not set
# CONFIG_DMA_API_DEBUG is not set
CONFIG_SGL_ALLOC=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_DQL=y
CONFIG_GLOB=y
CONFIG_GLOB_SELFTEST=y
CONFIG_NLATTR=y
CONFIG_CLZ_TAB=y
CONFIG_IRQ_POLL=y
CONFIG_MPILIB=y
CONFIG_OID_REGISTRY=y
CONFIG_HAVE_GENERIC_VDSO=y
CONFIG_GENERIC_GETTIMEOFDAY=y
CONFIG_FONT_SUPPORT=y
CONFIG_FONT_8x16=y
CONFIG_FONT_AUTOSELECT=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_HAS_UACCESS_MCSAFE=y
CONFIG_ARCH_STACKWALK=y
CONFIG_STACKDEPOT=y
CONFIG_SBITMAP=y
CONFIG_STRING_SELFTEST=y
# end of Library routines

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
# CONFIG_PRINTK_CALLER is not set
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=4
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
# CONFIG_BOOT_PRINTK_DELAY is not set
# CONFIG_DYNAMIC_DEBUG is not set
CONFIG_SYMBOLIC_ERRNAME=y
# end of printk and dmesg options

#
# Compile-time checks and compiler options
#
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_REDUCED=y
# CONFIG_DEBUG_INFO_SPLIT is not set
# CONFIG_DEBUG_INFO_DWARF4 is not set
# CONFIG_DEBUG_INFO_BTF is not set
# CONFIG_GDB_SCRIPTS is not set
CONFIG_ENABLE_MUST_CHECK=y
CONFIG_FRAME_WARN=8192
# CONFIG_STRIP_ASM_SYMS is not set
CONFIG_READABLE_ASM=y
CONFIG_DEBUG_FS=y
# CONFIG_HEADERS_INSTALL is not set
CONFIG_OPTIMIZE_INLINING=y
CONFIG_DEBUG_SECTION_MISMATCH=y
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
CONFIG_STACK_VALIDATION=y
# CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
# end of Compile-time checks and compiler options

CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x1
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_MISC=y

#
# Memory Debugging
#
CONFIG_PAGE_EXTENSION=y
# CONFIG_DEBUG_PAGEALLOC is not set
# CONFIG_PAGE_OWNER is not set
CONFIG_PAGE_POISONING=y
# CONFIG_PAGE_POISONING_NO_SANITY is not set
CONFIG_PAGE_POISONING_ZERO=y
# CONFIG_DEBUG_PAGE_REF is not set
# CONFIG_DEBUG_RODATA_TEST is not set
CONFIG_DEBUG_OBJECTS=y
CONFIG_DEBUG_OBJECTS_SELFTEST=y
CONFIG_DEBUG_OBJECTS_FREE=y
# CONFIG_DEBUG_OBJECTS_TIMERS is not set
CONFIG_DEBUG_OBJECTS_WORK=y
# CONFIG_DEBUG_OBJECTS_RCU_HEAD is not set
# CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER is not set
CONFIG_DEBUG_OBJECTS_ENABLE_DEFAULT=1
# CONFIG_SLUB_DEBUG_ON is not set
CONFIG_SLUB_STATS=y
CONFIG_HAVE_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK_MEM_POOL_SIZE=16000
# CONFIG_DEBUG_KMEMLEAK_TEST is not set
# CONFIG_DEBUG_KMEMLEAK_DEFAULT_OFF is not set
CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y
CONFIG_DEBUG_STACK_USAGE=y
CONFIG_DEBUG_VM=y
# CONFIG_DEBUG_VM_VMACACHE is not set
# CONFIG_DEBUG_VM_RB is not set
# CONFIG_DEBUG_VM_PGFLAGS is not set
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
# CONFIG_DEBUG_VIRTUAL is not set
CONFIG_DEBUG_MEMORY_INIT=y
# CONFIG_MEMORY_NOTIFIER_ERROR_INJECT is not set
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_CC_HAS_KASAN_SW_TAGS=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
# CONFIG_KASAN_STACK_ENABLE is not set
CONFIG_KASAN_STACK=0
CONFIG_KASAN_VMALLOC=y
CONFIG_TEST_KASAN=m
# end of Memory Debugging

CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
# CONFIG_KCOV is not set
# CONFIG_DEBUG_SHIRQ is not set

#
# Debug Lockups and Hangs
#
# CONFIG_SOFTLOCKUP_DETECTOR is not set
CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=y
# CONFIG_HARDLOCKUP_DETECTOR is not set
# CONFIG_DETECT_HUNG_TASK is not set
# CONFIG_WQ_WATCHDOG is not set
# end of Debug Lockups and Hangs

# CONFIG_PANIC_ON_OOPS is not set
CONFIG_PANIC_ON_OOPS_VALUE=0
CONFIG_PANIC_TIMEOUT=0
CONFIG_SCHED_DEBUG=y
# CONFIG_SCHEDSTATS is not set
# CONFIG_SCHED_STACK_END_CHECK is not set
# CONFIG_DEBUG_TIMEKEEPING is not set

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
CONFIG_DEBUG_RT_MUTEXES=y
# CONFIG_DEBUG_SPINLOCK is not set
CONFIG_DEBUG_MUTEXES=y
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
CONFIG_DEBUG_RWSEMS=y
# CONFIG_DEBUG_LOCK_ALLOC is not set
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_DEBUG_LOCKING_API_SELFTESTS=y
CONFIG_LOCK_TORTURE_TEST=y
# CONFIG_WW_MUTEX_SELFTEST is not set
# end of Lock Debugging (spinlocks, mutexes, etc...)

CONFIG_STACKTRACE=y
# CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
# CONFIG_DEBUG_KOBJECT is not set
CONFIG_DEBUG_BUGVERBOSE=y
# CONFIG_DEBUG_LIST is not set
# CONFIG_DEBUG_PLIST is not set
CONFIG_DEBUG_SG=y
# CONFIG_DEBUG_NOTIFIERS is not set
CONFIG_DEBUG_CREDENTIALS=y

#
# RCU Debugging
#
CONFIG_TORTURE_TEST=y
# CONFIG_RCU_PERF_TEST is not set
# CONFIG_RCU_TORTURE_TEST is not set
# CONFIG_RCU_TRACE is not set
CONFIG_RCU_EQS_DEBUG=y
# end of RCU Debugging

# CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
# CONFIG_DEBUG_BLOCK_EXT_DEVT is not set
CONFIG_NOTIFIER_ERROR_INJECTION=y
CONFIG_PM_NOTIFIER_ERROR_INJECT=y
# CONFIG_NETDEV_NOTIFIER_ERROR_INJECT is not set
CONFIG_FAULT_INJECTION=y
# CONFIG_FAILSLAB is not set
CONFIG_FAIL_PAGE_ALLOC=y
CONFIG_FAIL_MAKE_REQUEST=y
# CONFIG_FAIL_IO_TIMEOUT is not set
# CONFIG_FAIL_FUTEX is not set
CONFIG_FAULT_INJECTION_DEBUG_FS=y
# CONFIG_FAIL_MMC_REQUEST is not set
# CONFIG_LATENCYTOP is not set
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_FENTRY=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_RING_BUFFER_ALLOW_SWAP=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
# CONFIG_FUNCTION_GRAPH_TRACER is not set
# CONFIG_PREEMPTIRQ_EVENTS is not set
# CONFIG_IRQSOFF_TRACER is not set
CONFIG_SCHED_TRACER=y
CONFIG_HWLAT_TRACER=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP=y
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
# CONFIG_STACK_TRACER is not set
# CONFIG_BLK_DEV_IO_TRACE is not set
# CONFIG_UPROBE_EVENTS is not set
CONFIG_DYNAMIC_EVENTS=y
# CONFIG_DYNAMIC_FTRACE is not set
CONFIG_FUNCTION_PROFILER=y
# CONFIG_FTRACE_STARTUP_TEST is not set
CONFIG_MMIOTRACE=y
CONFIG_TRACING_MAP=y
CONFIG_HIST_TRIGGERS=y
CONFIG_MMIOTRACE_TEST=m
CONFIG_TRACEPOINT_BENCHMARK=y
CONFIG_RING_BUFFER_BENCHMARK=y
# CONFIG_RING_BUFFER_STARTUP_TEST is not set
CONFIG_PREEMPTIRQ_DELAY_TEST=m
# CONFIG_TRACE_EVAL_MAP_FILE is not set
# CONFIG_GCOV_PROFILE_FTRACE is not set
# CONFIG_PROVIDE_OHCI1394_DMA_INIT is not set
# CONFIG_KUNIT is not set
# CONFIG_RUNTIME_TESTING_MENU is not set
CONFIG_MEMTEST=y
# CONFIG_BUG_ON_DATA_CORRUPTION is not set
# CONFIG_SAMPLES is not set
CONFIG_HAVE_ARCH_KGDB=y
# CONFIG_KGDB is not set
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
# CONFIG_UBSAN is not set
CONFIG_UBSAN_ALIGNMENT=y
CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_X86_VERBOSE_BOOTUP=y
# CONFIG_EARLY_PRINTK is not set
# CONFIG_X86_PTDUMP is not set
# CONFIG_DEBUG_WX is not set
CONFIG_DOUBLEFAULT=y
CONFIG_DEBUG_TLBFLUSH=y
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
# CONFIG_DEBUG_BOOT_PARAMS is not set
# CONFIG_CPA_DEBUG is not set
CONFIG_DEBUG_ENTRY=y
CONFIG_DEBUG_NMI_SELFTEST=y
CONFIG_X86_DEBUG_FPU=y
CONFIG_PUNIT_ATOM_DEBUG=y
CONFIG_UNWINDER_ORC=y
# CONFIG_UNWINDER_FRAME_POINTER is not set
# end of Kernel hacking

--vQ3nNXu39BMSLhj/--

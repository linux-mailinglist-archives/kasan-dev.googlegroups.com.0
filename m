Return-Path: <kasan-dev+bncBDV37XP3XYDRB2EDWGYAMGQESLYYJOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 150C0895AC8
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 19:35:39 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-5d8dd488e09sf4678543a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Apr 2024 10:35:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712079337; cv=pass;
        d=google.com; s=arc-20160816;
        b=EU0eOJsrk/7tScAE9alasXMpP0ls6PMxZjPfsydBzxyIGwNgdcU7KL1mxynNAGj1Cj
         695DBNddCxPPntDj+n6hRoWbojy51rQzb3mOXvSAq2rBIzlSulsaBuJ4l6xRIz5h6dyY
         tq5+FBUXl0yCi7LXc+vcSIBDQb3uWaiD5w3g5ipyHtytfyU5XX06AyM1+B2Vm11fY45J
         Zzi+zETNUIqZ/7BAYCfRqShuFjiOlCrDtkRvKSwsmVw4fFUKFiju1bcYMDBAGiBTBPol
         Q6yY4OuUI5+YOwyyeLWn0GuhXKCevzNJGyCe5I8fUE+TdXIi9C3GP8r9WXJs2mJN0sG+
         uctg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QI2foRljmeOLgA7shNK5ec8Chkkit40DqX8LppHyCvQ=;
        fh=2wNL4vevlWRSO7yE8lys+CUMC5XYHn5CumzMXgZjC6o=;
        b=NTfC8wg7r5HdlSBDiBMv2cXrankQAbN732oH4bn9n9UeqIGC9Ur5lleVJtIFqZJQMb
         rsNXUdLtDJecquSCq1gM0unHOfYh9rpU950sgUN5AP2bl/2vwl5mAA4lAY6cjh5PmZXA
         jt9XHaz918TNRXHalAJxlovwxAvaeOKyjhL5ik+Z/kPnPVkO3oOXLwi+ag4MWSpua2qQ
         IL+lDInEWjAX+bzn3JBndygODFJ57NlAN45fzyrah51E06hcjF/PRttCcKEMiK+g79yI
         XGNjUrNxZnCFaRIAhtz12rOSS8UhkTfFy/EvRwuOUG7UOnFhafNq9dVg2VOEQ0W4CqhC
         cjwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712079337; x=1712684137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QI2foRljmeOLgA7shNK5ec8Chkkit40DqX8LppHyCvQ=;
        b=MmzdIrrPZXZlM68jnYmsFHRHTzya+WHD26b/IlbmJ6iq/NUuo+TqLBhVc3V9z1vZDe
         W6KIicR5+6+2+UAwAV1oDxJ56IhFgTHskXxKpCg1BFl4Jf7gnTbwGU7f7dwTa9hjnF+E
         3xt/Msu1hWUAs3WlwIo0q1uV4q938iF4y56BcAlejc+hNGsV84o5Y+V0TqxnFCIKNeMu
         Gn5eZNJo7EFcMon9eq3RQ/9hXzCVLn18Ishqf0NGssA0n5tZ+UnMVOCP+8Nf+DWxP4Za
         HD8qk5DkD1+ob5jzF9FuDuRiySOdZfBBAnIkEu68pmj/XgMcvzhWNqs2YjRcW3bWU3iH
         OWDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712079337; x=1712684137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QI2foRljmeOLgA7shNK5ec8Chkkit40DqX8LppHyCvQ=;
        b=i1lZyb9bAQunHVIwSW2bNXyYV1cnkDWjVckIjmK8p99vOuWFag0kWw5LOzXKR4h2zD
         HVYYHLi9x4IE3IJ1CfH7oiRvNHTY733ioc1A15tC51zk4FJyWkpZ/AjBN6EBtdUYC/JK
         BVjCQqM98+o2P+z2aKYZn4iU5bMTwTw1mKj0TquRbVxdWI1zVe7D1Nnw+XRkv2Mw2ipf
         VmNjJXLnttnHOhFpkvNoh96wfDTy87C+93/DGFuNJOdU5jsy+hxQ1yYDVzKMHIcQTajp
         yZWt9cagY4q0XJNsn9JgRrXW3oz31zCk6f0f+3Xr39BywkMfI3SWmPzoeHWPcRUpD+Rh
         b47w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeVzzEFzqTSl0PLkRMvMSlC8twdxsp9IdAj47OKEE59DDu2XDim2a4OGayAZAu3VsyMLdDKc+ZI/joAxy7tgR+QNnC3t2w4g==
X-Gm-Message-State: AOJu0YzG/mR6v595IR1frtXKXABNBKhASFP9cWpWlrwYXqDEez3j3lPt
	qvUZkKJ375PF1rUSRExaRa2zVKktrKRDfJStw8BE1yIwcnRBf/4E
X-Google-Smtp-Source: AGHT+IEfKHWXLy1SsZzxD8g9ZQ5THbLC6vo/+tcjIL6hPWl5IZnS1IFCbCl3kbQUEhogvgMr49TH1g==
X-Received: by 2002:a17:902:ecd2:b0:1dd:918d:33ae with SMTP id a18-20020a170902ecd200b001dd918d33aemr14950978plh.60.1712079337041;
        Tue, 02 Apr 2024 10:35:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1209:b0:1e0:f879:a3a7 with SMTP id
 l9-20020a170903120900b001e0f879a3a7ls176967plh.1.-pod-prod-06-us; Tue, 02 Apr
 2024 10:35:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSRyO5P22GF0EUrz513IuOtdkgSmkPmq2+gvYh3Yl6mQzYKaIOcmuksSPcDfwO8kiiBiaPOl5Mp3vPSR65pwh9P4YFSHYDeVt/Xg==
X-Received: by 2002:a17:902:7848:b0:1e2:a70:247e with SMTP id e8-20020a170902784800b001e20a70247emr12243610pln.18.1712079334627;
        Tue, 02 Apr 2024 10:35:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712079334; cv=none;
        d=google.com; s=arc-20160816;
        b=yWnHnpbk69eWZrEOuOvMCVI/f8M2EGuOpZh10Z8U1+nyPfz0Wb+oeNmp8BTyXxug9G
         bVKbO1kpOk2p92KNk3tCdFuShjg0vRwZUdvdSEi63Vbj6yraHP4TW+NVO9MgO9VJAoKU
         vfwRn52goxH0fQUr9LrJnlnOLgt5wOi5L/ZSWir/c6P0xc4LfUqRKc1nY8ckNFs3g0GK
         arWmIjmVJ8gQM9lTff8javDABfX6IAMKGtaBgEFg0uyj2/sh3IrTxzJoP/AZzdxEMsQc
         mNRhnNHDNxHE8SE28OsGmh+i20AIqMatIpH/qqodEmR7j2uwkTk2CdoPRRNbongd1oXY
         SUMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=R7TJfTIbEGKkiLbqy2GapjVKYQ2VDXig4kuf0NPPKdE=;
        fh=EvlTaLlVDlxXrJqdBARNEk6Sb0wSkHJ8toqf251ANfc=;
        b=X7G5qtaQJ0u7fFeQZwCz/NXBp2tD2aelgv1+43l1nXlBdUeOFmDsyEHKNSKdYAfI8D
         2WAqYrKfDsRxOyaLMAeIuxSjONVjWjp60AKYikWyuhwczC8sp8TVETf9fcZtAIn5bmqF
         TqNkHV8mth6K2QxxGOdAiD8ZUoue8/NqtGZrxDlhkF+GHJqo0XqvEANE76z+PqGADeOp
         hBCfuIi7CZ1Xx/GPYIvNOGi8is1jfKtEGT2ZKDaUwyl6qgTCwY+GfPGM8Nb1PdCeJZJs
         79BKktJ9KNdh21bm6xrPPcMA6s3DMZfBKTYgNuXxAWSp2c2mzryQKHvH70IusPEqVE/r
         kXhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a6-20020a170902900600b001dede653af6si623158plp.1.2024.04.02.10.35.34
        for <kasan-dev@googlegroups.com>;
        Tue, 02 Apr 2024 10:35:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BC6A11007;
	Tue,  2 Apr 2024 10:36:04 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.16.234])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1E3A83F766;
	Tue,  2 Apr 2024 10:35:30 -0700 (PDT)
Date: Tue, 2 Apr 2024 18:35:28 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: kernel test robot <oliver.sang@intel.com>
Cc: Paul =?us-ascii?Q?Heidekr=22uger?= <paul.heidekrueger@tum.de>,
	oe-lkp@lists.linux.dev, lkp@intel.com, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: [linus:master] [kasan]  4e76c8cc33:
 BUG:KASAN:slab-out-of-bounds_in_kasan_atomics_helper
Message-ID: <ZgxB4PZ8N6QjRqLA@FVFF77S0Q05N>
References: <202403310849.3bb9f3d2-lkp@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202403310849.3bb9f3d2-lkp@intel.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sun, Mar 31, 2024 at 10:18:17AM +0800, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG:KASAN:slab-out-of-bounds_in_kasan_atomics_helper" on:
> 
> commit: 4e76c8cc3378a20923965e3345f40f6b8ae0bdba ("kasan: add atomic tests")
> https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master

This is expected; it's the point of the test...

Is there something this should depend on such that the test robot doesn't build
this? Otherwise, can we please avoid reporting KASAN splates from this KASAN test module?

Mark.

> [test failed on linus/master 8d025e2092e29bfd13e56c78e22af25fac83c8ec]
> [test failed on linux-next/master a6bd6c9333397f5a0e2667d4d82fef8c970108f2]
> 
> in testcase: kunit
> version: 
> with following parameters:
> 
> 	group: group-00
> 
> 
> 
> compiler: gcc-12
> test machine: 16 threads 1 sockets Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz (Broadwell-DE) with 48G memory
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202403310849.3bb9f3d2-lkp@intel.com
> 
> 
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240331/202403310849.3bb9f3d2-lkp@intel.com
> 
> 
> 
> [  306.028382][ T4480] ==================================================================
> [  306.047117][ T4480] BUG: KASAN: slab-out-of-bounds in kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
> [  306.057673][ T4480] Read of size 4 at addr ffff888168de7330 by task kunit_try_catch/4480
> [  306.067074][ T4480] 
> [  306.070605][ T4480] CPU: 2 PID: 4480 Comm: kunit_try_catch Tainted: G S  B            N 6.8.0-rc5-00151-g4e76c8cc3378 #1
> [  306.082834][ T4480] Hardware name: Supermicro SYS-5018D-FN4T/X10SDV-8C-TLN4F, BIOS 1.1 03/02/2016
> [  306.093195][ T4480] Call Trace:
> [  306.097725][ T4480]  <TASK>
> [  306.101846][ T4480]  dump_stack_lvl+0x36/0x50
> [  306.107696][ T4480]  print_address_description+0x2c/0x3a0
> [  306.115489][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
> [  306.123367][ T4480]  print_report+0xba/0x2b0
> [  306.129115][ T4480]  ? kasan_addr_to_slab+0xd/0x90
> [  306.135383][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
> [  306.143412][ T4480]  kasan_report+0xe7/0x120
> [  306.149087][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
> [  306.157076][ T4480]  kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
> [  306.164966][ T4480]  ? kmalloc_oob_right+0x3e0/0x3e0 [kasan_test]
> [  306.172608][ T4480]  ? kasan_save_track+0x14/0x30
> [  306.178787][ T4480]  kasan_atomics+0xeb/0x190 [kasan_test]
> [  306.185724][ T4480]  ? kasan_bitops_generic+0x140/0x140 [kasan_test]
> [  306.193520][ T4480]  ? ktime_get_ts64+0x83/0x1b0
> [  306.199669][ T4480]  kunit_try_run_case+0x1ab/0x480
> [  306.206017][ T4480]  ? kunit_try_run_case_cleanup+0xe0/0xe0
> [  306.213174][ T4480]  ? _raw_read_unlock_irqrestore+0x50/0x50
> [  306.220337][ T4480]  ? set_cpus_allowed_ptr+0x85/0xb0
> [  306.226821][ T4480]  ? migrate_enable+0x2a0/0x2a0
> [  306.232966][ T4480]  ? kunit_try_catch_throw+0x80/0x80
> [  306.239549][ T4480]  ? kunit_try_run_case_cleanup+0xe0/0xe0
> [  306.246540][ T4480]  kunit_generic_run_threadfn_adapter+0x4e/0xa0
> [  306.254054][ T4480]  kthread+0x2dd/0x3c0
> [  306.259312][ T4480]  ? kthread_complete_and_exit+0x30/0x30
> [  306.266147][ T4480]  ret_from_fork+0x31/0x70
> [  306.271775][ T4480]  ? kthread_complete_and_exit+0x30/0x30
> [  306.278575][ T4480]  ret_from_fork_asm+0x11/0x20
> [  306.284413][ T4480]  </TASK>
> [  306.288653][ T4480] 
> [  306.292149][ T4480] Allocated by task 4480:
> [  306.297686][ T4480]  kasan_save_stack+0x33/0x50
> [  306.303495][ T4480]  kasan_save_track+0x14/0x30
> [  306.309255][ T4480]  __kasan_kmalloc+0xa2/0xb0
> [  306.314945][ T4480]  kasan_atomics+0x8c/0x190 [kasan_test]
> [  306.321745][ T4480]  kunit_try_run_case+0x1ab/0x480
> [  306.327860][ T4480]  kunit_generic_run_threadfn_adapter+0x4e/0xa0
> [  306.335239][ T4480]  kthread+0x2dd/0x3c0
> [  306.340469][ T4480]  ret_from_fork+0x31/0x70
> [  306.346020][ T4480]  ret_from_fork_asm+0x11/0x20
> [  306.351815][ T4480] 
> [  306.355163][ T4480] The buggy address belongs to the object at ffff888168de7300
> [  306.355163][ T4480]  which belongs to the cache kmalloc-64 of size 64
> [  306.371174][ T4480] The buggy address is located 0 bytes to the right of
> [  306.371174][ T4480]  allocated 48-byte region [ffff888168de7300, ffff888168de7330)
> [  306.387688][ T4480] 
> [  306.390884][ T4480] The buggy address belongs to the physical page:
> [  306.398313][ T4480] page:000000005ccb3a22 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x168de7
> [  306.409549][ T4480] flags: 0x17ffffc0000800(slab|node=0|zone=2|lastcpupid=0x1fffff)
> [  306.418339][ T4480] page_type: 0xffffffff()
> [  306.423762][ T4480] raw: 0017ffffc0000800 ffff888100042640 dead000000000100 dead000000000122
> [  306.433384][ T4480] raw: 0000000000000000 0000000080200020 00000001ffffffff 0000000000000000
> [  306.443077][ T4480] page dumped because: kasan: bad access detected
> [  306.450608][ T4480] 
> [  306.454016][ T4480] Memory state around the buggy address:
> [  306.460748][ T4480]  ffff888168de7200: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> [  306.469821][ T4480]  ffff888168de7280: 00 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc
> [  306.478894][ T4480] >ffff888168de7300: 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc fc
> [  306.488019][ T4480]                                      ^
> [  306.494672][ T4480]  ffff888168de7380: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> [  306.503812][ T4480]  ffff888168de7400: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> [  306.512946][ T4480] ==================================================================
> 
> 
> -- 
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZgxB4PZ8N6QjRqLA%40FVFF77S0Q05N.

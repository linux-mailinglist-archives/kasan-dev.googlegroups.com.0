Return-Path: <kasan-dev+bncBC4LXIPCY4NRBC456STQMGQEPRE2IOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DF33D799C30
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 02:32:12 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5029c5f4285sf2156069e87.3
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Sep 2023 17:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694305932; cv=pass;
        d=google.com; s=arc-20160816;
        b=MNRY2SY7qhY4gYGmnci+ddab6H0aeOoU8flI3YiG4x5C8GNSUzJIhC4xUcN7qn9xfr
         M1ZL5nfsR8b9/mMfyzFR15YxMWd4rykO38uVImD7f84K1LjhKSJM9tf0Huj+heDunj9X
         3nmRvE4Lu6L72n6+KGiQDdIhvZcNfC0qelOABUeoaTf/7uBmbNr5K1xRPvKZ5enoMf9T
         VworScj/hAx41bE9/vDNOoI12dm5hHO4l2lXJCU6f0hdbNFswvx8tnqWkrYipHvo1KD8
         UPXDlXyO7kUYswJfr9kwsu8Bww3XeXIaq6MNvRkI3S3EYV1yKx6++TUbsMBdpRpUpm3w
         rkdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dgICFcWvjTvzfjhj0yFVEYqO/YD6hk9GpSTuNJaK1Yo=;
        fh=QPVjUeLKAzf4Q/HuuUwr+dq4KhHUpbsoc21/hSuco4c=;
        b=yZ17+LyzkwkFL1tPcziGI3QrZ79xEyjh1AkgjGKbJkfme87Y5thN2YSDikTmEuly0r
         NKZbzKKqZ3Y85mQMt+QhMEIEQvF9IHxrfgZk76rGwu1ekQOiAXvoJJ5KTN1iJgfjVYKH
         ATjW2LTRaXZz81ED+ShqmmrfnwAuhyRp+v5DZZahFM3ynruGzYp7ZsrYczWLxheFQIhE
         8TAA1HAiAqLbSIE1LWj/22kp19kKvCezlZdnvEdszGMI0EKNr99yjrTQjfDR7uGjvdOd
         jZ7UvrD6EoWDfOYpxzLNUkCc6aE5T4AfS6zlGSGSQepp9gcYuZ8tvk0WyvJ3QcjoIXJm
         5lWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DkAkiHtA;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694305932; x=1694910732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dgICFcWvjTvzfjhj0yFVEYqO/YD6hk9GpSTuNJaK1Yo=;
        b=r3YpeJXdE/MqhSNmbozd8V5ObmRlV+lmjuulILR5OzSnMeEQL5yPwuBACensYaqCWy
         O/BylvKM8lq4JPO/4TxzEcX+2gzDoViNzaoEUC/QDkk6RbHFtpb7cNaC6bpkqRn6a+zt
         DCjItYj1hsIFW2p+hdcsWcZPCgi0R0vVrv8aSr3X3Hdt7pWfDbnEWEYVYuc46wcDBu8v
         AnG/M0P0mMP65rXNkA1DnHT/HGljAQwMulekg7ADeJs2OcfiwxjbSHEg8XQ5nuG0ZLsD
         cooskrTBKqu39kXLNCr2tyz4WjblOXt5IfL5T2Q5MHQORtgKRtCFw9K4yO2UwLqIuQEP
         G+9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694305932; x=1694910732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dgICFcWvjTvzfjhj0yFVEYqO/YD6hk9GpSTuNJaK1Yo=;
        b=sy7wZeEIJJglDHlDJY1K+87iXZucZ5B+Nos5u79M/wMO4INUdG6qIViMmfa++g9Ngs
         Eky+AlPaZZrWeRWoJTEYeo1ZMcRQD0ST71I9d5eYV4gyQrRUjlqPWcLeuZSclYm8Qwzu
         xSFGGMYYHRUJfbpaNLd+pWV+ZitGf6PxlFajPCd9FPXc9RpxELzCxq7YJFlsnRhsqaTR
         aVWqhjoSPa1bb7RoNNcSLUIs9OQ1Nzq5r7UqYuX00u1tWQgB9tIMAl4al8JAo4OFeefH
         9OkvLUF7zBdAhMNFOShlbRXo9TKTV0AkRhkSbG+YHOGc0RoDyPSly7VPjKFW97H7mw5i
         D7dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyspEFpO3+IPBwkc72oeOcEaFNEADly0Y5MAYL+fdH/xA3jvR8o
	Zc0TqV9iTpO1FGZaPPvjbVE=
X-Google-Smtp-Source: AGHT+IHYWLACMwKUAVzh08991uew56fKDwHfINTkwGFcQzyaxvDu0P6wJQG/ddcYDihZwgXdrM6UAA==
X-Received: by 2002:a05:6512:3713:b0:4f8:766f:8dc3 with SMTP id z19-20020a056512371300b004f8766f8dc3mr4347397lfr.32.1694305931419;
        Sat, 09 Sep 2023 17:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:608:b0:4ff:80d4:e131 with SMTP id
 b8-20020a056512060800b004ff80d4e131ls985498lfe.1.-pod-prod-09-eu; Sat, 09 Sep
 2023 17:32:09 -0700 (PDT)
X-Received: by 2002:ac2:5629:0:b0:4fb:8f79:631 with SMTP id b9-20020ac25629000000b004fb8f790631mr4964716lff.46.1694305929560;
        Sat, 09 Sep 2023 17:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694305929; cv=none;
        d=google.com; s=arc-20160816;
        b=d0rarGG0MEpvJvEFggmobOYyMK3QWcInSQ0nBSXmcIoREs4MaG0ppBQT17D1gvB12m
         LBAEeXqUSun7ly3HOqBoccg336C4ymTK836+66fB4eDtC5QeWJVKwkvns4RRb468kLma
         jnPwVhfE8zEe8aswAyHN1jQbjVqqB5dWIpP4WXKCrO2z92EXAT2VXIupBowH+ZxhRWun
         /hU0o5nQACPF+IH4ks8Pt3kJwstvZZQFT2EvCvQtah/uffXkcURkpRrHdBwfHBdG6XXx
         VtxWr74hWR1XGRvT2QD3d1wYhCLpQ8ivJgFF3rviaLxAb/7hKOiGLZVbgK9EaGmz2nvo
         obLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WVMHJtdSnzene9Leu6JXJVHJ9+YuPoIq3bYcuTT+HVs=;
        fh=QPVjUeLKAzf4Q/HuuUwr+dq4KhHUpbsoc21/hSuco4c=;
        b=XDGm4X3ysuXBDbnWs4FdKih1auHXHTV7XM/FBHB53LqmjPzymBwYBRaTWAcuWHTeCc
         LBEh5UjjNeVAxM2S4Ie4CVgsqEDzMc4TJfAT2vrWFY3GGe+5IQyA2/4Yr7L3mhxbF1Da
         qDTGLN1IZFxGLavjvEc7uCQblapVxF3PFGrnGzwbqaI00LekLh+n8gRzzk+/09jNOlOM
         Pj0UUo3wo7MPX4oTk4OqpSfeDb/SjVPlQeriIvcnsgWh2OTxMevnOrHXHGxbCeg82IrN
         W5OBIks1QEPMc9L0ccZP1j/UqqOARd4LkuatbUBxmUcdNxs48tFAd5GvmOKVLY9Q7gFn
         lHhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DkAkiHtA;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id d16-20020a056512369000b004fbcd4b8b84si321614lfs.0.2023.09.09.17.32.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Sep 2023 17:32:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10827"; a="368119148"
X-IronPort-AV: E=Sophos;i="6.02,240,1688454000"; 
   d="scan'208";a="368119148"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2023 17:32:05 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10827"; a="916583516"
X-IronPort-AV: E=Sophos;i="6.02,240,1688454000"; 
   d="scan'208";a="916583516"
Received: from lkp-server01.sh.intel.com (HELO 59b3c6e06877) ([10.239.97.150])
  by orsmga005.jf.intel.com with ESMTP; 09 Sep 2023 17:32:03 -0700
Received: from kbuild by 59b3c6e06877 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1qf8Mr-000464-0J;
	Sun, 10 Sep 2023 00:32:01 +0000
Date: Sun, 10 Sep 2023 08:31:44 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Potapenko <glider@google.com>, dvyukov@google.com,
	elver@google.com, akpm@linux-foundation.org, linux-mm@kvack.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/2] kmsan: prevent optimizations in memcpy tests
Message-ID: <202309100805.cRHktAYd-lkp@intel.com>
References: <20230907130642.245222-2-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230907130642.245222-2-glider@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DkAkiHtA;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted
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

Hi Alexander,

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-everything]
[also build test ERROR on linus/master v6.5 next-20230908]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Potapenko/kmsan-prevent-optimizations-in-memcpy-tests/20230907-210817
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20230907130642.245222-2-glider%40google.com
patch subject: [PATCH 2/2] kmsan: prevent optimizations in memcpy tests
config: x86_64-buildonly-randconfig-006-20230910 (https://download.01.org/0day-ci/archive/20230910/202309100805.cRHktAYd-lkp@intel.com/config)
compiler: clang version 16.0.4 (https://github.com/llvm/llvm-project.git ae42196bc493ffe877a7e3dff8be32035dea4d07)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20230910/202309100805.cRHktAYd-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202309100805.cRHktAYd-lkp@intel.com/

All errors (new ones prefixed by >>):

>> mm/kmsan/kmsan_test.c:414:16: error: passing 'volatile void *' to parameter of type 'void *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
           return memcpy(dst, src, size);
                         ^~~
   arch/x86/include/asm/string_64.h:18:27: note: passing argument to parameter 'to' here
   extern void *memcpy(void *to, const void *from, size_t len);
                             ^
>> mm/kmsan/kmsan_test.c:414:21: error: passing 'const volatile void *' to parameter of type 'const void *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
           return memcpy(dst, src, size);
                              ^~~
   arch/x86/include/asm/string_64.h:18:43: note: passing argument to parameter 'from' here
   extern void *memcpy(void *to, const void *from, size_t len);
                                             ^
>> mm/kmsan/kmsan_test.c:468:21: error: passing 'volatile int *' to parameter of type 'const void *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
           kmsan_check_memory(&uninit_src, sizeof(uninit_src));
                              ^~~~~~~~~~~
   include/linux/kmsan-checks.h:47:37: note: passing argument to parameter 'address' here
   void kmsan_check_memory(const void *address, size_t size);
                                       ^
   3 errors generated.


vim +414 mm/kmsan/kmsan_test.c

   409	
   410	/* Prevent the compiler from inlining a memcpy() call. */
   411	static noinline void *memcpy_noinline(volatile void *dst,
   412					      const volatile void *src, size_t size)
   413	{
 > 414		return memcpy(dst, src, size);
   415	}
   416	
   417	/* Test case: ensure that memcpy() correctly copies initialized values. */
   418	static void test_init_memcpy(struct kunit *test)
   419	{
   420		EXPECTATION_NO_REPORT(expect);
   421		volatile int src;
   422		volatile int dst = 0;
   423	
   424		src = 1;
   425		kunit_info(
   426			test,
   427			"memcpy()ing aligned initialized src to aligned dst (no reports)\n");
   428		memcpy_noinline((void *)&dst, (void *)&src, sizeof(src));
   429		kmsan_check_memory((void *)&dst, sizeof(dst));
   430		KUNIT_EXPECT_TRUE(test, report_matches(&expect));
   431	}
   432	
   433	/*
   434	 * Test case: ensure that memcpy() correctly copies uninitialized values between
   435	 * aligned `src` and `dst`.
   436	 */
   437	static void test_memcpy_aligned_to_aligned(struct kunit *test)
   438	{
   439		EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_aligned_to_aligned");
   440		volatile int uninit_src;
   441		volatile int dst = 0;
   442	
   443		kunit_info(
   444			test,
   445			"memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
   446		memcpy_noinline((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
   447		kmsan_check_memory((void *)&dst, sizeof(dst));
   448		KUNIT_EXPECT_TRUE(test, report_matches(&expect));
   449	}
   450	
   451	/*
   452	 * Test case: ensure that memcpy() correctly copies uninitialized values between
   453	 * aligned `src` and unaligned `dst`.
   454	 *
   455	 * Copying aligned 4-byte value to an unaligned one leads to touching two
   456	 * aligned 4-byte values. This test case checks that KMSAN correctly reports an
   457	 * error on the first of the two values.
   458	 */
   459	static void test_memcpy_aligned_to_unaligned(struct kunit *test)
   460	{
   461		EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_aligned_to_unaligned");
   462		volatile int uninit_src;
   463		volatile char dst[8] = { 0 };
   464	
   465		kunit_info(
   466			test,
   467			"memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
 > 468		kmsan_check_memory(&uninit_src, sizeof(uninit_src));
   469		memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
   470				sizeof(uninit_src));
   471		kmsan_check_memory((void *)dst, 4);
   472		KUNIT_EXPECT_TRUE(test, report_matches(&expect));
   473	}
   474	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202309100805.cRHktAYd-lkp%40intel.com.

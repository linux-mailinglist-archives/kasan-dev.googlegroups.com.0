Return-Path: <kasan-dev+bncBC4LXIPCY4NRBN6SZPAAMGQEKCDG7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 82AA7AA59EE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 05:23:37 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3d94fe1037csf8093185ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 20:23:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746069816; cv=pass;
        d=google.com; s=arc-20240605;
        b=jucObLt6SH3wdJwpSIZz0Bfdwde7uHZ+msih08Bzi1ThNNFORramY7B3p3Vubqa3vs
         uIx9vSH8TeHq30KnSvX2mMl4LLHZnRCUnGACBNuhegqsK4iYAaRV6KI6YQb+Tj9IxCF0
         yFQHFesBYkW5ZOBML5pq2Ek921osYc6/CCfKT52qI8gUo88Yx8GBZZWhxsLIl1/NGIPO
         jszLP+V6OFU2++v7lV0G1J2OFxTuXNxFD0X5wB6+dpnt07g5VezUmuzxC6obaZFXbrzB
         zhXEUZuxY7hievXQGmdHEbERceH4SF8JekoLTiG6BSWluTLuErxcjGJ9swX71SgBiylu
         cgTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VtOWFi1w7IfwHMzoqPIbZsfgyFnmCNNqHHjS69DzgY4=;
        fh=o4W19AMVwRL2OeaIVBqg60E7P6vVZhdkj12vEuULsKU=;
        b=D1bRSns5U7VTgETyRhMz4EQn8D4YM+X39UsCKtPo29gr/k0DUNdRTQkRO0ZE6vVK/0
         dsD/fuWWir+8tPjROjDiFMDirC6Mtq0byyK/7a9DhqsADac8doxwGhQP9ATQej0lxmrj
         vVZGPO/wiD9MVLQcElLq2bsvcYapVxKVWz2pmkTUQNMcjkrUEGTn/6ZxJNLEB8FQJ44q
         HsHVAgFu84nSw70g9/4/q+WCHBJC6Rwro6tE+6t2pQmbKjtcr7Kf/uqBLjcQr/acP0v3
         26bFqkmhBxcGqD4h8KmBrFDv7rJdXxc6ZljUf0Foyvmr++aBUYO/jPDP18euYI2no1MS
         v03Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Fc2tq5XS;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746069816; x=1746674616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VtOWFi1w7IfwHMzoqPIbZsfgyFnmCNNqHHjS69DzgY4=;
        b=QL6g+McCMHQcIWjZA7KiEsEfL+clW3U++95FjQ29dsm6P6EnhYkq4zyV/T6UN0qpVt
         EbbtYoANmXIogyHnYUjUEXGpbAazTDjtZVfiPBIMdT46po2rf1lnegBxdirwBuk6A7ZX
         624r6fTCVeUQbGW+6JjYjH20iiOw73Hm4Zy6EP55QIx5txVKqqNzDwxhDqIDRG4kYkHJ
         5eU3BqU+6aL3GzomNRH3PO0F6dPXLkdjCISG9zJ6XNkCUOpO/fbxBsPDODmEHm0VTxcc
         r4/YscFbKbhv8EdKTQu2FJZQ7Vqv0lJ6COM/qISM5M+St/XgPvfdp/6FNLrXTwil2KKb
         J1WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746069816; x=1746674616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VtOWFi1w7IfwHMzoqPIbZsfgyFnmCNNqHHjS69DzgY4=;
        b=C1mJDtwrOeBHBWK5DAmqnydBKmlF405ZKAYGf51vVRRcQkKji4EQ8y742Rj5kWmqUh
         l7ZPXk0RhOZaM6fqpOdRin0kWpZRa4ng+29yjLPoUXb//psI2pu7bZAi9o5U2ifrMBKm
         zaFnTIGBtJ5QVdCqoI9QPjiWxM1pSHD0mp/Ar8o4AyU1d4WRTh/JXzn4Xjc8gumz14dq
         nHGR2vOwLLqgM3HEVqBiDE++v3hb84Fw0S42NfSfTtdlgoGZySO/f1KHfFZ6nDzKIvKX
         3LmQA5/4pDFUNvrSXJrx3kKQ9nutr7G8nrG/nprlrLI31uKmmK737TyGGfrunNVDNZia
         8Htw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWaTitKmUfKDds5Jh8EqyuK62k0v1N8q50Yh3iWJ5yZDMcnKe2WnXg8dxkbj8cO2FQJnhkKVA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4lTxQsOtnNw0P7tBEbxbwLTyM3eFsSQHnK55ku6dfWjY6bNOx
	oxcq4V7X6YWT8MNrQl/FISxbjUx8AMJiFR2ziS3pGITcyyToZDkg
X-Google-Smtp-Source: AGHT+IF1YgYMjXbaoIWF6PeuypWAnKCp07e/epzmwRDCO6acQloO+qBMRZ9mvaUBvJEI9VI0ZXF/ow==
X-Received: by 2002:a05:6e02:3385:b0:3d6:cb9b:cbd6 with SMTP id e9e14a558f8ab-3d967fc1e87mr50066045ab.13.1746069815858;
        Wed, 30 Apr 2025 20:23:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHopHN5PQgbzBl3Pqab1t5TOxi20ngaHNz2pX1Ivcf4mg==
Received: by 2002:a05:6e02:198f:b0:3d9:3cd3:13a5 with SMTP id
 e9e14a558f8ab-3d96e70a872ls4720435ab.0.-pod-prod-06-us; Wed, 30 Apr 2025
 20:23:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6BmM61js2Jzzl2x0AZEgGRjU9njs8HX5Iu7dUFROKeGcJQ9D78tGGbzMbYVkH81Qb73Xe6JcJKLo=@googlegroups.com
X-Received: by 2002:a05:6e02:2488:b0:3a7:820c:180a with SMTP id e9e14a558f8ab-3d968009df5mr60113885ab.19.1746069815017;
        Wed, 30 Apr 2025 20:23:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746069815; cv=none;
        d=google.com; s=arc-20240605;
        b=cd2/P91x4rAa9OC6gMV6CWka0LRvGbaP1eYpXbZLQ5hfZerbgUaXk1w14QNnpBrGjW
         3f+gh7HCXLztJi3YclQmjENUiIV/dcdpDKVf5pdaDtDmrLAA+5t2iH5prLlb5V5KEyv6
         BYalz2jrTuM9ugAAQKJ7fPumky7N3N7PoA0p9oMA8/Blv1jAT94sJDYHbnKUY+3fl42v
         ey9rXgwR785vRYEqW5tmBvfHeEr7zNlm+MZ9FYVfJ/FZPpl/SBPSf5I/dI45Ey7fGuA3
         gec5PJKcRPSiCBBNw4rTD+3Jt0Q/Mz+yH21pRE5WHUXWM6MgQL5AtLKSLz7d/iVULCUX
         0icQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9MU0Q4CT+onxp0FpdQAIfPSHrJwsMJDLhjSNR7nZYD0=;
        fh=5EfUUJEVggJkcBC6NBp8ZtA4t3srMWAmv5wbOrhjiz4=;
        b=Z9lVvw9V551DHBSF/IZ+3SZM5EuWZEcCdHoiNo6vmjN8pLlR5t9CtrBTPvo3ZE1DKF
         D1aLcbKZRWPd3BLwz6Zp6/uRVIrk1v3AmR3zO3gRWHB/xBgFRA3USkulCdT1DI/Kjlz7
         JCDf3n5pCHpQrPHl7pxTbzdLkwSZ5ypOnz1tdXhFxyjhcn1tXMCRp6Icb9kvFYntt5rU
         bDofs4x6F3aMzjMUBGitUJQiWMQYnYIANdXGYxcyJPWomqMixPgfVzyjQreWMEt61jdb
         y/DIaR0I0KOyRSLHhjlvU8PZEyT8mwqCpEujIf0KBhKoJwu/qws4jERz03cmF6ot86De
         V36w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Fc2tq5XS;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f86720eb0fsi156376173.0.2025.04.30.20.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 30 Apr 2025 20:23:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-CSE-ConnectionGUID: QmNfvtWLQ/aB/Y6/AtthIg==
X-CSE-MsgGUID: CmwTb0/TRRGlu514fbNnvQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11419"; a="73136877"
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="73136877"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Apr 2025 20:23:34 -0700
X-CSE-ConnectionGUID: PQUWvfaJS/ybTMOZlBwt6w==
X-CSE-MsgGUID: JoGepA1fTjuYCerjhxy0+g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="134034716"
Received: from lkp-server01.sh.intel.com (HELO 1992f890471c) ([10.239.97.150])
  by orviesa009.jf.intel.com with ESMTP; 30 Apr 2025 20:23:31 -0700
Received: from kbuild by 1992f890471c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uAKWG-0003vp-1K;
	Thu, 01 May 2025 03:23:28 +0000
Date: Thu, 1 May 2025 11:22:50 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Daniel Axtens <dja@axtens.net>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <202505010957.08s1jPkF-lkp@intel.com>
References: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Fc2tq5XS;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted
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

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on linus/master v6.15-rc4 next-20250430]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Gordeev/kasan-Avoid-sleepable-page-allocation-from-atomic-context/20250430-001020
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev%40linux.ibm.com
patch subject: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from atomic context
config: x86_64-buildonly-randconfig-002-20250501 (https://download.01.org/0day-ci/archive/20250501/202505010957.08s1jPkF-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250501/202505010957.08s1jPkF-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202505010957.08s1jPkF-lkp@intel.com/

All warnings (new ones prefixed by >>):

   mm/kasan/shadow.c: In function 'kasan_populate_vmalloc_pte':
   mm/kasan/shadow.c:313:18: error: implicit declaration of function 'pfn_to_virt'; did you mean 'fix_to_virt'? [-Werror=implicit-function-declaration]
     313 |         __memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
         |                  ^~~~~~~~~~~
         |                  fix_to_virt
>> mm/kasan/shadow.c:313:18: warning: passing argument 1 of '__memset' makes pointer from integer without a cast [-Wint-conversion]
     313 |         __memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
         |                  ^~~~~~~~~~~~~~~~
         |                  |
         |                  int
   In file included from arch/x86/include/asm/string.h:5,
                    from arch/x86/include/asm/cpuid/api.h:10,
                    from arch/x86/include/asm/cpuid.h:6,
                    from arch/x86/include/asm/processor.h:19,
                    from arch/x86/include/asm/cpufeature.h:5,
                    from arch/x86/include/asm/thread_info.h:59,
                    from include/linux/thread_info.h:60,
                    from include/linux/spinlock.h:60,
                    from arch/x86/include/asm/pgtable.h:19,
                    from include/linux/pgtable.h:6,
                    from include/linux/kasan.h:37,
                    from mm/kasan/shadow.c:14:
   arch/x86/include/asm/string_64.h:23:22: note: expected 'void *' but argument is of type 'int'
      23 | void *__memset(void *s, int c, size_t n);
         |                ~~~~~~^
   cc1: some warnings being treated as errors


vim +/__memset +313 mm/kasan/shadow.c

   299	
   300	static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
   301					      void *_data)
   302	{
   303		struct vmalloc_populate_data *data = _data;
   304		struct page *page;
   305		unsigned long pfn;
   306		pte_t pte;
   307	
   308		if (likely(!pte_none(ptep_get(ptep))))
   309			return 0;
   310	
   311		page = data->pages[PFN_DOWN(addr - data->start)];
   312		pfn = page_to_pfn(page);
 > 313		__memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
   314		pte = pfn_pte(pfn, PAGE_KERNEL);
   315	
   316		spin_lock(&init_mm.page_table_lock);
   317		if (likely(pte_none(ptep_get(ptep))))
   318			set_pte_at(&init_mm, addr, ptep, pte);
   319		spin_unlock(&init_mm.page_table_lock);
   320	
   321		return 0;
   322	}
   323	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505010957.08s1jPkF-lkp%40intel.com.

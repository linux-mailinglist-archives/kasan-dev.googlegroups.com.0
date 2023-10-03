Return-Path: <kasan-dev+bncBC4LXIPCY4NRBCER56UAMGQELCMC3VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id EC3EA7B62D6
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Oct 2023 09:53:45 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-503c774fd61sf563884e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Oct 2023 00:53:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696319625; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpCkG7/DnWM0Yuj1y2mAwWZM1fG8p8+s1F66a2oW/HlEGduXiqG70Ay7uAk+mew5io
         gDNiX2UtP/GwuOeSj8v1gyitl/LAE4i1Oqn5co/q7mg7yWeN4h536ZjBwqBm0aU570Ro
         ZO1IuaOgYO3nPnV7lS1H17HYTPRJnv1oO/JktaHuE0OVvI1/jNpeU8VhLqJr+uxx4p3d
         oDPppNmI6/otfZoG3FlNL6bGTQAR6wZUVnBVi/Zp2TYlS2rNS+Wld7KP0W9AJb8AlcPK
         qXZV8/E3OEuJqcyTMVl58WIxvoE9ThlqkrAa8x8aX6K02KvHF94vuTwGk6T93BZ+QPtM
         XjhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CKFrZFIrmJ2YEh9ljPOUsbJbj/v2WjlgV8luQrUGoWQ=;
        fh=bcfbn4ytBUbPWm9d5XklwLSqGFGw6hzHRExKbuwiuZ4=;
        b=cUynrsyhm67DdHGmKi/w/HVB4sKgWGO9mx11QwfjqAYMGObnf9IlWP3l4XwQUYNIiL
         Jsj0A8GgAC4EAxGEndNeA85ZwEpgRTbf0NY5wqJDMwzsQSdfNvO4HKMaJucgM9fYEN7M
         2BO9WKCLZMEeIn5XTVnD4pG6jmBVVXQ6bUORMdYQ8CtChzAy7S4Hljlabj5yRD0eNq9m
         2Q4Gxz5w2ADsV84SJ1i7mR8WNs0p9oC4vdhfqwaLR/doce4J9dq3suizpu3GGkGZgNFu
         LR64lnxMYV5xk9ewzzb0DOgxrHs21MeVEPwbDgF1inC8CNv1dHO/T1UnQwKQrnAdc5NF
         odZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=FftPiatV;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696319625; x=1696924425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CKFrZFIrmJ2YEh9ljPOUsbJbj/v2WjlgV8luQrUGoWQ=;
        b=GFvTx+CQSUWp+637QmZCRoP9OcEvBr0rJVksouL5lBLah6xyH+v+0AGq2zWw227G4g
         j42ypalsULqsOBf6AXrnIFl21f7jbLZT3D4osw+4HW7N7m9THT2RIlvszDWXEw8a/yoF
         1jyWPs/WBrl3KUboDlJwrJQ6UBFiFWyDqCaRA0DhuM7l41CYnvY4VzsuTGaZfFd+tTm/
         R4jk2wu1aJPdltWSZPvkubVWRJjvGBgWWqb1Aip6zAXauCrHXnK78LCx5DCnmo0VTRhw
         nnUHpUmVtlEGCfHiRh6q6yEtIglqEFnejuPHHguPQ0st4nGxXbG1HJpf+gFhtjq1CMIT
         v3ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696319625; x=1696924425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CKFrZFIrmJ2YEh9ljPOUsbJbj/v2WjlgV8luQrUGoWQ=;
        b=uwUKPomZZqf9VZo42rKSzv5RoZylTpl4qUq8FF4vTmvcxK/7SXjp7jNMs4+qrInqFj
         Tfv+ZO3jfQntIrQXjkDw1Hi1/QUevXiJYxNAOpCP/CUXH6TfYu8OjXEk2eQLT1bJ1hgM
         QOAR57r3zvPZq+uRpnpeYj/u7jtOFkIJpPt6EYY8XJmK8UwFSg3c1t7lSDgchhByOCuG
         4XLiD9SYCbPz5VnllRvimE/ZBFpp9twG3coXfFcpgjzSq82Feap2gHqKOQjh1n2RtKgb
         4/hTn1Sk6kr/Nho88UI3IRn5Zjaf+pawd5MYBPtwi+cizqn80PNMRWppD9UIzkmW490j
         gPgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwE+jQdfxcCOo3B0gfnQF6KCq3ZMianQqzDomNBwbi31WwuK3bN
	468r8ooQGnugghpbHymJ40c=
X-Google-Smtp-Source: AGHT+IGOGfwoDMdijasYtr3gDHBCbAdgigQzOO3dNnARHyTAz5czwm+ycfMwPx/Iam8aR5Mje6yWTQ==
X-Received: by 2002:a05:6512:2507:b0:500:aed0:cb1b with SMTP id be7-20020a056512250700b00500aed0cb1bmr11013966lfb.24.1696319624489;
        Tue, 03 Oct 2023 00:53:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:641d:0:b0:500:80c9:a128 with SMTP id y29-20020a19641d000000b0050080c9a128ls312595lfb.0.-pod-prod-03-eu;
 Tue, 03 Oct 2023 00:53:42 -0700 (PDT)
X-Received: by 2002:a05:6512:2507:b0:500:aed0:cb1b with SMTP id be7-20020a056512250700b00500aed0cb1bmr11013902lfb.24.1696319622416;
        Tue, 03 Oct 2023 00:53:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696319622; cv=none;
        d=google.com; s=arc-20160816;
        b=MnV5DbveNtz6PkcnyzE3R0PKtXoSmdIM2ZffpR2EHd6MM/o+05koC3iVbmt6++xLcb
         XhCUk5xmEaDdBdB5c2gwf/u9QFQLI7UhQXwFW9GVNxUs4beIsVvTF1QmCPt4Dgh4YbT8
         21Dw4Tn9wB4Co773D1/6gnFaEHTLKYeTWmPnaZrQzKGhwkpsNinMyhy3t5O6/VaAoWv1
         ni0DL88fblOidJSRBy0T5817DkFaKUccdMJI3nTXaWl9fkMwfXX2fHcYCoW8lSoU40w6
         WaclMl6slGbS/Fu/8a398fbxlHjl8qoeck17k/v4DcsQJDEa9ZXkPoyschQD93IqXLDG
         9XRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=m7K0+FwtuhE4EKsjVm5hWwwIehi2E1MB208mtDdrg28=;
        fh=bcfbn4ytBUbPWm9d5XklwLSqGFGw6hzHRExKbuwiuZ4=;
        b=u91dA2a80DJdy6yBWb1cTyi63nmMg/Hp1GqK+AElRmgo2/tf5lSY4NbY0jpx7LbshO
         kCFyElX32laoV/EmTETQhV7ztS43fdYQVzY30/5VulAwmygkLCOjGUhZwBco54fP7CSi
         LI/Q4PE/We+4kfhypjCQ5BYzZsFQxnde3fN6cgrJj7SlvOJKyicJLt5SBvXpYBs16wQb
         qEdz2NWH/lDT8LI1+34TBqVgeNUYViQuWdue6FrpmS3SUE/XVoQnuH49JFb5FT0/ZKmU
         pEVfSPU71bAf0RYbZfXz0GwYXS+4+gUUHSzRO/EniTgd4W1yg80mv9ec7ZHttTq/vVZg
         icGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=FftPiatV;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id az11-20020a05600c600b00b0040653ab52e4si732061wmb.0.2023.10.03.00.53.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Oct 2023 00:53:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10851"; a="385639771"
X-IronPort-AV: E=Sophos;i="6.03,196,1694761200"; 
   d="scan'208";a="385639771"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Oct 2023 00:53:30 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10851"; a="754323419"
X-IronPort-AV: E=Sophos;i="6.03,196,1694761200"; 
   d="scan'208";a="754323419"
Received: from lkp-server02.sh.intel.com (HELO c3b01524d57c) ([10.239.97.151])
  by fmsmga007.fm.intel.com with ESMTP; 03 Oct 2023 00:52:57 -0700
Received: from kbuild by c3b01524d57c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1qnaD7-0006tx-2G;
	Tue, 03 Oct 2023 07:52:54 +0000
Date: Tue, 3 Oct 2023 15:52:46 +0800
From: kernel test robot <lkp@intel.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH 2/5] mm: Introduce pudp/p4dp/pgdp_get() functions
Message-ID: <202310031548.53wZmUUH-lkp@intel.com>
References: <20231002151031.110551-3-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231002151031.110551-3-alexghiti@rivosinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=FftPiatV;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted
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

Hi Alexandre,

kernel test robot noticed the following build errors:

[auto build test ERROR on linus/master]
[also build test ERROR on v6.6-rc4 next-20231003]
[cannot apply to efi/next]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexandre-Ghiti/riscv-Use-WRITE_ONCE-when-setting-page-table-entries/20231002-231725
base:   linus/master
patch link:    https://lore.kernel.org/r/20231002151031.110551-3-alexghiti%40rivosinc.com
patch subject: [PATCH 2/5] mm: Introduce pudp/p4dp/pgdp_get() functions
config: arm-moxart_defconfig (https://download.01.org/0day-ci/archive/20231003/202310031548.53wZmUUH-lkp@intel.com/config)
compiler: clang version 17.0.0 (https://github.com/llvm/llvm-project.git 4a5ac14ee968ff0ad5d2cc1ffa0299048db4c88a)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231003/202310031548.53wZmUUH-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202310031548.53wZmUUH-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:29:
>> include/linux/pgtable.h:310:29: error: function cannot return array type 'pgd_t' (aka 'unsigned int[2]')
     310 | static inline pgd_t pgdp_get(pgd_t *pgdp)
         |                             ^
>> include/linux/pgtable.h:312:9: error: incompatible pointer to integer conversion returning 'const volatile pmdval_t *' (aka 'const volatile unsigned int *') from a function with result type 'int' [-Wint-conversion]
     312 |         return READ_ONCE(*pgdp);
         |                ^~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:47:28: note: expanded from macro 'READ_ONCE'
      47 | #define READ_ONCE(x)                                                    \
         |                                                                         ^
      48 | ({                                                                      \
         | ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      49 |         compiletime_assert_rwonce_type(x);                              \
         |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      50 |         __READ_ONCE(x);                                                 \
         |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      51 | })
         | ~~
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:11: warning: array index 3 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
      97 |                 return (set->sig[3] | set->sig[2] |
         |                         ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:25: warning: array index 2 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
      97 |                 return (set->sig[3] | set->sig[2] |
         |                                       ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:11: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     113 |                 return  (set1->sig[3] == set2->sig[3]) &&
         |                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:27: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     113 |                 return  (set1->sig[3] == set2->sig[3]) &&
         |                                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:5: warning: array index 2 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     114 |                         (set1->sig[2] == set2->sig[2]) &&
         |                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:21: warning: array index 2 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     114 |                         (set1->sig[2] == set2->sig[2]) &&
         |                                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1075:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:156:1: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     156 | _SIG_SET_BINOP(sigorsets, _sig_or)


vim +310 include/linux/pgtable.h

   308	
   309	#ifndef pgdp_get
 > 310	static inline pgd_t pgdp_get(pgd_t *pgdp)
   311	{
 > 312		return READ_ONCE(*pgdp);
   313	}
   314	#endif
   315	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202310031548.53wZmUUH-lkp%40intel.com.

Return-Path: <kasan-dev+bncBC4LXIPCY4NRBXMLZPAAMGQEK2QPBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A103BAA592A
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 02:52:47 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-224192ff68bsf3861675ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 17:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746060765; cv=pass;
        d=google.com; s=arc-20240605;
        b=WCsGk3R5Yy9AzppC90JVjE3bVNnpl5eKdxtLaNP32viBbL8VcoW1kUHO5Nj+tBDaYU
         wtf6DRU/TCgpnHrU6N7F8bBr5yGn7MwGvE6cv/RlCbRQt8/tjOXhPIi1d4lE0Iw74QX4
         nELCesFiBZZlHa8zx3qt3bgwGwDQjzV+mCXskdMddspU4+8qpC0IkuKKepByfTWETvk2
         q492YhrP7+Bd6hSl8wE/tAoKQcvPR7LmDshXcS7B57lozDN2lvOHQmjbKaHniJmXz+5m
         6vZJ8yE29soDkwB81vW0LjQbYBxPkA04tKlbzhTzJDrKg8WNiDyDZadDkzrwThVhDD2s
         Gq8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/JqOS6I4MEBmS1zVIJsi2SdUdYDv+8JNV5adH47MRHo=;
        fh=6qiUmueDQcIuTzI+50nrwQPaN67EmzYnSfGy57n+Ckk=;
        b=K2s3D5zc5RWTMNn5ZPqB3DAPmfnqCIB/e3xz+TF8KEe9TGViPYvdDA+oSoRnt6SXjP
         8QnFkqaJVKx4sGn13CszfuehmTAx1CY3eviFDI46v/FcgTYafnO7E+LYW13UGvyEM3IH
         g5hvsg3kIzchvqjU6jGb55XoqXl3Zicylui/cr6C4iNaa+ZQaW0LXm/PvwPA/Ee6T+6W
         Zi/FLR+q2fBpY5qCqxWPWsgaK7nfT8rGuLsz5c4YRqv5MLFOjufqvqA8r+wPllbthoRX
         6xRiF958PvFVEzwfWFBo+OOKTjxARs95GNOnminpYUuCWHVxpMWF7sffomPgmnv+j52q
         mRyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NWOzK+4+;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.10 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746060765; x=1746665565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/JqOS6I4MEBmS1zVIJsi2SdUdYDv+8JNV5adH47MRHo=;
        b=W2qIzE5tM224g4blAHUzOTwKiE3hQWs+E6TsklIwZEakDkVeUy8MGXbA29JZ+g81Pj
         93c/az18h4q9yYDGvZr5x8qLRqjcYhGsraJnAqBJQWMNvkz8xT3XYBjf23tuwEpZz41l
         EkGAf+KpCmKGXy2muCQ+BjvDKsvuiiE81aPwbRR1lMKES3QOFOc5Yr6vDNdUTSziNbZT
         NlIyoPiPJitT98c6FF1lYjXVI29NaXfC94vPoPiSC7cXtTyZMNzGFHwUuoAT2s+iagfw
         Fbi8QYOBsbUoLWZYr3jfLQvL40Y1CrY2SSZgD+xCNkMEbxPqXPabsPVtveXR9r/Gr89e
         2XhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746060765; x=1746665565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/JqOS6I4MEBmS1zVIJsi2SdUdYDv+8JNV5adH47MRHo=;
        b=TmHQvS4zbPbE0ftJY9hnyXztwDqNrPQz8ZOL2goi19YXMoHp8up0aTXzi8gm3DSKh9
         sL5VNIfj/92FTiNgSoq/R8p8+KGX1/ZQJXIh03lzxkoSkMjp5/EO88j32yi9YEGGbwwa
         cvoMu7MQyzIDFUOSGgyXi2JzBe5erp4bAkZrt8TGs6DGC+yivLFET76KShPxJ92m0xzX
         iwR3hhBPrLYFyF1k2X9gMvKVwPR2QUhLru6elOVgZF7UDiyFYpnlK+42lCXOBxn3WquT
         UcvXl5/h5FcbWCyP7B+qxgRFXXJkQ8tLDs1Dimc3ahB/+h5x1KOhy9w/qf+jB6iqHDcW
         0xkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyQEMbTNzQHx/YTJKY2Bq0SvtOVeSwIHEkihkYSVYBF2+Pd07TXms4xbQhoK1gmgOzRY7rNQ==@lfdr.de
X-Gm-Message-State: AOJu0YwayYeGCMeUlHdPdp8PpEG1fvsydU9Fj82n+ZAMI7/8Yr8ciNAq
	nR/OjdY0swpjCSMH9hIYx3I5d+OZxaEmIf1I1mG9+skV3QEiMf1l
X-Google-Smtp-Source: AGHT+IE7LonCsXJTRhLZdweX4fP7N9LfLehZ2RBZQ9fQfu8ejd6RQkld2ap5rKfYw0NJ4RYxAKBchg==
X-Received: by 2002:a17:902:e54c:b0:223:f408:c3cf with SMTP id d9443c01a7336-22df34ff96amr79781675ad.21.1746060765334;
        Wed, 30 Apr 2025 17:52:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHXxwiPFPo0/R8shvb0nnVJyfU1IrV8tuy+Btaf6dYDdQ==
Received: by 2002:a17:902:8546:b0:220:c15b:c2cb with SMTP id
 d9443c01a7336-22e02fbfb8cls2882495ad.1.-pod-prod-02-us; Wed, 30 Apr 2025
 17:52:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWaZH+fJDA0raF3LYjd+f6feGSI2G9+dn9/YJtRS+jPPJbYs8jYZ3WKfwFcun6tBmm5UvwMSlQEGRA=@googlegroups.com
X-Received: by 2002:a17:902:e785:b0:220:c63b:d93c with SMTP id d9443c01a7336-22df35bb0fcmr90650725ad.44.1746060764081;
        Wed, 30 Apr 2025 17:52:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746060764; cv=none;
        d=google.com; s=arc-20240605;
        b=XF45UktGyQ4Yk3WhQmUFwQhWPb7wRpxDOkgucFIyV+zxZlnpZuoJA061ewS1bKzMLm
         IFgd3P6GRmOigQjorFkOs6S+gPtWzrVOu4iVtjXGFdEMPRe11pwA3fssSPzYQHV3nGgl
         V9RB/FnT/sUOF7kDPUE+TL0lFhJxMaPYIRnkfQ8f/B+WwmIDi3nmrcRgH1fFfY2gf//E
         X8XGG3CpV5TCDiFRtjtiQbjveUlrzhHQy0yFPtBaVJBmSz1la7iCVADwHGC8oZw8YMoa
         WhQFMmBK2mt7xrIsYOQDHlUi6IFvZ08B5Cn2fg4SMwvL18cke8rvhmZDR28sfRAaAJ7A
         2CAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VrPd49iXvl6S+8n79+YTI6YNvBM/OwWSppIhiflqbaY=;
        fh=LuYu5bkq/plYhTQx+Zt132wP478RdiuWAFMQEhZmqas=;
        b=cQtFSlUwPOoROFXPFxeHCkx3oqT+rIzOrehhHHPN1jNjvheUkigasLVmg3dgdOIUDn
         +AKjVjEZq151DBX0xWzX+QthVtcFH4O1EmoJgLhjK8IZz7YV5TSGOlNq7UpmDmNpyNqG
         yDC/ZAql7WhxJ6y2DP+vx9I09uBZrSKO07oSprDZyA0VnM1Gh5cspTzuoDM0iNjQ9oZU
         50M1KdwqvYTSddaMBkS9zSCjTJ+9KvugNpnX4o9GCejMDvmhIwTRHjg5fEVVFlbPl8mO
         ps54sltWTRhqQLaD23KKVABnhMaMyP+B2Fv3lIck0hOLuRxD323iMBMbACS+ctpbEVrJ
         CRRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NWOzK+4+;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.10 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22db4c177b1si7059115ad.0.2025.04.30.17.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 30 Apr 2025 17:52:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.10 as permitted sender) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: +BH8gzTaS8CRNkPiO+6Lbg==
X-CSE-MsgGUID: 4XmAO1DQRGqz8Fl+PteP3w==
X-IronPort-AV: E=McAfee;i="6700,10204,11419"; a="59102535"
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="59102535"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Apr 2025 17:52:42 -0700
X-CSE-ConnectionGUID: CZ7wJ0HsTry5iIOxqydNWQ==
X-CSE-MsgGUID: FivrNy4gQVOiBEzlJsy6KQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="165336468"
Received: from lkp-server01.sh.intel.com (HELO 1992f890471c) ([10.239.97.150])
  by fmviesa001.fm.intel.com with ESMTP; 30 Apr 2025 17:52:39 -0700
Received: from kbuild by 1992f890471c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uAIAH-0003s5-0L;
	Thu, 01 May 2025 00:52:37 +0000
Date: Thu, 1 May 2025 08:51:46 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Daniel Axtens <dja@axtens.net>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <202505010807.0tj4Krnz-lkp@intel.com>
References: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NWOzK+4+;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.10 as permitted
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
[also build test ERROR on linus/master v6.15-rc4 next-20250430]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Gordeev/kasan-Avoid-sleepable-page-allocation-from-atomic-context/20250430-001020
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev%40linux.ibm.com
patch subject: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from atomic context
config: x86_64-buildonly-randconfig-001-20250501 (https://download.01.org/0day-ci/archive/20250501/202505010807.0tj4Krnz-lkp@intel.com/config)
compiler: clang version 20.1.2 (https://github.com/llvm/llvm-project 58df0ef89dd64126512e4ee27b4ac3fd8ddf6247)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250501/202505010807.0tj4Krnz-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202505010807.0tj4Krnz-lkp@intel.com/

All errors (new ones prefixed by >>):

>> mm/kasan/shadow.c:313:11: error: call to undeclared function 'pfn_to_virt'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
     313 |         __memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
         |                  ^
   mm/kasan/shadow.c:313:11: note: did you mean 'fix_to_virt'?
   include/asm-generic/fixmap.h:30:38: note: 'fix_to_virt' declared here
      30 | static __always_inline unsigned long fix_to_virt(const unsigned int idx)
         |                                      ^
>> mm/kasan/shadow.c:313:11: error: incompatible integer to pointer conversion passing 'int' to parameter of type 'void *' [-Wint-conversion]
     313 |         __memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
         |                  ^~~~~~~~~~~~~~~~
   arch/x86/include/asm/string_64.h:23:22: note: passing argument to parameter 's' here
      23 | void *__memset(void *s, int c, size_t n);
         |                      ^
   2 errors generated.


vim +/pfn_to_virt +313 mm/kasan/shadow.c

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505010807.0tj4Krnz-lkp%40intel.com.

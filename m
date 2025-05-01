Return-Path: <kasan-dev+bncBC4LXIPCY4NRBTHSZTAAMGQEP2CBSOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6626FAA5C75
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 11:05:18 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-3087a704c6bsf826704a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 02:05:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746090316; cv=pass;
        d=google.com; s=arc-20240605;
        b=V90GYDQYBtOVSBIiMNYKNldVuiKHQj8zqLUHVWnIJVG/M4yUlfFe1pWgYkr+M1Zu0K
         PJOFz3UGgjEiSsbPRpXU/0VJ4kqBjNGw3xouz3PagllyNMjrcMMMby/CR2+qu1x6I18g
         xBB2SDYhro/5cqOBzVZL9IZai3nvQe4KAFCcy/lxX7lwKgl90bik0ydOwrJpivPRHUq3
         Vr/peskzNXvcDA7XahEH8r5N/ARIwR4V3FtcwZ08dC02YfUJFic5q6gFr3ptqipYGuue
         qnnPQknOid1h895p/i8PpZzuMUDhurE4A1yZsjHcLySMoqzODd+fzHYnAgxjJii+2Z4N
         81uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sx1TKcIYTa6MA2LNjY1+dRycNiqETpQPst4HUWxEWj0=;
        fh=DQgFAsBnq5SkSV2OLVB5ONdpS0qCqQ7dfP391YlUCYY=;
        b=jRxCNOSIW1BmNpzR5Sg5ioG1mpa6+TYj1xc3x2y3OARGmPTrC34Cv/sdm/elYBybhP
         d5BbC/GiEf1VFBZptwlyoK6qefwvC14uJ/mGhrNk/QnzOFG7nzusT+N6pnQ6rid6aks4
         kjIbRWWmXX//BEchNetEUD6vVSasXDOt+Dp34Hjb3oxQeSLSz8brCmFIVBdMHsmXSt90
         e3l5xuTyc57aetNnAEuAdPV/cX2zmwKgaJ70VhRfb3P9vbz0BNko5DiDbjFKp9uFyqn/
         zCW55tGBJ11vXn2fzn7Gn0Ump3hBqP5EfRy4XTNNBsM69igN7UNONu0FdDzaDi9OqQXx
         JZwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VZE+WDfY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746090316; x=1746695116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sx1TKcIYTa6MA2LNjY1+dRycNiqETpQPst4HUWxEWj0=;
        b=iqfabmb6eEYgaVbpVKZq6WM6ORKvbQYIxabZlcykpgrmjBHyaAFW1ZjQlbby8Phywg
         IohgDKiAin9toOSqznoa5t11E1tWSBBrPUoDy1IkuX6kjPmqCU9oFMJVZqS/sRSyje2H
         +gnINJ+v5rabIzoLT0MA4KPmgyvOWdbMcJAvzPOP8+lCF7zCN2hPa30dPSPPkZ3PCiB5
         R9PymPPvSyNxgd4IYdzcIZlQR698beIYzdiRiNwd5lOWTxDp5VFjeK8hIkTmhB1jlnmu
         nLXwghEROgxJeebA/fMeoVS174iOf5Zu+T9hV6UqerbSVUdooFjrMhrlDBh03kvijc2n
         zxCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746090316; x=1746695116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sx1TKcIYTa6MA2LNjY1+dRycNiqETpQPst4HUWxEWj0=;
        b=VT4OEO/WPshTawJQAcFtdd0fpa8gVtwvGY6Xh/b7k5sNPDwUDes0RpDoMInChL5umR
         R4zdJSZZ4QG0kCzG90cjooBADAJwQtHka/8Tx6bOsZTYG3tXp3XG9+eWWo5dveUWscaM
         Ptey/5e0IqQRDLbbe0gMYxl5iiSj1GpgTv/VKfXiSzZOOXILKY+dkD5CvLevef9JdgAy
         4WnwR2NwnbLuPUUzEF8MbHoyxn/VEFfNXU9gVKBRkEsz0eGrJnRdUnfmsf2l6L0DLOAw
         5xfjOF+SwmQbJjc+ACjYE3gEPN7ax3ncWgVDPxJhz62DP9Cy14DdcnpzlR6OESQiIYW4
         tWVw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXtzs/9WaQRWWf/iu4NcdkA9Yvqcyz1ZeLwdnBzYiHE1QESeVjWY+Tw9kYFwP0UII0seKWnw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0R147vbccEeXIbsoBng0vaDyw+CL61YCVwNIAfiSlHZmuZCmj
	FwY2MBhhvTItDO13EWpxFv+84AyMhyAy6M5p2g8V9QsYjTH4l52f
X-Google-Smtp-Source: AGHT+IGG1mc5F+OeOZeecuBT4xl2Qt1iOwdy8jW70Qq7rKV7NavFDCRrxdm4W/d5sEpHqw7s+rIndA==
X-Received: by 2002:a17:90b:5206:b0:2ee:ee5e:42fb with SMTP id 98e67ed59e1d1-30a41d1a9eamr3101508a91.13.1746090316501;
        Thu, 01 May 2025 02:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFp649dXwRbGoD7Dyy1Nqj1BnYs1cFEpqiSBTIViNUzDw==
Received: by 2002:a17:90b:5403:b0:2dd:58a2:6016 with SMTP id
 98e67ed59e1d1-30a3f71983dls721424a91.1.-pod-prod-09-us; Thu, 01 May 2025
 02:05:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZiZp6UH1FnkHFkdyuPUe4cXlGkUedArW76ReO7tOWzvP0ZNkmIHClYpRhFPISINQtK+jbzxqClHU=@googlegroups.com
X-Received: by 2002:a17:90b:562d:b0:301:98fc:9b2f with SMTP id 98e67ed59e1d1-30a41cfc2e0mr2894734a91.1.1746090315204;
        Thu, 01 May 2025 02:05:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746090315; cv=none;
        d=google.com; s=arc-20240605;
        b=iHmrvSLC/bygbNtCE5b9Wx3DMJL99UjDlBNrnfzgG8XlWDnqyS+ylatbqM/fDyF+LE
         2dYQnrMZQUzJO5TLzbyEuvbOxRw1fEo+jJYlKnwCSUY+YuW/Ogxz24wNQOW0A+pss5x+
         9YvguI+dAvwhg5rSFeXS4j/30+QI9hFPouls/O5B1kaNCyiY3gF8d2ICRDZExVo+VPaT
         rccGUBlKBQsKEgeuvYopoopCe+ya9ZTX+HC5uBNRs+2n+C28T0BxrnsM6TXi5tvckOth
         WWSvWabn4SJSnMIah7rDBwsodPMzhPbLukU9zzcmUuQrFBI4tKBXsGw4tttAONKH9PNe
         lFwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=O7p7JICzN8bMSjVDbrCzxcynJk+1GsZW7smk1iZiYPI=;
        fh=5EfUUJEVggJkcBC6NBp8ZtA4t3srMWAmv5wbOrhjiz4=;
        b=Ci7Bzkqrz+zVPnNhMMBDuDlT9J+AqFTsGN5TZvLYGe3yOYk3MSMtaQcmEkishdkbVh
         9+4u8BWfg+aBWj/3CiASyHJb+AfifB2B8sYZIm8Tih99bBfFaEaSdXNpHYWwCo81DbPJ
         M1KVJKLL9+lfddSxnqZPboPZzgRrsIg6kypaSZoAM9CkOjbHCZQ5r4UfFBHv9ud7ing+
         M5qhwmCkVcuv7WERsnrs/k9gmUgW7AzudH2w6xNY6aMY1WNCIqdi5Xa9F9RF0g9TsgOY
         tnBjIa59oe7ZLBNXOtCi0NVphIP1SpMIp0alc3RiiuFfpmvqPVGOnR7GC3tH7CDimcrr
         eZCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VZE+WDfY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a244b503asi445346a91.0.2025.05.01.02.05.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 01 May 2025 02:05:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: pBrINvvbRNyJVF6qkpthKg==
X-CSE-MsgGUID: SzRKa+/nSXCdRS3g9mRdgg==
X-IronPort-AV: E=McAfee;i="6700,10204,11419"; a="58423470"
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="58423470"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 May 2025 02:05:13 -0700
X-CSE-ConnectionGUID: AQZpm5eZTuOAKYj8W4GChA==
X-CSE-MsgGUID: eCKoVHzCQjq4j/jvm5gZaA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,253,1739865600"; 
   d="scan'208";a="139527385"
Received: from lkp-server01.sh.intel.com (HELO 1992f890471c) ([10.239.97.150])
  by orviesa005.jf.intel.com with ESMTP; 01 May 2025 02:05:10 -0700
Received: from kbuild by 1992f890471c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uAPqt-00044N-1D;
	Thu, 01 May 2025 09:05:07 +0000
Date: Thu, 1 May 2025 17:04:54 +0800
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
Message-ID: <202505011646.eHmKdH9T-lkp@intel.com>
References: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VZE+WDfY;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted
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
config: x86_64-buildonly-randconfig-002-20250501 (https://download.01.org/0day-ci/archive/20250501/202505011646.eHmKdH9T-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250501/202505011646.eHmKdH9T-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202505011646.eHmKdH9T-lkp@intel.com/

All errors (new ones prefixed by >>):

   mm/kasan/shadow.c: In function 'kasan_populate_vmalloc_pte':
>> mm/kasan/shadow.c:313:18: error: implicit declaration of function 'pfn_to_virt'; did you mean 'fix_to_virt'? [-Werror=implicit-function-declaration]
     313 |         __memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
         |                  ^~~~~~~~~~~
         |                  fix_to_virt
   mm/kasan/shadow.c:313:18: warning: passing argument 1 of '__memset' makes pointer from integer without a cast [-Wint-conversion]
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


vim +313 mm/kasan/shadow.c

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505011646.eHmKdH9T-lkp%40intel.com.

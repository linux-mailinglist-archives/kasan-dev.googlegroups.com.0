Return-Path: <kasan-dev+bncBC4LXIPCY4NRBA7UTLFAMGQEVLQIILI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B89F6CD3146
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 16:00:20 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88a2e9e09e6sf85778226d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 07:00:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766242819; cv=pass;
        d=google.com; s=arc-20240605;
        b=VUu4rb1qfS6B2xBz/THgBg+npk3aCEGMfQS5zpIJbOuwCMbWdD3/uI8X/KB5akFYPx
         0rNV+AAb2zan/TPNkck6TLYe1m7crqGW+q1PT/i4JjWmV0sl3z80XpP6IitILPxZViJg
         5n0ltCJsfuvTVnS+ORBZKSvOdKYv3XohjuiB5KrF2RTKVl5s3j6snqaWA+d2p0SPjmHc
         VfAJbXhe7tu6NayGJaP48hX5a8KDzIRP7n+uT/F5JxpxmTwAQQnjOYU2YrYg1UbyiCep
         T7gCFj9U8+TwXM8++Zp8qCS6mk70j388ANU8SJPa3rQIet81cGLj5cMYDDhQ3ne5KkZr
         YJ5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QY9MPICo7dbXBnr7KGQqDT4fmnvHHYl2NeXIThrA4yM=;
        fh=6bEdWU5x85aaXL1NIpUXwc1ZMQAxCVnlCdiBZT8pyQs=;
        b=KrZNEHr12R5nCqqq9uqvOUzfsdSFQXBf3xidzAQ7/kwOy7/ULTBJKOgbgXZsSrKvaW
         YeZMWgqad56vG9+Jydz5UCGCQyvbYUX6XnIlgHQBQjNgdsd5ZjKSEBekHm8pCYzAbU98
         Yfi4ZJpcgrkXyB+oZ5w6Af1dlHMntH2k6o/jzIDCN/bIBSQVY2QfZQw4P1W3wIUHY4jO
         S6Ah38rZ5N1w8P/Pn6gBxV9kZWM2tL+eBcCpV8x/GF48DIu5y0T2Ep9K56DlsxdSFjl3
         isNnEl+nCVUY+tdKpQtqGYiKhyAduFgXk86TF4zGkZu5HAkUtYi9J2U4ncHHZTSHHwDD
         D3Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QF0k9o1b;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766242819; x=1766847619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QY9MPICo7dbXBnr7KGQqDT4fmnvHHYl2NeXIThrA4yM=;
        b=qvftXHzJFG7aYn0RmlLNm3CSa8cUq7VnEOdTjzSsLmeBw1NyLspLdpMROVmqrmCSFq
         7kx4t2RZfRgYS9YSma1d/1t1SImuMUI4fJK9+itLcp2fNxtRH8NPPPEe98JeRl2vQO2k
         Sj/sVsqPocBqskQt4WArC+osWCy9/xNodrTaBHWtRuKhW7BUOpeXv/JuEwB2KuSjScy/
         LcbvK8W5LVkcwe9BNBYZEjLfyvz2iPoEhml7XsdE+G+7dvLi8xxbju0a4VSRfveUg7W6
         AdknRVdtvKL81e7SX7gShgNvLi/HLKbMa1eURzboI9muFcT6xBolLpVnUV+lb7KvCus6
         z0Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766242819; x=1766847619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QY9MPICo7dbXBnr7KGQqDT4fmnvHHYl2NeXIThrA4yM=;
        b=QCiJ6ZqA75/mAFbj/dKrL5qJ4/41UepbvdT+T8MGwwR7hMn6UEang2/8XfUg0Z4xsy
         eLhM3EkWdLDChPTAtRD+LYxGr2+hRebe9aaGnyfvIHeOrca8sm/6UzUxYfLA+H6Z2fKk
         Irdafia+Gws78Bo1n1yp3I8tthZ+cC+XhYQz2/FLfZDZ6aGTxrJHLjVv2/xL6sCWCLuC
         /vOe0RRg+SvNTBCJ4Lx1Y9POM3u1VPU9Adq90sCgN5iB3Ke3WiASMCNsOtlnvRWgYskK
         +uJlsC0FEOZpAH07XzKX/LNGn4zPx2QCW1rjImdTEOG0UNbL7aq0NpqbjKkSUZIJ0ANh
         KtFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVckj/lefEhjji4KhNvtAU8eeQD/TkR9lVmvvfsjwoEAIeW5iAEOVEVPypYdY0mdCGUucD+w==@lfdr.de
X-Gm-Message-State: AOJu0YzEBRBRobAG/jahtqdEbT+XlX0p4D97jSKfl7U/dDRlGB4C2Htr
	PVT6nXcDZ2nTAVQ+hiRhQ+heDcDD2tBlsdEorFP2ObQk5ZZV+va1isLu
X-Google-Smtp-Source: AGHT+IF6niObBxs4IptN7A3GUxR53nK05y8UoFx/Kj/639SRp9Lw3y7DRfchNSLxB0qMDAquSUsB8w==
X-Received: by 2002:a05:6214:4805:b0:880:4f1b:c948 with SMTP id 6a1803df08f44-88d7f5ad9cfmr111019816d6.0.1766242819199;
        Sat, 20 Dec 2025 07:00:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaopvuFxLqBum7MhI2GElENuZp9bCwWYs7FdKXqQo6VDA=="
Received: by 2002:a05:6214:4105:b0:882:7510:5ec3 with SMTP id
 6a1803df08f44-8887cdb8cc1ls138464016d6.2.-pod-prod-04-us; Sat, 20 Dec 2025
 07:00:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRPObFCFrvSXIzthyF1ZSR6rumPtRwpwezSbqFv1KucXwFa9f0cVzXAmUu85uR7sHwNij8LuNrl7k=@googlegroups.com
X-Received: by 2002:a05:6102:2c81:b0:5db:deb6:b261 with SMTP id ada2fe7eead31-5eb1a687a81mr2075294137.13.1766242817782;
        Sat, 20 Dec 2025 07:00:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766242817; cv=none;
        d=google.com; s=arc-20240605;
        b=a+FiD86g8Fo19NOJPgUlDKUTPGUB8oznSG7/Ea9BK7690tJXXNT3q9iQZ+wo6CZNm+
         jbEOgyGYCaZJ9uf/nlXvy7ZVRIbWE73Z8pmYql1nXSyPxaeS5mrqIaTt/sqnSEcRohXZ
         WCAXiI4u9bsEF0Fj/VmN81UcUt0CJa5BoiPguSX1yH+nr21W8ERWlpig3E3gVSjoJ5/Z
         uxiaH9SNxIXb7SybfQ4G8t6k74eoogN2EyKAWu5bKB47p6gVMKsX13JUB2oIniTMq3hY
         9Afgq8NOtcIqWvDZUnO8qXl6ZXPdQqRCMhpwOAsP++hfSc4wZjtmux2r9wjTRuOT10Ze
         TdDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Saq2FZEcwQrd82YyfDDhi4uHhVd+/wspSeiOMWjVo4Y=;
        fh=xEc2vZ+l8KVa9d0Z9iuvHEC7996Rn8e4seIcLTjQuuQ=;
        b=iUgeRQXHEL2VBZ2DG5xEXDce1W9UikSczFnyuLu4CYxdunGIK4Gf/23W7mEo2qyS3t
         BoKSO8kATbaMM0ZdRh6Izq/7+fnaRdHpv4Sy4lE33aIK8wH5HS1uj1iokHBN+ldQDHDJ
         ZuxvUjDNwaDwk7JRYE8snKp4+5rrtv/Cp2tuxtQt6v2Yzbv6p8ZgnvFDbUFgHGkNMtui
         fKldJD2K59z/F/8UV0sqY3qqLQNgm5haFuwQOEVsZaigGrE/pyVNlP+xujSDujluCRX0
         7Ui0BCMrEPTahHAUrmZdMVYuB0cXFo/hYYNfbbQ994XwjOuFGFtUG50d59vE3gqXYFwt
         rEhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QF0k9o1b;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5eb1a85b7e0si89907137.0.2025.12.20.07.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 20 Dec 2025 07:00:16 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: mmeYcsJCRwe22naEVCQ3NQ==
X-CSE-MsgGUID: 04odoDqERwqvSoOb3jRl8w==
X-IronPort-AV: E=McAfee;i="6800,10657,11648"; a="72034853"
X-IronPort-AV: E=Sophos;i="6.21,164,1763452800"; 
   d="scan'208";a="72034853"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Dec 2025 07:00:15 -0800
X-CSE-ConnectionGUID: ysKCsu1NS7yg8Gtmsb+gbA==
X-CSE-MsgGUID: mUb9l548SkiLudHURCvl3A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,164,1763452800"; 
   d="scan'208";a="198359998"
Received: from lkp-server01.sh.intel.com (HELO 0d09efa1b85f) ([10.239.97.150])
  by orviesa010.jf.intel.com with ESMTP; 20 Dec 2025 07:00:12 -0800
Received: from kbuild by 0d09efa1b85f with local (Exim 4.98.2)
	(envelope-from <lkp@intel.com>)
	id 1vWyRF-000000004hf-0nvW;
	Sat, 20 Dec 2025 15:00:09 +0000
Date: Sat, 20 Dec 2025 22:59:31 +0800
From: kernel test robot <lkp@intel.com>
To: yuan linyu <yuanlinyu@honor.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>, kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, yuan linyu <yuanlinyu@honor.com>
Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Message-ID: <202512202213.aA8qY41g-lkp@intel.com>
References: <20251218063916.1433615-3-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251218063916.1433615-3-yuanlinyu@honor.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QF0k9o1b;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted
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

Hi yuan,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on drm-misc/drm-misc-next linus/master v6.19-rc1 next-20251219]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/yuan-linyu/LoongArch-kfence-avoid-use-CONFIG_KFENCE_NUM_OBJECTS/20251218-144322
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20251218063916.1433615-3-yuanlinyu%40honor.com
patch subject: [PATCH v2 2/2] kfence: allow change number of object by early parameter
config: i386-buildonly-randconfig-001-20251219 (https://download.01.org/0day-ci/archive/20251220/202512202213.aA8qY41g-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251220/202512202213.aA8qY41g-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202512202213.aA8qY41g-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kfence/core.c:997:16: warning: variable 'nr_pages_covered' set but not used [-Wunused-but-set-variable]
     997 |         unsigned long nr_pages_covered, covered_size;
         |                       ^
   1 warning generated.


vim +/nr_pages_covered +997 mm/kfence/core.c

   991	
   992	static int kfence_init_late(void)
   993	{
   994		unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
   995		unsigned long addr = (unsigned long)__kfence_pool;
   996		unsigned long free_size = __kfence_pool_size;
 > 997		unsigned long nr_pages_covered, covered_size;
   998		int err = -ENOMEM;
   999	
  1000		kfence_alloc_covered_order = ilog2(__kfence_num_objects) + 2;
  1001		kfence_alloc_covered_mask = (1 << kfence_alloc_covered_order) - 1;
  1002		covered_size =  PAGE_ALIGN(KFENCE_COVERED_SIZE);
  1003		nr_pages_covered = (covered_size / PAGE_SIZE);
  1004	#ifdef CONFIG_CONTIG_ALLOC
  1005		struct page *pages;
  1006	
  1007		pages = alloc_contig_pages(__kfence_pool_pages, GFP_KERNEL, first_online_node,
  1008					   NULL);
  1009		if (!pages)
  1010			return -ENOMEM;
  1011	
  1012		__kfence_pool = page_to_virt(pages);
  1013		pages = alloc_contig_pages(nr_pages_covered, GFP_KERNEL, first_online_node,
  1014					   NULL);
  1015		if (!pages)
  1016			goto free_pool;
  1017		alloc_covered = page_to_virt(pages);
  1018		pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
  1019					   NULL);
  1020		if (pages)
  1021			kfence_metadata_init = page_to_virt(pages);
  1022	#else
  1023		if (__kfence_pool_pages > MAX_ORDER_NR_PAGES ||
  1024		    nr_pages_meta > MAX_ORDER_NR_PAGES) {
  1025			pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
  1026			return -EINVAL;
  1027		}
  1028	
  1029		__kfence_pool = alloc_pages_exact(__kfence_pool_size, GFP_KERNEL);
  1030		if (!__kfence_pool)
  1031			return -ENOMEM;
  1032	
  1033		alloc_covered = alloc_pages_exact(covered_size, GFP_KERNEL);
  1034		if (!alloc_covered)
  1035			goto free_pool;
  1036		kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
  1037	#endif
  1038	
  1039		if (!kfence_metadata_init)
  1040			goto free_cover;
  1041	
  1042		memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
  1043		addr = kfence_init_pool();
  1044		if (!addr) {
  1045			kfence_init_enable();
  1046			kfence_debugfs_init();
  1047			return 0;
  1048		}
  1049	
  1050		pr_err("%s failed\n", __func__);
  1051		free_size = __kfence_pool_size - (addr - (unsigned long)__kfence_pool);
  1052		err = -EBUSY;
  1053	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202512202213.aA8qY41g-lkp%40intel.com.

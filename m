Return-Path: <kasan-dev+bncBC4LXIPCY4NRBVOZUK4AMGQEF6I4MDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E73E9999BC4
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 06:43:02 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-8352a3cc8b5sf157725839f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 21:43:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728621781; cv=pass;
        d=google.com; s=arc-20240605;
        b=EU8gXUqzoUgwnmuyz3efCWawk+69bO5xYPifETSTbIuI6PmMtoUvmjYJkrU1Fpd5gN
         ufzI/2bOpdlRgg1zPsusumHHnhq6yuxDpawRFKTL3JAdFUtffgT0pEd3INW+gtUTyh1p
         cHElBimh/hfXHAuDq5rrYBn8gzxJm2sPS1YajfhS6INt9256aa8Z/OTvotPFG5R6bVQG
         E3XnH0yYIvCJOlnKFPGe1scRZOny+SMlY66rSk3KsxzZR1w0OT/hqn0tIIFkpJsAZN+f
         QTLsYte/o6qL7GgWZ0q3XGT9L07kY4VgIYNS32knsr9gBRz3itM8U5i6ZbEIfnRgKHsa
         y43g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mNzinKzN4+tPhB6mBXq2KUyVkHU9zQjevhAUisg8ntY=;
        fh=GUSr74QgfRM2ystqAkdKHOIeQWKMQDwmOQN0cNyjPoI=;
        b=e0s1gCZnu32RLttPInkTL9GuEelFR60E2zaKTbmh+CAYF1OEHiPgKBC9F6u2w5w1BF
         cdG5yM2Pyn9sPeR13lw/jBMW/S6NVrjUyocOGRhhLcJIo/Sah6rFxAHM5wM9PeenZgR+
         PVUPl8DZ9sqYBxK1g9Scp69E4RmZbjiZPDFnimsjEUmEWPyJctALrYDOCQYah+Z6ZYNd
         a1ScQiOdohQHIPsqRkaKuXgurMwAewtTmlXv2nXnVNvrZRxxYHCOsqLxSND4l+K9uvYs
         iYnE98bFZkYwUCJGgX7FzEVYNcq6QfEs3TMPiiuaYi+BRhYOOJxICZsSt2sl19nOfdR7
         CMFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mSsLiclH;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728621781; x=1729226581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mNzinKzN4+tPhB6mBXq2KUyVkHU9zQjevhAUisg8ntY=;
        b=EOW5KVJjG39UKIY6XZOPEOKjVX4ahESMpNcJaH63+Vsq8oYD+PGzXb5pG/Mnn3Ymqs
         4GZqttGnAkmboarI3VnmELXmx9KfFhrusblni/ObxQQZydSgOxEw3g6s172X9IjNdAjX
         XuragQfzcYgqWEmmv1gYKKBmHNlTMFBODxRo4pssgbN00pL912fxFqwaX4MUJoM5cmPx
         tk5X6KOCNUJ5gFFHyrh8rfUWmgGXHpxNzUZ40iS4ut/zMUrPQHJ5pfE/2OLRTqjb3MDz
         f0KVbUmXR/46fJSqBYgxug3oLgNTYMr7MlaTvWHLPE4TUhovNc/il92yFDSQ9IkVN+yR
         s7uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728621781; x=1729226581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mNzinKzN4+tPhB6mBXq2KUyVkHU9zQjevhAUisg8ntY=;
        b=ZcHOcKsxxdQkf4EPgsFOnpdnnKYliKbX9uNEwkYT1v8zgUHAL0x+YIvVEGPoICqZgj
         32n3NEX9ibYZRTlSd7porSdq2MEB/QRY9IElC8AlFLQVLq29Abv1xKqChvzDkin1xRtC
         Uqhll5/vqrQIQZP3HwCTFmEaRPW4DaJW8716bXivj46t4fbKJ0QeUAMf7BhkcVORn34z
         szvNkHUI2SgglabpqSNHgeZNGvqe+NmJL7Axa1pOeJti7B6pqd48lWYkZvXcGWsRVA2v
         0FxTZm+MwskL5BLjWEG8ACMf+4B8sJy3sFFCE39qG6g4C/ShnODwQAye2ofrZ7goxLj9
         BlmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWq6PsBVQe/+Dwqe4Cwsa3Z0nDXK4PWrqGgagF8Yt8jeRTl63YRwpRrClqur4f+BCFcaVdEQA==@lfdr.de
X-Gm-Message-State: AOJu0YxhczohVDgMLtXvnB7pO6ksLB82jz+81ziPaZ3XSsmKfOYNcZZ3
	S9UOTKqX0EBuoZ7V83kP4ihrdfCYGVFgZwTeWoytFlBqx4BCovNU
X-Google-Smtp-Source: AGHT+IF6ORiKmt5tduZzZS7Kv7rg2DTeS+JlVm30G3CjdxZIefstSn4jxAmSbcuju3NvAq9qXVVRmA==
X-Received: by 2002:a05:6e02:1548:b0:3a1:a69f:939a with SMTP id e9e14a558f8ab-3a3b5f7c44fmr13671145ab.13.1728621781346;
        Thu, 10 Oct 2024 21:43:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c24c:0:b0:3a3:9c22:3a4a with SMTP id e9e14a558f8ab-3a3a736d09bls9259885ab.0.-pod-prod-03-us;
 Thu, 10 Oct 2024 21:43:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdrPDYtDuV2ON30D9FdplCaWmSAAFHeJvGyoPkraBEGf1T0cMBwAgdzYbjI+1A5epWm5HthUtfTmY=@googlegroups.com
X-Received: by 2002:a05:6602:2cc5:b0:82c:fb31:2340 with SMTP id ca18e2360f4ac-837932de019mr114660639f.7.1728621780402;
        Thu, 10 Oct 2024 21:43:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728621780; cv=none;
        d=google.com; s=arc-20240605;
        b=B0qJQ0//rCBk6Rhnv88nHIgaGEzKItbY0erLW+p9Jd0yTw5p1+3nm34skr6rU6/m14
         9JTv/VW30KUt6TaZsLPlDxyC3mWd61TCJWIMdiA9tyXhmYyqr9UiABIVl9hvJc167n4e
         tHnpevFA3pZXQ6ldAwd0tVWL6DHV2E5u6q5PpfJqNtIriRoO9Oo6aG+3r5wTkr6uk6gf
         rfQ60P5dOdvG/3G67VkePdbfSavFaIBOrKq2Pc3f6/zXVImkxMawbFYnUWKQaU2NRABC
         Jh0mP0PKYZ3cwO36b904pqfhG5MJgsk33eaPgMEBCxnjx7Gig+qVvozBvhig/Vdl15zv
         HpzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6ueJlU84+7U4j+zBBLEI9J39OkJAqCNlP6eXO48ylO0=;
        fh=Pii+ye6aEamv3UXG1Ma9xLfTLXLb0tVQsv97JAq2y4U=;
        b=TFRK5hnWz9bMuG4xoE8BTU/dF4kVoDpTSVGfeqwrZaUCNzwg4zbEdAHBshH2jKVaQz
         RfqK4xWQc9qiIdtRmeH+xaeuKQ1VtlBQ9BhAqpTF/SDFjQv2Vb0Opo04ppsQSkfQyHSa
         6MzJ6lYKWhq4ByK/HScsg0xSG4R4hOVm/wkM0QTPFlV77q7Wdp9uVGMMcNphtS3q2Neh
         bSMNTmk+FV6fjZj84Md1SJdakj+RjkErj3piyPranZahiG/ZGhVtLGSB0FevcE5YI1yQ
         A3ldmMspsdCbZEm5XAqWmH7eQ+0SvcA4kKPbEmrFm9BvTQ+JmgHWfBXm7SSFSkaFe+U4
         +CEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mSsLiclH;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8354ba63012si12389339f.3.2024.10.10.21.43.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 10 Oct 2024 21:43:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: KQfh4J7gTc21KHgkbpReQw==
X-CSE-MsgGUID: nVDsvuazR262x4C/AhlFIw==
X-IronPort-AV: E=McAfee;i="6700,10204,11221"; a="27959197"
X-IronPort-AV: E=Sophos;i="6.11,194,1725346800"; 
   d="scan'208";a="27959197"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2024 21:42:58 -0700
X-CSE-ConnectionGUID: pbRcFdqLRZmQX/JmBKPFNg==
X-CSE-MsgGUID: /8q1Oky7SJmnO1TALXDWhw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,194,1725346800"; 
   d="scan'208";a="76712344"
Received: from lkp-server01.sh.intel.com (HELO a48cf1aa22e8) ([10.239.97.150])
  by orviesa010.jf.intel.com with ESMTP; 10 Oct 2024 21:42:56 -0700
Received: from kbuild by a48cf1aa22e8 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sz7UL-000Bod-0J;
	Fri, 11 Oct 2024 04:42:53 +0000
Date: Fri, 11 Oct 2024 12:42:35 +0800
From: kernel test robot <lkp@intel.com>
To: Bibo Mao <maobibo@loongson.cn>, Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is
 created
Message-ID: <202410111254.kon5pPzX-lkp@intel.com>
References: <20241010035048.3422527-3-maobibo@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241010035048.3422527-3-maobibo@loongson.cn>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mSsLiclH;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted
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

Hi Bibo,

kernel test robot noticed the following build warnings:

[auto build test WARNING on 87d6aab2389e5ce0197d8257d5f8ee965a67c4cd]

url:    https://github.com/intel-lab-lkp/linux/commits/Bibo-Mao/LoongArch-Set-pte-entry-with-PAGE_GLOBAL-for-kernel-space/20241010-115120
base:   87d6aab2389e5ce0197d8257d5f8ee965a67c4cd
patch link:    https://lore.kernel.org/r/20241010035048.3422527-3-maobibo%40loongson.cn
patch subject: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is created
config: s390-allnoconfig (https://download.01.org/0day-ci/archive/20241011/202410111254.kon5pPzX-lkp@intel.com/config)
compiler: clang version 20.0.0git (https://github.com/llvm/llvm-project 70e0a7e7e6a8541bcc46908c592eed561850e416)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20241011/202410111254.kon5pPzX-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202410111254.kon5pPzX-lkp@intel.com/

All warnings (new ones prefixed by >>):

   In file included from mm/sparse-vmemmap.c:21:
   In file included from include/linux/mm.h:2213:
   include/linux/vmstat.h:518:36: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
     518 |         return node_stat_name(NR_LRU_BASE + lru) + 3; // skip "nr_"
         |                               ~~~~~~~~~~~ ^ ~~~
   In file included from mm/sparse-vmemmap.c:23:
   In file included from include/linux/memblock.h:13:
   In file included from arch/s390/include/asm/dma.h:5:
   In file included from include/linux/io.h:14:
   In file included from arch/s390/include/asm/io.h:93:
   include/asm-generic/io.h:548:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     548 |         val = __raw_readb(PCI_IOBASE + addr);
         |                           ~~~~~~~~~~ ^
   include/asm-generic/io.h:561:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     561 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:37:59: note: expanded from macro '__le16_to_cpu'
      37 | #define __le16_to_cpu(x) __swab16((__force __u16)(__le16)(x))
         |                                                           ^
   include/uapi/linux/swab.h:102:54: note: expanded from macro '__swab16'
     102 | #define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
         |                                                      ^
   In file included from mm/sparse-vmemmap.c:23:
   In file included from include/linux/memblock.h:13:
   In file included from arch/s390/include/asm/dma.h:5:
   In file included from include/linux/io.h:14:
   In file included from arch/s390/include/asm/io.h:93:
   include/asm-generic/io.h:574:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     574 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:35:59: note: expanded from macro '__le32_to_cpu'
      35 | #define __le32_to_cpu(x) __swab32((__force __u32)(__le32)(x))
         |                                                           ^
   include/uapi/linux/swab.h:115:54: note: expanded from macro '__swab32'
     115 | #define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
         |                                                      ^
   In file included from mm/sparse-vmemmap.c:23:
   In file included from include/linux/memblock.h:13:
   In file included from arch/s390/include/asm/dma.h:5:
   In file included from include/linux/io.h:14:
   In file included from arch/s390/include/asm/io.h:93:
   include/asm-generic/io.h:585:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     585 |         __raw_writeb(value, PCI_IOBASE + addr);
         |                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:595:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     595 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:605:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     605 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:693:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     693 |         readsb(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:701:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     701 |         readsw(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:709:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     709 |         readsl(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:718:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     718 |         writesb(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:727:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     727 |         writesw(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:736:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     736 |         writesl(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
>> mm/sparse-vmemmap.c:187:23: warning: no previous prototype for function 'kernel_pte_init' [-Wmissing-prototypes]
     187 | void __weak __meminit kernel_pte_init(void *addr)
         |                       ^
   mm/sparse-vmemmap.c:187:1: note: declare 'static' if the function is not intended to be used outside of this translation unit
     187 | void __weak __meminit kernel_pte_init(void *addr)
         | ^
         | static 
   14 warnings generated.


vim +/kernel_pte_init +187 mm/sparse-vmemmap.c

   186	
 > 187	void __weak __meminit kernel_pte_init(void *addr)
   188	{
   189	}
   190	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410111254.kon5pPzX-lkp%40intel.com.

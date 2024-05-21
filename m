Return-Path: <kasan-dev+bncBC4LXIPCY4NRB5P6V6ZAMGQEM5AETRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AEA38CA5FF
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 03:57:11 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2b2bc9bc0a9sf4050382a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 18:57:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716256630; cv=pass;
        d=google.com; s=arc-20160816;
        b=XwUhjYi4f9OewTGMo54R/ML28QSiayRN6hMdCCxxTGRJif/qeuZZ0lPHXMGRlm+0h3
         Ed+CdX5h0mcW4gG/ZIFIdwiXX/JD6uTc7b7ISWX3hb8SBhxXFtOFnb418scgAQ23mKk9
         zzzTAo+BbPvDkf40GAOV8vgZvh28WI28RB8PHuLB3Kw1Ka4E5DyoM3EyDnt05Cky7sSf
         l7jxTbE1pdSZcoG7gLiz464vW/BxaC+vKCfdYxj9C1hMn/bn4Qx1pSkeOxYcQnP4a/7x
         oGI7bbQK0inkWGX3IoUQTwpO3FIoJcb79Ofyblve2FJwR8yVdH/LOK28OVsdT137by/y
         We2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MDmIB8WW+GCEHPp8n2LrQIyrlMp7foBf2Ko9iSqLzCU=;
        fh=1gK7T3wWTeXLe6RF649tsw72CjyMlSkmB5HvgFrxaTk=;
        b=nZJ6nxIYQJnCatxAnjS4l2Upr77gIbKD7xd+6Ai0ZYnzAtlSc2Yl8g+44hRKKP6oBK
         SETwfcr8e8+C0dBagw4tNYROOwak81fvjd47XId+klX1ZZDOzOBrAjv7YnBljTrU94Zi
         9Tmj6JflHKo+2h2ynLOJJ4mJRNWZ1B+YkmOVMUiZQ0pidlS4EnbTIKR6cFcTKryDeyrp
         tQg/qRMVxHtUaLsAfSGyUNzVaweVGlyZbcpoUzE8jQ+zI7/DE+8ddbmu9PhjZkekPNcg
         0voDJKfJ1UJ66/TIA7mo+LXEqW0CjUNPogn2p5lwW/f8K2WoWSRKqyiCPMhv4yMch7dA
         06wQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="LoQkg5E/";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716256630; x=1716861430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MDmIB8WW+GCEHPp8n2LrQIyrlMp7foBf2Ko9iSqLzCU=;
        b=cWbpNvbdyEqmE50VdBODJ/Zo1Es1ddnZCvSBCHteIlbu54gJ5Fc5xp80z7NuZb0ql3
         PqY9B5locEqYulelwRav8z8Yy2eXLNGHF3gFrJaCAzKs8rTTf96cvTqHRMn2yo5mC+gm
         faYjdyz6/3Rr9TSagNZi6Ip/20tDh/A8s2WxFEFOeE+TvjisyXNaxU3k72Jzrsgxrh+o
         DwlIX/lrMJ0RW46x0RDFjl+tXHcuuB9uCniX8xiEdzUNTUWCn6fAg/DK4vHGS1S8luiQ
         UUsVsJ3KGbhmBNb7dkuz+l+dhhTuXb7ngTf2UdGNYo1Jtpc/ruJOfyX/ON+AuAMo+t6H
         13iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716256630; x=1716861430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MDmIB8WW+GCEHPp8n2LrQIyrlMp7foBf2Ko9iSqLzCU=;
        b=RnWad+EbElAg2p1NpN6CcRrc9/tRgfCaU9FNNfC2iNt+FLzSS/sIUf5nvYlZI+ek+d
         HDaJzL+zXlQnmDLmOapTe1BD3f+UdRknYdRB6QpZ4H2r9OCjyD40j2csXPxnpRXFqtZv
         hqmZvyyW7rPmksFXYjcRdotW0rYxrxYHrFpl+kVnT7T4hfnnH/j2q/MQOuOckyaN29Rw
         qVjYVFmnxFtl2Q0XMdYfwBN821vMjxv9GGcv7cTtJ5PBJ8JvslG7vUS3FlVr/1DxIh1y
         OUiNahQ/7J/5oGn10hTsVdG8FPAcqTg0vUhXHDDdNIY+tGcxxUOmucWbQOdlmrdZIP7n
         jq+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1zmHmCDeoml82T2GNIfy53eVf6Hcv8MqdleQZ79xxtyAH3pRkdLPnZjLsyIKkXnYHZN8T3vHMm2Zx4SVO0UIH/v6C9SetEw==
X-Gm-Message-State: AOJu0Yy0gaQNc3o7YFZGaa5w8DnQWr/Ys60j4kqITbR8c+kTcwB6+GEG
	zntDmC4Fy8uGDqKMZY0IMgVAgkAA0NEufzKgiodJrnNx0kkERH/l
X-Google-Smtp-Source: AGHT+IGrkfOOWyXlCSHMahc328NHeTLGXJfXteOqy8iYdmijcQMg3nCxtpkkxk/t2Upe2rWC68qM/Q==
X-Received: by 2002:a17:90a:e2cd:b0:2b1:88bb:20ed with SMTP id 98e67ed59e1d1-2b6ccd69770mr28353364a91.2.1716256629805;
        Mon, 20 May 2024 18:57:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:891:b0:2bd:619f:b53c with SMTP id
 98e67ed59e1d1-2bd619fb5d9ls1349339a91.0.-pod-prod-05-us; Mon, 20 May 2024
 18:57:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULhWDVTGMh/VYQyM3kOciU+yDsTLqyeSapPTqxt2S1kY6bYyatjmNaG2dhw2JSDXteAXg6SLNK0FqtTuaq4Ng2ra8rItOox/teJw==
X-Received: by 2002:a05:6a21:2d8b:b0:1af:f6b9:e3e4 with SMTP id adf61e73a8af0-1aff6b9e5e8mr27514349637.12.1716256628612;
        Mon, 20 May 2024 18:57:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716256628; cv=none;
        d=google.com; s=arc-20160816;
        b=Ovst4wHCiisOXMhUffwT3FNrvi3nf/dukJpzPG14cFZwcb2eb1cjHACWTDu5KD7AS2
         lW/NHwT8Xx5LcnHYMAGFH/czEcQ6D0z3iJg6TvLfix7RLHV6MmLSKz6SdaZ8i95wRMhr
         t1Cdxzr32W4QlEnUk6nch1biHPY1J2EmaM5FzfPzHsNPajrUao5JFuq16v1f8JrC+7KB
         ZI+/+Jq79K3OthhCKV9UizxQGBKplf5xUJCwPdcIVh6J2Ht32/aljcq9Cy2t4syhDrsM
         Mpo+RvBfKJQjFXWPnEwtwJpHmts9CLXein8aozyNoUec+ONOlIJlVkVRKw/Xe4H31Vwg
         d/BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4XOdonK61HwqB+JzHNixc4K1Fno2Zez9npZuAJiMxDY=;
        fh=X0q5N04R+VkpvgRsQviR8PPKDWLVCYCyBzWFdqL2AV0=;
        b=jDhrCtDcR6dLgXqYzG3gFTiFEmiJjNh3CGf485a9wo+vqYKoYVrxKPY/0YDc5dmj3p
         k1m+BHR/fZ0HDhGzKtpjFiT5CJP1RB8hCIepeU/0obuaUcQqIQg7hC+zcNujY2NHaSTd
         CHUYP1NwPWDENG9Zcug3UIkiKMZVE0KlE6H3oCF1BMFJrnGeoGKTS/uSONQWxNhm02TO
         N6KpJX2iCbntz9p44u7s6VSmU/PG5OSMEF1XuA2SqJWjGfxn71YKzXZpFiv4O8qz9uCW
         DEWP/KeaWzOLAbAAMW+ILKquFsRgQlr8ZwshQ0u0Jucy3XsBK6mSvXpYka29qxBtyyV8
         v28g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="LoQkg5E/";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f2fd4d5dc3si1699965ad.8.2024.05.20.18.57.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 May 2024 18:57:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: K8aulNXoTOej9eTvs2nJOA==
X-CSE-MsgGUID: mrlt2DGCThiXq/RTH0Facg==
X-IronPort-AV: E=McAfee;i="6600,9927,11078"; a="16209463"
X-IronPort-AV: E=Sophos;i="6.08,176,1712646000"; 
   d="scan'208";a="16209463"
Received: from fmviesa007.fm.intel.com ([10.60.135.147])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 May 2024 18:57:07 -0700
X-CSE-ConnectionGUID: gkEx2B0PQjme+xutkoXRBw==
X-CSE-MsgGUID: GreslKcMQbSzX9LpbAHzsg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,176,1712646000"; 
   d="scan'208";a="32636555"
Received: from unknown (HELO 108735ec233b) ([10.239.97.151])
  by fmviesa007.fm.intel.com with ESMTP; 20 May 2024 18:57:02 -0700
Received: from kbuild by 108735ec233b with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1s9Ek4-0005P2-1e;
	Tue, 21 May 2024 01:56:50 +0000
Date: Tue, 21 May 2024 09:56:26 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Tejun Heo <tj@kernel.org>, linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcov, usb: disable interrupts in
 kcov_remote_start_usb_softirq
Message-ID: <202405210906.RYSUrzQH-lkp@intel.com>
References: <20240520205856.162910-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240520205856.162910-1-andrey.konovalov@linux.dev>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="LoQkg5E/";       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted
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

Hi,

kernel test robot noticed the following build warnings:

[auto build test WARNING on usb/usb-testing]
[also build test WARNING on usb/usb-next usb/usb-linus westeri-thunderbolt/next linus/master v6.9 next-20240520]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kcov-usb-disable-interrupts-in-kcov_remote_start_usb_softirq/20240521-050030
base:   https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb.git usb-testing
patch link:    https://lore.kernel.org/r/20240520205856.162910-1-andrey.konovalov%40linux.dev
patch subject: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
config: s390-allnoconfig (https://download.01.org/0day-ci/archive/20240521/202405210906.RYSUrzQH-lkp@intel.com/config)
compiler: clang version 19.0.0git (https://github.com/llvm/llvm-project fa9b1be45088dce1e4b602d451f118128b94237b)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240521/202405210906.RYSUrzQH-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202405210906.RYSUrzQH-lkp@intel.com/

All warnings (new ones prefixed by >>):

   In file included from kernel/fork.c:30:
   In file included from include/linux/module.h:19:
   In file included from include/linux/elf.h:6:
   In file included from arch/s390/include/asm/elf.h:173:
   In file included from arch/s390/include/asm/mmu_context.h:11:
   In file included from arch/s390/include/asm/pgalloc.h:18:
   In file included from include/linux/mm.h:2210:
   include/linux/vmstat.h:522:36: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
     522 |         return node_stat_name(NR_LRU_BASE + lru) + 3; // skip "nr_"
         |                               ~~~~~~~~~~~ ^ ~~~
   In file included from kernel/fork.c:46:
   include/linux/mm_inline.h:47:41: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
      47 |         __mod_lruvec_state(lruvec, NR_LRU_BASE + lru, nr_pages);
         |                                    ~~~~~~~~~~~ ^ ~~~
   include/linux/mm_inline.h:49:22: warning: arithmetic between different enumeration types ('enum zone_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
      49 |                                 NR_ZONE_LRU_BASE + lru, nr_pages);
         |                                 ~~~~~~~~~~~~~~~~ ^ ~~~
   In file included from kernel/fork.c:79:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:547:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     547 |         val = __raw_readb(PCI_IOBASE + addr);
         |                           ~~~~~~~~~~ ^
   include/asm-generic/io.h:560:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     560 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:37:59: note: expanded from macro '__le16_to_cpu'
      37 | #define __le16_to_cpu(x) __swab16((__force __u16)(__le16)(x))
         |                                                           ^
   include/uapi/linux/swab.h:102:54: note: expanded from macro '__swab16'
     102 | #define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
         |                                                      ^
   In file included from kernel/fork.c:79:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:573:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     573 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:35:59: note: expanded from macro '__le32_to_cpu'
      35 | #define __le32_to_cpu(x) __swab32((__force __u32)(__le32)(x))
         |                                                           ^
   include/uapi/linux/swab.h:115:54: note: expanded from macro '__swab32'
     115 | #define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
         |                                                      ^
   In file included from kernel/fork.c:79:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:584:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     584 |         __raw_writeb(value, PCI_IOBASE + addr);
         |                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:594:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     594 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:604:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     604 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:692:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     692 |         readsb(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:700:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     700 |         readsw(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:708:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     708 |         readsl(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:717:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     717 |         writesb(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:726:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     726 |         writesw(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:735:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     735 |         writesl(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   In file included from kernel/fork.c:92:
>> include/linux/kcov.h:132:68: warning: non-void function does not return a value [-Wreturn-type]
     132 | static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
         |                                                                    ^
   16 warnings generated.
--
   In file included from kernel/exit.c:8:
   In file included from include/linux/mm.h:2210:
   include/linux/vmstat.h:522:36: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
     522 |         return node_stat_name(NR_LRU_BASE + lru) + 3; // skip "nr_"
         |                               ~~~~~~~~~~~ ^ ~~~
   In file included from kernel/exit.c:21:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:547:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     547 |         val = __raw_readb(PCI_IOBASE + addr);
         |                           ~~~~~~~~~~ ^
   include/asm-generic/io.h:560:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     560 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:37:59: note: expanded from macro '__le16_to_cpu'
      37 | #define __le16_to_cpu(x) __swab16((__force __u16)(__le16)(x))
         |                                                           ^
   include/uapi/linux/swab.h:102:54: note: expanded from macro '__swab16'
     102 | #define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
         |                                                      ^
   In file included from kernel/exit.c:21:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:573:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     573 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:35:59: note: expanded from macro '__le32_to_cpu'
      35 | #define __le32_to_cpu(x) __swab32((__force __u32)(__le32)(x))
         |                                                           ^
   include/uapi/linux/swab.h:115:54: note: expanded from macro '__swab32'
     115 | #define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
         |                                                      ^
   In file included from kernel/exit.c:21:
   In file included from include/linux/tty.h:11:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:584:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     584 |         __raw_writeb(value, PCI_IOBASE + addr);
         |                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:594:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     594 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:604:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     604 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:692:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     692 |         readsb(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:700:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     700 |         readsw(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:708:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     708 |         readsl(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:717:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     717 |         writesb(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:726:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     726 |         writesw(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:735:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     735 |         writesl(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   In file included from kernel/exit.c:62:
>> include/linux/kcov.h:132:68: warning: non-void function does not return a value [-Wreturn-type]
     132 | static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
         |                                                                    ^
   14 warnings generated.
--
   In file included from kernel/sched/core.c:9:
   In file included from include/linux/highmem.h:10:
   In file included from include/linux/mm.h:2210:
   include/linux/vmstat.h:522:36: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
     522 |         return node_stat_name(NR_LRU_BASE + lru) + 3; // skip "nr_"
         |                               ~~~~~~~~~~~ ^ ~~~
   In file included from kernel/sched/core.c:33:
   In file included from include/linux/sched/isolation.h:7:
   In file included from include/linux/tick.h:8:
   In file included from include/linux/clockchips.h:14:
   In file included from include/linux/clocksource.h:22:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:547:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     547 |         val = __raw_readb(PCI_IOBASE + addr);
         |                           ~~~~~~~~~~ ^
   include/asm-generic/io.h:560:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     560 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:37:59: note: expanded from macro '__le16_to_cpu'
      37 | #define __le16_to_cpu(x) __swab16((__force __u16)(__le16)(x))
         |                                                           ^
   include/uapi/linux/swab.h:102:54: note: expanded from macro '__swab16'
     102 | #define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
         |                                                      ^
   In file included from kernel/sched/core.c:33:
   In file included from include/linux/sched/isolation.h:7:
   In file included from include/linux/tick.h:8:
   In file included from include/linux/clockchips.h:14:
   In file included from include/linux/clocksource.h:22:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:573:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     573 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/big_endian.h:35:59: note: expanded from macro '__le32_to_cpu'
      35 | #define __le32_to_cpu(x) __swab32((__force __u32)(__le32)(x))
         |                                                           ^
   include/uapi/linux/swab.h:115:54: note: expanded from macro '__swab32'
     115 | #define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
         |                                                      ^
   In file included from kernel/sched/core.c:33:
   In file included from include/linux/sched/isolation.h:7:
   In file included from include/linux/tick.h:8:
   In file included from include/linux/clockchips.h:14:
   In file included from include/linux/clocksource.h:22:
   In file included from arch/s390/include/asm/io.h:78:
   include/asm-generic/io.h:584:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     584 |         __raw_writeb(value, PCI_IOBASE + addr);
         |                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:594:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     594 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:604:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     604 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:692:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     692 |         readsb(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:700:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     700 |         readsw(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:708:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     708 |         readsl(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:717:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     717 |         writesb(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:726:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     726 |         writesw(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:735:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     735 |         writesl(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   In file included from kernel/sched/core.c:48:
>> include/linux/kcov.h:132:68: warning: non-void function does not return a value [-Wreturn-type]
     132 | static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
         |                                                                    ^
   kernel/sched/core.c:6548:20: warning: unused function 'sched_core_cpu_deactivate' [-Wunused-function]
    6548 | static inline void sched_core_cpu_deactivate(unsigned int cpu) {}
         |                    ^~~~~~~~~~~~~~~~~~~~~~~~~
   15 warnings generated.


vim +132 include/linux/kcov.h

   119	
   120	static inline void kcov_task_init(struct task_struct *t) {}
   121	static inline void kcov_task_exit(struct task_struct *t) {}
   122	static inline void kcov_prepare_switch(struct task_struct *t) {}
   123	static inline void kcov_finish_switch(struct task_struct *t) {}
   124	static inline void kcov_remote_start(u64 handle) {}
   125	static inline void kcov_remote_stop(void) {}
   126	static inline u64 kcov_common_handle(void)
   127	{
   128		return 0;
   129	}
   130	static inline void kcov_remote_start_common(u64 id) {}
   131	static inline void kcov_remote_start_usb(u64 id) {}
 > 132	static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
   133	static inline void kcov_remote_stop_softirq(unsigned long flags) {}
   134	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202405210906.RYSUrzQH-lkp%40intel.com.

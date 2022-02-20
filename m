Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKEBZKIAMGQEV244HRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 018784BD07C
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Feb 2022 18:55:53 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id g17-20020adfa591000000b001da86c91c22sf6179729wrc.5
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Feb 2022 09:55:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645379752; cv=pass;
        d=google.com; s=arc-20160816;
        b=s2vYe5v5E0rqq5aD4Nt7WJWAmPu+IMJXuVl1zoHgk8CYCATT8d6+QB5nTWKcbsNTCi
         faSLgh1DoxibK+Sh3GnirzsUqNJ8DxMCEUVrATwU8GaLUf/6ESoKlMwoVPlt9D1Bti28
         z3ZRpGT7gDWxT8MHjGvVF6CqXZ7CcP4miHAg2L+H3jW6JuXXiEJksDBgGuzwvqRXKW8S
         pR5ZA8nrlgzqE+m4FBceJWWPQbbTj6RpxbBOHyKv+FI3MW4qbVy/HSC3G2dsxy5TDr4+
         x74Rx/H7MUsZVc5jHomCP4GcngLSFObvAc0QEdAx1GAQKNxYfI8sc1HftaQZRM8eRM2i
         uB/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=aQWW76krRrso8xhLaxsseVxofpnsK/IajN1FBAbQrmA=;
        b=Z3Fw9qBM24KE76EcaOij8P7GfP/HZRAv6E7uKrlTyiGzSTNQ7IphuSp0tX1UPBNWA3
         r9tbGU3DkWqjieXftZdunskYXEfj5PZUqFI994Fc9QdQDSCFgA/ymSSyhFKtH3tdUOgE
         M4ikpgWg/xHTJwCHbnLOlzVP9efZJnFcd/+kI2slA1oZfnmzyyKJ8wjch68Q5D79eGYx
         DMdNY1zDrxs0vz0PeBt278zmvt5SQ1tiVfdAfYZtlC3x7srFCerEuE1SJXM9deXxD5H/
         DP3syLsiouUgwqv330cnFLbRxzbYsx4ZGhZv24VjpmyZs8F8USozDEDo39u5PfhKv6B4
         zWIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SRJniCeY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aQWW76krRrso8xhLaxsseVxofpnsK/IajN1FBAbQrmA=;
        b=R6Dp4WsgG8eoiTbrSmLK4x6f4uPgr571U0lMKuPmjJn+XDl9bfKEOrs07VpFJUbS06
         IPgSMDjyOWZru8FIr0pywD2PVYiO7wQp74R21htR/TexL57UiNSehminHESmY1GJwSLF
         xfC5o/ARkC8rZCrP0Z5ifet38KKCSdL3tIPotvsmZkMV+/Acm3GvD4Z8BnYKJN65KVAc
         7QdgRGmL4r8SvLHi0P1ozF4N2+KFU1llf/lP4T8E6Wp3+hpXVtb4We8tScu3vI4N6O/T
         rSLhhXNQYnODpFnArWQVCazm+cLFBu8cRz+jpHy7E3EVTxz/YggL7hO6n8u7vQUIICYm
         Pe9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aQWW76krRrso8xhLaxsseVxofpnsK/IajN1FBAbQrmA=;
        b=6N1uczavMnGvEnCZwfBYRzl2fnyb0sby9SdMQD61LeKvMKvqpYXxv6F5mWeJccS7Rv
         axodQrDIJscU1OgoPsUYPuiXeT+ehq0hgJTo1KYXtiA6oWiJRRkTwpXHQfKT7VG7pSt0
         fmKkSfDvAkyDScVzPCj9kBq/Yup6sxirWdF8dngiaUqhkgw6PW8cNZa5741b6PKjWVEf
         EQ+Jk68+oEqf1Cv/mMZ3kFBr22+fGDeQ50LlmL1B+PudfdWpepqu3eIl2vFMJDEMEztI
         dx/Qe46eLa4ONtaIG/Htn+y6NMxlWNP6HFLirtR04W58iDAGTK24/16rEpLJ5VRlBJNO
         UhZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533K4dzS8y5+5MmSv/YXx9y874VsDL0QuZjG/rbc2JP1/vZG+9Vi
	MT3b3AoXTxlg8WIvSJ+Is4A=
X-Google-Smtp-Source: ABdhPJy1yfUbFJ1NTzLT57svhjhJti35u5b0yarCBH1PcRhBmzF9z+Dh/rSUSiuyQhkXNGiYH0gGFA==
X-Received: by 2002:a05:600c:2b82:b0:37b:fb77:aff with SMTP id j2-20020a05600c2b8200b0037bfb770affmr18797181wmc.152.1645379752588;
        Sun, 20 Feb 2022 09:55:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:17c3:b0:37c:5305:28db with SMTP id
 y3-20020a05600c17c300b0037c530528dbls8853028wmo.2.canary-gmail; Sun, 20 Feb
 2022 09:55:51 -0800 (PST)
X-Received: by 2002:a05:600c:1d28:b0:37c:a9d:d39f with SMTP id l40-20020a05600c1d2800b0037c0a9dd39fmr14960546wms.172.1645379751644;
        Sun, 20 Feb 2022 09:55:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645379751; cv=none;
        d=google.com; s=arc-20160816;
        b=gQtOZ3/oNeKytNK0+iuSiON7Rqn9K3xK+IZ8FNM+tnlFj00mCb+iBUW9x8li8gpClO
         cursnYFOUQwpNHDoEKvXfginunIN/Xt3asAs0okD2/VMsqqfpLFMmf4+jesZaA9q9Hx6
         +1A5CncMi3K0Gj70489fVgv/P/eysVG4wEDn4kKvNJPM8gvtZTqccIsiLVqRkekJzbOI
         qcY2woM0SwCF2mEUzsh5OY627AyRZMjriO+nCFHRIVOWEaObhWVT9XiktKnzER0GcU5b
         RMnkFxhTMp0JIV8pgE7hyE+Se1N4ujV0y9SYrdeNVK9KOsFz8H4RkHsdn/vjUdudNZdh
         qsKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KnxQX1cd9L11GGzGq7uJ41MkKMuIN8AaOa4y2Q1EhEc=;
        b=CGofB92tGe2/6AjbycreF2Q6hZTKxWP2ZDPNMi0Qu1sq9iTKnSXNQ12a//woFeJTWe
         CbpyfN354WV6I9j+p5PZOLpitAtbilUjIu6TCpmen3+txhtx1fzVXGFlb4fhG1g7Hl5J
         KQvX9cb9kQ3QCa7fP5bWSgXzakgbXBgOX6W/K/f+Er9tOhwXh9bre9dbn/8Qj+s19Fsy
         1g5V7XNd/VqDNayMHtF7DTojzfsjRJNhhRDs8zsTVlDbpJu9HwgLml87h36feif4BGOU
         bHBHKd/fPlfEupQipALZ0FXl1HW4O3lAtbc55mlMxGwhcUpDHy8wdn3ZRKvnwOTaLfty
         egWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SRJniCeY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id v13si1391993wro.0.2022.02.20.09.55.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Feb 2022 09:55:51 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6200,9189,10264"; a="248972264"
X-IronPort-AV: E=Sophos;i="5.88,383,1635231600"; 
   d="scan'208";a="248972264"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Feb 2022 09:55:49 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,383,1635231600"; 
   d="scan'208";a="636422461"
Received: from lkp-server01.sh.intel.com (HELO da3212ac2f54) ([10.239.97.150])
  by fmsmga002.fm.intel.com with ESMTP; 20 Feb 2022 09:55:45 -0800
Received: from kbuild by da3212ac2f54 with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nLqQz-0000Xm-5R; Sun, 20 Feb 2022 17:55:45 +0000
Date: Mon, 21 Feb 2022 01:55:40 +0800
From: kernel test robot <lkp@intel.com>
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org
Subject: Re: [PATCH -fixes 1/4] riscv: Fix is_linear_mapping with recent move
 of KASAN region
Message-ID: <202202210123.ilPycxXe-lkp@intel.com>
References: <20220218133513.1762929-2-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220218133513.1762929-2-alexandre.ghiti@canonical.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SRJniCeY;       spf=pass
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

Hi Alexandre,

Thank you for the patch! Yet something to improve:

[auto build test ERROR on linus/master]
[also build test ERROR on v5.17-rc4 next-20220217]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/Alexandre-Ghiti/Fixes-KASAN-and-other-along-the-way/20220220-181628
base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git 4f12b742eb2b3a850ac8be7dc4ed52976fc6cb0b
config: riscv-nommu_virt_defconfig (https://download.01.org/0day-ci/archive/20220221/202202210123.ilPycxXe-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project d271fc04d5b97b12e6b797c6067d3c96a8d7470e)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install riscv cross compiling tool for clang build
        # apt-get install binutils-riscv64-linux-gnu
        # https://github.com/0day-ci/linux/commit/de8a909a9eabf9066802a3396b7009cbf4fa4369
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review Alexandre-Ghiti/Fixes-KASAN-and-other-along-the-way/20220220-181628
        git checkout de8a909a9eabf9066802a3396b7009cbf4fa4369
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=riscv prepare

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from arch/riscv/kernel/asm-offsets.c:10:
>> include/linux/mm.h:837:22: error: use of undeclared identifier 'KERN_VIRT_SIZE'; did you mean 'KERN_VERSION'?
           struct page *page = virt_to_page(x);
                               ^
   arch/riscv/include/asm/page.h:165:42: note: expanded from macro 'virt_to_page'
   #define virt_to_page(vaddr)     (pfn_to_page(virt_to_pfn(vaddr)))
                                                ^
   arch/riscv/include/asm/page.h:162:41: note: expanded from macro 'virt_to_pfn'
   #define virt_to_pfn(vaddr)      (phys_to_pfn(__pa(vaddr)))
                                                ^
   arch/riscv/include/asm/page.h:156:18: note: expanded from macro '__pa'
   #define __pa(x)         __virt_to_phys((unsigned long)(x))
                           ^
   arch/riscv/include/asm/page.h:151:27: note: expanded from macro '__virt_to_phys'
   #define __virt_to_phys(x)       __va_to_pa_nodebug(x)
                                   ^
   arch/riscv/include/asm/page.h:143:2: note: expanded from macro '__va_to_pa_nodebug'
           is_linear_mapping(_x) ?                                                 \
           ^
   arch/riscv/include/asm/page.h:122:75: note: expanded from macro 'is_linear_mapping'
           ((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < PAGE_OFFSET + KERN_VIRT_SIZE))
                                                                                    ^
   include/uapi/linux/sysctl.h:88:2: note: 'KERN_VERSION' declared here
           KERN_VERSION=4,         /* string: compile time info */
           ^
   In file included from arch/riscv/kernel/asm-offsets.c:10:
   include/linux/mm.h:844:22: error: use of undeclared identifier 'KERN_VIRT_SIZE'; did you mean 'KERN_VERSION'?
           struct page *page = virt_to_page(x);
                               ^
   arch/riscv/include/asm/page.h:165:42: note: expanded from macro 'virt_to_page'
   #define virt_to_page(vaddr)     (pfn_to_page(virt_to_pfn(vaddr)))
                                                ^
   arch/riscv/include/asm/page.h:162:41: note: expanded from macro 'virt_to_pfn'
   #define virt_to_pfn(vaddr)      (phys_to_pfn(__pa(vaddr)))
                                                ^
   arch/riscv/include/asm/page.h:156:18: note: expanded from macro '__pa'
   #define __pa(x)         __virt_to_phys((unsigned long)(x))
                           ^
   arch/riscv/include/asm/page.h:151:27: note: expanded from macro '__virt_to_phys'
   #define __virt_to_phys(x)       __va_to_pa_nodebug(x)
                                   ^
   arch/riscv/include/asm/page.h:143:2: note: expanded from macro '__va_to_pa_nodebug'
           is_linear_mapping(_x) ?                                                 \
           ^
   arch/riscv/include/asm/page.h:122:75: note: expanded from macro 'is_linear_mapping'
           ((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < PAGE_OFFSET + KERN_VIRT_SIZE))
                                                                                    ^
   include/uapi/linux/sysctl.h:88:2: note: 'KERN_VERSION' declared here
           KERN_VERSION=4,         /* string: compile time info */
           ^
   2 errors generated.
   make[2]: *** [scripts/Makefile.build:121: arch/riscv/kernel/asm-offsets.s] Error 1
   make[2]: Target '__build' not remade because of errors.
   make[1]: *** [Makefile:1191: prepare0] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:219: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +837 include/linux/mm.h

70b50f94f1644e Andrea Arcangeli   2011-11-02  834  
b49af68ff9fc5d Christoph Lameter  2007-05-06  835  static inline struct page *virt_to_head_page(const void *x)
b49af68ff9fc5d Christoph Lameter  2007-05-06  836  {
b49af68ff9fc5d Christoph Lameter  2007-05-06 @837  	struct page *page = virt_to_page(x);
ccaafd7fd039ae Joonsoo Kim        2015-02-10  838  
1d798ca3f16437 Kirill A. Shutemov 2015-11-06  839  	return compound_head(page);
b49af68ff9fc5d Christoph Lameter  2007-05-06  840  }
b49af68ff9fc5d Christoph Lameter  2007-05-06  841  

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202210123.ilPycxXe-lkp%40intel.com.

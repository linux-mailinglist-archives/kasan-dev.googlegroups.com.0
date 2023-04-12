Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGHQ3OQQMGQEKN2HDLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 576436DFD7D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 20:27:37 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id i18-20020adfa512000000b002efac436771sf2370882wrb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 11:27:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681324057; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gt/e9MgU9x2pYlu8ZqWP9rk7bXLJbLA89J+tmQJP5ptLRp4980LKdYq3MD5fIC2m5E
         9IR2r0YdjFhOhMGNrSu1vIZ+0tjHpuYuXTROQ6MTIQusMOrfca7kuN3RcvXaABA212A7
         yyX4NUDZ7krh3e8S65BUM04+tAMAI++EQ+5w9xBpC2FKkMVr4EtWiaV2oyleinmldGGo
         zVxlEgWXi/EKQ9Taut4HIX57ovKpzUlVP0ZDn/jdwh59Mw9UR7d9s+ZmGlyqTjGq1EGu
         pfndHUbigByQ/kEaP8BQ6SQsgV23cVksiJPK3tHKL9inTSPKAJOJQkz3EdG6TMSXHa1C
         hgdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7Kw1uPY+lPcv08vVv5suva4ChzuaJ/UwrtOy0lBsKjk=;
        b=Bj8C1m6fFImiNn8yEeyBiCOgEsyzA0FZX3Nir3RED8X+QJCsZggCt1jsuY5lbQdi/Y
         QFjKMu4jkfCD5JJbquKVd6kR6xuyCJc9vsCHYdTg1ly5uUMDUgjXJIAI9iORcAmhpe/s
         ++8Wz1EbIhyH/ys/XGcOeYLa3nIzicVnW8x7EUFogPBuF8SJnWZHwYLCe9MKRDwJgfLz
         2pDQlUcCJvR92zpWnMbZH3YgYkj7Y39BfLq/w0oHh80hSWM1eMIXXUzmxN3AEihvQPKQ
         P9KZaNWY9TE6DaHlnqD6VOgSoK7Z7KmDK/70e8+/7aHfzmWBcPJ6hXM7zRl6nUMup5Vs
         +Vyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dQMyS6XJ;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681324057; x=1683916057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7Kw1uPY+lPcv08vVv5suva4ChzuaJ/UwrtOy0lBsKjk=;
        b=jN+z6FS9ufaTioofX8iMSURlJwq+i9WTZE1v3CWcfvSpKdLXqYHomKSw8mLjv2/BZU
         FZQ73//QlYS9sjm3zn/EjcKIkpv2sAq/rcCsHxUyhOYvUf42JyAXQz+JoqCqyfskJnq0
         aML1hi6TaN6nF2/d2rYBn6J+VwHQ+nbCJ7aiOA9WtnnkXVQixco3QnMBXcoSJQFkmUy5
         EsDh1YoJu8dDK+QYQNc64Tqz9HLVUQOyhfWxc3g50ath6RN2/fmmed9R2T6qFzlhBBMJ
         ry5gcw5lc3rw+WPGVJBTWRFDAIcwxgZHTUkikN+3AL1UtnLoApZ12HStmbecWOzy1ocI
         WD6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681324057; x=1683916057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7Kw1uPY+lPcv08vVv5suva4ChzuaJ/UwrtOy0lBsKjk=;
        b=cKEt26DGD3zlY8hDPRvH7hCIrXn23NQqDPPve0TK6yx6hEg1WT1g5DmXA8PdXBHsp6
         SKgJ8mUZsOWx5KzFyXA7FZxRO6F6HKCqrgXmDVwdOdNCp+Nd5/VPpj62zBIr1kmqQYAy
         9C2saID5mA7WjoeQYGbuVoi4DCaUVl2OmSJ17/xwH/n/nHAkPqVYhSuS69RNTExt9ka3
         sPizCQD3eqAmp+1PiFtb79OGTKpwwzUYfjSyJBL8+boRs6IwLcAXmIWxJBxkPYVH3C26
         p4sfmpbjrN4cS+7lzI92oW+4IxpuW5em52186vqPaACRNu1CPzeJeWt2Z5A0H/0wCV8t
         ZEhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dMmy9wJAc/qJMgU45gwCszPEldcZr9CyWusgTMb/3A/wDga2ay
	8RPrAvk1LwzbxBWDe/rBiRuhzg==
X-Google-Smtp-Source: AKy350YqgMbcpH4WrIyE50Eggc/LCOVcn3HhA3o+LMqYqJ55MUk12hD7iYg1C/fqxT686UyFRBhzmg==
X-Received: by 2002:adf:fe83:0:b0:2e8:b9bb:f96c with SMTP id l3-20020adffe83000000b002e8b9bbf96cmr823794wrr.0.1681324056591;
        Wed, 12 Apr 2023 11:27:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f11:b0:2c5:5262:2e24 with SMTP id
 bv17-20020a0560001f1100b002c552622e24ls3497216wrb.2.-pod-prod-gmail; Wed, 12
 Apr 2023 11:27:35 -0700 (PDT)
X-Received: by 2002:adf:e2c3:0:b0:2ef:b3db:60e6 with SMTP id d3-20020adfe2c3000000b002efb3db60e6mr13558910wrj.47.1681324055332;
        Wed, 12 Apr 2023 11:27:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681324055; cv=none;
        d=google.com; s=arc-20160816;
        b=RuzEnvne9X/lt6pZnPltM/5y9Mzma/l05lUw//Hs2aZ0djjJALCEJanJctu1fL61bX
         BPBIN0A609yjTBcE53oD2WgL7gF9dF7CjZAK0SBG7I4vLE0lNMVjeUQQEPD93alyepxg
         VCoi1RguM3NGeT3nIAlFcqV8aOHF6ZvYBjBxQ4Pt2P588dfLbqz0QiOAqYDxlUN1pqxQ
         +F2a/mMNYFrmBn74I/jwTbXmh+u1MuJoU6Exc4rKIRP/AFg/rQ+n2U83ujb3y2fI2/8U
         WiEcMNIpZJbhMC5Dh0aqt8EIFoZtkVc7QpAv73Sr332h884Y6ojbYwLFT+7OPoGDhWsy
         LIhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FEx2RXa7C9mlSDURKaFxHRP7K8xP2unWOpKXdi+pcVg=;
        b=Amtbxpc59L3MT1HNsz3Yp6tLj6cBCNb5sPdV26CV694VROatOp+aREjo4n2wfpEizy
         5AYgQsdxEQEW0b3WbW3Ms+7TBFPmi+zuy9A9JaVnrzV69mabSunSzTA6nD/YYSYQ1Yxa
         2EEqnAausOAi/ACw6vUCL+1G30me3isITMQvDAkOgqHsEpRQGwZjFuI4DKhOSaOxYstc
         q3UAHCAJXjzE23+sOAujrN4b3N2e5cUEq0aaYtN1lSC3j25FohJaEo5yJBoDGYuDdSK8
         ekDTaLhk0G60SXJieYd3t5+D+OnbbBN/yRfZm+IfB94hla2Abh+ZWFs5kdbM6nYs1Niv
         6YsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dQMyS6XJ;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id bx29-20020a5d5b1d000000b002ceac242c41si815939wrb.4.2023.04.12.11.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Apr 2023 11:27:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10678"; a="342738374"
X-IronPort-AV: E=Sophos;i="5.98,339,1673942400"; 
   d="scan'208";a="342738374"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Apr 2023 11:27:29 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10678"; a="778403203"
X-IronPort-AV: E=Sophos;i="5.98,339,1673942400"; 
   d="scan'208";a="778403203"
Received: from lkp-server01.sh.intel.com (HELO b613635ddfff) ([10.239.97.150])
  by FMSMGA003.fm.intel.com with ESMTP; 12 Apr 2023 11:27:26 -0700
Received: from kbuild by b613635ddfff with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1pmfBg-000Xyz-2T;
	Wed, 12 Apr 2023 18:27:20 +0000
Date: Thu, 13 Apr 2023 02:27:19 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, urezki@gmail.com,
	hch@infradead.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com,
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Subject: Re: [PATCH 1/2] mm: kmsan: handle alloc failures in
 kmsan_vmap_pages_range_noflush()
Message-ID: <202304130223.epEIvA1E-lkp@intel.com>
References: <20230412145300.3651840-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230412145300.3651840-1-glider@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dQMyS6XJ;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted
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

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Potapenko/mm-kmsan-handle-alloc-failures-in-kmsan_ioremap_page_range/20230412-225414
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20230412145300.3651840-1-glider%40google.com
patch subject: [PATCH 1/2] mm: kmsan: handle alloc failures in kmsan_vmap_pages_range_noflush()
config: i386-randconfig-a013 (https://download.01.org/0day-ci/archive/20230413/202304130223.epEIvA1E-lkp@intel.com/config)
compiler: clang version 14.0.6 (https://github.com/llvm/llvm-project f28c006a5895fc0e329fe15fead81e37457cb1d1)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/f8f0837563234abfae564b24278879d42d52a6e8
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Alexander-Potapenko/mm-kmsan-handle-alloc-failures-in-kmsan_ioremap_page_range/20230412-225414
        git checkout f8f0837563234abfae564b24278879d42d52a6e8
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=i386 olddefconfig
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=i386 prepare

If you fix the issue, kindly add following tag where applicable
| Reported-by: kernel test robot <lkp@intel.com>
| Link: https://lore.kernel.org/oe-kbuild-all/202304130223.epEIvA1E-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from arch/x86/kernel/asm-offsets.c:14:
   In file included from include/linux/suspend.h:5:
   In file included from include/linux/swap.h:9:
   In file included from include/linux/memcontrol.h:22:
   In file included from include/linux/writeback.h:13:
   In file included from include/linux/blk_types.h:10:
   In file included from include/linux/bvec.h:10:
   In file included from include/linux/highmem.h:9:
>> include/linux/kmsan.h:291:1: error: non-void function does not return a value [-Werror,-Wreturn-type]
   }
   ^
   1 error generated.
   make[2]: *** [scripts/Makefile.build:114: arch/x86/kernel/asm-offsets.s] Error 1
   make[2]: Target 'prepare' not remade because of errors.
   make[1]: *** [Makefile:1286: prepare0] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:226: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +291 include/linux/kmsan.h

68ef169a1dd20d Alexander Potapenko 2022-09-15  284  
f8f0837563234a Alexander Potapenko 2023-04-12  285  static inline int kmsan_vmap_pages_range_noflush(unsigned long start,
b073d7f8aee4eb Alexander Potapenko 2022-09-15  286  						 unsigned long end,
b073d7f8aee4eb Alexander Potapenko 2022-09-15  287  						 pgprot_t prot,
b073d7f8aee4eb Alexander Potapenko 2022-09-15  288  						 struct page **pages,
b073d7f8aee4eb Alexander Potapenko 2022-09-15  289  						 unsigned int page_shift)
b073d7f8aee4eb Alexander Potapenko 2022-09-15  290  {
b073d7f8aee4eb Alexander Potapenko 2022-09-15 @291  }
b073d7f8aee4eb Alexander Potapenko 2022-09-15  292  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202304130223.epEIvA1E-lkp%40intel.com.

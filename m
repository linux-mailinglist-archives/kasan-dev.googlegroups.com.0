Return-Path: <kasan-dev+bncBC4LXIPCY4NRBVEYUSJQMGQEMVSZHBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 706B4511446
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 11:26:45 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id bt27-20020a056512261b00b004720e026d4dsf510538lfb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 02:26:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651051605; cv=pass;
        d=google.com; s=arc-20160816;
        b=s2dhFycsop8YeHhrTbb94HJofGfNECJ4FneZsDtUBSjRCa51YwU57CoH9nw0th440d
         gjuFQE0biAC7N8p9gCloKRT87hjOhhy1Co9ONaLndfNAUwmujAC1/oOy0T+z/5Vt9ro+
         ZlcYk+cFfAcv4tpa7DBzCNJgHxUGgwlZxA90qBw+EIwPoBG2wDLzHU1yp3dueDzc/i5e
         myXUHfSApbXfd4PCLDrwDh+wXbCdIvkm/YEYBDum+y0AfUgP4hG1NyokpzbOkjEni/C4
         Pc3UB4VgJHBRWSOTVu2WnhNN8GNtDlc6EcX1CYc7L8KCSf6IdFxUF2tObysFs+1zspGJ
         H+hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iyr6Q57/JqRlMJsvGexqFyx8/H07K7Gt70l1xRaQkaY=;
        b=Vu6rqStWn7sz/wRH9Zzw+U+JzFu9wQ5uQd1OnfCCPrUnkOpcOacOjDMSoQ9aXHGBDX
         ZtB7UINp3h1E7kBgf9G51SMxmOA11oOOpvJTEVU0LIkvHPRG9sRBAlqjoq1MaMZ5nWhC
         Qd5f/i8UAHF/6LlGxCfgI7DTFSqWKT2hgD+Oy15guxJJLMQEEDrAegjpxkwSay47npeW
         3881lymZS4GZXiXDwbaAyfmfoURbMUz5kicrW+zbp4DRFQWU0JXE+iarTXcrqZxM1k4f
         us0LLE/dxZOuQ0YM6+8qt1mBVnG5byK3oR8we4dDDtgnpGnHODAd0ZHF/qExlcKSL0ew
         EhgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZGi9JkSd;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iyr6Q57/JqRlMJsvGexqFyx8/H07K7Gt70l1xRaQkaY=;
        b=b8pXB/Qhvigdk/AYaCUJMZ5KGL0bfG6GH1BYNvEdrICLXG0f0s89r8/nKBiX2S9DDc
         Gl9/VtVM26TbMxaIJeCbl7E6hQoVOlt5wS/GVlKHD+EqrxdtxGYxXE24wROdkGL514GJ
         9+u8tiiTGCLJoZ3iXJsCGWfwCZzIA6z7tM3T8yuWOWi8rlumVispobHh7tw/BLO8cHTi
         A+X8H7cfPAUpGlPdJSBpaLnY9wIDzk1pNqV84gOeiKh7VhLWhG8Dv5QntUYfJY50WYuV
         XxvbL8HQRtnx1H2MSdmAk/pPpIYCYa91nsL5qKTZm9+j26uLgTMuDVN0kRu2W4jzI76V
         LEnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iyr6Q57/JqRlMJsvGexqFyx8/H07K7Gt70l1xRaQkaY=;
        b=7Y0u2BfodMeP/pjatIMid27PzcG3jiiWpuJ58C8Sufw6dCDhS0ebH6Dzl15j0klZ2/
         mCjogWmIO7hINh2+K1UUJ3X/Et6OHSMzMPHIUTeHqIYY6tj5T0addVTS8J8FQYDLC/5/
         0ZOzwfAMSp5jIxxhEoGplkpQJALI7cmnM3L++J1mX04E8qKbe8ypQtC+NLX3FHWrC5LS
         qY0MZzCDoYOgkPXTG1ZWCotbNbTiNlIaCFzzc52rp0l8uTaksAQXa5lzsNwfJsuTIeUq
         4vlvyOzLnvlgDugKYgAc8An+XZg2FITZQg+XHo/vavWW05hYzwFfoiqYnFdCUHdFVxDt
         7S2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uEi34XrqrAtNEqhYYXF2C+711/ODcdM0BUtzkU9RQqYkrgVte
	MIy26i47zZfWxDhoPU32xyU=
X-Google-Smtp-Source: ABdhPJxRjvvtdaSTrIKWjFDg31Hk6LYNbE4OdT0ic6Nj/j86OJTZ9OhkDQkRhTPHSvxEP/M6Aw2cjQ==
X-Received: by 2002:a2e:7513:0:b0:24f:13ac:e5ef with SMTP id q19-20020a2e7513000000b0024f13ace5efmr8418381ljc.512.1651051604628;
        Wed, 27 Apr 2022 02:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211e:b0:24f:2648:9ef0 with SMTP id
 a30-20020a05651c211e00b0024f26489ef0ls536937ljq.4.gmail; Wed, 27 Apr 2022
 02:26:43 -0700 (PDT)
X-Received: by 2002:a2e:94c5:0:b0:24b:7029:75eb with SMTP id r5-20020a2e94c5000000b0024b702975ebmr17869300ljh.506.1651051603470;
        Wed, 27 Apr 2022 02:26:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651051603; cv=none;
        d=google.com; s=arc-20160816;
        b=uiSngdpX3S5uMh62mc7V7E5nHcuvMPavOPypfdwY5NA7WL0EH+EYmnWgJgxRkvy62D
         Fvg92FjpD7w0kF2ySdYhmc2PoNo8kXb9+e8Ny1RPEHBRza9pruLRLptMY4/4LRZ17Q5z
         8RSYBzmP6uzjtXDVifsGaHG3/3mPFMGatsHhtPjwhq71sLZTZeKkUX2dNaw2DtOcHqQS
         muyHqfM4b5b9DmPD3XaX8MR5FYGJg6A7cGQ0zTjkvCQNWdi8NtWRi2ZhSdDMS71Nn2gn
         Lc4+hpXvp+v7KNMOR82n/PVq8qGk6+3PPwgmT1CZgbMcJk3ALEqtQbXZH+VPQ7JhsPQR
         9exQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hIsjl/rkImLDMM3/KIy1wV63V6VYjP9ndrrbQFfEO+c=;
        b=YdnxFl5QOfyNu3YqTEG3TNU9xq9CoSYODLvKSUNlM2Rccu9S2lnT7rZRnqUfmt6cr1
         Ymam3U3JV4641NPN92sDPUuMT/a7qISiGAhrrKaKuuoN/9JONpM02sLpTXfPgdRTMStD
         PR1yXo/g4Gv4yh41LXPIjLlXucENlX7hO9eGhctMVOytPzIAtUrASsMPTgMmPV6j8u55
         QNupEUnaKDMxbfSccpb0X3axbAJwYHy4+qX73gWuWzKJcoH4HPIxrdLcoUrdKgQWHbe8
         uNGnzD+UP070E8Djp7CPW6M2SQR/Fepk/W0kSr0niTXyuAMKzUjzP0vICtckG6wh+EIj
         qiAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZGi9JkSd;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id i42-20020a0565123e2a00b004721a3e27cfsi46722lfv.12.2022.04.27.02.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 02:26:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="263463679"
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="263463679"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 02:26:40 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="539773405"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by orsmga002.jf.intel.com with ESMTP; 27 Apr 2022 02:26:35 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1njdwR-0004YO-1A;
	Wed, 27 Apr 2022 09:26:35 +0000
Date: Wed, 27 Apr 2022 17:25:47 +0800
From: kernel test robot <lkp@intel.com>
To: Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Peter Collingbourne <pcc@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v4 1/2] printk: stop including cache.h from printk.h
Message-ID: <202204271721.kgeFN450-lkp@intel.com>
References: <20220426203231.2107365-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220426203231.2107365-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZGi9JkSd;       spf=pass
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

Hi Peter,

Thank you for the patch! Yet something to improve:

[auto build test ERROR on vbabka-slab/for-next]
[also build test ERROR on arm64/for-next/core linus/master v5.18-rc4 next-20220427]
[cannot apply to dennis-percpu/for-next]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/printk-stop-including-cache-h-from-printk-h/20220427-043357
base:   git://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git for-next
config: csky-randconfig-r031-20220425 (https://download.01.org/0day-ci/archive/20220427/202204271721.kgeFN450-lkp@intel.com/config)
compiler: csky-linux-gcc (GCC) 11.3.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/edcb0f592304f7849a39586f9e3fe0d8f6e6c6b9
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/printk-stop-including-cache-h-from-printk-h/20220427-043357
        git checkout edcb0f592304f7849a39586f9e3fe0d8f6e6c6b9
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.3.0 make.cross W=1 O=build_dir ARCH=csky prepare

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from include/linux/compiler_types.h:73,
                    from <command-line>:
>> arch/csky/include/asm/processor.h:19:13: error: 'SMP_CACHE_BYTES' undeclared here (not in a function); did you mean 'L1_CACHE_BYTES'?
      19 | } __aligned(SMP_CACHE_BYTES);
         |             ^~~~~~~~~~~~~~~
   include/linux/compiler_attributes.h:33:68: note: in definition of macro '__aligned'
      33 | #define __aligned(x)                    __attribute__((__aligned__(x)))
         |                                                                    ^
   make[2]: *** [scripts/Makefile.build:120: arch/csky/kernel/asm-offsets.s] Error 1
   make[2]: Target '__build' not remade because of errors.
   make[1]: *** [Makefile:1194: prepare0] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:219: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +19 arch/csky/include/asm/processor.h

e9564df753fd547 Guo Ren 2018-09-05  16  
e9564df753fd547 Guo Ren 2018-09-05  17  struct cpuinfo_csky {
e9564df753fd547 Guo Ren 2018-09-05  18  	unsigned long asid_cache;
e9564df753fd547 Guo Ren 2018-09-05 @19  } __aligned(SMP_CACHE_BYTES);
e9564df753fd547 Guo Ren 2018-09-05  20  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204271721.kgeFN450-lkp%40intel.com.

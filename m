Return-Path: <kasan-dev+bncBC4LXIPCY4NRB5NC6GIQMGQECEMHPUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 730EF4E6221
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 12:09:42 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id u13-20020a50a40d000000b00419028f7f96sf2798241edb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 04:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648120182; cv=pass;
        d=google.com; s=arc-20160816;
        b=RgZOY6v9EIuxFoFupg8f69rQWDukG2a8YmwLeZdgwpacZgtVJz2FI1u5wsx7ej3jvT
         4EWEDKv7+RSz2CjCstqfpdGSwk5xj+lEo02XJh2UwKj05949w9ZxX1iLVE3GOeg6Mpuy
         iLdYYovdO07TuKfSY2nOTrLJozkr5R5PreXf4Li8he7mvgihIj1WSKc2S/VKG9XdSAOY
         VFhqxrJwdwxG9bUy+AjM1AjEUglBBCl2zHLPeW0EFA3/qs0H5/zU0TQ3BgwT6dXSYQjq
         Sde15ftcyz8vJizuXRnYvvq8r/DtDUUm7sEQer6ZL7mZZIOB4TaofMKJ4s+JopO1jT73
         rKKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5S7YUJicagr6gk8LiA9kTFB5Qnmpiar6lJKULvAV9vY=;
        b=CBq1PVA/RiNiyB1ST308fDhNpsQcBIFUM2zHupEQ68fUZeIqBMSmYFJp5DcvoeRNXw
         U16doYq3awWGV+G5Yb3vFhCh2vvzw/oPjvv8ZJMu0fK2vCji53s3IJspNRWKCn+nodk5
         9zDJ9dD03QxZ0WaW5eO2mPLuxZcoDAlNGk1Q9ZllOu365/IqLUInZyyfIDfy8ovE6NC7
         DXdw5vVlqAzbE+NX3PZXU9jF1N5QxubyZvn51ffO1E3/StLWqSS5t84DFFA0RM27+fqZ
         dH87Z+hhcqzSPOxmcJDlDJspqt/0C1Aknzahy0rqe8AKvnIj1JS60n0eVxFj10eZgG5p
         /PWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=OEVsu+pV;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5S7YUJicagr6gk8LiA9kTFB5Qnmpiar6lJKULvAV9vY=;
        b=PjpeegN3jmR7x0zs1JZmDFz6NSm2kCR/4sN4SoP50Xwz69n0/d2KMw4Uo3xII1acHw
         wjhXoSH/tEXLLDpL/ggUId1hltHgsVACVXv3+Bj/ImQ18AM32eBj1hQQMCBzWkn2vKNU
         PI3pMsoskV7xJE0W1/PAFxl4ekepiDkA79Hz4B3jKPJzwBr9ts3THydnRWgajBz18rqI
         1lHLT7/d3EbWKw2pJS5crb4KIshIwEghm7s/l/F9mtzL/C6Z4hrI5RsMP2NU+P384SoT
         /WIoQfSF8v4RR0cyxAK4oJ3UsISR2O0OFDN3czrCQJTalrTywJ+9r8EPGrYIAiiu82wM
         elhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5S7YUJicagr6gk8LiA9kTFB5Qnmpiar6lJKULvAV9vY=;
        b=Qjlt0nFXcje2Z2qbs97DxK08OyYNrgB9HjV0YwgMlaFaV3cT62hzxVAy+w9AaIENeQ
         6DiuiLaVbXGDd/D3DUPRAb4N+rzcUbyYqDltxzKRcCMmzd+YGbjMN6qufqTwRZ8Dtck5
         k6IbgUoggtDo0D+EH4SY3n9w2+5IJhxXcagMWvJGL7m9uTZUb+FNp4Il8WthMIeBBkGc
         BlXzC19dpRfwJmTduFJXTD2VFDTVkvOLWQxFzgNFYwMCEiKfo6Qx7Zp35+3PgLH2g17j
         xzI/RvXBNsL78JHe6tdIc80h0o6L7QDv+wGIwTPTXEEYIdh4oksDsugsWeJWIOtTnzwK
         KNoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533g7TJWVTjWiY3mms7TTvcY2l47V2XNlpRYEe4kyaodFUT0rd/V
	kRrUGTdJ1XDAVSAVpcLV86w=
X-Google-Smtp-Source: ABdhPJwvI/dya6ak8ree1aaoMIyPJYX9Tijumf/tWTaZKfdjoIY3Ykre9G/lPecTspew4HNWGVLtqw==
X-Received: by 2002:a17:907:8a06:b0:6df:e099:536 with SMTP id sc6-20020a1709078a0600b006dfe0990536mr5221598ejc.351.1648120182071;
        Thu, 24 Mar 2022 04:09:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d1cf:0:b0:403:768d:84b2 with SMTP id g15-20020aa7d1cf000000b00403768d84b2ls751900edp.1.gmail;
 Thu, 24 Mar 2022 04:09:41 -0700 (PDT)
X-Received: by 2002:a05:6402:cac:b0:410:a920:4e90 with SMTP id cn12-20020a0564020cac00b00410a9204e90mr6114137edb.60.1648120181177;
        Thu, 24 Mar 2022 04:09:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648120181; cv=none;
        d=google.com; s=arc-20160816;
        b=lUxHxIK2iyzAHYCTdqahNQmPHzxc1BuNOmFeHG5BKsngIsx3vTXNV9x1G7ghxOf1YH
         kjmYsqFkvCZ/4Wr8mnMIQ5KWYYBlr5rzMOzmy6Pk/jVDsxMobieNCwQTSLmob9Awuxfb
         Yd+AfpmIhGZEeBlANK7kvfQlxp/qZwflqEUS6B+QUhZT0kMvnQXP4hhGRwosms43oC6B
         Srhwq9HtnIaHX7gl6/mML4snjrOYoz44sIoCyTDkXopm7M4WjqNCdM7F5wrwa5FtQl8c
         /lg0CedxQZLOlk7FcF1Ukiv/KuIT73VFUWrijiWZlqXb59OS/hXJP6SLfi3YMkhWONDe
         noGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YFl0Hz6qym2gKKJl6sYcFfpgiRdcEeAv3yUIS7Yyxtw=;
        b=reA6JUXbAC/T5mw/A5xpFlfRgSqlGO/X5SW5rg83oX+cJXU8KTjTGs7orGM6up5ABP
         Ch1IyNRZjEeSQWwPYNioS6MuVL0bxW0fuPPlsYvaq9rlH+NKjiAinWYrzaIjZc+kjAyN
         vNsmjQg2PxwiTCQ5c5ll/XNW9t5xt+hMiZ2oOEZvV7ubk0Ic1SQdIO/lWlfjZLinT86h
         YyyEan2RAkumw4g60LcIHg7bmyardHfFIIB1tY6bUtGDvM6rP9h08p1pIlWw9DfkEgi4
         jmVsTLj3YZh545tGVY6/NzxIeiU+jf2JyifZKDsjSb/V5TzWmQ4FyC1+C0+p3b17GUdV
         dJYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=OEVsu+pV;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id b6-20020a50e386000000b00418ed4ebb86si143494edm.2.2022.03.24.04.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 24 Mar 2022 04:09:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6200,9189,10295"; a="283207276"
X-IronPort-AV: E=Sophos;i="5.90,207,1643702400"; 
   d="scan'208";a="283207276"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Mar 2022 04:09:39 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,207,1643702400"; 
   d="scan'208";a="584040294"
Received: from lkp-server02.sh.intel.com (HELO 89b41b6ae01c) ([10.239.97.151])
  by orsmga001.jf.intel.com with ESMTP; 24 Mar 2022 04:09:34 -0700
Received: from kbuild by 89b41b6ae01c with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nXLLR-000L0h-OF; Thu, 24 Mar 2022 11:09:33 +0000
Date: Thu, 24 Mar 2022 19:08:57 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Mark Rutland <mark.rutland@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/4] arm64, scs: save scs_sp values per-cpu when
 switching stacks
Message-ID: <202203241922.UDw4JHPD-lkp@intel.com>
References: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OEVsu+pV;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted
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

I love your patch! Yet something to improve:

[auto build test ERROR on next-20220323]
[also build test ERROR on v5.17]
[cannot apply to arm64/for-next/core hnaz-mm/master linus/master v5.17 v5.17-rc8 v5.17-rc7]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/andrey-konovalov-linux-dev/kasan-arm64-scs-stacktrace-collect-stack-traces-from-Shadow-Call-Stack/20220323-233436
base:    b61581ae229d8eb9f21f8753be3f4011f7692384
config: arm64-defconfig (https://download.01.org/0day-ci/archive/20220324/202203241922.UDw4JHPD-lkp@intel.com/config)
compiler: aarch64-linux-gcc (GCC) 11.2.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/da5bedb1ac7aa0b303f6d996d306e675860b6e12
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-arm64-scs-stacktrace-collect-stack-traces-from-Shadow-Call-Stack/20220323-233436
        git checkout da5bedb1ac7aa0b303f6d996d306e675860b6e12
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.2.0 make.cross O=build_dir ARCH=arm64 SHELL=/bin/bash

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from include/asm-generic/percpu.h:7,
                    from arch/arm64/include/asm/percpu.h:248,
                    from include/linux/irqflags.h:17,
                    from include/linux/spinlock.h:58,
                    from include/linux/irq.h:14,
                    from arch/arm64/kernel/irq.c:13:
   arch/arm64/kernel/irq.c: In function 'init_irq_scs':
>> arch/arm64/kernel/irq.c:44:25: error: 'irq_shadow_call_stack_ptr' undeclared (first use in this function)
      44 |                 per_cpu(irq_shadow_call_stack_ptr, cpu) =
         |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/percpu-defs.h:219:54: note: in definition of macro '__verify_pcpu_ptr'
     219 |         const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;    \
         |                                                      ^~~
   include/linux/percpu-defs.h:269:35: note: in expansion of macro 'per_cpu_ptr'
     269 | #define per_cpu(var, cpu)       (*per_cpu_ptr(&(var), cpu))
         |                                   ^~~~~~~~~~~
   arch/arm64/kernel/irq.c:44:17: note: in expansion of macro 'per_cpu'
      44 |                 per_cpu(irq_shadow_call_stack_ptr, cpu) =
         |                 ^~~~~~~
   arch/arm64/kernel/irq.c:44:25: note: each undeclared identifier is reported only once for each function it appears in
      44 |                 per_cpu(irq_shadow_call_stack_ptr, cpu) =
         |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/percpu-defs.h:219:54: note: in definition of macro '__verify_pcpu_ptr'
     219 |         const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;    \
         |                                                      ^~~
   include/linux/percpu-defs.h:269:35: note: in expansion of macro 'per_cpu_ptr'
     269 | #define per_cpu(var, cpu)       (*per_cpu_ptr(&(var), cpu))
         |                                   ^~~~~~~~~~~
   arch/arm64/kernel/irq.c:44:17: note: in expansion of macro 'per_cpu'
      44 |                 per_cpu(irq_shadow_call_stack_ptr, cpu) =
         |                 ^~~~~~~
   arch/arm64/kernel/irq.c: At top level:
   arch/arm64/kernel/irq.c:105:13: warning: no previous prototype for 'init_IRQ' [-Wmissing-prototypes]
     105 | void __init init_IRQ(void)
         |             ^~~~~~~~


vim +/irq_shadow_call_stack_ptr +44 arch/arm64/kernel/irq.c

ac20ffbb0279aa Sami Tolvanen 2020-11-30  35  
ac20ffbb0279aa Sami Tolvanen 2020-11-30  36  static void init_irq_scs(void)
ac20ffbb0279aa Sami Tolvanen 2020-11-30  37  {
ac20ffbb0279aa Sami Tolvanen 2020-11-30  38  	int cpu;
ac20ffbb0279aa Sami Tolvanen 2020-11-30  39  
ac20ffbb0279aa Sami Tolvanen 2020-11-30  40  	if (!IS_ENABLED(CONFIG_SHADOW_CALL_STACK))
ac20ffbb0279aa Sami Tolvanen 2020-11-30  41  		return;
ac20ffbb0279aa Sami Tolvanen 2020-11-30  42  
ac20ffbb0279aa Sami Tolvanen 2020-11-30  43  	for_each_possible_cpu(cpu)
ac20ffbb0279aa Sami Tolvanen 2020-11-30 @44  		per_cpu(irq_shadow_call_stack_ptr, cpu) =
ac20ffbb0279aa Sami Tolvanen 2020-11-30  45  			scs_alloc(cpu_to_node(cpu));
ac20ffbb0279aa Sami Tolvanen 2020-11-30  46  }
ac20ffbb0279aa Sami Tolvanen 2020-11-30  47  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202203241922.UDw4JHPD-lkp%40intel.com.

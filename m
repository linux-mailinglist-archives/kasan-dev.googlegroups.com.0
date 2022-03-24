Return-Path: <kasan-dev+bncBC4LXIPCY4NRBN6K6OIQMGQEQK5ZD2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6CE4E6A52
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 22:40:08 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id z16-20020a05600c0a1000b0038bebbd8548sf4499788wmp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 14:40:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648158007; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+zFiAY1SUb0geLzJq5GC9AeqVmS+raN8xb9Gp8637OW3JEutEf/B8oqhr6r13Hlgo
         l4pbyd/HJh/iktmaRdpNLdtS4O7m1uAwUVv/Lirx7DJjBjR7NBW5yU79dQESFndrVprd
         qOBrNaf9xvA2P9cNa4+3MLps0mGsqSRwqkMTLqEr1wvhKt/Lr1F/qdz8EBz1tgDnZKao
         BYELTopeqNdu8nN0wKqUYg/fWOnsU3Mp835ycYsF0jDiGo38knxFFP8HMhvTz4H5zxlq
         4fYJx7YvR4AOM5elngTCdj+M+PprHqi7JS+0FEBNELCc1bh0iQu9T051OadcOghoxM3L
         gMdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=K8nCJmdKMSlYWQI5RRRdOWFy1BM/q5tsoB8TA49CGF0=;
        b=0YEfZNRyEhTr6vL7aEG65uB3/RZlJbVgrk4LU1btjqRSSzHDOuhRLjMB8FJRhC8xTB
         BA7ls5CQ+UFnBNNkUwmMiK5pZtPE2xB6cwWkKclknDgFFziBWr4QAIzEsonLb719SvD9
         hMm2lSE6uIWK3VvOOF6olJ8RmAKEfc1r3MLqMikGKnxxwcrFKnapACw3GIn+iFmMG04h
         usAONGtbCjg0/IAdXiDc4MXapW3ZPcpkjq+//VyqJFACTQmsYr17v41nvm6xXbUdSVEG
         YRRK/039OkOZEvRHAgC3CUG4RDgCWqk0avx1GmqyJbb/hTa3oSD7I3DnlA/t2rRbIzT7
         T37w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=i8tD6rMD;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K8nCJmdKMSlYWQI5RRRdOWFy1BM/q5tsoB8TA49CGF0=;
        b=aKujBIZ8WBHYL/395liyUGOcrMCxvROTRgCm0xFzn82ALeHdXUj7mdL75NfN9Md/L4
         gCHEejuLKcO6VBFq3G81peJ/xAgNAZnj5dlefmbyPLTjS1BsenTITgKuQnmWXToq+vI1
         qxX1c8Ry51z1VdPzc5m1W6tUSmvwBvnYlgBGgwhYzhtX3C3jPsLsVi+J23NLZwEAN34f
         JdB9R3D42YxK/cihqULq9IYoiMs5vdN8CuNLsP2bLCeBKWekTuh/rhonCU5zsfAyYXB7
         LdPYUKwoYmTacMqpNOTout4mhix0zZSZN+ySQo5X0dSXgP2tLWq8qFTWlRrz7w+HL8pN
         eo8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=K8nCJmdKMSlYWQI5RRRdOWFy1BM/q5tsoB8TA49CGF0=;
        b=ebh1ZCGa7F+Bq3KFGbnk2bIkBEt31hfuooj5knaHbKu5GqCfPtr8XDBi+FX0o0t+2c
         k8Utk+1hlKSaujJS5nwORrLIiumHAOY526BCHMa9eNP9vNvLSrAVgmp8oFijma6aH7v8
         CFZvqedMYxHhB9Zd7z1CLCmO7D5R3EgGMhnDbpbhf6FOuR5Q0Qmy9DqG7uhvJEsWfuWX
         k/Jc9KJCd544feCSG6VM8i5JlQ/S5Cx5BfvdKpzMNnIsy421CNE4jO8qsd/LOc5RrRVo
         BiGkb6bEqFzjlJUzyHW5Irbeoy7dPx83el2iUhkBXs1WcleZgX60toCuWqHd/Rs5etzu
         K8YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533n8E6h0Isyi9PWkVos3a4B+Vmm7GjHgzMbY6q1Y5+xbKQyBAWc
	nt8oGaBl0zzj0hQEVXPbRHs=
X-Google-Smtp-Source: ABdhPJz5a/cJ0KWVWjvQmYMRS9y/PeR7sO3iOkooTA0G+K2L2dY3gxbNeHhqA16da3TGdT0TeX90lg==
X-Received: by 2002:a05:600c:1994:b0:38c:95b5:bbfa with SMTP id t20-20020a05600c199400b0038c95b5bbfamr16539267wmq.0.1648158007732;
        Thu, 24 Mar 2022 14:40:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64aa:0:b0:204:1c8a:51f9 with SMTP id m10-20020a5d64aa000000b002041c8a51f9ls32825wrp.2.gmail;
 Thu, 24 Mar 2022 14:40:06 -0700 (PDT)
X-Received: by 2002:adf:f24d:0:b0:203:ee8a:2160 with SMTP id b13-20020adff24d000000b00203ee8a2160mr5985904wrp.497.1648158006765;
        Thu, 24 Mar 2022 14:40:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648158006; cv=none;
        d=google.com; s=arc-20160816;
        b=Q7sjtY+a9gqvspfv8b5k2YzIB+yobFRl5IkOALNPzKQAIO2ONLVzYXM4Cn3EC92U0S
         Pub48FP/oPRC0AbOidxnOTdy6jkB2FSa49LiyfgPEcg68q33b0YFNGvHpQcNWQi8FVOM
         J2vRwzHqfTig9zWzE7TzP1oK+5QpdTVREuNcllyACaQZWMJ7j2uwi4U4cbo6is3J6BP4
         zymyd3gmzVoUGpDXff0vFuQvA7qbtdM30bwQIuT7bKHqfPZ/K06+Ur/XRT1FgIzXqIrF
         CqbWiyC/VrirT++5JVjSeqOTyug8cJfs3plabVp8imy+xob+TGG6+bMf9shohas+Za6t
         AJmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1YeiEDTNFqUXIa6v2bxIChPrdZw4ewQnO/vCQ4Aercg=;
        b=IMTZy/1WXT3OQgxQCB+Jivm6ihnHyaNbsRmoZoreD3X56ZgtRU75utv4KcK7uEn/Lh
         S9F1qqwJjFHT7DNQMfo0fi0K4DPsChacruZyWw5NlGUG1BWJ0PmsQUcpHBouQZbfXPBW
         nC43Lxa+5LoY0lnJ2xcNneYcHrcxPEB393omKMitBNLNAxLzMbMctGUPgVXHNStu1LQH
         7HS1cRn0YHIAIEnYPvOy3UsBtK86AeNQRUqFU1cK/cOA/iUWGlSrYm9dYhH0lXfn54rJ
         6In3L7iHz1NtbR6iEJgWbQ7QawowIUf1E9e9ZpM9AUsNYK2kA+x5q7PEBaeZQmIN1bOK
         4IqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=i8tD6rMD;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id c6-20020a056000184600b002040a29c341si219037wri.4.2022.03.24.14.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 24 Mar 2022 14:40:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6200,9189,10296"; a="258205730"
X-IronPort-AV: E=Sophos;i="5.90,208,1643702400"; 
   d="scan'208";a="258205730"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Mar 2022 14:40:04 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,208,1643702400"; 
   d="scan'208";a="650014103"
Received: from lkp-server02.sh.intel.com (HELO 89b41b6ae01c) ([10.239.97.151])
  by orsmga004.jf.intel.com with ESMTP; 24 Mar 2022 14:40:00 -0700
Received: from kbuild by 89b41b6ae01c with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nXVBX-000LT5-JQ; Thu, 24 Mar 2022 21:39:59 +0000
Date: Fri, 25 Mar 2022 05:39:41 +0800
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
Message-ID: <202203250512.yMAPu8rv-lkp@intel.com>
References: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=i8tD6rMD;       spf=pass
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
config: arm64-allyesconfig (https://download.01.org/0day-ci/archive/20220325/202203250512.yMAPu8rv-lkp@intel.com/config)
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

   arch/arm64/kernel/sdei.c: In function 'free_sdei_scs':
>> arch/arm64/kernel/sdei.c:124:33: error: 'sdei_shadow_call_stack_normal_ptr' undeclared (first use in this function)
     124 |                 _free_sdei_scs(&sdei_shadow_call_stack_normal_ptr, cpu);
         |                                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   arch/arm64/kernel/sdei.c:124:33: note: each undeclared identifier is reported only once for each function it appears in
>> arch/arm64/kernel/sdei.c:125:33: error: 'sdei_shadow_call_stack_critical_ptr' undeclared (first use in this function); did you mean 'sdei_stack_critical_ptr'?
     125 |                 _free_sdei_scs(&sdei_shadow_call_stack_critical_ptr, cpu);
         |                                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         |                                 sdei_stack_critical_ptr
   arch/arm64/kernel/sdei.c: In function 'init_sdei_scs':
   arch/arm64/kernel/sdei.c:150:39: error: 'sdei_shadow_call_stack_normal_ptr' undeclared (first use in this function)
     150 |                 err = _init_sdei_scs(&sdei_shadow_call_stack_normal_ptr, cpu);
         |                                       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   arch/arm64/kernel/sdei.c:153:39: error: 'sdei_shadow_call_stack_critical_ptr' undeclared (first use in this function); did you mean 'sdei_stack_critical_ptr'?
     153 |                 err = _init_sdei_scs(&sdei_shadow_call_stack_critical_ptr, cpu);
         |                                       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         |                                       sdei_stack_critical_ptr


vim +/sdei_shadow_call_stack_normal_ptr +124 arch/arm64/kernel/sdei.c

ac20ffbb0279aae Sami Tolvanen 2020-11-30  118  
ac20ffbb0279aae Sami Tolvanen 2020-11-30  119  static void free_sdei_scs(void)
ac20ffbb0279aae Sami Tolvanen 2020-11-30  120  {
ac20ffbb0279aae Sami Tolvanen 2020-11-30  121  	int cpu;
ac20ffbb0279aae Sami Tolvanen 2020-11-30  122  
ac20ffbb0279aae Sami Tolvanen 2020-11-30  123  	for_each_possible_cpu(cpu) {
ac20ffbb0279aae Sami Tolvanen 2020-11-30 @124  		_free_sdei_scs(&sdei_shadow_call_stack_normal_ptr, cpu);
ac20ffbb0279aae Sami Tolvanen 2020-11-30 @125  		_free_sdei_scs(&sdei_shadow_call_stack_critical_ptr, cpu);
ac20ffbb0279aae Sami Tolvanen 2020-11-30  126  	}
ac20ffbb0279aae Sami Tolvanen 2020-11-30  127  }
ac20ffbb0279aae Sami Tolvanen 2020-11-30  128  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202203250512.yMAPu8rv-lkp%40intel.com.

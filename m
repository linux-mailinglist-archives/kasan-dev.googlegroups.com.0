Return-Path: <kasan-dev+bncBC4LXIPCY4NRBCG36CIQMGQEEY3SNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 0215B4E606F
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 09:36:25 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id r18-20020a17090609d200b006a6e943d09esf2060022eje.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 01:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648110984; cv=pass;
        d=google.com; s=arc-20160816;
        b=hRYz23/rK6WR0IdzF3P71QiGUnwvcUnfVq80Blixy2eZK4GNKh3uXgF7BW15MCVRgG
         hEUFP+/mqFCThiKJjNu5dpPV64CRVJVBItNMjsoPcQsS9YAVBaliAo54bypxHwjbApDO
         z6so3a9fuW6/J9qF+jM9Wlh1rrolN+Y0pt5/ZNrUbg5F8YAAZ79iTqbWli4Arn1c4pyH
         +Td7e8FR14DQOKVjDKsOWs77adH4ABEFbp8MbgzeIpuE2gDFiUBje9rw/YFU3kkpaGRF
         L5MFubaLD5rlMz+dBB7cwz7G358FsC+Qcm4PJqPY+6wfjzAchvXjS00ZNoeqdv3F7hc0
         iSQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2oB4aco2Icht8te6DFH7Op7XuSozgV/9/7RFRDFCb7I=;
        b=a+U9uJxMMLWrb6qYxBmcEQ7/qam3tNSP+Byb4mF/6NS4djUZycanf/bRTEk29A2kay
         Cix68tQOU5Cgbmpm0fPhPHe45S1KdqoK6qdGd9ff2Yv4uGRA9vLBIWhpMwFlvWgRNTMh
         1319xQOss6MBgEa3gHqaPBHOCo2p/ZS4PabNyvdjl8YycKymtGqMZz7btL2sCFM8hZgw
         4FB0u2ynYeBWLcCS3aYgayuqWYB7s+zcx5mHmSzNt9uDv29w5wq7vknwKA82xbkaWA+k
         CnhcVa+YU0jHLLvLFiHA7SWq1Xaz+sW075PQFoXgq6OXk3l1/VovcQDrC/Jqi8zPkfYk
         fVSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=czJ1GBmQ;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2oB4aco2Icht8te6DFH7Op7XuSozgV/9/7RFRDFCb7I=;
        b=eW0T/YWBf/OUHkQyMHYrVOTOXMNrXkmlF9VvTQKb2nUjYDRsc/0bEDKzz1IUgRrB/R
         7YALbylE3akZaFNAn5XCJdT+9QMgl55RAlUZVCIoIIlOpXN+fAidDA63pY+j0ZOLpIMv
         IJHrYkNFmvvFm3/vXz0dHIE6vxScOXBjRjBsYNe4aUUSLLVEAj1m461mkADa32DODzWV
         WQwXpoYaX60Ag27ugVxpDsg8f0mySFq3QiCbz9C12XsXN/loh46+VRDdYQ9uftnEojVJ
         dGt9SZ0lM0b0L5JKxX6GkXZi4uzn22BC4tZygF2IVonu5Wqf3KiX14PAFNrOoBqJAG2C
         nDpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2oB4aco2Icht8te6DFH7Op7XuSozgV/9/7RFRDFCb7I=;
        b=F88JmWyUKfsGId3p0wax1lOo9OnQy0NXCPQxyQNYVwfFRBVBvtzuB5Qe+4MEjbAD3g
         gUzwZ6+KDDpT+1jhQ432idXRo+An2XDwjyzKmTuJ32RPXb3y9WBD77leTigfu6gcPBIS
         3kN/Myhh5vAmb+/dMgKHQJUBf1bDtONoEvNCQ0LAf7FseREIvFzfC83a1s0VXyPoMtfm
         cYHQ2duq4845QNVn5w4XHY1sLqPmp8stcMuQhZ0fGnEW5rcPDlgh5c1pTw/D+BFJtsic
         LXX1Q4dPufn4/0rpYj2KXwUnsR3/xdRY7rNl14SenAn/y9tOBEhkfhNwKhQSDw46dWMz
         Y89A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533y6OXzHbIiAbZI9/TXcGSiv10Af5lJa4YxWq65gbc+7asj3mdm
	Dc808RqMIAuujt4FgptCF+A=
X-Google-Smtp-Source: ABdhPJx7mK7a6DK6QLEQI/mY70OLwgdj3WGqrQWr2Q54BAHzRkMHVlLGDZZu1dN/W8yf6eHDRoT2YA==
X-Received: by 2002:a17:906:7304:b0:6e0:6918:ef6f with SMTP id di4-20020a170906730400b006e06918ef6fmr4444918ejc.370.1648110984493;
        Thu, 24 Mar 2022 01:36:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7b99:b0:6e0:2e3b:95cd with SMTP id
 ne25-20020a1709077b9900b006e02e3b95cdls519629ejc.11.gmail; Thu, 24 Mar 2022
 01:36:23 -0700 (PDT)
X-Received: by 2002:a17:906:b1d0:b0:6cd:fa02:b427 with SMTP id bv16-20020a170906b1d000b006cdfa02b427mr4423013ejb.99.1648110983499;
        Thu, 24 Mar 2022 01:36:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648110983; cv=none;
        d=google.com; s=arc-20160816;
        b=J4fDZiUBNMn36Dxu8h36n6V6b/cnvtyb+cG9lfBRRBm9EIPAchYkZZRQu15fyAqxiV
         9lRWh7EdGh6ttnSlpkyzPmy3HX9R+hwh0IWqsGozzSAz17+PTS1gCZNeMbaHfFViQ0A/
         D8PrDpnYLlJeJBtNDg5WdYUuSPKhyeBzz8XQAPalBfhOGdBHoNvWBOSinNElPYZgnJsw
         FnnZthEDbY1NQr35ojB3EblxIwCt9ujThPglTc4wPphW6Z8KkdMmqXlgfHzF+WYwLaeP
         RAaWnn34Iaoa+YaWEjfvTokwCmJRkCirF89Rlnhraz1ZNc5DuqR9P5jAyl5HUZtAdauN
         7JOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/zWMY6HYC/XgmFESg8bwwM43d5rLHP5RwYF+eVjQnN0=;
        b=ToCqMWWCJIeDFqY6lQe+k8kQ/dviDdJSHk1w/zBUQgGwMlap+gkTUFyaOyhv7bBPED
         EyvUfmeJwtWKCHKa3DOrYWmXmQbwFeQrEOs/pkJg8X1iXKT0fjDY1isZgiaWF0965C0k
         wQE4qOrk2UDNM+VP6II7N6bY7DNkHffIshl78ujTbimSSbquHCzv/UJPtrvxZZTcXJby
         ElEUbUSxCFivmXP7EP9B2QrKi/uG/D7sG68uDhZ6+hEX9Z98kBOrMqixocjIcSltoyCH
         suocL779ScDyM62R+LGWcPW3+cOWxGO8WgOPdt4yICAmr6XGqEKP+y3LsaGEze140/C3
         bgEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=czJ1GBmQ;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id w1-20020a17090633c100b006d0a73e6736si101851eja.1.2022.03.24.01.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 24 Mar 2022 01:36:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6200,9189,10295"; a="319029491"
X-IronPort-AV: E=Sophos;i="5.90,206,1643702400"; 
   d="scan'208";a="319029491"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Mar 2022 01:36:21 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,206,1643702400"; 
   d="scan'208";a="516089850"
Received: from lkp-server02.sh.intel.com (HELO 89b41b6ae01c) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 24 Mar 2022 01:36:17 -0700
Received: from kbuild by 89b41b6ae01c with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nXIx6-000KsI-9F; Thu, 24 Mar 2022 08:36:16 +0000
Date: Thu, 24 Mar 2022 16:35:40 +0800
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
Subject: Re: [PATCH v2 3/4] arm64: implement stack_trace_save_shadow
Message-ID: <202203241622.fKuBI2l5-lkp@intel.com>
References: <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=czJ1GBmQ;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted
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

I love your patch! Perhaps something to improve:

[auto build test WARNING on next-20220323]
[cannot apply to arm64/for-next/core hnaz-mm/master linus/master v5.17 v5.17-rc8 v5.17-rc7 v5.17]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/andrey-konovalov-linux-dev/kasan-arm64-scs-stacktrace-collect-stack-traces-from-Shadow-Call-Stack/20220323-233436
base:    b61581ae229d8eb9f21f8753be3f4011f7692384
config: arm64-defconfig (https://download.01.org/0day-ci/archive/20220324/202203241622.fKuBI2l5-lkp@intel.com/config)
compiler: aarch64-linux-gcc (GCC) 11.2.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/322e934f3c0bb04b4afb32207ba142153f1dd84e
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-arm64-scs-stacktrace-collect-stack-traces-from-Shadow-Call-Stack/20220323-233436
        git checkout 322e934f3c0bb04b4afb32207ba142153f1dd84e
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.2.0 make.cross O=build_dir ARCH=arm64 SHELL=/bin/bash arch/arm64/kernel/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   arch/arm64/kernel/stacktrace.c: In function 'arch_stack_walk_shadow':
   arch/arm64/kernel/stacktrace.c:289:20: error: implicit declaration of function 'task_scs'; did you mean 'task_lock'? [-Werror=implicit-function-declaration]
     289 |         scs_base = task_scs(current);
         |                    ^~~~~~~~
         |                    task_lock
>> arch/arm64/kernel/stacktrace.c:289:18: warning: assignment to 'long unsigned int *' from 'int' makes pointer from integer without a cast [-Wint-conversion]
     289 |         scs_base = task_scs(current);
         |                  ^
   cc1: some warnings being treated as errors


vim +289 arch/arm64/kernel/stacktrace.c

   260	
   261	noinline notrace int arch_stack_walk_shadow(unsigned long *store,
   262						    unsigned int size,
   263						    unsigned int skipnr)
   264	{
   265		unsigned long *scs_top, *scs_base, *scs_next;
   266		unsigned int len = 0, part;
   267	
   268		preempt_disable();
   269	
   270		/* Get the SCS pointer. */
   271		asm volatile("mov %0, x18" : "=&r" (scs_top));
   272	
   273		/* The top SCS slot is empty. */
   274		scs_top -= 1;
   275	
   276		/* Handle SDEI and hardirq frames. */
   277		for (part = 0; part < ARRAY_SIZE(scs_parts); part++) {
   278			scs_next = *this_cpu_ptr(scs_parts[part].saved);
   279			if (scs_next) {
   280				scs_base = *this_cpu_ptr(scs_parts[part].base);
   281				if (walk_shadow_stack_part(scs_top, scs_base, store,
   282							   size, &skipnr, &len))
   283					goto out;
   284				scs_top = scs_next;
   285			}
   286		}
   287	
   288		/* Handle task and softirq frames. */
 > 289		scs_base = task_scs(current);

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202203241622.fKuBI2l5-lkp%40intel.com.

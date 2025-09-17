Return-Path: <kasan-dev+bncBC4LXIPCY4NRB6MCVHDAMGQEK6NJ54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 88116B7CAC1
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:07:55 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-57363fa0e80sf2292368e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:07:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110875; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kc588FgmeOjMo9DCxqI2f+fH4AJO/Gjz14rAP3Jr9D0Usd47dbiio3XT6/HfbVcLr4
         jKGmgvDCRU80vRM8znCoor/SNV8jQMb6kJQ3EUd2Gvm0ZVEoWuFrBvYDijYFiCbx0eDP
         BO/hWpicSG5r8t5LI2Zc4sYk8NgwApsvQDh1cfd72PyS5VO0ns3zf8KMT/LHSrSevJJL
         irGNqvJXADqr3yR3LkmWlnMPrKr0bEZ7TPivbHaZiGQQOeFNL0U78yFh93TgjUwAvX4F
         bqvSl2pXxTTM0goUvG6BajFnTs4IYrVNYyr15sEBJMROTpUJnUPR6r2QMFqPkAHw+la1
         jyHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0Ln9sR+XyPg8KJxP6pKi4LoJv/an1cclhgAc0JVKl6M=;
        fh=iJAgE0WGaWdTgaW7XKT2TJzUa/21DTThAY4q9FbbBeE=;
        b=IbfCjn64iOo7s2liu2wbrnA/r9q18xSpqjaOZov0zlXKE39D94ClWlz3dgBU1V+F2c
         DJBtpnwS5VZTmGWKTKU/GbjSllwYEJc11OuYMVoeTa0sH/8YVoJZGEg01Qi9ZEfCgshz
         mLIOi+s6SC3245icjK8wE9GeO2rHf71gUnd+0D41bgGpGHkd2bun0QTavs9W/fDHTUCg
         M5xHQvlHGPKDsSluhoZp2xlqNO1OczO27w2SIyu/5O3+bkqR6MDwvyjzryL5z+lxHYRy
         tXB/0WwzGF+DXfdXsyJ7cTzQO44WRs1B8r3MrW/uDEdxCvfMW6LK3SBKYANcosWyiR4I
         eMSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cYLl7O5r;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110875; x=1758715675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0Ln9sR+XyPg8KJxP6pKi4LoJv/an1cclhgAc0JVKl6M=;
        b=eEiAnj1oiKMrxHYa/rGpe56W8K/hVGfT0KNajNKpV/IAz/0XzUbIF0fPP178CAee3O
         VCdem6uicaP7zi7MgNXP7nwpjqNCLUWloIMpqsC2VkMiXvym2AFl71w+co/lgBuvs8O/
         zhudpSf65anF0TVPSAQTP/nPpV9kuAMnrPgmsT5ZBDzO1+3b6E71AYHCdx/R3DIjRugE
         egDS2GoHsvERBkUn1XAb0Iat3b8oh0KOZtV+rY5bBSWhyr4AtGiTXVImd1jgOK0eLezW
         pUGT/2oKt/cTOjV2SWWmnL37HUpzS5CBVOi159whMbF8bm64t8cPGfpclcQWpf+yX7Nl
         XaGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110875; x=1758715675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0Ln9sR+XyPg8KJxP6pKi4LoJv/an1cclhgAc0JVKl6M=;
        b=Z3PYVFa1SpHQU6uE3H1uyTxhvph/AHJQXodUwFEjw3FSxysvHvBdn8er8/8nyrs+dt
         wv/KTa0ZkEKn7HorT4rCcnyAOrE5x5suad+5DB9qYslLv5ek5o0f4rGJ97ckv2kAutuk
         QKJGlE60G9ApT6WzKBOJcPoM1hsyWWQIZLuJJJAZCB1MDlkQMpzbf9kp5XLU3NOxm76q
         DQYL9L0wIYgbG0gIkr68isJnXy7erZDETC7evS4mNMKmaMJY4uW1mC4ffd86K0BMgYHc
         pYCuuwa73YNCAdY8QJqW9Ng0Wp7ATjIU6MUia5Uo+gZOCKvHiOasoBYtITYs02OEmqrg
         czRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0tHlS8kHBOWxXpa9KMzagKAt/dlkmQW+eZit74TsMkCMAecQMcKtfOTTThcC58tg5NsR/ug==@lfdr.de
X-Gm-Message-State: AOJu0Yzuyi6F9QX6+jFbDHcBOyR+IeJgyd7JV+1DddmaQLEtFRhuJS6o
	9vi7Y/FH9uSVNC3cEiLAYOSMkZ/qnEKUhrCAoAds13bZFNctPZvPPipc
X-Google-Smtp-Source: AGHT+IGXWg1ZbMVB6iH/qdZ0o+pOb4SKEdB6/Wzy/oQJcpkLy/XJcOxAy6qTSZEUhMoGsQQBbx+I3A==
X-Received: by 2002:a05:600c:1f89:b0:45b:88d6:8ddb with SMTP id 5b1f17b1804b1-462074c6780mr5329695e9.37.1758085497834;
        Tue, 16 Sep 2025 22:04:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7oGMVgjFfbhc+t54VOqB4C05tXuSuRs/1f8lFzZVquFw==
Received: by 2002:a05:600c:674f:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-45dffc18bb5ls32824695e9.2.-pod-prod-05-eu; Tue, 16 Sep 2025
 22:04:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXoTqfbBhgqmA+SsRX+PzJ5338/9Qo9AI0ZuY4B5dT3gxlak/1yh4JW7ECMPr45eImoWMbd19uV/Q=@googlegroups.com
X-Received: by 2002:a05:600c:450b:b0:45b:5f3d:aa3d with SMTP id 5b1f17b1804b1-46205eb1681mr4784275e9.21.1758085495082;
        Tue, 16 Sep 2025 22:04:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758085495; cv=none;
        d=google.com; s=arc-20240605;
        b=VQh/Z8EJWeA7mdHls5B4V7qnVgtXcLlRP4FnwmoYJzPO7GDBA9UkLIblVYjLtiygnd
         RRTDjaIgNECaCraoSJlPk/nYyHu2sslyEkDS5nAmXHyFpcrlQ6WU1EUnYdTfuTyalXaf
         ALMv3y34PeEbIfDqj1zttB5c01VVCQKFzkaUnk0geaef7DrcKW+APkAUBqJmtrvD0EhK
         fwsJr8GBS/6eu+LlxQ4WhlMbntxhB4gKHfMtChabwiqUW0/wUZQ+wzjKUgi3Usi8xwaN
         1Mn2bntk//BwmFu+YZYVP+LBPD+oB47ZqWZhZjSFuoVldVgpk4wAt6qM3ByCsDkzm1NQ
         PLvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XZEz55vnKWns6VDkaWcQmypGBYAaCR3xPOFfGClLlqU=;
        fh=lYa0FG45bwqSJAg0l7nL5e2519l1C90YKv5AyQwXbVo=;
        b=QoFQJD99FHqQmAy3n9qxyo+JLWBAbaM6TCDrIdTT2L7uiZMwmpPsM46Ky+pp3CDpVs
         5+/Ex+LH9C8EHrvyt+NrXKwAL7hnpv+MQnxOCHPzj0T+Stq+28YVPZ6Krh0d8Xl0St0M
         7EWGwBwmVc4qJpBIoV+e4LgTa0bSq+Am4aeKPFdDuHC1twswdnQT9WQNH3S7/y200Hn7
         FhI5V7FdHo2qOl2+ksgwvP/vGWgLQOETrbXnQXQpbtRI0Tv0H7zGEQMxG8qQ86oMdFHi
         ZOl9g5mfFjJPAeBjqgpxFdPvbgvvSGTTVudHF7SaVFqSv+dTKzhKdjFXpqhxjdWnnMz+
         vJGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cYLl7O5r;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f32522420si1148915e9.1.2025.09.16.22.04.54
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 16 Sep 2025 22:04:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: de+3LsLLSGGVxf5OxxZ84A==
X-CSE-MsgGUID: 35IFwWJRQkKN08X7b2Nhvg==
X-IronPort-AV: E=McAfee;i="6800,10657,11555"; a="71484281"
X-IronPort-AV: E=Sophos;i="6.18,271,1751266800"; 
   d="scan'208";a="71484281"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Sep 2025 22:04:53 -0700
X-CSE-ConnectionGUID: sB/NHNXdQIqoO2ykPrcXBg==
X-CSE-MsgGUID: Jad/lXalRXmHa4vZHqcc7g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,271,1751266800"; 
   d="scan'208";a="175224112"
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by orviesa008.jf.intel.com with ESMTP; 16 Sep 2025 22:04:46 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uykLT-00015t-1z;
	Wed, 17 Sep 2025 05:04:43 +0000
Date: Wed, 17 Sep 2025 13:04:11 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com,
	glider@google.com
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com, elver@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com
Subject: Re: [PATCH v1 09/10] fs/binfmt_script: add KFuzzTest target for
 load_script
Message-ID: <202509171240.sw10iAf6-lkp@intel.com>
References: <20250916090109.91132-10-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-10-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cYLl7O5r;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted
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

Hi Ethan,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-nonmm-unstable]
[also build test WARNING on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.17-rc6 next-20250916]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20250916-210448
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20250916090109.91132-10-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 09/10] fs/binfmt_script: add KFuzzTest target for load_script
config: i386-randconfig-013-20250917 (https://download.01.org/0day-ci/archive/20250917/202509171240.sw10iAf6-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250917/202509171240.sw10iAf6-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509171240.sw10iAf6-lkp@intel.com/

All warnings (new ones prefixed by >>):

   In file included from fs/binfmt_script.c:166:
   In file included from fs/tests/binfmt_script_kfuzz.c:8:
>> include/linux/kfuzztest.h:135:3: warning: format specifies type 'unsigned long' but the argument has type 'int' [-Wformat]
     134 |         pr_info("reloc_table: { num_entries = %u, padding = %u } @ offset 0x%lx", rt->num_entries, rt->padding_size,
         |                                                                             ~~~
         |                                                                             %x
     135 |                 (char *)rt - (char *)regions);
         |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/printk.h:585:34: note: expanded from macro 'pr_info'
     585 |         printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
         |                                 ~~~     ^~~~~~~~~~~
   include/linux/printk.h:512:60: note: expanded from macro 'printk'
     512 | #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
         |                                                     ~~~    ^~~~~~~~~~~
   include/linux/printk.h:484:19: note: expanded from macro 'printk_index_wrap'
     484 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
         |                         ~~~~    ^~~~~~~~~~~
   In file included from fs/binfmt_script.c:166:
   In file included from fs/tests/binfmt_script_kfuzz.c:8:
   include/linux/kfuzztest.h:141:37: warning: format specifies type 'unsigned long' but the argument has type 'int' [-Wformat]
     141 |         pr_info("payload: [0x%lx, 0x%lx)", (char *)payload_start - (char *)regions,
         |                              ~~~           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         |                              %x
   include/linux/printk.h:585:34: note: expanded from macro 'pr_info'
     585 |         printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
         |                                 ~~~     ^~~~~~~~~~~
   include/linux/printk.h:512:60: note: expanded from macro 'printk'
     512 | #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
         |                                                     ~~~    ^~~~~~~~~~~
   include/linux/printk.h:484:19: note: expanded from macro 'printk_index_wrap'
     484 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
         |                         ~~~~    ^~~~~~~~~~~
   In file included from fs/binfmt_script.c:166:
   In file included from fs/tests/binfmt_script_kfuzz.c:8:
   include/linux/kfuzztest.h:142:3: warning: format specifies type 'unsigned long' but the argument has type 'int' [-Wformat]
     141 |         pr_info("payload: [0x%lx, 0x%lx)", (char *)payload_start - (char *)regions,
         |                                     ~~~
         |                                     %x
     142 |                 (char *)payload_end - (char *)regions);
         |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/printk.h:585:34: note: expanded from macro 'pr_info'
     585 |         printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
         |                                 ~~~     ^~~~~~~~~~~
   include/linux/printk.h:512:60: note: expanded from macro 'printk'
     512 | #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
         |                                                     ~~~    ^~~~~~~~~~~
   include/linux/printk.h:484:19: note: expanded from macro 'printk_index_wrap'
     484 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
         |                         ~~~~    ^~~~~~~~~~~
   3 warnings generated.


vim +135 include/linux/kfuzztest.h

6f8f11abdf5c57 Ethan Graham 2025-09-16  117  
6f8f11abdf5c57 Ethan Graham 2025-09-16  118  /*
6f8f11abdf5c57 Ethan Graham 2025-09-16  119   * Dump some information on the parsed headers and payload. Can be useful for
6f8f11abdf5c57 Ethan Graham 2025-09-16  120   * debugging inputs when writing an encoder for the KFuzzTest input format.
6f8f11abdf5c57 Ethan Graham 2025-09-16  121   */
6f8f11abdf5c57 Ethan Graham 2025-09-16  122  __attribute__((unused)) static inline void kfuzztest_debug_header(struct reloc_region_array *regions,
6f8f11abdf5c57 Ethan Graham 2025-09-16  123  								  struct reloc_table *rt, void *payload_start,
6f8f11abdf5c57 Ethan Graham 2025-09-16  124  								  void *payload_end)
6f8f11abdf5c57 Ethan Graham 2025-09-16  125  {
6f8f11abdf5c57 Ethan Graham 2025-09-16  126  	uint32_t i;
6f8f11abdf5c57 Ethan Graham 2025-09-16  127  
6f8f11abdf5c57 Ethan Graham 2025-09-16  128  	pr_info("regions: { num_regions = %u } @ %px", regions->num_regions, regions);
6f8f11abdf5c57 Ethan Graham 2025-09-16  129  	for (i = 0; i < regions->num_regions; i++) {
6f8f11abdf5c57 Ethan Graham 2025-09-16  130  		pr_info("  region_%u: { start: 0x%x, size: 0x%x }", i, regions->regions[i].offset,
6f8f11abdf5c57 Ethan Graham 2025-09-16  131  			regions->regions[i].size);
6f8f11abdf5c57 Ethan Graham 2025-09-16  132  	}
6f8f11abdf5c57 Ethan Graham 2025-09-16  133  
6f8f11abdf5c57 Ethan Graham 2025-09-16  134  	pr_info("reloc_table: { num_entries = %u, padding = %u } @ offset 0x%lx", rt->num_entries, rt->padding_size,
6f8f11abdf5c57 Ethan Graham 2025-09-16 @135  		(char *)rt - (char *)regions);
6f8f11abdf5c57 Ethan Graham 2025-09-16  136  	for (i = 0; i < rt->num_entries; i++) {
6f8f11abdf5c57 Ethan Graham 2025-09-16  137  		pr_info("  reloc_%u: { src: %u, offset: 0x%x, dst: %u }", i, rt->entries[i].region_id,
6f8f11abdf5c57 Ethan Graham 2025-09-16  138  			rt->entries[i].region_offset, rt->entries[i].value);
6f8f11abdf5c57 Ethan Graham 2025-09-16  139  	}
6f8f11abdf5c57 Ethan Graham 2025-09-16  140  
6f8f11abdf5c57 Ethan Graham 2025-09-16  141  	pr_info("payload: [0x%lx, 0x%lx)", (char *)payload_start - (char *)regions,
6f8f11abdf5c57 Ethan Graham 2025-09-16  142  		(char *)payload_end - (char *)regions);
6f8f11abdf5c57 Ethan Graham 2025-09-16  143  }
6f8f11abdf5c57 Ethan Graham 2025-09-16  144  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509171240.sw10iAf6-lkp%40intel.com.

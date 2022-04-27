Return-Path: <kasan-dev+bncBC4LXIPCY4NRBG4IUSJQMGQEASUMIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 46FCA5113D4
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 10:51:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id d6-20020a05600c34c600b0039296a2ac7csf351219wmq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 01:51:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651049500; cv=pass;
        d=google.com; s=arc-20160816;
        b=ieNdIBBQ6znpwhBEwumm2+KIWl0ZGpxwBhF8mLaX6b6irAB5pSdUwHOZLvg+TW/70O
         5CxhamSnwHfB7osXrx87YwQM0zbyL8Enx8dOmTEzeoG0fI2c/fCuae2NSd7MqctvfV/I
         9klpWjFRVCcNuRRJTmJ9Fzu4gD3/vV/8Uqklrr93AU5JOy0AXHGmluIq5qgCMdj+nBub
         eZF58dSqc8EiB2u2RQdgzQ2qobGb7bnvRtgqJmhS2vB2RouukZiwdkCc63ejKT8sPyol
         9D7+1aYHp0aKpjgu01EU+P6NrjYa5dX116VScZM2V/d89lc+OXEDwoy2qoLj2VutN5z0
         ZGXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+0QjlK/GKxEWlCfXNzipcs8tMdhgV0RnZhdH9yHg/mE=;
        b=dXmhgV7Iglv/PLdtluNIoATfhEtV7HnAYfbCG0bmnHOE4czF8PrOZ5m5UO9aOB+141
         KcL0Gd102B4bJzGU6wyc3Zu76hpkQGLvNeZu6OEtsAtgM7DfRl2M2Gd6Dq8YB5Vsln+2
         L7Wuu/2sBfFoTEyCd8gJOBm++J3QY+4Az/Tie+lKEqqtiXXE7qyjlmu0VSiil9LzJx57
         YdO/gJcA5wuHrRF1kHIHA95ffaaV1jjy4j5aSpXic8gbv1ZETQGj9WrwWJo0D8ipAovU
         nJ18Zgh2U5U7aBYW6zoUknS6aA6GCgbm3MaE6zajp+jh+Fo4jGsaMB2T/UemlvL3KwVv
         4eDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aKpvKs7o;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+0QjlK/GKxEWlCfXNzipcs8tMdhgV0RnZhdH9yHg/mE=;
        b=Y6qpxeEP6abCrgBBOzi+KodC3GP56vnB7zwqOJuTVndJLECmlEHAMH8c5DPeEn1Nds
         Lc6l27wnKISa49UF0T3zm0F5K6+ij6ji7R39oMW32hx8yXiYb1aC+Xu47cHa9GqsZWPm
         YlHTWGyO7BbLQuiP7HqepflYaV/RrI5PB+4a/4Bh+r7tefOkgrull2o30e9dMw5p5eJC
         6t6/t9C4+SKcTrtG24R0afGkHyzpEwRpxkYFcMQLw3F46dSWRkM3fdOOCg5BDSKuwBcH
         Y8/t+QMKWOm/h5G/P4wUnP3F9/bROEwu/tc2vFIP2EEAqf8a3HyoIuU3J4W5GlkQzHMM
         oNFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+0QjlK/GKxEWlCfXNzipcs8tMdhgV0RnZhdH9yHg/mE=;
        b=i/jvGvFjSOHSAg2IcAKsBRs/8WU0XnGBFlKnYYmQqlgNGqvXgrj4CYE5cRwURE3keR
         jeAviBr172vcqNuBqyN5NNSTqKlFMHDdq5ywp4XukP9Gkon56YgZ5bi7Ti08k3ArfoxJ
         gWFtli9KQxFXYBKzBLGMs0S6CrHGTxKfdAE38pN7TZux1bUa+foSl98AGHZuwBUTupjB
         wigRD9WBmNqeROnqRlOVm1EszcIlJSc9VkphF+F+w6ZbbrnydV6R/lqlZ6chfs2OQjt1
         ftBTAb/fpHWhpuJSZuNeaif4AAVc/4XY39X07As5FSFcKomWnjpdEP0356D6SNV/is4j
         pq8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rKTpC2Aau87DfWakzwohPkGiLmnTd6RrNv+e0h64u9WuQzKyW
	qyhCqDxz0fhnD5/VABwy38k=
X-Google-Smtp-Source: ABdhPJw89+Y2gMldcYIu6+gkvaFnCQJvZOohyXS01/fhh3DSjFdDvHyTinq5S2pGYQ9Ii6NCdnzg9g==
X-Received: by 2002:a5d:4303:0:b0:207:a7d8:4ce6 with SMTP id h3-20020a5d4303000000b00207a7d84ce6mr21786594wrq.101.1651049499761;
        Wed, 27 Apr 2022 01:51:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d8a:b0:38e:d19c:f24f with SMTP id
 p10-20020a05600c1d8a00b0038ed19cf24fls689473wms.3.canary-gmail; Wed, 27 Apr
 2022 01:51:38 -0700 (PDT)
X-Received: by 2002:a7b:c844:0:b0:38e:7c92:a9e3 with SMTP id c4-20020a7bc844000000b0038e7c92a9e3mr24479439wml.140.1651049498801;
        Wed, 27 Apr 2022 01:51:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651049498; cv=none;
        d=google.com; s=arc-20160816;
        b=YL100ZLmzTLXbBOVSHzd+XneBIDmEiASVDzp/AD5diGq/iurL/rMUaQBvJfshEXdmi
         R7aMRIShyeq0le8kP9BjHejFGfUC3Zmi09OH0QDYlRAyqTvLsrK6EVYj/s+2U+7u0hkH
         WThyDGKa5XeyUTIxk9qZq+a8eaTYWP9YqD97T1RgvnOl6WBU6dZ/v1t1b9RrdJJCE2r2
         36V74l6k/pksjF8nulltm+7l2KFeFImXt5spM2CXZqlUnM1TSUNjgaVr+hoxTlmHchuV
         4+5lFckPoF8Iv/PWWBpxWN9pfro18mkmN0H/R1NPewCa788RcTlipMZFLVZLh2ANm/an
         ELdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AK3BUeFi5me3tVTcSQhasCatW08MXJLkfq2eXjoUyFY=;
        b=0V3CVguejBRT4SJAcI9XB4IbynwdaJoKsGRJj0TvHDToYCZ77Fi/fJMWrjZl05R2iJ
         K6NP0PjsJT45fjwgSveSiHVV+MV/nUE87exlmu0UeNgaVgZog8HEmHmd4JhtveLX/7IQ
         TIUewFple7hojnESFP7WsJkuAsGDCaER+ddcGbG+lSbU9cU4FkEVvFRm5sZD6DguoEqL
         7uRuUfp2+M4Dm6/uzw1dVMier5nLtu+/2f6p9QMxvvil9Vnbnk4vPwUdzHuy6oNHDUwe
         8SyYxC+Ct2r3+d9iihwMxZjBu4NVHaAqHV7u7d+56yIF4bGbdl6LQjCILoaPRquFeL94
         d7gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aKpvKs7o;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id f7-20020adff987000000b001f1f8f0f76csi45908wrr.3.2022.04.27.01.51.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 01:51:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="265674287"
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="265674287"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 01:51:36 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="539736231"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by orsmga002.jf.intel.com with ESMTP; 27 Apr 2022 01:51:34 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1njdOX-0004WY-HH;
	Wed, 27 Apr 2022 08:51:33 +0000
Date: Wed, 27 Apr 2022 16:51:32 +0800
From: kernel test robot <lkp@intel.com>
To: cgel.zte@gmail.com, glider@google.com, elver@google.com,
	akpm@linux-foundation.org
Cc: kbuild-all@lists.01.org, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	xu xin <xu.xin16@zte.com.cn>, Zeal Robot <zealci@zte.com.cn>
Subject: Re: [PATCH] mm/kfence: fix a potential NULL pointer dereference
Message-ID: <202204271645.QTJoeela-lkp@intel.com>
References: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aKpvKs7o;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted
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

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on hnaz-mm/master]

url:    https://github.com/intel-lab-lkp/linux/commits/cgel-zte-gmail-com/mm-kfence-fix-a-potential-NULL-pointer-dereference/20220427-151258
base:   https://github.com/hnaz/linux-mm master
config: parisc-allyesconfig (https://download.01.org/0day-ci/archive/20220427/202204271645.QTJoeela-lkp@intel.com/config)
compiler: hppa-linux-gcc (GCC) 11.3.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/920e9e639493bc72bee803c763f09760e3acd063
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review cgel-zte-gmail-com/mm-kfence-fix-a-potential-NULL-pointer-dereference/20220427-151258
        git checkout 920e9e639493bc72bee803c763f09760e3acd063
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.3.0 make.cross W=1 O=build_dir ARCH=parisc SHELL=/bin/bash mm/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   mm/kfence/core.c: In function '__try_free_kfence_meta':
   mm/kfence/core.c:1067:37: error: 'addr' undeclared (first use in this function)
    1067 |                 kfence_guarded_free(addr, meta, false);
         |                                     ^~~~
   mm/kfence/core.c:1067:37: note: each undeclared identifier is reported only once for each function it appears in
   mm/kfence/core.c: In function '__kfence_free':
>> mm/kfence/core.c:1075:37: warning: passing argument 1 of 'kfence_report_error' makes integer from pointer without a cast [-Wint-conversion]
    1075 |                 kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
         |                                     ^~~~
         |                                     |
         |                                     void *
   In file included from mm/kfence/core.c:37:
   mm/kfence/kfence.h:129:40: note: expected 'long unsigned int' but argument is of type 'void *'
     129 | void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
         |                          ~~~~~~~~~~~~~~^~~~~~~


vim +/kfence_report_error +1075 mm/kfence/core.c

  1069	
  1070	void __kfence_free(void *addr)
  1071	{
  1072		struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
  1073	
  1074		if (!meta) {
> 1075			kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
  1076			return;
  1077		}
  1078	
  1079		__try_free_kfence_meta(meta);
  1080	}
  1081	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204271645.QTJoeela-lkp%40intel.com.

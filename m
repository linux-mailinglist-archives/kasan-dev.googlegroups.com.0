Return-Path: <kasan-dev+bncBC4LXIPCY4NRBNOWUSJQMGQESRVLXNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8831451165C
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 13:38:30 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id bh7-20020a05600c3d0700b003940829b48dsf223728wmb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 04:38:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651059510; cv=pass;
        d=google.com; s=arc-20160816;
        b=qXiq8dQEGlwJFa6KrXGL+8Dsf5vBAQSt5FL/ueiivpvjv7M7pfkizDrjMIPB1UMqKz
         eDzjso4NRoiTkH/cOioy5cPJXfvHHJ1MVx0qB041aQy0+SWTA/K1LxvhQ01XEGXZPAOC
         eh+otVMM0R4i28yCi+PXo3rARAFx5ssJw18wKHu1+zih4pcAgV4gFxqCiFdG7uqvZmmv
         SeLEzKx7vuP46RgGJDCqCuokLbX7gPdIa/lANGUhZ3AN+HqSN8J/DlRPJv/3KYxBlCOO
         6riOylHkAV8UHl4YF7b6ZX7xITTVwO9Jn7dWHsDNx0L0sz0dIj6xcKb000T9/aqS3rgx
         h0Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6cgqBwNufYDBw76xM93pN0Z2JeopdkyVU5Tw9y0zRNM=;
        b=G8PJwNwiEJKH5Ik7aQi7zmLJM+savXWi6bkDEwJkMwMQnOTTcpWw61dKsiYS25rdy6
         oAw9CsAXt/bOnxeT/WnzoFEVy4dnd3GKmoiHtpSkLNq/MW0ovwy54bXNfGHvS3ZWdXYV
         vFsTCxIo5zprhGdsAtSKDcTl6lkI4SJ3+Omvt8TmYfvstjej7WpckEY0Y+yeHcu/dgU7
         4RQTPYVWp62IfcyDSE6Hg6C7JJ0YA9fio37CxIiezHgHi4wCnk3lDjBT/OPo+ECuVBlI
         +QYAsJmOFfC7snDD242ZBTIFXgKKlWUj9UGNFSAgy+RpeD63rtHU+iTtDR7BxKUxWBec
         5S7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mfZhGidi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6cgqBwNufYDBw76xM93pN0Z2JeopdkyVU5Tw9y0zRNM=;
        b=tS+KTcGuYfLNlyVXFQ3A5wyGcNRgvLYo0Lu+eTCiFyxHt2g63OzysQzPzpXRFhkIoV
         DBjfD9aWzKsmuon8n84y5S1is4Ow4c1SnlKl1jmE3CllUoWP1WXGCFTJIHH7JPunCiRJ
         eg6UF9wpNUm7ISYV7OaZA1cTDqd4D+YIuL9o7rFu5XydB5hRV/F7M0mArNFQA7Je4P3J
         bGNkwQNlEypUvZx8OLytngKK0jU6PuyL//WaPVfj6sG3Eo6vIjtXsvMrQVtqgTL3LbLT
         zjnT/1TGUMJK0yvo2NPwUvwt6QXdvRGKrM2OpzHfYLRLduW7dhbAQiJPiHaPPoKrJWAN
         MVKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6cgqBwNufYDBw76xM93pN0Z2JeopdkyVU5Tw9y0zRNM=;
        b=aVAO4liB1DCk6lys+Vo0rNx9+cM2ugDvyqg2XiBxGJlI1ooHXRd9711eVzfmggkmSH
         63a+6qelROxumqG3NOukRacb0bizxcniPzN3uld2m4NfV/68jJoE8qMgiZ9XyGoLgijU
         5GnQtOhPpXFGwM7CEEWrIJGQtrQGYV61p7tnPXyUHwfHZlmkfwYljjQPA06xNTMFkQqo
         oDStBxebNXRehFyhc/N+bqU4j0CuBsAh8Ae7yxVV2RqqqeMux3EY3U6HrHvkj9U6wf9H
         3DzFxQ/Zynz3vnzsgbHXjLQ7Mu3O1Iu5j8YY1ICvDtSmoke2V2cOTgchDDtQ5XMTOVcY
         h2kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HJNnkY/MMcajjGmFuj+Y3bMwZsbI8UKaKSKF/jJXRBqazyUyj
	OAYrdfoStXbGmm+wOb35pX4=
X-Google-Smtp-Source: ABdhPJwhvWS5guF6XTO1YrBhzPmxuwA+WjbRZLk/Ao1Q0G/XR5rMPnkfDW2JqnMUN/LQB+06RgR+hg==
X-Received: by 2002:a7b:cb47:0:b0:393:dd9f:e64a with SMTP id v7-20020a7bcb47000000b00393dd9fe64amr22608265wmj.170.1651059510145;
        Wed, 27 Apr 2022 04:38:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls2941387wrx.1.gmail; Wed, 27 Apr 2022
 04:38:29 -0700 (PDT)
X-Received: by 2002:a05:6000:2cd:b0:20a:9403:1681 with SMTP id o13-20020a05600002cd00b0020a94031681mr21518426wry.474.1651059509155;
        Wed, 27 Apr 2022 04:38:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651059509; cv=none;
        d=google.com; s=arc-20160816;
        b=vRTG8ewx8atD+5X5AiN+cpXpW0ELzVtxtW5jCJnsRAqz5ALXYoO0abQ4sN6ZYfTdew
         YTkDaOrTSAVgaZ9/gBiPYnquBQFfFipjN3bCxn5w4wPf1g2U8825uK27IbKbW9dE2M9j
         /iD7lY0ZOL6tRg3WW4hdQk9rf2zSoxzonAq+/3QdS43zznoXePYzd9aZKhD7qLAjv7Xo
         SaJSRRP0UMN9S7t4dFcqIKrExC748238VErMU+avUHrKpzV+6MVB52MT8GKOm5J48Mm0
         dSCu/0Gz7ZXoi8qVzVcznMQrB7zTiXQv4nZK4xgztStkimpdhdwZLLE7wfhqJz6eSlM9
         VYrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4enlcLmgqSo/9bUXivw5suVAHjqm8TxV+blkbNmfxpM=;
        b=Rs8Lauxt0LB4ueUXkoWm9qHUKGuf8MJqti7eWTfol/oBuEJhFD0KN0BNKZRJmqrKqY
         ktVc3Be4mL5Zb/tL2O+cGOIETyf0Su1xkNVj7rwIXtlIhtMvmqg+O70TX5wsamqC8srC
         8pPpEnY+kWZZsn4CZMYEoL1yZzzIp8nyNN8186KvuM2y/UjMr20zKGGVaXY6TuVjTyO3
         nfJL2f6VIATv70IgG0/QW6Y/HkxxX5TLYbBr20QWIumy0sDUL4lnH8u79Kl23KKT77sX
         D56ikq3/HMkD6J3aXmkCj7ZlVe1ZltOChm9Oij1OhlWEPNyieq04tKFU8tLJBbXxWahX
         vO3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mfZhGidi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id o13-20020a5d648d000000b00207bc168cacsi62076wri.4.2022.04.27.04.38.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 04:38:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="352336965"
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="352336965"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 04:38:27 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="617465323"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by fmsmga008.fm.intel.com with ESMTP; 27 Apr 2022 04:38:24 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1njfzz-0004dC-Ch;
	Wed, 27 Apr 2022 11:38:23 +0000
Date: Wed, 27 Apr 2022 19:37:42 +0800
From: kernel test robot <lkp@intel.com>
To: cgel.zte@gmail.com, glider@google.com, elver@google.com,
	akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, xu xin <xu.xin16@zte.com.cn>,
	Zeal Robot <zealci@zte.com.cn>
Subject: Re: [PATCH] mm/kfence: fix a potential NULL pointer dereference
Message-ID: <202204271916.aTcNyVdc-lkp@intel.com>
References: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mfZhGidi;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted
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
config: arm-buildonly-randconfig-r004-20220427 (https://download.01.org/0day-ci/archive/20220427/202204271916.aTcNyVdc-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install arm cross compiling tool for clang build
        # apt-get install binutils-arm-linux-gnueabi
        # https://github.com/intel-lab-lkp/linux/commit/920e9e639493bc72bee803c763f09760e3acd063
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review cgel-zte-gmail-com/mm-kfence-fix-a-potential-NULL-pointer-dereference/20220427-151258
        git checkout 920e9e639493bc72bee803c763f09760e3acd063
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm SHELL=/bin/bash mm/kfence/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   mm/kfence/core.c:1067:23: error: use of undeclared identifier 'addr'
                   kfence_guarded_free(addr, meta, false);
                                       ^
>> mm/kfence/core.c:1075:23: warning: incompatible pointer to integer conversion passing 'void *' to parameter of type 'unsigned long' [-Wint-conversion]
                   kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
                                       ^~~~
   mm/kfence/kfence.h:129:40: note: passing argument to parameter 'address' here
   void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
                                          ^
   1 warning and 1 error generated.


vim +1075 mm/kfence/core.c

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204271916.aTcNyVdc-lkp%40intel.com.

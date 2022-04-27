Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGHJUSJQMGQEYOOOIXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B29B5116A0
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 14:18:33 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id z35-20020a0565120c2300b004721f8a4e37sf659916lfu.20
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 05:18:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651061912; cv=pass;
        d=google.com; s=arc-20160816;
        b=t2nlRjbbe4l3U9wP32xZWc7XTZyF5szpTccedwbhYGerqeDk2VJuDpkOrl9gBpHW6/
         ENymdipdcd2a22GLTp6/OoudP28GwWbOkTKerkzYt4oaHoQK70iJDd5niKW4cuaAjcjT
         yyXnmuT/P5D4tHE623UjttvMj1ndVZNasntM1sjOoHaM1+Yg7Ky40V0h8DNhHrHSk7mP
         KFE9nLAjogJU5DmsKZqRZkBE3NpJBphhdKrqOg7FBLxdTwWupikWnqRipxQZqATvwXeH
         qfjzdOMTstmK3nmBMoQUdQH+scAcpUu5RBq3D9hVOQ8XmTU8jNQ8+dsi/fN2KFtYtFgR
         bB2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LExP1tBE5rd+VqPRI2tU9qBi/8Oxtnlx6wRoZj1qvEw=;
        b=G39D512UPSfY35IadNMpuAEVdq37/Gyo4HzRIsWOQ/PqI8GsTKSlCdwOXJXH2yP8nQ
         OPvkrV/gfM4Z6Bo2HnmdNEAkdl+zXmSG8ld2aI6zUa6mZCYll031o8DUpNmwCCVPo5ka
         aDkducncT0lc85X/WVSLee8+0qdacMSLhdhyyYdKdWckKNP+nS+p/Iak45z7kCcJcZPl
         17dVEdPZnaxf9JsQmybXMEltmj3rdpQQ5dkgk/KBP2w8PJZ68HnkpIBg+Xo7ODfSRZx+
         xV8ydkBehZ+s2qSeDi3CryHEbDmbnB9uEYOIjHWjmL7GJYyWoQn4rDWaRpNLzUVc6+L9
         Iypw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bNtVbFw6;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LExP1tBE5rd+VqPRI2tU9qBi/8Oxtnlx6wRoZj1qvEw=;
        b=T0SsOtUKEoWOukfaMrMr4j3AoqHb6IhOkKJuVrdk7LGRLdBBS85L4u7ej9Jka/wGml
         cSbqdGn3xFmi2S6BYP8BzwnIm7l7gOJ8gQELObyq5JxlaA7hBW3BuUS//a79Z3Pj34up
         LpBgoqw8MGfSNE+8Gkzw2Tuc15Lk5IORdfNHvgLbUyisOo0No2kCl2kWU3bedoaPcJgi
         yYdInqan5BjikVjnbfbEhCEKuPv4c88aLeRQnuiVNL+wU3739bHLthuu0m9qawdOrn17
         owpRkTQOcFgExwqAVqHoziGWvOGWVrkWXHYA+7h/d45ZDeC/AcYAB/iMpztTUlW9raIP
         lWbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LExP1tBE5rd+VqPRI2tU9qBi/8Oxtnlx6wRoZj1qvEw=;
        b=sftDFbRszWhCXEtSBGZv76iQbSIIH0TPUPrTTGY9PuymzDU6icBtY+4L9s9T/p9r2y
         QPo0rmAJwLm6IjuG2KyRUzefnIf7X6rCVeKkFZe1Bt8ZL5wPOyCZoC1sH2R6PJJ430ZH
         kUBkbdRlYNFGOKlVlH0orlld1pETvY351G5gWiyKQPKvtf0a5krHxJkaIVDyikMEjyFg
         Eu+J9v9HyFGK1XPl3ieJdfHcGgTIUipEgPJwV3zsRMkkvPj1Q6lZpcczaVph+cdVhUvC
         rStCK8pb6Q90VZCECgurZJJGy//uBu+4Ob3qHfLJZXWrabYm1sveeC9h51QVEj/jzYN7
         IhjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530C3RQAdwQN65YXwa2CGCH2GasJ82St/6+6iXstkP/8XaIJDH64
	vze/vgtcPKPryKzwj/5ncps=
X-Google-Smtp-Source: ABdhPJwH4u8rcqe6+93PZjF/KMS/vC3lvjUXZfy+TulCgMLCTgAArSoCEfKiJ2CJ7ac9Uh4nOnPWCQ==
X-Received: by 2002:a2e:82c9:0:b0:24b:385:fc45 with SMTP id n9-20020a2e82c9000000b0024b0385fc45mr18292147ljh.308.1651061912536;
        Wed, 27 Apr 2022 05:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2815:b0:471:b373:9bb9 with SMTP id
 cf21-20020a056512281500b00471b3739bb9ls1790652lfb.3.gmail; Wed, 27 Apr 2022
 05:18:31 -0700 (PDT)
X-Received: by 2002:a05:6512:158f:b0:472:29c:1620 with SMTP id bp15-20020a056512158f00b00472029c1620mr11677746lfb.245.1651061911203;
        Wed, 27 Apr 2022 05:18:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651061911; cv=none;
        d=google.com; s=arc-20160816;
        b=OYzgDd+fobX8GRQ/ztSLH0vk+h4yoNuykIcnPaqIUgHCwewxm7u5zdmu3z3Oe0OtFW
         Lbc88oi+9lbdBpIz7rS796/yvObpQtPuUNBJQ3TcW0FkibYSB95RBsEK4jW5FZaQtT1E
         BojtliTfINhuXMkKRf+9XBnYIrJCGDwPXHRDk1hmHSgEnuJLYyQw8o6hg5p+6DEMaI1G
         KnPoLWzTWij+5J4MCsEoz6UtTNHTahT0h/8RgzEYi3rJ9Hv8xXwUpQ15uotNHeaLQRO+
         KN0Vcr/QBaapM+uMYoRCT0NflZNrKI6x+HdRNJlFnQ39j4ZI1q+/7qR9oI6RGTk2I2yB
         zCag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Gm4HoZohZKmqArL4kJXHBQ3PlNtwDXhx5Cso6v5cEsI=;
        b=OpRRWN24d347tDEOyKgeA9tcwRA4Y63AM+rdg29k4XP3mvzFtzFPUa+NLfTUBasKGE
         qIua6pRAs++WurHIRly/aXzmzFg8CNbOcdklvTAs6K1kEE++T6hWxvCRpWS1MmpFWH1M
         tTShgk1HWHQX3iKXR41iVkieQfFGVao/7FraiQZj3YHeiSG9AFbhhv0dLxqM4lgH30+w
         VAm/KPNRnt18dUkMbpCO72C31jLo+N+dMd33FJyRd0M3++kLKxGlSgoSL16F1Fpcw2ME
         kz/y0z+zuf1J5JsqMFI8f0HpbRsei76/2wxcoa3YRDiRZI2cMtG0FbzTRp+PtKl5nQe3
         +O9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bNtVbFw6;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id j19-20020a2e3c13000000b0024c7f087105si53832lja.8.2022.04.27.05.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 05:18:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="265719431"
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="265719431"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 05:18:28 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="876392050"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by fmsmga005.fm.intel.com with ESMTP; 27 Apr 2022 05:18:24 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1njgci-0004eE-9P;
	Wed, 27 Apr 2022 12:18:24 +0000
Date: Wed, 27 Apr 2022 20:18:16 +0800
From: kernel test robot <lkp@intel.com>
To: cgel.zte@gmail.com, glider@google.com, elver@google.com,
	akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, xu xin <xu.xin16@zte.com.cn>,
	Zeal Robot <zealci@zte.com.cn>
Subject: Re: [PATCH] mm/kfence: fix a potential NULL pointer dereference
Message-ID: <202204272015.3JRd9BKR-lkp@intel.com>
References: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bNtVbFw6;       spf=pass
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

Thank you for the patch! Yet something to improve:

[auto build test ERROR on hnaz-mm/master]

url:    https://github.com/intel-lab-lkp/linux/commits/cgel-zte-gmail-com/mm-kfence-fix-a-potential-NULL-pointer-dereference/20220427-151258
base:   https://github.com/hnaz/linux-mm master
config: x86_64-randconfig-a014 (https://download.01.org/0day-ci/archive/20220427/202204272015.3JRd9BKR-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/920e9e639493bc72bee803c763f09760e3acd063
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review cgel-zte-gmail-com/mm-kfence-fix-a-potential-NULL-pointer-dereference/20220427-151258
        git checkout 920e9e639493bc72bee803c763f09760e3acd063
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

>> mm/kfence/core.c:1067:23: error: use of undeclared identifier 'addr'
                   kfence_guarded_free(addr, meta, false);
                                       ^
   mm/kfence/core.c:1075:23: warning: incompatible pointer to integer conversion passing 'void *' to parameter of type 'unsigned long' [-Wint-conversion]
                   kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
                                       ^~~~
   mm/kfence/kfence.h:129:40: note: passing argument to parameter 'address' here
   void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
                                          ^
   1 warning and 1 error generated.


vim +/addr +1067 mm/kfence/core.c

0ce20dd840897b1 Alexander Potapenko 2021-02-25  1050  
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1051  
920e9e639493bc7 xu xin              2022-04-27  1052  /* Require: meta is not NULL*/
920e9e639493bc7 xu xin              2022-04-27  1053  static __always_inline void __try_free_kfence_meta(struct kfence_metadata *meta)
920e9e639493bc7 xu xin              2022-04-27  1054  {
8f0b36497303487 Muchun Song         2022-04-01  1055  #ifdef CONFIG_MEMCG
8f0b36497303487 Muchun Song         2022-04-01  1056  	KFENCE_WARN_ON(meta->objcg);
8f0b36497303487 Muchun Song         2022-04-01  1057  #endif
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1058  	/*
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1059  	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1060  	 * the object, as the object page may be recycled for other-typed
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1061  	 * objects once it has been freed. meta->cache may be NULL if the cache
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1062  	 * was destroyed.
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1063  	 */
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1064  	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1065  		call_rcu(&meta->rcu_head, rcu_guarded_free);
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1066  	else
0ce20dd840897b1 Alexander Potapenko 2021-02-25 @1067  		kfence_guarded_free(addr, meta, false);
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1068  }
0ce20dd840897b1 Alexander Potapenko 2021-02-25  1069  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204272015.3JRd9BKR-lkp%40intel.com.

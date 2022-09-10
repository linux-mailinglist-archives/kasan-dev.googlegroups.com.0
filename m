Return-Path: <kasan-dev+bncBC4LXIPCY4NRBE5S6GMAMGQEN4FQUTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 98A225B45A9
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 11:29:56 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id h4-20020a1c2104000000b003b334af7d50sf3438014wmh.3
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 02:29:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662802196; cv=pass;
        d=google.com; s=arc-20160816;
        b=KMbFmJ3yKY8OoCISJFE5IFAgADf3tjGdCVsDgUt7A0VZvzZwS5BaMGfeHJT7ThM4q8
         uQlC1EM9s6jawp+55q7My4XzpEL7qZ2yUu2XR5tph6P8GItIBbN6YgENOtBVICx/idpi
         Yw3T6bURXFLn8VJEiYjXJTjwl2+tyiYsZWWHD8O4pLnszJ+BFUR0KVpL5kzvNEclhLHp
         QD4/AJFeBpQGLh4w5WrwV46M+D81RTYlL2GkIUWxPSL0nV5ti9jMhL9KDPipl1+kTBTw
         aWExOH+O6otK/WHDNy/Y5LOo0GC1pZ/GOGljjaoEi0foPhPJpyogDyzZf55kb3DqM8KB
         +I0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+Vtal9o5z8jBzn5ZoJYgcqF5ukEhhtIBTjuROaRFYlY=;
        b=dH9fBiN1kfOMH/c3gUwG7iiqEPEJdH9o0jSTHN9SgQUiv0feTbZxwoXyh9+864PKnJ
         aBzfB1POiBt0S+FKBAosHkyXrcB8JPMaPZ3QCAXy12JfQIanE0WsL2kHXpaYhhE3rubl
         /D7988xikgiRDJ/vNNKBTGzLxqcue4v3ejH6uZE8gtl7X/E9v1v8YC6WnFjNOo8Cf69D
         OhkOuL8Z5aFupqiw6N9vxpQL08qCZqP0ZCQ/jolZ+5z2zkUu487APxxbdAYjReL0MR4H
         LebvuIoRS8ry86ydnhFFS7ebo6dVRHuu2PT6trS6Yo5Ol9szNohGtYC8xKSueHTVf79q
         SKEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LNaHxtAw;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=+Vtal9o5z8jBzn5ZoJYgcqF5ukEhhtIBTjuROaRFYlY=;
        b=sVtRNp7VLGnU2s7M8X+HFvGVvgUyjlTLeeKHjdup/4H7J50DND4WoYnoiih7BJzXjC
         uuLzd1nIJzrczt1rjj+ODyJZKnjfmIczmpT1HirOzFlCRbuoSENEPztnIEL74YVFcvYq
         Y9zOmzSAncSuRk5g4SuFkeHTixhncg/wmn4tbtho3LQ6XFz1V3zdvD6MOhvIZyWcZNrQ
         K1z+rsWqhdNJ9e+JY917DCdlR/dPcO482jPrpqLxl0wOWwx1muFcgcSk86ADKrLBBQVq
         c0YJ1p0dqDq0qoTgpm5xp17pabCs7ThZ9AM/HEoBQ0wIUZD3ly/mCNfGteLhsKOmZc/q
         yJSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=+Vtal9o5z8jBzn5ZoJYgcqF5ukEhhtIBTjuROaRFYlY=;
        b=W/eWt4TOPQpXUJ9CL3oA42CFAOxPiPJLHTARf71q6UwR5ZfUUUnhA4x0jHdGUtRYuA
         yp17+TlQXN2G/C6f/mezxUU30zU31SFKPXbeXEUKDn2/kmZGDnzrwnG8LjNDcZAqIDvt
         a+APYU7UCQAP2GEGeu9bm0t74m5dbA78Y90NmXT8KUjWdjlCOcEokaHPmpntFCt2hj9K
         yp2OcT3H3XwkFwsMcw281wbV5BhyUUGCtwQTJ981d3ecf5Czuo8T+zY5wMUrje2udnEz
         iFzWHSfXOe3ySQMg1hTZqCsXM4cgC6zchw7LybqDj48oF2mXrSimYyWNfxJoH1Wlmly8
         fmqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo34T964EdMbYhlct8opWewXBVG+vf7+cCyzXVgLfndN9CtsGmkL
	OBl5rFnSJ3IzZdn+e7AwNy0=
X-Google-Smtp-Source: AA6agR7Q5est9Xyo9bxn8p1NAK2Gz9GathcBi5kx4QcVjfac6EzCzUd5di0J7HYpNzjgx0cKUvh3+w==
X-Received: by 2002:a5d:5c0c:0:b0:228:df98:7516 with SMTP id cc12-20020a5d5c0c000000b00228df987516mr9966908wrb.208.1662802196098;
        Sat, 10 Sep 2022 02:29:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6187:0:b0:228:c8fc:9de8 with SMTP id j7-20020a5d6187000000b00228c8fc9de8ls10820632wru.1.-pod-prod-gmail;
 Sat, 10 Sep 2022 02:29:55 -0700 (PDT)
X-Received: by 2002:a05:6000:1886:b0:22a:2944:a09 with SMTP id a6-20020a056000188600b0022a29440a09mr8209638wri.391.1662802195162;
        Sat, 10 Sep 2022 02:29:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662802195; cv=none;
        d=google.com; s=arc-20160816;
        b=inLe4gUSC7zxURRW+C7IB+elmWJdSuhxw6/0CzjeCj95tjb4ZXcmROKMHN4LPCq1hI
         TSsDle5Im02pJDpDkoB4mkO08auEBRs+IXvAV2hIaUUB0XBzkmCG5xzHk6tG3tnxHer1
         +RbPcENaoU9ZOHHNzHrpBgt2eXeX+3J+TqPCPWClcljTM2sA/shPGrqMVJYoR+/Z7gdp
         GM1uiuo2Iol2gvi5NonMPh9mgCmrp7QesXPTJGT/zNjIYPc71zlL7Pb76GBgoLvL3sT2
         mbihbHwh+aQ3fNd40LHcbIekWrVQhGI3ZzmahxUbt6bqK3WtTTLeVI72BOgoSR9BV7Xl
         +zUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aQJENNlfrEdW6z95epbfP88E3ZEs/RhjlipOARQJ+ew=;
        b=RWsolGXaOIJwXdT4U2x4knR90pxuVrD3SqLHmbq1J0aoYGRvcNpL0sBdzm2wpeA5eH
         FJ+UawsDAqzWpx0VH/UYXgsxfiDsEIDIEmboleavWA1gRRi53QDjTYL88YFvuDJuUDIc
         I3jRU3bpi5fywEWr8qCMkKPYGCO7RnyzQ4g2QdOaPNgwROrxBWay+xO1vESEocInD7jz
         rNoFwxw8nA83OLaXyIh5D9QlE1Ata7ZoKnzkWTwMs5IooBv2MhVX6i7d/3Jl3pnNHXSx
         lEM5jRS/+leglXDkLgBCnhpCSAd/yWcLJlAUMzixLufBeWCVZXYvI2gFFIYDjPRf70tq
         rS9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LNaHxtAw;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a54f1563c9si154609wmb.0.2022.09.10.02.29.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Sep 2022 02:29:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6500,9779,10465"; a="280648649"
X-IronPort-AV: E=Sophos;i="5.93,305,1654585200"; 
   d="scan'208";a="280648649"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2022 02:29:53 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,305,1654585200"; 
   d="scan'208";a="615531143"
Received: from lkp-server02.sh.intel.com (HELO b2938d2e5c5a) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 10 Sep 2022 02:29:51 -0700
Received: from kbuild by b2938d2e5c5a with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1oWwoA-0002MM-14;
	Sat, 10 Sep 2022 09:29:50 +0000
Date: Sat, 10 Sep 2022 17:29:25 +0800
From: kernel test robot <lkp@intel.com>
To: Peter Collingbourne <pcc@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Peter Collingbourne <pcc@google.com>,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] kasan: also display registers for reports from HW
 exceptions
Message-ID: <202209101733.SvgcwWsA-lkp@intel.com>
References: <20220910052426.943376-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220910052426.943376-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LNaHxtAw;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted
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

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on next-20220909]
[cannot apply to arm64/for-next/core linus/master v6.0-rc4 v6.0-rc3 v6.0-rc2 v6.0-rc4]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220910-132721
base:    9a82ccda91ed2b40619cb3c10d446ae1f97bab6e
config: powerpc-allmodconfig (https://download.01.org/0day-ci/archive/20220910/202209101733.SvgcwWsA-lkp@intel.com/config)
compiler: powerpc-linux-gcc (GCC) 12.1.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/2140392d32582f62b922eaf4d1824e5a7838b420
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220910-132721
        git checkout 2140392d32582f62b922eaf4d1824e5a7838b420
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-12.1.0 make.cross W=1 O=build_dir ARCH=powerpc SHELL=/bin/bash

If you fix the issue, kindly add following tag where applicable
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

>> mm/kasan/report.c:506:6: warning: no previous prototype for 'kasan_report_regs' [-Wmissing-prototypes]
     506 | bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
         |      ^~~~~~~~~~~~~~~~~


vim +/kasan_report_regs +506 mm/kasan/report.c

   505	
 > 506	bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
   507			       struct pt_regs *regs)
   508	{
   509		return __kasan_report(addr, size, is_write, instruction_pointer(regs),
   510				      regs);
   511	}
   512	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209101733.SvgcwWsA-lkp%40intel.com.

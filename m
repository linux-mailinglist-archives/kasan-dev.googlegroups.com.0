Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGHN3WSQMGQEU4YVJNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E21D9758D3B
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 07:37:29 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-51d981149b5sf3894779a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 22:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689745049; cv=pass;
        d=google.com; s=arc-20160816;
        b=AoBrIphvhHECkEolaht4VETvdWOST0ckyzsRnaPmIDbHnaEBE3di7nDrHNQ5lusCnZ
         OGYVnlOiYau/jMXWFbNrhXg78za7iDO4z0b0lMcAY0TAB0XGLRrMFmIn0Dt3aoB68Zr5
         3NDfyl1gjM3meJB+snywZOamLOEGU9s8dtXukGLhDcthSyEDrRI12X2Y/5LONV4/U1+z
         N0QLxH3lV0TI+9WTgfxL4ReX2Y4cEpETAiPybGdkdiU3YPL0lomO+NYreD2GM0ERWyq/
         M3mp1e3tE3AbypJY0aGTT2P/bfX4Zjl7KsEsE/jLxjCOw4Z0BK1ORNUuKAe+CohwLqPe
         DvRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/+auliUSdf2JfPCdJxJ+c0Ptxbk2CBdLqmR291RNnQk=;
        fh=1ZBb3ZLieD7rn/YgtMXmw3IlR8a2i5+z8+cbrurNsEw=;
        b=Z1UOgbhW6t3pig3Ftd6M3LNDpOrBrvT437PDbTfcn+gOfJJ4i5V09sUTHqLPzXEsw3
         RPSx8C9IwXg9YHvZJRHEld6XtKSDtqEDWx3xLwRfr6UMBk8Ch4VhX7zPZwc1G0FmoDm3
         uH+AI48UtSccGjkHcde5J2S6IE4xv6vIBwMPHAcatI4oGbXZtR7Rf1YHpukkvgb8pmVy
         CJBcuoKRXxPjboWRkAR/lwzsFhCySpqNxT07kdjtsXluCnKOCtRIsNxZQxqPK6/9HRMY
         ddybQ/2PWeHhwWkc4BdhzXYQ2H888dHHZAV1z4SiBtPtJsbFBmh6Gls3HbvZgNLs+RNg
         5jqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HSr0A87L;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689745049; x=1692337049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/+auliUSdf2JfPCdJxJ+c0Ptxbk2CBdLqmR291RNnQk=;
        b=R1kww+LfZWGSfM1GfVqbtegXcpGa9T0Mh/MQSigQKYvW+grhLmlVFID8Y1bv3OCx9c
         asHTEgQcdFHBH1iG+jnDj52DFcLbNUEZWeb6wwDg+kOTNdVc/RgSxaKdpnKZGroySh+Q
         37Uqcn9a/ckGUVOeJ+h0vHO50PvmIKhLkzjHU0Z9u/fq9o41E1SAmoJuVFWFrIJf8u0u
         wo53xOGBlyDj9HUKcr5ODWQzQlqMFFD9T647KaKeNSadM/+ve9wVx4WDP0oewC3rQM4+
         RULSgvyyWiIJQeWGOVOp1sxtQxAONzXMp9IiwvdnVHaVVpLTclD2jRH8V7jO+l8AV8xs
         5Uxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689745049; x=1692337049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/+auliUSdf2JfPCdJxJ+c0Ptxbk2CBdLqmR291RNnQk=;
        b=jEXNzp34m/Sd4GjSKrj0Bsi5O0OuVn4PL7+Q1uH2oapTN+xbZAYggjHvxTolCLFb18
         yA0MQZ5ViyY7qrSSK7Rvji4WdGfI1NUDlcVa7aMxnufcsact8Vgr2xJ60vFnNpzdgliv
         bNGpFn4HEf+GkXf+nL64Oh6g2CD/7cRpklrRfZyZ8OidSBH57l3oCglpx6Nm3X8RwvjI
         KVAVMQvFL0BZtLilTDlAflrosGcvoYYFbs6KILU9Y3V0iN0+ed4w8sGo+oFB8l8fgc7o
         gBoMoKECj+qQa+9ncRSb6yM1pA2sBR1OWWHex07TTh+yZytnQo5LVCDHzNje6vgZ+/nQ
         pxUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLai1swH0U8TC80THASbh5ZuTVQebPYzXkrZscqQjcdMeIvoV0bx
	Vdze+xfgdtwuUY7NFrsP09A=
X-Google-Smtp-Source: APBJJlGx0Z5fd74xzuB19gKQQ61KTBy2HX1FQKtj6quDV11MWDJEqws+T3/syvtQ7UvZF6YO8UtdxQ==
X-Received: by 2002:aa7:d809:0:b0:51e:2d16:8473 with SMTP id v9-20020aa7d809000000b0051e2d168473mr1845110edq.36.1689745048931;
        Tue, 18 Jul 2023 22:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d154:0:b0:51d:8056:da3f with SMTP id r20-20020aa7d154000000b0051d8056da3fls2646551edo.1.-pod-prod-09-eu;
 Tue, 18 Jul 2023 22:37:27 -0700 (PDT)
X-Received: by 2002:a17:906:1096:b0:988:699d:64d0 with SMTP id u22-20020a170906109600b00988699d64d0mr1465495eju.32.1689745047279;
        Tue, 18 Jul 2023 22:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689745047; cv=none;
        d=google.com; s=arc-20160816;
        b=Up8/LpBuY5vDr8hcO3EVyBD44KDgY5QWroKrIaEnmM5yo5zDvF6Xe14cxLxn2gYKD9
         BTJw1li5sNrcmYUwJqUbC9FfDNelTHL0NbLSNnD1tCjCNxO5hSpbsQIRtfKPciNEvUNK
         0PUXc7Tb4wGTE1XzeNT+7mJnAbsAXMzgjITjK3Zms/qIhKao0XqahRkkY0jIUWvF8y+O
         Vi5OHy4k3k+RMdW6NEBhvcLtjDz+xWKAHWJngEfyRG8DJOmTfnwHp+UGWYt+BEBWJuhS
         0vaJ6D8CYOmtcWkp2TpapzwbgoIXiUIt3N5wsvKwwkYxC0B1T4DrVkfk6w+HAIIuvlju
         McqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=g3YOXnbEZFYyOQGdApXvC3MTaiPZdUCKhMJawzytxN4=;
        fh=1ZBb3ZLieD7rn/YgtMXmw3IlR8a2i5+z8+cbrurNsEw=;
        b=IclDrXlLFeuz12zNZF0rNCVteC82ea6+kEdkcMa70UR/xJLtSdFvSfpg6uwnwDnvvQ
         BHk3BMjWTpqCPUGdYukRfPAOky1glL4W7RDb11Oe+juZqq5g6ObUIQtEWwKbNZVxsYNT
         cFlFqmit9ccaw0mjg1DsX5tRFcQtlmRLBczJNp6nsL4t4eAxVywg0rVSxE3Ef5tIZiLB
         PXyZDrYVm0lLYuT64TCJI6wmAXGi4i2l0zxihhOi0WaPFw3joqODAZuGIfZ2Nc7AUx3h
         sf5+tNsn6Rd0FeOOq26wPcOshQJ3pTu7y9Y8P3YlP2jGJwnqXn3y8LdrLNnsEGNkuQOc
         Hk6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HSr0A87L;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id hu16-20020a170907a09000b00991ee378a7csi246152ejc.2.2023.07.18.22.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jul 2023 22:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10775"; a="346679537"
X-IronPort-AV: E=Sophos;i="6.01,215,1684825200"; 
   d="scan'208";a="346679537"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Jul 2023 22:37:25 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10775"; a="723876144"
X-IronPort-AV: E=Sophos;i="6.01,215,1684825200"; 
   d="scan'208";a="723876144"
Received: from lkp-server02.sh.intel.com (HELO 36946fcf73d7) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 18 Jul 2023 22:37:22 -0700
Received: from kbuild by 36946fcf73d7 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1qLzsH-0004BV-0x;
	Wed, 19 Jul 2023 05:37:21 +0000
Date: Wed, 19 Jul 2023 13:36:38 +0800
From: kernel test robot <lkp@intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Subject: Re: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Message-ID: <202307191350.tJh2PZdE-lkp@intel.com>
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HSr0A87L;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted
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

Hi Andy,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on linus/master v6.5-rc2 next-20230718]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Andy-Shevchenko/kasan-Replace-strreplace-with-strchrnul/20230628-233727
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20230628153342.53406-1-andriy.shevchenko%40linux.intel.com
patch subject: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
config: x86_64-randconfig-x001-20230718 (https://download.01.org/0day-ci/archive/20230719/202307191350.tJh2PZdE-lkp@intel.com/config)
compiler: clang version 15.0.7 (https://github.com/llvm/llvm-project.git 8dfdcc7b7bf66834a761bd8de445840ef68e4d1a)
reproduce: (https://download.01.org/0day-ci/archive/20230719/202307191350.tJh2PZdE-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202307191350.tJh2PZdE-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kasan/report_generic.c:286:3: warning: variable 'p' is uninitialized when used here [-Wuninitialized]
                   p[strchrnul(token, ':') - token] = '\0';
                   ^
   mm/kasan/report_generic.c:267:10: note: initialize the variable 'p' to silence this warning
                   char *p;
                          ^
                           = NULL
   1 warning generated.


vim +/p +286 mm/kasan/report_generic.c

   242	
   243	static void print_decoded_frame_descr(const char *frame_descr)
   244	{
   245		/*
   246		 * We need to parse the following string:
   247		 *    "n alloc_1 alloc_2 ... alloc_n"
   248		 * where alloc_i looks like
   249		 *    "offset size len name"
   250		 * or "offset size len name:line".
   251		 */
   252	
   253		char token[64];
   254		unsigned long num_objects;
   255	
   256		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
   257					  &num_objects))
   258			return;
   259	
   260		pr_err("\n");
   261		pr_err("This frame has %lu %s:\n", num_objects,
   262		       num_objects == 1 ? "object" : "objects");
   263	
   264		while (num_objects--) {
   265			unsigned long offset;
   266			unsigned long size;
   267			char *p;
   268	
   269			/* access offset */
   270			if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
   271						  &offset))
   272				return;
   273			/* access size */
   274			if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
   275						  &size))
   276				return;
   277			/* name length (unused) */
   278			if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
   279				return;
   280			/* object name */
   281			if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
   282						  NULL))
   283				return;
   284	
   285			/* Strip line number; without filename it's not very helpful. */
 > 286			p[strchrnul(token, ':') - token] = '\0';
   287	
   288			/* Finally, print object information. */
   289			pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
   290		}
   291	}
   292	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202307191350.tJh2PZdE-lkp%40intel.com.

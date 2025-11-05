Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKNBVPEAMGQEH2WWJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F32FC33EC7
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 05:20:59 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47754c0796csf20775425e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 20:20:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762316458; cv=pass;
        d=google.com; s=arc-20240605;
        b=C7Nnz0tt9Q523Z9ZikBY8ra9eCa4RvI3skjkFXVUWnqjMoqrm0Pd1gsw28rFpke7k7
         xMsGXxntvQd+gukOrI/YwDpU2FTRjBN7dtHHfDbTdca+O7I5cPzMP5HhTx2Jr5fz8Oe4
         DOONYEfMlEzTwzdV73piWcbmEG5m8uKEpYiOmri9vytelahxXdnLfPY4INyRSNEuuuNa
         Cj6UqQYji4Ee1Zhp2AUxVwl3BQyClnRMoeX0hq+axQbV92NV6v3L5RwZ4aNFeZaNmBFf
         sBOc6LNT29O12MF6o1V7fhLAsQsMphWHC2Q6AYRhvwSP5Ih6NP9NtXAqRbwm2sCNa+2U
         BCkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XFo/tGqkGE2KTniJuHqTXNZa865RrkF23Bncz1t2ZQU=;
        fh=mXmxsG9wTveb/TdZ5j3FvN+p3hoKwjh3hZ5gQyhkyUI=;
        b=Nw0OYYBLXF3AE0ddDU4uk/CUvw/AAzzloaAr+DToAwtDdBfXQFAufc0I76X6FRAaax
         x1FMtC8UgRKCgep1w8dfv//7buHnTOVR2d7ZwoThNoFY8OsxidaHzGtKK0G2rkfbZ2o9
         +3QMo8Rb+JA/aM2tHblMjiBkIRjDNrIr6Q+I7+JyiTY76padfhnzIexcj8ATmRVtNz8e
         rk9RxuiTBAGL+dp/oZVKNDmQGhzc/xRhWU069fwt2s1MB64Ig342Ux7AndqNu2F2Of7r
         Tv5X50vsUDU+2LELa2D/1SruJ56aB5IbOQoIUL5opCDLXgo8kxNitHY/3y/TBAQjPVXa
         0doQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W8yWVUdD;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762316458; x=1762921258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XFo/tGqkGE2KTniJuHqTXNZa865RrkF23Bncz1t2ZQU=;
        b=ewT3LJCefgUXrd8C8/PiVU2XxWMK9qDRI9apt3iFM6MJEaPJ1xJ34wgzZqnGFW4MLK
         098s0FMZJlUsBi2Fo2Numa1roD1aLRG3HxCm/3ntvJtIjYHk9tdKnsSQQSgHyONEV68c
         uWZTL/iJ3UJGWeS+rZ8o577OLTHci2/GYRbsFMbJDI1XIxrraVd9gaSIs2iOO/LG0Oh/
         r9ulKZtjopGmOQzmOj9kIYhInlU5c5EsaZN4i+vnufEfRXLcEA4yC8D7/1DEKgAtelUR
         I/eRMs6w7EOM04b+QHo0574uf5KcUwM2HKOl8kyvfLY4YMP3wN6KjoModgiA/JUAvKaw
         7fcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762316458; x=1762921258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XFo/tGqkGE2KTniJuHqTXNZa865RrkF23Bncz1t2ZQU=;
        b=rY31Zu+6cnVXm9I2vj2lWCB3nEUHF5zrKvbi44s21TpdLVYTvoXrN0B4Z9OyEly8dn
         s0YEJ3sLwNGVxBWQNAN+aQjwromtN5+zVu3S8JtvS1K53eCsQzlXsH0AkC++F0DNZoA7
         LxNIaCemR24vrtTlk7ULX4jHvu8wl2Htg79aaA8GRBicSD+OIt5lZu8wLE7v/xS+Nnrn
         5GwZ2VnQ/DlzZhTV269MiYYyZNJl1b5YhECawe2edszML+qz6EyAHKX2ObdaD8LzD3xE
         YT6wRgmU/PzHsEi9AnDPUMTdpr9TynU301w/MQo5IsVbC1r2X6/Mb3wW8ZriyV/Lg1be
         r4TA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJku6cCmV3K/fi+gVVd4YQsUvCQeyD6Jrfz9syhLF7Ifkppw9Zk2FdIcg5Z6ArUlmZ4uomWQ==@lfdr.de
X-Gm-Message-State: AOJu0YyyvsRJ24PzwxcFJmjCb2zqakUuse113NKwsgNrfAAH12ZDHJgL
	Oh76pzOTIBhRmYI6kz6tEG0RkAhvIs/SshYNkmBCFIyMAS2vf1Y6OCgG
X-Google-Smtp-Source: AGHT+IH1OjEirR+W7A3BcPC7hJkuNItGuPs5EM3IF12T2yZffD2YlMFtwCLTo+vnKeJ84oq2XgdSRA==
X-Received: by 2002:a05:600c:64cd:b0:475:d917:7218 with SMTP id 5b1f17b1804b1-4775ce7df88mr14847765e9.36.1762316458585;
        Tue, 04 Nov 2025 20:20:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YUtEyxOirJqCEYmn+WIp0litbVzQRI2uaLM4yOEsiqbA=="
Received: by 2002:a05:600c:138c:b0:477:4db4:d384 with SMTP id
 5b1f17b1804b1-4774db4d3c7ls29629535e9.2.-pod-prod-07-eu; Tue, 04 Nov 2025
 20:20:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLBPrE3/jMABBkcOxWLCK+u4HfG5cfDYEAV1PRgk+sSbogKAORzzGXsFtJ3RHS8E+m2gdIm7RiOL8=@googlegroups.com
X-Received: by 2002:a05:600c:1e23:b0:46f:b42e:ed87 with SMTP id 5b1f17b1804b1-4775ce8e781mr13597185e9.40.1762316455428;
        Tue, 04 Nov 2025 20:20:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762316455; cv=none;
        d=google.com; s=arc-20240605;
        b=UiYZ6W3S7gj8xOsKabryxKvQ+10jntdw8oIvZ9KRPK2TT3uXp8BA6gKlpyD0M4n4ME
         UooMUAZU2OWQ+ywV3p5V0AnFh7YdKRQzaXIXpWsbBmr2J+oXRIHy+zvTf1OY1jW8yqyL
         lVGK6jaZRjn549r3NXgeL4iO007LWzEzeCOFdPZjQJaEGn4I1KZ5GMorFsD5Pq+pETVQ
         mTDFM0eM10Vej89R0rADWK6hI/nDmBMA9VwZ+4jv6K45Eq0zyL4X2ITKaiFY6mn8CSPq
         qp5ZKgEGDOCUdqjaHcuCyRhuKfavaOvgmMKNAhJe5qr4eqsY1iwyzkvYSQac0fAB5LPC
         WX6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zq4W7y+PxrZhypoQbEZTZrrBUkflx9ODl5ddzOQLhBk=;
        fh=OiVs0XiIQNJAGMw8ZpFpF0+Z0hjbMRrc5VBbXsh3l38=;
        b=IuW3oNK+g6qbE59xok/pT3yOWKmb5tmXRW/vZd7gsMI3QCQnApZr2KpHgS4HpKed8Q
         bU+wvFYfLDHnhgVoC5bS1V7pec2lQ97Dcocan5Jmvv1LTohaJLTvv/aznoZGk7U0KGmo
         C+gmuOMhJ+6+vaz3MMysaJsOqnNJZ9AUd9DyrrXHY8uJzgEGfInEXYKAezKoYw6sxsus
         RkmAYf73S18uDIyvwCN59Ws1Zcnu7LKV4Mb5tN+Vte6nwecn1PAeug7zx3oPokPUtimd
         A9CjN6RZEPeK+8YN1uHGrSMdNabxUjQYLxPLyEMzCp/H7YegdrLKTiZrvepPJWQkT3pT
         Bn9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W8yWVUdD;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47755856d25si386575e9.0.2025.11.04.20.20.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Nov 2025 20:20:54 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: F6xEmUvgRwa/kBO8+xaqaw==
X-CSE-MsgGUID: MHcdoygYS6SoMpPv3O3LQg==
X-IronPort-AV: E=McAfee;i="6800,10657,11603"; a="64461022"
X-IronPort-AV: E=Sophos;i="6.19,280,1754982000"; 
   d="scan'208";a="64461022"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Nov 2025 20:20:52 -0800
X-CSE-ConnectionGUID: QYLtRUMnQEeRSfVzBGxQ5A==
X-CSE-MsgGUID: FzSmdCbGRSq8R4gHd8Yy8w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.19,280,1754982000"; 
   d="scan'208";a="191698524"
Received: from lkp-server02.sh.intel.com (HELO 66d7546c76b2) ([10.239.97.151])
  by orviesa004.jf.intel.com with ESMTP; 04 Nov 2025 20:20:48 -0800
Received: from kbuild by 66d7546c76b2 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1vGV0e-000S9y-33;
	Wed, 05 Nov 2025 04:20:38 +0000
Date: Wed, 5 Nov 2025 12:20:07 +0800
From: kernel test robot <lkp@intel.com>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	m.wieczorretman@pm.me, stable@vger.kernel.org,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <202511051219.fmeaqcaq-lkp@intel.com>
References: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=W8yWVUdD;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted
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

Hi Maciej,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on linus/master v6.18-rc4 next-20251104]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Maciej-Wieczor-Retman/kasan-Unpoison-pcpu-chunks-with-base-address-tag/20251104-225204
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman%40pm.me
patch subject: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
config: x86_64-buildonly-randconfig-003-20251105 (https://download.01.org/0day-ci/archive/20251105/202511051219.fmeaqcaq-lkp@intel.com/config)
compiler: gcc-14 (Debian 14.2.0-19) 14.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251105/202511051219.fmeaqcaq-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202511051219.fmeaqcaq-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kasan/common.c:584:6: warning: no previous prototype for '__kasan_unpoison_vmap_areas' [-Wmissing-prototypes]
     584 | void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
         |      ^~~~~~~~~~~~~~~~~~~~~~~~~~~


vim +/__kasan_unpoison_vmap_areas +584 mm/kasan/common.c

   583	
 > 584	void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202511051219.fmeaqcaq-lkp%40intel.com.

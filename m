Return-Path: <kasan-dev+bncBC4LXIPCY4NRBN7EVDDAMGQEX5IEJWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5069BB7E190
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:42:13 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-62f4f7d7501sf2622381a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:42:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112906; cv=pass;
        d=google.com; s=arc-20240605;
        b=WseCvaTN+ofMKkYkDcM4OVrSllJ1WIZbmJzVyHhCpAPIOMnEBoK//oBS6KxYRQhX6h
         LMqwZ2k54eQijn2nbknZ97L1tMYDNfYFttbxpxbx8jQnE8ZLBpxcdyE5dd09zeihzd6l
         lHowEfUi3706emo3PS9KVVV2GPdxkTPnmMb8lV4GUCc8GQKv+58nyMcR0p2nIBilXhuK
         MNpjoXYWVY1GEkvqu/x7cAaAo7eLj8fG9dqkGVNY1dStMUQqyy/mr7BkbwRkhc1vGduz
         LvAU7+AFGw9YW6N/MBEabD2YqsDDcrYwms4eeE0oylJbAgQW8JnP5rzsBJ2oLFkijzyq
         LyxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mnGwWr1DS/MV4jl5ohUvg/TQND5YvloSi1hHeIi1yY4=;
        fh=tCr+xHUZEvkFdf05YLnbBVzrdV2I2H8eiMja8wR/2ow=;
        b=WcGDo0PHrpQppyOYX0g4xbYhDLoLOuW4k2j9GPa6ov8xEtSHQgB0xbcDXP0M6apnjZ
         fI8gqrzmgnZQT3k0tYCYQvgOsD4UGV8mG9GAq5Zge5uFf3bQ7UmAUuNjlWAQxY6UmHNw
         NUheoXDqKZ6PlmnWfmHK12nCn3AX+raMQ78b34ieasvePB+FFr26zcoBEJxOvAAaFw6a
         t73grnpPdFqzReQd5y0Rsi0opxbB8aCkg6GuA4Qtpl01Qrmnxya4GaNtGHhGk7LOYJCW
         0jGCnkF5ZFxbD8VMoLJuDOpI3LKf2K4Xv5VuS4ImDSzo93MrDWSgpWluua6vsqr2R3Tw
         2x1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Q5G4s19U;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112906; x=1758717706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mnGwWr1DS/MV4jl5ohUvg/TQND5YvloSi1hHeIi1yY4=;
        b=nJB2h0Vite69PzvAbIg4ejiFB+/NI2xASpBvrF/wGXLuzupnWb/XN4bKVeWzXiCP3N
         8JDVVZwaxNgNsLhKVmTeLH2hgjs0K0mJgSy+t1qc3+0tjp/f98D58IUaD/YnXVcxu6xj
         zUoXgKMaZ2p+COvvKy4XNo7zUGiMpIlUiXrVKykktXHPPPOpoA8CozOiKY0tHzvld0pX
         b+W5H5EoLE3hOFrgbPVFF20Q8sSgfFGJhcb6oLZ0AIMCO3P30GgBc/rjOga55S5f6uob
         tPM3CzIkICXZjTGygzc3BHj3tcY74ATJKaekP9F4fK9GqDV8SG/trP7/sR1Oqt4jkQzh
         9LbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112906; x=1758717706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mnGwWr1DS/MV4jl5ohUvg/TQND5YvloSi1hHeIi1yY4=;
        b=u8zDZWJYzlRHc0J2HxIc7tcfalij+ZYeZ1xJ6GUaly7e8e+x4dEqdwiQwx9qpFuGYu
         qST9pZAEvbk8zFIsWqYUBfROiiAOuRoAGS03n0cLcqt7S/fajn4p80zlTjFYlBEXySZ8
         kJk/cPPT+t1n5B220wGQO4aqbOtlKwW0WFgt2A5Gp0UCfaVK0Wytta4MZuvqE1SGoiAy
         IZ6hakHeUvRAH4hkCYexHVTFVm0mhnh8sL6pWy+57IjVjYLDJSQS9eR/kN4jFK4PZJkO
         qVPY8ztJ1LMh5/m1gM0LFC6pVDfzg6Vt+HgKaRtbReGSNp0qIsLbH/qeOJrS8Ds0q9UV
         w5BQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRxv3ISGyxOEdjcSlLjTv7TmUvBnYcGvKjsu7Vxg+smZnksB2RGe/Z5+otIQ8URrJFeyYgjA==@lfdr.de
X-Gm-Message-State: AOJu0Yxs5h1za28QmT0IrXJ9TXRb8IMAEM8yG0nROYhblNXiABekLDrX
	NAS1pmo3Q32mduScohttOsTy7NzAoZqvoFWaE4SParerLNxjKT0rMAxI
X-Google-Smtp-Source: AGHT+IFfwqF9dhNRxvtcmixIoQ2QLe2Yv2dPJXZTCJJbZg7l1dFiGxDryt6DRpJ/6JbGpzWih3xqkA==
X-Received: by 2002:a05:651c:23c5:20b0:351:8d16:d0bd with SMTP id 38308e7fff4ca-35f64c13b2dmr1448031fa.19.1758081592177;
        Tue, 16 Sep 2025 20:59:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5KqPSABlUHGwGcAI+jbtn8vWZqJXBPGvhit6eOhiEykA==
Received: by 2002:a05:651c:4405:10b0:336:c2ac:9a7e with SMTP id
 38308e7fff4ca-34ea8ce8974ls10237111fa.0.-pod-prod-06-eu; Tue, 16 Sep 2025
 20:59:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhktQRdZ+cCSwyjBVjrbQLb78eFhYkfw4GdL3BstuvxeMIxAAQ1RH6IllAOHsgl4wnBCvQR2KvD6Y=@googlegroups.com
X-Received: by 2002:a05:6512:6382:b0:55f:6a6a:4956 with SMTP id 2adb3069b0e04-57799cbb5a8mr139076e87.13.1758081588833;
        Tue, 16 Sep 2025 20:59:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758081588; cv=none;
        d=google.com; s=arc-20240605;
        b=UB7sclUVyMcUV2Y/0JjeF4mrb1qsrB7g3iT4srf2ye9IkOLWmf5SaRUIv133HMj63H
         Tq6uMoAWwBtt+ySJQq9HGXW1HYRnHCMtjApk8Dce+RCszKZR4VQwDbMnnOu8rxcphuFP
         /icD/+KlN6P+fPFPma5xKMHN8gOH0NIv6sQeH6KYS7XvmLCy1r1VeicSyfqHclWurRvz
         g7xD/SHAPS3R8R1pKa0Ne+bElIU/IMwAqZph3sgCwdoZK6HPQEZoflVsAEYn4p5bomVp
         8O6xQjRdZYJ2MWGLaui0a9XQDNzGsycyLhBUr9Fysund7O4e4KoSWLjvwHSFB8o4oHP5
         MeZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qxH3ebGI96ZajPSG4F/6sPmWjW4W9BFD5gYTw4M5JDg=;
        fh=lYa0FG45bwqSJAg0l7nL5e2519l1C90YKv5AyQwXbVo=;
        b=OjGLWh5FhzMnfC84miKSS6PMReWQoG6UggCRP8pPZ/Z58IvlayFOnOqBg9+QNe77NE
         P7GvWGVrb/PKUWiDcE9Y9gJDtVKVqkkGCQfX6m505GWeYMGROqFGFkvWwRTwgQ8s5bzN
         yxlFnW+hXCwqwjA9nqT2I4SRFkFOcWH+DzkOMgueDnM1fKOjVNUhs0lprBRLc6Um5BRq
         shYiibzObLzDL047KwMado3jH8Fl/eSi9XB7WCPYh/3GjQEbqRUvskH22gt+WDfLJ4Oh
         vjdni36A06qrDP9fIHMYxaauzukBcpXnm5NKJmqU/ChzUqGzQZg/dzFNQ2jmzCMf2uDj
         XjvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Q5G4s19U;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.17])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-57076e579f8si260591e87.2.2025.09.16.20.59.47
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 16 Sep 2025 20:59:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) client-ip=192.198.163.17;
X-CSE-ConnectionGUID: M0BHgnr4T/ymxhKFowlDnQ==
X-CSE-MsgGUID: M5uC5PHlS3SLe3sFR/pw9Q==
X-IronPort-AV: E=McAfee;i="6800,10657,11555"; a="60305018"
X-IronPort-AV: E=Sophos;i="6.18,271,1751266800"; 
   d="scan'208";a="60305018"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa111.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Sep 2025 20:59:45 -0700
X-CSE-ConnectionGUID: 8r1RW9JuQCOoNSWzEvSMaQ==
X-CSE-MsgGUID: 7cId5LfgQUu8YUrX2ncqBw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,271,1751266800"; 
   d="scan'208";a="180266969"
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by orviesa005.jf.intel.com with ESMTP; 16 Sep 2025 20:59:38 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uyjKS-000127-0B;
	Wed, 17 Sep 2025 03:59:36 +0000
Date: Wed, 17 Sep 2025 11:59:20 +0800
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
Subject: Re: [PATCH v1 03/10] kfuzztest: implement core module and input
 processing
Message-ID: <202509171131.vod7tLWH-lkp@intel.com>
References: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Q5G4s19U;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted
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
patch link:    https://lore.kernel.org/r/20250916090109.91132-4-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 03/10] kfuzztest: implement core module and input processing
config: x86_64-randconfig-004-20250917 (https://download.01.org/0day-ci/archive/20250917/202509171131.vod7tLWH-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250917/202509171131.vod7tLWH-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509171131.vod7tLWH-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> Warning: lib/kfuzztest/main.c:46 struct member 'num_invocations' not described in 'kfuzztest_state'

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509171131.vod7tLWH-lkp%40intel.com.

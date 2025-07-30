Return-Path: <kasan-dev+bncBC4LXIPCY4NRB4M6VDCAMGQE2OVYKUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A899CB1604A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 14:26:46 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-ae0d76b4f84sf618759666b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 05:26:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753878386; cv=pass;
        d=google.com; s=arc-20240605;
        b=XdsTGzyQpRhneh24x3pgBa7ozc8YU2d2qzwIYQtzicIj6BTFqxHH5Dre37FhSN41Ji
         WDhtFOcjDRRHiwB1lHKkL1eUVoqqZxDc34ADSsWmL+T9xM2wTzpcEBfKgDZQVoGA+LmW
         XNxEDJFqM36LIUJO0LuIcvpUM91Fa4z40mIdikrwcYo+UopIBGxW9pMk4Ehmwa1Mn8xH
         qvcNNStB9rYn27EPK75Vq2UWDVfTrIjtBTF3mLYByzvcqN7XQjhFMltVq8SUGLMqT3+T
         QGRwm9O0jo3tQmFWdLF5Vx/7pAb0EEeII9C70Zpb5c7iRrkXOTagm2B9XASxLffJl4pa
         C5Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0+OxSPKJmsBbSueRxN5wgSIYUg13W6WvMhqbw69qehI=;
        fh=L2BZXR2C/HhYkTMLPRikblur7GHkf3dn3qeKXBKwBp0=;
        b=SRfT1VSXB9qgVOJNScyaUsIiJBMkj+hzJ+9DlDpPKvVylBl+Pl8GHvRxfM2dIbaAGo
         pZZ/FcNPBkCLqxIqHypSTq4spJeqISd+dY1dspbvc6bFZkCxjBPL+vTXRpkaVvgNW+hy
         xgpmlurLZbsWDHg6+tgIM1/P5Z0k7QYPTC2IHq3svsPjxwsLLFzHm0JCngF7+uF8kNyc
         4aBxNSiZ02086B1+QLt2dVkxp83pmucsknnv1f/45wZDK01GcGdDjuYImf9xEp+4R0j5
         VFgUOea/XGZTkjjdqTRZuqYUNW6Ahzc3KJrCZLkNuHcLQkvPtu4abgxxXkwSRmZ3yW6L
         LjfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=iB8aGXNy;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753878386; x=1754483186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0+OxSPKJmsBbSueRxN5wgSIYUg13W6WvMhqbw69qehI=;
        b=p/eBe0OMa21TueEcZK5AOTbrOnALcNelkyjKTdVCKWHJWlBVtV4P63P3+WlOc5Qjss
         RYkMO+56LKTOukCGczA9wGMVE7L+c90Dw4US3HR5VcFHhTtRKKyEIyAt1ioVyQVWHKs/
         cHapGRxuGl0qpza1mn3l1Xkxpdmu9B8dw7vqwvrYumZsJx4+YX69p3C5tW1xMpTO20EI
         HNgKt3WWfc5FkcIwhRm5JFSqqQeOW0MzfAFWKa7wZB9M8WauFLMu4sMTOnFp+5J1FuN5
         312mpSrp+AY6S5dL5+qm0v5tsGDf5a/qjwZlnwQmT4CyJKzM7WttPTuldjE6OXCeWJDv
         sAVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753878386; x=1754483186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0+OxSPKJmsBbSueRxN5wgSIYUg13W6WvMhqbw69qehI=;
        b=UgCkPkcnihHrPL5rcqcXMYhyHPDy3RykGGYjTiqVk3L65dZ2Xhh4cfbtYPFdQcQbz0
         hk4ClAV5E1c5a9Io7fdlonC62S+vDb7fHSHRxd4ap2qpdXWvUlu0OVRvL/CrgQ6PVFrb
         KyeiQRQ1PGzipULAMIYlaakQZqJCWWUZ9Z51yuu60kBPFPkTNejeHUmh+hhzMUbGSYiG
         VSFP3Oxp28ysaLo6bwoOC3ybW3erP/IvoFBFGlvLxZXR/8NmYinyoUvEFV+hG4uT6Ka9
         J3s9iCezJ58GLkYvv7qeqfkCeqPXfFoK0GcAKGyN+3P6j/T32Y8ri8PH5TDKIizciX2X
         HW8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7DW05Uz0BqUO7H+yXyhohhW39q+zGaQSIEaoObF06UjrFoQi8AmhyO+5BwvT0rZ8qpy0YDw==@lfdr.de
X-Gm-Message-State: AOJu0YzJJHZDN3URr+T/JgcpWmB0U1i9U4AFkQFtq6QSadHbmN4LSCCT
	WwS62OJf+FFgx7wrZ5uQAZ0tWKeMtgQKVOd5QADCsS5g1YTi8dkybc3x
X-Google-Smtp-Source: AGHT+IG1FCgP6lrmmPTHfxHskamk7DN1MmiDOhA+bCwQpM7o3nF8U787IATpQ6IyI/zfxUIRubsESA==
X-Received: by 2002:a17:906:9fc4:b0:ae3:7255:ba53 with SMTP id a640c23a62f3a-af8fda28fc5mr387011966b.53.1753878385587;
        Wed, 30 Jul 2025 05:26:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe6qlF8OrJgXgFaElPe/NqqK5RCP3GY7w5N1F2ZB5W2YQ==
Received: by 2002:a05:6402:524d:b0:604:f62b:4107 with SMTP id
 4fb4d7f45d1cf-614c0ac1b68ls6742571a12.2.-pod-prod-04-eu; Wed, 30 Jul 2025
 05:26:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjRkNM2/eWk3aNILp42qddYrLkaRBxFb5fLCP9lTfvWW4uZjhsiV27y+URnI8BqyUwzH6NB2V2bbg=@googlegroups.com
X-Received: by 2002:a05:6402:268a:b0:615:8bee:56ad with SMTP id 4fb4d7f45d1cf-6158bee65a8mr2608760a12.5.1753878382742;
        Wed, 30 Jul 2025 05:26:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753878382; cv=none;
        d=google.com; s=arc-20240605;
        b=CBSAX7j3oCbZBEIXkzQiy4PKSAU6OudSVz//v52C1csTv6gk0w+W1CmMd0+fqcNWzz
         XZloJargWnPn+aU8+lYyVPARhctSKp3BfQuwN4meyHhZHT4/5I1QYpBihppppjqb4vCb
         gDyry0TpO4jIh81ebQTj4Z3EynRfIp/AEvxsGgXovzhv/NTLENaDkQVP92A/Artj/aDM
         5falt7f19ApXG1z5FvAP/mEAotY6wXcvk0r9NyDSeouh2o2engovn7iQsoK4OcQdQVMs
         i5IYCAwRK4fypWWC+bARSduADEUYXp3/JvqoQlneCWCWLn3XMdnmYGbYntBoxGiGsVBH
         asLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uVHkEQP3vM5YgPU7qWqNFjEoGqJApn+S6iV1mh2s7ls=;
        fh=/cgQMBJIatGqJQeifegXRTVZ9u6aajGJpaq1AvoqfCg=;
        b=ULPC19UqLeI7AGV4T/KJjGz8psMg7NF1XormoYL4FZohh3ROZyrZbUK7eRQYn617ev
         H087N0JviivBrfSVDvStp1VN4yuYWvUMi6AYmU0fvn5OFhWv9En8MoO3ak03z+dA8HGr
         IYGbKPFqXmiBFJCkTbfpex505MsmQiwEyO8iJARoGKrPvy7GcqVWCte6jFNvfj4y/wKv
         Vx16ciknDu3HD8U1WKfOMDWUl6l9VSgpZej0b2fMAKos9hNDGe1M/zsvw2DEZspQjOdu
         eW2kjTcwV60jnu9RC3Xd+u+i5e+KLN0JWb46UK24y14aSLI9k9teXwxnhJCX0VyfdY5M
         yZaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=iB8aGXNy;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.17])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61589d492b7si43529a12.0.2025.07.30.05.26.21
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 30 Jul 2025 05:26:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.17 as permitted sender) client-ip=198.175.65.17;
X-CSE-ConnectionGUID: FaOqzXTGT7Khec9ODKZH9Q==
X-CSE-MsgGUID: WWSDi356Tz+FflabPWBLxA==
X-IronPort-AV: E=McAfee;i="6800,10657,11507"; a="56142549"
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="56142549"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa109.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Jul 2025 05:26:21 -0700
X-CSE-ConnectionGUID: QsyMguNhTASkZtzr+udzvw==
X-CSE-MsgGUID: vuxavx1ZQKGyIClQO/DVXA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="163427193"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by fmviesa008.fm.intel.com with ESMTP; 30 Jul 2025 05:26:16 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uh5sr-0002ie-31;
	Wed, 30 Jul 2025 12:26:13 +0000
Date: Wed, 30 Jul 2025 20:25:51 +0800
From: kernel test robot <lkp@intel.com>
To: Marie Zhussupova <marievic@google.com>, rmoar@google.com,
	davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev
Cc: oe-kbuild-all@lists.linux.dev, elver@google.com, dvyukov@google.com,
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com,
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org,
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com,
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	linux-kernel@vger.kernel.org,
	Marie Zhussupova <marievic@google.com>
Subject: Re: [PATCH 7/9] kunit: Add example parameterized test with shared
 resources and direct static parameter array setup
Message-ID: <202507302042.9Aw3rrmW-lkp@intel.com>
References: <20250729193647.3410634-8-marievic@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250729193647.3410634-8-marievic@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=iB8aGXNy;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.17 as permitted
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

Hi Marie,

kernel test robot noticed the following build errors:

[auto build test ERROR on shuah-kselftest/kunit]
[also build test ERROR on shuah-kselftest/kunit-fixes drm-xe/drm-xe-next linus/master v6.16 next-20250730]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/kunit-Add-parent-kunit-for-parameterized-test-context/20250730-033818
base:   https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git kunit
patch link:    https://lore.kernel.org/r/20250729193647.3410634-8-marievic%40google.com
patch subject: [PATCH 7/9] kunit: Add example parameterized test with shared resources and direct static parameter array setup
config: arc-randconfig-001-20250730 (https://download.01.org/0day-ci/archive/20250730/202507302042.9Aw3rrmW-lkp@intel.com/config)
compiler: arc-linux-gcc (GCC) 8.5.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250730/202507302042.9Aw3rrmW-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507302042.9Aw3rrmW-lkp@intel.com/

All errors (new ones prefixed by >>, old ones prefixed by <<):

>> ERROR: modpost: "kunit_get_next_param_and_desc" [lib/kunit/kunit-example-test.ko] undefined!

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507302042.9Aw3rrmW-lkp%40intel.com.

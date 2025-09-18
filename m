Return-Path: <kasan-dev+bncBC4LXIPCY4NRBL55VXDAMGQESY2556I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EC34B827BF
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 03:21:53 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-42408b5749asf23266795ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 18:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758158512; cv=pass;
        d=google.com; s=arc-20240605;
        b=TnLtkqFO95NqjW0DnHhwW2QeQW+0Sn/QKubJUCRFfv1d5w0LjhB4csPmPuP9oMDFw+
         8EZ6y/O+dyPTIDaogoPx0WsjS1pEqCREmLc9ZUBswY5ydvcMtjJ6a3DvtEF1bQE3R5Gq
         JzIAZCl16Wy2Fe4Q75wKH5/0bMDBQFVdCOH4Zzk4xNtnLomSOJcdotQol1ud4Om6A5v2
         16wur+KZV+PmJYoz21wSAw+nyqXk7JwteLJ5M/T0hpA8rW0qmQbkvTYCZ7MDwZDnxnrn
         13akEcgyq6k45MoPv2VObBE8vNJzRuOG1CDpDq43hpgNAjTRFDBOng4VX4CXyTk76yv0
         brwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bgqxQL6NpJs79E2FPMQ/RAHgWpNwdmkG90eWpORYnWQ=;
        fh=MMKq4szJ6CvNCV2rkf8yivJkzJ+NVR7V6GrrOrUVRA8=;
        b=I2Rx5PCvQiyaODjorLMxAbe6t/qxaOxOTS6TTvK3PIoxlpwLisldmX6oN+CCAoB+N9
         pBFmPaKPE/QHV8uVQ0z3d4KpFEN+vgs15U/f8BIo+gn6li8YN1vZwzhQ1u9cjDuTCeyG
         gwHf5WAL1AuKX+rx9hsdxDUzGHwjaTF9iN2HEUj24RSgFUgJwSFWDnQCoFUiGHXvQOmM
         A++fymAUpMGw+PK2vRxdARmc7JXkxhniwwd1hoib/Rib6oeTh7ggW2ZSWuAaR/FAgx85
         cSd1Jo4OgkEnsNrX5/fQnfDH9GJcXWmEsQoQxUDDquCIf9qBGQ4RozzHxKOLMgkh0npd
         JVIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="g/qAJ+3t";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758158512; x=1758763312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bgqxQL6NpJs79E2FPMQ/RAHgWpNwdmkG90eWpORYnWQ=;
        b=q+TxFMP1ZXRCKiZM+mnBdWDYwV7yTZILz3zomm3hfuIOEY2/VG47Qt/+7npV7zRLOu
         bwSvxFDnM3ITYJLxiLgHcFkwpny8WDqOtyxHa9QBy8aQXi0fCC0rh706BtV746hSMzd+
         JQ4rMTeh+wCTCs0WcL0V6Ho8VeKsBMJ7luBeP/ZYD869cXFngmpnBWryRokxYPUsZiG9
         BwbbtUIN3ShT5yOf6IRr9WO6Vm2oleGo9mx5yLqHqyb4xTKsciDHTFUf5o48Em8W0PMr
         SzHxIsRydqkTF4CVkfy1z7F7u7Y2HuF/FQQnKDlzA1EVBPLh5cOju4gXG91/4S9RQbRu
         Do9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758158512; x=1758763312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bgqxQL6NpJs79E2FPMQ/RAHgWpNwdmkG90eWpORYnWQ=;
        b=NXO3A2PgcdkPy6Lg/kCc9D299IK8OYhOeZZWq5gSQzbD6bf9uMivQJ/gFQYhQNtM8U
         uS0Tj116q+ldAdrcryGEyWN01QUeIRcci0dIY+n5Ljd7gAQLozg2EnWGUitVGiI2tETj
         0TiZxLp5Ygf3oPrLeCRP46bUCc5Llwb0+1C9kPXJrbNeKSSc32Gdt9hPqdBZzf2z2Jne
         iB6vrQb7RLJGYfman3RqfhTNEcEyDNlt9ZCy0ySfnIJFZgOeIucfKnvQpCTs62TRTz7m
         lRcF6hDl+DTq3aAA+1qKr62h7nWLyivLa0j4hsoHnXLNI1Dn02foV5QRoUgIS5Jtl9PS
         LcTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUczoiuWgxm5cmTofzslbyNR29TdezVsj3npVgsVjEg+eRrFQaXUqxgq3rptaz0lbA4dvy2LA==@lfdr.de
X-Gm-Message-State: AOJu0YwTXkpjcCzWsVAUTRsRCTB3YE59ziIeO+M3A2zDk5zIsPnovjgZ
	kh+NE85nsgz2sx75pus/HkWB70rGfq2ivLj5r1bT9Q6d0GcXTuVqxilS
X-Google-Smtp-Source: AGHT+IGtB8jp5vaMGFuz8zMqwUxSUsEzinqUIh+7WbJbK3D253R8wjn+8RuhSYIdJPDAfs6S40Uzsg==
X-Received: by 2002:a92:c26b:0:b0:414:117d:3186 with SMTP id e9e14a558f8ab-424449d9c55mr21629405ab.13.1758158511793;
        Wed, 17 Sep 2025 18:21:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4kH5dIYJupPuCC2P8TjPzfhdKGQjI4PhLXYqF6kgZH0g==
Received: by 2002:a05:6e02:170d:b0:423:fd48:9b84 with SMTP id
 e9e14a558f8ab-42417aac3b4ls5441715ab.0.-pod-prod-00-us-canary; Wed, 17 Sep
 2025 18:21:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXrEb/MMaT6FWzE6oAmv4mH8qVZWiQU2PT1nBzFWresRbPHnrJ8LNy27UEJJvYydUONoIqq2ctW/o=@googlegroups.com
X-Received: by 2002:a05:6602:f0b:b0:867:16f4:5254 with SMTP id ca18e2360f4ac-8a43eb4ea08mr252856039f.6.1758158510861;
        Wed, 17 Sep 2025 18:21:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758158510; cv=none;
        d=google.com; s=arc-20240605;
        b=JW2Tc8yOC93lSiDdyq01Yh5b3ZNBE0lxrKaRRvoHKbkcClTeIZoZi7qRI7TbRw4kUL
         qAR3CtLhxq3nXb9jFEbDGDvVc4mxaPO0oAq7viHY0xVGbweOFdnU7uKNdzS1Oj8BjUtr
         4qMl15LYmQ42cSE8CHc4W9iutW5lu7iehN11Y9+yeuLuQyWxvQv8virsa0uAsr9Ve0D4
         k8oYyseVtOCd/s8lHcfg4Rs9O3Wok4ix1/pI1YqR/Q4Gv9Ws57rHUZKXohsNEjOQyENO
         E9lXpzHCdbAEzAud2ZJfKjq6LV3mHtSq95P9XPAo1P9GrW/7tM+w6bZTWuKoObX91r6w
         D3hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JL/CRPWC31oUF+ur7V+pUmTe9mvvwo6vPYfeJjk6t5o=;
        fh=Ep9PfZCNUvI/0vsxDj5zZVldyWlrufvmuAi3ZPIef7c=;
        b=eomQZqT7WhLxwkhooQfd0OKEfP6z8G2p1k//VXV2GhnSVGFS6EAIzC4vlwg+YdC3Uh
         bPgMeGFhmAs8k2ngjQqb1InMfivcO0fJffYtz0VaudtpJ8hR/StwWu2/QOAJlFYvUz8Y
         UIW9eaxTqQGDBkp9UZ/seXeBOcEUpQsctgE8n/oyX4WQXIm8dtpwL69AcKM7Kbge3/tW
         tt4O4QdVLgm3sWZeRzFO+8SXGW3afVNjJMb1iAzZhxeedkFdMkByH7B39mpk2V7jYZPA
         f9XaPBw6M7piO3wiY0IVstSpZpzHjS9Wp9DHJqmU231Cpv6Amf9gaqdYky8PDp5Pm4Dy
         vKkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="g/qAJ+3t";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.16])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-53d37e62d63si45202173.2.2025.09.17.18.21.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 17 Sep 2025 18:21:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.16 as permitted sender) client-ip=198.175.65.16;
X-CSE-ConnectionGUID: XCA8r/emQMK0NqOP14MBZQ==
X-CSE-MsgGUID: E6BqYDNaRiu1maz1wNtpvw==
X-IronPort-AV: E=McAfee;i="6800,10657,11556"; a="60627998"
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="60627998"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by orvoesa108.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2025 18:21:49 -0700
X-CSE-ConnectionGUID: 5pkUIZn2Q/6Mbe2PH99Gtw==
X-CSE-MsgGUID: wGtr9egyR3ugRJzUk/HTmQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="175477862"
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by orviesa008.jf.intel.com with ESMTP; 17 Sep 2025 18:21:43 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uz3LA-0002cJ-1Y;
	Thu, 18 Sep 2025 01:21:40 +0000
Date: Thu, 18 Sep 2025 09:21:23 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com,
	glider@google.com
Cc: oe-kbuild-all@lists.linux.dev, andreyknvl@gmail.com, andy@kernel.org,
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net,
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com,
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com,
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com
Subject: Re: [PATCH v1 03/10] kfuzztest: implement core module and input
 processing
Message-ID: <202509180855.TT6uHpiC-lkp@intel.com>
References: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="g/qAJ+3t";       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.16 as permitted
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
[also build test WARNING on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.17-rc6 next-20250917]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20250916-210448
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20250916090109.91132-4-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 03/10] kfuzztest: implement core module and input processing
config: x86_64-randconfig-r112-20250918 (https://download.01.org/0day-ci/archive/20250918/202509180855.TT6uHpiC-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250918/202509180855.TT6uHpiC-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509180855.TT6uHpiC-lkp@intel.com/

sparse warnings: (new ones prefixed by >>)
>> lib/kfuzztest/main.c:65:15: sparse: sparse: symbol 'KFUZZTEST_INPUT_PERMS' was not declared. Should it be static?
>> lib/kfuzztest/main.c:66:15: sparse: sparse: symbol 'KFUZZTEST_MINALIGN_PERMS' was not declared. Should it be static?

vim +/KFUZZTEST_INPUT_PERMS +65 lib/kfuzztest/main.c

    64	
  > 65	const umode_t KFUZZTEST_INPUT_PERMS = 0222;
  > 66	const umode_t KFUZZTEST_MINALIGN_PERMS = 0444;
    67	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509180855.TT6uHpiC-lkp%40intel.com.

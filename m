Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKOYV3DAMGQE4ZXMBYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C3D32B83379
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:52:38 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-78e30eaca8esf16102216d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:52:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758178346; cv=pass;
        d=google.com; s=arc-20240605;
        b=JlmnTB4zJ3kAmiObrz815dzUbGFB26xIk0dMhTEnHPkYwaEDkWINvSqmGOcxpC94GA
         VdjdYo86N96NFDzJy57JkpqdbfSNYJ/p8uc4SRSnUEawqI7LtlpNlh8dF70UKxCWS1Tq
         fAlUDJ4HeVj7xDo6Bw2Lg7y/6JrvpQCb+cAMGYBQ3MCQCGxJHSzrw637j4JeuA2JbA5X
         +tOe2sZhJVHRlcgZjJPBAAuWDK0g80PjF6FBO4+lFskQ8qdnEQshAZHoAIMLOQ4TTQja
         gcl9K2Qzdk9V6HDyFW1Nbvot8XT4PL4YuljZAuj4VIQWc1248m9tqI7lIb6Yhq5M5iMQ
         LuVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z8DCJcqsounfHn4uMQIYc1hAHy3jy5HhBCqBUYpH0Bo=;
        fh=OdBmecMZUcZvNCGSl1v7B63Yi07pouF5hmMOq8yEXgI=;
        b=JUnjnL7pcS09S/oY1VgrE1yxMWiPCmyHaTJ0wt7RY5LWIo8YzHP1KTFyE80y2Hrx/F
         tvdbAegQv0y4ZzTE7f2pjfTDnqTCd6buMq/FGmMTo2Mckjeokmfta2XqCMVlQxX74vo6
         pv031Bz1QNpp6h3d84moaPI4JN9X24hUsf03S3QfSy2G12Fi+dnBpFzNNIRo5JBS/MtH
         8fMHLJiiWakKj0o1LMCVYTqPPGhJmTzoj6pDX5WcKntBuX+dLlePVjLfqEV6ekQYd8VO
         ozywyJilVVSNMD88Pzk1AgXgRAKvp3SaoqCn2zc45auRgpAR8n2hHzBEeJBCxicXki9C
         8bHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=htshKVTl;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758178346; x=1758783146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z8DCJcqsounfHn4uMQIYc1hAHy3jy5HhBCqBUYpH0Bo=;
        b=GSAyvZ1MCakQBODouM/ZciBsl7wMyT9shY9H2T8fs8zgVoxuJGzQyoR5Qv4pXAfuHX
         paD69mrJYKXoatEaOqEkyzeoC+uNUG1VdX3hURjpnyhU0Pv7j/GeaClq+42p/jQ4cR1u
         PhaKQwwStDAdEl+KbKP1w7e93ThphxqK6IHnWofCsUT8J3GaDN57p6M/KL+NV89s5WgM
         VkP/ZhIOXqa2J6aXooLaolMCVaLPy4u2OCPSKsRJbDnRTFCo6pHumM/t7vLEELElC0N8
         vC1rqyY4azzNzJ8odHU0AayFywmBwA57KBRa+nRk1eDxCFq5yBgmUVrKeMbC2WbSAfQn
         fGjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758178346; x=1758783146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z8DCJcqsounfHn4uMQIYc1hAHy3jy5HhBCqBUYpH0Bo=;
        b=C8scjf2ISNBsIAapkfYg7ucSN1/rkNGAxWUCey6o/YHRxM1hhLShlqL5LaUwCbaP/W
         v6fjyxuxxBVX3pRNK+CYW2flrsFBzitB6+PIPpqV861GKJXjdgh2DxGW/VgeANAWMhvO
         SR3Xw7ZOb08CZd0RRamc5hAp3kO+lBtkCUte2RIlfrDeFr5vEeGGIrxXjaRkh/tWRmKY
         W6SbtEVX9ogzutS7Vkjk8f9+xNIIPPcu55OPHXlTB4BK1P4J3GYQ4/ClFI9FE8DO1mDM
         Js6lifIdTC6zbtNBI7vLdpkpTSZoMz3tfGMCerMw3Aayh79fxHSBV5pu3iW527iKGLp5
         9Zeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWq+2qUOuY997exY+rvqMaUBCI9vXmjPuBOjRTpf9zDkkZP7two2fRL/oPUNUcwVAkWRTjhQ==@lfdr.de
X-Gm-Message-State: AOJu0YxvY8dxxOPwaZVqCcUcLl6R/m1DLe5TfdNpK6/zsjIxiJJNhZ1c
	yuZtB03WkK44t/sHcAyhAm7vsxbE+YGpz7eytxdK0v0K1NgWvgy9prfO
X-Google-Smtp-Source: AGHT+IFCyNjXW6K4X9AY87GnKjT5IHiDbbNBw/S00It9VERNE1Cz4IkdeaT2lU8zb+l8nIyqT/xDAQ==
X-Received: by 2002:ad4:5dc9:0:b0:77e:2375:4179 with SMTP id 6a1803df08f44-78ecc63160amr51896096d6.12.1758178346194;
        Wed, 17 Sep 2025 23:52:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4oozrmRHWF+ODI3dkxb38i1A13reMP7B/ZxZv2aXU0rw==
Received: by 2002:a05:6214:ac2:b0:76d:632d:118c with SMTP id
 6a1803df08f44-7933bd33fa0ls6064776d6.0.-pod-prod-02-us; Wed, 17 Sep 2025
 23:52:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXC165CTp3ehLFI8icK0eYqAeBiDgpnYoFLByJB5B3YdkukZMGcaAelHmiAIu6ig/mKwgyDme8wpoY=@googlegroups.com
X-Received: by 2002:a05:6102:3592:b0:553:6fc:db4d with SMTP id ada2fe7eead31-56d6d57bbd1mr1651392137.31.1758178345172;
        Wed, 17 Sep 2025 23:52:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758178345; cv=none;
        d=google.com; s=arc-20240605;
        b=DKU8gxguyi8Ye1VLaCMX3VkuOfweREhG8aSzoC6MRiz2ERWQysqJIVZ7kSOWkf3Br7
         5Nr04MmsT1G0CSUuoEfn5A4UqZkS4zDOHf+NLgMa1Djdq7qHtEOeu9tpW2Nl++TAnVxp
         zgzQ+FUnqcQX2ClGfm3hbua9lPKGxpEs/Tbtw2Pu1OcWGndiGE84xsGRbEtp0MTy6DCU
         YY1yH3HLwjBT34vYm60VYURlcOO5Q9lcl51N5RIt7LRQhwORTSC1aimpnihQCbEp78Wb
         ltvJHGR+3nHGaVAtOBqr28pLnveKRQbLeCgUlD00T9t1pJSpVmYE8bQBPRe9IiyueM0I
         nJ4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SaNIHYQ/DPl2MmUXlucY+XCYwvRuaIbPphjKYBOBrbc=;
        fh=Ep9PfZCNUvI/0vsxDj5zZVldyWlrufvmuAi3ZPIef7c=;
        b=GGaBO0qldM6NroODz+AC52UsM5Z7tsY1pFI4Iw7ZdtYntYZUKko367KNUS3b8d9DiF
         iwV9KJRyxlqfLicF5OJMXygUCwPdwc73FzBIUo7x7Eh534jcESDR675fL64Yd33EyKHG
         eZK1DqvvzyKxQW9z9FKuvr9uVn6fRo8WJqH38R339vqqVeG1YRJw5ce9tFJqIz5onN0T
         90lLYwzvzrpxki3Je4mfD05ScSlYDZsErmdBeKHQfzz8qQZ8i3qtVm/FU/LCSLjqRRdd
         7juvOGqMNfH/LvPCLnpEDNAYNaZYbz5wdvC6JakFOAnz4qrrOccBSwWePnEu9vLvy6wS
         NP+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=htshKVTl;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-579df4cf919si77316137.2.2025.09.17.23.52.24
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 17 Sep 2025 23:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: WkezMdjjTpmJd4X8jj5DXw==
X-CSE-MsgGUID: nLzxJ62QSv+UqNhOS194hA==
X-IronPort-AV: E=McAfee;i="6800,10657,11556"; a="71925022"
X-IronPort-AV: E=Sophos;i="6.18,274,1751266800"; 
   d="scan'208";a="71925022"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2025 23:52:23 -0700
X-CSE-ConnectionGUID: Yc9nWOABRheo1JBzKZ9rOA==
X-CSE-MsgGUID: t2vfJQZQSTmlR2nJnRGstw==
X-ExtLoop1: 1
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by fmviesa003.fm.intel.com with ESMTP; 17 Sep 2025 23:52:16 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uz8V3-0002ql-1m;
	Thu, 18 Sep 2025 06:52:13 +0000
Date: Thu, 18 Sep 2025 14:52:04 +0800
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
Subject: Re: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
Message-ID: <202509181410.XN0MIpCh-lkp@intel.com>
References: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=htshKVTl;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.12 as permitted
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
patch link:    https://lore.kernel.org/r/20250916090109.91132-8-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
config: x86_64-randconfig-121-20250918 (https://download.01.org/0day-ci/archive/20250918/202509181410.XN0MIpCh-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.4.0-5) 12.4.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250918/202509181410.XN0MIpCh-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509181410.XN0MIpCh-lkp@intel.com/

sparse warnings: (new ones prefixed by >>)
>> crypto/asymmetric_keys/tests/pkcs7_kfuzz.c:15:1: sparse: sparse: symbol '__fuzz_test__test_pkcs7_parse_message' was not declared. Should it be static?
--
>> crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:15:1: sparse: sparse: symbol '__fuzz_test__test_rsa_parse_pub_key' was not declared. Should it be static?
>> crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:30:1: sparse: sparse: symbol '__fuzz_test__test_rsa_parse_priv_key' was not declared. Should it be static?

vim +/__fuzz_test__test_pkcs7_parse_message +15 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c

    14	
  > 15	FUZZ_TEST(test_pkcs7_parse_message, struct pkcs7_parse_message_arg)

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509181410.XN0MIpCh-lkp%40intel.com.

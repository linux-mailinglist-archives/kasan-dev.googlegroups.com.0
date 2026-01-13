Return-Path: <kasan-dev+bncBC4LXIPCY4NRB5WWS3FQMGQER26WYCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C58DD16435
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 03:18:32 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b6c274d69sf4028961e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:18:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768270711; cv=pass;
        d=google.com; s=arc-20240605;
        b=B+8JOz7jZCdpno+PoRtTyeRrqkNgZZXV+H4Vca6MmE0GBEkuGn2BTObDpoGnIpT5d7
         4nt4NLWfgeLYp8ERWOqyCoVSh848+bdLiyeCXYdqvnjdH6wvrhl2QysSK4AXlHZvAB+C
         lTRh5ZBoBdhNmRAemm7yO78EVehY7SXvexiSsB2QOtydV3gtTZiSGIkzVu18m06nFnhE
         S9P5stxv9Yih7DZ3VDGqqikypqcgZFt+VC98YXhOh19jQiDXK1l66CrwxL85CplIQgrt
         T54aLswku12JY2GZ9OU8nb8uhYcIkHhItvw9/Gr0Y36slbuzwKtcXba7bt6f4zugB2hY
         5ONg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nUwhMX6INST2hZcpi5VxnBdCt4g5SpQt4denr1Dz588=;
        fh=MWD2ca9/+XbCIY6Fx8j/v2X0tnE9fQ1xIcaJcB6diAI=;
        b=hn8ACIBWB4jOaBIF+yQLvmVz5uqhH3AQhnEwT1mPh5mzP9yRTZ5CZhRzTuN1nMgzLA
         sA2Fe2BSkFNij4uob0a5N5ZrYZyD9xf+QlBOZ2t3r61ec5k1ZbS7yn1dB4+6YaYXNNaA
         F6049BDGHSdKsAoNucddyBso+h01FDOud13A3X05N8ZsF1asHbRpr5l4FvD/BXHIJcJh
         GIyfOCE2Pn/5gYZ8XhKOY2iIzf/ZI/uh8dfAFtYlVE29Zrm+WB0gH7vVOaWBz7UW6zed
         YR8t3zE87+ELx+GW2cV0uS161furCPAaBqgELtJbE9AKjitfV29F0RGpo+2n7vWVctN1
         1U5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DOW9sLSp;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768270711; x=1768875511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nUwhMX6INST2hZcpi5VxnBdCt4g5SpQt4denr1Dz588=;
        b=coOfrjLwUOd5e+iNiWiN7iIqzIT/Dc1UVAouiSzAaroQ2DF00LXCqkHDDzoE/6A63q
         e/qKSwvUMzh42v+bicqBGkxp7R0gtJgkH9ePEayzkHe3KDZ9RDaLF2vQEzPUKtLH54rb
         WvMiYRhUkvtXuZoG7RpBpFiczZeHy2n3IAeTvPj1wkgVILfV4ZtEpZoWnIfy4kYecYBM
         UvIARNQo9y4eLjVOKoO4QG2e68Xhr/teqCi4qmE3p6iHjV0zIJHysgmJvJUcr62XsoNC
         jcx5leNYkFiIrGvH2huB2aAbDm+cMlYfEcdjf4Rwt5dLKlqb7ZCjqkzlX54S9YAaKSsL
         hvJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768270711; x=1768875511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nUwhMX6INST2hZcpi5VxnBdCt4g5SpQt4denr1Dz588=;
        b=DE4k26MIuN8nkXnbggydlQWV/jGKHzW/9ajZtGqSEma8hCJATLuIhCfgJbTzAJPXvh
         DHMcNUDEJup4QG1IlsVGo24Oij/7uS6xT0ayAxX0aRd0/WCc3RoU/sAiVklQlK2MR7sY
         YIdOqKjHzF30pJ2FpodWPEU5rI3LdnKNeIgPke5P5p2jD2xeljwCEu/YFkVXDh8EQAg4
         uEAu7W4ar5U8ChZnMpE4daNCw60f66S/wwilZI7dDhkfko7ydf5uFTAvs2mSTaqXslYa
         wpPRmTArI1ZaYywtcsT+JhaWC4mCloSR/0R5qsoVE9QClGcXpn1PUO8qOWcOL3ksozSN
         DC+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXexUL4gXYIlErXfAONblUeJEHo4AMvTRyHb749hj3ZU7nFbY2m/y2MrfpJKTYAKphbZ05alw==@lfdr.de
X-Gm-Message-State: AOJu0YzdMF6a2kmA4aPtecSR3vynH63yU2mCQ8g14LqTn1segojDRElH
	Bf3BQ197yVE3dXSYEUwjntZIWEEZKu0Ev6hLYCaWsv23e0Y19BktDrVl
X-Google-Smtp-Source: AGHT+IFVHXQ5Qp7Evrk0Sqf93ZYAw3GnrFHc8Ho2LrPFqdJaRa5MA0zFQiMIBO2D39gAKi96fVEXNA==
X-Received: by 2002:a05:6512:308a:b0:59b:834d:fddf with SMTP id 2adb3069b0e04-59b993faafbmr407512e87.11.1768270711398;
        Mon, 12 Jan 2026 18:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FrslZgrQoS7IJU5kO34fZiwiJ1KYMufkfyqKhzNo1VqQ=="
Received: by 2002:a05:6512:158f:b0:59b:739a:3ae4 with SMTP id
 2adb3069b0e04-59b739a3bf5ls1124292e87.2.-pod-prod-00-eu; Mon, 12 Jan 2026
 18:18:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVlaWHW8Iz4qtzOcGqOHxu+mDaROVdl3jl3HgFAqlqtXmx69MAVV3teqKjQWqMgcFu1hYm1pUyqHn0=@googlegroups.com
X-Received: by 2002:a05:6512:3d02:b0:59b:6f90:bb9b with SMTP id 2adb3069b0e04-59b9941ff33mr376427e87.19.1768270708510;
        Mon, 12 Jan 2026 18:18:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768270708; cv=none;
        d=google.com; s=arc-20240605;
        b=RY+stoWpXQwLkl15Lo64HCGOQMw3mmkyADgnt3sfEnOXGVQ+m5RQOG/lQJAmDnWqwn
         WqBFpwA5G/p9CO7HJm76jvtuh94i9csKVwbb/qSH7+8gaTPa4F7ByJxHskhmLzlk1dy9
         uaQwr30czrNR3CdTMBM7llYIZWWeH17wR7GGckDZ7ZDlzrKiD3qUI/Bl4btNO3/AGEWF
         etIa2X8aRqkKZMyL2kMXRiZEjTF3dnECnqtrPhjp/Fy9LFEMI5gqCoihOx3FwSjdrBU+
         ImnGwzYneRsxzwsxjWMxp9lA+AvLnisIkhr+jeIGdMsfuVhMHxVUj6Uxgvo8s2DQUzme
         mugQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kkD5qCwWzUrMnmGuo89WDfFeh3wSCT7fMQ6b8QTXbDY=;
        fh=pt2KBZSDlyqL9srQ4blYv+pP+sWRT+o3gaZU8uTWFwk=;
        b=lZgiaxihsvdfHOHT9dWOqTMG2ZRyqGG4G+4ZSbwbIlgVxKbhJiuASlV4xzsXgSuDt8
         6KRqSiJaKmkjg55ecKQOy5wUeIVPX9tW0plYPRucJcBp84aLdolFrlPp42pzESHQfQLL
         QXqyVuYdGmwovWCCgfTzaKjNfCklurkKK4dI6zG0IdDRuMj4ia5phDZLlqkr/TD1zlH1
         Job3B1D0A18P6rCqwh7zZs1AvomLsVZkHWL3s/6LNfbduNPLBgg++EmM8x9bmgopfr4d
         pgdBp6f3JNfgtfCQR5DpxAgvkDkmP5CJL/TTZSrFnttA8aeo3iXOQqSBgs6Ou3fcIMFa
         ctHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DOW9sLSp;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382fc3b94f2si3009321fa.7.2026.01.12.18.18.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 12 Jan 2026 18:18:28 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: MyOP+oAETo2Zltq5mUkwUg==
X-CSE-MsgGUID: hCHY6oYdT8GNiorHtuOhkw==
X-IronPort-AV: E=McAfee;i="6800,10657,11669"; a="73184122"
X-IronPort-AV: E=Sophos;i="6.21,222,1763452800"; 
   d="scan'208";a="73184122"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2026 18:18:25 -0800
X-CSE-ConnectionGUID: wNJWnrmuQbep4LDKovdUiQ==
X-CSE-MsgGUID: sb3tkOFtS0Gig7MufspTXg==
X-ExtLoop1: 1
Received: from lkp-server01.sh.intel.com (HELO 765f4a05e27f) ([10.239.97.150])
  by fmviesa003.fm.intel.com with ESMTP; 12 Jan 2026 18:18:19 -0800
Received: from kbuild by 765f4a05e27f with local (Exim 4.98.2)
	(envelope-from <lkp@intel.com>)
	id 1vfTz6-00000000E68-3fEh;
	Tue, 13 Jan 2026 02:18:16 +0000
Date: Tue, 13 Jan 2026 10:17:53 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com
Cc: oe-kbuild-all@lists.linux.dev, akpm@linux-foundation.org,
	andreyknvl@gmail.com, andy@kernel.org, andy.shevchenko@gmail.com,
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net,
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com,
	ebiggers@kernel.org, elver@google.com, gregkh@linuxfoundation.org,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	mcgrof@kernel.org, rmoar@google.com, shuah@kernel.org
Subject: Re: [PATCH v4 4/6] kfuzztest: add KFuzzTest sample fuzz targets
Message-ID: <202601130828.lXrl0Ijb-lkp@intel.com>
References: <20260112192827.25989-5-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112192827.25989-5-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DOW9sLSp;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted
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
[also build test WARNING on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.19-rc5 next-20260109]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/kfuzztest-add-user-facing-API-and-data-structures/20260113-033045
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20260112192827.25989-5-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v4 4/6] kfuzztest: add KFuzzTest sample fuzz targets
config: m68k-allmodconfig (https://download.01.org/0day-ci/archive/20260113/202601130828.lXrl0Ijb-lkp@intel.com/config)
compiler: m68k-linux-gcc (GCC) 15.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20260113/202601130828.lXrl0Ijb-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202601130828.lXrl0Ijb-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> Warning: samples/kfuzztest/underflow_on_buffer.c:24 function parameter 'buf' not described in 'underflow_on_buffer'
>> Warning: samples/kfuzztest/underflow_on_buffer.c:24 function parameter 'buflen' not described in 'underflow_on_buffer'
>> Warning: samples/kfuzztest/underflow_on_buffer.c:24 expecting prototype for test_underflow_on_buffer(). Prototype was for underflow_on_buffer() instead

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202601130828.lXrl0Ijb-lkp%40intel.com.

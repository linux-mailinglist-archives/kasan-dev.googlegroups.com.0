Return-Path: <kasan-dev+bncBC4LXIPCY4NRBRUMVXDAMGQEN6CCQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CFDBB824E6
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 01:37:45 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-77c3fca2db2sf364049b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 16:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758152263; cv=pass;
        d=google.com; s=arc-20240605;
        b=C9ga67Ta9wdu6YTF3SKRIx+xrvCEfcCsSV4YuUPzitjs/a6oKYIsVYsc8FCkdxd6OW
         9aVO0qw2coLvPc0u4f50ymG+ulLsFOEiWMz1+KyYyy0+CgjpxebvNNwFXyA9po/OC+ue
         YtjwkXiMEYHYHHU11zUEtUPGnNr72Fp1ul0Pnf2Tgsqnwgl+mlw6h/oQPKN+5De3og6f
         jsTGpChCD+3k3lYjnrBiPTESlFr9UYXw0h3hrp1LLeqChgJRLXkqGNU1uZ/05EPmpUfN
         yCFpEm8N2h7J6LAmcXa0gzhy2hbIOVKtY7iE90ZFRhr4hsLfPLRbX/+U9FxxTFlK/ddA
         A3+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iwWQdanTLdTvUcWLblhfkJ6vH0Yw9QbEzG0iYEOWekI=;
        fh=tD9+LOIDR8ZcpSLUituorkCAADSbulV3RwY/1q4SpGI=;
        b=NxZtFOGvYVTss8QdzO//oN1hSjRWtNxOPWp4zSVaBB+cAIQSB7rGoYpilQZLy8e2s7
         1obYVS/l6OZCm0V2obd7ZB1Y3o15RAIHrALqHAc2lIJECjFX6MXxuPrnrTEGt8OQiFxf
         bNdST5/uir8qZCxNADIqGaLg7Kpj3rhyRFdA+GVGO5eAc4+oRXYuxssSjXybXILdKLyL
         OBVYP/eU5BXS+Ksrqe9HwPirJ0BbSg4e3ZRbXCe3PbM0ZcYOw4nMypAcAKkkHUHgS7jl
         02sBQs9bmSi/WQV+Vm28+ISTJcVcEzxpuvvmBW/3WpKhfV+LOCafbyptFg4R01XHQGze
         fWYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZGsYgqoF;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758152263; x=1758757063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iwWQdanTLdTvUcWLblhfkJ6vH0Yw9QbEzG0iYEOWekI=;
        b=KXgyzXGMWU6R/yQcfFTFCdubJQG4V6jANXMeL6jmgaySXs3IRWI0MJznEPZrJKyJnJ
         P3cNJf9Lo9pI+vSX9fPmpUTtzBBBfyR9Mz+hD2QgvlNQ4cgXc8KoodiWEjwsenIGbUFG
         Cl/XNR6vcY4fmjLEW6IS7YJA5C9oL/h9VCfn0ng4MwkUQnlVcz8Kzhbuc/B+HOGKb35Q
         8jUhCAqtDShYQvoEvjfEKiHG4Fun6jXRbVswd513nBHKrickYA2ZtINIeTSFtgfyRanU
         Z15rK9Z6qdQN4LhrbQYDrsKIFu50ikvsAvjzFUm1BV2by4olEMNx5aCSnrqAOL0Xt9H4
         Kn1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758152263; x=1758757063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iwWQdanTLdTvUcWLblhfkJ6vH0Yw9QbEzG0iYEOWekI=;
        b=Gbm4vjfwVv/ZTu2i/l+px3duL+rXOmLzw1FWhRJPQLt8tKm5RdLB7300bx2Q2JTtin
         5qDmEb/DGlvyRN4P9lWEn88Y/eYCl00VO30IWPWcRrRNoAaRdXI5HEhVXc5pXXGfugIZ
         yskXtfq55cCfSIlhAnApsJJ8EO9WMTv6CHX8bfv7kmuaxkI46cZba4zm/ulrjnvF3b6S
         5VHj0Fn66l7Q8kE+ANqpenQ1GHXeIDrBK11d2+jW6Lb2FF76bmbRzLwBHHpBVXQS11Ed
         JozSwA4EJgkene3SbpQU+uQ1Dc7ZL6C0TZ+UJSS2l3yukQLohcrSQj6J6zxMaF8CWixQ
         /0BA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdiTA1Wg9f05+DW9tCQKQdM4tVsxC63V53mZNDjBYUN+y3wzf3BzZ16odRgmtto/QM2gtJbQ==@lfdr.de
X-Gm-Message-State: AOJu0YzbZUbtRBAcX38ZGnWLfDrgXUqZzTNX2FHpb875S/6gDXOHwCWf
	EmAZrmHuh5gUH0TtdDH8I8HA33AJVBBSl7lP9b79s5enu56JtC14IAcB
X-Google-Smtp-Source: AGHT+IGqZavb7BbdC6zD3/RaoBpjik811hRK3igfD+P/RQyNLqwvHwr+5EfMD9d9dFf4gOYxxF9GjQ==
X-Received: by 2002:a05:6a00:2e18:b0:772:5352:eb53 with SMTP id d2e1a72fcca58-77bf8c76c76mr5796766b3a.18.1758152263281;
        Wed, 17 Sep 2025 16:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6nEjPNJzhA6IT7oZW2sSCyQgG5XBIV+vdo4LRJIYUntA==
Received: by 2002:a05:6a00:4641:b0:76b:b326:ac43 with SMTP id
 d2e1a72fcca58-77d14c4fa27ls226354b3a.1.-pod-prod-09-us; Wed, 17 Sep 2025
 16:37:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGUcQoToIdNgA0hfiWTwpRcugvFJt2ladsgXVooOpQusx7YPuoGXvujwg6Rm39yK3voNb/YzN7xWo=@googlegroups.com
X-Received: by 2002:a05:6a21:6da3:b0:250:1407:50a4 with SMTP id adf61e73a8af0-27aa5b80ed1mr5836086637.43.1758152261289;
        Wed, 17 Sep 2025 16:37:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758152261; cv=none;
        d=google.com; s=arc-20240605;
        b=HvMYWtF1k0IR4oJUdrS35ATFKI9DJpzNI6esjAl0S6ylNuOXzT4f1BnVPAQeLkK5p2
         xfM8elbN6VRvsPkIEmwlgK31O1xemapK/1KXV/iFnWTOTnkBAbhxeYN2m3Aad0XmUAs1
         ET5heQYVOIl+lsbbbojPs40nixmv0rHsxpfLnj6VgEQq/wV92m5BzvK1VRnSwvmQo0Ea
         Trj6+jICWK2FHeVadlLcQcZJz3+9h1mOReEcDnNYRFbVjCZn2okDqvFHY/8HEiusFpf+
         SY5wYVXdzsDJ2SoXq1HGpG/y0DY6HXmeQu3TcYoEaz5XfMJWtz8nJB867MLIQKQ4LKxZ
         KAPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=W5u4mbrkttDZPXylDQNMtBldz1csoAOz1xispqU5El4=;
        fh=lYa0FG45bwqSJAg0l7nL5e2519l1C90YKv5AyQwXbVo=;
        b=eXRNkhZWQ+50YYCozp6KypYBFJitsLLORT5FtFSTndwx9nM9yFu4/b8q1Htv1xVCWW
         2LZqwjOFfHVIRutCzNaztF0oTcwhWl9ksbgnq/htvZKTTtkdUkPHzBByAW+XFRKMOoah
         M6fJcB9uH+CpmV61krwg7qJoMGeT1q/YLPR+07wijSfEjz5a80sZTdH07y/cstg3DEFf
         PXv97rZBUx7hC2vMTyrPQmtL5a0VOH8EOeBmmYuHL5yVD3D1/SHdg8TjuhgqupDtv8fM
         EPnPsI8+ViFG93OGODfO/2SYw5fJYGVd5efSl14VTrpHpQYyO6hgFS8EEyvFQZRWDI6Y
         JJ0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZGsYgqoF;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b54ff356417si44152a12.2.2025.09.17.16.37.40
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 17 Sep 2025 16:37:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted sender) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: 4328d+icQf2O2M0jGeadOQ==
X-CSE-MsgGUID: fvh2WkofTwSaS+ry/mwqrA==
X-IronPort-AV: E=McAfee;i="6800,10657,11556"; a="71576746"
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="71576746"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2025 16:37:41 -0700
X-CSE-ConnectionGUID: QcxZYuG2QOyvuJ2rkRherg==
X-CSE-MsgGUID: 5O/Z75r0RRWd2IesMQAMfQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="175779636"
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by fmviesa008.fm.intel.com with ESMTP; 17 Sep 2025 16:37:34 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uz1iN-0002ZT-2Q;
	Wed, 17 Sep 2025 23:37:31 +0000
Date: Thu, 18 Sep 2025 07:37:10 +0800
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
Subject: Re: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
Message-ID: <202509180721.GaBOMCkp-lkp@intel.com>
References: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZGsYgqoF;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.13 as permitted
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

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-nonmm-unstable]
[also build test ERROR on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.17-rc6 next-20250917]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20250916-210448
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20250916090109.91132-8-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7 and RSA parsing
config: x86_64-randconfig-075-20250918 (https://download.01.org/0day-ci/archive/20250918/202509180721.GaBOMCkp-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250918/202509180721.GaBOMCkp-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509180721.GaBOMCkp-lkp@intel.com/

All errors (new ones prefixed by >>):

>> ld.lld: error: undefined symbol: pkcs7_parse_message
   >>> referenced by pkcs7_kfuzz.c:21 (crypto/asymmetric_keys/tests/pkcs7_kfuzz.c:21)
   >>>               vmlinux.o:(kfuzztest_write_cb_test_pkcs7_parse_message)
--
>> ld.lld: error: undefined symbol: rsa_parse_pub_key
   >>> referenced by rsa_helper_kfuzz.c:22 (crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:22)
   >>>               vmlinux.o:(kfuzztest_write_cb_test_rsa_parse_pub_key)
--
>> ld.lld: error: undefined symbol: rsa_parse_priv_key
   >>> referenced by rsa_helper_kfuzz.c:37 (crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:37)
   >>>               vmlinux.o:(kfuzztest_write_cb_test_rsa_parse_priv_key)

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509180721.GaBOMCkp-lkp%40intel.com.

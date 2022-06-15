Return-Path: <kasan-dev+bncBC4LXIPCY4NRB6F4U6KQMGQEKZCV62A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C3B54C9C1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jun 2022 15:28:25 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf6049868lfa.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jun 2022 06:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655299705; cv=pass;
        d=google.com; s=arc-20160816;
        b=rG1gS9jBLqOw8Ao4OlwQMQ5cHZiTJaotAugVYaigQt2XLzJx+PhlM9X8HkaWm7GwpI
         q2sI9MpuIC83e2w1tFCBNu6BNt/DW48AIuFiqXIYyUBZCUm6kc1MO0jqkuyhIuUHHXPW
         q15P4CXRDQFr7cKNlw/6CgqUeahyxvI+kXlenP2yr6ICrMDBxZ7ItK6I/Uyh47SeMlRU
         4Nvwx8Luu5QIDx1BxuGrAY71pkklQ0w2AdUxcIbaPx5k4vTYROEDbqGRVLZKsPlWwP3S
         zqVhMN6NaD728pO+MXF4K+iNu+O2jjONJnrMJ1nrxMiW2o8RDtH6csLe2Z1VJ6nglNK+
         0CMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0maEw8fXy44KXG55MSTdZ2VaU0fN9EYTcJFYdGQ9uco=;
        b=baPhR3VVSMlSRYTZ8rUfXiCBxafjBQznVhjrvWagX4XB4NiTM3NSSwK/R936ScwFvm
         NBSNz9o+NxYp0QvSCF5SJarcuCKmzziR7F081UAPTRRabUz3JJMkIb9QyTnOsNcM8nzv
         YCzuqgYdJ81ELwt60KbWGtnGO4so6cq5TjGmcTemUB/h+gPKE5v1mzmPus/m9wRinlOf
         Z12HuT80FlgeaeN08hbwf30IC7W+yZCrITeBJTxzK6jOyAp6hFgeUjNV+oWz9QLXSph+
         J8itS17Oo5EP+KCEiqo65M5N8eIMob4cCg3JcUi9yFa4oTudIN38CmxRQUsfC3IzR3fH
         ZeRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EKXT8mOT;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0maEw8fXy44KXG55MSTdZ2VaU0fN9EYTcJFYdGQ9uco=;
        b=WycRC139fEsiSMG6+b3FjaEK1BXB9FIiHXvDs3JKXqyKZH1YuQ02kEtwlxBjzHvKdL
         +N4vci9Oo9ZZLm32cLKbEG6g2RjQPKu/FVOO2LApSaFayr69mOptNharOttX3BQoEq6o
         AOXKTCBVliTiXvaA69KroBwKym4o6B2HKnyfP1xO5OR3lTX9bqpTil5qawPuB3msgHdg
         lnqe7Fx7jDN3lO+eixsD1TWyj8u+cNb3neP6XkIxoYA/q8ya00XjNWghzrWLvcWoWXmG
         pbY9qTONvRtOKnWD+rYelB38NMUPp9stC0r7TKJJeIRNSPpOac3AjAxo3Drl7VW9DYWt
         yq7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0maEw8fXy44KXG55MSTdZ2VaU0fN9EYTcJFYdGQ9uco=;
        b=P6MDK5pLkXMgIklYHMoNv87RtW8mEPVW+YoTAPTPDKMjWda2w7qjMg3PD+TVesNNAu
         iWWzQfLDMpxMhmrtvjUkNW4Aryae4ZT7jyrj22nkAhMlh395QUQciSkculJyKOEeTWrA
         /Vk+I2E6tTT8vB6XfxEfpFs7wmloOq1XkLSwh/n+Bt4+6dfRWornuUhQ/OWjZdYLo0Ux
         ZDgDzc98MqSOdEVFb6wi1WHUKWhFoO8jTxG58K1IjxvAnrZTWmRHACenpGg9s8bRHpmz
         3jf9sMSXLfHNe73KuemOgWYmYAYM/B2mHwJBuBe68HTQRsdG+ycplDnT8vAudELtHAB+
         VXFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+0+4xk+uKXOOsszJJ280glaSjZe2H0gvxgk5RScFYi9AnibDRF
	8+PfDCE3UYgSbsTk6ySjyJ4=
X-Google-Smtp-Source: AGRyM1uJVRW4xtFbkx5rpUXa/k0x8S7kt/ap4PmvBOOBSBDCWBiIoutJ+4OYKkgeZPYSHqFmvvcvEQ==
X-Received: by 2002:a19:4f1a:0:b0:478:fffe:db3d with SMTP id d26-20020a194f1a000000b00478fffedb3dmr6002127lfb.485.1655299704729;
        Wed, 15 Jun 2022 06:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cc:0:b0:253:9ae0:be3b with SMTP id u12-20020a2e91cc000000b002539ae0be3bls1348444ljg.10.gmail;
 Wed, 15 Jun 2022 06:28:23 -0700 (PDT)
X-Received: by 2002:a2e:b904:0:b0:255:5c9a:b46e with SMTP id b4-20020a2eb904000000b002555c9ab46emr5094839ljb.7.1655299703536;
        Wed, 15 Jun 2022 06:28:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655299703; cv=none;
        d=google.com; s=arc-20160816;
        b=wljHSBK7cOhZrkcIwfnc9b6G8MQJoDb959+K1LwVVzdL5MMjdOzQTqxPweW/6KfmB4
         ADBG9oGqq4eeLhwoSg1wo9gu6445iC0HMTExUVkiD7PiylwwxfDYXJnG33A1vsIxECzC
         lllhzmIhpr3SINq3n30UcC1TuyycSXNUjlbW4NoQANnEbOwryHv5mVyfhiyeZ9iwRwSm
         rhVYyZkqRSB+Hr/8xGQFt78P7Xq/Z3shIgO3zLdAtSW/ld0IFPcJ0PUxZ6RU1QLDvVaq
         K1sAe/63qhzlvBzAKyZxuFDEZJSxk/NcyQ48BFs+wkfAFCFJNMuZG3Lvi3R6wZpZwvAE
         Ssbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gl+tPDD6pbk5k4M8pL8/xQQasJf2li+6Ho4YYC0tB5E=;
        b=Kg+mQ2fic3/NSXZOqqFtUp1PtRpg73daoCGOwRXsjeYK7X9VjF1f6hdQfTYp4SGRFA
         8Eju3d8iNtEAe2DFG1qeXUvyKFQAMHa1XsnhrCABBbSObLzoVmbD9N4KWXvKs8xHCqBg
         YmWzLk/DFhIOSSCbtz8sBTCCDrC/7puKG9tK1Rmv23pqt3zhUeuqQrOopVYTV/NxTh4A
         cL+lRGdLPi2HM1BR3E5u+rJvToYx8rye+MrFHL4UeFZ6bpcFiHsA1MCde8IWtn8dHOp1
         O5jK+7kHh5cF4aNKFJnbibcxn2qK/qA1umU9PX89FJFG5SaGfwPsjBG82j+G6X2ZPkCZ
         rFOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EKXT8mOT;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id s11-20020ac2464b000000b004785b6eac92si423081lfo.7.2022.06.15.06.28.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jun 2022 06:28:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6400,9594,10378"; a="279007011"
X-IronPort-AV: E=Sophos;i="5.91,302,1647327600"; 
   d="scan'208";a="279007011"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Jun 2022 06:28:21 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.91,302,1647327600"; 
   d="scan'208";a="612739745"
Received: from lkp-server01.sh.intel.com (HELO 60dabacc1df6) ([10.239.97.150])
  by orsmga008.jf.intel.com with ESMTP; 15 Jun 2022 06:28:17 -0700
Received: from kbuild by 60dabacc1df6 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1o1T4C-000Mtf-RD;
	Wed, 15 Jun 2022 13:28:16 +0000
Date: Wed, 15 Jun 2022 21:27:33 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: kbuild-all@lists.01.org, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 24/32] kasan: move kasan_addr_to_slab to common.c
Message-ID: <202206152134.sadCRvGk-lkp@intel.com>
References: <5ea6f55fb645405bb52cb15b8d30544ba3f189b0.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5ea6f55fb645405bb52cb15b8d30544ba3f189b0.1655150842.git.andreyknvl@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EKXT8mOT;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.115 as permitted
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

I love your patch! Perhaps something to improve:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on linus/master v5.19-rc2 next-20220615]
[cannot apply to vbabka-slab/for-next]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kasan-switch-tag-based-modes-to-stack-ring-from-per-object-metadata/20220614-042239
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
config: s390-allyesconfig (https://download.01.org/0day-ci/archive/20220615/202206152134.sadCRvGk-lkp@intel.com/config)
compiler: s390-linux-gcc (GCC) 11.3.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/b0b10a57b2d9a5e5ae5d7ca62046b9774df1a88f
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-switch-tag-based-modes-to-stack-ring-from-per-object-metadata/20220614-042239
        git checkout b0b10a57b2d9a5e5ae5d7ca62046b9774df1a88f
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.3.0 make.cross W=1 O=build_dir ARCH=s390 SHELL=/bin/bash mm/kasan/

If you fix the issue, kindly add following tag where applicable
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   mm/kasan/common.c: In function 'kasan_addr_to_slab':
>> mm/kasan/common.c:35:19: warning: ordered comparison of pointer with null pointer [-Wextra]
      35 |         if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
         |                   ^~
   mm/kasan/common.c: In function '____kasan_slab_free':
   mm/kasan/common.c:202:12: warning: variable 'tag' set but not used [-Wunused-but-set-variable]
     202 |         u8 tag;
         |            ^~~


vim +35 mm/kasan/common.c

    32	
    33	struct slab *kasan_addr_to_slab(const void *addr)
    34	{
  > 35		if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
    36			return virt_to_slab(addr);
    37		return NULL;
    38	}
    39	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202206152134.sadCRvGk-lkp%40intel.com.

Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKHPUKJQMGQEEDA5D3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C6E37510F89
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 05:25:29 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id k13-20020a50ce4d000000b00425e4447e64sf242076edj.22
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 20:25:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651029929; cv=pass;
        d=google.com; s=arc-20160816;
        b=hT3DgMKedZM7JDc9rc6lXjAOFG+IPJsWsLQeLPd8vYIr8XItC01yRIDxeME4NVq/be
         l8EAjXmksVgoc208aDt+/d7dK0HufW49++ZtdnVm24GD+KKbCtOPh8XC4kIladhyhhso
         3I39DguI2q4tpBS0Wo32gzuvIkDrPCOUk5wjmf2qldHRhoQ4zQMflX391rq5yNfrsqTy
         VWkpwfujdxWRnx9pAZW/Lnu0tQRQGhmU3fpEuRj0c+8limuVycYEleA8iM3a/1ee5aG4
         bvxQdrA1gllzz2rxL6a2pAmEnw8Zo/h/f2Ne1JNrAioWlGd8anZu5DniUq+ZJeUbDue1
         jxPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=faK2pzI3plFShlbMhSbEEHV5fG6+p2d6jrfHlrcd1CE=;
        b=GAktzgejQhuY4+VsaGC+5RQZ29l4sg2N6VPyrtM3jbT4C9IRGqo3z85agUsxUDzrVC
         /+07S4P2IewAHUUpkCZaBH+nwJWo5aotAlfn3pb0Qd3FAVpM9C6t8iuheJf5A4h/J/I4
         qudjuFiLANczKiP1inZNKm/Is5JO5XfVvX82khfJTtZnUtJZ/WTBLl7vaP524kq7hacM
         SmlD1/BL0SHthLnHaO5i65Ad0J30bhOG3/4zn6c35BJ581AiOHGgEDSMXXf1mHCI91xO
         aKRO+5JDjCX1JcRKAjkrVUzpnscwUuXi6HKDc4a0H0c9lB2oNr2LTHC67F0zHEhX5P1V
         1D9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=OO2K4r9d;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=faK2pzI3plFShlbMhSbEEHV5fG6+p2d6jrfHlrcd1CE=;
        b=bAzSIX5yGV4Zpl/yoy1uZWZT4096WDiSKda0oI1dohdVutrnLabxAVD1Z+wJsmK3RK
         5WEGO0fE+P/lVIlPTKYUYONootZLbccd3WqVsLDXEZR9jgf0eUr5RA3GREK3E5072xDt
         tNJslgjZdo3/Cpv9HooX6Ah+/O5PBmj8do8yh+2chjkwjEMzXgdbuar8Nb0qCLPKd8OZ
         TbWc9o/bA/r0Kl7/S/5fQHmnKOzIhYVQ7SK8xzmyiEZbTzcaegavQYciZrPrZgBvOMg8
         EQwIuE2lKc+Qs2BTJgxXyt6KMFVTI2ySaNaZvrBTst+CLeEkS7enpXh5Sfwzhp/3y1UM
         u2gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=faK2pzI3plFShlbMhSbEEHV5fG6+p2d6jrfHlrcd1CE=;
        b=mtI55FRgdYgECT1d7wrfNKRU32XF8KgX9D17lvIacMEs7mBlXi7mjmiKuiI6q1yUBa
         v3iHmD/A/P12kwLo0Q9HqwGhYM8T1f9HQn+6+66vDGZ17V4OKGe7TltZixs8yczrMw0U
         WC+Psgj2Boea1JChy9XHYWrs9QgxxWpgrOzfvFXvP0ivCbap17+2ebAy8xpUx/arNNGy
         Ioh3KngrUgZF6av29F/yNXFhyTeB1qu0dnCO0QEgvuJfoQhhjQHqmYH5aEtEbY+ilyAK
         BXIXGtHAJ6OWxVWDrVQRJBJSDdSXJwRN+XdMe+d6/oFau4aN9IPBq/7Fs1xuXgfdxKGu
         2uWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uU0voGvc4BCIn5hFXCHiyQRWLuAWqx5T8I34rbwkW99U2tWki
	isDNrreaH8WedL8RAQUo91E=
X-Google-Smtp-Source: ABdhPJyvpJ2nXwN0u4h4CO5lFL95/JcSE8p9Renu4jozlwO5eFFXB5sPu8I99w9qt1SuyJaxgX1sHw==
X-Received: by 2002:a17:907:7f0f:b0:6f0:24b6:3f6d with SMTP id qf15-20020a1709077f0f00b006f024b63f6dmr24091525ejc.254.1651029929224;
        Tue, 26 Apr 2022 20:25:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7b8d:b0:6f3:a9c3:6052 with SMTP id
 ne13-20020a1709077b8d00b006f3a9c36052ls2685627ejc.0.gmail; Tue, 26 Apr 2022
 20:25:28 -0700 (PDT)
X-Received: by 2002:a17:906:c145:b0:6f3:9ea7:1d41 with SMTP id dp5-20020a170906c14500b006f39ea71d41mr10511575ejc.269.1651029928062;
        Tue, 26 Apr 2022 20:25:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651029928; cv=none;
        d=google.com; s=arc-20160816;
        b=JCVorItpA1aFQHVRrsqq392FZ+z8IBZQShtu4KI99iH4ijt3r6yYsg//d7cvBRHKWN
         7icmWlnJ2nh5nUscMsRcprmFrYfzwx7u9vWPTqmMuqUBGrYD+6ldSi6yeN2RisY99Auq
         9ked8g4c+ZDkAQ5+A8CuBxJ+fuBCiLQYnyZoIAchEInLif0GkbllKQOCRl6AviKF3Ay1
         ownT9lGshe3Zub0iLez2+trVpvbj8s7E1SS76U004L/nqF4cs6tD4I3tk6prsMc1jlrr
         FswnFs9iH3lfnU0N38UNHipxLHQhqCf6h3DUYmkWp00KLVIRE7cYrjZoZMQg+Eqte9MB
         7LBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZPTgDNWLgXCa/pKdOzPP96cv+QqxkoFxSm8CBTqVGZo=;
        b=iyWZlfg4Gq6y/umscwgclLUxRcymDdzGOsB1LDsS/sl2bpzcxhEEvS0g+HseKiV49I
         yQo1Nnxwuu0URYxfq8ZVJGQjHpoCJrLiSGm3FRhS/qM7hTuukwiHWcqW1exMn3KOba1+
         aGvFDWXmds5WBd77mDAg8TpGS/EeIl4gIveG9J9IGjaUVkdx9eemOnAwpdAqk83zArAL
         3fYP1RuR6tNYr04n1L/fprvzLTHGmZRF6Ok7iBrYRt99PIYJNwVv92c+WIt1mQGts4I+
         HsIItbLH46xALjy6YVmVMHsC+Yh5cjedgtF7yqZ66d5G08x2M9pNsNWiVeNMUJ9mKNqc
         vtRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=OO2K4r9d;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id v8-20020aa7d648000000b00425adbac75dsi22582edr.2.2022.04.26.20.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 Apr 2022 20:25:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="245722076"
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="245722076"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Apr 2022 20:25:26 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,292,1643702400"; 
   d="scan'208";a="661015977"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by fmsmga002.fm.intel.com with ESMTP; 26 Apr 2022 20:25:21 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1njYIr-0004Gi-5Y;
	Wed, 27 Apr 2022 03:25:21 +0000
Date: Wed, 27 Apr 2022 11:25:15 +0800
From: kernel test robot <lkp@intel.com>
To: Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Peter Collingbourne <pcc@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v4 1/2] printk: stop including cache.h from printk.h
Message-ID: <202204271135.P05x34Pe-lkp@intel.com>
References: <20220426203231.2107365-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220426203231.2107365-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OO2K4r9d;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted
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

Thank you for the patch! Yet something to improve:

[auto build test ERROR on vbabka-slab/for-next]
[also build test ERROR on arm64/for-next/core linus/master v5.18-rc4 next-20220426]
[cannot apply to dennis-percpu/for-next]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/printk-stop-including-cache-h-from-printk-h/20220427-043357
base:   git://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git for-next
config: arm-randconfig-r025-20220425 (https://download.01.org/0day-ci/archive/20220427/202204271135.P05x34Pe-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install arm cross compiling tool for clang build
        # apt-get install binutils-arm-linux-gnueabi
        # https://github.com/intel-lab-lkp/linux/commit/edcb0f592304f7849a39586f9e3fe0d8f6e6c6b9
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/printk-stop-including-cache-h-from-printk-h/20220427-043357
        git checkout edcb0f592304f7849a39586f9e3fe0d8f6e6c6b9
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm SHELL=/bin/bash

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from kernel/bpf/bpf_lru_list.c:8:
>> kernel/bpf/bpf_lru_list.h:36:21: error: expected ';' at end of declaration list
           raw_spinlock_t lock ____cacheline_aligned_in_smp;
                              ^
                              ;
   1 error generated.


vim +36 kernel/bpf/bpf_lru_list.h

3a08c2fd763450a Martin KaFai Lau 2016-11-11  29  
3a08c2fd763450a Martin KaFai Lau 2016-11-11  30  struct bpf_lru_list {
3a08c2fd763450a Martin KaFai Lau 2016-11-11  31  	struct list_head lists[NR_BPF_LRU_LIST_T];
3a08c2fd763450a Martin KaFai Lau 2016-11-11  32  	unsigned int counts[NR_BPF_LRU_LIST_COUNT];
0ac16296ffc638f Qiujun Huang     2020-04-03  33  	/* The next inactive list rotation starts from here */
3a08c2fd763450a Martin KaFai Lau 2016-11-11  34  	struct list_head *next_inactive_rotation;
3a08c2fd763450a Martin KaFai Lau 2016-11-11  35  
3a08c2fd763450a Martin KaFai Lau 2016-11-11 @36  	raw_spinlock_t lock ____cacheline_aligned_in_smp;
3a08c2fd763450a Martin KaFai Lau 2016-11-11  37  };
3a08c2fd763450a Martin KaFai Lau 2016-11-11  38  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204271135.P05x34Pe-lkp%40intel.com.

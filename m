Return-Path: <kasan-dev+bncBC4LXIPCY4NRBAO4TCJQMGQEL4YZR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 21E7D50D8B2
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 07:13:38 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id y13-20020adfc7cd000000b0020ac7c7bf2esf1547744wrg.9
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 22:13:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650863617; cv=pass;
        d=google.com; s=arc-20160816;
        b=BzzQZTtaH2bmUFX2Q41UkMtV+MAxK+Ij6ns50rgOowUzzkHftQBTXGEXPFnsN/1uEq
         DUAztZpGevou/rHaiQTNhvqM7YyMzwnI31qm6bv+PwZXhDnbL1vYc7QLPADCkvT6GKc5
         QsZpYEiC7G0etk0bSpU00tg+BmTN2BKBMGdVwJklkzEzrrIfbdbxZj+QYxV9KNdVRelO
         SJF8U000SRTllA32AGbQluZwqg23M5iOy5YJTvKMpnyfNLqEOCu3BoLztQeftMlOtuSR
         5dre9oGCpRyUiimJkBRi26lW3MoPVHg3F9qC05AWeG9VrjTolKORT08pQpuCwk6o3Pv7
         4g3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8kq1tFvjEKEZKRlGriqOY0ERYgOBn4yzo7BNHIYZo7U=;
        b=f2vf0UpMEdIfH+kE1mBWpxPjAieKtwC7zNXR8AuC1ikTWmHUozATZApX1MOg/ZtXfM
         B9e/71pr1A2wih2fBXzylqg0PbM/Hc3TvSVspZo6mQRi9CoEXb/MnN96FeaFEDTHXpoE
         IfgkTrsXNSAAsX+E5QvPu3M6j8XFAtI1DXnEUqI1GeQ3i+iH66PxJv8FZ5lMkyXMs6Qn
         cOMTjLYQVJSgpTNAn+5jF+fC4wHfupf/bcw6jf1QhjFdSDfXsIXQz8orQGIWeXyOhO5t
         YHVuQ9FKC4ziPfgu7QspFiyDzHxXaJUVx6egj6LvWbYzzUollISF/3gYWCJI4LDO+7Lm
         GFXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=L20EUhNz;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8kq1tFvjEKEZKRlGriqOY0ERYgOBn4yzo7BNHIYZo7U=;
        b=T4J5tAGOLewCfYZ0YptVN9ulXkGwfmRKBWcec4GclkAGnu7O7sr53YwxAKLvGg/Il3
         mIJBSTSogmqB+ARX013phEHEuxLem0JzOPzA7KfpCi+bQOcDO/0G8EeAGL2OFidhUrUw
         Zr3Fbh1ElwOvWb610zqWu/zM9WYpt8eMqeubAwnjDjjqaHHTKSZQiWWB8vmypAfnrzif
         u3m4aXBrBROFe3BKSSVXPIyJYWYNfcaULdn1K0xO6SsapJYr+2dcgqw4xN9BWXg5C7Dy
         aNwCFLinwm/JGvQj289K8JQL0AS38i49IUwTnLspExi3hd2IMFhc9RYbDKR2M5YYi/+u
         qucA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8kq1tFvjEKEZKRlGriqOY0ERYgOBn4yzo7BNHIYZo7U=;
        b=W/Io0tyA78tZu6diJdfDjcpwGaEtK6mIRvH4TQyLLtN7dmfZpau2squA+7WeQDMwP2
         zRbonI3V0i3gVihUbDDEu7KZUtwksoCJH4mtOaN/3B4E12/c66HTbDoviw+YP97/TlND
         qlZwp7jJZh1ZfBCYi7p4dQn3mtrhqYuTVzhw7r8vQTrz8WGdFc60DTaSAlnoetx+2cLF
         z5pfrMu4yOBAHXDOTTu7XpAjPK1B4sv4QJnvb7VAeQjVk+Ps13Oo+t/n2IlPcfX617Az
         01FYB7p72/YUj8nBnWeotyqaaAOnulDt94UybbINIi+t10R0+73+xFn4ZUJMqwMnrnQz
         HrDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GW5IN1YscElBA5bcrKoGN2FmUcD3T7QLDuY0fnBlIpXb+pF1n
	OPCH1sZvTIcprlqTnyA1N/E=
X-Google-Smtp-Source: ABdhPJzz7Akt/nucKuCVZpi+HyNmnvHeBQ6++kluBvIcDznj0gZxMzm5dm6ZCmrW02InKNVoHRjkFw==
X-Received: by 2002:a05:600c:35c6:b0:393:ebf0:d530 with SMTP id r6-20020a05600c35c600b00393ebf0d530mr3154147wmq.34.1650863617481;
        Sun, 24 Apr 2022 22:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:59a4:0:b0:20a:d221:a277 with SMTP id p4-20020a5d59a4000000b0020ad221a277ls250604wrr.2.gmail;
 Sun, 24 Apr 2022 22:13:36 -0700 (PDT)
X-Received: by 2002:adf:ec03:0:b0:20a:d0b5:a06f with SMTP id x3-20020adfec03000000b0020ad0b5a06fmr8113502wrn.669.1650863616443;
        Sun, 24 Apr 2022 22:13:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650863616; cv=none;
        d=google.com; s=arc-20160816;
        b=kcIMiYUjrSd+ZsEjCvVCQrZLb50Jns+hmP8E1PR+oNmazKvIJQwMbj5eJWS/DzzDT3
         baRvD4rXskCtAwDY3359z4G5e6qVBpgV7zHilnk5tZLnWXoYDZEytUxihJuSuzI+Zabl
         6KuaLrSpfctM5mRPVzKoOakpYNWu5ldNtytP+g8ofBesFm6TRgvmUtLzYO9I1jT8u/WL
         A43A9xTTaLndyO9qTgRcDSkFsNxSMHISQ+jZvIYlduyC7ztlmbd1W4dCTd61qeZ9gi6t
         HrDGwyqAkglHfxEKgtUjznougUp99Gpbupkw8JoQQ25q1Qs9eGQsKCSeKyHjnw/RS2Fl
         +HwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BzFcH+9HxnED02i/GxtlfKbsgMleMbKnvE/TTAKlSdI=;
        b=Ckq+9sCiD/enyCA8GijTyVDtfWBrlwjLYPudEsW7AnnL6qIq1uX2+FDZrvGFetnl9+
         yhOQQX8VquoZ/kz0UxHj5Hu0LU6fMkmPbqkl3q7fkIP1TvvIqxeySktCXh4wrb8lDFWV
         HsDk4Y6pA0h7X3VpjiaG9N7UtgchCW/QAcPKvHBF7pQ5xdUkW8cgbDbyiwYYX0GMBylP
         WRZ7qfeEljdH2ndMWz67N0LybAG38UGGp4jPcikEMvp92nN5G2b/QKC5zgAeiyDvuFdH
         IDVpqYqMAoItfKCfOsULdDPA7e0TIEbJgXp/sRfJxgpZbPqQMGCc+KaWSnPSQTSvJYln
         o5qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=L20EUhNz;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06b.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id g9-20020a05600c4ec900b00393eb6edf83si87119wmq.0.2022.04.24.22.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 24 Apr 2022 22:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6400,9594,10327"; a="325625896"
X-IronPort-AV: E=Sophos;i="5.90,287,1643702400"; 
   d="scan'208";a="325625896"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Apr 2022 22:13:34 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,287,1643702400"; 
   d="scan'208";a="704401579"
Received: from lkp-server01.sh.intel.com (HELO 5056e131ad90) ([10.239.97.150])
  by fmsmga001.fm.intel.com with ESMTP; 24 Apr 2022 22:13:29 -0700
Received: from kbuild by 5056e131ad90 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1nir2P-0002AF-3Q;
	Mon, 25 Apr 2022 05:13:29 +0000
Date: Mon, 25 Apr 2022 13:12:47 +0800
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
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
Message-ID: <202204251346.WbwgrNZw-lkp@intel.com>
References: <20220422201830.288018-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220422201830.288018-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=L20EUhNz;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted
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

[auto build test ERROR on hnaz-mm/master]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
base:   https://github.com/hnaz/linux-mm master
config: arm64-buildonly-randconfig-r002-20220425 (https://download.01.org/0day-ci/archive/20220425/202204251346.WbwgrNZw-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install arm64 cross compiling tool for clang build
        # apt-get install binutils-aarch64-linux-gnu
        # https://github.com/intel-lab-lkp/linux/commit/3aef97055dd4a480e05dff758164f153aaddbb49
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
        git checkout 3aef97055dd4a480e05dff758164f153aaddbb49
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm64 prepare

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from kernel/bounds.c:10:
   In file included from include/linux/page-flags.h:10:
   In file included from include/linux/bug.h:5:
   In file included from arch/arm64/include/asm/bug.h:26:
   In file included from include/asm-generic/bug.h:22:
   In file included from include/linux/printk.h:9:
   In file included from include/linux/cache.h:6:
   In file included from arch/arm64/include/asm/cache.h:56:
   In file included from include/linux/kasan-enabled.h:5:
   In file included from include/linux/static_key.h:1:
>> include/linux/jump_label.h:285:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           STATIC_KEY_CHECK_USE(key);
           ^
   include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
   #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
                                     ^
   include/linux/jump_label.h:291:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           STATIC_KEY_CHECK_USE(key);
           ^
   include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
   #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
                                     ^
   include/linux/jump_label.h:313:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           STATIC_KEY_CHECK_USE(key);
           ^
   include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
   #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
                                     ^
>> include/linux/jump_label.h:316:3: error: call to undeclared function 'WARN_ON_ONCE'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
                   WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
                   ^
   include/linux/jump_label.h:324:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           STATIC_KEY_CHECK_USE(key);
           ^
   include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
   #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
                                     ^
   include/linux/jump_label.h:327:3: error: call to undeclared function 'WARN_ON_ONCE'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
                   WARN_ON_ONCE(atomic_read(&key->enabled) != 0);
                   ^
   6 errors generated.
   make[2]: *** [scripts/Makefile.build:122: kernel/bounds.s] Error 1
   make[2]: Target '__build' not remade because of errors.
   make[1]: *** [Makefile:1283: prepare0] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:226: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +/WARN +285 include/linux/jump_label.h

bf5438fca2950b Jason Baron     2010-09-17  282  
c5905afb0ee655 Ingo Molnar     2012-02-24  283  static inline void static_key_slow_inc(struct static_key *key)
d430d3d7e646eb Jason Baron     2011-03-16  284  {
5cdda5117e125e Borislav Petkov 2017-10-18 @285  	STATIC_KEY_CHECK_USE(key);
d430d3d7e646eb Jason Baron     2011-03-16  286  	atomic_inc(&key->enabled);
d430d3d7e646eb Jason Baron     2011-03-16  287  }
bf5438fca2950b Jason Baron     2010-09-17  288  
c5905afb0ee655 Ingo Molnar     2012-02-24  289  static inline void static_key_slow_dec(struct static_key *key)
bf5438fca2950b Jason Baron     2010-09-17  290  {
5cdda5117e125e Borislav Petkov 2017-10-18  291  	STATIC_KEY_CHECK_USE(key);
d430d3d7e646eb Jason Baron     2011-03-16  292  	atomic_dec(&key->enabled);
bf5438fca2950b Jason Baron     2010-09-17  293  }
bf5438fca2950b Jason Baron     2010-09-17  294  
ce48c146495a1a Peter Zijlstra  2018-01-22  295  #define static_key_slow_inc_cpuslocked(key) static_key_slow_inc(key)
ce48c146495a1a Peter Zijlstra  2018-01-22  296  #define static_key_slow_dec_cpuslocked(key) static_key_slow_dec(key)
ce48c146495a1a Peter Zijlstra  2018-01-22  297  
4c3ef6d79328c0 Jason Baron     2010-09-17  298  static inline int jump_label_text_reserved(void *start, void *end)
4c3ef6d79328c0 Jason Baron     2010-09-17  299  {
4c3ef6d79328c0 Jason Baron     2010-09-17  300  	return 0;
4c3ef6d79328c0 Jason Baron     2010-09-17  301  }
4c3ef6d79328c0 Jason Baron     2010-09-17  302  
91bad2f8d30574 Jason Baron     2010-10-01  303  static inline void jump_label_lock(void) {}
91bad2f8d30574 Jason Baron     2010-10-01  304  static inline void jump_label_unlock(void) {}
91bad2f8d30574 Jason Baron     2010-10-01  305  
d430d3d7e646eb Jason Baron     2011-03-16  306  static inline int jump_label_apply_nops(struct module *mod)
d430d3d7e646eb Jason Baron     2011-03-16  307  {
d430d3d7e646eb Jason Baron     2011-03-16  308  	return 0;
d430d3d7e646eb Jason Baron     2011-03-16  309  }
b202952075f626 Gleb Natapov    2011-11-27  310  
e33886b38cc82a Peter Zijlstra  2015-07-24  311  static inline void static_key_enable(struct static_key *key)
e33886b38cc82a Peter Zijlstra  2015-07-24  312  {
5cdda5117e125e Borislav Petkov 2017-10-18  313  	STATIC_KEY_CHECK_USE(key);
e33886b38cc82a Peter Zijlstra  2015-07-24  314  
1dbb6704de91b1 Paolo Bonzini   2017-08-01  315  	if (atomic_read(&key->enabled) != 0) {
1dbb6704de91b1 Paolo Bonzini   2017-08-01 @316  		WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
1dbb6704de91b1 Paolo Bonzini   2017-08-01  317  		return;
1dbb6704de91b1 Paolo Bonzini   2017-08-01  318  	}
1dbb6704de91b1 Paolo Bonzini   2017-08-01  319  	atomic_set(&key->enabled, 1);
e33886b38cc82a Peter Zijlstra  2015-07-24  320  }
e33886b38cc82a Peter Zijlstra  2015-07-24  321  

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202204251346.WbwgrNZw-lkp%40intel.com.

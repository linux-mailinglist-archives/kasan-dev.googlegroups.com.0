Return-Path: <kasan-dev+bncBC4LXIPCY4NRBLPI52UAMGQEVX4QOUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B7E97B60BF
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Oct 2023 08:26:55 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-502fff967ccsf488529e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 23:26:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696314415; cv=pass;
        d=google.com; s=arc-20160816;
        b=ksQFRxO7A5GGcuDYCzlco5c3KgxBFMhk4yiHIB4+1Lx+dSGWpqPhpbKVB1MAFpjcf+
         5lyuePsu1mdTVSePGOdOeoMxROBPK6o0g4hn/C+Q7WODpMv2K4y22EzqYmwi0nY+N+T9
         SHibpyOJkxDoiVZz372pnqtkHmwnN55ULEvbpp+B9NjYTmajmm6UODnB8wS6hDHDQAvN
         CP4WXO6XRAAZvH+IzQkLMixipv4gYnw4v3bzHixzwLWohnhyePtuKdNs8PUTO0yIL+4v
         ZBBlo8ukVyEa8VXniPT9FswpQRsQcdO1/tZ+qYrXn4AOcH762TxuzM2X4iBRRHf2ToWz
         D4pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uDiBZfIq13IZe5eNfEmnabL4Hs6WRFwYn1X8qv6h/Hc=;
        fh=u/MdqG6Pq209I2xecCUBA+qljk9rl0dXuc6AHw9L0no=;
        b=DbUAg2LLcJr9KC/BzU9uGI1HPwgc8BoONkw3V1KVCnz75qTIOnYaYmXgNp8lG7HVnt
         59rLJ5wrpXBHA9yRFmynNer0gLQ7dwZLGZBstC5gmbYs0tURDUxhve4nnGEXPyp7JnE4
         62YaPF584hVd0S+56+MNU4CvouBrQ5MO2K5JS+5jjgS/zdM804FC1SflEX11R5i6C8SO
         C33fX9zWPkdHPDvDHAv5gvuufWnP505pZ4bvYDiuzVrLVnZvViBPHK7RWt751Gi+z2AT
         fPcWcxCmGU2ZBjH7KXA9Fdh5i/bXW2ljArpStzKUHL2B6kq3kcX7c3MaGAuIHsqe8aNB
         VGfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UGAApVf0;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696314415; x=1696919215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uDiBZfIq13IZe5eNfEmnabL4Hs6WRFwYn1X8qv6h/Hc=;
        b=A7Kf5tM3ReG3BS4kaAK/64gPnpKQ7CfC3COx0hBL2VCm8e9RR7dorK4tjUyOK/Jasj
         V29eR+zIyGt/MY2G6/yxB+jE3wBSTVXCXA3Jeb8UmsTDsUieZidmTcTu5xMeo+TRYO36
         74FaCYot8fPItsfLB8oJ7GHpvMZVo/Kv4uazkig0bIysWTxr1ru6lZ/f2R+vzXiQEJsS
         bHdYKkxKYcWRZpKuCU9nlmJxsoGXxsu2xTftLi+9w2qIrb1q87jSnFacaS3Q46Z2Pbt0
         MFFQSMOi+kdXbqdHMddB/Tly3RA+DlZ48RWow6SvT2UZVme5GQ3pv58pfwRP5M6W3B8L
         Ukdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696314415; x=1696919215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uDiBZfIq13IZe5eNfEmnabL4Hs6WRFwYn1X8qv6h/Hc=;
        b=jKtsQLocV5qbpHGhFrmFzq5cNEYmpsCeJmuGmAVnjnSWFJ/Skvpq/qbBuQlVfSPnRP
         ARfUQSVM2LUxOwflUMgxcwDOY5vD79mujGx3KxvemW7p6hsEufSy6H/DGYKlA0Z0k4k0
         5Cp2t5gWSrd7ozIbLrKmKC0sm3euBsha/88AB07A0l7hb90WEY68OfwRCbR+NsAjqF/4
         6sgq0ARjpQF0jg/Cv/3ktGuJTpVKjqhYWCggSYGJAciwITE77USnzZmzXcnu+57rNfay
         xrbMBTi4jfdAmfRViNTkp/hH8AD370mCTGsX8v711lGTN3bU3Y3yZBvNEBFLebo/tkHB
         LXpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTFwTuBSgRiwO3VnQzMi2prNxIS905DNTRQm/iVsCGItpWTR1P
	dvzZ9EgaJ9qUKgxfIrEgNbI=
X-Google-Smtp-Source: AGHT+IGGpzjwDFKgY3F89Rlpevzl5t3Eu4wgP4kjSNy1rqP7XF048IrX67UkWtrID2dfZJv37oRaLA==
X-Received: by 2002:a05:6512:238c:b0:503:3682:2624 with SMTP id c12-20020a056512238c00b0050336822624mr12216676lfv.48.1696314413747;
        Mon, 02 Oct 2023 23:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:915e:0:b0:502:d736:5e79 with SMTP id y30-20020a19915e000000b00502d7365e79ls258557lfj.1.-pod-prod-03-eu;
 Mon, 02 Oct 2023 23:26:52 -0700 (PDT)
X-Received: by 2002:a05:6512:485a:b0:503:90d:e0df with SMTP id ep26-20020a056512485a00b00503090de0dfmr10706156lfb.34.1696314411883;
        Mon, 02 Oct 2023 23:26:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696314411; cv=none;
        d=google.com; s=arc-20160816;
        b=lokJuRs35BBN3vLmR4WHMqhhmRro08zlav+UvxdVBa7ReZe81Bm2Vq6Povwsp+8me/
         5KoTml8jeiEKwSoEOaVSMTh1UHhHnt9nhfVsUEVQjoR1RxTk1TE4vrm14yZFtio9dQC+
         U1EgSkVhHfxnsDJCnMrgB95Vsg6nIVY2rEH2bhzv6VJIz/2kJQdPNdJDVkoBbZ1M7pDA
         YzqwLo9e5C5tdMvI6d/QFCg0ZjR0PjXPDOnRTkSHuKtMTyVS7tjbFbYs0M1/6PTYULiB
         TAjST/ODWA7pM4xt8Vw6RKUzn6KKfpT+bVdHpXm3qYJ8w4TVMr0Yny/QGn1SLm546H9n
         +0wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LLQ8jeURFPSUxZYGth9AN4dXBx934ufF3tdH12arynI=;
        fh=u/MdqG6Pq209I2xecCUBA+qljk9rl0dXuc6AHw9L0no=;
        b=o68PNF+Rx0x085JNiTUDjSGSbAk3J5bp+SXwhfkaH6lwWjmqlMsggLQvmWnAjsCPn6
         /NIuJRY5wzbMoLmsqOg3xWUj01ZGe39MhSSyAmn7LIIzxn1/HZM7CeTRRiwMMrifQLf5
         WZXkdq9dqckb8NL/nrAHpPHpdWQMvuSPPnrgVRhxfyweJMefDBRTbcj8bSE1ohVvRtX3
         Du18ersbgGQz5IMpNnotWU4eSXT39Xvl3/rL+cPYYTOewMRaPLnT4hcrWFB/vlE56GFs
         wdnQSzurecgD/UXJrHgWe/GStarwPHhayjF7UhjlDzhBvnhrKI22Hek6iFOaK5lpQyqc
         asMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UGAApVf0;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id s16-20020a056512203000b004ffa201cad8si25581lfs.9.2023.10.02.23.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Oct 2023 23:26:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10851"; a="373145750"
X-IronPort-AV: E=Sophos;i="6.03,196,1694761200"; 
   d="scan'208";a="373145750"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Oct 2023 23:26:47 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10851"; a="924530368"
X-IronPort-AV: E=Sophos;i="6.03,196,1694761200"; 
   d="scan'208";a="924530368"
Received: from lkp-server02.sh.intel.com (HELO c3b01524d57c) ([10.239.97.151])
  by orsmga005.jf.intel.com with ESMTP; 02 Oct 2023 23:26:43 -0700
Received: from kbuild by c3b01524d57c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1qnYrh-0006qP-2N;
	Tue, 03 Oct 2023 06:26:41 +0000
Date: Tue, 3 Oct 2023 14:25:42 +0800
From: kernel test robot <lkp@intel.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: oe-kbuild-all@lists.linux.dev, Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH 2/5] mm: Introduce pudp/p4dp/pgdp_get() functions
Message-ID: <202310031431.NkMgiRBL-lkp@intel.com>
References: <20231002151031.110551-3-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231002151031.110551-3-alexghiti@rivosinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UGAApVf0;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.20 as permitted
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

Hi Alexandre,

kernel test robot noticed the following build errors:

[auto build test ERROR on linus/master]
[also build test ERROR on v6.6-rc4 next-20231003]
[cannot apply to efi/next]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexandre-Ghiti/riscv-Use-WRITE_ONCE-when-setting-page-table-entries/20231002-231725
base:   linus/master
patch link:    https://lore.kernel.org/r/20231002151031.110551-3-alexghiti%40rivosinc.com
patch subject: [PATCH 2/5] mm: Introduce pudp/p4dp/pgdp_get() functions
config: arm-allyesconfig (https://download.01.org/0day-ci/archive/20231003/202310031431.NkMgiRBL-lkp@intel.com/config)
compiler: arm-linux-gnueabi-gcc (GCC) 13.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231003/202310031431.NkMgiRBL-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202310031431.NkMgiRBL-lkp@intel.com/

All error/warnings (new ones prefixed by >>):

   In file included from include/linux/mm.h:29,
                    from arch/arm/kernel/asm-offsets.c:12:
>> include/linux/pgtable.h:310:21: error: 'pgdp_get' declared as function returning an array
     310 | static inline pgd_t pgdp_get(pgd_t *pgdp)
         |                     ^~~~~~~~
   In file included from ./arch/arm/include/generated/asm/rwonce.h:1,
                    from include/linux/compiler.h:246,
                    from arch/arm/kernel/asm-offsets.c:10:
   include/linux/pgtable.h: In function 'pgdp_get':
>> include/asm-generic/rwonce.h:48:2: warning: returning 'const volatile pmdval_t *' {aka 'const volatile unsigned int *'} from a function with return type 'int' makes integer from pointer without a cast [-Wint-conversion]
      48 | ({                                                                      \
         | ~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      49 |         compiletime_assert_rwonce_type(x);                              \
         |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      50 |         __READ_ONCE(x);                                                 \
         |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      51 | })
         | ~~
   include/linux/pgtable.h:312:16: note: in expansion of macro 'READ_ONCE'
     312 |         return READ_ONCE(*pgdp);
         |                ^~~~~~~~~
   make[3]: *** [scripts/Makefile.build:116: arch/arm/kernel/asm-offsets.s] Error 1
   make[3]: Target 'prepare' not remade because of errors.
   make[2]: *** [Makefile:1202: prepare0] Error 2
   make[2]: Target 'prepare' not remade because of errors.
   make[1]: *** [Makefile:234: __sub-make] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:234: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +/pgdp_get +310 include/linux/pgtable.h

   308	
   309	#ifndef pgdp_get
 > 310	static inline pgd_t pgdp_get(pgd_t *pgdp)
   311	{
   312		return READ_ONCE(*pgdp);
   313	}
   314	#endif
   315	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202310031431.NkMgiRBL-lkp%40intel.com.

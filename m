Return-Path: <kasan-dev+bncBC4LXIPCY4NRBZ6642PAMGQEL33TVTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EFEBD685C09
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 01:16:40 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id x12-20020a056512130c00b004cc7af49b05sf7518629lfu.10
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 16:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675210600; cv=pass;
        d=google.com; s=arc-20160816;
        b=GClZ9TfF4msiUer/kekvSSdCrWYJtogrj3e0Gbtx3FkK4zrQdH9MLlWUtyhHCYtdMC
         awA06l/ptEIz5PPK/hjMpldvGD83Vjq7ySsoCzzWrt6SE2snxC5edvnux5svrqYVWMA4
         Oh9KcrjMmOPRSzcEHva3w0nWRMG2mTuOU25EggxAtfRBrgaRDyWh5aZrLSqep+U3SjEa
         Ion8AsTH9sHdmNWONk90LSAMpnAQUlFROPY54+mJLyEv554mMukgCLJo4XGaPUszF22I
         b34LD0Rn7p/G8he2rBurG+mooJR/mjd4r9fBfzYonaPXzUezek8PUqN+dQgAxHQnw4ET
         fVJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H1RqYJJiVH2ztbUT/wNbEHvUdEPd1VOI6piT5Jj3vr4=;
        b=Hnp7YOoQp5EmXV7hBym6Fyowi4udPRXkzFocxfaeQ2ixWSuNzxD1M7INDa12F1Bml3
         HBl265Od+NftRiO/Qp5EO6+mjthdmLynJGFPLsqskdBg1y2y5syz5l4oslWaBTVRYOXx
         kEEAQJggtsXp95CyAT2l6LAHYrihipgDX8VO1wPU37LRny7SjXavuiJK3jCvD981fGl4
         di9Dm57MysjD3rV6sqiIYiYd0QJMTl2oskAU6VPzIvXT+qHu3zYnTZqyQBW+P581yQr+
         3DZzKm8PtdIXI/Wq9A4v0NuHTzewdzJZyBFbMDh00LhoyHhgEmeEukd+pCdyONhHbdxV
         9b1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="dKtWxd/Y";
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=H1RqYJJiVH2ztbUT/wNbEHvUdEPd1VOI6piT5Jj3vr4=;
        b=Q1hV/481x5m7oz7+P5mySu7GAG6YjCWunie42VCHJ1KKNg4IG1B94+alC3VebVp+5q
         ZUrqu8Cp3gUkT6c06MYPQ1cQnyTNwMp6WoWSOXTol3sfCwvaWfX2kAoYjKzWP3V+43ql
         d1J/3+l2MbYzm8i1MiGNiU6YYp4wcY1RQI0bc2mbmxq7EFAiBgoThOkO2JJ19D/nBqiC
         fNB/pl88kbFhpUZugGNSnc6x+aqt9A5CF7ucU8/P8Sf1PhL4DfyL6y2d++VO0OjUlTph
         SgA4E2n0cbC3xFxQ3RReHRGlhPAsa3un5QPukkC2h7Me7JRs44+IzOGLERJ0QfbNEsw2
         vpDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H1RqYJJiVH2ztbUT/wNbEHvUdEPd1VOI6piT5Jj3vr4=;
        b=rD1OWLxh90otaEiCHpdkmIPzc7+znJq5Ul6qJaWmPq15Hr7ZGS0jp8n0ITfda8WvF3
         6yekA/B+ZuDFYds/KnPb9nRwcl5UfSV9ElqhgWbRs9yu9gjwkSaCRSfqY1kqS1UbJ3AQ
         f8fP/jFCV093wyE/s4htDvqoKYKrQsbebhR0zT8mulxYGmiKXTiH83GewbliuHMo2zz7
         p8Rvh7Cu7LQNnHQG3tMKezVOl9gCQyi25W86PtTcU99aaU82+hmWfGmUWLf0a04XBxYn
         0DL2iDXzR9izaA0bLAORjcfakjjNnZHtSU/eTLaAZWwKqJRRVkAZAhuGIv5POdSlGH7o
         aLxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV9KipvlOsj9nCCrAUAMdZLt4RJewu+GDva5/c9wl1yk8sNGC5/
	p6lcK7EaVZiY8UBAW0g0cII=
X-Google-Smtp-Source: AK7set//dPuyFG0857Wd8eWuRp75iky2HuLRAVxWmdyvBNqyzlg+4R3U0x3XGpWghwrVb6v0lhDwiQ==
X-Received: by 2002:a05:651c:1214:b0:290:5970:ce1d with SMTP id i20-20020a05651c121400b002905970ce1dmr33098lja.48.1675210600220;
        Tue, 31 Jan 2023 16:16:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls1593109lfc.0.-pod-prod-gmail;
 Tue, 31 Jan 2023 16:16:38 -0800 (PST)
X-Received: by 2002:a05:6512:3da0:b0:4a4:6af4:43b7 with SMTP id k32-20020a0565123da000b004a46af443b7mr18233lfv.69.1675210598760;
        Tue, 31 Jan 2023 16:16:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675210598; cv=none;
        d=google.com; s=arc-20160816;
        b=GNpAmBaASiQncWaa0G4vwOA0+MQJi9BUTSyG7SzOnHRRFiKEUT+aF4vH1aS01f+L5v
         6Iw/sT87TOlLGxGlT97DxR4lXIj0G92DKR1N27UaG/byJ4mQoQDbvF1/DQZOkYfQjZKn
         eoc6Q8yjOoW1iOiCLEDkTw4MRm4T291NvTGJzdYxbhBvGO2xWS8SNmeTrtjaKt5GnVxm
         Fl4exx/5n608M42/meo20XRUCsrll86jtzcq112eCjnoUvHnRlqjlDfkOp1OQ6cqmDoD
         bg6agYWt6RuIBZR4E2MEcAHGKj2KOaqpGn63cvWwDy5KM8P2Lc1+XTfGeU2nLkWg6npa
         Ye7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FM84qKqbt/H6Mn2b/GnC6Q1BgQyY4TzrxZftjK+5pEs=;
        b=khi2XaHSfN6Hhiu5BtLzkusGFHYV0pZZbbxFdDt+3mw3ziNIQ29qMW9O6Lu44ZrhpZ
         E+idzX3pKQltOUxp/y0DJEZZBVPoxfoZRumauLlUHczXv9RVcyVC9birQMLA5VmJXhbn
         ABQQnEoY5LkpFnSqQaWIjAf4On4s/4aYW1QV2Mq//k+IM5TprUTE2acVP8p6II2BqZf8
         FGBrKQE1IroeGZI5iuk8azO5PXAIRZmzgulincdwcvj3YHhRcFIDQoIAufNBysMNvP34
         +CH+0zyExRal2drxNabraRmo1lG/jdKZ4+rKeQThrzDsaieEw6WW+TiPpRrtyyztCt7g
         /Y8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="dKtWxd/Y";
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id i30-20020a0565123e1e00b004d5e038aba2si886589lfv.7.2023.01.31.16.16.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Jan 2023 16:16:38 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10607"; a="330108530"
X-IronPort-AV: E=Sophos;i="5.97,261,1669104000"; 
   d="scan'208";a="330108530"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 31 Jan 2023 16:16:36 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10607"; a="838579710"
X-IronPort-AV: E=Sophos;i="5.97,261,1669104000"; 
   d="scan'208";a="838579710"
Received: from lkp-server01.sh.intel.com (HELO ffa7f14d1d0f) ([10.239.97.150])
  by orsmga005.jf.intel.com with ESMTP; 31 Jan 2023 16:16:32 -0800
Received: from kbuild by ffa7f14d1d0f with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1pN0ne-0004pS-39;
	Wed, 01 Feb 2023 00:16:30 +0000
Date: Wed, 1 Feb 2023 08:15:57 +0800
From: kernel test robot <lkp@intel.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-efi@vger.kernel.org
Cc: oe-kbuild-all@lists.linux.dev, Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH v3 2/6] riscv: Rework kasan population functions
Message-ID: <202302010819.RAsjyv6V-lkp@intel.com>
References: <20230125082333.1577572-3-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125082333.1577572-3-alexghiti@rivosinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="dKtWxd/Y";       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.65 as permitted
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

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on linus/master]
[also build test WARNING on v6.2-rc6 next-20230131]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexandre-Ghiti/riscv-Split-early-and-final-KASAN-population-functions/20230125-163113
patch link:    https://lore.kernel.org/r/20230125082333.1577572-3-alexghiti%40rivosinc.com
patch subject: [PATCH v3 2/6] riscv: Rework kasan population functions
config: riscv-randconfig-r006-20230201 (https://download.01.org/0day-ci/archive/20230201/202302010819.RAsjyv6V-lkp@intel.com/config)
compiler: riscv64-linux-gcc (GCC) 12.1.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/c18726e8d14edbd59ec19854b4eb06d83fff716f
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Alexandre-Ghiti/riscv-Split-early-and-final-KASAN-population-functions/20230125-163113
        git checkout c18726e8d14edbd59ec19854b4eb06d83fff716f
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-12.1.0 make.cross W=1 O=build_dir ARCH=riscv olddefconfig
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-12.1.0 make.cross W=1 O=build_dir ARCH=riscv SHELL=/bin/bash arch/riscv/mm/

If you fix the issue, kindly add following tag where applicable
| Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

>> arch/riscv/mm/kasan_init.c:442:6: warning: no previous prototype for 'create_tmp_mapping' [-Wmissing-prototypes]
     442 | void create_tmp_mapping(void)
         |      ^~~~~~~~~~~~~~~~~~


vim +/create_tmp_mapping +442 arch/riscv/mm/kasan_init.c

   441	
 > 442	void create_tmp_mapping(void)
   443	{
   444		void *ptr;
   445		p4d_t *base_p4d;
   446	
   447		/*
   448		 * We need to clean the early mapping: this is hard to achieve "in-place",
   449		 * so install a temporary mapping like arm64 and x86 do.
   450		 */
   451		memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(pgd_t) * PTRS_PER_PGD);
   452	
   453		/* Copy the last p4d since it is shared with the kernel mapping. */
   454		if (pgtable_l5_enabled) {
   455			ptr = (p4d_t *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
   456			memcpy(tmp_p4d, ptr, sizeof(p4d_t) * PTRS_PER_P4D);
   457			set_pgd(&tmp_pg_dir[pgd_index(KASAN_SHADOW_END)],
   458				pfn_pgd(PFN_DOWN(__pa(tmp_p4d)), PAGE_TABLE));
   459			base_p4d = tmp_p4d;
   460		} else {
   461			base_p4d = (p4d_t *)tmp_pg_dir;
   462		}
   463	
   464		/* Copy the last pud since it is shared with the kernel mapping. */
   465		if (pgtable_l4_enabled) {
   466			ptr = (pud_t *)p4d_page_vaddr(*(base_p4d + p4d_index(KASAN_SHADOW_END)));
   467			memcpy(tmp_pud, ptr, sizeof(pud_t) * PTRS_PER_PUD);
   468			set_p4d(&base_p4d[p4d_index(KASAN_SHADOW_END)],
   469				pfn_p4d(PFN_DOWN(__pa(tmp_pud)), PAGE_TABLE));
   470		}
   471	}
   472	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202302010819.RAsjyv6V-lkp%40intel.com.

Return-Path: <kasan-dev+bncBC4LXIPCY4NRBPP35GHQMGQENKDYNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A06A4A7108
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 13:49:02 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id w7-20020adfbac7000000b001d6f75e4faesf6869189wrg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 04:49:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643806142; cv=pass;
        d=google.com; s=arc-20160816;
        b=gE95IqKIsYojVsPgUnro/EzvnNzt46T6+a9DbaHKTktFJRBKLYaEAvdDycPazXuRjf
         d3GDO41gtZ1r+mFVeiMYGQTimSHSWmi/kKERPjYocDTXzz8QgMJcgbnF04X1xjkj3edJ
         +fXEiBh7qfdrBWNW4OCVJjKsyiIlG4IAWCVRnaPUS+3JDGWPbmbZzDsRlfs4Uwt6ka5C
         fagcpAxevU30503XnX8Ckxw9TgveEC0hS/T+n7h8j5EppZ8rhlWTwXrGY5BlxAt2VvsD
         MlitN6/b13qYLPIvbUpVdW5DICEHhoVR+8sPlBGtxF6cmm1rqZbtnffKV9rdd6/6HFlg
         N3gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=HMzlecq5gwB9a8nz7GRwaGAC0q0NTUAiJIDcNX0QWn8=;
        b=SmRmR1tgN6zcPVIKih3who+BtJZksYJB3ZiY+WkVqYzNrStuf6Yms6rQK1vn+nbH7B
         rrgJWWleKhbIJuZIlRR4pUSUeg30PDGMT1EeAyjcwObJAHGECgegJhJd6/g2lqBesO0z
         RDcZNhqZyjmgGNJo3gGBL3NvZkwfyPmIpjH/uOa25CBTRQo9NNgYYRv3qU8YNM8Yom0/
         UhkdwpCOnjig79db1L0z1nRykOKf3SIbFjI7zfRUUW7fTIPSTib/6HnBQ/Jn5sDxQo2s
         X9r79X+cMIqtMvrE4QsEu397S1N65R0kPEhdJWW5bolErJmasjCxL0QNmERDGOZsfxr0
         mtPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Dzoi4e4K;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HMzlecq5gwB9a8nz7GRwaGAC0q0NTUAiJIDcNX0QWn8=;
        b=Ri2J/PATffFR6EB8xPxjaRXscFnnlEckrI12QPUt8jjeokxgrwSQsTQkQppe84WiwG
         4+TryYzxRt1O7+tYPo3ZJYj+sqt1xNRLyLY/0fLx+vdcfd/ShOoOhxOp3BpFWzPgd9qW
         lu0W+R+hJTs736xJPLk/Eu7egt8TP5Ec3hgJqR4Mu/EOn4M74eVIDvNUeEoYPyt7sVFD
         3IxLcxZ8NcjA6Gn+VKaYCB8xXciz0L0aRRXnIYdDfg8X4cpH5Gf92xN8W6jkJINj0P6V
         tUWNjDGyJtOO2Fo8L0SSe1VB+Dev5Avf88dO2J+A2+X2nOVDNlRl0TlJkCQKNXEMun4I
         78Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HMzlecq5gwB9a8nz7GRwaGAC0q0NTUAiJIDcNX0QWn8=;
        b=7NFropFOwOX/lAgBBi44AvWrEl6rbWOLxmBUKNSGK4x3NTEXh32Yo2fxGqA2JUMlKQ
         BSPAMTOYiAM9OgkHydGymR3vh6qL2/SwJVqtuiZf86n5R7iErDN0Poz8lED0faQtDfBe
         I+THPEBtLeZRN8OHwC5Uy5PHxoRRX9BeuiZc327F5O48t/OpLlrl2nuMwPhCw77ir0lS
         5rki6opFjYp1lSAHHlvTB/hV3zop9wAHSDWg5/1wEuzR9zaLqyIGyFd9SeY3j/I68kAY
         5pO64VoLXcF1GFZp6yKMghF+Pi2ww/IFLs/R2GyxwGNK33Z3X2NjFShOHFYc6cSfEEBm
         a3MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oVI7ohL643eBhKfLqEvxLP2+iONA8d0fgQy8WCbN4h0rEdpM0
	cPBC0+Afu+jNXq45QG4DB4w=
X-Google-Smtp-Source: ABdhPJyM44nZGPz/1px17cHkdEcTP1aFcQxPOFv7IBRa8RNEP706UFn1/nCbu2kzPrbS5jWemU9XmQ==
X-Received: by 2002:a05:6000:1a8c:: with SMTP id f12mr15160915wry.153.1643806142019;
        Wed, 02 Feb 2022 04:49:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:694d:: with SMTP id r13ls132482wrw.3.gmail; Wed, 02 Feb
 2022 04:49:01 -0800 (PST)
X-Received: by 2002:a05:6000:2c6:: with SMTP id o6mr24665884wry.652.1643806141109;
        Wed, 02 Feb 2022 04:49:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643806141; cv=none;
        d=google.com; s=arc-20160816;
        b=VgQ5Edxm+rXPyGhq3r1WiWxgSPmNpglhbhjU/Gu+s6BZ8smAsdmZ2sY8Ucvlbsm0w6
         WEWLahQ/Ddyq1k6QU1Eqb86B+Wyk9YkDLgZ64qgAr7rET/LmvmabuTbyPUsrkZjUk8K2
         y5oTzObZnrmGiOxJy2MZIjDLRIMh2QOQOf39qe49PIjn4lduKzUSd//HPZCK8eUYbGmz
         /n/wVxGnqwKbvDYT10yxuzeS5NY1BiF9+zr0ciKQ2GG/zS34vfYkrQqD80KC5Avcmnwc
         ZZ24u8lsfxKHC/30wCAMgFT/NTgtfL6WL1aLA1sIg3iNqAobNI1FEa6EYzTvm1QZ+riB
         tqkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=S8xFoYAKrReiu59zd7UrpcZcdCu8dsHolcjZ5jizCUM=;
        b=o9a7oEQ5x9Rp703j3pmDZT5sXpIXlmPLObIrs3E3HvLDTX3Ha4wWMHQI7lVOQQF1qq
         aasGvbDy7gPCk6wGqNj6swCDUOdbJyCy1KjJdiBAAt36EUNgYk00On7fSJ0MDNz3XG0m
         O/beNuajUxWdISMmF3JjKyzZppUqs0/6PFRxzd8W2JzT/GSi4JBZPGz30BlRIWxNoQDh
         n3Z8ll02/sbLelHcMRH3IoT6AxTpuH3T6nD2O73fGwwCIsRXQ352reA9z0xMNwmUWzwH
         MrqF9X+VvF9JWYja6lL4/kmLmSG0OHUsRrDDxUTjbzDntyUijK52CXraaN9IIWhQcH78
         EamA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Dzoi4e4K;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id l24si361445wmg.1.2022.02.02.04.49.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Feb 2022 04:49:01 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6200,9189,10245"; a="247676219"
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="247676219"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Feb 2022 04:48:59 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="480094065"
Received: from lkp-server01.sh.intel.com (HELO 276f1b88eecb) ([10.239.97.150])
  by orsmga003.jf.intel.com with ESMTP; 02 Feb 2022 04:48:56 -0800
Received: from kbuild by 276f1b88eecb with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nFF4B-000UaO-M6; Wed, 02 Feb 2022 12:48:55 +0000
Date: Wed, 2 Feb 2022 20:48:49 +0800
From: kernel test robot <lkp@intel.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-hardening@vger.kernel.org" <linux-hardening@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/4] mm/kasan: Move kasan_pXX_table() and
 kasan_early_shadow_page_entry()
Message-ID: <202202022041.mkJKLdPP-lkp@intel.com>
References: <3fe9bf0867b2ffc7cd43fe7040ee18d245641ec1.1643791473.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3fe9bf0867b2ffc7cd43fe7040ee18d245641ec1.1643791473.git.christophe.leroy@csgroup.eu>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Dzoi4e4K;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted
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

Hi Christophe,

I love your patch! Yet something to improve:

[auto build test ERROR on tip/sched/core]
[also build test ERROR on linus/master v5.17-rc2]
[cannot apply to hnaz-mm/master next-20220202]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/Christophe-Leroy/mm-kasan-Add-CONFIG_KASAN_SOFTWARE/20220202-164612
base:   https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git ec2444530612a886b406e2830d7f314d1a07d4bb
config: riscv-randconfig-r042-20220130 (https://download.01.org/0day-ci/archive/20220202/202202022041.mkJKLdPP-lkp@intel.com/config)
compiler: riscv64-linux-gcc (GCC) 11.2.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/23eabd57613c3b304c1c54f1133ef5376cf5731d
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review Christophe-Leroy/mm-kasan-Add-CONFIG_KASAN_SOFTWARE/20220202-164612
        git checkout 23eabd57613c3b304c1c54f1133ef5376cf5731d
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.2.0 make.cross O=build_dir ARCH=riscv SHELL=/bin/bash kernel/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from include/linux/slab.h:136,
                    from kernel/fork.c:16:
>> include/linux/kasan.h:102:36: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     102 | static inline bool kasan_pud_table(p4d_t p4d)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:113:36: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     113 | static inline bool kasan_pmd_table(pud_t pud)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:130:36: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     130 | static inline bool kasan_pte_table(pmd_t pmd)
         |                                    ^~~~~
         |                                    pgd_t
   kernel/fork.c:162:13: warning: no previous prototype for 'arch_release_task_struct' [-Wmissing-prototypes]
     162 | void __weak arch_release_task_struct(struct task_struct *tsk)
         |             ^~~~~~~~~~~~~~~~~~~~~~~~
   kernel/fork.c:764:20: warning: no previous prototype for 'arch_task_cache_init' [-Wmissing-prototypes]
     764 | void __init __weak arch_task_cache_init(void) { }
         |                    ^~~~~~~~~~~~~~~~~~~~
--
   In file included from include/linux/slab.h:136,
                    from kernel/resource.c:17:
>> include/linux/kasan.h:102:36: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     102 | static inline bool kasan_pud_table(p4d_t p4d)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:113:36: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     113 | static inline bool kasan_pmd_table(pud_t pud)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:130:36: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     130 | static inline bool kasan_pte_table(pmd_t pmd)
         |                                    ^~~~~
         |                                    pgd_t
--
   In file included from include/linux/slab.h:136,
                    from include/linux/resource_ext.h:11,
                    from include/linux/acpi.h:14,
                    from kernel/irq/irqdomain.c:5:
>> include/linux/kasan.h:102:36: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     102 | static inline bool kasan_pud_table(p4d_t p4d)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:113:36: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     113 | static inline bool kasan_pmd_table(pud_t pud)
         |                                    ^~~~~
         |                                    pgd_t
>> include/linux/kasan.h:130:36: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     130 | static inline bool kasan_pte_table(pmd_t pmd)
         |                                    ^~~~~
         |                                    pgd_t
   kernel/irq/irqdomain.c:1918:13: warning: no previous prototype for 'irq_domain_debugfs_init' [-Wmissing-prototypes]
    1918 | void __init irq_domain_debugfs_init(struct dentry *root)
         |             ^~~~~~~~~~~~~~~~~~~~~~~


vim +102 include/linux/kasan.h

    84	
    85	#if defined(CONFIG_KASAN_SOFTWARE) && CONFIG_PGTABLE_LEVELS > 4
    86	static inline bool kasan_p4d_table(pgd_t pgd)
    87	{
    88		return pgd_page(pgd) == virt_to_page(lm_alias(kasan_early_shadow_p4d));
    89	}
    90	#else
    91	static inline bool kasan_p4d_table(pgd_t pgd)
    92	{
    93		return false;
    94	}
    95	#endif
    96	#if defined(CONFIG_KASAN_SOFTWARE) && CONFIG_PGTABLE_LEVELS > 3
    97	static inline bool kasan_pud_table(p4d_t p4d)
    98	{
    99		return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
   100	}
   101	#else
 > 102	static inline bool kasan_pud_table(p4d_t p4d)
   103	{
   104		return false;
   105	}
   106	#endif
   107	#if defined(CONFIG_KASAN_SOFTWARE) && CONFIG_PGTABLE_LEVELS > 2
   108	static inline bool kasan_pmd_table(pud_t pud)
   109	{
   110		return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
   111	}
   112	#else
 > 113	static inline bool kasan_pmd_table(pud_t pud)
   114	{
   115		return false;
   116	}
   117	#endif
   118	
   119	#ifdef CONFIG_KASAN_SOFTWARE
   120	static inline bool kasan_pte_table(pmd_t pmd)
   121	{
   122		return pmd_page(pmd) == virt_to_page(lm_alias(kasan_early_shadow_pte));
   123	}
   124	
   125	static inline bool kasan_early_shadow_page_entry(pte_t pte)
   126	{
   127		return pte_page(pte) == virt_to_page(lm_alias(kasan_early_shadow_page));
   128	}
   129	#else
 > 130	static inline bool kasan_pte_table(pmd_t pmd)
   131	{
   132		return false;
   133	}
   134	

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202022041.mkJKLdPP-lkp%40intel.com.

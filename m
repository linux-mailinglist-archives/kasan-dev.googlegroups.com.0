Return-Path: <kasan-dev+bncBC4LXIPCY4NRBM5GYGBQMGQEKRALQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C9F9359FA0
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 15:14:28 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id g12sf3737809ion.15
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 06:14:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617974067; cv=pass;
        d=google.com; s=arc-20160816;
        b=LXu/q7dfeVW4l0/B8EFZjZDMUsgaX/17gZ2j2Ij5gfKcvJXd3k7uwmOlKxd223Nl+W
         9ChfPaaO8FgeaGHZC5zdi/NJff5Czz0VmRqB9xdmOx3XCZsqkG6YY0N2sc6wIufm6Srz
         gxBCMcVIqDMFJeoaoY0p3Xa2nnGcSr6Os/1ExzJuOJFQbHPnkcXQ8EXV0rpILG9ZA/nD
         GrXg4KN1u+lXGUAAoMVPcLJFPRdsg2tnjoCL8xeQTLWSUTkvmJ0WfeM5hV9xH/bpKqYm
         p75013hIPMBO6et9J/bUjItJYLUQ5ew5nHFHHBGM7OmlcADDYFkQ5lIjjZK3WQD4S9Zv
         CO6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=ILjgj1WtF0S635+P4fB0yFOs08zHdexXaWwgjgW7Pyg=;
        b=Pr/xsTtSRLrpporJLpcNh9QqgHTYR32alLxE6Sps4e37e7QQgYhwzKcCglssCXMXv6
         jm32Ra0M0/O7aPRSzNjKSYwO83vA0mU2GlAdavTe2uEi/s6Wf+JQVK6lyKcAXh8vSZg5
         H+WNt1zycMxSHZjcpq1Y5v82RQp40IxkyNlNDBX5+ZE974ykbsnXJduU1mjhr2zTvMUB
         hyr6KW3G5ki83js6HBx9sIz9QSucC3W1PPg6j+qxwZ34Jt0HqAD3KTOxd1vp7B6C23fq
         JC0jC3EFvBEi503vRU3/b3tD+0VMtCZTzPjrVCkHJNFrr/fKYStFOrl+bxHkAbwQspPV
         w+Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILjgj1WtF0S635+P4fB0yFOs08zHdexXaWwgjgW7Pyg=;
        b=JcPbhmRVGeDldeKvJzv2rvtaXpqNxgogl9p5OD6GCJUkZbD1DXqKQF3AO2j7FOril4
         v+vH31dl45cwIS5kwU3TozHiU+nZHTr6CejyBWWEjVj++pf4Oig21cGs+NBa5FBUMOLt
         UVoGTY0Pd5md0J4EHQxQSQw9xU26XJsFvgMzIUzSkK2i6L8i1Jm3e5WjV/Ggr5WQpqiy
         AlgUKsFkOX9J/gF+pTsocMChzaW7BVLa8oYHwmAX1biwHaVQddI2oUH6ngSf5xLyXYdM
         /eIIcw2lHhDSC7pRvRRQ2+Wy//9IEy7PS9e9oIDkZUP9aENlMUeoYkJsa439D4eD28CY
         EIXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:date:from:to:cc
         :subject:message-id:references:mime-version:content-disposition
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILjgj1WtF0S635+P4fB0yFOs08zHdexXaWwgjgW7Pyg=;
        b=Wb63Esl273eosdN9GnGy8Vw2d1fxcN/GFIjipj3sUchCVt8c4wLAR46+i+TJctod40
         SF/22aZxyGe32L/n333O41GTflvrDV2yh0Q2ErPQL76NV5ZA3hjAFcWl4tsvl0Uc4yTV
         u95g43iQVMJBKmoLDw3S0aQfd3uj2b2DsWLEb1aBNfUGKaQbMuTcx8vHKH1Cg4b0ldXt
         qIW3O+1CLVCv6w8mnDFHyDfuJNmPpW84QjZZEmTBTN6smb/EyMXtClM7K56AIc+dbHfB
         qZayMf6wOBxlApaDTyYy7ruSyU2cF9/X0Om+nZMXCdVcgXPmVO1M28d0Kw13wqdTC3ZH
         VQuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315Ud7kWMQw8f6l6xyVzhlUqoq7reYADgzFT2fR7rbx1JItenST
	uEk5S0btIdaVCzv6JX85mMk=
X-Google-Smtp-Source: ABdhPJwxOvcBcTzG1PC3XfVZ11zOa98FKGb6S8eBCzxICv4HKLdZOrLim5X1RqPf1yGHd1kM5Zx5YA==
X-Received: by 2002:a92:c24c:: with SMTP id k12mr10897728ilo.75.1617974067099;
        Fri, 09 Apr 2021 06:14:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1061:: with SMTP id q1ls1971817ilj.4.gmail; Fri, 09
 Apr 2021 06:14:26 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c21:: with SMTP id m1mr11784876ilh.204.1617974066280;
        Fri, 09 Apr 2021 06:14:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617974066; cv=none;
        d=google.com; s=arc-20160816;
        b=WUD3Rs0EY36/O5ncS9+I0PJKlGksiZcl9mjMAvYzWVc22g7MjgqqTh2b9WZxeSj9wz
         oLdhumX6AKJCEoGsq+jojF84guLyYJmumUQopOok3ML6wDgs8KlJ9Y7IhxzTkmDUtQeP
         nkj21wix1m3VF2Mw74heo+K0p+6wnikLK0JsoDiXAM4BzGI+VPC5egiTrfh8LYbWytKz
         lAQYdvKws3B46ugJmVLjlis804i8YtgDdeo5GGaaNkbPtQsDFBZwBYOT2mPIYdaqRD7g
         reDalyH3quXevt7TWGT9jqIGBpJ9mjUwfDh/AropOQSYgk6VQh4BC3OApIAWRMvf2VZC
         vqGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:ironport-sdr:ironport-sdr;
        bh=GB/ILt2gwBlH+/UXRu8Y8LYijjV53KbaR9OQfkMig7c=;
        b=cJOHjIvELMbs4Re02g0T7f5FJPo1ngs4w8H7wrd6OAWjg1/abDHxJVQ1SlRGFXIg/V
         chmarbhculmM8yuKJ4XxCqhELK9lVfcAgtZCVIDvIAgBn3wgwWM0zGUoagjE8PcU/8vA
         uYcesRwJWK5sH8UiEWtckvVJT4k7fumYFeLvufQDFD3MsWj8UVeomDJ7zfUYp81wddG+
         NrfrqHSnzq4b4ELol/uQeOFSSJRraBndIjhpfG91kZq1hw0TSXZqc40tddbm0ednxRyB
         ugykkpw5KTh5uYXwZ8JloCbJtkkqrbNtNYla/wYdMomEUiby8TQVpUs/fHNwYuIJRNqH
         8m4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id r15si154369ill.3.2021.04.09.06.14.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Apr 2021 06:14:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
IronPort-SDR: HybIubbbOWoRz04UcNLVTj+KMnWY1PiLCG5gBxx18AZNoJhCma0a/Vy4O61K4HgnTunS9yJnWr
 MVhwDlh45lqg==
X-IronPort-AV: E=McAfee;i="6000,8403,9949"; a="193872346"
X-IronPort-AV: E=Sophos;i="5.82,209,1613462400"; 
   d="gz'50?scan'50,208,50";a="193872346"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2021 06:14:25 -0700
IronPort-SDR: Sm0fOG9fjLZyvrl0Od8KyEZUDe5mNlxjsgTxkutXWveU9lobqMeJdA+qjfWmYidxPqJM3NqPqd
 muHpjIvWS1NA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.82,209,1613462400"; 
   d="gz'50?scan'50,208,50";a="380647196"
Received: from lkp-server01.sh.intel.com (HELO 69d8fcc516b7) ([10.239.97.150])
  by orsmga003.jf.intel.com with ESMTP; 09 Apr 2021 06:14:22 -0700
Received: from kbuild by 69d8fcc516b7 with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1lUqxp-000GqE-Qv; Fri, 09 Apr 2021 13:14:21 +0000
Date: Fri, 9 Apr 2021 21:14:06 +0800
From: kernel test robot <lkp@intel.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: kbuild-all@lists.01.org, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, stable@vger.kernel.org
Subject: Re: [PATCH v2] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <202104092126.pvVQG3UB-lkp@intel.com>
References: <20210409101902.2800-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="RnlQjJ0d97Da+TV1"
Content-Disposition: inline
In-Reply-To: <20210409101902.2800-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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


--RnlQjJ0d97Da+TV1
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi Vincenzo,

I love your patch! Yet something to improve:

[auto build test ERROR on arm/for-next]
[also build test ERROR on soc/for-next kvmarm/next linus/master v5.12-rc6 next-20210408]
[cannot apply to arm64/for-next/core xlnx/master]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/Vincenzo-Frascino/arm64-mte-Move-MTE-TCF0-check-in-entry-common/20210409-182215
base:   git://git.armlinux.org.uk/~rmk/linux-arm.git for-next
config: arm64-allnoconfig (attached as .config)
compiler: aarch64-linux-gcc (GCC) 9.3.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/59174442d4b85039bfec7ede4825ff2b5c0b4331
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review Vincenzo-Frascino/arm64-mte-Move-MTE-TCF0-check-in-entry-common/20210409-182215
        git checkout 59174442d4b85039bfec7ede4825ff2b5c0b4331
        # save the attached .config to linux build tree
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-9.3.0 make.cross ARCH=arm64 

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All error/warnings (new ones prefixed by >>):

   In file included from arch/arm64/include/asm/pgtable.h:12,
                    from include/linux/pgtable.h:6,
                    from include/linux/mm.h:33,
                    from arch/arm64/kernel/asm-offsets.c:12:
>> arch/arm64/include/asm/mte.h:89:1: warning: ignoring attribute 'gnu_inline' because it conflicts with attribute 'noinline' [-Wattributes]
      89 | {
         | ^
   arch/arm64/include/asm/mte.h:34:14: note: previous declaration here
      34 | void noinstr check_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
>> arch/arm64/include/asm/mte.h:88:20: error: static declaration of 'check_mte_async_tcf0' follows non-static declaration
      88 | static inline void check_mte_async_tcf0(void)
         |                    ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:34:14: note: previous declaration of 'check_mte_async_tcf0' was here
      34 | void noinstr check_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:92:1: warning: ignoring attribute 'gnu_inline' because it conflicts with attribute 'noinline' [-Wattributes]
      92 | {
         | ^
   arch/arm64/include/asm/mte.h:35:14: note: previous declaration here
      35 | void noinstr clear_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
>> arch/arm64/include/asm/mte.h:91:20: error: static declaration of 'clear_mte_async_tcf0' follows non-static declaration
      91 | static inline void clear_mte_async_tcf0(void)
         |                    ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:35:14: note: previous declaration of 'clear_mte_async_tcf0' was here
      35 | void noinstr clear_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
--
   In file included from arch/arm64/include/asm/pgtable.h:12,
                    from include/linux/pgtable.h:6,
                    from include/linux/mm.h:33,
                    from arch/arm64/kernel/asm-offsets.c:12:
>> arch/arm64/include/asm/mte.h:89:1: warning: ignoring attribute 'gnu_inline' because it conflicts with attribute 'noinline' [-Wattributes]
      89 | {
         | ^
   arch/arm64/include/asm/mte.h:34:14: note: previous declaration here
      34 | void noinstr check_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
>> arch/arm64/include/asm/mte.h:88:20: error: static declaration of 'check_mte_async_tcf0' follows non-static declaration
      88 | static inline void check_mte_async_tcf0(void)
         |                    ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:34:14: note: previous declaration of 'check_mte_async_tcf0' was here
      34 | void noinstr check_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:92:1: warning: ignoring attribute 'gnu_inline' because it conflicts with attribute 'noinline' [-Wattributes]
      92 | {
         | ^
   arch/arm64/include/asm/mte.h:35:14: note: previous declaration here
      35 | void noinstr clear_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
>> arch/arm64/include/asm/mte.h:91:20: error: static declaration of 'clear_mte_async_tcf0' follows non-static declaration
      91 | static inline void clear_mte_async_tcf0(void)
         |                    ^~~~~~~~~~~~~~~~~~~~
   arch/arm64/include/asm/mte.h:35:14: note: previous declaration of 'clear_mte_async_tcf0' was here
      35 | void noinstr clear_mte_async_tcf0(void);
         |              ^~~~~~~~~~~~~~~~~~~~
   make[2]: *** [scripts/Makefile.build:116: arch/arm64/kernel/asm-offsets.s] Error 1
   make[2]: Target '__build' not remade because of errors.
   make[1]: *** [Makefile:1233: prepare0] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:215: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +/check_mte_async_tcf0 +88 arch/arm64/include/asm/mte.h

    20	
    21	void mte_clear_page_tags(void *addr);
    22	unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
    23					      unsigned long n);
    24	unsigned long mte_copy_tags_to_user(void __user *to, void *from,
    25					    unsigned long n);
    26	int mte_save_tags(struct page *page);
    27	void mte_save_page_tags(const void *page_addr, void *tag_storage);
    28	bool mte_restore_tags(swp_entry_t entry, struct page *page);
    29	void mte_restore_page_tags(void *page_addr, const void *tag_storage);
    30	void mte_invalidate_tags(int type, pgoff_t offset);
    31	void mte_invalidate_tags_area(int type);
    32	void *mte_allocate_tag_storage(void);
    33	void mte_free_tag_storage(char *storage);
  > 34	void noinstr check_mte_async_tcf0(void);
    35	void noinstr clear_mte_async_tcf0(void);
    36	
    37	#ifdef CONFIG_ARM64_MTE
    38	
    39	/* track which pages have valid allocation tags */
    40	#define PG_mte_tagged	PG_arch_2
    41	
    42	void mte_sync_tags(pte_t *ptep, pte_t pte);
    43	void mte_copy_page_tags(void *kto, const void *kfrom);
    44	void flush_mte_state(void);
    45	void mte_thread_switch(struct task_struct *next);
    46	void mte_suspend_exit(void);
    47	long set_mte_ctrl(struct task_struct *task, unsigned long arg);
    48	long get_mte_ctrl(struct task_struct *task);
    49	int mte_ptrace_copy_tags(struct task_struct *child, long request,
    50				 unsigned long addr, unsigned long data);
    51	
    52	void mte_assign_mem_tag_range(void *addr, size_t size);
    53	
    54	#else /* CONFIG_ARM64_MTE */
    55	
    56	/* unused if !CONFIG_ARM64_MTE, silence the compiler */
    57	#define PG_mte_tagged	0
    58	
    59	static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
    60	{
    61	}
    62	static inline void mte_copy_page_tags(void *kto, const void *kfrom)
    63	{
    64	}
    65	static inline void flush_mte_state(void)
    66	{
    67	}
    68	static inline void mte_thread_switch(struct task_struct *next)
    69	{
    70	}
    71	static inline void mte_suspend_exit(void)
    72	{
    73	}
    74	static inline long set_mte_ctrl(struct task_struct *task, unsigned long arg)
    75	{
    76		return 0;
    77	}
    78	static inline long get_mte_ctrl(struct task_struct *task)
    79	{
    80		return 0;
    81	}
    82	static inline int mte_ptrace_copy_tags(struct task_struct *child,
    83					       long request, unsigned long addr,
    84					       unsigned long data)
    85	{
    86		return -EIO;
    87	}
  > 88	static inline void check_mte_async_tcf0(void)
  > 89	{
    90	}
  > 91	static inline void clear_mte_async_tcf0(void)
    92	{
    93	}
    94	

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202104092126.pvVQG3UB-lkp%40intel.com.

--RnlQjJ0d97Da+TV1
Content-Type: application/gzip
Content-Disposition: attachment; filename=".config.gz"
Content-Transfer-Encoding: base64

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
cMhXhY58AAA=

--RnlQjJ0d97Da+TV1--

Return-Path: <kasan-dev+bncBC4LXIPCY4NRB6X35GHQMGQET5CWTKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A5E34A710D
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 13:50:03 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id p17-20020aa7c891000000b004052d1936a5sf10352284eds.7
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 04:50:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643806202; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8AsYXrBwdcAA7pOoCeA6aMt2P247J+MSK/n83hV/yCNug9rjG4O1CUEz0tC8OAljL
         /rAvCUV42D+0OJeGLKjGXxsqMnpbnVuem1JttRTbau8yXZAuOZMAfmL/DhgrzLyA2jaG
         brsXoECtbaA1TUYgx8/tp/FcRJJD/Fm8Fa1t7AhTsxbkQW0N9jCk4ceWWWNMjCdPqrjP
         JFhPU8/uMtQP+VGYzvlm+Prol1OI+WSLAgNOuRy49E7FGdHRZX3pF48mTmV2UUr0GPnw
         035NI7Lyf9jyaCwvmlNB6fh+riL/RNJXQDxcNKoENa0uFxSR+XXTwnzTC2u2Mkazwejb
         Fu2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=dXzWeUzcIvA7137yLDkCMzEkGluSl311keOVmC7OKLs=;
        b=rSPqMShgpIboRJ9rKIinKAZizRhGSXN0FilxybvRFHsHpVXfT3zNpY7nRxbIKRNSIy
         +DTnHFdlPN9ow2Xr0nJ6qZrr61uQQttW3x1OQ7Db1iwtyVYoiUJVBTQ+9w5u4ee90uIC
         gy4cBdgxev6RcjBj6K/kfEWjF96s31DjjwoZ04HK3Be5lETSwsymrer7RpoZNOETDHAg
         bQaQ2earr0omxLQSFNunn9bRqi3Q9QU2A7RnYhmgDf3IWzzDuL7m7awu8S2nhH10Uvnx
         xMRQld14qkbxWeQTuYZqG3pV/woEmjVJHYEuj0dzC4CImJhktjnXLP4f657l2Ag4LyKH
         0rGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aOGostHt;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dXzWeUzcIvA7137yLDkCMzEkGluSl311keOVmC7OKLs=;
        b=TWkzT3ktm5ZyjZ7Dxfst9znZE5h5yiCmgr3c09TshFU3cCayV6b9RroiU3C3aiyBRT
         nMEjGq8jdKhMfqWN2S7VtvR5jbDO+9CwHpGYprfQYIiqq3VJFTG3Z1f+1BlrU5iEKm/e
         eKlm/68FnL7eeOjp8hyKcYHCDIp6wbpnNh6SGHjHPgN2zjNFvYdoMTB7z713r/I2xi+z
         luTg3/+0KBJ+tEEHDI/l30Y6E9MuvrvkEoLUkvByNflGhcEzWehQYkPmBSKBf1koWCIE
         H84ya6bYRLXP/YAHVnXz7DQ6yisxpW8r4g3epMrmab6c+TojD3ie909sMbNKBFkGaaZc
         8xDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dXzWeUzcIvA7137yLDkCMzEkGluSl311keOVmC7OKLs=;
        b=vjCE7gpUqFZUPwwwUDCBdDG1cjymwpWwN6vESas2qecreFa+jlS2Zzb9WyrUsia5yf
         1Ztm1w+Njxtr9uJFz3mvZAHpH66mxU6/dl2qGkz0MO/HfBb6GoQfn845n+kb08bpSdf0
         iY/0vBEP9biPUyFGVfw+LrFnIOCmq3HIzRZY7REJafRHffu2REkHkXMvc3Ch+NPYWa74
         /V65wnOenpuK49XGwk1F6zaeMhSaj3REALnUB1mkvT0fmxxSekgWRALIdhPYNF6SwQWr
         qHV4XWylLJ4S59Ew11XXQ2U1M7MJkSjLxtjq8ILV+/lFD592EYe3eyK60wl8ahcvb8cu
         GGAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SzuaKeoQXLHOByNTaldt610elv8KwS7FVzCZ7li3W0QaxnNSl
	2JiKxo0cQunX4Wn8dALyo+Q=
X-Google-Smtp-Source: ABdhPJydTj05FeiiSWVCgZrhBpg7JD5DfRbBs2YXJnkHuQGhr5l5gdGakG9YXt2BKwHi/jVa9f9vuw==
X-Received: by 2002:a17:907:7e85:: with SMTP id qb5mr25208313ejc.557.1643806202654;
        Wed, 02 Feb 2022 04:50:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d11:: with SMTP id gn17ls9478975ejc.10.gmail; Wed,
 02 Feb 2022 04:50:01 -0800 (PST)
X-Received: by 2002:a17:906:794f:: with SMTP id l15mr25843333ejo.75.1643806201756;
        Wed, 02 Feb 2022 04:50:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643806201; cv=none;
        d=google.com; s=arc-20160816;
        b=MqGicbAAJNRotMmY0epY5wU1N+NMY3Us/WxHvgzK5ruOkTpF0vK0kcsMFoD0iR1ExV
         PIhafxgqijF5kjB/6Y0M4tcxdtVecYySWK4QO0Wgdg5Fdmr9Z8dHBHxJCYry1OtsBMZh
         nt/CGaKonv7hDCuDy9i0M1AzhFhFeaxtF2mRveWX8mYiBw26n+l10gY1gI0ZNn+MgFPz
         mJFRC+QFwx22MYUBG/rrt70SjO07FG/Iz4YgydZLMLUrlglW1sptxTdQzrNxTvMdVbq+
         JWLwp/Eap/wr1KapCrLdtL/Q3QNOL0nCUwEY/xL1NakVI3UShiEJ9HxiptpKMeettTDC
         H2Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BvdqpdvY93c6FqfHwXT42tg0asKK578St626J/9S0To=;
        b=q/doMn2dcY6+oCc2sDdfo6Vi3yIHnl2uRT8L3Y9TVx81vYQDHXI24XqFBQ4iFY8bUx
         sU3TnHCTk+cGqhxPVX3JXQEUwylsWJ6RSx4l6oeR2B+PhgG5OOBXpugc2CN/WW9qbxci
         j/GGGwNEAHQ2LZzFnxYxTNz7n5eEnFsdMbI/8BqFCo8uL7m9Bg71ac8MFf9/09WaqYZI
         d2S/gSGul15p5O5V/Pg/syWqbXoJhs6BtZ4K1AL3Hn0H2iPjXJr0iKfIQ1n6muZYBs1Q
         14gYhqIXAdpKSZnuvnUvNCbYKrIOr1acAuQT4Ln0tX3VvZ9CpqYyx9H4YfuFU3CFAx8l
         BMxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aOGostHt;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id s15si883483eji.1.2022.02.02.04.50.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Feb 2022 04:50:01 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6200,9189,10245"; a="334266356"
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="334266356"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Feb 2022 04:49:59 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="627057106"
Received: from lkp-server01.sh.intel.com (HELO 276f1b88eecb) ([10.239.97.150])
  by fmsmga002.fm.intel.com with ESMTP; 02 Feb 2022 04:49:56 -0800
Received: from kbuild by 276f1b88eecb with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nFF59-000Uaq-QS; Wed, 02 Feb 2022 12:49:55 +0000
Date: Wed, 2 Feb 2022 20:49:00 +0800
From: kernel test robot <lkp@intel.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-hardening@vger.kernel.org" <linux-hardening@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/4] mm/kasan: Move kasan_pXX_table() and
 kasan_early_shadow_page_entry()
Message-ID: <202202022037.dX0aClQq-lkp@intel.com>
References: <3fe9bf0867b2ffc7cd43fe7040ee18d245641ec1.1643791473.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3fe9bf0867b2ffc7cd43fe7040ee18d245641ec1.1643791473.git.christophe.leroy@csgroup.eu>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aOGostHt;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted
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

I love your patch! Perhaps something to improve:

[auto build test WARNING on tip/sched/core]
[also build test WARNING on linus/master v5.17-rc2]
[cannot apply to hnaz-mm/master next-20220202]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/Christophe-Leroy/mm-kasan-Add-CONFIG_KASAN_SOFTWARE/20220202-164612
base:   https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git ec2444530612a886b406e2830d7f314d1a07d4bb
config: mips-cu1000-neo_defconfig (https://download.01.org/0day-ci/archive/20220202/202202022037.dX0aClQq-lkp@intel.com/config)
compiler: clang version 14.0.0 (https://github.com/llvm/llvm-project 6b1e844b69f15bb7dffaf9365cd2b355d2eb7579)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install mips cross compiling tool for clang build
        # apt-get install binutils-mips-linux-gnu
        # https://github.com/0day-ci/linux/commit/23eabd57613c3b304c1c54f1133ef5376cf5731d
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review Christophe-Leroy/mm-kasan-Add-CONFIG_KASAN_SOFTWARE/20220202-164612
        git checkout 23eabd57613c3b304c1c54f1133ef5376cf5731d
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=mips SHELL=/bin/bash drivers/irqchip/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   In file included from drivers/irqchip/irq-ingenic.c:10:
   In file included from include/linux/interrupt.h:11:
   In file included from include/linux/hardirq.h:11:
   In file included from arch/mips/include/asm/hardirq.h:16:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:21:
   In file included from include/linux/slab.h:136:
   include/linux/kasan.h:102:36: error: unknown type name 'p4d_t'
   static inline bool kasan_pud_table(p4d_t p4d)
                                      ^
   include/linux/kasan.h:113:36: error: unknown type name 'pud_t'
   static inline bool kasan_pmd_table(pud_t pud)
                                      ^
   include/linux/kasan.h:130:36: error: unknown type name 'pmd_t'
   static inline bool kasan_pte_table(pmd_t pmd)
                                      ^
>> drivers/irqchip/irq-ingenic.c:111:22: warning: shift count >= width of type [-Wshift-count-overflow]
                   gc->wake_enabled = IRQ_MSK(32);
                                      ^~~~~~~~~~~
   include/linux/irq.h:1175:41: note: expanded from macro 'IRQ_MSK'
   #define IRQ_MSK(n) (u32)((n) < 32 ? ((1 << (n)) - 1) : UINT_MAX)
                                           ^  ~~~
   drivers/irqchip/irq-ingenic.c:124:22: warning: shift count >= width of type [-Wshift-count-overflow]
                   irq_reg_writel(gc, IRQ_MSK(32), JZ_REG_INTC_SET_MASK);
                                      ^~~~~~~~~~~
   include/linux/irq.h:1175:41: note: expanded from macro 'IRQ_MSK'
   #define IRQ_MSK(n) (u32)((n) < 32 ? ((1 << (n)) - 1) : UINT_MAX)
                                           ^  ~~~
   2 warnings and 3 errors generated.


vim +111 drivers/irqchip/irq-ingenic.c

42b64f388c171a arch/mips/jz4740/irq.c        Thomas Gleixner    2011-03-23   59  
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   60  static int __init ingenic_intc_of_init(struct device_node *node,
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   61  				       unsigned num_chips)
9869848d12601c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2010-07-17   62  {
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   63  	struct ingenic_intc_data *intc;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24   64  	struct irq_chip_generic *gc;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24   65  	struct irq_chip_type *ct;
638c885185dc2e arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   66  	struct irq_domain *domain;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   67  	int parent_irq, err = 0;
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   68  	unsigned i;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   69  
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   70  	intc = kzalloc(sizeof(*intc), GFP_KERNEL);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   71  	if (!intc) {
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   72  		err = -ENOMEM;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   73  		goto out_err;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   74  	}
69ce4b2288d22a arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   75  
69ce4b2288d22a arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   76  	parent_irq = irq_of_parse_and_map(node, 0);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   77  	if (!parent_irq) {
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   78  		err = -EINVAL;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   79  		goto out_free;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   80  	}
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   81  
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   82  	err = irq_set_handler_data(parent_irq, intc);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   83  	if (err)
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   84  		goto out_unmap_irq;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24   85  
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   86  	intc->num_chips = num_chips;
3aa94590e7bf82 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   87  	intc->base = of_iomap(node, 0);
3aa94590e7bf82 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   88  	if (!intc->base) {
3aa94590e7bf82 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   89  		err = -ENODEV;
3aa94590e7bf82 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   90  		goto out_unmap_irq;
3aa94590e7bf82 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24   91  	}
9869848d12601c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2010-07-17   92  
1fd224e35c1493 drivers/irqchip/irq-ingenic.c Paul Cercueil      2020-01-13   93  	domain = irq_domain_add_linear(node, num_chips * 32,
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   94  				       &irq_generic_chip_ops, NULL);
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   95  	if (!domain) {
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   96  		err = -ENOMEM;
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   97  		goto out_unmap_base;
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   98  	}
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02   99  
208caadce5d4d3 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  100  	intc->domain = domain;
208caadce5d4d3 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  101  
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  102  	err = irq_alloc_domain_generic_chips(domain, 32, 1, "INTC",
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  103  					     handle_level_irq, 0,
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  104  					     IRQ_NOPROBE | IRQ_LEVEL, 0);
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  105  	if (err)
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  106  		goto out_domain_remove;
42b64f388c171a arch/mips/jz4740/irq.c        Thomas Gleixner    2011-03-23  107  
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  108  	for (i = 0; i < num_chips; i++) {
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  109  		gc = irq_get_domain_generic_chip(domain, i * 32);
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  110  
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24 @111  		gc->wake_enabled = IRQ_MSK(32);
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  112  		gc->reg_base = intc->base + (i * CHIP_SIZE);
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  113  
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  114  		ct = gc->chip_types;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  115  		ct->regs.enable = JZ_REG_INTC_CLEAR_MASK;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  116  		ct->regs.disable = JZ_REG_INTC_SET_MASK;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  117  		ct->chip.irq_unmask = irq_gc_unmask_enable_reg;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  118  		ct->chip.irq_mask = irq_gc_mask_disable_reg;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  119  		ct->chip.irq_mask_ack = irq_gc_mask_disable_reg;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  120  		ct->chip.irq_set_wake = irq_gc_set_wake;
20b44b4de61f28 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  121  		ct->chip.flags = IRQCHIP_MASK_ON_SUSPEND;
83bc769200802c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2011-09-24  122  
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  123  		/* Mask all irqs */
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  124  		irq_reg_writel(gc, IRQ_MSK(32), JZ_REG_INTC_SET_MASK);
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  125  	}
9869848d12601c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2010-07-17  126  
821fc9e261f3af drivers/irqchip/irq-ingenic.c Paul Cercueil      2020-08-19  127  	if (request_irq(parent_irq, intc_cascade, IRQF_NO_SUSPEND,
2ef1cb763d92f3 drivers/irqchip/irq-ingenic.c afzal mohammed     2020-03-04  128  			"SoC intc cascade interrupt", NULL))
2ef1cb763d92f3 drivers/irqchip/irq-ingenic.c afzal mohammed     2020-03-04  129  		pr_err("Failed to register SoC intc cascade interrupt\n");
adbdce77ccc345 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  130  	return 0;
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  131  
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  132  out_domain_remove:
8bc7464b514021 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  133  	irq_domain_remove(domain);
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  134  out_unmap_base:
52ecc87642f273 drivers/irqchip/irq-ingenic.c Paul Cercueil      2019-10-02  135  	iounmap(intc->base);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  136  out_unmap_irq:
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  137  	irq_dispose_mapping(parent_irq);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  138  out_free:
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  139  	kfree(intc);
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  140  out_err:
fe778ece8e2522 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  141  	return err;
9869848d12601c arch/mips/jz4740/irq.c        Lars-Peter Clausen 2010-07-17  142  }
943d69c6c21746 arch/mips/jz4740/irq.c        Paul Burton        2015-05-24  143  

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202022037.dX0aClQq-lkp%40intel.com.

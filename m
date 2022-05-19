Return-Path: <kasan-dev+bncBC4LXIPCY4NRBANTTOKAMGQEUEX2MSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA1AE52E0EC
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 01:57:53 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id o10-20020aa7c7ca000000b0042a4f08405fsf4514209eds.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 16:57:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653004673; cv=pass;
        d=google.com; s=arc-20160816;
        b=gmMhQ3oEDI4bWHSNXPkgPxZ9g8/BblnvPF156VrcacpcQuxYhWMG42w+jDfM6673p/
         cLSCFUnIuVAhU40IHGc/0m9kXItpoOuWk2JrY6sDQM6hM2XkQuXcyMVFt7fr4j0HEtil
         d9XGfoNeOph+SP4F2300AkqZCNF/KBeY3vm9BnneDog9tqFZClymDkYRTqnq32t/FwqR
         Nfrwnecp8tZeFRcAvdEnhslZawftxvNL77mllANGxhTC6hSB/1GFgJm6WB7xWAbD7H8z
         JBC+OjqlV9+jOgmfoys2CIhyehu5mdxX0S8CIJRpg8YVo8wRq6mhPS//Py0Rhjn00+KT
         W19A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tRr4B9OWHQu2SsBybnbv/qc/YS6jnMX4UhfOTtG88JI=;
        b=jY1ZU/WF5c1Jrlx9eSXIl/A0Wdl6gDx8CbbNG2SauIks++jrt77aZwRO6ujuPlJdiq
         mX/vgqssQ8+wgKy1OxjCr5+CGLbx4CUeX+8dEWcYd1s7XuBo0qUxEXOEMhUXd6vshU52
         RWge5N5S9Lfa750+k5lirE/ZWCIJpsMJvm4KQDmlRG/L+LnTTXpabHrhjnDFcIKYZ20/
         A5174yIXqwV5TjCxWyZH4qidg+kK4pBXWcIPlMGq7b3nLK9yqZkrFrol2xIEGHOfdyUU
         LjELcTXZoQDhiTG0bvtr5SmB2refuoc2vnaNrVJEydArXHjklm+Cyi6u9woaVffinkXD
         orpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Th12ecPq;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tRr4B9OWHQu2SsBybnbv/qc/YS6jnMX4UhfOTtG88JI=;
        b=PYs4p3UuUUvmGZIMCDLwLwUT6dHdCEfmxZWJP9uL5TyAbXHI004UogA66A6eH2Gqsv
         pJU3YSc5gp8QKW/vjv0NDtCa8pSpCc3gaUhDyd2zhT6bOVQAHbKB6MO8ody175uSFOM+
         zihdKEzDur38PCnNyti0EHIqwgbgMTtxA4v5yLwiKaLdGisujMlD0o201sAQ/Jsi1WRd
         cq3NIRprUrlz8AG0+/K2PNzL7zNq9BI+5tMu4I/eRMQ+M+1K6HUM1Xp9kCu8oAcp4w1V
         6pRn3zLzwr1ebXnqqCn27GiYWCNMEnyYkT5bphZSWnIyryAQanA9xS3WgswDoNIvNyji
         SGTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tRr4B9OWHQu2SsBybnbv/qc/YS6jnMX4UhfOTtG88JI=;
        b=vA0l1d8M9uM3e2G6KEm4yySzJ5PQtWbjLnhvM8Rc04dUlHauGBPnkcjRCpqZEb9Dgz
         EqEOXXwU7kGTJFJCXjDIiJXbC2/I+qQOANwq62vUnvqjD4Q5TwOSPMEgqVWDqYFWfBCS
         WAT0MxQRaclHp8FlAX0w0OUyFkyM+fgh4RDoKA7kZTIZk4NkM4uTS39WxBm2xJdOq8pd
         TMZyuOGQ/Nq1+zdIGTkXVXHXbQ13FBaHZK6pQzRAjZ/qpykQoQW6+S5zAv2/EwM/pgl9
         zYS8dylYopUcXn+VHwNcLdUVZENfm9tGhuP1mcPLwgm0qoFkzo7nMHKjfULo9CiFAM1w
         mcCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YxpDnFmicWJAypssleD9HPfEAY2xuAcZlxX0gMSrBxG8Qdoof
	TbggFsHKDY1gceIu8JvLhuo=
X-Google-Smtp-Source: ABdhPJyq1JEiJN3PG3vISztKt+oWW+n1b4j1nY0HqsuOimFqZmxSls5szwPZjoQY3HQzQIz182SDzw==
X-Received: by 2002:a17:906:c14e:b0:6f9:9d73:77e with SMTP id dp14-20020a170906c14e00b006f99d73077emr6480385ejc.258.1653004673518;
        Thu, 19 May 2022 16:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7253:b0:6f4:60e6:9f97 with SMTP id
 ds19-20020a170907725300b006f460e69f97ls2287365ejc.8.gmail; Thu, 19 May 2022
 16:57:52 -0700 (PDT)
X-Received: by 2002:a17:907:1c97:b0:6f5:22ae:7024 with SMTP id nb23-20020a1709071c9700b006f522ae7024mr6650885ejc.570.1653004672516;
        Thu, 19 May 2022 16:57:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653004672; cv=none;
        d=google.com; s=arc-20160816;
        b=As7tgF2QEdcYgn8+tNgBYHJkpIi3/mB8vdVRGBiy3NKPYkUZICGKrEtsMWe+EMXHWh
         hm9q9r9tHEIld4Op/Oak13urcLHbt80ta/gnd/zTVUkwoik59oiE2HSu9BeKJd1TF81i
         THwHLYJNotPNrAXd4wFgxSC/ls3QWk6BqbYKFjb42LIFszbqpu5pZtjvcqXxsROOdUEZ
         fkztJSk6OZzQg6pdUPMMoiUg4miuCkIhlkZezpHkM6gxnf5gvn+0hDFo/inGXLWBT3HY
         htYdtCCY+cCj2VoSPZ+kldQ9kqaOzkP4XGIgo8WXUNoXbbD00UUB14rzrINNO5LVy/Kp
         1NFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=t5b0iBsotPgKHYPltddZfcaNwrZS6UaP3+RldLFyQCs=;
        b=NHZxniMc/Z5OnLtsdivL8AnWM9G4KJ0MI9Q0dkPbk/XmcYAujoHpL6mHzb+jyw2oge
         xit+D7ej14OxUMfV1T4bHIj14jb4ulgngBa5W5bGS9CknSMJMGUuLyMyHKhAijO4RjbG
         PODKUieHTz8EgZ9QbLQoPGT9dYbBU8Fu03e8Lo64dMyLThK5nvvQbYMgBvrxnNV53ahl
         qy88tfO89HsTzM+AmccQWn+m/PqF9Qt6+Qh6q0F1mSsC4hHvQSgp7P1PofVvAfc71VDd
         W7SUgTxtoD5XdbFDZXEwqoOltL3HNZF0EU/glWFi/C5zSpL4jlDPZhyrIElSI2reLIt7
         IDKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Th12ecPq;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id d10-20020a50cd4a000000b00418d53b44b8si399140edj.0.2022.05.19.16.57.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 16:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6400,9594,10352"; a="252314514"
X-IronPort-AV: E=Sophos;i="5.91,238,1647327600"; 
   d="scan'208";a="252314514"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 May 2022 16:57:50 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.91,238,1647327600"; 
   d="scan'208";a="557181864"
Received: from lkp-server02.sh.intel.com (HELO 242b25809ac7) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 19 May 2022 16:57:45 -0700
Received: from kbuild by 242b25809ac7 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1nrq1Z-000445-04;
	Thu, 19 May 2022 23:57:45 +0000
Date: Fri, 20 May 2022 07:57:41 +0800
From: kernel test robot <lkp@intel.com>
To: Jisheng Zhang <jszhang@kernel.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Anup Patel <anup@brainfault.org>, Atish Patra <atishp@rivosinc.com>
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
Message-ID: <202205200730.afjapejq-lkp@intel.com>
References: <20220519155918.3882-3-jszhang@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220519155918.3882-3-jszhang@kernel.org>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Th12ecPq;       spf=pass
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

Hi Jisheng,

I love your patch! Yet something to improve:

[auto build test ERROR on linus/master]
[also build test ERROR on v5.18-rc7]
[cannot apply to next-20220519]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/intel-lab-lkp/linux/commits/Jisheng-Zhang/use-static-key-to-optimize-pgtable_l4_enabled/20220520-001459
base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git f993aed406eaf968ba3867a76bb46c95336a33d0
config: riscv-buildonly-randconfig-r003-20220519 (https://download.01.org/0day-ci/archive/20220520/202205200730.afjapejq-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project e00cbbec06c08dc616a0d52a20f678b8fbd4e304)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install riscv cross compiling tool for clang build
        # apt-get install binutils-riscv64-linux-gnu
        # https://github.com/intel-lab-lkp/linux/commit/d052c69ebaf48ac2925d6f9fa033d9e394da1074
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Jisheng-Zhang/use-static-key-to-optimize-pgtable_l4_enabled/20220520-001459
        git checkout d052c69ebaf48ac2925d6f9fa033d9e394da1074
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=riscv SHELL=/bin/bash drivers/tty/ net/ceph/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All error/warnings (new ones prefixed by >>):

   In file included from drivers/tty/tty_io.c:73:
   In file included from include/linux/sched/signal.h:9:
   In file included from include/linux/sched/task.h:11:
   In file included from include/linux/uaccess.h:11:
   In file included from arch/riscv/include/asm/uaccess.h:12:
   In file included from arch/riscv/include/asm/pgtable.h:112:
>> arch/riscv/include/asm/pgtable-64.h:19:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   arch/riscv/include/asm/pgtable-64.h:27:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   In file included from drivers/tty/tty_io.c:75:
   In file included from include/linux/interrupt.h:11:
   In file included from include/linux/hardirq.h:11:
   In file included from ./arch/riscv/include/generated/asm/hardirq.h:1:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:464:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __raw_readb(PCI_IOBASE + addr);
                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:477:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:37:51: note: expanded from macro '__le16_to_cpu'
   #define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
                                                     ^
   In file included from drivers/tty/tty_io.c:75:
   In file included from include/linux/interrupt.h:11:
   In file included from include/linux/hardirq.h:11:
   In file included from ./arch/riscv/include/generated/asm/hardirq.h:1:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:490:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:35:51: note: expanded from macro '__le32_to_cpu'
   #define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
                                                     ^
   In file included from drivers/tty/tty_io.c:75:
   In file included from include/linux/interrupt.h:11:
   In file included from include/linux/hardirq.h:11:
   In file included from ./arch/riscv/include/generated/asm/hardirq.h:1:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:501:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writeb(value, PCI_IOBASE + addr);
                               ~~~~~~~~~~ ^
   include/asm-generic/io.h:511:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:521:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:1024:55: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           return (port > MMIO_UPPER_LIMIT) ? NULL : PCI_IOBASE + port;
                                                     ~~~~~~~~~~ ^
   7 warnings and 2 errors generated.
--
   In file included from drivers/tty/tty_ioctl.c:11:
   In file included from include/uapi/linux/termios.h:6:
   In file included from ./arch/riscv/include/generated/uapi/asm/termios.h:1:
   In file included from include/asm-generic/termios.h:6:
   In file included from include/linux/uaccess.h:11:
   In file included from arch/riscv/include/asm/uaccess.h:12:
   In file included from arch/riscv/include/asm/pgtable.h:112:
>> arch/riscv/include/asm/pgtable-64.h:19:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   arch/riscv/include/asm/pgtable-64.h:27:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:11: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                           ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:25: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                                         ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:98:4: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           set->sig[1] | set->sig[0]) == 0;
                           ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:100:11: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[1] | set->sig[0]) == 0;
                           ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:11: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[3] == set2->sig[3]) &&
                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:27: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[3] == set2->sig[3]) &&
                                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:5: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           (set1->sig[2] == set2->sig[2]) &&
                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:21: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           (set1->sig[2] == set2->sig[2]) &&
                                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:115:5: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           (set1->sig[1] == set2->sig[1]) &&
                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:115:21: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           (set1->sig[1] == set2->sig[1]) &&
                                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:118:11: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[1] == set2->sig[1]) &&
                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/tty_ioctl.c:13:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:118:27: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[1] == set2->sig[1]) &&
                                            ^         ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
--
   In file included from drivers/tty/tty_port.c:8:
   In file included from include/linux/tty.h:5:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:9:
   In file included from include/linux/sched/task.h:11:
   In file included from include/linux/uaccess.h:11:
   In file included from arch/riscv/include/asm/uaccess.h:12:
   In file included from arch/riscv/include/asm/pgtable.h:112:
>> arch/riscv/include/asm/pgtable-64.h:19:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   arch/riscv/include/asm/pgtable-64.h:27:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   In file included from drivers/tty/tty_port.c:8:
   In file included from include/linux/tty.h:12:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:464:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __raw_readb(PCI_IOBASE + addr);
                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:477:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:37:51: note: expanded from macro '__le16_to_cpu'
   #define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
                                                     ^
   In file included from drivers/tty/tty_port.c:8:
   In file included from include/linux/tty.h:12:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:490:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:35:51: note: expanded from macro '__le32_to_cpu'
   #define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
                                                     ^
   In file included from drivers/tty/tty_port.c:8:
   In file included from include/linux/tty.h:12:
   In file included from include/linux/tty_port.h:5:
   In file included from include/linux/kfifo.h:42:
   In file included from include/linux/scatterlist.h:9:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:501:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writeb(value, PCI_IOBASE + addr);
                               ~~~~~~~~~~ ^
   include/asm-generic/io.h:511:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:521:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:1024:55: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           return (port > MMIO_UPPER_LIMIT) ? NULL : PCI_IOBASE + port;
                                                     ~~~~~~~~~~ ^
>> drivers/tty/tty_port.c:245:2: warning: implicit conversion from 'unsigned long' to 'unsigned int' changes value from 18446744073709551615 to 4294967295 [-Wconstant-conversion]
           INIT_KFIFO(port->xmit_fifo);
           ^~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/kfifo.h:130:69: note: expanded from macro 'INIT_KFIFO'
           __kfifo->mask = __is_kfifo_ptr(__tmp) ? 0 : ARRAY_SIZE(__tmp->buf) - 1;\
                         ~                             ~~~~~~~~~~~~~~~~~~~~~~~^~~
   8 warnings and 2 errors generated.
--
   In file included from drivers/tty/serial/earlycon.c:16:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:15:
   In file included from include/linux/pgtable.h:6:
   In file included from arch/riscv/include/asm/pgtable.h:112:
>> arch/riscv/include/asm/pgtable-64.h:19:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   arch/riscv/include/asm/pgtable-64.h:27:6: error: call to undeclared function 'static_branch_likely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
           if (static_branch_likely(&_pgtable_lx_ready))
               ^
   In file included from drivers/tty/serial/earlycon.c:16:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:464:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __raw_readb(PCI_IOBASE + addr);
                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:477:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:37:51: note: expanded from macro '__le16_to_cpu'
   #define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
                                                     ^
   In file included from drivers/tty/serial/earlycon.c:16:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:490:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
                                                           ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:35:51: note: expanded from macro '__le32_to_cpu'
   #define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
                                                     ^
   In file included from drivers/tty/serial/earlycon.c:16:
   In file included from include/linux/io.h:13:
   In file included from arch/riscv/include/asm/io.h:136:
   include/asm-generic/io.h:501:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writeb(value, PCI_IOBASE + addr);
                               ~~~~~~~~~~ ^
   include/asm-generic/io.h:511:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:521:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
                                                         ~~~~~~~~~~ ^
   include/asm-generic/io.h:1024:55: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
           return (port > MMIO_UPPER_LIMIT) ? NULL : PCI_IOBASE + port;
                                                     ~~~~~~~~~~ ^
   In file included from drivers/tty/serial/earlycon.c:17:
   In file included from include/linux/serial_core.h:13:
   In file included from include/linux/interrupt.h:21:
   In file included from arch/riscv/include/asm/sections.h:9:
   In file included from include/linux/mm.h:700:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:11: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                           ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/serial/earlycon.c:17:
   In file included from include/linux/serial_core.h:13:
   In file included from include/linux/interrupt.h:21:
   In file included from arch/riscv/include/asm/sections.h:9:
   In file included from include/linux/mm.h:700:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:25: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                                         ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/serial/earlycon.c:17:
   In file included from include/linux/serial_core.h:13:
   In file included from include/linux/interrupt.h:21:
   In file included from arch/riscv/include/asm/sections.h:9:
   In file included from include/linux/mm.h:700:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:98:4: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           set->sig[1] | set->sig[0]) == 0;
                           ^        ~
   include/uapi/asm-generic/signal.h:62:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from drivers/tty/serial/earlycon.c:17:
   In file included from include/linux/serial_core.h:13:
   In file included from include/linux/interrupt.h:21:
   In file included from arch/riscv/include/asm/sections.h:9:
   In file included from include/linux/mm.h:700:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:100:11: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
..


vim +/static_branch_likely +19 arch/riscv/include/asm/pgtable-64.h

    16	
    17	static __always_inline bool pgtable_l5_enabled(void)
    18	{
  > 19		if (static_branch_likely(&_pgtable_lx_ready))
    20			return static_branch_likely(&_pgtable_l5_enabled);
    21		else
    22			return _pgtable_l5_enabled_early;
    23	}
    24	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202205200730.afjapejq-lkp%40intel.com.

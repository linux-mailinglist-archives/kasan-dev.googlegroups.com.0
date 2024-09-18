Return-Path: <kasan-dev+bncBC4LXIPCY4NRBK6FVS3QMGQENQT2V5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EA8E97C03C
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 20:57:50 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2054ff12bb9sf1350555ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 11:57:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726685868; cv=pass;
        d=google.com; s=arc-20240605;
        b=RfT7xOqYuRBQ0TOuxOG0lUFHkQbzGWkn/jpnyQKWPk3f22NIjCbnG0bD+kOZ16f5jV
         3dBVOO0oSyQDGbYl+j8KK/Wgr3xCHJ3I2VRUS25h7AM5IKW+6UkGCrUoBDfSaXedkfBN
         njc6TtkIx5OUiojnjGFA3y/qFEpycbMhuKCQu/MjSrV7Zz4Y1ig8OvIwkYB/c2fkQ6tK
         DykLk7OmvN586ggMwxHiZcz3dTVfwW+hKCda18tgMSAeMqvq0ClOCM9ddTKQeASgmxj1
         iqiuU0pr9mdyjv81aiMR1rJcX/gAj002eQfeedO5lA0e5U/dgJPTVHSYjXmaT/SsGhdl
         H6Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tgQFKFGhzHzMkZXZgWnrziAntkXi/I+aR2EtN9vyxSo=;
        fh=yNSJn4NuIUydyZjzxaz/LeHP8PjHaA3U/+j2KoLkCFA=;
        b=jr5kjoMDPZWScKO0pZYTuuv3Uuyt8CQ64hzTQTExa6A4YGS0oczZs2VZl8jpXAkB9K
         mzuWinFW1yi+bsg++9gnS0mh8sXjmnEa20Crguabr1UpQ7ATr1j8PiHIB/jL7xuRrSxq
         LyqrMFY//dr1g0PhSFlpFAe5o+DKzGJdLgyqQy7DkkMoVxWp8K5eSUPGkGqoEK/42OQE
         pkSxlOi73SWpvVxvQrjaB2lzlFeDaf/UpzK7UMI2iQFa9LjQ9uKwrWqRfSQi4AiiqzVd
         m50HOqt43v88p6ozhMzFCBGblkSmduywAIT+1kdLTM1J1uA67cFyQQ7trDYu/TlvEyPW
         wWAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="KId2Ee/N";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726685868; x=1727290668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tgQFKFGhzHzMkZXZgWnrziAntkXi/I+aR2EtN9vyxSo=;
        b=DIeHR6CMt4sYUTedlV66DAq96Up7T9rFe5DbfDzw1UTknLF/XlJWSfh2Fk/eyWsWDM
         lKTQIb+slbGtiqfLDMEjmcnj5cXlK3LeSCKAmWiWcaoZvTzDCBQJU6NgL40/4PeYWh6W
         Sq40jRMrNzXiGIEJFmV+Y/GtTJIsrhwXbNounU4qM7QTQN2DfkURTarHBcWnmTWk0Ybm
         HSloKWmmkz7eTE7g7Y6gJOevPgzIOgQU0rAx50DLglpmiuWmRpbSPSHKbCTcs0glRXGT
         c3noRi/2mv2gInRhj8AHowkr1mQbOtMKnq4DA93ADOGWEY+ev3FrbWK/Z+WH06ThDeFL
         Gp1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726685868; x=1727290668;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tgQFKFGhzHzMkZXZgWnrziAntkXi/I+aR2EtN9vyxSo=;
        b=wtbqdSaepvM2lb5l80KwhhFBJyoBgLKHUhY2LtikOgJM0ZCcFESPHafIadV+GD2IbS
         gakpu4q/DZd4jWMjiPgMoWEjVeze2I7YHDd9vrL43682jkz75sOmWcMafJSiHlja3uFi
         G26ngsjDVYRXshIRwe6yHdXFesZ5gf0TOADbdxggVPSt3W2fSAdl+h4nx14CaP+A0GwQ
         Ra8OjSMQi3k0Cy6aZTUo37RKOCg0+tA6RQ0KAZQwL2wulp44bUB6E8zAh1CPQYV2HkaN
         /pgAqdhlPpLTh1rrqrt8rMB7JVxARhrYoLuOZf1PrOKpUHyl4D6BnbmA4rBxe7cl4fdU
         ts2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbqrnneelBu8CVCMLMF+cb0Ty6n/8GdrdBvzGj6bjpRCda4H0RvPru4jSbJclc4bDZZArJuA==@lfdr.de
X-Gm-Message-State: AOJu0YzIAKwV5yXge4Hx9MiGCxPFOPyxYIG4rr2QZq837ANqv8HNDKe5
	AEfJR6o7c9bWqt/qTMmtU8pxs8reGKrq4Fnyu2WKl+WW+LMm+NBQ
X-Google-Smtp-Source: AGHT+IFcTZh4tNxMTo/K/N0mtTNp26saTyrEeYtxHb8ogpqJWyK2mUhgE1m55qeLDnFc2paIMwkZpA==
X-Received: by 2002:a17:903:22cb:b0:202:2ee4:16ce with SMTP id d9443c01a7336-20782b90948mr269895945ad.61.1726685868066;
        Wed, 18 Sep 2024 11:57:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:206:935f:fa6 with SMTP id
 d9443c01a7336-208cb90a354ls1084235ad.0.-pod-prod-05-us; Wed, 18 Sep 2024
 11:57:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlKVVhjPiazJsry6VjwKkLdQf7WB40eiRQQ+JpgsRKgKqOTtFuUodktag4Oqa+XsbjkcoJKm8y6BQ=@googlegroups.com
X-Received: by 2002:a17:902:ecc3:b0:206:9519:1821 with SMTP id d9443c01a7336-20781d56826mr235520545ad.14.1726685865795;
        Wed, 18 Sep 2024 11:57:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726685865; cv=none;
        d=google.com; s=arc-20240605;
        b=WbnzBw4QMdJ2FCmKROuIxywGMuj8KQbdQ/f7U1gNKCffmZMlIZdcCee5spbC+xO3eA
         crNnXRBL78cZn6GkPR+CotM7+sMPDjfgwZjkLAMwINwNxs1hj3fV+B8LB7nsRW5f3QTP
         jLakA/wzacU2JVLYrZdpixouA8H4gyARSk5Bki8xvCPHZKswmQc3WMeePmfZHmWMEdq9
         HD66R6HHRs85pd2LENvfDDpnUh32zEKdphEJv7uSoirPAoCITI6RJRvurAipp0vDtSV1
         oGHLw7fAsDH2WtoPlvrl+wgGd8cW2fLt0vCrOq+OgsldqLyzPNZ7DDyA6qx2IAiLHGXE
         BTFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=shXxn80eTs/zrbWdpuHXRkBDH9DrRj3sE8GsmHAtmlA=;
        fh=VwgPvzgypl63TfFFpOUSlMuPy9I5DEveezSynE+Fm0g=;
        b=ilKfkgGpHmypcOzcyWeOHJ8DW/Be7viNvRH2CrIy6pRcNyvqvjGRuQQ8w/arcXxElM
         uZn8wdJeLxfvI2mS319hMLAKHreXC+erWo9MeY4R3mroB1zt2WAI7vs0q8HsnxeKt4XC
         R1AeLhUblGpYFNB1E/1TKX86QP3IzlR0XAK1xQv6FoaStw3Vped1WfHVWwWLVad76FZT
         kLj3rb6qMRPGFS0dzJlUcqxR4PJba15K88K6iYoDyJKOGceELah9ok1KhyAFSJxNQSNa
         fee8273080bW/EPdRlTHtRaITB+qgogJ+F+94zzd90Ss/M+4QbqoudiaL4yOdESqwcoE
         xJNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="KId2Ee/N";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-207946f2525si3894685ad.11.2024.09.18.11.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 18 Sep 2024 11:57:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: 9+RDi451SP2gH6XTwC04pw==
X-CSE-MsgGUID: 1ghiwxe7RrOdexJQtsiXwQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11199"; a="25739628"
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="25739628"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Sep 2024 11:57:44 -0700
X-CSE-ConnectionGUID: sLnHQreLSg2vk4+qzDcHEw==
X-CSE-MsgGUID: RGijHgmTRSecDRaYHwGhDA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="69916612"
Received: from lkp-server01.sh.intel.com (HELO 53e96f405c61) ([10.239.97.150])
  by fmviesa010.fm.intel.com with ESMTP; 18 Sep 2024 11:57:37 -0700
Received: from kbuild by 53e96f405c61 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sqzrr-000CXC-1a;
	Wed, 18 Sep 2024 18:57:35 +0000
Date: Thu, 19 Sep 2024 02:57:21 +0800
From: kernel test robot <lkp@intel.com>
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Dimitri Sivanich <dimitri.sivanich@hpe.com>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>,
	Naoya Horiguchi <nao.horiguchi@gmail.com>,
	Pasha Tatashin <pasha.tatashin@soleen.com>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>
Subject: Re: [PATCH V2 4/7] mm: Use pmdp_get() for accessing PMD entries
Message-ID: <202409190205.YJ5gtx3T-lkp@intel.com>
References: <20240917073117.1531207-5-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240917073117.1531207-5-anshuman.khandual@arm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="KId2Ee/N";       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.18 as permitted
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

Hi Anshuman,

kernel test robot noticed the following build errors:

[auto build test ERROR on char-misc/char-misc-testing]
[also build test ERROR on char-misc/char-misc-next char-misc/char-misc-linus brauner-vfs/vfs.all dennis-percpu/for-next linus/master v6.11]
[cannot apply to akpm-mm/mm-everything next-20240918]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Anshuman-Khandual/m68k-mm-Change-pmd_val/20240917-153331
base:   char-misc/char-misc-testing
patch link:    https://lore.kernel.org/r/20240917073117.1531207-5-anshuman.khandual%40arm.com
patch subject: [PATCH V2 4/7] mm: Use pmdp_get() for accessing PMD entries
config: um-allnoconfig (https://download.01.org/0day-ci/archive/20240919/202409190205.YJ5gtx3T-lkp@intel.com/config)
compiler: clang version 17.0.6 (https://github.com/llvm/llvm-project 6009708b4367171ccdbf4b5905cb6a803753fe18)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190205.YJ5gtx3T-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202409190205.YJ5gtx3T-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from mm/pgtable-generic.c:10:
   In file included from include/linux/pagemap.h:11:
   In file included from include/linux/highmem.h:12:
   In file included from include/linux/hardirq.h:11:
   In file included from arch/um/include/asm/hardirq.h:5:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:14:
   In file included from arch/um/include/asm/io.h:24:
   include/asm-generic/io.h:548:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     548 |         val = __raw_readb(PCI_IOBASE + addr);
         |                           ~~~~~~~~~~ ^
   include/asm-generic/io.h:561:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     561 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:37:51: note: expanded from macro '__le16_to_cpu'
      37 | #define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
         |                                                   ^
   In file included from mm/pgtable-generic.c:10:
   In file included from include/linux/pagemap.h:11:
   In file included from include/linux/highmem.h:12:
   In file included from include/linux/hardirq.h:11:
   In file included from arch/um/include/asm/hardirq.h:5:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:14:
   In file included from arch/um/include/asm/io.h:24:
   include/asm-generic/io.h:574:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     574 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
         |                                                         ~~~~~~~~~~ ^
   include/uapi/linux/byteorder/little_endian.h:35:51: note: expanded from macro '__le32_to_cpu'
      35 | #define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
         |                                                   ^
   In file included from mm/pgtable-generic.c:10:
   In file included from include/linux/pagemap.h:11:
   In file included from include/linux/highmem.h:12:
   In file included from include/linux/hardirq.h:11:
   In file included from arch/um/include/asm/hardirq.h:5:
   In file included from include/asm-generic/hardirq.h:17:
   In file included from include/linux/irq.h:20:
   In file included from include/linux/io.h:14:
   In file included from arch/um/include/asm/io.h:24:
   include/asm-generic/io.h:585:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     585 |         __raw_writeb(value, PCI_IOBASE + addr);
         |                             ~~~~~~~~~~ ^
   include/asm-generic/io.h:595:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     595 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:605:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     605 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
         |                                                       ~~~~~~~~~~ ^
   include/asm-generic/io.h:693:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     693 |         readsb(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:701:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     701 |         readsw(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:709:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     709 |         readsl(PCI_IOBASE + addr, buffer, count);
         |                ~~~~~~~~~~ ^
   include/asm-generic/io.h:718:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     718 |         writesb(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:727:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     727 |         writesw(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
   include/asm-generic/io.h:736:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
     736 |         writesl(PCI_IOBASE + addr, buffer, count);
         |                 ~~~~~~~~~~ ^
>> mm/pgtable-generic.c:54:2: error: cannot take the address of an rvalue of type 'pgd_t'
      54 |         pmd_ERROR(pmdp_get(pmd));
         |         ^~~~~~~~~~~~~~~~~~~~~~~~
   include/asm-generic/pgtable-nopmd.h:36:28: note: expanded from macro 'pmd_ERROR'
      36 | #define pmd_ERROR(pmd)                          (pud_ERROR((pmd).pud))
         |                                                  ^~~~~~~~~~~~~~~~~~~~
   include/asm-generic/pgtable-nopud.h:32:28: note: expanded from macro 'pud_ERROR'
      32 | #define pud_ERROR(pud)                          (p4d_ERROR((pud).p4d))
         |                                                  ^~~~~~~~~~~~~~~~~~~~
   include/asm-generic/pgtable-nop4d.h:25:28: note: expanded from macro 'p4d_ERROR'
      25 | #define p4d_ERROR(p4d)                          (pgd_ERROR((p4d).pgd))
         |                                                  ^~~~~~~~~~~~~~~~~~~~
   arch/um/include/asm/pgtable-2level.h:31:67: note: expanded from macro 'pgd_ERROR'
      31 |         printk("%s:%d: bad pgd %p(%08lx).\n", __FILE__, __LINE__, &(e), \
         |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
      32 |                pgd_val(e))
         |                ~~~~~~~~~~~
   include/linux/printk.h:465:60: note: expanded from macro 'printk'
     465 | #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
         |                          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~
   include/linux/printk.h:437:19: note: expanded from macro 'printk_index_wrap'
     437 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
         |                                 ^~~~~~~~~~~
   12 warnings and 1 error generated.


vim +/pgd_t +54 mm/pgtable-generic.c

    46	
    47	/*
    48	 * Note that the pmd variant below can't be stub'ed out just as for p4d/pud
    49	 * above. pmd folding is special and typically pmd_* macros refer to upper
    50	 * level even when folded
    51	 */
    52	void pmd_clear_bad(pmd_t *pmd)
    53	{
  > 54		pmd_ERROR(pmdp_get(pmd));
    55		pmd_clear(pmd);
    56	}
    57	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409190205.YJ5gtx3T-lkp%40intel.com.

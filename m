Return-Path: <kasan-dev+bncBC4LXIPCY4NRBCGUR7AQMGQE55RLBNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31029AB604B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 May 2025 02:55:38 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5fd267dbbd6sf371603a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 17:55:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747184137; cv=pass;
        d=google.com; s=arc-20240605;
        b=XjfAqqsvAos2b0umZyQYN3nqL4UaJ237tk1FjOqaLGMu8zAbmJwZYkcUm2fkzo2eBU
         QpGpwnLXLvDHFkwzuROsj5QHwkQj9aYx5INMVaKCKEm5jFDv/dWPQyf9zT93WnqzBLpD
         zSxJYrfXzMVF7IU7Eo7GzRpyuXR3VuFxe0yEmQQ5I5jLwGSMHzj6BqillDNofs4UOVAx
         mkSUSd23t2xySwQrnsWHcahQHDEXni2B9gxh7g6jEyhvmxDcS63I06aZHG4MO52DI7+x
         BL228lHywkXX+pT845JhuIJ6OreC9hmsOX0hK4MNnBz3RlsN/Vcr71KCiW8fN+r94cG9
         JIEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GO82N6fR8/CGlr6XlQvanV5UL5RCqLyQSAPQBerEddk=;
        fh=YKmQA7ecWr2lDQFa4levaoIEnhH2ba95rOLShrWcyzc=;
        b=E+JTtYIFzUbjKd3jr0cP5UXY8U9grp/wz5rxsj5eJSmyDjIOGbyDRG3nIPK6rQ96Yp
         B20dkd8vgtoYowKmsoKar8xVeDaydstpnpwBgcAyzd15SVkVRZY0PB8iCcuNjQlbcTMO
         bbjHLtmUhLPByspL6qJJEp6b4HSCqRmGyoEb2rH8/ozbL3DjrlRR2Fa/eR80R2zwgd4d
         9vAhAfe+6HGnfE7tP1yQldeeuM/aRhtuFZmYnQT3pawAMv99r9RYuciFuPO6ZBQWX5h9
         lCM4/u7aDL5PwnHYPAHb5sMGH8gSD+0vM53fS4Pxp7wxS8gj3ZoBlNCeVqvUV+BwJyxR
         2FjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BONzfzNS;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747184137; x=1747788937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GO82N6fR8/CGlr6XlQvanV5UL5RCqLyQSAPQBerEddk=;
        b=G9SJCK9iRCk8qBRR0Bvc2jkGpFNFlz+5L8EvhVasumCe1Nf1TB1a1w5dykTAKack7q
         b2nF1VbszvzdTK8kV7N4BcbW0fLVP+hynMFTPq8LVbaG2q5BQUmYkUdjIoNtxbyFjGwF
         TTZENOye3OVMYt1qxKyqMyfA5DKdKU8pLVfAaldhhd4t1WMVu5aghKRQCskXFM97BFI8
         MTDjznMKMMcuUWAZ6lmkUWlk+Ikg2XLuI5drUQVOLgUz3UyfN4bi0G1gVY0yAy6ZlN/o
         BAg+sbfVAiJC52zgqTc5JygSxSyfE7dF+WLqNiwfLJCOG6NU5nt+ydFXCxY6EEuSaCcU
         ZNQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747184137; x=1747788937;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GO82N6fR8/CGlr6XlQvanV5UL5RCqLyQSAPQBerEddk=;
        b=EsJSKB06tqNPGKse8bfF+Y47TD69uGMoZmnfrYB069fKqvjlNolG5mCna9cLIjQ1vo
         bmOhhSCssGdU3Dt2dL29BuWiyf0DVWY2YaswbfSI6+7muslqt9SqVThjKuSa+KlAWwSo
         F11jHjsi1yGCD/eY/NvHAizzUmY8F+l9g21wlNdk/IUiO5zSml0PQhtQZOKCpb/+nHua
         8xhS/KNH+4SQG5NUkKjrnp3bYH7l1ZI5x17lMbmt/wtyvX9W2SXdT2igKrjonnwgY8MS
         I+CgQVQUNGVBhh5dVtwcQ4rvFhH/1zkwWd3vHPM9lTNomSFYBfc2QWmAex88dyWDZMKs
         bFog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN5H0dHZZwO/mt5DzgH7d79vCf7ShUrNYjgrRyAyKn4fdyZOaXqZFJzT5ukVjyqi8JLo9tzA==@lfdr.de
X-Gm-Message-State: AOJu0YzUMaW+1gwRRFTQ1trEMC/ilkicbJZuzv92BUbcKnm6zK/g/NcL
	wapMWDXO23fLiCiBk4fEWbJNnmaJVquH2t+RMBQcFLhlYzoDaNRM
X-Google-Smtp-Source: AGHT+IER5zn8QhgTGrCHlqvAZGq8BplD0B5mC3kBCpuR+KxXdzV5sArOOysIYRzcuEtwktstU60cow==
X-Received: by 2002:a05:6402:1ece:b0:5fc:8c24:814d with SMTP id 4fb4d7f45d1cf-5ff95c088e2mr1444296a12.14.1747184137330;
        Tue, 13 May 2025 17:55:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGGFBF0BGckh9lZvldf6btoKJiVNd+W4E45X2ZoHGrtPA==
Received: by 2002:a05:6402:34cc:b0:5e0:42ed:49c5 with SMTP id
 4fb4d7f45d1cf-5fc39109917ls526213a12.1.-pod-prod-00-eu; Tue, 13 May 2025
 17:55:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURWu7mE391shxbrUs3fJxv9P/uWB/KICmqZT+8wU6wMqUdmMZFQX56xIYKg6IgUg/YvttVYAVOJO4=@googlegroups.com
X-Received: by 2002:a17:907:7da3:b0:ad1:d304:e2b8 with SMTP id a640c23a62f3a-ad4f75a5eb8mr122026866b.26.1747184134695;
        Tue, 13 May 2025 17:55:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747184134; cv=none;
        d=google.com; s=arc-20240605;
        b=Fr4NYH7EXz0mBmSamScIea+M1gOZoTXARnhlbHwPjBJnecBN4erC4aQY3YCz90Ro6o
         +vDTMXa0PgCx/KQ/yOZ8KgubYQ9jkRJijjUFPirfoTTOqP4O0X+e+e5ESLcRjOEANm8m
         eWk5zmLvhhozcypi/wp3ZUqpAxp9jmkc6yp8sQtBTJ9GMjZRKW7xhE9r4Ej0sxkH89BE
         2C1CBerd6BYOd3jZT7YqO8Z3vSikVb0pmfMwNDV12QkxlNDph/tmfiMzkggIw8edH+LG
         5e3uRwKVHU71/b5dYvsCkbzlF6l/xOKqlZ+mSiRLuvljQROWoRcLlZ3IBX+ogUmyCBi6
         JoxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XlYT6MNncwrjrBVNzvakYaGt9qHqFEuJz9vDJInwvgU=;
        fh=H77gnXxg2vf7aPqnMeC48sBOWVGt5/zx6QMJI5giLhs=;
        b=elLCmvrzmR29o2VNdi0x/r9ofVlwOhhiz996VbcxsGJSNtzPfzHLDFng0P3aXRcrrb
         0rTvnrDmUCuNLprpyvVzPeZVu26XUI5iMVWggozoMS82hhKtuOe38EzrNKQaPzJsVrdI
         jRf0FjF53f58CBd1AyJgP9YlS3+6GkuFVrnuh3c4m3ytWbvlAS1YVeN7ZoszAURje/IT
         +JCcSj5y24xDuzrOWQnqQ1h4HKYnTvPNepl+pCK8y74ALeGIjOWKg3hjNa4L+8OHTWn9
         pSauNLZrm7BhnAdqCWaAOvYswemuaaiWZDhxWB/bKoyd2PZqpkA8vrkz2YENCMXM4wUc
         sQUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BONzfzNS;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ad2194a20d6si22117566b.2.2025.05.13.17.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 May 2025 17:55:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: ZJgvie97T8Gk4YCLhjedzA==
X-CSE-MsgGUID: nNVB4gCpSK+rwzTnVeeV1g==
X-IronPort-AV: E=McAfee;i="6700,10204,11432"; a="48932055"
X-IronPort-AV: E=Sophos;i="6.15,286,1739865600"; 
   d="scan'208";a="48932055"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 May 2025 17:55:31 -0700
X-CSE-ConnectionGUID: br3IwOFKQR23ZwIIxxCoXQ==
X-CSE-MsgGUID: CrAgaGlaQSqJ9cQt6R9bWw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,286,1739865600"; 
   d="scan'208";a="141899938"
Received: from lkp-server01.sh.intel.com (HELO 1992f890471c) ([10.239.97.150])
  by fmviesa003.fm.intel.com with ESMTP; 13 May 2025 17:55:24 -0700
Received: from kbuild by 1992f890471c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uF0P3-000GY3-2c;
	Wed, 14 May 2025 00:55:21 +0000
Date: Wed, 14 May 2025 08:55:11 +0800
From: kernel test robot <lkp@intel.com>
To: Kees Cook <kees@kernel.org>, Arnd Bergmann <arnd@arndb.de>
Cc: oe-kbuild-all@lists.linux.dev, Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Ard Biesheuvel <ardb@kernel.org>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	kasan-dev@googlegroups.com,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/8] init.h: Disable sanitizer coverage for __init and
 __head
Message-ID: <202505140811.z8Nb00zH-lkp@intel.com>
References: <20250507181615.1947159-2-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507181615.1947159-2-kees@kernel.org>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BONzfzNS;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted
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

Hi Kees,

kernel test robot noticed the following build warnings:

[auto build test WARNING on kees/for-next/hardening]
[also build test WARNING on arm64/for-next/core masahiroy-kbuild/for-next masahiroy-kbuild/fixes linus/master v6.15-rc6 next-20250513]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Kees-Cook/nvme-pci-Make-nvme_pci_npages_prp-__always_inline/20250508-021852
base:   https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
patch link:    https://lore.kernel.org/r/20250507181615.1947159-2-kees%40kernel.org
patch subject: [PATCH 2/8] init.h: Disable sanitizer coverage for __init and __head
config: x86_64-buildonly-randconfig-001-20250513 (https://download.01.org/0day-ci/archive/20250514/202505140811.z8Nb00zH-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250514/202505140811.z8Nb00zH-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202505140811.z8Nb00zH-lkp@intel.com/

All warnings (new ones prefixed by >>):

   drivers/mtd/maps/ichxrom.c: In function 'ichxrom_init_one.constprop':
>> drivers/mtd/maps/ichxrom.c:115:12: warning: 'byte' is used uninitialized [-Wuninitialized]
     115 |         if (byte == 0xff) {
         |            ^
   drivers/mtd/maps/ichxrom.c:97:12: note: 'byte' was declared here
      97 |         u8 byte;
         |            ^~~~
--
   drivers/mtd/maps/amd76xrom.c: In function 'amd76xrom_init_one.constprop':
>> drivers/mtd/maps/amd76xrom.c:108:12: warning: 'byte' is used uninitialized [-Wuninitialized]
     108 |         u8 byte;
         |            ^~~~


vim +/byte +115 drivers/mtd/maps/ichxrom.c

^1da177e4c3f41 Linus Torvalds     2005-04-16   88  
^1da177e4c3f41 Linus Torvalds     2005-04-16   89  
e4106a7c8236eb Julia Lawall       2016-04-19   90  static int __init ichxrom_init_one(struct pci_dev *pdev,
^1da177e4c3f41 Linus Torvalds     2005-04-16   91  				   const struct pci_device_id *ent)
^1da177e4c3f41 Linus Torvalds     2005-04-16   92  {
^1da177e4c3f41 Linus Torvalds     2005-04-16   93  	static char *rom_probe_types[] = { "cfi_probe", "jedec_probe", NULL };
^1da177e4c3f41 Linus Torvalds     2005-04-16   94  	struct ichxrom_window *window = &ichxrom_window;
^1da177e4c3f41 Linus Torvalds     2005-04-16   95  	struct ichxrom_map_info *map = NULL;
^1da177e4c3f41 Linus Torvalds     2005-04-16   96  	unsigned long map_top;
^1da177e4c3f41 Linus Torvalds     2005-04-16   97  	u8 byte;
^1da177e4c3f41 Linus Torvalds     2005-04-16   98  	u16 word;
^1da177e4c3f41 Linus Torvalds     2005-04-16   99  
^1da177e4c3f41 Linus Torvalds     2005-04-16  100  	/* For now I just handle the ichx and I assume there
^1da177e4c3f41 Linus Torvalds     2005-04-16  101  	 * are not a lot of resources up at the top of the address
^1da177e4c3f41 Linus Torvalds     2005-04-16  102  	 * space.  It is possible to handle other devices in the
^1da177e4c3f41 Linus Torvalds     2005-04-16  103  	 * top 16MB but it is very painful.  Also since
^1da177e4c3f41 Linus Torvalds     2005-04-16  104  	 * you can only really attach a FWH to an ICHX there
^1da177e4c3f41 Linus Torvalds     2005-04-16  105  	 * a number of simplifications you can make.
^1da177e4c3f41 Linus Torvalds     2005-04-16  106  	 *
^1da177e4c3f41 Linus Torvalds     2005-04-16  107  	 * Also you can page firmware hubs if an 8MB window isn't enough
^1da177e4c3f41 Linus Torvalds     2005-04-16  108  	 * but don't currently handle that case either.
^1da177e4c3f41 Linus Torvalds     2005-04-16  109  	 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  110  	window->pdev = pdev;
^1da177e4c3f41 Linus Torvalds     2005-04-16  111  
^1da177e4c3f41 Linus Torvalds     2005-04-16  112  	/* Find a region continuous to the end of the ROM window  */
^1da177e4c3f41 Linus Torvalds     2005-04-16  113  	window->phys = 0;
^1da177e4c3f41 Linus Torvalds     2005-04-16  114  	pci_read_config_byte(pdev, FWH_DEC_EN1, &byte);
^1da177e4c3f41 Linus Torvalds     2005-04-16 @115  	if (byte == 0xff) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  116  		window->phys = 0xffc00000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  117  		pci_read_config_byte(pdev, FWH_DEC_EN2, &byte);
^1da177e4c3f41 Linus Torvalds     2005-04-16  118  		if ((byte & 0x0f) == 0x0f) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  119  			window->phys = 0xff400000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  120  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  121  		else if ((byte & 0x0e) == 0x0e) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  122  			window->phys = 0xff500000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  123  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  124  		else if ((byte & 0x0c) == 0x0c) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  125  			window->phys = 0xff600000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  126  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  127  		else if ((byte & 0x08) == 0x08) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  128  			window->phys = 0xff700000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  129  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  130  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  131  	else if ((byte & 0xfe) == 0xfe) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  132  		window->phys = 0xffc80000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  133  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  134  	else if ((byte & 0xfc) == 0xfc) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  135  		window->phys = 0xffd00000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  136  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  137  	else if ((byte & 0xf8) == 0xf8) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  138  		window->phys = 0xffd80000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  139  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  140  	else if ((byte & 0xf0) == 0xf0) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  141  		window->phys = 0xffe00000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  142  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  143  	else if ((byte & 0xe0) == 0xe0) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  144  		window->phys = 0xffe80000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  145  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  146  	else if ((byte & 0xc0) == 0xc0) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  147  		window->phys = 0xfff00000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  148  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  149  	else if ((byte & 0x80) == 0x80) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  150  		window->phys = 0xfff80000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  151  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  152  
^1da177e4c3f41 Linus Torvalds     2005-04-16  153  	if (window->phys == 0) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  154  		printk(KERN_ERR MOD_NAME ": Rom window is closed\n");
^1da177e4c3f41 Linus Torvalds     2005-04-16  155  		goto out;
^1da177e4c3f41 Linus Torvalds     2005-04-16  156  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  157  	window->phys -= 0x400000UL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  158  	window->size = (0xffffffffUL - window->phys) + 1UL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  159  
^1da177e4c3f41 Linus Torvalds     2005-04-16  160  	/* Enable writes through the rom window */
^1da177e4c3f41 Linus Torvalds     2005-04-16  161  	pci_read_config_word(pdev, BIOS_CNTL, &word);
^1da177e4c3f41 Linus Torvalds     2005-04-16  162  	if (!(word & 1)  && (word & (1<<1))) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  163  		/* The BIOS will generate an error if I enable
^1da177e4c3f41 Linus Torvalds     2005-04-16  164  		 * this device, so don't even try.
^1da177e4c3f41 Linus Torvalds     2005-04-16  165  		 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  166  		printk(KERN_ERR MOD_NAME ": firmware access control, I can't enable writes\n");
^1da177e4c3f41 Linus Torvalds     2005-04-16  167  		goto out;
^1da177e4c3f41 Linus Torvalds     2005-04-16  168  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  169  	pci_write_config_word(pdev, BIOS_CNTL, word | 1);
^1da177e4c3f41 Linus Torvalds     2005-04-16  170  
^1da177e4c3f41 Linus Torvalds     2005-04-16  171  	/*
^1da177e4c3f41 Linus Torvalds     2005-04-16  172  	 * Try to reserve the window mem region.  If this fails then
01d0afddf37cbb Geert Uytterhoeven 2015-05-21  173  	 * it is likely due to the window being "reserved" by the BIOS.
^1da177e4c3f41 Linus Torvalds     2005-04-16  174  	 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  175  	window->rsrc.name = MOD_NAME;
^1da177e4c3f41 Linus Torvalds     2005-04-16  176  	window->rsrc.start = window->phys;
^1da177e4c3f41 Linus Torvalds     2005-04-16  177  	window->rsrc.end   = window->phys + window->size - 1;
^1da177e4c3f41 Linus Torvalds     2005-04-16  178  	window->rsrc.flags = IORESOURCE_MEM | IORESOURCE_BUSY;
^1da177e4c3f41 Linus Torvalds     2005-04-16  179  	if (request_resource(&iomem_resource, &window->rsrc)) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  180  		window->rsrc.parent = NULL;
f9a5279c70af10 Joe Perches        2010-11-12  181  		printk(KERN_DEBUG MOD_NAME ": "
f9a5279c70af10 Joe Perches        2010-11-12  182  		       "%s(): Unable to register resource %pR - kernel bug?\n",
f9a5279c70af10 Joe Perches        2010-11-12  183  		       __func__, &window->rsrc);
^1da177e4c3f41 Linus Torvalds     2005-04-16  184  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  185  
^1da177e4c3f41 Linus Torvalds     2005-04-16  186  	/* Map the firmware hub into my address space. */
4bdc0d676a6431 Christoph Hellwig  2020-01-06  187  	window->virt = ioremap(window->phys, window->size);
^1da177e4c3f41 Linus Torvalds     2005-04-16  188  	if (!window->virt) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  189  		printk(KERN_ERR MOD_NAME ": ioremap(%08lx, %08lx) failed\n",
^1da177e4c3f41 Linus Torvalds     2005-04-16  190  			window->phys, window->size);
^1da177e4c3f41 Linus Torvalds     2005-04-16  191  		goto out;
^1da177e4c3f41 Linus Torvalds     2005-04-16  192  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  193  
^1da177e4c3f41 Linus Torvalds     2005-04-16  194  	/* Get the first address to look for an rom chip at */
^1da177e4c3f41 Linus Torvalds     2005-04-16  195  	map_top = window->phys;
^1da177e4c3f41 Linus Torvalds     2005-04-16  196  	if ((window->phys & 0x3fffff) != 0) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  197  		map_top = window->phys + 0x400000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  198  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  199  #if 1
^1da177e4c3f41 Linus Torvalds     2005-04-16  200  	/* The probe sequence run over the firmware hub lock
^1da177e4c3f41 Linus Torvalds     2005-04-16  201  	 * registers sets them to 0x7 (no access).
^1da177e4c3f41 Linus Torvalds     2005-04-16  202  	 * Probe at most the last 4M of the address space.
^1da177e4c3f41 Linus Torvalds     2005-04-16  203  	 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  204  	if (map_top < 0xffc00000) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  205  		map_top = 0xffc00000;
^1da177e4c3f41 Linus Torvalds     2005-04-16  206  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  207  #endif
^1da177e4c3f41 Linus Torvalds     2005-04-16  208  	/* Loop through and look for rom chips */
^1da177e4c3f41 Linus Torvalds     2005-04-16  209  	while((map_top - 1) < 0xffffffffUL) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  210  		struct cfi_private *cfi;
^1da177e4c3f41 Linus Torvalds     2005-04-16  211  		unsigned long offset;
^1da177e4c3f41 Linus Torvalds     2005-04-16  212  		int i;
^1da177e4c3f41 Linus Torvalds     2005-04-16  213  
^1da177e4c3f41 Linus Torvalds     2005-04-16  214  		if (!map) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  215  			map = kmalloc(sizeof(*map), GFP_KERNEL);
4883307c6d8e59 Zhen Lei           2021-06-10  216  			if (!map)
^1da177e4c3f41 Linus Torvalds     2005-04-16  217  				goto out;
^1da177e4c3f41 Linus Torvalds     2005-04-16  218  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  219  		memset(map, 0, sizeof(*map));
^1da177e4c3f41 Linus Torvalds     2005-04-16  220  		INIT_LIST_HEAD(&map->list);
^1da177e4c3f41 Linus Torvalds     2005-04-16  221  		map->map.name = map->map_name;
^1da177e4c3f41 Linus Torvalds     2005-04-16  222  		map->map.phys = map_top;
^1da177e4c3f41 Linus Torvalds     2005-04-16  223  		offset = map_top - window->phys;
^1da177e4c3f41 Linus Torvalds     2005-04-16  224  		map->map.virt = (void __iomem *)
^1da177e4c3f41 Linus Torvalds     2005-04-16  225  			(((unsigned long)(window->virt)) + offset);
^1da177e4c3f41 Linus Torvalds     2005-04-16  226  		map->map.size = 0xffffffffUL - map_top + 1UL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  227  		/* Set the name of the map to the address I am trying */
3a38d3af92c423 Andrew Morton      2007-02-17  228  		sprintf(map->map_name, "%s @%08Lx",
3a38d3af92c423 Andrew Morton      2007-02-17  229  			MOD_NAME, (unsigned long long)map->map.phys);
^1da177e4c3f41 Linus Torvalds     2005-04-16  230  
^1da177e4c3f41 Linus Torvalds     2005-04-16  231  		/* Firmware hubs only use vpp when being programmed
^1da177e4c3f41 Linus Torvalds     2005-04-16  232  		 * in a factory setting.  So in-place programming
^1da177e4c3f41 Linus Torvalds     2005-04-16  233  		 * needs to use a different method.
^1da177e4c3f41 Linus Torvalds     2005-04-16  234  		 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  235  		for(map->map.bankwidth = 32; map->map.bankwidth;
^1da177e4c3f41 Linus Torvalds     2005-04-16  236  			map->map.bankwidth >>= 1)
^1da177e4c3f41 Linus Torvalds     2005-04-16  237  		{
^1da177e4c3f41 Linus Torvalds     2005-04-16  238  			char **probe_type;
^1da177e4c3f41 Linus Torvalds     2005-04-16  239  			/* Skip bankwidths that are not supported */
^1da177e4c3f41 Linus Torvalds     2005-04-16  240  			if (!map_bankwidth_supported(map->map.bankwidth))
^1da177e4c3f41 Linus Torvalds     2005-04-16  241  				continue;
^1da177e4c3f41 Linus Torvalds     2005-04-16  242  
^1da177e4c3f41 Linus Torvalds     2005-04-16  243  			/* Setup the map methods */
^1da177e4c3f41 Linus Torvalds     2005-04-16  244  			simple_map_init(&map->map);
^1da177e4c3f41 Linus Torvalds     2005-04-16  245  
^1da177e4c3f41 Linus Torvalds     2005-04-16  246  			/* Try all of the probe methods */
^1da177e4c3f41 Linus Torvalds     2005-04-16  247  			probe_type = rom_probe_types;
^1da177e4c3f41 Linus Torvalds     2005-04-16  248  			for(; *probe_type; probe_type++) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  249  				map->mtd = do_map_probe(*probe_type, &map->map);
^1da177e4c3f41 Linus Torvalds     2005-04-16  250  				if (map->mtd)
^1da177e4c3f41 Linus Torvalds     2005-04-16  251  					goto found;
^1da177e4c3f41 Linus Torvalds     2005-04-16  252  			}
^1da177e4c3f41 Linus Torvalds     2005-04-16  253  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  254  		map_top += ROM_PROBE_STEP_SIZE;
^1da177e4c3f41 Linus Torvalds     2005-04-16  255  		continue;
^1da177e4c3f41 Linus Torvalds     2005-04-16  256  	found:
^1da177e4c3f41 Linus Torvalds     2005-04-16  257  		/* Trim the size if we are larger than the map */
^1da177e4c3f41 Linus Torvalds     2005-04-16  258  		if (map->mtd->size > map->map.size) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  259  			printk(KERN_WARNING MOD_NAME
69423d99fc182a Adrian Hunter      2008-12-10  260  				" rom(%llu) larger than window(%lu). fixing...\n",
69423d99fc182a Adrian Hunter      2008-12-10  261  				(unsigned long long)map->mtd->size, map->map.size);
^1da177e4c3f41 Linus Torvalds     2005-04-16  262  			map->mtd->size = map->map.size;
^1da177e4c3f41 Linus Torvalds     2005-04-16  263  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  264  		if (window->rsrc.parent) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  265  			/*
^1da177e4c3f41 Linus Torvalds     2005-04-16  266  			 * Registering the MTD device in iomem may not be possible
^1da177e4c3f41 Linus Torvalds     2005-04-16  267  			 * if there is a BIOS "reserved" and BUSY range.  If this
^1da177e4c3f41 Linus Torvalds     2005-04-16  268  			 * fails then continue anyway.
^1da177e4c3f41 Linus Torvalds     2005-04-16  269  			 */
^1da177e4c3f41 Linus Torvalds     2005-04-16  270  			map->rsrc.name  = map->map_name;
^1da177e4c3f41 Linus Torvalds     2005-04-16  271  			map->rsrc.start = map->map.phys;
^1da177e4c3f41 Linus Torvalds     2005-04-16  272  			map->rsrc.end   = map->map.phys + map->mtd->size - 1;
^1da177e4c3f41 Linus Torvalds     2005-04-16  273  			map->rsrc.flags = IORESOURCE_MEM | IORESOURCE_BUSY;
^1da177e4c3f41 Linus Torvalds     2005-04-16  274  			if (request_resource(&window->rsrc, &map->rsrc)) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  275  				printk(KERN_ERR MOD_NAME
^1da177e4c3f41 Linus Torvalds     2005-04-16  276  					": cannot reserve MTD resource\n");
^1da177e4c3f41 Linus Torvalds     2005-04-16  277  				map->rsrc.parent = NULL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  278  			}
^1da177e4c3f41 Linus Torvalds     2005-04-16  279  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  280  
^1da177e4c3f41 Linus Torvalds     2005-04-16  281  		/* Make the whole region visible in the map */
^1da177e4c3f41 Linus Torvalds     2005-04-16  282  		map->map.virt = window->virt;
^1da177e4c3f41 Linus Torvalds     2005-04-16  283  		map->map.phys = window->phys;
^1da177e4c3f41 Linus Torvalds     2005-04-16  284  		cfi = map->map.fldrv_priv;
^1da177e4c3f41 Linus Torvalds     2005-04-16  285  		for(i = 0; i < cfi->numchips; i++) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  286  			cfi->chips[i].start += offset;
^1da177e4c3f41 Linus Torvalds     2005-04-16  287  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  288  
^1da177e4c3f41 Linus Torvalds     2005-04-16  289  		/* Now that the mtd devices is complete claim and export it */
^1da177e4c3f41 Linus Torvalds     2005-04-16  290  		map->mtd->owner = THIS_MODULE;
ee0e87b174bb41 Jamie Iles         2011-05-23  291  		if (mtd_device_register(map->mtd, NULL, 0)) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  292  			map_destroy(map->mtd);
^1da177e4c3f41 Linus Torvalds     2005-04-16  293  			map->mtd = NULL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  294  			goto out;
^1da177e4c3f41 Linus Torvalds     2005-04-16  295  		}
^1da177e4c3f41 Linus Torvalds     2005-04-16  296  
^1da177e4c3f41 Linus Torvalds     2005-04-16  297  
^1da177e4c3f41 Linus Torvalds     2005-04-16  298  		/* Calculate the new value of map_top */
^1da177e4c3f41 Linus Torvalds     2005-04-16  299  		map_top += map->mtd->size;
^1da177e4c3f41 Linus Torvalds     2005-04-16  300  
^1da177e4c3f41 Linus Torvalds     2005-04-16  301  		/* File away the map structure */
^1da177e4c3f41 Linus Torvalds     2005-04-16  302  		list_add(&map->list, &window->maps);
^1da177e4c3f41 Linus Torvalds     2005-04-16  303  		map = NULL;
^1da177e4c3f41 Linus Torvalds     2005-04-16  304  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  305  
^1da177e4c3f41 Linus Torvalds     2005-04-16  306   out:
^1da177e4c3f41 Linus Torvalds     2005-04-16  307  	/* Free any left over map structures */
^1da177e4c3f41 Linus Torvalds     2005-04-16  308  	kfree(map);
fa671646f61182 Jesper Juhl        2005-11-07  309  
^1da177e4c3f41 Linus Torvalds     2005-04-16  310  	/* See if I have any map structures */
^1da177e4c3f41 Linus Torvalds     2005-04-16  311  	if (list_empty(&window->maps)) {
^1da177e4c3f41 Linus Torvalds     2005-04-16  312  		ichxrom_cleanup(window);
^1da177e4c3f41 Linus Torvalds     2005-04-16  313  		return -ENODEV;
^1da177e4c3f41 Linus Torvalds     2005-04-16  314  	}
^1da177e4c3f41 Linus Torvalds     2005-04-16  315  	return 0;
^1da177e4c3f41 Linus Torvalds     2005-04-16  316  }
^1da177e4c3f41 Linus Torvalds     2005-04-16  317  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505140811.z8Nb00zH-lkp%40intel.com.

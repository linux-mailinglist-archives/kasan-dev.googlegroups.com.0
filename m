Return-Path: <kasan-dev+bncBC4LXIPCY4NRBSMY5KHQMGQEM57KY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8233D4A720B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 14:51:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id v190-20020a1cacc7000000b0034657bb6a66sf4538949wme.6
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 05:51:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643809865; cv=pass;
        d=google.com; s=arc-20160816;
        b=cmDjR18h6GnsLVM0Hgn/CO7p/W175ZMTT86tfYi6BjVGaoTYQzv3d4+iPJdC1PxWpw
         hLTMJ0OqL8ewbWaP5sPycN0uIseTR5UK8qle7HnCptZ8BVdeJ8IfLS+HdVUSb2wgzBg6
         C6emt8IJB4HZa3dvXkrNGh2veUmvjUT9I7+XpraSCOtROJWW1xrWN4Cqo3AAuA/Bwzuo
         R0xXuJLoihgzUaI5YiWHkHhd6jUbe9Rhk39Tw3cCHLKFHEd5XVj4QC8V8ho79GEFIuRl
         c67uKKZsr6Athtsoj2wghHTggJJm6ZNpjukuUMOX3jMckitZ8+z9kctKABNhycQMU226
         wrTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=B6HgaRCkLnAcir7nmVCefFhHfUVszga1YNghA7+cSNo=;
        b=rdvR8HQUvE3FGvKYOpOn4iQo+MPsg2BO+MBTmlXk2syBPV+lEkZwWqRgZq0+Koebmx
         nU7DY+giV2+zKcL3uABoexnzzI24f/rndnPM4TZXtErCLS7zZC3SvGgdfriHX2mLhPa/
         zXACs+SO7IidBpnOczHnGVdvvLboHn4J8uHCFcmVbYfs7SVKm4l+yR2rX2pHxb1+qJLc
         3MywA/Ouq49vPQBJ+FwFDR2kqaRfPXAJqHvK00WMYNqv+eXkDAqNIDUadLKsRdASQjSk
         4aO12/9ZYiAwe3fY5TuLQRI9Xi8CHHGM5TkiY6ZqX+gfI5QN6otFzZriI+Rp+huBar6z
         KnNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RUlYhVTH;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B6HgaRCkLnAcir7nmVCefFhHfUVszga1YNghA7+cSNo=;
        b=pLg5qGSIVWe4gLtmveySZ9znb1Hv7IaP5K7hzY0+pRVSGsrarjsVjeDb+MRyvuL/Wy
         NyGTLoHTHX0+4fmXxAqlQ5pYwiFJA13uewodO4ofWMGBl88ZDDU9crC6HTnxMmWozr1b
         +zaaXJm5tMRPWaHDQk8Yy6VXTkD5lATOuUqHT0D7SPbBoThD4gtAHeEmuaoUnOOy9oxK
         xPLUKM1NNWs2jrqlJH1Ms221qLWKCeghfb9u6isRKD8l1KPXoR+WCRdLO4rfwmUn8WVS
         QAFnGnTLl2CFONYNcZ9gkv8DIU0qISh7vxZMuBfQVu9LWBCpHAqP0dj1xhpHuWwHdHVf
         V9NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=B6HgaRCkLnAcir7nmVCefFhHfUVszga1YNghA7+cSNo=;
        b=csSjrntsPqn6dprzrHY6awk+p0eXLHayn3Vln+++NZOmE/4lSnUueuN8W9bORAWtgy
         WnxiakTektHWz2kGCdJS4OAEhlwZ1x3EhyirzhuyM8Cf7fc8KDWdD9KpJ6dQvXezTMpk
         geoLDJuJna4dx/2AszbFJ1Qd1/jYfFTasLmxTemj98ooFg324/5dUdeGdCq7iQvKvuAb
         gun3iiF8Hs8zlgPBGsRg2VUyafH/pHrzZC+zrvX8S0cFrPebKjIxjl4XNf85ABibXXaD
         Aty0riLamkA+vAE1ctPeK3QAXJzONepaZfiLWQ6CXkzuc/CSbnJmfWjkUZ9ZcmACFzhE
         vg2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Pjy/Bpv4BM72/gkQgzmDNvpHC5/UKsU5k326ej3eoBYQzpe/x
	zrs0u8svqqnqTkAllmUAESk=
X-Google-Smtp-Source: ABdhPJwslPKFt4ul4bzebBPgctjjSMdgsKi0KQxz9kC4EOB0SCuUu9kHCpo1qGk04zHvKePc+HnKvQ==
X-Received: by 2002:a05:6000:1081:: with SMTP id y1mr25579518wrw.660.1643809865268;
        Wed, 02 Feb 2022 05:51:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c8:: with SMTP id b8ls402563wrg.0.gmail; Wed, 02
 Feb 2022 05:51:04 -0800 (PST)
X-Received: by 2002:a5d:6da4:: with SMTP id u4mr25390684wrs.611.1643809864385;
        Wed, 02 Feb 2022 05:51:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643809864; cv=none;
        d=google.com; s=arc-20160816;
        b=O+cEeQ9j5nfDqQyDJRW9Qtam+BDCzK1cwSZv78M6FEmmqFLOrrnpnA3vs35xxlYPaD
         YTgMz7EqPJ5EvCha7uUx5NRNxW46x2OxuAadqR8lyV9VLqGNkr7wZIYMr1UavcAe3hKj
         14H25bGoIvv+T1ZNPrWhbP0cYF/3MrVafiSq5vg/uMzKhkD4KnfoqZGoO5SCosxNHJPC
         Na5tjO+5VvGfdDtLTPX0PVI3eYY7OhpGlFAAGKFbE4bEvonC1TMwL1we4dl33L3r7kqT
         UpoIJt2AnSKRJpZvdJb+X4WvQBEi9Bkph58vE0P3I8LlmHBI2hPkunuJY5ghnNWB1C5x
         K1WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5VQvBs0dgJkZ9fBMFcqRNaysDtzmeTDL8dwHPzpsbdQ=;
        b=snLB+oFx4ORRLt7aDmbiNFnThIAX7n+P+uBP4jUHO/+XtyDmv/dTIa/5BINR7+edaO
         fHZkmDMRkOOm2VGkH+bqMBwRtM75C93o7JRIBQTBq+G1EVqVNfLoYSpRYZI6G1xk7DXQ
         0h03mFCeshOvBS3MtAvMqLz1atdNifubW1A+OSVOKQWvoo0NSHra0k86Z1vrzaqR9X2l
         ZBYf1+/C/r+g5Wnu4rEWl7j2aG3624/EvgcZTUKJhULasIy3jbRwqKFpEVc0BeNtqx9R
         iXd4EZtYVbZi1CQiSUpAS2UU/keU7pj8pu2T64V/2MKev/7cVeBx14IZXD/ao91lQP3K
         lvQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RUlYhVTH;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id c4si268181wmq.1.2022.02.02.05.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Feb 2022 05:51:04 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6200,9189,10245"; a="247686421"
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="247686421"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Feb 2022 05:51:02 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,336,1635231600"; 
   d="scan'208";a="534855601"
Received: from lkp-server01.sh.intel.com (HELO 276f1b88eecb) ([10.239.97.150])
  by fmsmga007.fm.intel.com with ESMTP; 02 Feb 2022 05:50:59 -0800
Received: from kbuild by 276f1b88eecb with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nFG2E-000Uek-Jm; Wed, 02 Feb 2022 13:50:58 +0000
Date: Wed, 2 Feb 2022 21:50:20 +0800
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
Subject: Re: [PATCH 1/4] mm/kasan: Add CONFIG_KASAN_SOFTWARE
Message-ID: <202202022149.BRH60mXN-lkp@intel.com>
References: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=RUlYhVTH;       spf=pass
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
config: x86_64-randconfig-a013-20220131 (https://download.01.org/0day-ci/archive/20220202/202202022149.BRH60mXN-lkp@intel.com/config)
compiler: clang version 14.0.0 (https://github.com/llvm/llvm-project 6b1e844b69f15bb7dffaf9365cd2b355d2eb7579)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/29c1001f88c380ea391fa5520f2ddcce35e35681
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review Christophe-Leroy/mm-kasan-Add-CONFIG_KASAN_SOFTWARE/20220202-164612
        git checkout 29c1001f88c380ea391fa5520f2ddcce35e35681
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from arch/x86/boot/compressed/cmdline.c:2:
   In file included from arch/x86/boot/compressed/misc.h:32:
   In file included from include/linux/acpi.h:14:
   In file included from include/linux/resource_ext.h:11:
   In file included from include/linux/slab.h:136:
>> include/linux/kasan.h:56:41: error: use of undeclared identifier 'KASAN_SHADOW_SCALE_SHIFT'
           return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
                                                  ^
>> include/linux/kasan.h:57:5: error: use of undeclared identifier 'KASAN_SHADOW_OFFSET'
                   + KASAN_SHADOW_OFFSET;
                     ^
   2 errors generated.
--
   In file included from arch/x86/boot/compressed/pgtable_64.c:2:
   In file included from arch/x86/boot/compressed/misc.h:32:
   In file included from include/linux/acpi.h:14:
   In file included from include/linux/resource_ext.h:11:
   In file included from include/linux/slab.h:136:
>> include/linux/kasan.h:56:41: error: use of undeclared identifier 'KASAN_SHADOW_SCALE_SHIFT'
           return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
                                                  ^
>> include/linux/kasan.h:57:5: error: use of undeclared identifier 'KASAN_SHADOW_OFFSET'
                   + KASAN_SHADOW_OFFSET;
                     ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:11: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                           ^        ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:97:25: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[3] | set->sig[2] |
                                         ^        ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:98:4: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           set->sig[1] | set->sig[0]) == 0;
                           ^        ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:100:11: warning: array index 1 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return (set->sig[1] | set->sig[0]) == 0;
                           ^        ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:11: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[3] == set2->sig[3]) &&
                            ^         ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:113:27: warning: array index 3 is past the end of the array (which contains 1 element) [-Warray-bounds]
                   return  (set1->sig[3] == set2->sig[3]) &&
                                            ^         ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:5: warning: array index 2 is past the end of the array (which contains 1 element) [-Warray-bounds]
                           (set1->sig[2] == set2->sig[2]) &&
                            ^         ~
   arch/x86/include/asm/signal.h:24:2: note: array 'sig' declared here
           unsigned long sig[_NSIG_WORDS];
           ^
   In file included from arch/x86/boot/compressed/pgtable_64.c:3:
   In file included from include/linux/efi.h:19:
   In file included from include/linux/proc_fs.h:10:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:


vim +/KASAN_SHADOW_SCALE_SHIFT +56 include/linux/kasan.h

69786cdb379bbc Andrey Ryabinin  2015-08-13  50  
9577dd74864877 Andrey Konovalov 2018-12-28  51  int kasan_populate_early_shadow(const void *shadow_start,
69786cdb379bbc Andrey Ryabinin  2015-08-13  52  				const void *shadow_end);
69786cdb379bbc Andrey Ryabinin  2015-08-13  53  
0b24becc810dc3 Andrey Ryabinin  2015-02-13  54  static inline void *kasan_mem_to_shadow(const void *addr)
0b24becc810dc3 Andrey Ryabinin  2015-02-13  55  {
0b24becc810dc3 Andrey Ryabinin  2015-02-13 @56  	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
0b24becc810dc3 Andrey Ryabinin  2015-02-13 @57  		+ KASAN_SHADOW_OFFSET;
0b24becc810dc3 Andrey Ryabinin  2015-02-13  58  }
0b24becc810dc3 Andrey Ryabinin  2015-02-13  59  

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202022149.BRH60mXN-lkp%40intel.com.

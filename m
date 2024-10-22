Return-Path: <kasan-dev+bncBC4LXIPCY4NRB7P2364AMGQERNCBR3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BD589AB6CD
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 21:31:11 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a39631593asf1632385ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 12:31:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729625469; cv=pass;
        d=google.com; s=arc-20240605;
        b=aj9/2wI0Dyyac6aQkK23cb6oy0UbEK+BKXBTyddpchK4D0C5HsE7dqSz9mFVvPuHqi
         vRUil2uEUym4b79Cu48A87HCiKE5etVjqDY5TnRP8scmX2pMs67gmfPth+Lgtc6Qfkxx
         Cg46jKkShpnOavRpOtiSwBuoKKpNjf66zVuTiSkemP8InzYin5Qsc+Bgf7+7wUdretsY
         2wNU4aFcGdLfoigwT1811XDx0bOQkURu6z6Ls02M6ZtoF33P7aEmyJyMMSXIKXEK3nNb
         zzWnPo3ezIJ53I5iQ2S8/SmgtKVPNe362qjl2lZccgHKvKTQWHKYCRa72AQrf2z8BVkS
         X6OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LNZ9TsAYnVUHKb83WsYl2EejSsqXe6JraR6hAkBKTps=;
        fh=NzxM3yP9Z4iOTp2kRyB+BX+yRuutmosbR+gZ2UZSvHI=;
        b=OVJulp7zUgngvfFlxXxR88xBTJeidJoOpxrhIvg4tZ/0Aa8eKOr+r2YU+vb9PJTkx3
         0B82IuX8v+JxjWx8CQa6ehegN8jscG1eusvuVEFigFqHAii0aSZHhRP6PoEyXDBSlzXI
         e9wcZ5bJOlqTJgP4oPIarPcO/KfhOah+EwVbJidYTUPERmjPexOAUy07o8v3QkrUf7zg
         NbPRT3jIfxdKE9939NnsbSEH3Zv7BMneq5tDOy7vLoh9KDabqWpeuxMchU4/hUZTis2d
         Y2/mCJCbClq4TbIHPnkeByDP1cDF/gOAvE1C1JgdsWKoFOplR0f3t1gHht0XBHECj6RY
         J8+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="bAJDzYn/";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729625469; x=1730230269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LNZ9TsAYnVUHKb83WsYl2EejSsqXe6JraR6hAkBKTps=;
        b=IglBGPkfi9Awyf5LZ+Io2oqGN3Y3L9A5lXhjvV+GPgimXZV1XvQJWTuaf1j/WbEeHF
         4qYNj+UDrHTqrERZzqMN1Rlo+1TBRjeO/uAx7XvP8J+VUv3e1tzE1i3sUj1QyzgBpvpR
         Lp6okiqwtJEb1n+Rr26ghpTQ7UaFKdVKUSmvgVYgOSS1BeOd9NSKa1MXGi6RlK2dPTlf
         r/mzB6WH0291CST6NkVl4eGTaPLpzqvTwslxB2rHWmRSKAOk219bvovJfS3fpZ1cBHF3
         DstSBrFc97NihnNZ78N4wVIRO28itmuCIrNHsylsNe6afo8063pir8ZDuDymd6alk8Mh
         GONQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729625469; x=1730230269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LNZ9TsAYnVUHKb83WsYl2EejSsqXe6JraR6hAkBKTps=;
        b=hgIKWKAQ+TRhbnJpU/zH/d0Vo2wMovkfcvQEk3FxUVYNZxYzNkhP38GFM/wXNEZYNG
         REHMmt0NTpBnv6iZ0L0F3DaLH9mUR9j18sql42z9Mps6f7b8Wd6V2p1XIqSVI0GUfh50
         6bJx/fcqLSZZoWdN6isXKUpAX75J/OJOHyQuVOVnev0A3iJieWlj/jsH3iJzn6ETlbOz
         dLLL6BLoSxNbgOHECgy7NvxK4R2yHmVsGG2HuYWphyLje4/i48ulsSKHVPe5NS9scEks
         U6Vde6xYqoYiGpvI+Ps0UT3vO3qq3mIZHLQpTh+2gXIAwkJ1gNTfbnRNr/e/jIkrw5iC
         TU0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWX12870p9OXJYaoag4MxpVhk3XpQxQpWuYDHD33MmaQc7UUN5ykIdXS/4yNuioH7osKIDHEQ==@lfdr.de
X-Gm-Message-State: AOJu0YxObDgEinC0/mEQN5jdjhyHJoRaatCTBQud5fae3EUGWQ1dujt8
	RAWtM7NOmiOSjjqJLAaPm8rEHKut5P0nKZencUKLEU0QChMdYbYO
X-Google-Smtp-Source: AGHT+IFGewUCGJf8kJ8Le4DQ8cRrm1+iIjs0eb8TZ++uUIu1N0r9rqgnMjz0nvbenuuF7iw0WFwm5A==
X-Received: by 2002:a92:cda5:0:b0:39f:507a:6170 with SMTP id e9e14a558f8ab-3a4d5995265mr1682895ab.8.1729625469491;
        Tue, 22 Oct 2024 12:31:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ee:b0:3a1:a57a:40b6 with SMTP id
 e9e14a558f8ab-3a3e4af2c4als5947835ab.1.-pod-prod-00-us; Tue, 22 Oct 2024
 12:31:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHkpFzVIj3AiMpwouxoCTOxJeD3VzgDjFRZEfwy9xoOb8sL96VvaPxYxgf55ZD8Oa2Y3r4q3yspTg=@googlegroups.com
X-Received: by 2002:a05:6602:340e:b0:83a:b83a:bfa8 with SMTP id ca18e2360f4ac-83af6538467mr14019439f.6.1729625468122;
        Tue, 22 Oct 2024 12:31:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729625468; cv=none;
        d=google.com; s=arc-20240605;
        b=OFnWHgV7NhhRSIfaWWGndlITSEnYhtio87RPALdLvcPewaoSK8DNdeNpMOeIbqvH+u
         GL2F/fqlYyUPpzF8u/0Q0BR+7HE6dj3W8Ql3Tuxi9ixiYpS+B1YAkeQFkTz8wKMeE7+i
         FT+QmuMkQSS9ORIdmtkGhfbxwEHHrIrZ49E0h3QU3qiVuB2sSWFLP2wZsWlefJ37IUw/
         lwYMcAWnKH+DgCQWd+ykCWQ0BhBtd/jOK8JEIOrhzlsn8WY8GTKtW6N6Zb5QgMUV6VyI
         0iMDUT6fEc1mTublrAlhZZvTwMG9ambOtP5l0+ptMW5bnVIUByGM05TB8/zv6MsqD7Z3
         jP4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6gW6sdh9l3devP3hcuMDnR299+H+UwnleHdgFQFx0ns=;
        fh=fSM/8HxWtT2rEdVZa0SYVxs4mgtZiX8VorsCBU0XNAk=;
        b=OB5AXAJDk9ffg2JGo+EJuvW6H3lRndTatmQ7CikAepUnBSbeTUo8TcJpqj60X/lXGb
         jMi9X21IJuiSLVpu6d5KGqD0lmAi+dEGmAEUDoffuFMi+/16ZF2sIL19CAyfGf/ckYyz
         trVQmjIru0OfQ89crnV5XlmaKpDX5zETSxOunEkIUsgH9H0eVtI5uyBROGYXWwPup/xM
         DPd7aLnoQQZxI0EuIq/oq35av59vBsvL6hMyF6oadil6U8MEuWsPyIdfHTQh5FjCF1LZ
         1Xej3IMd18/Lxfz+Q5lorBO2RZLAgIkOsOphalpT+KxNQ7kvZbPPfkIXM4E1Q1jRZKQk
         NXvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="bAJDzYn/";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.17])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dc2a2f6605si235991173.0.2024.10.22.12.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Oct 2024 12:31:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted sender) client-ip=192.198.163.17;
X-CSE-ConnectionGUID: iGYdV39UQniaioJUt8dpvQ==
X-CSE-MsgGUID: O721471OQnac+8MX2zD2aw==
X-IronPort-AV: E=McAfee;i="6700,10204,11233"; a="29077395"
X-IronPort-AV: E=Sophos;i="6.11,223,1725346800"; 
   d="scan'208";a="29077395"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa111.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Oct 2024 12:31:04 -0700
X-CSE-ConnectionGUID: Pwm7nuaRS+OM+Ao/bzXSFQ==
X-CSE-MsgGUID: VwQ5hbwkRxu5oP8/NSHLAg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,223,1725346800"; 
   d="scan'208";a="84759782"
Received: from lkp-server01.sh.intel.com (HELO a48cf1aa22e8) ([10.239.97.150])
  by orviesa005.jf.intel.com with ESMTP; 22 Oct 2024 12:31:00 -0700
Received: from kbuild by a48cf1aa22e8 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1t3Kan-000U0d-2J;
	Tue, 22 Oct 2024 19:30:57 +0000
Date: Wed, 23 Oct 2024 03:30:45 +0800
From: kernel test robot <lkp@intel.com>
To: Samuel Holland <samuel.holland@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: oe-kbuild-all@lists.linux.dev, llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: Re: [PATCH v2 4/9] kasan: sw_tags: Support tag widths less than 8
 bits
Message-ID: <202410230354.sjewoFxA-lkp@intel.com>
References: <20241022015913.3524425-5-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241022015913.3524425-5-samuel.holland@sifive.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="bAJDzYn/";       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.17 as permitted
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

Hi Samuel,

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-everything]
[also build test ERROR on arm64/for-next/core masahiroy-kbuild/for-next masahiroy-kbuild/fixes linus/master v6.12-rc4 next-20241022]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Samuel-Holland/kasan-sw_tags-Use-arithmetic-shift-for-shadow-computation/20241022-100129
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20241022015913.3524425-5-samuel.holland%40sifive.com
patch subject: [PATCH v2 4/9] kasan: sw_tags: Support tag widths less than 8 bits
config: sh-allmodconfig (https://download.01.org/0day-ci/archive/20241023/202410230354.sjewoFxA-lkp@intel.com/config)
compiler: sh4-linux-gcc (GCC) 14.1.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20241023/202410230354.sjewoFxA-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202410230354.sjewoFxA-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from include/linux/kasan.h:7,
                    from include/linux/mm.h:31,
                    from arch/sh/kernel/asm-offsets.c:14:
>> include/linux/kasan-tags.h:5:10: fatal error: asm/kasan.h: No such file or directory
       5 | #include <asm/kasan.h>
         |          ^~~~~~~~~~~~~
   compilation terminated.
   make[3]: *** [scripts/Makefile.build:102: arch/sh/kernel/asm-offsets.s] Error 1
   make[3]: Target 'prepare' not remade because of errors.
   make[2]: *** [Makefile:1203: prepare0] Error 2
   make[2]: Target 'prepare' not remade because of errors.
   make[1]: *** [Makefile:224: __sub-make] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:224: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +5 include/linux/kasan-tags.h

     4	
   > 5	#include <asm/kasan.h>
     6	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410230354.sjewoFxA-lkp%40intel.com.

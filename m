Return-Path: <kasan-dev+bncBC4LXIPCY4NRBVGZUK4AMGQEFOSWNYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6157D999BC3
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 06:43:02 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3a3b7d1e8a0sf915805ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 21:43:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728621781; cv=pass;
        d=google.com; s=arc-20240605;
        b=iCErbP72EaREG8miRtRc/2U5ThA2TwlpjBH4gVtszVqvqdlBjAN0EOjt2hVHnF1ak4
         2jgiI2ADmL7af2f2dDwoPQN/yzka8zEpKN9mFWBpA0ctWtec8tSpnjKT7tMEgLp/Ouy1
         2IpmvbbQ+lMCEnCsGWVad8cKIo3R1I6iR41Ya2H7b+BQC5WWpdE2DbIa6X+MB/dOG2UY
         gAMH+qHeL29ysDlQ6VSwp/nCVqS0QBwIrY2GPVsj4lf6WLKlofd9gHN+DEXatgjbULhm
         z0aBGw4f1FQ5htpTsYpP5UMJATYnguK0yx2Lzs36H2JysM1e7ZyN+f2DjAkyZo29GpV5
         sQOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5etIQaXqn6H8Yb2k1owLFJRkAaw4Xx2eL/cKKamoMLQ=;
        fh=RBhmMIrD6r7bfX6A+hkoFaYQ41cVSs/uOTZKuaOVdnA=;
        b=WBHJUJmE1v3Vk3d0KfWKZKwt16RiWr/ONZQz2NuBzq3kZCBHngMAm/chPMrPEVuytS
         /SyzfEU/NELsZdKrwfYgCkLmWeSS/bgjvx7iFN8p9Wt6fUgo2lbhUKiyjYnD3GfVK2NE
         9UroVTJdeRULpaOkCww/Ei0s+mEKrwPXEznTJF6xgV0xvCFvm30rZrSMhrpC9S5N6lG1
         SYzmTAnwjbj5RzTmV8LpkEtimcYjuAFc+E9sZ3/s1HIvM3F527TDypAvIy2MyytoqdFv
         vRHHn/EwiuxEJf5hc9fTORS9UBs0we3xsSp5aVF7wM11n8TVGDdO1wF8BWz8WGkhfdmI
         JOBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KRoDA2QS;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728621781; x=1729226581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5etIQaXqn6H8Yb2k1owLFJRkAaw4Xx2eL/cKKamoMLQ=;
        b=ZssfixZuYo+MfbTMUP47/LHiZILWGN8iYzVzpW0BAWDd92FjZgbyouKnF23WLdSY7A
         CdJU1Vuejw6r+GolJ16JzsWnM+F0f+rtf19sS8KrdFrdDsWCD+myUh3ufKfnOLRKuyHJ
         EkyVXdF+6sbRUG4T2WrHieOTbO3BVfJ2lveW2me1AhOMKp66bXBJruF0Of0qcubwubsp
         JrgGdMGlUg1L6SJ2LfkXV8X2qm4s1PKzsLZ/BN9lyNhjkVZdaMhYZlgEuG/RlpxTfuka
         c2CJkt6mClsj6zTildBIVrDBM3YV628fHqEM6ukdlTWjkaiCWcXKG/txzf+YZv9Hxf+m
         nwYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728621781; x=1729226581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5etIQaXqn6H8Yb2k1owLFJRkAaw4Xx2eL/cKKamoMLQ=;
        b=F3OgFI1d+JrNKaKdfvNXQZOYlO1E7ZD3sgujZIefk0zntmGqa4fx5lDiGySp3xm7fK
         l0y9sJt0UdO49Z93MuHcKki6n6MN54lzMyI6JuMgB5FvDtPWm3tE4Lks3SXOAwrvvADg
         cW2dELGf++CSGkj4AymBG7k2h5qqOX9dSI0s5sv9/X8Tp1nagKChS1lHe2XXVprclyE6
         +P2f7gsCJ40BF9smPGb+KwkKMrZ7JeJvpKfNlAP0CXOuBVV7zjSTgCpWjh1SyEo7onEV
         E33ZPIkDhaQlTKvQg9UC6I6tgUzxdeYKOg2RJWh4Y6jfYkK/QZvjnczj7VaDNdZeGmY2
         mlCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhAUJEbYOGtqnciBTJEkrWi8VmTuszaAdMMW9DXHhWB7g3TRwwt/4I1BVTTl+sBr33Y1E3yg==@lfdr.de
X-Gm-Message-State: AOJu0YzvgttHWaPlo8xxKNriZgrJrNvk3PHqvQAyuUl0xxpgohxsCIdy
	rtaIfPipqt5i0oFQiHUkhSegxDKLJdyaZDxWzatM1oEtUjMtzG/f
X-Google-Smtp-Source: AGHT+IHzIbWMhGWKkAF99m++MRPfI8VrrJ/vE4OLaSRLoTNCQ0BMRCy1k1T9XEbxqI92U1i07To82Q==
X-Received: by 2002:a05:6e02:1c4a:b0:3a3:49f0:f425 with SMTP id e9e14a558f8ab-3a3b5c73ef8mr11855375ab.0.1728621780759;
        Thu, 10 Oct 2024 21:43:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1e0a:b0:3a0:b55f:cde1 with SMTP id
 e9e14a558f8ab-3a3a73702d1ls7268745ab.0.-pod-prod-04-us; Thu, 10 Oct 2024
 21:43:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYJndJs9/rBhD94aqWTDRPp6JgMUIkSi+WWuXZuzfQwp8PokbM9YwxS3PfwqKg7HXVPLt1lV+Lsxg=@googlegroups.com
X-Received: by 2002:a05:6602:6216:b0:835:4856:648f with SMTP id ca18e2360f4ac-8379486f03amr94462639f.13.1728621779769;
        Thu, 10 Oct 2024 21:42:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728621779; cv=none;
        d=google.com; s=arc-20240605;
        b=ItBz7/9/qciOlYDb838263Pqeg/quijmhfz7KEs3smcdAcmqqc2y/jAk78cirHB0CF
         g7C8nuw/vwo7RroY5cytCeCOdn71EErVU6ypQoMPhNAqPTTuPsOMLtqbNGVET/2CeBd3
         Uu3qGn3y9yx3EaDWi09SfMgfb37YIquxsawiJiBiDjvGH7LEHnISnIod+jk34Hy93fBX
         QxCKZJLws/oGmeczOffeEW/0fMS4lMTfhMuYW1XnWbJIrNZGDq9YnwVivYDcYyz9Cf/H
         duW2iJC4p7gOaRxEyHwVMI8eCrqOKbaVTOOb8ZCtTbk31AL6Y+gEqXEwQZy7j74D/4Xj
         bCtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pSGjEa/8+kzNE1XGfnMWU84Zh4u5d+Xz9yVI1Lg20Jo=;
        fh=q7ovFHT2eZDZteJAozpv+P0krjJ4lMvqAiOcc6vWXws=;
        b=MTvcNPLNYsIvfKfOPMMh7myLVnlNfLU62Q0TIi2iuEJbnOA/y5/VSjq5LZ7fBObHnt
         3CEvlc9RTn/PD7d+7EhRNLHiAIHrNvN8jKhxrlw7Ju51fVwvtWuNarIpn21ZEGoN/Ex4
         I8f9l0pJP5xjIcb21WvDuTPZ6NmJTWNV9sRS4bGKOei2pxzRbaZyHTByCFbiYN1pIIVe
         MTE4dw5l0uM5awSfzrMiYhVeGlywpFooBfKBvEtGbDw3b+G5GuUcS1ANl1/ixF2fNJEN
         A1N+oWNGo7qGH9K1lmTVuI5A6o7v7v/qW8+wGHYAFg0IMvZAXZUPudCMdSSkTtiixKlF
         tigw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KRoDA2QS;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8354ba63012si12389339f.3.2024.10.10.21.42.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 10 Oct 2024 21:42:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: mKpXPIRZTLiBPylvfWxuHg==
X-CSE-MsgGUID: U1hoMkovQi6WPmowvFAQeg==
X-IronPort-AV: E=McAfee;i="6700,10204,11221"; a="27959189"
X-IronPort-AV: E=Sophos;i="6.11,194,1725346800"; 
   d="scan'208";a="27959189"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2024 21:42:58 -0700
X-CSE-ConnectionGUID: KJglW9e3T0WVrSBrbjM5uw==
X-CSE-MsgGUID: uCRysRmrTnaJG5jbWpYrcg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,194,1725346800"; 
   d="scan'208";a="76712342"
Received: from lkp-server01.sh.intel.com (HELO a48cf1aa22e8) ([10.239.97.150])
  by orviesa010.jf.intel.com with ESMTP; 10 Oct 2024 21:42:56 -0700
Received: from kbuild by a48cf1aa22e8 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sz7UL-000Bob-0F;
	Fri, 11 Oct 2024 04:42:53 +0000
Date: Fri, 11 Oct 2024 12:42:34 +0800
From: kernel test robot <lkp@intel.com>
To: Bibo Mao <maobibo@loongson.cn>, Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is
 created
Message-ID: <202410111213.dfJ08626-lkp@intel.com>
References: <20241010035048.3422527-3-maobibo@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241010035048.3422527-3-maobibo@loongson.cn>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KRoDA2QS;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.21 as permitted
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

Hi Bibo,

kernel test robot noticed the following build warnings:

[auto build test WARNING on 87d6aab2389e5ce0197d8257d5f8ee965a67c4cd]

url:    https://github.com/intel-lab-lkp/linux/commits/Bibo-Mao/LoongArch-Set-pte-entry-with-PAGE_GLOBAL-for-kernel-space/20241010-115120
base:   87d6aab2389e5ce0197d8257d5f8ee965a67c4cd
patch link:    https://lore.kernel.org/r/20241010035048.3422527-3-maobibo%40loongson.cn
patch subject: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is created
config: x86_64-defconfig (https://download.01.org/0day-ci/archive/20241011/202410111213.dfJ08626-lkp@intel.com/config)
compiler: gcc-11 (Debian 11.3.0-12) 11.3.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20241011/202410111213.dfJ08626-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202410111213.dfJ08626-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/sparse-vmemmap.c:187:23: warning: no previous prototype for 'kernel_pte_init' [-Wmissing-prototypes]
     187 | void __weak __meminit kernel_pte_init(void *addr)
         |                       ^~~~~~~~~~~~~~~


vim +/kernel_pte_init +187 mm/sparse-vmemmap.c

   186	
 > 187	void __weak __meminit kernel_pte_init(void *addr)
   188	{
   189	}
   190	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410111213.dfJ08626-lkp%40intel.com.

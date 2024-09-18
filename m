Return-Path: <kasan-dev+bncBC4LXIPCY4NRBQGKVS3QMGQE2R5E7OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E822397C04A
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 21:08:49 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6c368bbf8fasf1527576d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 12:08:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726686529; cv=pass;
        d=google.com; s=arc-20240605;
        b=PBoRgIQd2xe3r9ykLRFg6hTbHZ1pw3RGyKlyRe3+dC0wEazXR68sEM1bv4SNtn7RnW
         sHSvP3NyyHQ0Ca6fdDw7C7ZxKCFERBTVht0jNkYtouqjyF04YG0QkvpX36Zo4vOJuSPv
         bX9KlFJGUkwpnSxzDqDCn3HGjxtqtD19VI7kr/AGQQLRD7Qz3Idr6Mqx6+z4FMSPbyl7
         +sjJZG27GzorrarTG/7V3aWJB30ZWJSNFQsFWvIoYNTPBOhhs6EH7daNOI5KhaAnc94a
         5YARKKIZjLUAXXNGRb8UqNMZ5FKyjnftFNe49CBOcnRFjn/q5pIo0WUKhrbW7ifp36FR
         cBgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BF1/Cf/bMmIubbIoPuRAJk7mdARBAzKwQaYbyK0fklk=;
        fh=l8rc0/WhZDPmwXOr3xDJZz1LVWokYOSO2CGljAbf6yM=;
        b=TVZWT4Vo8Uahfc6e44Q27w7d2MRJUN0ULxmVPFnoJQpvt5n/X28TsR6gSCpbKLu3e2
         iYctahjjW5IqrmQClIE3FGlfGIxT++I64JMLRzk/TiNoFET30Ir0XcSmum7POCefxUQl
         xAqGgRBYYCOx//i9EdZqUl1L3jtycJmeglxtMt1q1Dgirh8HCAwUc4OVh/91NqwQqoWj
         nsHFAHXbqUpOlSSZUyS7nzArElfpEZYQItRt9/yrnuvvloMrmVvx6912yuUSWVbK9M0Q
         qozpx4YweZts1gebWXcl2hR/vUHEEVOivbUryXNUheMq5wrphIxbcDZtvl8QDl+6ALfX
         8TKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PdAgvYU0;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726686528; x=1727291328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BF1/Cf/bMmIubbIoPuRAJk7mdARBAzKwQaYbyK0fklk=;
        b=TuoGDukyVeHcvMAr702vKunfSU6oXNG1MPM2ukygWy9mP9+5RzDWc0DU1bqrg4M9YC
         m/RohRjgccv4onzGG1KPI8p6Paytiru/Q2IiQyQZ27UvKRzvhgGdvcwscekfA7LMczFk
         l63zGVS3zg1gqaUPo5woqzbNiANgl+ZbbohysR7mCkeVCZ5G0+h20uzIH9Iovq+MeQLR
         JvdDzy6sdOVP73vxZPL5hlLyJZROw+VV9Pz1lKCM0Psap8K4WSlimHuffsghsJytqi6L
         ErFfwqGnetBr10IkQiK8F+Ty+e3gVZTHEIxOxOaFydxV5thbIS3MX1uOe8k3oJfObkUi
         6R1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726686529; x=1727291329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BF1/Cf/bMmIubbIoPuRAJk7mdARBAzKwQaYbyK0fklk=;
        b=jdWZBks8zT7Lz259cC5hIsE1CMPQAmprnlcr/46//3UDtOK8ymUu7wKJwWARMghCy1
         e0QIGaxlwpiH91Jg7R3s7ph8gdOgl9D6+nKCNGYyeJJNc5RhBPKpVkhPVfbWdWTI5O0i
         9lU9ofZD9eXHPXOA6Uq0riE3zxnnhzJq4jrsEmHZPkFU2v+Rhj0ajJilvKmw8gT0YMf8
         EnkJexLgrYkz63BF27Nniu25zy+6ZiC9wVKSJtn5km6bv5i2qQ6IM5iXeJzZjwaZboT5
         K0X4NUJiNueKLiNgqfTE+ETnok+yOYTQVjVolsUaqpXOsxD3CkvYPICEGgzLseE7dIUH
         ogWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVT+pN+Z6S71jPINUJAHMMX72ZSzCLvNYKqIeNB8ne4GB/FyCoETZPAnwy0KXEJs0azZm4bfg==@lfdr.de
X-Gm-Message-State: AOJu0YxjBbJy9W9Ews4rP1XTwLeizBjunM4qjAs8OWJijDhETYix9njC
	bjyqcJHd4xqZllKjv6bfQciyszPwCLnajoX8KlDczN4GlXL+sAtO
X-Google-Smtp-Source: AGHT+IH6v9tEc2RtH7Z1CJD2DNI5w6gFGXTlP3h1sNexrVWT29PYVFGU4sm3ih4vfIeYNTKkwfKu9g==
X-Received: by 2002:ad4:5ba9:0:b0:6b7:9a53:70e9 with SMTP id 6a1803df08f44-6c6823a985amr11874876d6.17.1726686528528;
        Wed, 18 Sep 2024 12:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c84:b0:6c5:1cfa:1e03 with SMTP id
 6a1803df08f44-6c6a76bc2cbls3505156d6.1.-pod-prod-00-us; Wed, 18 Sep 2024
 12:08:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4bsREGyWLQqob1JTfVjHTIeM+xavY5qh9QmtcuvgBa+D/aUIymjzTh8ahzsz7d4U/oHJAvQUNxzU=@googlegroups.com
X-Received: by 2002:a05:6214:2f0f:b0:6c3:6560:af09 with SMTP id 6a1803df08f44-6c66d3197b6mr13074586d6.0.1726686526926;
        Wed, 18 Sep 2024 12:08:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726686526; cv=none;
        d=google.com; s=arc-20240605;
        b=Yv5MdtalweIctyCXmcWn7J/X1rN2oHde936MXX9CS0AFnVaAs53nV9Z9k6iCbOsuj8
         lwS2ptFl7Hj1r/8u/cZGJoHrKB+AiGUb8UCfAM4QHy8dPQVah8FB7kDbf3/MXFxqHFSR
         2FJ0tl63V/gJgs2a/ElP0Zkc623rYV0UOL9dp7pDdLznx9Knvgh6YaDgtpXPFQen9+1d
         agr6NyU8FBIgOIQgjpj5BpiR5re7h52X7VrULCNx11wDUIGdYoUx8uKSDmtXY7wcxTNQ
         AE8QVztMcooQ0RExMGUWn44hVpFWo7NQZb89tMmqfZPdn7VRQAG7zz3yEDiDlsyjxi7A
         xMgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OcGfQAufu8vGmBinaJQDL2pcnedGYVmTbjlZ/+ZHvqY=;
        fh=Y1B9wSQI5U6WPQ65RLorXOmeDmdiD/GZGS/PcmMT8BM=;
        b=F8hLkt9OFRnCgB3hC9+w1YEi5EIHBsC3v6GjNg7xniUFOSGXFxWyHQCJNdvX7lanlr
         zNfrsBg4HO/ZnP9igsunHQ2Kkkkp4IfmkF9JLt7D/1y75rtJZ11MRW+tcLXN+SG4XBty
         J/n4VK7cNLAwOVSFhbhiNUJLbtB8OyY8lE0C75AuzGczTKmSM6ZTKI5rSBZoDyWlqhp3
         1jW54VGndp5/B1HG0wOYBr+aGpgvrCbAKccM4XTu3GrG6rAr8aSq6WebMg8OtwxQVuEH
         NodcJ7jfCbXwrudxovF/EfoXXbaBiAS/JKP5e/vNgJI/mVJZ43HTn2aS05aGJ8lvzzvx
         xXPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PdAgvYU0;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c75e585925si38926d6.6.2024.09.18.12.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 18 Sep 2024 12:08:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: HZWsgirMRe6YM3ZfVYU51w==
X-CSE-MsgGUID: 1RyhgX60Sn6fbaz/Wx8FBA==
X-IronPort-AV: E=McAfee;i="6700,10204,11199"; a="36194250"
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="36194250"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Sep 2024 12:08:44 -0700
X-CSE-ConnectionGUID: E2/7ThRkRaOBRTJVwSLyGw==
X-CSE-MsgGUID: OO27+qXXTP69v+TQeImesw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="92975592"
Received: from lkp-server01.sh.intel.com (HELO 53e96f405c61) ([10.239.97.150])
  by fmviesa002.fm.intel.com with ESMTP; 18 Sep 2024 12:08:39 -0700
Received: from kbuild by 53e96f405c61 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sr02W-000CXe-0w;
	Wed, 18 Sep 2024 19:08:36 +0000
Date: Thu, 19 Sep 2024 03:07:42 +0800
From: kernel test robot <lkp@intel.com>
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: oe-kbuild-all@lists.linux.dev,
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
Message-ID: <202409190244.JcrD4CwD-lkp@intel.com>
References: <20240917073117.1531207-5-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240917073117.1531207-5-anshuman.khandual@arm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=PdAgvYU0;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted
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
config: openrisc-allnoconfig (https://download.01.org/0day-ci/archive/20240919/202409190244.JcrD4CwD-lkp@intel.com/config)
compiler: or1k-linux-gcc (GCC) 14.1.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190244.JcrD4CwD-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202409190244.JcrD4CwD-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from include/asm-generic/bug.h:22,
                    from arch/openrisc/include/asm/bug.h:5,
                    from include/linux/bug.h:5,
                    from include/linux/mmdebug.h:5,
                    from include/linux/mm.h:6,
                    from include/linux/pagemap.h:8,
                    from mm/pgtable-generic.c:10:
   mm/pgtable-generic.c: In function 'pmd_clear_bad':
>> arch/openrisc/include/asm/pgtable.h:369:36: error: lvalue required as unary '&' operand
     369 |                __FILE__, __LINE__, &(e), pgd_val(e))
         |                                    ^
   include/linux/printk.h:437:33: note: in definition of macro 'printk_index_wrap'
     437 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
         |                                 ^~~~~~~~~~~
   arch/openrisc/include/asm/pgtable.h:368:9: note: in expansion of macro 'printk'
     368 |         printk(KERN_ERR "%s:%d: bad pgd %p(%08lx).\n", \
         |         ^~~~~~
   include/asm-generic/pgtable-nop4d.h:25:50: note: in expansion of macro 'pgd_ERROR'
      25 | #define p4d_ERROR(p4d)                          (pgd_ERROR((p4d).pgd))
         |                                                  ^~~~~~~~~
   include/asm-generic/pgtable-nopud.h:32:50: note: in expansion of macro 'p4d_ERROR'
      32 | #define pud_ERROR(pud)                          (p4d_ERROR((pud).p4d))
         |                                                  ^~~~~~~~~
   include/asm-generic/pgtable-nopmd.h:36:50: note: in expansion of macro 'pud_ERROR'
      36 | #define pmd_ERROR(pmd)                          (pud_ERROR((pmd).pud))
         |                                                  ^~~~~~~~~
   mm/pgtable-generic.c:54:9: note: in expansion of macro 'pmd_ERROR'
      54 |         pmd_ERROR(pmdp_get(pmd));
         |         ^~~~~~~~~


vim +369 arch/openrisc/include/asm/pgtable.h

61e85e367535a7 Jonas Bonn 2011-06-04  363  
61e85e367535a7 Jonas Bonn 2011-06-04  364  #define pte_ERROR(e) \
61e85e367535a7 Jonas Bonn 2011-06-04  365  	printk(KERN_ERR "%s:%d: bad pte %p(%08lx).\n", \
61e85e367535a7 Jonas Bonn 2011-06-04  366  	       __FILE__, __LINE__, &(e), pte_val(e))
61e85e367535a7 Jonas Bonn 2011-06-04  367  #define pgd_ERROR(e) \
61e85e367535a7 Jonas Bonn 2011-06-04  368  	printk(KERN_ERR "%s:%d: bad pgd %p(%08lx).\n", \
61e85e367535a7 Jonas Bonn 2011-06-04 @369  	       __FILE__, __LINE__, &(e), pgd_val(e))
61e85e367535a7 Jonas Bonn 2011-06-04  370  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409190244.JcrD4CwD-lkp%40intel.com.

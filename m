Return-Path: <kasan-dev+bncBC4LXIPCY4NRBAXYWCIAMGQE2M5JN4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D76D24B7B5C
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 00:49:22 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id y10-20020a056402358a00b00410deddea4csf382838edc.16
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 15:49:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644968962; cv=pass;
        d=google.com; s=arc-20160816;
        b=fV2lzFzk+cInCIWfaTl+2TZEjNc2ZOaKIRjoA7048llyvvT9uPx1B0xk2OhLQPvf74
         ZyI7c+NF9RamL3nGnMzwV8uUuSH9of5Gyg8ShRp34J7KkKIi38QEml+ArBhRmifTZM0G
         HHO9ge+/UXnhk2OF9vlyrfwrHInN7hfbpBYEtPzTmSUvAV/QbYlyjDz2HeKQzIkfFuJn
         zViLzowInGiS8CkySYHmgyNl0Zv3wr3c6T+Nme0QJdIJ3u2qhRx19IBWFpvbB+gMCdyE
         6XRwQmApCcGR4OAyx0nCg91bEPSDmyuxt5+oKQ3BgckjbZTzLmlf2+x6mjZylvRm8Ub8
         fz7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=slplFmsDWhZP8q7ioUxnEDINWEguWXnAyjkSin4yum4=;
        b=LDYXuN2cMmuN8A5OVAZXthE4hs/YiKCYknCmdBGQI/tV/EKo7iQME99HfCTvSn7MJI
         lXAAMOjW8yyd2QeIwELXHg94pbFlnYpbiZYDQ3GElomSt8QaLG2t1tE1rxLE6iUYu9fO
         urAfmH2f0no1BEj1HVLBN8vKzc9Bjoz0/O+ydI6b2Gk/XPAcqsdfKqBX35+SN0Pt+ZYy
         UhzHN0iosDEksc4KCcw7mUTe0C3xoVC67FXFni04bqp9WXYztNV3d6hxygJO8h3zqhXP
         JJ8usHm8v/ZJctHNnLgsCbHzRYGZsXPz/HEvtqU9vv9/HUKBnrfqqJMD/jzGGP6eCbyt
         Lupg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="PRRPLg/6";
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=slplFmsDWhZP8q7ioUxnEDINWEguWXnAyjkSin4yum4=;
        b=FvyV9BkcxNRS7tbxz6WSrfy0p53f9jI4L06i1BGQl39j1fZsYuOFU1N2I4viMfF3MH
         WTaz8lJm8m6fxrFUURFAfeBH8+iCbiouzmweUMi0UT8Wt/XuWyak3HdilZAI5k8QOakV
         SHJ7GKT3/RY8rblRt0vZPian+kMPr3dcb9yimuKh5oXch+GjVd9grZHddfqW1q/wHegR
         jktP1asJwfMuMIAPXbnjzjl9Hf3foKNkwvXRqi3pNh0WEdg5y/OkMYckBChDHc5gQN3x
         U8accCN8CqMC7yf1ZSVps5irjVsoJliDPMiQELBCeUcx6fr5rzwlk/r4nFb5PEBgyyF1
         j0FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=slplFmsDWhZP8q7ioUxnEDINWEguWXnAyjkSin4yum4=;
        b=4JTvgOn8eQh8Nf2SwWPjM8iTqNX50aUkdcZUpTjhVCmbWT0f+UOUQ1FxFg8Z3HA3VS
         B3QTEA/h+KFKvcKhhnmhbWXkQrvq+HYqT5ssh2OTBD7JE0xhm66iheSY4o6pp1eDjSjy
         CGZyVbTgQ8EU8xSTDO56LY20mobRQkJqHFq/MfMyOprkrgYqYmq74gvtwYZTJMnD4VpI
         EZfIUV+HGra23Xvswh231Kp6fI1m214AKGZG4xzLXqsz1W8VZzGmwceS7fjnSYq8Jh3D
         kYQR419b+pIB17iDgL6XYvLeqxEM0pEP8PnVsQC/Bqb4Oh4SHLmMD8Y93aLtOIMHJugd
         oCoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IDyBq2H3PV40NSNJONDp7yc1fE1p6cIxP9JRQ26JLWG5LjrAx
	WhFXIBcvPR9nw2HLkbTdNeU=
X-Google-Smtp-Source: ABdhPJxEf41JlKvLginlgqB01MDvrvejFFslooa+b3d6OK0Vvl5VPrY+gm0Cd7CfHwJ8gy8gSmzrIw==
X-Received: by 2002:a50:b402:0:b0:410:836e:92f3 with SMTP id b2-20020a50b402000000b00410836e92f3mr252721edh.29.1644968962493;
        Tue, 15 Feb 2022 15:49:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c01:: with SMTP id s1ls509611ejf.2.gmail; Tue, 15
 Feb 2022 15:49:21 -0800 (PST)
X-Received: by 2002:a17:907:234c:b0:6cd:7ca0:8423 with SMTP id we12-20020a170907234c00b006cd7ca08423mr334261ejb.218.1644968961535;
        Tue, 15 Feb 2022 15:49:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644968961; cv=none;
        d=google.com; s=arc-20160816;
        b=y9uONAn5pym4eUsp/oydRKMxn3QWTAshGNIqeyrtU6hZtq8ipZBGJry8QS/efDKk0p
         nvVW1gHdVFy+5z04i0G1Z3JxdBvo3tjtHO0Cgl5P1GHIPJjftH12gF/YB1Ny26luaIlR
         OGsW3ETGgu/8WUI6e2/b7FE3+quclmJeheQotWihsv6QtVDBeqL9mii+8Wm92Ok2B9Gk
         CwY9TpEZbubMqAkI6xj9wJCHap+Liao/MO4J0MjZXjGFbv79nTJeERKX+A0UeusjYnut
         aenI2Fp4OV/k5g09dPs31FqQiYP0ZHBuUqBlS6Qht0aWIEM5dT5K64AGw0UJ8BfrZWS7
         Rq/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tt7nKxrh9jEpdHrHwsLGJO6mupbmUSsDCChB2h1NPXI=;
        b=pdkiKVNOg/3D7OvVDkrEbW0K5QV+oO7jfNPs8nvxmkY+Iv4FQqZAF+GzhMNTG+/0ev
         hHP60QTzLHA3rDx35PCw3xr93wO9W51RbCqG7Hx+LgCQ+LCpxDgpkqoLdCeBu68M69IC
         9xe1+uPn2yFTO/ssuWMfD3AIFS7HbCbu9TJ7dWmRikhnDxjr8zEE7kp6eTBYCbM50s4V
         wIpM7lBWpBHUq7wChz6KyBIwTNLQePLSCPUnjjZqpeOeWSP7N4ifFiS8URJ+K1JnCbMm
         tPxOBx5iwEo1tyLMrSdg8NIjhmEU+gy5UsA6JeumDF1K3GixhTIpJxq5zxysheUIVgFv
         4UQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="PRRPLg/6";
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id s15si1652633eji.1.2022.02.15.15.49.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Feb 2022 15:49:21 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6200,9189,10259"; a="249316493"
X-IronPort-AV: E=Sophos;i="5.88,371,1635231600"; 
   d="scan'208";a="249316493"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Feb 2022 15:49:19 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,371,1635231600"; 
   d="scan'208";a="588014904"
Received: from lkp-server01.sh.intel.com (HELO d95dc2dabeb1) ([10.239.97.150])
  by fmsmga008.fm.intel.com with ESMTP; 15 Feb 2022 15:49:15 -0800
Received: from kbuild by d95dc2dabeb1 with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nK7ZK-000A9l-SR; Tue, 15 Feb 2022 23:49:14 +0000
Date: Wed, 16 Feb 2022 07:48:58 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: test: support async (again) and asymm modes for
 HW_TAGS
Message-ID: <202202160721.IhkGJaXa-lkp@intel.com>
References: <51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="PRRPLg/6";       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted
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

Hi,

I love your patch! Yet something to improve:

[auto build test ERROR on linus/master]
[also build test ERROR on v5.17-rc4 next-20220215]
[cannot apply to hnaz-mm/master]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/0day-ci/linux/commits/andrey-konovalov-linux-dev/kasan-test-support-async-again-and-asymm-modes-for-HW_TAGS/20220215-232923
base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git d567f5db412ed52de0b3b3efca4a451263de6108
config: arm-allmodconfig (https://download.01.org/0day-ci/archive/20220216/202202160721.IhkGJaXa-lkp@intel.com/config)
compiler: arm-linux-gnueabi-gcc (GCC) 11.2.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/0day-ci/linux/commit/50334edb33a25643468715fbfc0e6d4a7d594432
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-test-support-async-again-and-asymm-modes-for-HW_TAGS/20220215-232923
        git checkout 50334edb33a25643468715fbfc0e6d4a7d594432
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.2.0 make.cross O=build_dir ARCH=arm SHELL=/bin/bash lib// mm/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from <command-line>:
   mm/kasan/report.c: In function 'kasan_update_kunit_status':
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
   In file included from ./arch/arm/include/generated/asm/rwonce.h:1,
                    from include/linux/compiler.h:255,
                    from include/linux/build_bug.h:5,
                    from include/linux/bits.h:22,
                    from include/linux/bitops.h:6,
                    from mm/kasan/report.c:12:
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/asm-generic/rwonce.h:55:27: note: in definition of macro '__WRITE_ONCE'
      55 |         *(volatile typeof(x) *)&(x) = (val);                            \
         |                           ^
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
>> mm/kasan/report.c:360:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     360 |         WRITE_ONCE(status->report_found, true);
         |                          ^~
   include/asm-generic/rwonce.h:55:34: note: in definition of macro '__WRITE_ONCE'
      55 |         *(volatile typeof(x) *)&(x) = (val);                            \
         |                                  ^
   mm/kasan/report.c:360:9: note: in expansion of macro 'WRITE_ONCE'
     360 |         WRITE_ONCE(status->report_found, true);
         |         ^~~~~~~~~~
   In file included from <command-line>:
   mm/kasan/report.c:361:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:361:9: note: in expansion of macro 'WRITE_ONCE'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |         ^~~~~~~~~~
   mm/kasan/report.c:361:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:361:9: note: in expansion of macro 'WRITE_ONCE'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |         ^~~~~~~~~~
   mm/kasan/report.c:361:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:361:9: note: in expansion of macro 'WRITE_ONCE'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |         ^~~~~~~~~~
   mm/kasan/report.c:361:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:60:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      60 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   mm/kasan/report.c:361:9: note: in expansion of macro 'WRITE_ONCE'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |         ^~~~~~~~~~
   mm/kasan/report.c:361:26: error: invalid use of undefined type 'struct kunit_kasan_status'
     361 |         WRITE_ONCE(status->sync_fault, sync);
         |                          ^~
   include/linux/compiler_types.h:326:23: note: in definition of macro '__compiletime_assert'
     326 |                 if (!(condition))                                       \
         |                       ^~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
--
   lib/test_kasan.c: In function 'kasan_test_init':
>> lib/test_kasan.c:56:20: error: invalid use of undefined type 'struct kunit_kasan_status'
      56 |         test_status.report_found = false;
         |                    ^
   lib/test_kasan.c:57:20: error: invalid use of undefined type 'struct kunit_kasan_status'
      57 |         test_status.sync_fault = false;
         |                    ^
   In file included from lib/test_kasan.c:25:
   lib/test_kasan.c: In function 'kasan_test_exit':
   lib/test_kasan.c:66:45: error: invalid use of undefined type 'struct kunit_kasan_status'
      66 |         KUNIT_EXPECT_FALSE(test, test_status.report_found);
         |                                             ^
   include/kunit/test.h:782:28: note: in definition of macro 'KUNIT_ASSERTION'
     782 |                            pass,                                               \
         |                            ^~~~
   include/kunit/test.h:841:9: note: in expansion of macro 'KUNIT_UNARY_ASSERTION'
     841 |         KUNIT_UNARY_ASSERTION(test,                                            \
         |         ^~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:849:9: note: in expansion of macro 'KUNIT_FALSE_MSG_ASSERTION'
     849 |         KUNIT_FALSE_MSG_ASSERTION(test, assert_type, condition, NULL)
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:1341:9: note: in expansion of macro 'KUNIT_FALSE_ASSERTION'
    1341 |         KUNIT_FALSE_ASSERTION(test, KUNIT_EXPECTATION, condition)
         |         ^~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:66:9: note: in expansion of macro 'KUNIT_EXPECT_FALSE'
      66 |         KUNIT_EXPECT_FALSE(test, test_status.report_found);
         |         ^~~~~~~~~~~~~~~~~~
   lib/test_kasan.c: In function 'kmalloc_oob_right':
   lib/test_kasan.c:94:55: error: invalid use of undefined type 'struct kunit_kasan_status'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
         |                                                       ^
   include/kunit/test.h:782:28: note: in definition of macro 'KUNIT_ASSERTION'
     782 |                            pass,                                               \
         |                            ^~~~
   include/kunit/test.h:841:9: note: in expansion of macro 'KUNIT_UNARY_ASSERTION'
     841 |         KUNIT_UNARY_ASSERTION(test,                                            \
         |         ^~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:849:9: note: in expansion of macro 'KUNIT_FALSE_MSG_ASSERTION'
     849 |         KUNIT_FALSE_MSG_ASSERTION(test, assert_type, condition, NULL)
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:1341:9: note: in expansion of macro 'KUNIT_FALSE_ASSERTION'
    1341 |         KUNIT_FALSE_ASSERTION(test, KUNIT_EXPECTATION, condition)
         |         ^~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:94:9: note: in expansion of macro 'KUNIT_EXPECT_FALSE'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
         |         ^~~~~~~~~~~~~~~~~~
   include/linux/compiler_types.h:334:9: note: in expansion of macro '__compiletime_assert'
     334 |         __compiletime_assert(condition, msg, prefix, suffix)
         |         ^~~~~~~~~~~~~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:49:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      49 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:94:34: note: in expansion of macro 'READ_ONCE'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
         |                                  ^~~~~~~~~
   lib/test_kasan.c:138:17: note: in expansion of macro 'KUNIT_EXPECT_KASAN_FAIL'
     138 |                 KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
         |                 ^~~~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:94:55: error: invalid use of undefined type 'struct kunit_kasan_status'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
         |                                                       ^
   include/kunit/test.h:782:28: note: in definition of macro 'KUNIT_ASSERTION'
     782 |                            pass,                                               \
         |                            ^~~~
   include/kunit/test.h:841:9: note: in expansion of macro 'KUNIT_UNARY_ASSERTION'
     841 |         KUNIT_UNARY_ASSERTION(test,                                            \
         |         ^~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:849:9: note: in expansion of macro 'KUNIT_FALSE_MSG_ASSERTION'
     849 |         KUNIT_FALSE_MSG_ASSERTION(test, assert_type, condition, NULL)
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~
   include/kunit/test.h:1341:9: note: in expansion of macro 'KUNIT_FALSE_ASSERTION'
    1341 |         KUNIT_FALSE_ASSERTION(test, KUNIT_EXPECTATION, condition)
         |         ^~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:94:9: note: in expansion of macro 'KUNIT_EXPECT_FALSE'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
         |         ^~~~~~~~~~~~~~~~~~
   include/linux/compiler_types.h:334:9: note: in expansion of macro '__compiletime_assert'
     334 |         __compiletime_assert(condition, msg, prefix, suffix)
         |         ^~~~~~~~~~~~~~~~~~~~
   include/linux/compiler_types.h:346:9: note: in expansion of macro '_compiletime_assert'
     346 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:9: note: in expansion of macro 'compiletime_assert'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |         ^~~~~~~~~~~~~~~~~~
   include/asm-generic/rwonce.h:36:28: note: in expansion of macro '__native_word'
      36 |         compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
         |                            ^~~~~~~~~~~~~
   include/asm-generic/rwonce.h:49:9: note: in expansion of macro 'compiletime_assert_rwonce_type'
      49 |         compiletime_assert_rwonce_type(x);                              \
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   lib/test_kasan.c:94:34: note: in expansion of macro 'READ_ONCE'
      94 |         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \


vim +360 mm/kasan/report.c

   345	
   346	#if IS_ENABLED(CONFIG_KUNIT)
   347	static void kasan_update_kunit_status(struct kunit *cur_test, bool sync)
   348	{
   349		struct kunit_resource *resource;
   350		struct kunit_kasan_status *status;
   351	
   352		resource = kunit_find_named_resource(cur_test, "kasan_status");
   353	
   354		if (!resource) {
   355			kunit_set_failure(cur_test);
   356			return;
   357		}
   358	
   359		status = (struct kunit_kasan_status *)resource->data;
 > 360		WRITE_ONCE(status->report_found, true);
   361		WRITE_ONCE(status->sync_fault, sync);
   362		kunit_put_resource(resource);
   363	}
   364	#endif /* IS_ENABLED(CONFIG_KUNIT) */
   365	

---
0-DAY CI Kernel Test Service, Intel Corporation
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202160721.IhkGJaXa-lkp%40intel.com.

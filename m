Return-Path: <kasan-dev+bncBC4LXIPCY4NRB3F4T7CAMGQE4ZKZJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF262B1431F
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 22:32:45 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-558fa7eef58sf2758821e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:32:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753734765; cv=pass;
        d=google.com; s=arc-20240605;
        b=EOfRvYSYOTSriYz5xEttCVhXzwHUbGxqWi/uqT9EjDc+/N5+DQaScJkXezA6wN/Zod
         bIKdE9Y+ZXhqiNsTY3e06442qSG3EqzBlv5lWRobSMwWt5rHS3BquXxR60a1pYqijpC2
         7OInKdEtvR+dSGvxcaKxGqlFbSEd3AlRy25S2IGRaDPkI72q4Y30nZsDclmgdOb6Mhw9
         avA4LLT8hbTi8t+TEgZZOVPf4yy+zjFdotVXCRbUiwnJFur68W0bKmbeBs4pKKAZZUsn
         /i0wh8DyCzfucf+nGa/cseOI/mNK4bwyBmL+eYo7OBRRroz3UO6xqQbIBmN4xLP+X9vo
         LI0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LYlv4cT433+QIiAPyTJ2XJQnJQm/KGEJc3Md3yN/ca0=;
        fh=XzT/SidK7IUMSNlTmcv6SK7tud5YTQFq+BUPQ7o+kYg=;
        b=QlEWH5M2ExFMSsN47tBEpX4S1ev0Psxb1G3mHApiQiT8/IGmIMx4Q3evmQMuduZII3
         6Sx6qxqTR2AtoRtGA5XNKBI20wmoCtICMiboWJ8QTWFWv5F193FUIacLecdQyCpYkFmH
         lVvBbmEl0qadEKlbTZYo+Li3GderB5Sk0RTW1j12zfvjQ0712svXj1UT8X7E7OYLksaT
         jKFH9c4ozkE0bw80pjCprsctcVwr26X5d+c/Yjujo4mfVrF0XR44Tbhg4KGRqcGE0rsu
         VZQF5km3Ie09UQhaEvMiRIiCHAH8rWlKS4P7KRaitTFrvFjtdZV4gGW0QgDb+Gnmigna
         XJoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="hH/jOmPX";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753734765; x=1754339565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LYlv4cT433+QIiAPyTJ2XJQnJQm/KGEJc3Md3yN/ca0=;
        b=KUysNeunPINpKEeLdOiEpcxVzRNQaMiR/lJYakKhFhFr1/Ufk9IBwWbE4ny75uvCpy
         anVPVvqHpU/VPo+ppw+fp/SFWKanMkDpNL24z96Wu4jYd6o5Wxs64zFqDJ4pPJlQGRLp
         iTXTnPQ1lky9RDGi5T6oeHGD5OuOnCkuP5X2slJlRYGruRALpmspczxG2+QRqfjjDVgx
         jzRO69Y2Jz5HDmy9Zwbfw0bfG/rc1cc3haZKoTPrH19mr1h+kund79e3bDJ6FCr2l1Uf
         nmgvVWjGJ+5UyYVmVrR6XEfTPC5Jc/6CHrtnbPz3JgtwITtgKQTxOs7nO4zTuiOkvdOQ
         SkXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753734765; x=1754339565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LYlv4cT433+QIiAPyTJ2XJQnJQm/KGEJc3Md3yN/ca0=;
        b=eiYpae/9CGbEDMCz6rJ+NyTgkkLZPRXJZrOAGb/wZbFjaBjrQk2ilGPBrKeJptUXBK
         DUkGiU8mtYjol6zMWZ5tGDhuWPnlm2Pc/Lm45c6f5BM+i+E7s3aCP30kR50nWQPH29dY
         G/UZnmGMv8finiIlN0zn9kCHCyWvUlYdkkFuOhzPsCQjyTSQihv0oBAKcHkJ6jqrYhTI
         dc/NChsl5PE+EjRTP9VD0CaREaL30bPp1tzOmIwx+Fnm28kMMDf8ayBGz3SpMyIIjJoe
         faEo0sTjCO7goCTh5UTGmWvrYg0ptzzv4xumFKygUhwtOKEWpo1ocZqV62fu1GSKNCE7
         GcFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUG+0Vhbw1OE6OyY6kjBhrqPPnLXs6uyXwSByUc8npZDZ1M1AueEYyN0BuTn+SeFwQG1hHPHQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzkhh6mvIA5cjvLprp+KA1WKIsz1Tp5yp2RKyS2NWK+PBhKwMKr
	4krjM5wB0+o6FVRPW668B3gk1YYM/3AkaD5kYrLIo/tnrmm8TXkylAAY
X-Google-Smtp-Source: AGHT+IGmhQRJ6iTyX37AqMm8SSWWk+d4nR9r6zkrE3Q5sVTA47gGi2DubxzvLsY3ghGnCftu6SmmdA==
X-Received: by 2002:ac2:4f03:0:b0:553:3028:75bd with SMTP id 2adb3069b0e04-55b5f4c4d81mr3652419e87.49.1753734764724;
        Mon, 28 Jul 2025 13:32:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfxeEMVaHQI+/ghkqZZwED0EEuMBZ73Y3GrdrniW8JSUA==
Received: by 2002:a19:2d01:0:b0:55b:74e3:1cd3 with SMTP id 2adb3069b0e04-55b74e32388ls28504e87.0.-pod-prod-07-eu;
 Mon, 28 Jul 2025 13:32:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNDn2hq4OxAuQAGBT2xv9i/qyWHRj/Guy+RTN9kTAXi7rSRooMlq8h+Y+LXKTUT/S6GVm646P6bb8=@googlegroups.com
X-Received: by 2002:a05:6512:3e0a:b0:553:cf7d:72a0 with SMTP id 2adb3069b0e04-55b5f3db5f9mr3161564e87.5.1753734761626;
        Mon, 28 Jul 2025 13:32:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753734761; cv=none;
        d=google.com; s=arc-20240605;
        b=bQtdAZYIeGZSB56hzxjsvPux3OyXq/yIZo25dYeNbEYi4x22x5wKhAWGa8El5gjdQ9
         MyiCu+q3qF4dfsxWtQT66JUjJ4avTQ7HwY0M0h7Yjq5jPXAYubuEXvc/vBVaTvZAKaoj
         tTBXNcAfBkQij1CSB3H3FuT/ascLZLgibF1UI/f2cC5XuU7qSlXQ/Hy0njA3nM9uGgKV
         MrjWSnO5n0kl5RNH0LYhcvx/s/sG6JqY8oGNKdACh5NZeLKDX6CAfwtyanofnHGLDIN7
         XQvUJezlD3qygencpMCuYCZt3KiSQFs1pGEw3cun+hwVRSR1MvrSSA0ddi0O+cPaMdNL
         mpBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bl9P7qTHPw56Q+lzK9fEyQqRy5FZCXQRQJSpQh4aAgM=;
        fh=++CctvY9Az6vAmU7ll8eijH7dmu13rfHxEObLf/3+3M=;
        b=URFqLozo9K2kcDp3d7H/+s8PSVtdv7pxOFcEWVEFzg2xKZQ5N+VfN+l/IWm69z1RjJ
         BrvXLJTF+OBsZ4bjj7qQEosVNd/kexu0mFPbvdYJbWVfxtRHpO+51OtC3Qy8iQXlNlxc
         1TCgM4XO8zRurF0BOg+mveMjUkd8Nl0bp0Gm0eUWlxTGYO67XINRMDQJc6bHY8es1EmO
         Hc7GXS7kw6nozwYd4idmg9zmJzRsqboj38drtJc7MYsWozbjwY89CmiqGarFHtjOwuCx
         kJhIk5XZbdAVtnv9JYGjxlgYmgLBpPVmdgGaz4aQmi6GkYwN8fgWjc1BVgHrmcqh84e7
         wh8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="hH/jOmPX";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b631f9103si217736e87.4.2025.07.28.13.32.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 28 Jul 2025 13:32:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: Zk+MDSiDQJObAKhhYtCt2g==
X-CSE-MsgGUID: f59Ng7JXT/6qTHMQ5Cdo8A==
X-IronPort-AV: E=McAfee;i="6800,10657,11505"; a="59641836"
X-IronPort-AV: E=Sophos;i="6.16,339,1744095600"; 
   d="scan'208";a="59641836"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Jul 2025 13:32:40 -0700
X-CSE-ConnectionGUID: 2wrIv/C9QFOOd4BCJV51UA==
X-CSE-MsgGUID: ied5mmcvQVqXnE540yZa8Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,339,1744095600"; 
   d="scan'208";a="162221192"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by orviesa009.jf.intel.com with ESMTP; 28 Jul 2025 13:32:36 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1ugUWQ-0000kB-1E;
	Mon, 28 Jul 2025 20:32:34 +0000
Date: Tue, 29 Jul 2025 04:31:52 +0800
From: kernel test robot <lkp@intel.com>
To: Dishank Jogi <jogidishank503@gmail.com>, elver@google.com
Cc: oe-kbuild-all@lists.linux.dev, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	rathod.darshan.0896@gmail.com,
	Dishank Jogi <jogidishank503@gmail.com>
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in
 atomic ops.
Message-ID: <202507290412.DayPyZpH-lkp@intel.com>
References: <20250728104327.48469-1-jogidishank503@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250728104327.48469-1-jogidishank503@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="hH/jOmPX";       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.15 as permitted
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

Hi Dishank,

kernel test robot noticed the following build warnings:

[auto build test WARNING on linus/master]
[also build test WARNING on v6.16 next-20250728]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Dishank-Jogi/kcsan-clean-up-redundant-empty-macro-arguments-in-atomic-ops/20250728-184659
base:   linus/master
patch link:    https://lore.kernel.org/r/20250728104327.48469-1-jogidishank503%40gmail.com
patch subject: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
config: x86_64-buildonly-randconfig-002-20250729 (https://download.01.org/0day-ci/archive/20250729/202507290412.DayPyZpH-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250729/202507290412.DayPyZpH-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507290412.DayPyZpH-lkp@intel.com/

All warnings (new ones prefixed by >>):

   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
>> kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
>> kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
>> kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
>> kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);


vim +1260 kernel/kcsan/core.c

  1169	
  1170	#define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
  1171		u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
  1172		u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
  1173		{                                                                                          \
  1174			kcsan_atomic_builtin_memorder(memorder);                                           \
  1175			if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
  1176				check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
  1177			}                                                                                  \
  1178			return __atomic_load_n(ptr, memorder);                                             \
  1179		}                                                                                          \
  1180		EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
  1181		void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
  1182		void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
  1183		{                                                                                          \
  1184			kcsan_atomic_builtin_memorder(memorder);                                           \
  1185			if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
  1186				check_access(ptr, bits / BITS_PER_BYTE,                                    \
  1187					     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
  1188			}                                                                                  \
  1189			__atomic_store_n(ptr, v, memorder);                                                \
  1190		}                                                                                          \
  1191		EXPORT_SYMBOL(__tsan_atomic##bits##_store)
  1192	
  1193	#define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
  1194		u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
  1195		u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
  1196		{                                                                                          \
  1197			kcsan_atomic_builtin_memorder(memorder);                                           \
  1198			if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
  1199				check_access(ptr, bits / BITS_PER_BYTE,                                    \
  1200					     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
  1201						     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
  1202			}                                                                                  \
  1203			return __atomic_##op##suffix(ptr, v, memorder);                                    \
  1204		}                                                                                          \
  1205		EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
  1206	
  1207	/*
  1208	 * Note: CAS operations are always classified as write, even in case they
  1209	 * fail. We cannot perform check_access() after a write, as it might lead to
  1210	 * false positives, in cases such as:
  1211	 *
  1212	 *	T0: __atomic_compare_exchange_n(&p->flag, &old, 1, ...)
  1213	 *
  1214	 *	T1: if (__atomic_load_n(&p->flag, ...)) {
  1215	 *		modify *p;
  1216	 *		p->flag = 0;
  1217	 *	    }
  1218	 *
  1219	 * The only downside is that, if there are 3 threads, with one CAS that
  1220	 * succeeds, another CAS that fails, and an unmarked racing operation, we may
  1221	 * point at the wrong CAS as the source of the race. However, if we assume that
  1222	 * all CAS can succeed in some other execution, the data race is still valid.
  1223	 */
  1224	#define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
  1225		int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
  1226								      u##bits val, int mo, int fail_mo);   \
  1227		int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
  1228								      u##bits val, int mo, int fail_mo)    \
  1229		{                                                                                          \
  1230			kcsan_atomic_builtin_memorder(mo);                                                 \
  1231			if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
  1232				check_access(ptr, bits / BITS_PER_BYTE,                                    \
  1233					     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
  1234						     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
  1235			}                                                                                  \
  1236			return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
  1237		}                                                                                          \
  1238		EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
  1239	
  1240	#define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
  1241		u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
  1242								   int mo, int fail_mo);                   \
  1243		u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
  1244								   int mo, int fail_mo)                    \
  1245		{                                                                                          \
  1246			kcsan_atomic_builtin_memorder(mo);                                                 \
  1247			if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
  1248				check_access(ptr, bits / BITS_PER_BYTE,                                    \
  1249					     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
  1250						     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
  1251			}                                                                                  \
  1252			__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
  1253			return exp;                                                                        \
  1254		}                                                                                          \
  1255		EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)
  1256	
  1257	#define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
  1258		DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
  1259		DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
> 1260		DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
  1261		DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
  1262		DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
  1263		DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
  1264		DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
  1265		DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
  1266		DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
  1267		DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
  1268		DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
  1269	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507290412.DayPyZpH-lkp%40intel.com.

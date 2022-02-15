Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKPAWCIAMGQEWKNBRZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CE7044B7ADB
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 23:58:50 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id h6-20020ac25966000000b00442b0158d70sf78639lfp.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 14:58:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644965930; cv=pass;
        d=google.com; s=arc-20160816;
        b=AmoaZMEUVPXRb3J/cn9/mKy08SuqE4+N+qmWa6IKFJe61b7kbpamYsq1OEhF/SKJcV
         FUekxSbWW5ToTEbEVxVVMf2z5dGIRk/sVR05VZroHkizjdLd9gEF1qF/zZHog90VAwIn
         ufjXYoPWj18c3KmbSWDZ2T3Ra/2jwtPOute44gAhkSDgVLoUPYpFzX1fVN5TQrDnJgiJ
         XJIpkT8L8gDJ5HYoud/JBBroKMdtY7xZHVgBedWFNZ4/32fjQdxGKEi9lOBmH4DIpZJD
         Zd16gg8yG2Fzl8LzgyRgT0N/RF8ANhAAl7ezDjB03o9GhtvEGtqbuYb7wrdD+vCkOaWR
         wZWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=SSvTYUQTXjavFbx6WQztiXdjDDCUk6y/pKb/HLd81Jk=;
        b=UhNssJ/JYw8ZPhwo4Hb9aJEA9VxylhHj6JCZPQB2u/unpyeJSE2IRtL9OmfKXa6/PW
         AdQsl78D/iPd0LA5YObFVLRaH1VuLEqbp7IyU42/tuEzdPHQlA4n6/NL11K2jH72lHYd
         Z6nDwZhd/uToHlQxSSP4Ua+cB+CSJRZZgTzUjCwfgbY9jim+UtXRpgeOO31tQHhjMtUF
         /49mB7+Fad3pvpPH9wD43refp9VOKVR6pfG6yF+fETubkX9ZTo8RYIKSRQYJZmC65mYe
         H3M2c2SUXemgU29MMfCMFwiqGv4l7Ux80aE6Bk5fra6usjIkDccg3xJavR71ZfWg7ugM
         FzYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=baqvXked;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SSvTYUQTXjavFbx6WQztiXdjDDCUk6y/pKb/HLd81Jk=;
        b=Kvq4KKZSeDChOZ/lllJ0cYF4EBfgaso26LqEHLfttXjiGCIEVD6JJ5divsx0maSJYt
         +PmQf0ccGmX6p5dE5cjzlWa+jOvJjrQpoazUkyenKi2/jMksJjTLfWgkY/JDA63PglEt
         O1458z5cnpAcOf5xRG5FuqSuhGNmcbTWisoHb0AM7n1gtGBLs0alMwPZbc8oxGYT3o/n
         iWo86dbNcWLZADHTJd+ucfqSKKlFDSfmtsKuLywcuhI7Kj/LL0AdjJYpqFqY8QfV163r
         slU5GfIIRMEdSWoqkGJxRowTJSPBsK2+AYIoh9RH0FUl06UIMK8TgC1xIdW8gmdzcOSs
         nt0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SSvTYUQTXjavFbx6WQztiXdjDDCUk6y/pKb/HLd81Jk=;
        b=ognpm+lcesmOjNAE5RU0fE2QP6kx00LmS54jTq2ARiCSWO0Hx7MQegWoLJw25tyLDu
         FMjBPwlC3iI83jp91JSRh/hTtuWORgb1AC+ilKDR34yKmgxG09v3Pup3q70rsQxLIhns
         KPjHP0WB1WcWRn9LBQ9ZcH6VuUivQlEAxtn93jKWuoCiP1MTBjeXg3a7au/souoa6H7I
         bnwz+UnxlsbSDRif8xXhr7LV2z+Kc1rzFnsoEZNbTE7+xFw0pZuyK7GkxM018CJYFXb8
         cUz5GigvbKcOO9BJncukIo/zm8T9HO4YxJ+lg0EBTpdLJTRbtVECPMf2p6YNTtTaLLtv
         Uk/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NlCL8A7xEjuhXGs9iGk7ddj87RAm0f4+dPUH2fxvMZjhxgmJ6
	kxYhtDnjRb1cM14TrfO3JjE=
X-Google-Smtp-Source: ABdhPJzQ+ui+iFldruA8FkOh1RS9h/i9NLoQ8dcEWcKckX4BlcupCb5kr+m2ipbsxqE1YxbL1u4p6Q==
X-Received: by 2002:a2e:aa18:0:b0:244:bb00:db39 with SMTP id bf24-20020a2eaa18000000b00244bb00db39mr3589ljb.341.1644965930129;
        Tue, 15 Feb 2022 14:58:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:43cc:: with SMTP id u12ls198197lfl.2.gmail; Tue, 15 Feb
 2022 14:58:49 -0800 (PST)
X-Received: by 2002:a05:6512:1028:: with SMTP id r8mr472138lfr.143.1644965929101;
        Tue, 15 Feb 2022 14:58:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644965929; cv=none;
        d=google.com; s=arc-20160816;
        b=pGKQrgp0th/0yS0sgeEtPMJ3U6mYjjZzMBTqn/S3xIzbOJxkOJ85o6BbOkZ5w9Wbzw
         L8dbBHGK1Lnotl756yNBHCsrUT0GxGlLXdGbskNPQayN7kK0kXUcQc9AY3OY5lweAzPb
         Z2aFLG3Ja/VqfVhzb442RWbBa21F53Q7k/a+8Va9Zais/ANPOhuC0wlTMmEBjthBxZBf
         7YvaQdQeDmu888xn12QoFRWw9fgYlvjI+GzVXqW4l6BVHvGGRxMmwLFZ3L5Kot5uNRwd
         6LFaKIwtwhOW1k5lZecaAC1cw3L3BMpowhoy3MyovtVBxW/9OmnxDyItwf2Bvgu/RBI7
         j3jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zm1YgvPDFhkhTgVNfD0a03KzIBP8CA/Y15THzRQcKZU=;
        b=sE3MG5Kj8YTXUzP6G5ldALCSEE83hTr8ljMzUrPKCQ9HDyr8dZqJvokfbsvrlHbrjB
         qDGw65XnfXfKwU3Y9WOyJ5R/bONmR9UH+Cbf4TE7SKXCatstPKds6H9DE9h6ydLO6r2w
         UNJLiwqDbMNF5SJH/nNxOUG6LNFxoyty5b8iB6ZDkTjEK5utek5rcBYD8tAWaUsjh4Ql
         x6rm4SyCmL1PZDKNvNOSGajzzJkdxVdfd42kBpyQ2HBm3xemJMnFzwxKQ1J7kU7LgWJ8
         YPNIsRkvbdrOznTbbIvcxukbB+B+AcpDoh5G6OYuLT6HP3eqvIaDfLJeIZSbB/v8fvSp
         j8lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=baqvXked;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id c24si234082lfc.0.2022.02.15.14.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Feb 2022 14:58:49 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6200,9189,10259"; a="275050979"
X-IronPort-AV: E=Sophos;i="5.88,371,1635231600"; 
   d="scan'208";a="275050979"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Feb 2022 14:58:46 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.88,371,1635231600"; 
   d="scan'208";a="636179010"
Received: from lkp-server01.sh.intel.com (HELO d95dc2dabeb1) ([10.239.97.150])
  by orsmga004.jf.intel.com with ESMTP; 15 Feb 2022 14:58:10 -0800
Received: from kbuild by d95dc2dabeb1 with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nK6lt-000A8D-Mp; Tue, 15 Feb 2022 22:58:09 +0000
Date: Wed, 16 Feb 2022 06:57:59 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
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
Message-ID: <202202160627.SICieucW-lkp@intel.com>
References: <51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=baqvXked;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted
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
config: arm64-randconfig-r036-20220214 (https://download.01.org/0day-ci/archive/20220216/202202160627.SICieucW-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 37f422f4ac31c8b8041c6b62065263314282dab6)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # install arm64 cross compiling tool for clang build
        # apt-get install binutils-aarch64-linux-gnu
        # https://github.com/0day-ci/linux/commit/50334edb33a25643468715fbfc0e6d4a7d594432
        git remote add linux-review https://github.com/0day-ci/linux
        git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-test-support-async-again-and-asymm-modes-for-HW_TAGS/20220215-232923
        git checkout 50334edb33a25643468715fbfc0e6d4a7d594432
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm64 SHELL=/bin/bash mm/kasan/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:313:10: note: expanded from macro '__native_word'
           (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
                   ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:313:39: note: expanded from macro '__native_word'
           (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
                                                ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:314:10: note: expanded from macro '__native_word'
            sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
                   ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:314:38: note: expanded from macro '__native_word'
            sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
                                               ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:48: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                                         ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:61:15: note: expanded from macro 'WRITE_ONCE'
           __WRITE_ONCE(x, val);                                           \
                        ^
   include/asm-generic/rwonce.h:55:20: note: expanded from macro '__WRITE_ONCE'
           *(volatile typeof(x) *)&(x) = (val);                            \
                             ^
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
>> mm/kasan/report.c:360:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->report_found, true);
                      ~~~~~~^
   include/asm-generic/rwonce.h:61:15: note: expanded from macro 'WRITE_ONCE'
           __WRITE_ONCE(x, val);                                           \
                        ^
   include/asm-generic/rwonce.h:55:27: note: expanded from macro '__WRITE_ONCE'
           *(volatile typeof(x) *)&(x) = (val);                            \
                                    ^
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
   mm/kasan/report.c:361:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->sync_fault, sync);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:313:10: note: expanded from macro '__native_word'
           (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
                   ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
   mm/kasan/report.c:361:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->sync_fault, sync);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:313:39: note: expanded from macro '__native_word'
           (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
                                                ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
   mm/kasan/report.c:361:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->sync_fault, sync);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:314:10: note: expanded from macro '__native_word'
            sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
                   ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)
                                ^~~~~~~~~
   include/linux/compiler_types.h:326:9: note: expanded from macro '__compiletime_assert'
                   if (!(condition))                                       \
                         ^~~~~~~~~
   mm/kasan/report.c:350:9: note: forward declaration of 'struct kunit_kasan_status'
           struct kunit_kasan_status *status;
                  ^
   mm/kasan/report.c:361:19: error: incomplete definition of type 'struct kunit_kasan_status'
           WRITE_ONCE(status->sync_fault, sync);
                      ~~~~~~^
   include/asm-generic/rwonce.h:60:33: note: expanded from macro 'WRITE_ONCE'
           compiletime_assert_rwonce_type(x);                              \
                                          ^
   include/asm-generic/rwonce.h:36:35: note: expanded from macro 'compiletime_assert_rwonce_type'
           compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),  \
                                            ^
   include/linux/compiler_types.h:314:38: note: expanded from macro '__native_word'
            sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
                                               ^
   include/linux/compiler_types.h:346:22: note: expanded from macro 'compiletime_assert'
           _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
                               ^~~~~~~~~
   include/linux/compiler_types.h:334:23: note: expanded from macro '_compiletime_assert'
           __compiletime_assert(condition, msg, prefix, suffix)


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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202160627.SICieucW-lkp%40intel.com.

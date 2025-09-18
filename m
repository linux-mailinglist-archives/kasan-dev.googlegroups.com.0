Return-Path: <kasan-dev+bncBC4LXIPCY4NRBJ7UVXDAMGQERVZBL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 804D5B82BD6
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 05:19:05 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b5d5cc0f25sf8477751cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 20:19:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758165544; cv=pass;
        d=google.com; s=arc-20240605;
        b=BR/f5kzT/Bk9B+QxyPp9TqHYlc1zhRZVVzB4Yu9ksUyYTKoA9QGWevRI+L3s/kfNpB
         K7WTZ4+a+EjC76w+WokzNROci+Cgvj5cU7bcf8HcqGCHwZluPv1FkcoKTc/n871aemlG
         XvgjKvw1ENlFcS2avpLc59fL1rjKdj+qlhMHhKYHFx6W0JN8n2jIrjEhDFkB5VI1JtUA
         D594dM8f6TV0CFKgTGCa0dUlA335ykhcIKP+HC/8Y+iZp51IUwTHg0v3CQDaYTVkXTvO
         pOSgfv7ADJ4677S978xcy1aXoCF0Avy10gS0OE3HcYzy89iK17PhSrRwPefqKxBjD41H
         6icQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rAgQLIz0InChVWFFEGg2fcUHuq4xeRMcbhhghRyapOI=;
        fh=/kaGJTRdQcOd8Fqf6hch2YSZadIFxquMbHeKYqkW/qA=;
        b=S52F5RWq2EUQiKog3s5GIJM5cnMbwuiV7AxNsQViDD9qYb3JJHXMU3bOjMyOPYVm8t
         OsCvJb2Yvi/6EqIn+ogdY8nXY8U9u2kxSuK1sWtvP9Nv1zuREL1h1fuxEkR1FmBUCY0M
         QoGOqn+9wTTsPOfdliuQIJ7dQ2q35Ge7KzT32G4ofYHWlU0rLYzoXy6x/rjCQE+114Xc
         Wbl1AxztgNABAfvDWi7QwGBASozlQ8r1mWeL6/gdhasOOqiWn4+597OFXScAiEb2z2Oh
         fd7eRroJ+vc+1dPkUNbITSx9YAdE64fon1y1I7krVtKD4buYydVU80ks5lap2HZaKIKc
         fASg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HT15zk2u;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758165544; x=1758770344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rAgQLIz0InChVWFFEGg2fcUHuq4xeRMcbhhghRyapOI=;
        b=QBYeRxJQHB1brGcGgiV2orBnRJnsRU4YFG6nnCzFleOHT2U0bfxixpCN3IcK+UDkoC
         tUROFNZMxEGFwe7cgIQmklb24AYbrGb4wZGfkJJnVHGD+MaHp3sL6Q/qio8uaBC7oHBl
         YelepGFEfrl9xDmE6gz4eypQ0XCL5wzsE5bJhPBHctOCcbCd1Y/MnM7uOO/8bF+ttCfV
         IISFEPtrwsRP6fBZJIgXWb/hud8B10Zk4crqeQMJrCqS1e+qQRrBUNovGcAG3ajuBiNN
         1bg/b1iljS1zhZeXw3Uwh8hSMOsTRxgqTtmrcizPYQsPlzmBsTlTzIEG2kC/PD1V0sLm
         W6LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758165544; x=1758770344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rAgQLIz0InChVWFFEGg2fcUHuq4xeRMcbhhghRyapOI=;
        b=LCn3eLtCQJQVkg8kLbCZ0nGUYiywVmSnpBgJSt94mjkU6JDpTlyiBudsIUJampVSny
         riwzaUUeNG/PSFt9SeXpsVActV3xb6SrhkUkrAXocZmRDoTyZJwNCt94851+ScoHtUhE
         rOOAQsyqCQ7t/ZxsILWzDjCzkaABils601Rb2hdBO6/Mq9OFgq5UeZAyyG3sJSMY9wCy
         OQIoN+sFHr3LJZ6wXBCfG20a+71foPxnC9uwPhrmFN8Zm1JrBPbsz1utuwr/K23Sefup
         J2t64Qar+G1Wck3V/p4xqSTi0JDQK6vbnqwzsGVGMh64GvPpW92I7s8RcHugbwbi2KWQ
         hFFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCwrW1j35192r6AAxHGgpAy5AIalk6t+Eff38T2i/XyQ7GIsFKKI5VWOstW9SSdyOmjm70nw==@lfdr.de
X-Gm-Message-State: AOJu0YyBD+ZpdDWVnBAYO/oigbDmggI0kqrevslJuR1T+woXcBVkj/W0
	dvc25bUYbXYCCXBvmOgTwN9avmYt3ZS6tJech5MeAOmAWdQg98ss8cLc
X-Google-Smtp-Source: AGHT+IGBZ1M/754PkaY1Iz/t8cCQvZEODW2QIKKneUwcV92O67g+Z1Bzm4DC/1MT7KV5aoYlk205NA==
X-Received: by 2002:ac8:58c3:0:b0:4b2:eeed:6a17 with SMTP id d75a77b69052e-4ba6a5d773amr55792411cf.46.1758165543738;
        Wed, 17 Sep 2025 20:19:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5jRbCOlE4ypKc5VZ8+K3vAQXJP+KN9NfAJqwyc+RCJ8Q==
Received: by 2002:ac8:57d1:0:b0:4b7:a98b:51db with SMTP id d75a77b69052e-4be07589456ls5490311cf.2.-pod-prod-03-us;
 Wed, 17 Sep 2025 20:19:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAXxGRvntyr4mNGAMKubF5LwAiVdqm7LI+T4hl8TWSKKNkyLYRpQMeMf6SttIk5mAtdTSaenUBlKQ=@googlegroups.com
X-Received: by 2002:a05:622a:590a:b0:4b7:9aea:1a0d with SMTP id d75a77b69052e-4ba6c6b254cmr57022031cf.76.1758165542795;
        Wed, 17 Sep 2025 20:19:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758165542; cv=none;
        d=google.com; s=arc-20240605;
        b=DiAwLmvwaVw4q4/qAHelIsBw7KMaJF266PSUTqCYqGqK01eOguxZvXJhdbWVy895oe
         zGnbl1Xbf/Nv5sumEdF/ATIceG2NfptWAuKRbo4Mwf0mU0dJg2I+y4c/CT/Z7qlQJKEn
         0W+/Z9vZ81hTqY1hBWi3M/2qCgN9MO2DNIZuYOLbrQxtM2FKcFLGaiz9QL6wd6BFkBxJ
         ec5Fbh8BERpnhR43D/jOy1ekQjWjKTGJR/6/1izdWnZ1TY+Uf05arMDd+qyZiE4phJEO
         Z16NS/OCIx6uRqokil+JcKIint+psIV0HxaV9dtxQC8k6gELSR2Z6BLcEnyWQV2ANfq+
         XUAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dQg4VOw6/IdS7zCdlkkwiGHYivVni7H2YH1AE7eKIJ0=;
        fh=Ep9PfZCNUvI/0vsxDj5zZVldyWlrufvmuAi3ZPIef7c=;
        b=anHIIiU4A8h6Monp0B/+kyNKOdyJMBqmx4joNMVTQU2ACZ+DYUYtZcTzU7Y+6TuH2v
         We2B6pjmNCLa9FYFte/57Bpckq0X2owvoIyWOAt7SUScK5JznvumGwbpfSswubGAtY06
         IqHcCuzLPgdHU7ACh/iTX0wGtp5HOP81Au9HpqmxZIa/DLTy0t74XUPl0FnYGj/T2Hn1
         Qup/2OCWM6ywWV4ggbDdslYu9ubJoH6U+6ZbiYHW6UXlar5QNPT68ZPrkGHxeSvBBP2y
         ueLNi4NY0jq+pm4wxwuXh4UxfP/aKx1fBENaWVOFk1YzywhZZPofvDYa9D5U23aKJyzx
         tm+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HT15zk2u;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bda380d3a8si554221cf.3.2025.09.17.20.19.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 17 Sep 2025 20:19:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: E4DZrtyyRXqooE+Q9tkPpQ==
X-CSE-MsgGUID: AvkZmJ+tSlmMipD0BLBoDQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11556"; a="71166105"
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="71166105"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2025 20:19:01 -0700
X-CSE-ConnectionGUID: 3G2x57egTrGvbePk9Tt6tg==
X-CSE-MsgGUID: VibjPdNIQKS4LH6sSyukmQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,273,1751266800"; 
   d="scan'208";a="174709563"
Received: from lkp-server01.sh.intel.com (HELO 84a20bd60769) ([10.239.97.150])
  by orviesa010.jf.intel.com with ESMTP; 17 Sep 2025 20:18:55 -0700
Received: from kbuild by 84a20bd60769 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uz5Aa-0002hL-0s;
	Thu, 18 Sep 2025 03:18:52 +0000
Date: Thu, 18 Sep 2025 11:17:59 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com,
	glider@google.com
Cc: oe-kbuild-all@lists.linux.dev, andreyknvl@gmail.com, andy@kernel.org,
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net,
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com,
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com,
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com
Subject: Re: [PATCH v1 06/10] kfuzztest: add KFuzzTest sample fuzz targets
Message-ID: <202509181042.zCqqD9To-lkp@intel.com>
References: <20250916090109.91132-7-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916090109.91132-7-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HT15zk2u;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted
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

Hi Ethan,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-nonmm-unstable]
[also build test WARNING on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.17-rc6 next-20250917]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20250916-210448
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20250916090109.91132-7-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v1 06/10] kfuzztest: add KFuzzTest sample fuzz targets
config: x86_64-randconfig-r112-20250918 (https://download.01.org/0day-ci/archive/20250918/202509181042.zCqqD9To-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250918/202509181042.zCqqD9To-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509181042.zCqqD9To-lkp@intel.com/

sparse warnings: (new ones prefixed by >>)
>> samples/kfuzztest/overflow_on_nested_buffer.c:63:1: sparse: sparse: symbol '__fuzz_test__test_overflow_on_nested_buffer' was not declared. Should it be static?
--
>> samples/kfuzztest/underflow_on_buffer.c:53:1: sparse: sparse: symbol '__fuzz_test__test_underflow_on_buffer' was not declared. Should it be static?

vim +/__fuzz_test__test_overflow_on_nested_buffer +63 samples/kfuzztest/overflow_on_nested_buffer.c

    53	
    54	/**
    55	 * The KFuzzTest input format specifies that struct nested buffers should
    56	 * be expanded as:
    57	 *
    58	 * | a | b | pad[8] | *a | pad[8] | *b |
    59	 *
    60	 * where the padded regions are poisoned. We expect to trigger a KASAN report by
    61	 * overflowing one byte into the `a` buffer.
    62	 */
  > 63	FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509181042.zCqqD9To-lkp%40intel.com.

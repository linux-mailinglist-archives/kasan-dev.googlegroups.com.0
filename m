Return-Path: <kasan-dev+bncBC4LXIPCY4NRB2XTZ3DAMGQEEHTT4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64E35B99218
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 11:29:16 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-63581a1a445sf601112eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 02:29:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758706155; cv=pass;
        d=google.com; s=arc-20240605;
        b=HsLhx2smE4IeyHo/gMAIxrMjEauCOABl6xs/j9VrbUKHzsQTvI5hXne2nbkMjOsHlQ
         08PvCeCJ8ysdlG3BCTwwide+ykNp0d1+i1Dh4JLSy483vAHR14wslmjgYN0H+VYVKHrQ
         AIkn1U1p4CmpdB7wRgNvqikJagqPKfPPNv3fCuxc5rsWhUUWF5R14+B6FMtQH/UfpaGI
         TB6YFzhhRfgpw64lYpM1C7xfzv5Ghx7pM1C+MC9TLVXtO0w/L3ck98pXBugKZb/6Lycj
         yO/i/Ohs/Hkks7sWYQRl7C86C54C3eAL/ga6pBQp8TtPkW9FdnxcQXwvQq5GdF6b8/bS
         KwCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UTpmq9Lopj3HjH4rcIGYD6oOvy6xIZG4ElIHUdewFZo=;
        fh=qy4elQy7DYy8Sft+Vkxq2vVblSvD5tsmG3hGIs6PoI0=;
        b=F/hZ4m6Zx1Dii9BYugO82DYWPrdEBRskSSN7RhnpVkqG+18NtyaWffKvKisgCm7y7a
         kBlwaDKxzgBGJARO5QT7/z1c3PfKewykvQQFZO0LWec2edQVAfUxjKll0+9gYj9zfFib
         yJSxS+J5b0I6HOo/V5EOD35z9aH3HrScnteDpgm/0wtblas118UcvtCAVWG7FD1pV5gl
         if8Vsh1BmqV2JNsSEzFLCyUAmSpWWEF7N3xIc2nD565dLWV5c/6pwfyE4Peq1C5Djgku
         KThg4MsvfFwMwBCT/HfcTCm06szBhEv/W8qgGR99BABcdyvw8f7QLF8nDokHKEBG2Rdx
         RpvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ALGIDVXY;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758706155; x=1759310955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UTpmq9Lopj3HjH4rcIGYD6oOvy6xIZG4ElIHUdewFZo=;
        b=Wa/w978RZeIxtV6EB7rE86dE0h720YaVq/80bkWgh963diHOk+wFTSvDgrttcHFp1r
         KmD7/7tSo8VTdpkJkijAeLQ2wQWAIXsDpc37mwv+S//TzSlS6WrHy/7UFVwYsMoM4S6j
         43+4uBs0cUKxI4lSAMycmQS1RrGje+Hf/C1Lid2t4c7hINgBRE//JijXa7CG8w5N/Xh5
         StoyHa6/782XdF4CgSfdXRyU9SopyQgZADug9j6K3g4xv5CiN2T4ZigTJHjETbcbpt4X
         7D1akZyMEXx4OBghjbJgeyjKPhqbsWBV2ppvCaV/h0YC7CQ8HT6yK0zhHS1vPkxKFksO
         Pk2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758706155; x=1759310955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UTpmq9Lopj3HjH4rcIGYD6oOvy6xIZG4ElIHUdewFZo=;
        b=dQsBaXzGyg0EjOlYPp7EB5NzMhuM1dyf9bGqCfZb1dCKjpv0iNd/b3/x5at9S9KrSr
         Q0k0DNdOznz2xYnorXVANRiHhmh/EkKCDfFUoVlPJU7ugsiNAAwHxlAOBRk+pVKN3kni
         eYRzrViFNvwo7w5Wsp3uzi4vAsTg6ii9oOXM2srJtruikgDtTSj6MJd1+BO+aHE2THEB
         dMk+cLLxS5P2tM2zhdeqpjf7KHzkerruJI0mfHY/LbV0GND8DlXFF2Fh5BTDavXafzVk
         9hWhedg3uTlUnBRTCJiJtKIysbPovieeaPfpImSdSQ/fxlBx4GL0MqEFnXpmv+Ub/xf9
         lSJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVHpGU3GU7d6bjV7/lLMPwCH5+5e67bR3wbsWUUugdJ6gCK1GSnXZKyMcsg3jBg137SZyixvw==@lfdr.de
X-Gm-Message-State: AOJu0Yy58JP/sv7Smnz0Ns09wbGr/bAtHhzCxDjnJ7B++a7B1sg2ZRwS
	EvgxAlVsbsWM21haE6x7AsqfPviv24D5hQkdUcB2OWu7Q/fD+hjJUAt6
X-Google-Smtp-Source: AGHT+IG8w0L1zDPYMte+3Q98QwDRu/RpuSIuRpZKfq9ADgs1mbQYgIJy7edxStLMtwuV/cXiRMmaBA==
X-Received: by 2002:a05:6820:54d:b0:623:45db:83f6 with SMTP id 006d021491bc7-6331ea33c08mr3126730eaf.8.1758706154745;
        Wed, 24 Sep 2025 02:29:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6K2sIaA3jLkBxqdmn/PvrH+elPGr3mC+AIwkjJrswKbg==
Received: by 2002:a05:6820:c08d:10b0:61e:dd7:6468 with SMTP id
 006d021491bc7-625dd84c95cls4175214eaf.0.-pod-prod-01-us; Wed, 24 Sep 2025
 02:29:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVs6eHQIl0YNYEk4Z5T7t5aj8RhtrSc7Y4WIiPY70eiVJZfXwxq2y2mUkTbgOXLq0SFTTUMgNd0ldc=@googlegroups.com
X-Received: by 2002:a05:6830:26eb:b0:79d:ebe:f238 with SMTP id 46e09a7af769-79d0ebef642mr305622a34.12.1758706153734;
        Wed, 24 Sep 2025 02:29:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758706153; cv=none;
        d=google.com; s=arc-20240605;
        b=G+7kggNImOFYP/v/vDoqsgKp7txcFYC/f9mtxJmHhIFx1b7H1kMuPOuOWFBM5uxoY/
         r/4uLtof0V4/e2TyCwJGryutubqyWPlyOxgVDs9bN6x0pAXEKR71106iylaQl0qML3nb
         /9QK4h7J/QIST+eI9MIJY4y5jJjj/Ae0SjMGDzMQg1LZ1mjJPoB8a7ig7DFuBB8fVO2u
         eR5pM01zCfpAcDGQyUfIUq2w7HYWjJ/jxpdUC0+jqybvVGvs4jvVz2Mw1jDqLXFVyISI
         wLss5q7gLFoliUMxnVt/BD1VzaRfQiUu685+Ue6J6iwyYxCKIS+OKF4uBQqZCsTGkQBO
         SsSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NQxhHDKJBxc1HbO7bdi2pKWv6xqO3AMW4eLlFgQFTOw=;
        fh=TASFc/MfWvlPTJQDkdqrmYgO5JxsXBmVOccrLNiXbU8=;
        b=OWiqErpCqmiwDP2DlwVDr5haQ9pB3JnnE9lKYpNXtzv2h9nm2dN8ovN3J8xDh/0U/6
         ECCw1wsIEOLDVUvHGq4l/Z0GWan/+yOQTSr635M9SjHyDMZGI+Ia51ktye6c6EqIbTNR
         r1MOD7v4zNHgfSb14Y4ihf81pl71ZMU9XIMLBz79QsgYzSgS4TXa9GSkyiF99aJ4ikk6
         38dQPZKwlVn39/KQ+4Azwk5bF4EOCqixp6d6PGqslgYvga74GO2O0yi4BLOZgH+/ncEd
         X9m7ONvGYtHFeL6T1x52gikY7BQB19gbgwe/GOhJkJSqhSgvPuDKXMkABBQIVpVe0Cv0
         Ikgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ALGIDVXY;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7692c348ae0si78455a34.4.2025.09.24.02.29.12
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 24 Sep 2025 02:29:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: Ec7Y3zyqR96VOAjsK5Stgw==
X-CSE-MsgGUID: jdcMdRHjSp+k27yi75tysQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11561"; a="60702489"
X-IronPort-AV: E=Sophos;i="6.18,290,1751266800"; 
   d="scan'208";a="60702489"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Sep 2025 02:29:12 -0700
X-CSE-ConnectionGUID: AoNF+o4URPO9+pRaHhaaHQ==
X-CSE-MsgGUID: /rwmqYRdQFCX2ffO479rtw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,290,1751266800"; 
   d="scan'208";a="182159717"
Received: from lkp-server02.sh.intel.com (HELO 84c55410ccf6) ([10.239.97.151])
  by orviesa005.jf.intel.com with ESMTP; 24 Sep 2025 02:29:04 -0700
Received: from kbuild by 84c55410ccf6 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1v1Lo5-000409-2y;
	Wed, 24 Sep 2025 09:29:01 +0000
Date: Wed, 24 Sep 2025 17:28:49 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com,
	glider@google.com
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com, elver@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com
Subject: Re: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for
 parse_xy()
Message-ID: <202509241655.GL49TRF9-lkp@intel.com>
References: <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ALGIDVXY;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted
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

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-nonmm-unstable]
[also build test ERROR on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.17-rc7 next-20250923]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20250919-225911
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20250919145750.3448393-9-ethan.w.s.graham%40gmail.com
patch subject: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
config: x86_64-randconfig-008-20250924 (https://download.01.org/0day-ci/archive/20250924/202509241655.GL49TRF9-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250924/202509241655.GL49TRF9-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202509241655.GL49TRF9-lkp@intel.com/

All errors (new ones prefixed by >>, old ones prefixed by <<):

>> ERROR: modpost: "kfuzztest_parse_and_relocate" [drivers/auxdisplay/charlcd.ko] undefined!
>> ERROR: modpost: "record_invocation" [drivers/auxdisplay/charlcd.ko] undefined!

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509241655.GL49TRF9-lkp%40intel.com.

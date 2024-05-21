Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGHQV6ZAMGQE6GMS7JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C488CA5BF
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 03:25:46 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-36c9d7ad3fesf134157465ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 18:25:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716254745; cv=pass;
        d=google.com; s=arc-20160816;
        b=vjAXS4W4oR/ox07Xm2BW8tHsSqT2zNoKCDv01z+fxqfhmJkyvRPqIdhlGEPlgl2UVf
         iuBYAvUXTy5Sr651fjxL25Dqz85PTeOjAarWiRhOc4QPxIEqzWra9eeH+bTuMCOYlIcL
         KYjf1YCXtSH898TWnEhowFR8wQNhd5/WNo84KFKR09byjuR5FrmssE59GfUBVZEhoSdn
         63GKIoqUUHE4FWrM6RGxRdKhrODVAbAmnIwudjKllX5tWfRm9DTKxipjFwDPI+fgYu7c
         E3lJW0+C8Yw6LUKgw1DJ38fsre5xOpg0a38slWznT95EoXq+P9lAvedFY+jXU1UWPQSM
         fOHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BjLdPW0pkVXyqKcvjDvd3Lr5prrkoEeAHTbQwb4oZ+0=;
        fh=OLij0axB9Ob7qY4MfLu+oems9wc4zY82/JHRBaKHkk0=;
        b=vGcdd0cQ2uJdxEPI/HXLV63BorYKCeqmcM2R73aTeXVZd1UgR4E6uUK9VHQAZgNkfc
         5JvPChBuM9XBQCq02XGBYI69UBJkCEfGZzHwozAKxWjJjb+c+8NWnhUxgsjePCZlU+3Z
         zM1wYzsHmDAYKhQZqrkmOIWKYXENq9WwBnN+894MqyocPLV7JWEfYFPs+2FoHE4kJygw
         NcLgRdlzFGDDFrGHtmMW4WodE2gETmGL8SYh6W6CBgt8NgkWUUbVWy4OQ1IjZN9mBOjw
         CZF8wPLJo7dF9iLrQWqDhT1YvCGb/r+Wx9blv/gyp6qY7XeOlvuwpXswPIfpGVxpbIzf
         7lZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gcdFwVu7;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716254745; x=1716859545; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BjLdPW0pkVXyqKcvjDvd3Lr5prrkoEeAHTbQwb4oZ+0=;
        b=vkXDdrdIq/LUTuV9qLIvBiZVVEzLxM/u7LlSFOB7IVzRhYY3eBivIO/Z4j9MDQwdh8
         83YrEkqWtng7CjMb718FWNUV6avzL1VZliVuMedz8ltDzOAMcZ5Ow/lqFKX0Ze8/BbW1
         73bjTKbq6DJYW0smEQGIs82XBCPH1+hykCxTbVZnftV4Ry+/VagSxC1WLspOOOSa0VAh
         AA3woBmKoaTLJVh5QpHyt8TKfEUqCrBt+m3hLlqfnDKyCdFqVWt90qI2xSMVTpmQr6Rh
         Il7eYlNAwvOa5gtN4ytS6TmATDW4Vh6SQidqQzjbG9O0Y1qdfd22jnIyLhmn04StPsNl
         DVYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716254745; x=1716859545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BjLdPW0pkVXyqKcvjDvd3Lr5prrkoEeAHTbQwb4oZ+0=;
        b=ngnmgWmLcGh5u0COjriPbYifqm8gOt4zt6y41oJPAKJoCrpTXWCIzTxCghmRPA+dTR
         UR+hBkvqjJmS6pV5t19Q/GacCqZK2UmAxKChBgoY/4sMBIOWWeyMmDJS3tN19sHtOMs5
         txc6V/aU0m5VWGZZ9QMxwN47AZezcfh1qTzedG9IUL7bctS4k4Tyb/++o5MzsfWuC/Zw
         KADTvw7o70EKEByI626NY7QSlJ9KFVsLxKjEzQQAGOL/7CmrUHD/wBtX9zBKrXImw5Jh
         EBBaDwVPSwZstjH9hotvCA0VONZYnJojtOxR6qoDfeztOvk7d28ihkM9HatWJmahCScR
         hmtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeslWotuQOaJows4z2ew/uBvv7EgEE1SacSQgGU6Xg39pENBYKuFWzMF5WAUFyMVHZl4bmqd4bPU624SgSeSWoqY0zRJMikA==
X-Gm-Message-State: AOJu0YyabflsluATBgExOfnswpB2/fV2I4Hf6V/loDxE8lUVW3Zx62BY
	jejrqkLvCZi4aUwB8bJJ4t/hbC5xKlBrshng+XPmHYjWkvO8Buye
X-Google-Smtp-Source: AGHT+IFQ6ITFIUcdM9L1I0VGF0C9q2ezUH5VDESG1l8WuDYwp6W64RuBr7DymL//h31c1ofJpV9YQg==
X-Received: by 2002:a92:ca48:0:b0:36a:ffd3:1cfb with SMTP id e9e14a558f8ab-36cc1429fd6mr381130875ab.7.1716254744869;
        Mon, 20 May 2024 18:25:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2184:b0:36d:b4c1:3541 with SMTP id
 e9e14a558f8ab-36db4c13761ls21294635ab.0.-pod-prod-01-us; Mon, 20 May 2024
 18:25:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4tKX72B6ykPmNRwH9E/HgCNrDWz3cbIKYL/v+7DTwLkyzfBmPymnvFLEGWAxVrNdYQWtWsz6htBdP2dTuXyir71HfPQSgafSqxw==
X-Received: by 2002:a92:c262:0:b0:36b:3799:a99 with SMTP id e9e14a558f8ab-36cc14cab48mr373452745ab.28.1716254743883;
        Mon, 20 May 2024 18:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716254743; cv=none;
        d=google.com; s=arc-20160816;
        b=jn1CTcb84ycn86KevvezejnfMj8Oo3SV9z3APSOeKUgPWOCil5aHX7ZFyyuq06opC9
         iLoDMCDkHIDtBa0smcAjFR3EUSAB55SH+oGxN1RHKSma2eSfHw9sslU+RNIqSLYlltsA
         KImsY0Ie2WbK8kX69tsufghuWd3hDraQ5LnekaqCc77x6ZiA+jfsJtyB4xFUHgJXvNA1
         DcyICKA3appwD4zWCk0xxh1+dvMD1wRjx4T+yWz8WDrtE2IcbOzdg4KiMoApPhXqMA7Q
         P5Vly409qkOE7Sk5Ye47So3sjQRCr/576d8b64KuNjnz678zT8RRKiR7zGtFVmbxdo7T
         5a4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nBy14n+NzSm8W8mmW9pn9UME3JW7PJMsqX4UCGSG3Qw=;
        fh=EcpVAlbqkS/8aDVSaCUzbJuR6AnIUVKCCsnq9fhiMJc=;
        b=B+BdfaBUDopiTmOSDeMfupfqxxd5KpJBMgsv6L+BZCVSRmCaWsS9fNtOC6lf33v/M3
         yiw4Qh5GsEfSPAsqeSksKtlwR2wHfN7PtN+Ky7r30jDJDEHeMrV5dTh4DI+qa+MEq0zT
         7xkdKUgmLuD1oXaF+Z5W2nI9KODZ5yAI0oPJrUS+4QNo+10wHwQTwcS4nxe7+6h0ZJ6L
         fQdcb9FUmC0/9tf1NCj4jQS24zYNXNewlZLSiIm+ag0joBMpsP3dPdyh7KkmGTySB1UK
         zqXEDXwUy0EwEN3b1XQtdpmp9duJQPmIsY5w55FeHGKq/rhZmZZ/st9qHOKxm1T5Xyok
         p3VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gcdFwVu7;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-36db6a52610si7619095ab.0.2024.05.20.18.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 May 2024 18:25:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: mJY9ds1gTEG59c9+6CWVUQ==
X-CSE-MsgGUID: QkGGPxHTTHSCvV1l7Vp38A==
X-IronPort-AV: E=McAfee;i="6600,9927,11078"; a="12261382"
X-IronPort-AV: E=Sophos;i="6.08,176,1712646000"; 
   d="scan'208";a="12261382"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 May 2024 18:25:42 -0700
X-CSE-ConnectionGUID: x843YUg/RJO56KjYuaUP1Q==
X-CSE-MsgGUID: pH5vquoqTUCG9M4aqGLW4Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,176,1712646000"; 
   d="scan'208";a="37114089"
Received: from unknown (HELO 108735ec233b) ([10.239.97.151])
  by fmviesa005.fm.intel.com with ESMTP; 20 May 2024 18:25:38 -0700
Received: from kbuild by 108735ec233b with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1s9EFz-0005MM-3C;
	Tue, 21 May 2024 01:25:35 +0000
Date: Tue, 21 May 2024 09:25:01 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: oe-kbuild-all@lists.linux.dev, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Tejun Heo <tj@kernel.org>, linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcov, usb: disable interrupts in
 kcov_remote_start_usb_softirq
Message-ID: <202405210908.bv3U0RAQ-lkp@intel.com>
References: <20240520205856.162910-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240520205856.162910-1-andrey.konovalov@linux.dev>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gcdFwVu7;       spf=pass
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

Hi,

kernel test robot noticed the following build warnings:

[auto build test WARNING on usb/usb-testing]
[also build test WARNING on usb/usb-next usb/usb-linus westeri-thunderbolt/next linus/master v6.9 next-20240520]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kcov-usb-disable-interrupts-in-kcov_remote_start_usb_softirq/20240521-050030
base:   https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb.git usb-testing
patch link:    https://lore.kernel.org/r/20240520205856.162910-1-andrey.konovalov%40linux.dev
patch subject: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
config: openrisc-allnoconfig (https://download.01.org/0day-ci/archive/20240521/202405210908.bv3U0RAQ-lkp@intel.com/config)
compiler: or1k-linux-gcc (GCC) 13.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240521/202405210908.bv3U0RAQ-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202405210908.bv3U0RAQ-lkp@intel.com/

All warnings (new ones prefixed by >>):

   In file included from kernel/fork.c:92:
   include/linux/kcov.h: In function 'kcov_remote_start_usb_softirq':
>> include/linux/kcov.h:132:1: warning: no return statement in function returning non-void [-Wreturn-type]
     132 | static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
         | ^~~~~~


vim +132 include/linux/kcov.h

   119	
   120	static inline void kcov_task_init(struct task_struct *t) {}
   121	static inline void kcov_task_exit(struct task_struct *t) {}
   122	static inline void kcov_prepare_switch(struct task_struct *t) {}
   123	static inline void kcov_finish_switch(struct task_struct *t) {}
   124	static inline void kcov_remote_start(u64 handle) {}
   125	static inline void kcov_remote_stop(void) {}
   126	static inline u64 kcov_common_handle(void)
   127	{
   128		return 0;
   129	}
   130	static inline void kcov_remote_start_common(u64 id) {}
   131	static inline void kcov_remote_start_usb(u64 id) {}
 > 132	static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
   133	static inline void kcov_remote_stop_softirq(unsigned long flags) {}
   134	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202405210908.bv3U0RAQ-lkp%40intel.com.

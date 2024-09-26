Return-Path: <kasan-dev+bncBC4LXIPCY4NRBJPQ2O3QMGQE472CMMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id B42A4986C2E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 07:59:02 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3e03befc39fsf720379b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 22:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727330341; cv=pass;
        d=google.com; s=arc-20240605;
        b=d/Aep1qT6REGVZfSM+7D0tGN2ZSJqXIM0aUzGaT6CGBsO8/Nooa4/kFSGZ9VN+DzTZ
         Fw2ME0k9gAnhfg8T7aW/xGLe5QSFs2UTVksDZwXavOIXNXALInqoglMRjdee0sJFv0vK
         k7WjjSfBwlKIqlLdEW7aF3tXXdsUOtl9qEfAUuf2S7FWNwdNwTqnAaZjah1ywzADOieX
         t6XQoi4Wng/Y3DBMwKteQMPxJVzKIZuCR+awAhSqYFhiOIqx56uN08bMPl5L9gKg4VPh
         LQfecUUs/7F3hVsag+lWsuxPn38Rll/qZg9FjBHVxCYtJ/YW+fEVs+xpB2oP1oEorw/h
         IlzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nvwfcEUFOhw6r8L18jceLi4wAC3jSl7w9mWoH5x0ESU=;
        fh=K75HHY+gWuMa7KTrt5xuhjtxBRutcyR2Hfw5NoTcWdk=;
        b=VVpvB4BpnzanH6oNRrJ57YxQS5a17OIre0i7ZiXHbiMFSiSwiMx4miUo68cpguo6Ix
         EyyjbiEZYY/hysNL2kq5dfKLW5SmYk16C42Ad65xrAKwmZLdz7cNXLheAkeQZ18UBocl
         FumEwzsf3K4DqpEGt9fu3EnUBqk2+BhBgMsfWIz1qMYI1ypc7XD2OGPboloa0btiTWWw
         gPS4cF1OazeADZ6pOBf0j1EuOOaA4c8xH1gYVx6PQExKfUCoM3JomW71zBGs3myv1xb/
         PnD5L/bae0YEXttyH+4dKBr2kIUOB4eXkJbCEV811KpRK7QyLsXwAHSKh4woDie5XDrd
         AP6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Mjrt8sMC;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727330341; x=1727935141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nvwfcEUFOhw6r8L18jceLi4wAC3jSl7w9mWoH5x0ESU=;
        b=LO7DZts3dXsl8V722RIHvOYEBKRSVVCd8q8Ghkjg2pCM6uI6k4HFQipP/NeSSKOjxw
         Fjz4DQUJDWHT2DSAGAnnsZUDHFWxWNpEa2+9gcJCXA+9NYNkQrSMmGk2tYoowdlaVtwM
         58XmTxUg/alVg1nK/05bEUjW/gLSl6p2nRSxjg34Da3dWDAGEL1J1wwC04DKMfEw6HAQ
         VL9uqfZxx/5zpp4D6CJGuVG48ypGYh3kFyilP+eYz8Z26Rim053yEFaVBtdutSyMjwKq
         LaRsdTT3ifLt/auNViGD4t5Yr7jS8zdCBoWaXbPhy4Cd8/ek/t9Zzkv7aIoNvFjyuoXl
         zghw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727330341; x=1727935141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nvwfcEUFOhw6r8L18jceLi4wAC3jSl7w9mWoH5x0ESU=;
        b=fctmmzcDOrroKV39jgtEj+uGY+nEO8ojf/J7WcSmA6gtxUwzuLhGVYdDmI1pmsS63z
         cTRFivSnUC1qqrf+h5j3GPt/59h1v+ASnHl2ORfVHcY4UgxJLDVGdQEn84tF+V7HaUBp
         pi4kde6HD4mkUxfJHLFWgxVmux/jogNzWdDRBw+xMyTw74o2twSsuAxWbKSMYfxFdWp4
         UDHMdHo9vIx+D7aCGtR+/1Zv16jBqIjZ4vvKv6Y3KNjhBIar5r4fItnGwaTHENRSOnSU
         oA4eqQPzVsUX3g4/z5A1uJtkgoxd4VmaswaTK5MB4UaziNglP+SJ5HMFAkb5H3bfooOL
         d1jQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhE7auJ1QNObGTjidLRLbWShCIPVkD8c3ZY7B8msCFpMzOM0JS8vlEOcd4odCvquMLsA7/5Q==@lfdr.de
X-Gm-Message-State: AOJu0YyLgEQsdkX+tykhP0tTdbWQ1eUtg5gZtLtUb3fiYp8oDE2Vdn1s
	YZJ2BDvOXwe1SohnXkz62yb3iVQ57350FTzkj5m7xXx4//QDsg2O
X-Google-Smtp-Source: AGHT+IEh2hEiVcZeHcehVEgxHxr9KqXbbxGM35am802uUHiAC4DQhAeaN76EZYfz7rQOPwRhIsOubg==
X-Received: by 2002:a05:6870:7249:b0:260:fbc0:96f2 with SMTP id 586e51a60fabf-286e15f7788mr4238830fac.34.1727330341232;
        Wed, 25 Sep 2024 22:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4e05:b0:27c:a756:f49d with SMTP id
 586e51a60fabf-286f91b6f75ls858598fac.1.-pod-prod-02-us; Wed, 25 Sep 2024
 22:59:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXE2Bqf48r/1E7kaqlWjDtzuNsmrdRsd2eWXkN6g2D1OCepmkuJLq4k0AeadhDDhEk30P0d0oSx1tY=@googlegroups.com
X-Received: by 2002:a05:6870:330a:b0:277:e5a5:3362 with SMTP id 586e51a60fabf-286e15f3febmr3957218fac.30.1727330340460;
        Wed, 25 Sep 2024 22:59:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727330340; cv=none;
        d=google.com; s=arc-20240605;
        b=eeNev9ItiGEBIAMTvavkUuYdjWSNEQOkVlTygT5NG3/pSuwhDlWCF8GvkBb7JN3kjy
         d2WfpbL/chl7Oa58XJDBXMCMPIowIKrx4ncz8wGCGIrOLXP9+r7hnKt2MjmITls2jWHZ
         WxqKHpTaq0ikusXXfygkvOPmcjidrPJFNBwk5v2s3sJn+gC23naYUCuQ8shDYHzAURgK
         cfnNOdDnr4Wgx/yHW5izsM09H6TEVQmL/P+h+1UEBGO533Q/xBumkhJFQxqP1LZqpXOF
         s5L3pbXdexMjLEgb01ZUXl2Kh1ZTYXT+O1hzk8lgBQ9p7MN3jK7yveHNDnKfsNvm6/h2
         YXjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+MlVzZplBkQXpB/MvbYD6ov8ZrsoL2/zC9u8Ul/lamU=;
        fh=fYHQcGCsuM1mZEaTKh1MDjWSRdez+CwAR+1TcU5yugA=;
        b=UljfSSj3ZF4o224ejGgL49C15WMGS3sfzX93fJhS9BBWsrn6wdAYSl2422hcXPKVSV
         +O743lJyWXUuYAaXBUVFVbFT5p/zCCnnJiVO7Ik2muuMP6LkTcNKTcsXEWgX4d3i285w
         SYftGuYaYZ/7HQpNMsknoPU0dp/MQbUY0Z0wTgg2S8lIFuG6lIa3+lXnexl8Af2hhPFP
         ly6REbcLIiEER59//oOesNGkP+P5WtAdvRh1kFUgOfQn1SFwLoyCbBbzM8vQ3eIqS5F4
         KAL5rLJLjmI+htxPNDwMjH4i6b5YoRDKb5r1N1dLyqrG4/+PP6hjwVpUEvfhOc+xXs+q
         NbyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Mjrt8sMC;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.9])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-283afc2dae9si281025fac.5.2024.09.25.22.58.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 25 Sep 2024 22:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) client-ip=198.175.65.9;
X-CSE-ConnectionGUID: 7Myc6g9HRSaBLwKsoorMWw==
X-CSE-MsgGUID: PzHD/5UBQLyeIaT1A/6cOw==
X-IronPort-AV: E=McAfee;i="6700,10204,11206"; a="48937722"
X-IronPort-AV: E=Sophos;i="6.10,259,1719903600"; 
   d="scan'208";a="48937722"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Sep 2024 22:58:59 -0700
X-CSE-ConnectionGUID: +LFQxGnFQtqE56+9kaUp8A==
X-CSE-MsgGUID: Xah0O/W4TiS3slHKVkG5UA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,259,1719903600"; 
   d="scan'208";a="102842484"
Received: from lkp-server01.sh.intel.com (HELO 53e96f405c61) ([10.239.97.150])
  by fmviesa001.fm.intel.com with ESMTP; 25 Sep 2024 22:58:55 -0700
Received: from kbuild by 53e96f405c61 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sthWf-000KK3-2D;
	Thu, 26 Sep 2024 05:58:53 +0000
Date: Thu, 26 Sep 2024 13:58:39 +0800
From: kernel test robot <lkp@intel.com>
To: ran xiaokai <ranxiaokai627@163.com>, elver@google.com,
	tglx@linutronix.de, dvyukov@google.com
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Ran Xiaokai <ran.xiaokai@zte.com.cn>
Subject: Re: [PATCH 2/4] kcsan, debugfs: refactor
 set_report_filterlist_whitelist() to return a value
Message-ID: <202409261331.9NyGRPt2-lkp@intel.com>
References: <20240925143154.2322926-3-ranxiaokai627@163.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240925143154.2322926-3-ranxiaokai627@163.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Mjrt8sMC;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted
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

Hi ran,

kernel test robot noticed the following build warnings:

[auto build test WARNING on linus/master]
[also build test WARNING on next-20240925]
[cannot apply to v6.11]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/ran-xiaokai/kcsan-debugfs-Remove-redundant-call-of-kallsyms_lookup_name/20240925-231034
base:   linus/master
patch link:    https://lore.kernel.org/r/20240925143154.2322926-3-ranxiaokai627%40163.com
patch subject: [PATCH 2/4] kcsan, debugfs: refactor set_report_filterlist_whitelist() to return a value
config: x86_64-allyesconfig (https://download.01.org/0day-ci/archive/20240926/202409261331.9NyGRPt2-lkp@intel.com/config)
compiler: clang version 18.1.8 (https://github.com/llvm/llvm-project 3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240926/202409261331.9NyGRPt2-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202409261331.9NyGRPt2-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> kernel/kcsan/debugfs.c:243:7: warning: variable 'ret' is used uninitialized whenever 'if' condition is false [-Wsometimes-uninitialized]
     243 |                 if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
         |                     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/debugfs.c:256:6: note: uninitialized use occurs here
     256 |         if (ret < 0)
         |             ^~~
   kernel/kcsan/debugfs.c:243:3: note: remove the 'if' if its condition is always true
     243 |                 if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
         |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     244 |                         return -EINVAL;
>> kernel/kcsan/debugfs.c:238:13: warning: variable 'ret' is used uninitialized whenever 'if' condition is true [-Wsometimes-uninitialized]
     238 |         } else if (!strcmp(arg, "off")) {
         |                    ^~~~~~~~~~~~~~~~~~~
   kernel/kcsan/debugfs.c:256:6: note: uninitialized use occurs here
     256 |         if (ret < 0)
         |             ^~~
   kernel/kcsan/debugfs.c:238:9: note: remove the 'if' if its condition is always false
     238 |         } else if (!strcmp(arg, "off")) {
         |                ^~~~~~~~~~~~~~~~~~~~~~~~~~
     239 |                 WRITE_ONCE(kcsan_enabled, false);
         |                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     240 |         } else if (str_has_prefix(arg, "microbench=")) {
         |         ~~~~~~
   kernel/kcsan/debugfs.c:236:6: warning: variable 'ret' is used uninitialized whenever 'if' condition is true [-Wsometimes-uninitialized]
     236 |         if (!strcmp(arg, "on")) {
         |             ^~~~~~~~~~~~~~~~~~
   kernel/kcsan/debugfs.c:256:6: note: uninitialized use occurs here
     256 |         if (ret < 0)
         |             ^~~
   kernel/kcsan/debugfs.c:236:2: note: remove the 'if' if its condition is always false
     236 |         if (!strcmp(arg, "on")) {
         |         ^~~~~~~~~~~~~~~~~~~~~~~~~
     237 |                 WRITE_ONCE(kcsan_enabled, true);
         |                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     238 |         } else if (!strcmp(arg, "off")) {
         |         ~~~~~~
   kernel/kcsan/debugfs.c:229:13: note: initialize the variable 'ret' to silence this warning
     229 |         ssize_t ret;
         |                    ^
         |                     = 0
   3 warnings generated.


vim +243 kernel/kcsan/debugfs.c

dfd402a4c4baae Marco Elver   2019-11-14  222  
5cbaefe9743bf1 Ingo Molnar   2019-11-20  223  static ssize_t
5cbaefe9743bf1 Ingo Molnar   2019-11-20  224  debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *off)
dfd402a4c4baae Marco Elver   2019-11-14  225  {
dfd402a4c4baae Marco Elver   2019-11-14  226  	char kbuf[KSYM_NAME_LEN];
dfd402a4c4baae Marco Elver   2019-11-14  227  	char *arg;
43d631bf06ec96 Thorsten Blum 2024-06-24  228  	const size_t read_len = min(count, sizeof(kbuf) - 1);
52313281c8b7ca Ran Xiaokai   2024-09-25  229  	ssize_t ret;
dfd402a4c4baae Marco Elver   2019-11-14  230  
dfd402a4c4baae Marco Elver   2019-11-14  231  	if (copy_from_user(kbuf, buf, read_len))
dfd402a4c4baae Marco Elver   2019-11-14  232  		return -EFAULT;
dfd402a4c4baae Marco Elver   2019-11-14  233  	kbuf[read_len] = '\0';
dfd402a4c4baae Marco Elver   2019-11-14  234  	arg = strstrip(kbuf);
dfd402a4c4baae Marco Elver   2019-11-14  235  
dfd402a4c4baae Marco Elver   2019-11-14  236  	if (!strcmp(arg, "on")) {
dfd402a4c4baae Marco Elver   2019-11-14  237  		WRITE_ONCE(kcsan_enabled, true);
dfd402a4c4baae Marco Elver   2019-11-14 @238  	} else if (!strcmp(arg, "off")) {
dfd402a4c4baae Marco Elver   2019-11-14  239  		WRITE_ONCE(kcsan_enabled, false);
a4e74fa5f0d3e2 Marco Elver   2020-07-31  240  	} else if (str_has_prefix(arg, "microbench=")) {
dfd402a4c4baae Marco Elver   2019-11-14  241  		unsigned long iters;
dfd402a4c4baae Marco Elver   2019-11-14  242  
a4e74fa5f0d3e2 Marco Elver   2020-07-31 @243  		if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
dfd402a4c4baae Marco Elver   2019-11-14  244  			return -EINVAL;
dfd402a4c4baae Marco Elver   2019-11-14  245  		microbenchmark(iters);
dfd402a4c4baae Marco Elver   2019-11-14  246  	} else if (!strcmp(arg, "whitelist")) {
52313281c8b7ca Ran Xiaokai   2024-09-25  247  		ret = set_report_filterlist_whitelist(true);
dfd402a4c4baae Marco Elver   2019-11-14  248  	} else if (!strcmp(arg, "blacklist")) {
52313281c8b7ca Ran Xiaokai   2024-09-25  249  		ret = set_report_filterlist_whitelist(false);
dfd402a4c4baae Marco Elver   2019-11-14  250  	} else if (arg[0] == '!') {
52313281c8b7ca Ran Xiaokai   2024-09-25  251  		ret = insert_report_filterlist(&arg[1]);
dfd402a4c4baae Marco Elver   2019-11-14  252  	} else {
dfd402a4c4baae Marco Elver   2019-11-14  253  		return -EINVAL;
dfd402a4c4baae Marco Elver   2019-11-14  254  	}
dfd402a4c4baae Marco Elver   2019-11-14  255  
52313281c8b7ca Ran Xiaokai   2024-09-25  256  	if (ret < 0)
52313281c8b7ca Ran Xiaokai   2024-09-25  257  		return ret;
52313281c8b7ca Ran Xiaokai   2024-09-25  258  	else
dfd402a4c4baae Marco Elver   2019-11-14  259  		return count;
dfd402a4c4baae Marco Elver   2019-11-14  260  }
dfd402a4c4baae Marco Elver   2019-11-14  261  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409261331.9NyGRPt2-lkp%40intel.com.

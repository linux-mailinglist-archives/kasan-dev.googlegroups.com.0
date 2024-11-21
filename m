Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBPP77S4QMGQELKRRMUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A71B09D4E5A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:12:15 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2969ecd4315sf834031fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:12:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198334; cv=pass;
        d=google.com; s=arc-20240605;
        b=A4TzoySZYA0iVixrT6tKVZF7cW9YnLLzwmY3s6p/r3yvI9h6E/Og2fc3VKQh29bDuq
         AbpLvEZTJ/8kLZ8mLl31w13ySCHAAHg7Tq1ba+unT4isVaxtwqq/iAhuFMZ5UCt87134
         2kRTkUR4mzHal7fY50smxPIo3rpD5lk1oyk8kTCG+PFVRmzbRKHwLrMkodgiprOEjtyy
         mQMnmK77g5usWtnbEuSkUJ2d2ESTlN0/4mlYIOrnwfgqOqItihfYy9LUajtQUWczVrBu
         esqLbP1G8Wk5jRr+pnga0zbZV4aAdtd/f1T4SLNvHDN4KjK6j4sjfkwcvOoDT/obm4/5
         4n9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OWTAIUaqUA2tczucZl8ULTXGM8xf0CuA3uM2EYbzrMk=;
        fh=T2RuuQ5PDNnS7Qouq9Rei5NlOp/dsytF3Kp0b2Nsy0U=;
        b=TjpuRfkvkJpYBpkkyBSvISz94D9guChGlKNw5XkOUrDlnaiHELIJeishhg+fznPlzW
         OM5OvdWDhNODKZZSe9PJ6tO6U+ZoKk2vkHMOkqnazts3dzPhOJUTI/qMzzrJGvEMysUH
         vYBJ7ypYDQ2vHzGVWrwVJxr2kBJSL2TU6CEWho6t0S7LcaE9bzET22t5FOMat8A32O0U
         qTfeBfZh2P+DfB3ccv6GU5r9PPncaVa/eqrmO/yaNnuxKTH0ShLHmHgHZTCcxgt6LLAt
         d2ere/jrG+zwY7GrR/Kgz/KYI6Z2La+qCoDBv7dpg+hAwUvpZxxww2OWryoEEJ3vdkQH
         fF4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BcmDtIa4;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198334; x=1732803134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OWTAIUaqUA2tczucZl8ULTXGM8xf0CuA3uM2EYbzrMk=;
        b=Of7f5sfyl9YQKJKxxiAl1kj5k8vA2PvZcpNckzBnfnrC+MBlOZ/7QfR2xtxE63q7rC
         V99WQP6HA1P50U4xiIbiRmEBgj0ABamSdLbtSdjGh3wop/k7uN1G+pnO0AL7+TZA+a2P
         H9y/KEGVjkzs7VkDY6aKZtVVa9EUThRu8PB2eClrpczAr/MCqccFHhlmguXSJQ4xyVul
         f1eq4+Ul4B6+vdf/uXNa+ZgW4BpHkXS7lifG6Elf/v7eU2XefvKDL/7Wd5U+bsysFLlS
         fXmIxd0G7pgRTVopMeRZPYqSB2bkO//UgpsLa1q94HAU0o8N3TmR8Swu9GbIaXoCYETw
         2LkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198334; x=1732803134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OWTAIUaqUA2tczucZl8ULTXGM8xf0CuA3uM2EYbzrMk=;
        b=rL7xsmMS6Yj9jXgXuuGLrTP4Q+aXRLML+q0FHC690m3FJMPkyJwktOAZUPyusxgZ6L
         bVbuA47CUSyz0e8fpZ4nOrJ9pZnbz9BpmUEARP/Vczm71PmxrLsvVNKU7OTowpJSaMnZ
         hVSVINmY9uCgelKzLItN1UapPqkjG7Af5knIxpl1P+ip3k4NsFvUEKHkwbSxLUUXdGGR
         xY3Twt9v8iUMVIMOx/wqxppAxNlpf+FCdJb0oHHg0DOa2X1G74AhnFSv1AFT7Qf57Nq8
         tU5pcbSTSbx13V4Isin+HjZOl7USGT5s7o0njGCIw5NWYtl5+V6BHUGy4zRqQdv7WLMk
         Ax7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXND5+HMKuCTrFoxfKqapi3/fK8ok7nIxInCdKxNyVotphNB4KwGPsC+Bi8+Shl9mWXeKuETw==@lfdr.de
X-Gm-Message-State: AOJu0Yyq/4inzL590HrKqCit7Y5Rp1+oCwQT4IHcqCOj9kP0VukQxDdO
	J4+4+eb598vgpzTHqRMa5uCdk0p24CUqp3pIXnJF1Xt9d9fYrvy0
X-Google-Smtp-Source: AGHT+IHMjwZaEgOCbyGMB+MNBWSuKU9R5Cd5pdAVrw+M3gWOYQX7C9plXJVWzNptfPCvxDQyEuOiBQ==
X-Received: by 2002:a05:6871:3b02:b0:296:dec3:8083 with SMTP id 586e51a60fabf-296dec380e7mr5527400fac.26.1732198334048;
        Thu, 21 Nov 2024 06:12:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:468f:b0:296:e98:31aa with SMTP id
 586e51a60fabf-296fc59279dls509213fac.0.-pod-prod-04-us; Thu, 21 Nov 2024
 06:12:13 -0800 (PST)
X-Received: by 2002:a05:6871:42c4:b0:277:da52:777 with SMTP id 586e51a60fabf-296d9b4f727mr6911992fac.11.1732198333085;
        Thu, 21 Nov 2024 06:12:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198333; cv=none;
        d=google.com; s=arc-20240605;
        b=WxL1XAJCBJk7UXcqD/MyfbqCEhEBz67vC2ZJsMWYkoQsmqsXnz7sG9gG1jOllEwQ9a
         eQNQo4+FcMfnR8IK2KMmdf3tvVhxq/Hbcidz1OOaGD2BS24RUCKhf9gWa0dgDzOxFp5P
         SlSlAt/eXVWc3Vn2kP6u2m3lMkeHLDjZ01FgexSgFUlS5XguwAt0iPkvjnnT2d5yMBKY
         MzhlQz+DTWoJRestVRsow3Y19U434XO+rZFqFSfzo19NsQvsr6HhIASs+cGIB8gychPg
         D1tFrsfl4LF0eb4xz4OyMz5GlP9lmQTxlmGfr1vubXyOBfvOKG3iXgjzjubeCEreg3oQ
         FLyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=aeeBz6fKUxjTtk5+5SFCnbrGLkuvTCzRT+8BJsg1Zdc=;
        fh=BuxweDoviiTrvykEWSRNa5gyMRe+aKQjNK6M2eeCyLA=;
        b=S6wwT3qzDzTLU3wm/uJ6qhiVInP2Qxb4HDjaJUiRMvlaNo1WqzO7WjMkU3vg8G4W7l
         ytx+f+QBW5FSXY9rsFthFHBqrUIUStIrstQpHET9J0inKFYXV1QYvtVghEBwWvZbrYl+
         +nucxjY4IhJAZzERGN6c4LkehhfoHtL/zHXHSmcgq0c457uXQrKSDVz1Z5YF3CIhgOZG
         MvIKthvP7liRzWpQtqk4rbzdrQuwJOutNb49WbWeo5htjteYA/Z2P/JsFHsNaCUEerID
         hRBYEGDOPe6AmhhWN888SZ+DYXiGY6Bhtr1En0eYLQVi5jBwGEP2gctig8OGyb2Qrc1m
         FdcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BcmDtIa4;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71a780f4778si568620a34.2.2024.11.21.06.12.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:12:13 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: TiZiz+XmRKqozKo6VZOthA==
X-CSE-MsgGUID: 6pehiSM0TjWcV3y6lrNe2w==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="32456644"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="32456644"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:12:12 -0800
X-CSE-ConnectionGUID: NE3iqxIcT+28S9Ztl1Q9/g==
X-CSE-MsgGUID: wC1j1mVuS02DgIto8YIOlQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="90674871"
Received: from smile.fi.intel.com ([10.237.72.154])
  by fmviesa009.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:12:10 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.98)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1tE7uh-0000000H5G4-296C;
	Thu, 21 Nov 2024 16:12:07 +0200
Date: Thu, 21 Nov 2024 16:12:07 +0200
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 1/1] kcsan: debugfs: Use krealloc_array() to replace
 krealloc()
Message-ID: <Zz8_t3vn4SXTNHH3@smile.fi.intel.com>
References: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com>
 <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BcmDtIa4;       spf=none
 (google.com: andriy.shevchenko@linux.intel.com does not designate permitted
 sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Nov 21, 2024 at 03:04:04PM +0100, Marco Elver wrote:
> On Thu, 21 Nov 2024 at 14:58, Andy Shevchenko
> <andriy.shevchenko@linux.intel.com> wrote:
> >
> > Use krealloc_array() to replace krealloc() with multiplication.
> > krealloc_array() has multiply overflow check, which will be safer.
> >
> > Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>

Thank you!

> Do you have a tree to take this through? Otherwise I'll take it.

No, but please, wait a bit, I have a sequential dependent patch.
I'll send a v2 soon.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zz8_t3vn4SXTNHH3%40smile.fi.intel.com.

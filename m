Return-Path: <kasan-dev+bncBDA5BKNJ6MIBB74NYSTAMGQE43ESDNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 545D6772877
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:00:17 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ba1949656bsf33760051fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:00:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691420416; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfQAzhPpKDhMuvIezipKP9AKWxQHyMIcHOV3k7XxSarLX/lCmPLycaAlHnugmWi6da
         6v4V4NbKr7/9Kg7CyeUv83X3TYKINWyP7auc2kMdqWzJKwsmuryZkRGOnhxDQFdDIJk8
         +GEWPK+jkWxXaxYhGb8VP47Phy0vH2QVfIgscIfTuhWrSzHc9z3xyzX4smEP2o2iaDmB
         v/TIWHNbuaf07P+Uwn08phv+yALffqRlhQqyZuHiimUJkPnZSVjD8Joqf8ZSS4S+4KGL
         m8/rsYmdwp7ty1RT7fbYZ8kx94TOS+AJbZSXPMlSN9Kfah02PaNIQKZkwt3Bj6b968i+
         er/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3tO2BuViEQ+PTHZcrYNryBbvzEc/M2sC96u3WTWpZEA=;
        fh=kC0MEPFgIv203S+Twf4/za9BgUivXrzFOL/tROBZ0G8=;
        b=s3Yn+og4vtuXXCZLLAygH7VyoQpQCA/4o3uVf55kW72/fGVc1BKRtiltJeo2PUP4wy
         vMDPHklwaA85KVlelv1+jr2Q4SVZvd8UOXDK7hhR7dlPCskDvfJbOSvyPU0BAIdcovxH
         8jqQIeB0kk0baYxTGkcmM/VnBQMjr/SHRseLBICT7dzIig382lB7YjJe4pAlbtpHOMlD
         PvK5T6TUv1CXIdnfsbMHYjHONc+Lj/357JgsrYbSPfpof5DearAGye2n9f14W4YoJDOV
         byEP8XGC05tYb2EwJXYy35tF7gxr/E1ibFpMvw2pXc8l57vITMwMh6Zck3udz/pSjn88
         fxSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QId6Wa+0;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691420416; x=1692025216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3tO2BuViEQ+PTHZcrYNryBbvzEc/M2sC96u3WTWpZEA=;
        b=e6Dk/Gf3aZcg9WZeJz+dmgZmed3avyDi1e7DC94O0qR1IHadphZ+swiNWpwKx38Q0o
         /cVAVDkq/Ii3vuJuPC1bjjyP3Ri4o8W/wqXGIcE7dJSAv1AD5t9/R2oWsjyFODum2tKA
         XgmHAoTqLAiGri4s9S9RsFdBCYZSyyC5elLQHpcytgDJhawzABH8f/67Pffhch17ryz4
         j4XOUXkcESqEd/WXU4PaUNC5voclsRYLJfh+cqpgfEnc97J5OD51oXx5EnXLY+CjwCb9
         lCEEcnw7mX19LvTTo21bJ5c3qHCJ6HK5I16459MgQjIV7rhH/ZR9gRkUxtH1BYYWu/w4
         Wq5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691420416; x=1692025216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3tO2BuViEQ+PTHZcrYNryBbvzEc/M2sC96u3WTWpZEA=;
        b=L0tz4G3AbL5/wNeM97mMTntYWHkMYa/nVn+d6/Fnfkk1iAlJE82Vrt3KOG/+Mj0NEy
         RdD21OhL7zGljAn+7/o/xiAWvhVnHNmxSdA3Wl9MLI2b7MOI+UVeT8pEpPZ2ruCDHNEw
         AXGsINthVIHURyODdnqf0op2ZlaLkVsj+n2i2Up9zHLMmispJtc86BrpByly0IPn7Yn+
         IdYQI/RuLlj65OEvPy9iRKiUECz3ho1Mn3G+/L8vMtdhEtfD0q7taT0B9+kh/CE749Lz
         DspW5th0Wl2e1HamG/tApsSBNmoM/JDHPZeO4CJMVDKkjqGYxqpDX7wVWP+0ESCLJaNV
         ilXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxBbGhFUJyYmSMzUI86KynR7pVSHV2+P8j1ABz3RGRaR8Jpwc1R
	nWbr3Df70/GyeblEocaXKMk=
X-Google-Smtp-Source: AGHT+IFk/QBgjRTWv7DdxG9VToHryxrzXfOMufTO0ax1GEmf0Pbra6IdAaTPhr8IpgV7huJU1puVRg==
X-Received: by 2002:a2e:b1d2:0:b0:2b7:14d4:ce6d with SMTP id e18-20020a2eb1d2000000b002b714d4ce6dmr7001206lja.48.1691420415728;
        Mon, 07 Aug 2023 08:00:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2127:b0:2b9:aac2:6927 with SMTP id
 a39-20020a05651c212700b002b9aac26927ls1369949ljq.2.-pod-prod-01-eu; Mon, 07
 Aug 2023 08:00:14 -0700 (PDT)
X-Received: by 2002:a2e:9f16:0:b0:2b9:eb0f:c733 with SMTP id u22-20020a2e9f16000000b002b9eb0fc733mr7355050ljk.35.1691420413964;
        Mon, 07 Aug 2023 08:00:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691420413; cv=none;
        d=google.com; s=arc-20160816;
        b=CNYiOsVj4XM2jwENoZTfUPCOhfGe4jImDEYvX0KHESFOIWWmzlLzstBQJXPKhRAWpx
         bfNulziahWAj1KprrCrz9g3uK6yW3OiZ93ASi2H3VeIKtjzUWwKM4XRvHTZ3HaQm9d7K
         1zykuLpUz3c+v6Hy9gu5rVf+hRBgNi/KveSGmjSfuCHltJs4jcUCBmgHtjROHICM8FXO
         VGzCw2VJ7BTdPnEHa6btACb2IUZ9rqTiXAeXJLTWZaMN8JZVjlm6zKy3ZsgrdTr0XbZB
         VQmIxIxY8m3FVryJTjktzgjhc0wQEi7N8PptqPSuQM4HvEdrkSkZFQk69S7SZYYXcGzq
         V5hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=YewzmV1KULXjWQuSaTbY2ZFglIvsKLdWDvtxjjTJNuU=;
        fh=kC0MEPFgIv203S+Twf4/za9BgUivXrzFOL/tROBZ0G8=;
        b=TG7hVThIlM3sMSjvb2SpT/pIWf8hIyTGYO0teYvWklpIyU/sdTFHssvPiRlPpwhMn/
         ROBBk7ZWJ9F0gzXJ+yoF5rHyo5Gh4WQ/IjDItyzcHA2Jyw/xO+Pxoj2lHJSu2FXucYJu
         srIiffEXWDtQI3wAMf42CufYHEkmrtUcKFmix1B+fDlIdJ7CTkRp/mYHtMkgNK+qeRko
         KjY5MqUwMs6BRhbEPa/5io/vFT+Z/JbztL490JKVkvmNAk2WW1z+kqC1tITq/P+681Lg
         z4mnTosC76yUA/wdeIB1/yiYmeY97l+A5ek0zFDNujpyatBbEBR26oQWDGSJ0oFtYCdU
         yQPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QId6Wa+0;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id bx7-20020a05651c198700b002b81b8865edsi593238ljb.7.2023.08.07.08.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Aug 2023 08:00:13 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="360651462"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="360651462"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2023 08:00:11 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="760526738"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="760526738"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga008.jf.intel.com with ESMTP; 07 Aug 2023 08:00:07 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qT1iI-00GPvH-0W;
	Mon, 07 Aug 2023 18:00:06 +0300
Date: Mon, 7 Aug 2023 18:00:05 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Sergey Senozhatsky <senozhatsky@chromium.org>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Message-ID: <ZNEG9YbSny86bxmZ@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
 <ZNEASXq6SNS5oIu1@alley>
 <20230807145302.GD907732@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230807145302.GD907732@google.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QId6Wa+0;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Aug 07, 2023 at 11:53:02PM +0900, Sergey Senozhatsky wrote:
> On (23/08/07 16:31), Petr Mladek wrote:
> > 
> > I am sorry but I will not accept this patch unless there
> > is a wide consensus that this makes sense.
> 
> I completely agree with Petr.
> 
> I found it a little bit hard to be enthusiastic about
> this patch in particular and _probably_ about this series
> in general, sorry Andy.

What to do with _headers_ that include kernel.h for no reason other than
sprintf.h (as an example)? Your suggestion, please?

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEG9YbSny86bxmZ%40smile.fi.intel.com.

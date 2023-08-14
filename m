Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBRFH5GTAMGQEJNBNPWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF7677BDC5
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 18:18:14 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4fe56b43af3sf3979166e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 09:18:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692029893; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zi1P1Horq9lIJHDsP+h7sfpM08v2HPiGHtnVPYKVmiKkKIPb5p1OSfpcHwXqJ2xZAF
         YCWTVaIM3xGdFELYSeSBQ+xuOYpFrfNIAW0L3ZsrIXJI1K0t0qo+YLBJHvjfDpc5ntk9
         S8qmiGhW0WeVPA7a/rh0/PQmWw9BEIxDDIb5D0Z7nMS/OVALkFYw5HQoFmJWSHVyh6x7
         QDch2Am18WUkODxc8LBlHPfSDNWD/Q6vkfsWDA+SpzO/4EZl85FRS/R7R57r7yL6qCM7
         FJdjjUi4nfBKAp+D7uUTTPu3ISyMGFyBRnxm2M0Ld7dwKpleRE3cA5lKJickDtw0Xv4O
         BSfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=E1hTJ9lKcKOlBDsEEob67bKet3Ke+vpdcawSwj+XDiY=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=x2j31ub11WcSyOZBym9heEZ+ovRIydnraKeVyexr9XAE0ruOFRX2iGmjjIfbE74Qx/
         K8pHek1ETuKm+ari1NS+Gx3trjtb3TqZLWRzbdb1Vs9ijj8I7VtToZEEnEUg8CukXvoZ
         9rxnDtiA9SiZfQA/4+W62pH63QLFyfR6rulAaSGXdzNfHDWW6Hn7xxGt7Pt68s8zvTgK
         jSjFXmFE8iarmtKfMZif6oM8ZMVb2bOu1mwnyPsK8Mv2YXPLAihjAFHrvRCp0h2rpIq7
         GoZkrjQZgTTft3hkKBscMI74ZZ8uk+maby8Sg7QrKgQDCyOhivwxHnKc1m1bRiiqSa8k
         WJag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ux7EykMU;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692029893; x=1692634693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E1hTJ9lKcKOlBDsEEob67bKet3Ke+vpdcawSwj+XDiY=;
        b=nrs9z5CVGim0ryxIWV7yVNjao4CGlPAsSLbuV6eAK5zzxyFbfooovHF2oVewAVzA0c
         0rS5qQB/unDFNDSXuv7BWvH27pz6E844pBsaNlW0pLiaICYrD9vGaofawtkNXHJ+tGai
         cPsXAwGCBk9oh5qyEDEOtxDSFWNojR36BB1padhKsDy9ahUBS2N8Gdym26KyuPx7G6Ws
         36KCQ9dMU3bFdHsb9IiZFHHwaP9OwbIr0F8pndQsvMLbyuY/SFfNJCrnjRcdiyleI+8R
         /fbr6f+ufGZ9wBI8kVUUGapsTS+zzloZsENxkbvIuKOBmuR8tGDJJBPPQ++zTpMMixOd
         uegw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692029893; x=1692634693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=E1hTJ9lKcKOlBDsEEob67bKet3Ke+vpdcawSwj+XDiY=;
        b=deqW5ntyISqTUGJ735t/szu6aA+xG3FMo1Hhxtf6YVaGaeDQnyVtGdFIyYMxzfhKmB
         CWrVz87HLA5MrbHS7aoRvzI3PMp+xlr3RunhHr3SxnFSID7KYzoeF+dV+e3ZtmmzLl3E
         CGInd3G6/PcnyEyEm3yqUrCjT99q7IDGIAoukrAytIZXRVkp69AU1ri3/nhLcSUG9W+l
         xCOivVL7PcIV76L/m8qzon+V/5D5AY6vL5mIMKPxedjog/8QxOKRO764tHyCkvjfOeHc
         bD+w2G/dR/ox4I04WLydeJgSLS2nH6xLnF2a7vIv57Qik+oCEuWYGtPHONjp6/htLZ/K
         gCLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwBAIeQSs9dpSxeAUbeUUepm0c039Z79eG+VrHHw/YZN42ZDXAt
	LyIkd7ofRROU2haKcrGg74k=
X-Google-Smtp-Source: AGHT+IGpa0tdCaudZ13hn6+5LSqGPrcYnNfl7TFPBEUXB0QpBlyalvZ83JqY93Mu5TiBdwj7+ZAgVg==
X-Received: by 2002:a05:6512:3da0:b0:4fd:d75f:21fd with SMTP id k32-20020a0565123da000b004fdd75f21fdmr9038853lfv.17.1692029893028;
        Mon, 14 Aug 2023 09:18:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5b83:0:b0:4ff:80d4:e131 with SMTP id o3-20020ac25b83000000b004ff80d4e131ls1070lfn.1.-pod-prod-09-eu;
 Mon, 14 Aug 2023 09:18:10 -0700 (PDT)
X-Received: by 2002:a05:6512:3e26:b0:4ff:7004:545e with SMTP id i38-20020a0565123e2600b004ff7004545emr4339059lfv.4.1692029890612;
        Mon, 14 Aug 2023 09:18:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692029890; cv=none;
        d=google.com; s=arc-20160816;
        b=gf/tSAkZQtC18+4uH7IiZZIMt71iHoB4oA62UgsQx+lRDh5fkuPFjDnNlZHtHcf7nG
         gHNSiyKzmCUouk1Q26urjhMMRjKUB+CFfiRe2Lan8Rjb4DVTQ03AsFKx6Jr4OqJJgHGI
         LDiEl2P6xvryZSuIuK0VjE641twS/9mLDUozbCT/tSJevqdsqh2jrL/dLJAXsRbtJ+am
         ZAdVpoFflZhNAagSXsH6xu5OsM0MhbKoOOw2SXyq83SeSI/6g/HUaUS4/tUAWCcyoKTe
         jmRSZVyLAu6SkWfLt2SyP8ExlLNR1QLM3tLwMijhO+T8ikAzL6j/Y0jBTiMR1qrs3El1
         yvcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=No9ltthySzagocc7IQarbuDxnK0QJ1EMK+VXs30lKkU=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=GWuGsFYBTSj7QVs6KBcuEDJ1XB7PsE10o0oJh54/SyaYRqH5SDMTERTEW2M7yHHrpy
         qFHqEhlHkZZveOAnaovUF64L7r7hrP44IdmToh5gUZ7AT4HmlNQgH5cO+0u3vZU6ra8G
         WcGZtG+y8rPkUZrZPruAtprrn75ugmc6TScl23EDL3y7lOflvmBW737REGRLwm/m+JMc
         BYLyZ+0jGIPVJnvzvbKd+PizWShWNrwwTnroj8XgkxCMQO4e1HM/lhb59nEuAzVn4W4a
         XfkmHmCYWPwQRSpSVvFPlbL351ymdfrmBK0K8fKLXKFBqPmJsN9u0BudMsRu9H2pbIQD
         4bDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ux7EykMU;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512214700b004fe157ebc07si767812lfr.1.2023.08.14.09.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 09:18:10 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="369547684"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="369547684"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 09:11:16 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="823500297"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="823500297"
Received: from smile.fi.intel.com ([10.237.72.54])
  by FMSMGA003.fm.intel.com with ESMTP; 14 Aug 2023 09:11:14 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qVa9v-00CAed-3B;
	Mon, 14 Aug 2023 19:11:11 +0300
Date: Mon, 14 Aug 2023 19:11:11 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Petr Mladek <pmladek@suse.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 0/3] lib/vsprintf: Rework header inclusions
Message-ID: <ZNpSH13mUAWyI0HW@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <ZNpKaausydIB_xRH@alley>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNpKaausydIB_xRH@alley>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ux7EykMU;       spf=none
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

On Mon, Aug 14, 2023 at 05:38:17PM +0200, Petr Mladek wrote:
> On Sat 2023-08-05 20:50:24, Andy Shevchenko wrote:
> > Some patches that reduce the mess with the header inclusions related to
> > vsprintf.c module. Each patch has its own description, and has no
> > dependencies to each other, except the collisions over modifications
> > of the same places. Hence the series.
> > 
> > Changelog v2:
> > - covered test_printf.c in patches 1 & 2
> > - do not remove likely implict inclusions (Rasmus)
> > - declare no_hash_pointers in sprintf.h (Marco, Steven, Rasmus)
> > 
> > Andy Shevchenko (3):
> >   lib/vsprintf: Sort headers alphabetically
> 
> I am sorry but I am still against this patch?
> 
> >   lib/vsprintf: Split out sprintf() and friends
> >   lib/vsprintf: Declare no_hash_pointers in sprintf.h
> 
> I am fine with these two.
> 
> Would you mind preparing v3 without the sorting patch, please?

Yes. Thank you for the review.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNpSH13mUAWyI0HW%40smile.fi.intel.com.

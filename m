Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBBGI2OTAMGQEPCVIKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 01940777970
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 15:20:06 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b710c5677esf10299241fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 06:20:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691673605; cv=pass;
        d=google.com; s=arc-20160816;
        b=S07gkLmP6rFm3K6NT+VXU6xmcLhMhf6pNccM3G62BGiz9HweP9O3k4dB3gAvukik9e
         njaRvdhZql94aLEcTjWyDrAGEXFmvJYzYxAOcn48DT1/xR1xf2iZi3yH8cDdqanMjRNb
         oM3x+0C3oqTpimMD3QAMIVVnWSG15x+lWmaNTg0qwiLMaiOHBm3cw0sBfLi478wDC6vM
         b/iDGexfpxRtzXrj2r+YBja/TcBMeFmm1D4j83RuCJ4s3R+qIZw4pH2KsZnQO+DykeHG
         eKxhl6Oazj9hYfQk4QnL7/QHJGxxMKAMGEnjWT3XarFj1SfMxdNrmfRVbh9spOy0eOA8
         imHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=PDaPgGSf2So8wPhmzbnuEMUPUz+LuSQdDa9C4U5MrXM=;
        fh=aVObcHQCuIfb0H24FZz69511wJfVmZKi0IRN1HdeLsI=;
        b=UBnj/IfxjIHDpAOt4B3RpitnCH15d8wtmFDu62zzTrKTvVZ1uD+RMAqYytqvvg4uoA
         eQ/zIiacKt3GsC4eWAqDioaGF8gFJlLw03zR5UvytGSh12qWYpdWfYuDiibZy4EI4ltW
         2TopbE+tYT85LJVtRlP8xaBpD0xVtqwk1rx1P87QjXVvdHTN7GV43uVyadErqTZ1pz1x
         0HKqn5oX5mrr6gUH7ha37loDiRm+8mLOS1k0ZrRq7kU0SzrpI0wMj4Gi1UnhcXs/O2Se
         SDdth76q5kZsZUW7TmxEbo4aneEAlh4CBwakcmuXQIGI3L5YAFtYlHpyDG0Hlo/9pO+L
         PoPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=if+AKfB4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691673605; x=1692278405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PDaPgGSf2So8wPhmzbnuEMUPUz+LuSQdDa9C4U5MrXM=;
        b=DNxi+LAjy8sez6/MqTzXMp+3kL9wYK7B6rp3IbY0Gn7sn8SvzYlYJlz/7T1ui80aP4
         F9haNNj4wqBm9KaFTZCkl0Rkr/5TRrNdzublLX44jdpmRPQTA/TusgQChlHkpaVFw1p6
         CbyFAkBe/yQj8gGPHCE30qViedpReZ7ZRiADoY4ZJZH27TWdWe5NXKTi9avHymhj6EX6
         nWzpPn2bpsJ3w3E70gVZHqUe2gRE/oep/ir7aG8j6z6TyqbmwDjR9vMcaYy+JFtjhs1z
         MqVULQRFQZObtkETT4EtuWYRfN9uaudf1c05Gs8BpRRQCaoJs55x2A8Y4LmuKG2+jT+6
         uv6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691673605; x=1692278405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=PDaPgGSf2So8wPhmzbnuEMUPUz+LuSQdDa9C4U5MrXM=;
        b=ehBHLLYjAmh0XbbGFICE+7W6m84AguMm3ma9zOD9824PLqh4vHNBhGkay2OENx+4hT
         5LgwjovPl5O2V1+L2Owi3IjiKm+CWzeA1WwsT9bwdDJbh2uzFAZ75YwemRbTbKG6kpKb
         luRaI8y4T4WjaBFUWuFCeCeYJyyIQqWmQgGa7MSOYZnlVaUAukqfufyhEhZMP/4/MCqG
         Xqr+hMr9M4ky0dWH75rAxZcBI0mQ2Dcio35pVRl2LpDklQsF8Fxdwr4CoYueVV1LIriC
         4YON3odCQAgn7T71njogreNeeo3dMmb5Hq/5EvWhR5iYyyAsXapmJB/VXG7Vb/ooIeZl
         ecXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxXfQ2AGRYEVelgMcOboRUShEdH3xxUk4T4lVAyDEJkeRn+FTMn
	fnT08XzIBbw9CsX1pHLgqRQ=
X-Google-Smtp-Source: AGHT+IEHDsZ5oLjzrFsYDnhwJxGLnw7rq8j6deVNX82REa8/Ptb9o280DPYGnkSn/UNEdUhnJ0K0Eg==
X-Received: by 2002:a2e:93c8:0:b0:2b6:d700:fbdd with SMTP id p8-20020a2e93c8000000b002b6d700fbddmr1921867ljh.15.1691673604389;
        Thu, 10 Aug 2023 06:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c5:0:b0:2b6:d6ab:415d with SMTP id s5-20020a2e81c5000000b002b6d6ab415dls111362ljg.0.-pod-prod-08-eu;
 Thu, 10 Aug 2023 06:20:02 -0700 (PDT)
X-Received: by 2002:a05:6512:3053:b0:4fe:af1:c3ae with SMTP id b19-20020a056512305300b004fe0af1c3aemr2403252lfb.15.1691673602471;
        Thu, 10 Aug 2023 06:20:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691673602; cv=none;
        d=google.com; s=arc-20160816;
        b=Sua8lqTdYVOCH80GmJ9ctQdKVnISZt5zYGnvbnyTD8PljcrjjBAf2G9iRZLel3Qt77
         DPxLf5SnNxtWlAoHssZxaZt/UW1y/dhmphn1OMGzGTCkbIWY5wZGiPtEcWpyhBhZNZ9s
         qrGMTKr7XtY/g6WzQbYapXzoKrHEx0L6Gd1UjEtEoMBazDFojKmjfWEcechUcSDWxsq5
         CM+ePVYiJrhSHtfgLr1qYUtyWxnkTviU8Dyao67Nq99M3hZJor/cQ1EUFnWDNfHXFGGW
         U2ZULf18R52y9GorG+jgDOYZAs8O6pVXb1jcNN8cbWkrL4NwHK0D9G3lxRrpaJbRAAWe
         RVlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Fmp0NCAT0sso9F3HDosxXjpBSPmGlaxJewcguxYp9Uo=;
        fh=aVObcHQCuIfb0H24FZz69511wJfVmZKi0IRN1HdeLsI=;
        b=xOjMm91a6h5zclH75nDdEqSOayVtJkHdfmL7dJr3KXlRpa3nFaJmoEBltw72aGnQI4
         EG2k7+LsWJP0S4jErQEyw55/no9hV8inGm3wJUugD6xWrye60awUOHLPwgw4UEdSKCr8
         EwmLanLADpJXNvVDMUEqGGPzL9sXMuKTem5nqsrNvTmPYW2yLnJrV7dtih9UFDO/ArnZ
         sqID/jyfjh1RIriQvqZ36MjMo8k9WBDS4ereYmFf5XPoVdkrNXQPitXHs0xy3Er9CVmf
         F5xkA/qM8OlKvEBVpMLJKkI+W7UUpmXybEHsNseVZMei4vsrd2AEhbov72PNDoDzpclA
         lnKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=if+AKfB4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id j2-20020a056512344200b004fe3478235csi91056lfr.7.2023.08.10.06.20.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Aug 2023 06:20:02 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10797"; a="371393053"
X-IronPort-AV: E=Sophos;i="6.01,162,1684825200"; 
   d="scan'208";a="371393053"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Aug 2023 06:13:37 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10797"; a="822244413"
X-IronPort-AV: E=Sophos;i="6.01,162,1684825200"; 
   d="scan'208";a="822244413"
Received: from smile.fi.intel.com ([10.237.72.54])
  by FMSMGA003.fm.intel.com with ESMTP; 10 Aug 2023 06:13:34 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qU5To-002GtZ-1Y;
	Thu, 10 Aug 2023 16:13:32 +0300
Date: Thu, 10 Aug 2023 16:13:32 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: David Laight <David.Laight@aculab.com>
Cc: 'Petr Mladek' <pmladek@suse.com>, Marco Elver <elver@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNTifGaJdQ588/B5@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <900a99a7c90241698c8a2622ca20fa96@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <900a99a7c90241698c8a2622ca20fa96@AcuMS.aculab.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=if+AKfB4;       spf=none
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

On Wed, Aug 09, 2023 at 08:48:54AM +0000, David Laight wrote:
> ...
> > If you split headers into so many small pieces then all
> > source files will start with 3 screens of includes. I do not see
> > how this helps with maintainability.
> 
> You also slow down compilations.

Ingo's patches showed the opposite. Do you have actual try and numbers?

> A few extra definitions in a 'leaf' header (one without any
> #includes) don't really matter.
> If a header includes other 'leaf' headers that doesn't matter
> much.
> 
> But the deep include chains caused by a low level header
> including a main header are what causes pretty much every
> header to get included in every compilation.
> 
> Breaking the deep chains is probably more useful than
> adding leaf headers for things that are in a header pretty
> much everything in going to include anyway.
> 
> The is probably scope for counting the depth of header
> includes by looking at what each header includes.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNTifGaJdQ588/B5%40smile.fi.intel.com.

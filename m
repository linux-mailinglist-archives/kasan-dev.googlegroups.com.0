Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBN4NYSTAMGQE3HQWKPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 443D977286F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 16:59:04 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5223d4b9da2sf3066842a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 07:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691420344; cv=pass;
        d=google.com; s=arc-20160816;
        b=r88XU6/VjQ8qRkJ0Ycr0oAQUresKCx0M0jTsJI8H12MXcOsjIX/iTexDUAHKQ4dP8+
         qiMw17SEwHY3yAiWIQUqyjTXByeTGcGCkWQXO3hLb7JNbusXuCkVn3lifzmZCOLgAnLf
         Hc3EvCSMF4iTA/CYo9f1cyJM3wcRMVLl6sv5LjQC1B9GphSAqEXWVHxgKfJjkinSYmyx
         A301dgaRLThdChXsZXsXn6RrAuas8JtQ1HpUEMBnOzL5wmtynKj4jz38yFiuw1YXwOZ2
         qWWF8iDj8V+xMlmMxhxKZ5atImHBewj4Vp4a0GgB9ScfSQKDtbBut9C0Mx3BeDr6ii4u
         ASnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=zPwIgstyfLvOi4CjyBYFLy+JW8M9K/BXnTHEq44DD0Q=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=A3ZC+Mh7hMqjM0iP/2RICAfECHuksjeLYzkctOXZyc8790P9dVXeci5LM21+qCITJf
         JmWmAh+Fn/UGP/dVbRjH5gJPPkMoaKZ6D5xh8Vh5DCO2TCJvoweRaE6Aw3qJnKfd1Nsy
         TMQP251kqKPpROnQYyPqhw31ALiSzizb43J1K+8jfCK61XPZbr5FWrKfNLN8pCuLHnWQ
         ity+CW0LHid8oEzQG9927RBGL7QgjLQuIjumUHB7KEldA2aFRfeGdzKraYYuwkbmEcNT
         zaFoy+WM6REAl8hCSmLOJrT+Bhhr0h6C590gmG+lCl1dYFkWS5kfVg48H9E9aKR6Kp7a
         cmGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KdJmnK3t;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691420344; x=1692025144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zPwIgstyfLvOi4CjyBYFLy+JW8M9K/BXnTHEq44DD0Q=;
        b=Aq6SBxlS/m6dMmefEr6jlyMCRPcxAgPUTHY/Z5SQTLOKT3oz0ZEffR5ls/ocF8Ucu7
         ab8CJotY706PnRJHAEf0LQM2IIY4vjgDTgi2FVnL3ETbS+Y27bqAZ85L4JrR0boAwI4F
         PqzDw52AjAPZp7mEtWqRQfjIrAdaa01CDgwoFykkd2aR2LoquMSeoXeQYtCfDf79WMxV
         B4F2sgqemPV8S46izsAHvNVkU//APBaZ6TDEz6tgQippujqzNdRnTjSzyE+aYG/as0NZ
         NmVyvs/O8/iEVEKeEncPHt3L4iAbnQkR/pUrgocDO08IG2Eg3IIInpa7bJ+XV0Wp6gcv
         1gDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691420344; x=1692025144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=zPwIgstyfLvOi4CjyBYFLy+JW8M9K/BXnTHEq44DD0Q=;
        b=VkF/ORwZ9e9ssEaRjhWjf+mc93efeciLn4246757cpaU9Zw5k53Rbr/nl/vjf0EXcE
         TfEv/JuMB5MlP4MyiODebEVp6Axe32vPoEzT7M44tYTYMejrnDQEvp3/caoUR9/rr/Gq
         KGv77CpyK7SaCZ8mS87CaWDiikpPigfj2HsI8iWkikx8Y04QmypeQ4rjR4YhhuoO/10m
         QMvzHfIlCTqtAe3ggm2NMStL2CggkITOXZiijsES7dBbP44B0B1RVt32k0QWI8tpDS6R
         ipXmq7mQVF/yOoOMLGq6R8BztMunP9u139rsLYcZIaoI7oyf8RAwPKmvRbNDhRaBxF2a
         vrlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzZu3YFhwArV5iIAkvxeWNyKzquraoiaU7iFpEySfr7GCB7uifF
	MMSQYFYhFYOvH4riDUVBQhg=
X-Google-Smtp-Source: AGHT+IFc5CBAg0mArVYG2cyHIohXlf5XTXwVlAmC+K4mn7lxX9oLHb2ftC9EIc7vGJqXQ/2dngfK0A==
X-Received: by 2002:a05:6402:110a:b0:523:7b1:3718 with SMTP id u10-20020a056402110a00b0052307b13718mr7089890edv.14.1691420343499;
        Mon, 07 Aug 2023 07:59:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cb59:0:b0:522:2aef:23ef with SMTP id w25-20020aa7cb59000000b005222aef23efls50937edt.1.-pod-prod-07-eu;
 Mon, 07 Aug 2023 07:59:02 -0700 (PDT)
X-Received: by 2002:aa7:db5a:0:b0:522:3ef1:b1d with SMTP id n26-20020aa7db5a000000b005223ef10b1dmr7149018edt.6.1691420341901;
        Mon, 07 Aug 2023 07:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691420341; cv=none;
        d=google.com; s=arc-20160816;
        b=qZtRUryVAphlZuMJf40rDuUwwT1CroICFLYQRx38fu84MhBFvrYIbhlU2O+bIWCwdG
         cUpXPPV4MBFSZ01zIQ2YG52shFLzAD6mUfRxYw4kv8xeBia7AUqM0Tv27jjDAZgEPaC6
         F/AsWbdF1SCbvWQelxeM7A52p/5ymJ2NqVuWEMF+i4YBGLeNzkWjRWgwu2ytuDxhx8F/
         hHsgu+jiQwXWszuP/0VXQKUoQAggZ+CFtOc6UmCtaXj7L7SUBnkhsmgP73NYCl1oGq3n
         ZcNsiSDFfq7mM4lSdblxqu7CeRrSqyN3JX8tsPDLfN/IniHHqlNF82i2wwv7qedFOsgG
         amNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wncTibvFCPYKiKKeWBp/BRtDhPuU5ncFeaxhSgM3H9c=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=RH9cKMqUCinK15mVCZiydrq6B2hYYgsRseN3UYBCd3RmkPBRUGxrlxexic3OrxKFyP
         J7vsbK1NUDKazlPABQGn/2HkKiDQSeIxlpP4DKwCxx+41aJMFC4EM7YFDuzRtAgM6caL
         iR7LmYqtwMs/BMWHBzS20c7uYhX1XlaROH1wcqQjuZuerWklYD0Ci3hn0AFRU8HS+Tlv
         QwFNG15uCY4ea4pXkIf0LJAp+KiiFxG1qZGbY1XmviuOQu+X7OG3qndiwQI/g7N5SJ9s
         LUK8cCyzGyf4x3E2358vsn/ggCg5ZdlTELn4Vl6sQ6BKSMyXodXBXKWmXgluJ6s0DWtV
         IEPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KdJmnK3t;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id ds9-20020a0564021cc900b0051fe05f750asi642298edb.2.2023.08.07.07.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Aug 2023 07:59:01 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="350872881"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="350872881"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2023 07:58:59 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="800960674"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="800960674"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga004.fm.intel.com with ESMTP; 07 Aug 2023 07:58:56 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qT1h8-00GNLO-24;
	Mon, 07 Aug 2023 17:58:54 +0300
Date: Mon, 7 Aug 2023 17:58:54 +0300
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
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Message-ID: <ZNEGrl2lzbbuelV7@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
 <ZNEASXq6SNS5oIu1@alley>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEASXq6SNS5oIu1@alley>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KdJmnK3t;       spf=none
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

On Mon, Aug 07, 2023 at 04:31:37PM +0200, Petr Mladek wrote:
> On Sat 2023-08-05 20:50:25, Andy Shevchenko wrote:
> > Sorting headers alphabetically helps locating duplicates, and
> > make it easier to figure out where to insert new headers.
> 
> I agree that includes become a mess after some time. But I am
> not persuaded that sorting them alphabetically in random source
> files help anything.
> 
> Is this part of some grand plan for the entire kernel, please?
> Is this outcome from some particular discussion?
> Will this become a well know rule checked by checkpatch.pl?
> 
> I am personally not going to reject patches because of wrongly
> sorted headers unless there is some real plan behind it.
> 
> I agree that it might look better. An inverse Christmas' tree
> also looks better. But it does not mean that it makes the life
> easier.

It does from my point of view as maintainability is increased.

> The important things are still hidden in the details
> (every single line).
> 
> From my POV, this patch would just create a mess in the git
> history and complicate backporting.
> 
> I am sorry but I will not accept this patch unless there
> is a wide consensus that this makes sense.

Your choice, of course, But I see in practice dup headers being
added, or some unrelated ones left untouched because header list
mess, and in those cases sorting can help (a bit) in my opinion.

TL;DR: I was tolerating unsorted mess (for really long header
inclusion block) up to the point when I realized how it helps
people to maintain the code.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEGrl2lzbbuelV7%40smile.fi.intel.com.

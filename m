Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBZPWZCTAMGQENYZ6RAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 023F9773A4B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 14:56:06 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-317a3951296sf3125218f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 05:56:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691499366; cv=pass;
        d=google.com; s=arc-20160816;
        b=b8Et7v1Lhh43eXAQvUMoql/+sCD0hjjhDte3M0GArH463UWZYPUBSDABTvTRCLJOo7
         V9ycf2U+z2oou2Eu9QAT8dcVCUlWF2R8n114dQHkQfi9SQ/LxbFUIqFeVWM4+cvS+ES4
         Hodoh8JG0GF398leAp8I+bP1l6wLnAmiCtJytsWMnfy0RXM+BE1UkTSxoT7KcxAV4E3k
         b4DeMcqNxQjDV8DlqCZZ0cZkO13HkEJmskZtQSLnfdMY6P9zOPdl6eQ1nswcDJsvKNLu
         MPFUQHTXYAPpVp7czjiMaAi9x+ZpzaD11DluueV4/dDhbWerQtyXeprCiQLPOhv77bUv
         +XHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sY6IdGaEJ1lrGn94+9365cd3KBGk2RdrFa4U1RdH8kY=;
        fh=aZKWQjavICzodXYqF8YKqkykQ9aB4sqRNcxR1QPOtDA=;
        b=OU6tlDhhJUx8qLRqd2q+zg1lymV7VZnkryRY63+2hxHALq6utPx3TVKlSOPUh1bOD9
         n7qo11g7WkNQ7X17HcnB4IhA56nRek6HJx9Q+rVERrz4c3ku59DImfbF4RCn/AhLM1mz
         C6/oLubF6DqM6fLXc44H6izQBv6uLBcTb6SwSHCBvgMrnllvoUfmmqn1tP3V4w5tagBc
         RQDfy6WGWSA+4ADq7BOl5BymP+KSG/vpiNBNJmJhYKgVeeflseCa5qanlkLllqUShL/H
         FH9SrVSyFY1FtUTEBcypFrz776xlshjp7PBXU51UtQJueP0g005C/4i+e4WQGApeIfqJ
         KOTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HyHb1No2;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691499366; x=1692104166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sY6IdGaEJ1lrGn94+9365cd3KBGk2RdrFa4U1RdH8kY=;
        b=oljcII6sYBRFFJYrV0CHoAv8PMhFPOOF4ccdOBv+LYpqZ8sYUDrYYpXsSyC/iwm6PJ
         aRFmx1+O6fUP7n3Fk+sizHWe6xFKlleKC2Jb8l1WaVHMvXfOWYxC/qOmjTcC7PX4WNha
         j+e7oSPGcpivlcGXrUIl6K+YHCdVOxnJMLEg9wNDeCq8fb+No+zQcaq5kBy1jx82VSK0
         hG7koUnF0XwZkcqNdt51o0a3aSlE/GPWZ61mJV3xLyxztQO2cQiZBhPQvOdHAhP8y7L/
         mFJ8CyS9AQkqQxO8Jr/7eeANrWc67VGDtBDG5m3VaCH5jyXOM9Ul11g/EOaQfm5xC9fd
         uZ9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691499366; x=1692104166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=sY6IdGaEJ1lrGn94+9365cd3KBGk2RdrFa4U1RdH8kY=;
        b=Sf194Fx9KlsnY+aS5G5eZA5w7gdawie6iWZPJzci+BoR/UegGbK7/5pOxcTz7yJXwI
         IVhCbpd3bEgWTHkt5yxqIDdf4lv2ts346gu5wC7/iom7cfe8zuOqK9Oq9nwVjwnTWsCi
         NtQg14ujot8479xU2C8AoW0JlhIW0DMNNJ6WNr4qH5k3H3Z7qowrmVytzQUPjPz6a5dd
         m/8K7Z/XT/RHhosGLM6r4RcJqI6XJbj/1vD2to/3cxLc+1jbmohz0Y7rRXF8N+ewKDe0
         p2K6FfgrQEEoTczbWzOp4L3lzJ8LNQqIFAwdEzq6Iu8Rwt0MFeebqUmnISTIVczjxewN
         YMaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YySIRTGwIJ+3LmG9aIob0oGyzWJMGjsns8gMu29oHE7JdSrZEL7
	Hdf4Gp0EGWUD0VlmElFnpuo=
X-Google-Smtp-Source: AGHT+IEnxGoSr6coIZB0f8gyxz4iodTh3X0ThwSvqe5e1wlJtO9sT+EXF7CBXkClU5wLy/YP8ghJzw==
X-Received: by 2002:a5d:5641:0:b0:315:963a:4a3e with SMTP id j1-20020a5d5641000000b00315963a4a3emr8163785wrw.7.1691499366086;
        Tue, 08 Aug 2023 05:56:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4566:0:b0:317:6a90:8149 with SMTP id a6-20020a5d4566000000b003176a908149ls490794wrc.0.-pod-prod-07-eu;
 Tue, 08 Aug 2023 05:56:04 -0700 (PDT)
X-Received: by 2002:a5d:5641:0:b0:315:963a:4a3e with SMTP id j1-20020a5d5641000000b00315963a4a3emr8163729wrw.7.1691499364456;
        Tue, 08 Aug 2023 05:56:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691499364; cv=none;
        d=google.com; s=arc-20160816;
        b=IEzdj6OV0yER7cpso20q8Qz3bViRhJGiJwkr/235j58cwBiwAmjASu3ZFxYtrwqOF8
         uTgeoSXC2SQVr4Zv0ADHNRZ7cPcSR2gq4LBpTbpgpQFnSRxS5tZGd2cZK12GRQS8j+Jc
         bjiz5p4PGGorrgSqvXk+805kdhXBHoH1m7mQFNjd+1u69Ru14nitahjIr+N1K1hlX4qW
         +lo5hU+v5CpqZig/UjkzvqSzJeHc+rGOyINTbO0AAtW48MaCl5kLuu9IaObrS2xABbJR
         Vhu46QetYsqlfKq5jJSOy3XNvSrO8jdlGVv7XPSe70tS9HiLCqLYo0s74wTwMdfwbiGN
         ktsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=cS67AqV0vEV8OwmmHmdU79GFUe04P47dd4NVD9c9O18=;
        fh=aZKWQjavICzodXYqF8YKqkykQ9aB4sqRNcxR1QPOtDA=;
        b=siBEJGsNmK/mxFi5+1sFVqAerPdSQaFdFTMRY4ZnWdLRQSs3YtDagwbm5f8jq3bLhd
         BPvNndli9zlcFCAoegpJLd73tSql5R6BKyyD9tniDOuJWxqJDYwF0bwTdn05757TBWbo
         LENiSGQO7UgCo/lKsP3A9E/Xkva5ZjmoDonYzWs024xkWA1eCamuWLikV5aBO9JjCivT
         YfVJLpqDfAenFRv3CcKY8FceolIwA+9aDLs05ZlbUMsL8BCZuIJt5HEyi3jJJyrJue/r
         r6MWRTVggOiIMB3Uxtnpd0QdF0sVb6cx6U4WfxLFxjLZWdTLTU73GwHiY6McEHVGgfEm
         nwUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HyHb1No2;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id u11-20020a056000038b00b003177f06b59fsi764101wrf.1.2023.08.08.05.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Aug 2023 05:56:04 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="457201112"
X-IronPort-AV: E=Sophos;i="6.01,156,1684825200"; 
   d="scan'208";a="457201112"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Aug 2023 05:56:02 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="708241283"
X-IronPort-AV: E=Sophos;i="6.01,156,1684825200"; 
   d="scan'208";a="708241283"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga006.jf.intel.com with ESMTP; 08 Aug 2023 05:55:58 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qTMFg-008epA-1w;
	Tue, 08 Aug 2023 15:55:56 +0300
Date: Tue, 8 Aug 2023 15:55:56 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNI7XO42WwEtGrCs@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <20230805114304.001f8afe1d325dbb6f05d67e@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230805114304.001f8afe1d325dbb6f05d67e@linux-foundation.org>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HyHb1No2;       spf=none
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

On Sat, Aug 05, 2023 at 11:43:04AM -0700, Andrew Morton wrote:
> On Sat,  5 Aug 2023 20:50:26 +0300 Andy Shevchenko <andriy.shevchenko@linux.intel.com> wrote:
> 
> > kernel.h is being used as a dump for all kinds of stuff for a long time.
> > sprintf() and friends are used in many drivers without need of the full
> > kernel.h dependency train with it.
> 
> There seems little point in this unless someone signs up to convert
> lots of code to include sprintf.h instead of kernel.h?

You can say it to any cleanup work that starts from the baby steps.

> And such conversions will presumably cause all sorts of nasties
> which require additional work?
> 
> So... what's the plan here?

My main goal is to get rid from kernel.h in the _headers_ first.
The secondary goal as discussed with Jonathan to have IIO subsystem
be cleaned up from kernel.h (meaning C files as well) at some point.

FWIW, I have started kernel.h cleanup due to impossibility to
make bitmap_*alloc() being static inline.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNI7XO42WwEtGrCs%40smile.fi.intel.com.

Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBRWL2OTAMGQE7QJTMMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 94515777991
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 15:27:36 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b9ce397ef1sf10280991fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 06:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691674056; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbuXmpIoOIeH8kNQGUmGm1IbgP/PN//IP0DAdLxBROMxTkld3UmEHyYHC7x95C6tDY
         6ekRKIEcI0AGlK0cd+GJIQ/pv+YCelvfQiiE+80NYCYxyoxMkIDJnxZfd5KPQ98nMhSe
         Vi1ZZIs3jjj0FgZvPFRS8uTyUd0tfW6U9J+Ynsn/gg0iVqX4PpSn1hxXy+Yp+QaQHyTr
         uuRuBO4An7cxUfDUfXNyYmWomXLYwZig20+aLyLIbzBvg4LRocNfBObiH/cKy1UMdEQw
         9H6sQR5ibNcYTNJcyzVdIJ7RPNOhGm+pVD1ZPwtKHoKcM3BCt4P8PvhRqaIk9aQvaM55
         7ZQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Z8FGbUR+rhuUUJfteb71bemYBVramdtps1S/YCNxG2c=;
        fh=lNSggOp2LH5a6m9Uq9ySVb/GwR7OyYeDIW3sll4q/RQ=;
        b=FUoPZ1Kx1hCBuOy6W470be9obIRDlBPAtXvbEap6zCwSpj2kCHvva1zN2xJJeVOH1W
         Ni2aeEF3ICuP1WTITVwh2JCC0j0smM372ROmGCD391QKqyI2hZla3muj+y3HQsIvL1Rn
         2sVUJc1NRf8vAmy/JLLIt8SokZbw8iP7802KPPFBkPKCY1Lx2o6/5PnpzUcrO230hPym
         f0j50TNKXgOygYYL1AHFtzd8UmcxiGXpoYgqfxoswZr1at0JXv8a+WTbx9I6S+iHunmi
         aVWchXS1aTYfjcr9RnEsKQvZhpU2o9v40LGjuO/sVafKFg/wBL3DvbNSRH/sKltQVT8+
         rWSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EHeSfamy;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691674056; x=1692278856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Z8FGbUR+rhuUUJfteb71bemYBVramdtps1S/YCNxG2c=;
        b=ZzIhkcdyW7kNhkp9JcY3U/+87td/XQss5I9kj9rZ/0DKj/PTr7EHLwLV3nG4+OJy0s
         7P2shLjrTffnmwZDEGAJeUnpAphBSyYfTIoWYeU3rjhVvIpkGsEkEX8+Zw3YVKudaq5P
         Jg0OgeNz9jXAhUaJBsVyOK70r0swPSSH2HgjrUeRNAmyn68nMYTQDajZyyhwZXSKqFcJ
         lsCKZ4QwPKcOhLUz4Z61eghygsFnSR7AyQi3MK90ZA3pb1j/i9hnTkeD4LkIUnYSIk13
         qy42E4/MjjtJXLMcr5+sF4F1ZjMQC/uDacnFfvG1J6ARqjlUF3An4p1HuFxAO3ANmW4B
         U68g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691674056; x=1692278856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Z8FGbUR+rhuUUJfteb71bemYBVramdtps1S/YCNxG2c=;
        b=DL/CWTC/cYjHrvLrlnDE7SP47wOPwzaoFjr8bbsfBMhiZELz5CJwO/qG2xlfRsfRBa
         GGh8s/Ppu7pA1uzotQ5I7mCIrP9/CiXFZBq7wZD8oF73+3l3MJquvx/Fb7Soiw3+lB3o
         L8dgl6vFx86Mad5kk2gclexJAisWLHRwI9TFJcEXSYG+pkzFjfj0qWa4+iDGxTTlgxcL
         59zck5LW6w88sdlcQNx7cAul1lLBxkCQ5upudD6b/TOFsSOpDm2t/vNz3JfoZCK0+S5c
         smIcwvNdTDHE8jRAA4PhZsHiPSIsm//2gLEg519wxyb8gcW+wcxwKztZsVQGu5zttZbq
         TMDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyEz8GB3Nl2QwAGSB4P2wvAwmC2V4h7KKM029aEJqFMP/tc3HUV
	L+AgUde1K5iVWDuqhk9WJQU=
X-Google-Smtp-Source: AGHT+IHvyJi8zGVv1KjzISc8PeiwL6j0+Ic5hGGhW1AUsoAucQ873MSo6jWBYGT8uWzC7SMqDcGDAw==
X-Received: by 2002:a19:9159:0:b0:4fe:a2e:890c with SMTP id y25-20020a199159000000b004fe0a2e890cmr1762676lfj.49.1691674055178;
        Thu, 10 Aug 2023 06:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5053:0:b0:4f0:9517:7df6 with SMTP id z19-20020a195053000000b004f095177df6ls330195lfj.0.-pod-prod-06-eu;
 Thu, 10 Aug 2023 06:27:33 -0700 (PDT)
X-Received: by 2002:ac2:44ce:0:b0:4f8:5886:186d with SMTP id d14-20020ac244ce000000b004f85886186dmr1667389lfm.9.1691674053421;
        Thu, 10 Aug 2023 06:27:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691674053; cv=none;
        d=google.com; s=arc-20160816;
        b=sdsmAkaazjWG9G9ZA1XDsdoo4yLzVajbxAXjNQQbmHEB6D5+JmTgVtqa+dM6jqyIFZ
         k0x+RXs5POasEnKrhTPgKcPESLCUSic8kOKmp9vzQgOiS5KvyhvxibzdKm+9gm+M7T0X
         Ed9kfKqQh6/v5dIbBKqeJkTTAKpSuM9Wo0UR7OCrAWQLa5YhfN36RTgvdiNyCMlLjQvh
         3YKbUEZIqJ48oTQVhu8tjGq90H0dO8zlQ0G9IQqNdGsxyce1CGh0y1Gz8SPYL4+4LGNR
         DNalUVxzt26hjIMDHhYQWiHJnj3HretDe7+Ng80y9rXUc2DT0gR2O+a3K/eqWCXrqWRn
         lpCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UFBYT5tzI4z4icu73XhQu5b0aU+HQ5Kc9/dN5xSAkyM=;
        fh=lNSggOp2LH5a6m9Uq9ySVb/GwR7OyYeDIW3sll4q/RQ=;
        b=oMKaJngdBmq1mRfyI0kKklKbXQ5jmigkliCAffs/AOA+nBW8JeOBM24aqTXHLPEpti
         klUl9Hw4Vg7GcF+vfHVrMQamf3QbiODKyvtFDdC57+9TJN6NLZPTYiYafozcTKxzCMHT
         wO3I4HyzCJZvaDE8KbH6Pfh1hvSa9N0blmNgW3eXiId+DRelwE223tvkJ9eY3xalD2tS
         gOwpDlH29/E+2Rg2T2g3jm+5GIyIlFxki0sjHoZ2Or3J/TlsEeMyouMoxB4hOXynrFrb
         /jHguGQsEVJVf9H0RfeekDsBqIR98MbERpxYP9LjEeFFGmfKJnBDQOmy3a0j1CWS1R7X
         zaRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EHeSfamy;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id g5-20020a056512118500b004fe3ba741c8si97035lfr.8.2023.08.10.06.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Aug 2023 06:27:33 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10798"; a="370298864"
X-IronPort-AV: E=Sophos;i="6.01,162,1684825200"; 
   d="scan'208";a="370298864"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Aug 2023 06:17:40 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.01,202,1684825200"; 
   d="scan'208";a="875714029"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga001.fm.intel.com with ESMTP; 10 Aug 2023 06:17:40 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qU5Xj-002PH0-0V;
	Thu, 10 Aug 2023 16:17:35 +0300
Date: Thu, 10 Aug 2023 16:17:34 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Steven Rostedt <rostedt@goodmis.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNTjbtNhWts5i8Q0@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
 <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EHeSfamy;       spf=none
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

On Thu, Aug 10, 2023 at 11:09:20AM +0200, Rasmus Villemoes wrote:
> On 10/08/2023 10.15, Petr Mladek wrote:

...

> >     + prolonging the list of #include lines in .c file. It will
> >       not help with maintainability which was one of the motivation
> >       in this patchset.
> 
> We really have to stop pretending it's ok to rely on header a.h
> automatically pulling in b.h, if a .c file actually uses something
> declared in b.h. [Of course, the reality is more complicated; e.g. we
> have many cases where one must include linux/foo.h, not asm/foo.h, but
> the actual declarations are in the appropriate arch-specific file.
> However, we should not rely on linux/bar.h pulling in linux/foo.h.]

Btw, it's easy to enforce IIUC, i.e. by dropping

  #ifndef _FOO_H
  #define _FOO_H
  #endif

mantra from the headers.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNTjbtNhWts5i8Q0%40smile.fi.intel.com.

Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBOPUZCTAMGQE22APIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A124D773A44
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 14:51:07 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-4fe4ff53de4sf5504927e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 05:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691499067; cv=pass;
        d=google.com; s=arc-20160816;
        b=oY7eqhNfm1x68XubsPjrpf4TzMhP8qwoij8EKbsguny7fkc4yx0emGOpKylhg5V6Dm
         aEWwP7JdAYHukOrjIF6wcRjUIT8fIG2kK0ML6PXxQEBrkTB9QDjT23rKrU4HNZ66xNPt
         AtP3n09ZPyRzXY6zW6/LwCBDMrQGhrcHc2ouoLeZAK/l9xou3CreQKIdR2qgBSWmu2ox
         Ud2SXFpFckj5Kj5oGNJdelCnCt0N0TGbDmpQzvbIQHjDhjF1+Mh/OI6Vb+vvzxHiVGAh
         30zSTm6yz8zVE3OsxoSZwIVE9ejDNSQTbL1GtgD6S8lOJMTitc+hBgnJzbkwh3TTMiQD
         wwyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gQJjlkW07SkIo7FFykfwPY/YIg+cT3Zs3VEQT0Gy6G0=;
        fh=J8lwpheDG2nnnIgEay13Ip2qo+FJjLxdcKa96+yY5rM=;
        b=Q33+z98RQG1FYu9zV1u6VrtCpkAsLCwd+70sfcs9rtKlCWAPJM2s0EAocOa29coOWF
         7qsy9fh9PrhvJ/lmrjePdde+V1eDr3lJBt5aRvFbb2sZczyale8Zw8Lw2xbt84Fk8zCl
         m3vNRu697QCBgQ5IYmIO3VxGZDtDIwliuWxiksz2KzoeeeDGIYTdroeTpvHrv3GTUPBE
         nzSwGLFXTIXSeXQWtQL/3lJxU9mcaLWdmGFfs2B1UkODyllLoYiSRXNKX8AGn+F2HIeD
         trrX2a50AfPzzsCvR6fR6kDLPEP9h4c/8ooKLYGyssmec7+xXct099q8gXyp2DK5TQUx
         RG3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KWQR3Nqr;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691499067; x=1692103867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gQJjlkW07SkIo7FFykfwPY/YIg+cT3Zs3VEQT0Gy6G0=;
        b=RwMCkvzDEhS6wp/wKNMOV5wwB3f0B4/E8fGG8LOC2jdnNHKndDF6IEv9a/sMOq7OHP
         ZE8rrvZ+DFVAI0M4adEKaUb8j8LGHejtSh7tSH6xd+7+Q0TaULHjkAoL4dIyImdEb1S0
         Z+2PHhSD5UVJesBM1oT+LiSR2zH14cCxkOEkHcmRr/3h4tQQonzNw52Sf/40TAGxs4/g
         HOuZAq5M4P6z6UM7S7om2vXxJzQfsvQm4WjmnvU2kz3usNIoalOE3g+72CirlUxFqD+D
         STrhiQZQzsqMiPZMy+srBrxWusXuKsPo8WAG996ePAlGtliJwFJo7BZ79cuI7VYj5O2S
         Cggg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691499067; x=1692103867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=gQJjlkW07SkIo7FFykfwPY/YIg+cT3Zs3VEQT0Gy6G0=;
        b=ecL8F6QYAtO6PGBt8IS5C4gOqBAf2CrYXSsunBRzRolNNMWUv0/bOTAQVFAniXXcyF
         uqFI8WeIEANnjT+cl8eYceGVxoE8kFe3kvvqpWyzBkQc1xfiODorQe1vC9kqU7+dkLer
         eArH5MrI7OhQaRlNGoRPdeEthIokIrrPOXHy0YlGUzZTlxSyXr7t1XGQhSM+LHe/+3Pv
         UINpAxRnq1VDdkljqGes5g13D8GbfaZYKQm3D3F58ag7agFBKfFVjj4NCNWCCr7SUGAo
         XIqHoHZB56TI3F9THm/r4P5OrIPEIEfsFn/73FGs2vTOArT/cPLI+R/u+iNFrvoY2k4+
         B3YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy8uoUqHRw0rx4vY+lsmC70CUv4ypJjepPci2QBGn8jzAaHUbYh
	HSsN1DVLL+OYxoqX0up6msFBhg==
X-Google-Smtp-Source: AGHT+IH8QdbWMf7jnWYhyL4tRZDVUxzBObXWNNFqKNebYHnYAT1BFNuYIRIy99w8VJd2dNHXMfxQTw==
X-Received: by 2002:a05:6512:32d1:b0:4fe:c53:1824 with SMTP id f17-20020a05651232d100b004fe0c531824mr8156120lfg.40.1691499066079;
        Tue, 08 Aug 2023 05:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:534:b0:4f9:5662:5ef9 with SMTP id
 o20-20020a056512053400b004f956625ef9ls105758lfc.0.-pod-prod-02-eu; Tue, 08
 Aug 2023 05:51:04 -0700 (PDT)
X-Received: by 2002:a19:5e1b:0:b0:4fd:ddbc:158d with SMTP id s27-20020a195e1b000000b004fdddbc158dmr6775424lfb.17.1691499064364;
        Tue, 08 Aug 2023 05:51:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691499064; cv=none;
        d=google.com; s=arc-20160816;
        b=PvjQrNfuakr8V9Ivvq/whnk/0LWSYup2DRCqBJqm+4VH3S4jPRHBIrfPpHspIgAaHA
         8VO7J31whp701zpSG/UrHCD9ySeGVZ/+PsplF45mBGnG3tVG1bWEqKuMYdpFej1jJrje
         b7X51UNpANT8C0XvjPx/AOrDBaYSTpJ5f3Sfmw+i5Ar+novuBYTXT58obocs/Ugvx2hy
         xdnX/aCuTJZDureQ0uewvg4xhCALoQIt39WJ/NX91yq0gq8rgRYbKkxYM/gEkZ76YkAw
         cALjizrJreXTS0ZT7XePe20kADFdkMGc+G9X27Z8Qoxdw9RiopA3JZ6hK9+MZSMkkrkD
         cyrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=c717CSUcQPSlow7vY+l0D1zfE/3ZWjsjq52MhwiY9jQ=;
        fh=J8lwpheDG2nnnIgEay13Ip2qo+FJjLxdcKa96+yY5rM=;
        b=kw2Rt1pSEE8AgwHM0evCACDk6nu99NUgI5fTA7NTqSO6wHHZKELA9rGJtXcnHCAE6s
         00NdUkS8Mr3ilO/gToS9qINvFAMy/agkbOo1+qIJM/aZQt0lZTWgFVoYJ9BLonxhmxpB
         tK1xh5tJok6/6NUgqwVp6RI+3JBHUtdO7PuOWi/Wu0Rt4261DrhcmUaa9NNkCdv4S/KU
         UtX/JQXf05mlpGguFY0XeASqGwBNbLaH6QLCkCzTU1rzudtBo+vMLduanrGHs35oh1yg
         QhXOkHVRhoOsG1b7Lla41MtGIHiBHr1HqddhI+x/P4ZyME884kPDraFN/2iuhvSwhlaL
         m/hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KWQR3Nqr;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id u8-20020a05651220c800b004fe3ba741c8si774500lfr.8.2023.08.08.05.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Aug 2023 05:51:04 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="369711747"
X-IronPort-AV: E=Sophos;i="6.01,156,1684825200"; 
   d="scan'208";a="369711747"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Aug 2023 05:49:59 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="681226171"
X-IronPort-AV: E=Sophos;i="6.01,156,1684825200"; 
   d="scan'208";a="681226171"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga003.jf.intel.com with ESMTP; 08 Aug 2023 05:49:56 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qTM9q-008S3O-2i;
	Tue, 08 Aug 2023 15:49:54 +0300
Date: Tue, 8 Aug 2023 15:49:54 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNI58vThL83P4nRY@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <20230807222455.27874f80@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230807222455.27874f80@gandalf.local.home>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KWQR3Nqr;       spf=none
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

On Mon, Aug 07, 2023 at 10:24:55PM -0400, Steven Rostedt wrote:
> On Mon, 7 Aug 2023 18:09:54 +0300
> Andy Shevchenko <andriy.shevchenko@linux.intel.com> wrote:
> > On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:  
> > > > kernel.h is being used as a dump for all kinds of stuff for a long time.
> > > > sprintf() and friends are used in many drivers without need of the full
> > > > kernel.h dependency train with it.
> > > > 
> > > > Here is the attempt on cleaning it up by splitting out sprintf() and
> > > > friends.  

...

> > > I agree that kernel.h is not the right place. But are there any
> > > numbers how much separate sprintf.h might safe?
> > > Maybe, we should not reinvent the wheel and get inspired by
> > > userspace.
> > > 
> > > sprintf() and friends are basic functions which most people know
> > > from userspace. And it is pretty handy that the kernel variants
> > > are are mostly compatible as well.
> > > 
> > > IMHO, it might be handful when they are also included similar way
> > > as in userspace. From my POV printk.h is like stdio.h. And we already
> > > have include/linux/stdarg.h where the v*print*() function might
> > > fit nicely.
> > > 
> > > How does this sound, please?  
> > 
> > Not every user (especially _header_) wants to have printk.h included just for
> > sprintf.h that may have nothing to do with real output. So, same reasoning
> > from me as keeping that in kernel.h, i.e. printk.h no better.
> 
> If you separate out the sprintf() into its own header and still include
> that in kernel.h, then for what you said in the other email:
> 
> > What to do with _headers_ that include kernel.h for no reason other than
> > sprintf.h (as an example)? Your suggestion, please?
> 
> It can include sprintf.h (or printk.h or stdio.h, whatever) instead of kernel.h.
> 
> What's the issue?

The issue is the same, printk.h brings a lot more than just s*printf().
Why should I include it for a, let's say, single sprintf() call?

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNI58vThL83P4nRY%40smile.fi.intel.com.

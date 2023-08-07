Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBVUTYSTAMGQEUUFP5EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EEDE7728D1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:12:23 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2b9e8abe539sf45356661fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691421143; cv=pass;
        d=google.com; s=arc-20160816;
        b=l3/WCPeEVDVSYftdd5NmceqDpkTHVGDxzc5j1Geqid/ngTi/qUIynMriFF1F3hdjdw
         dZGjtf3pIWTHSdjBuA4re/FqvaABKC/v/qVSLOyGP0urSqWn89rj2OCNJnPe2uteZII4
         5CxBLReJYfC459/TVbClkGSH8FvXFsjDKpUhjBn7mB8UU4oX5JLWgcpqJvOZrZxwhy7o
         4rHoIeZux/fh6YarMyc423YOD7FAZN8Y60Asj+2hs2f2MSChcDQDDO5SdJmI5za2JQg2
         ZQskXWZQ/MKmL4ejSox9IIOZM9hbJP4FKnilM2pGzmVylvbStGyiNzLWGFCuvtwjjex/
         LpvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4zgdMd8CRNvACfCeFSLaLRs8070MDJZDjiinmROqtAY=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=ghju6bzWuFAnvqi7cLJ3UlzajQxROAoJNFS+a67qGFNBp8BdMeP7l4RRGwm3Em8KtC
         csQiXi8Qvt/RV928V77n72EgTq514oIl0tqQBcTUpDSg8e9eeiaxH8XrgFjeEiKM9m5c
         4j5Q/fK1sr4hEuIs+/+Vq68jqFPmFdUpaCz2rMjMjhI8rNs5fXrMO1KK0CHDjV6byv/4
         HYoMwneFlh+nl0xbqUoiNARJjsltunBaFtEGtJ1eTwLkPyFCyS5hGyaGotUdqho0xvRX
         c4oTB/mOIg4ILBVWgxidPIcMyBa9JwXRw2KddRQlTJ68Ip17rbfLLQWczs3EjzmF5tXx
         ZAtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VX8rVyuQ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691421143; x=1692025943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4zgdMd8CRNvACfCeFSLaLRs8070MDJZDjiinmROqtAY=;
        b=niYgyiKFw5j/+WIu9cLTXYgmHnlli9RVnMXTX4bi4gfYxaBEvuanOdfsUubHEOePeP
         RyIXuRLGTscrn9ITOCzR74TfpIItFqBrt5Apqx3OWg8RI8ueGHUfoiioN4UBUeFehFEo
         XbisYlE133/MSFl1vlK4I8jUILIiiAlwlp7foahjhH1VqPzs6PeEyABUQQfl4e/mIFpz
         SxblDaXRBe+bJffCHFCHRCSEuhBAAzE7CwfddVRpRTsSM3m/u/hjQYBtskpKhrHxFUij
         7tK0ymR/2FwHSvOw5CBuPWoHdUKO7vy3VzrEmo4DMb5FQKfODCxr5Xurj4Kjs3JNCurW
         tH9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691421143; x=1692025943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4zgdMd8CRNvACfCeFSLaLRs8070MDJZDjiinmROqtAY=;
        b=G3PVlCrZLgul+9VNsOsVgmF1XqxGfweWTuNWjCN7V6PaAFjNLUAA1UrF4+BGvtRcjV
         sTljQhxW6AIhHzS0yCEGfX6z6ESGi97L1qku2QDf/fplHBGTKU74B/fwSyV8BsA78o6h
         PGp6GsGs3ieu2woWZhTiKcwZAhZ3Ebd/DRjWimWaiQy2iWwLSMaVhPD+16vogaQeml8J
         WM8Y39g35GZrDxTjm1GYLFyoFv1hEEAO1F7sMIQ7tRI+zzBlAwulJyLZjJiZKEo6y0p5
         9XFMiJFGpUgGSEkvZ99jjVhmoIDHKYvmuKJOACcpj5a/j8iyAT7yb8GdSxUOaFWNcud4
         Xfpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxmGJ8P+P1J7vSq3iHZ34QldSij8DwslvTmKc20X888MMu1qfPn
	8qQ0w457R+cU+Mf01ppYt24=
X-Google-Smtp-Source: AGHT+IGDAFEtsadGE1KNZxEvbFRFRvVRBDzf47VEAuxmLadgy04wNH8OOvZ+Mq4648hOCgMme9qoDA==
X-Received: by 2002:a2e:9e13:0:b0:2b6:ee99:fffc with SMTP id e19-20020a2e9e13000000b002b6ee99fffcmr6509379ljk.36.1691421142314;
        Mon, 07 Aug 2023 08:12:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c8d:b0:2b9:5e1d:de39 with SMTP id
 bz13-20020a05651c0c8d00b002b95e1dde39ls419781ljb.0.-pod-prod-06-eu; Mon, 07
 Aug 2023 08:12:20 -0700 (PDT)
X-Received: by 2002:a05:6512:1598:b0:4fb:8bea:f5f6 with SMTP id bp24-20020a056512159800b004fb8beaf5f6mr7991227lfb.34.1691421140600;
        Mon, 07 Aug 2023 08:12:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691421140; cv=none;
        d=google.com; s=arc-20160816;
        b=D5wrr7Df1WPNPAm7Y/5TvUmfQnJ//gFiU5w6yuomSbwyenuc8HtnWDzh0HGJ7MD1nY
         XRs6DTGF4xel0uxKS5sceWKU8o56trzaOMjMk3EvyNHJNBqo71kwEMODTo6gFQwMPLDT
         lzuzCUheGIXlLdSqIcPxZ8T7OnlU0OjKEgHFdLQfC7maSE16CI9YDakAo1+ZHMG6EVUr
         pxhBYoq5759gafuQxJlNEucJQBUEwm8gxaW9zLDSyxhJwxwrRACVk59cY+CdRL1oyT1/
         Ri4RHGTnDJX3lT37pLVUDjdlxrYkqmvY+VwlfNbDEa5sKGvhq3NFnhfohxTrhZXSBQJN
         ZfUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=guMrud55VTtcvPdgdTU777r0FixjH6cD/wJk+UegkBQ=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=Xqm+eNHjqP1/G4VhSmuy0u6U9y4X5oQeepaedRaMzbXi/URIAiOpJkvkQt/2ygH5A0
         pBa75UnT36ls5+Lv5dJ0lRlqMuBsO/2pGJmb+VkoJVO5O66kfWto0Yojp8om6FF+ExUB
         ZhUpbbSPlxgXD2ViMAeO2ds2rntd5BeGcyY9q+sLaAw7urkkI2pPD4WmUBVbaoLGe0dc
         2winbFTH+ekRD+MgnO6rOIWFfN88kEMFHqNo002I1AAE7btgmZxfBa7qTkpUXeKdF5AQ
         p5P7/L/gh3uPLXdOjyv3l6Czi0+xy27WsyaZK54hpgBJ2oCBYSr887Wv0lxGo3zDGcph
         SHQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VX8rVyuQ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id v2-20020a056512348200b004fe562df054si536460lfr.4.2023.08.07.08.12.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Aug 2023 08:12:20 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="434417648"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="434417648"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2023 08:11:29 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="854692563"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="854692563"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga004.jf.intel.com with ESMTP; 07 Aug 2023 08:11:26 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qT1tE-00GnnI-0l;
	Mon, 07 Aug 2023 18:11:24 +0300
Date: Mon, 7 Aug 2023 18:11:23 +0300
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
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VX8rVyuQ;       spf=none
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

On Mon, Aug 07, 2023 at 06:09:54PM +0300, Andy Shevchenko wrote:
> On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:

...

> > I agree that kernel.h is not the right place. But are there any
> > numbers how much separate sprintf.h might safe?
> > Maybe, we should not reinvent the wheel and get inspired by
> > userspace.
> > 
> > sprintf() and friends are basic functions which most people know
> > from userspace. And it is pretty handy that the kernel variants
> > are are mostly compatible as well.
> > 
> > IMHO, it might be handful when they are also included similar way
> > as in userspace. From my POV printk.h is like stdio.h. And we already
> > have include/linux/stdarg.h where the v*print*() function might
> > fit nicely.
> > 
> > How does this sound, please?
> 
> Not every user (especially _header_) wants to have printk.h included just for
> sprintf.h that may have nothing to do with real output. So, same reasoning
> from me as keeping that in kernel.h, i.e. printk.h no better.

(haven't check these, just to show how many _headers_ uses sprintf() call)

$ git grep -lw s.*printf -- include/linux/
include/linux/acpi.h
include/linux/audit.h
include/linux/btf.h
include/linux/dev_printk.h
include/linux/device-mapper.h
include/linux/efi.h
include/linux/fortify-string.h
include/linux/fs.h
include/linux/gameport.h
include/linux/kdb.h
include/linux/kdev_t.h
include/linux/kernel.h
include/linux/mmiotrace.h
include/linux/netlink.h
include/linux/pci-p2pdma.h
include/linux/perf_event.h
include/linux/printk.h
include/linux/seq_buf.h
include/linux/seq_file.h
include/linux/shrinker.h
include/linux/string.h
include/linux/sunrpc/svc_xprt.h
include/linux/tnum.h
include/linux/trace_seq.h
include/linux/usb.h
include/linux/usb/gadget_configfs.h

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEJm3Mv0QqIv43y%40smile.fi.intel.com.

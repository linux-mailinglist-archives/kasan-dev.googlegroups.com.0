Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBXESYSTAMGQEYUGZZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C0C7728CC
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:10:22 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2b9bf493456sf45628431fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691421021; cv=pass;
        d=google.com; s=arc-20160816;
        b=SsoFOfwYtZtBureTC9RNanfvIwxZVv7JeqMIPa58xoYzkvkt7cDqAK27h5Z+WoYmIh
         kwxU7zlGkOC87KFhtKKtZZImFTX1iQ2KJzGvzS5jYJ7vTs1GkL+mQIZFbnaVbyLvJ4Qf
         gosxwX7BeijbZT9ZQYe1e3/vdeSWHmDopQ0jNGfJS1LiwrPMWaz9Y2IE2IILQrvuua4c
         E607B0uRly0DlfNzn8SKsT1CqoF7guNziyewKCmfxtMdZFtRWB49l+RUZKkESIuznc4L
         k0fySD2/6AzpfuIov3mdnOIufZ34hc9LcHCau9GWKuCTJDbNq00n9fq8HafyeKkZdJFj
         LfcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=i40KaC7btvcCLb+VDYwmKG0xA2psHdi4nc56WE4vyBc=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=MhUHk/g20egFYZVT7C6yRo87GcHptAYLUAwtRlqIc3/Qykz5vUnPc4QcVLLSs/wV8O
         xyxkdHpfLQhACFOZTHaXAqdalypaLBfLUycgOHXtIbNlYapyu3RGn7gpTtMwtiLH38rR
         RBjfBDH04FxAV+BFlm1kG3LcFzFKV3mVDemphiLyscxSupujOnlUwFn8Jk5Maxew3UzE
         gIKyS68gdBDbGcrKWTNbl+bvzJ69d8bhi/v1VAtZuJ1X+IzS/oJ68rMZTDS9oJSFT2iQ
         HEY9Sp/TJgR3TSGZy0gKvCJgvW+dnQK0qtTiwpJG+NWFDi3OPdSW0Ew3n9cfsp7RRJMM
         drVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Z81dPEGj;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691421021; x=1692025821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=i40KaC7btvcCLb+VDYwmKG0xA2psHdi4nc56WE4vyBc=;
        b=cyQGAhAY55nLIl1Y9DkBuLCliRwmwf4xflluqI2SFopDjvQTP6sv2oEoepPYzProND
         yZCHDsmXElZUQyhXpalDQ7LLHx+4xCV6MNEl0npBog6ivZ42fhi+vaA+dp1VQmD51uSv
         BFeIXCJgJWG5tfYBkDqw6bgpZAJOjxXYNBmBAGemTF77roDuf+rc/ji4tcnxUysxMysr
         i95n21OVW8AviWB8bVW/JB+qCZHO7iMSpDVFmhv8Jbdu6Kqc4H97YGFDNLDCJZrc6Mjd
         iYTP4cQYIpfAF9lRsRDFj15nuW+7eY+0cxJjAy0mtEJPh0RNSPlcUhuMgelKCeOjXCc+
         qO+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691421021; x=1692025821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=i40KaC7btvcCLb+VDYwmKG0xA2psHdi4nc56WE4vyBc=;
        b=GigPDPI2M/ttjd+QV5qcDn5g5i1wEE7r2lnwVul4+IRExivt55GvB6C9eBjDHHz52S
         9nObOSliAEZ4OG4eAVvtBzUHucG9fjiJSystg3/j8zw5r36Sn+auoeqhKq4Bi5MTlIgQ
         9RcW0/Jh6x1PuiIabvZOg2/OOWz9gGAOjThG2/PWPYYsc6+i7ssQyZHzzp8NvKh9iUY3
         gxl9goVOyiav/78lSWFFfC92Fu+Mlv6YcGk9q2ZWDJqgpXjihkZCf4BcwC3HR9A7ytKC
         uxgln2z5fE8ZutVfU+woth4kv43oKO5Db8ejLPExGXB/HRlBfdVNRfbxJBHPgdgReT0J
         Od6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzi4gqPhCaJX/RpIHf2rch+Hvmy9lTyU07++vb+HMBBTOnH9k8l
	rxCRI6BYVSD8di5xUiX1EuA=
X-Google-Smtp-Source: AGHT+IGYBjfouR67Sv3WrD7C4+j3nSX6IPsWhfQWMU5Y0vZxQUloQOuKzqEUTRm2REG9E5NUd3RBwA==
X-Received: by 2002:a2e:850b:0:b0:2b9:581d:73bb with SMTP id j11-20020a2e850b000000b002b9581d73bbmr6472715lji.26.1691421021120;
        Mon, 07 Aug 2023 08:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1b:0:b0:2b5:8027:4784 with SMTP id b27-20020a2ebc1b000000b002b580274784ls74874ljf.2.-pod-prod-07-eu;
 Mon, 07 Aug 2023 08:10:19 -0700 (PDT)
X-Received: by 2002:a2e:b0ec:0:b0:2b6:fa3e:f2fa with SMTP id h12-20020a2eb0ec000000b002b6fa3ef2famr6203023ljl.32.1691421019195;
        Mon, 07 Aug 2023 08:10:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691421019; cv=none;
        d=google.com; s=arc-20160816;
        b=GDWMy01A9KmJmuKJmo9IspLl8OJP6tp9hKCyEOgndWCIAvaMvXFvIJjrI1eEOh9drT
         jyL/VTU6qQ1p/KPSv3kk0lJ66SznU+dRwF1pCggHwcUyJS3EzQ0iyx31aaVlfQlomgRb
         OvZpdx3e7WptsYYdbUn2dx+yCVgOJlQJ7uR38/9orOLE0Z7snCzYtWP6LIGcgTYFe+rC
         k/4LUwrKQYGwMLBD6+6BP4tun75BHQUAfzc4vb6eAjXg6K2q/KGP5SKsfn9CEGVW9v5V
         i5uBHrkjzW8GGk1HN2NcwXlLATHTSnk/vcbM1pdbgOW7QUgrqcprIN1SL89LFEI02fVQ
         GAPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DBoloknsgWCBv8GQFCwXllkjZBxlmNHMZzvDZYgVj+U=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=0KXZPI93ERh4hK/AYWCQklj5zhq2KMWM+e2PL2s1xFiXiNj6GkkJTPPIL+ALNw2lfG
         7kJrf94MapesdorxY8FWotJLlrPIxqAVGZXMqww9PCUUUJfnmad36wBkWRAMiRavt/hv
         PMm+oou2pzO+u2rub0L/jlgP82K+bQP/U99yDMYh60RKzF8jWvPd5vMFKEU65QyHw9/u
         fwVT3E+P3cYac3zSJBMfS19/C5ICicQRq3U0joa9NKluPNzreLl6P6Mt4tNAuswYSP73
         GgLXWZp16YgHt5AJ9mH8nT6bXuUhZagyfOPuSuUXDK6ukLkY2IEx4FGJ+ftO9tU/CaZ1
         5E4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Z81dPEGj;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id x15-20020a2ea7cf000000b002b96150efccsi625174ljp.0.2023.08.07.08.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Aug 2023 08:10:19 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="374246592"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="374246592"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2023 08:10:00 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="904797907"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="904797907"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga005.jf.intel.com with ESMTP; 07 Aug 2023 08:09:56 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qT1rm-00Gkcv-2K;
	Mon, 07 Aug 2023 18:09:54 +0300
Date: Mon, 7 Aug 2023 18:09:54 +0300
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
Message-ID: <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEHt564a8RCLWon@alley>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Z81dPEGj;       spf=none
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

On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:
> > kernel.h is being used as a dump for all kinds of stuff for a long time.
> > sprintf() and friends are used in many drivers without need of the full
> > kernel.h dependency train with it.
> > 
> > Here is the attempt on cleaning it up by splitting out sprintf() and
> > friends.

...

> I agree that kernel.h is not the right place. But are there any
> numbers how much separate sprintf.h might safe?
> Maybe, we should not reinvent the wheel and get inspired by
> userspace.
> 
> sprintf() and friends are basic functions which most people know
> from userspace. And it is pretty handy that the kernel variants
> are are mostly compatible as well.
> 
> IMHO, it might be handful when they are also included similar way
> as in userspace. From my POV printk.h is like stdio.h. And we already
> have include/linux/stdarg.h where the v*print*() function might
> fit nicely.
> 
> How does this sound, please?

Not every user (especially _header_) wants to have printk.h included just for
sprintf.h that may have nothing to do with real output. So, same reasoning
from me as keeping that in kernel.h, i.e. printk.h no better.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEJQkDV81KHsJq/%40smile.fi.intel.com.

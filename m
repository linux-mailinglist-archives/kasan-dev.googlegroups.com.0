Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMFM7OMQMGQESGNISAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A81565F67A4
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:20:48 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d22-20020adfa356000000b0022e224b21c0sf520667wrb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:20:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665062448; cv=pass;
        d=google.com; s=arc-20160816;
        b=WIv+SMWRfpUB2rmwo8w3QQYt5snvJqn5/62kCdka5vzcryk+F6jkkLg6wcnQUNd6Hq
         UuJuuwwSA7iDZcDnxqna+yILFgGiO33n+jIxwJBjzNf2foUH8zBua/lH3+yg/xS7uvpF
         wjjxChpqfdth8oo8IboQjd05Pt7he8qWzZv7KtcjvWZtgWf1l0MuDQ2J4ZuBJMOEhB5C
         6rrldKIFX+VOMdlC+tFsaGg2KqmtvVdDP1psO0XFXi4cadXygBEpbZJALjV44B9Q0Z4H
         ElfdlesmBy+lA8ciEd2Hj+A17cWyUSftfML7O2lCe85fqXiHjZEzRU2W36IgRULCUmZM
         zAQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uRy0YMvJd2BE0o+5yKQuqN/wqB7nvWLsucmSluU4woA=;
        b=QDpJJnhWPDLFN1iTH13zFXUtg6VtJbC8786O0CN/PKsrXVOPwEkxSGyXQVyouGGZFj
         Io9fBncJsf5JuY177rBNIMCHX/XH6CiRjv4Q2KQqysIHwp4GYka+rMEInv0AGd+N0dR9
         NWW4oT/Y7592KeGbx8Tm16+nq6J5PtmyQ5oXoQU7iX73iLxAX0UBGvG6UdsLHvxE6JXf
         VOO5dNbUTf3pV36w6Ms040RCThMkR+7E4khUqdZr+hwE0fjvcyJiy868CwRr4cEcObyy
         WKnJ18qUcyUaOk8XHN2Fbwj+ZLYFmoD4WrDNRzOwqfUAB61rTLNRHzYBQe+pZrv1BQh5
         aM1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="SVGxZ/5u";
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uRy0YMvJd2BE0o+5yKQuqN/wqB7nvWLsucmSluU4woA=;
        b=oBCsOhH2675C+eI+eD8UH3Ag3RCWPZHBlGToKJNhXOF5yHR5jEZ1b1fQ+feieysRAy
         hsLr6RBJ/ZlmhKFhRFXzAlW/XJ3fvn/p0CkpAnwOGp5Vlz5ztkZP+Dv5e0XsgsC49sgd
         YL3zZ/3l8pKT/TQLqmSrxxO1B0WUyEJBQyMYdq7JzJ0tOw/676DB3eTwPD1qaqNy7ybW
         FA27TAqL/KhfJpovMtBAp2Pt+75G2hMYxdsUPvumKji1PDNhRgGu95daXyI8AYN7zxfE
         053ZWwgyrSWy2CU6VWQfYSMq78nUP9QZeUyc9H7U/rk2E43NZbb9Nn3PbwHAy0bh8Obu
         s3Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uRy0YMvJd2BE0o+5yKQuqN/wqB7nvWLsucmSluU4woA=;
        b=i8Hac8wYtgFHWaMQiCHkc2V2Vxtj6+ci76zgceDzHxdZu+M+dvKRNGaYixSfWjNb5z
         FdXnGGJci4E4YSSJ6q8Et1zDiDU+NTOCbyfqHrRc2BVOsgxZ0S8Y8HMyGV+/5mhQn7YN
         66X6nB7jfY6ym55qlAnFsLKprxNlKvuHISUrskISY+SVKkvLljaa5mvzcivvG0OzmHxw
         Lf+j1Kt4n6vStS1qe5rHqO9cWR6k0cq+CfdorOgztt3XoTfJV4kT4q7wj2Y6Ja28YIbW
         idWWlyAJZTwL68SawN8yH8ufTWosnXZ3nBRjKSJ2vY2mtnr5MNJfNkySmyhnll6K771Q
         xCxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0ksmNVoMCTHrTjIWuTqlCEvap3f/9iNVj40wXEtfwgFGa6Sx/1
	5PnGH6wErAzyjb7VOdOSi40=
X-Google-Smtp-Source: AMsMyM7LiKcYrGsPwycOStf/dn+RxZNa8LYogffVy4o7+VVEGAn10EEukl1szKi1rGVzFogbRWMsvg==
X-Received: by 2002:a5d:4910:0:b0:22e:4007:d047 with SMTP id x16-20020a5d4910000000b0022e4007d047mr3130220wrq.609.1665062448283;
        Thu, 06 Oct 2022 06:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70b:b0:22e:5d8a:c92d with SMTP id
 bs11-20020a056000070b00b0022e5d8ac92dls3502419wrb.1.-pod-prod-gmail; Thu, 06
 Oct 2022 06:20:47 -0700 (PDT)
X-Received: by 2002:adf:ef4b:0:b0:22e:5c0c:f5f with SMTP id c11-20020adfef4b000000b0022e5c0c0f5fmr3142740wrp.9.1665062447209;
        Thu, 06 Oct 2022 06:20:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665062447; cv=none;
        d=google.com; s=arc-20160816;
        b=V4C2m/zHDMEeH0e37z7IvgqvHAjcg20xPuz8R+xHyc5lveOrJsWMGlAyDT4iE3SglO
         nmxZwpn3+ZqIRgG7O/nG8RUR6t4hl/lGrVWBP6P89W2CpuDqxKGWtgpbzxDZef3IzKqm
         VKvkE6FgXoN4k5AdNNDlSxaIDcgllKL2NmJ1/n0T0WkMerjkonMouUeF3+ZQKtNJ43i+
         BZe9249LSkNMEtwShMJEyNXutaSu0MPcPpTOfWh4N7AIxI7BXxeumY2gGDMgf5LTO4pL
         IqeRwgQ6Xrr3Qo7KkHyfcCPF355FpVxX9BMQcTxqcMufo75qPB8IvAhztnypiWp9GjJW
         i4UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZA/qVV/OjVPeYSfM3XvsjCeMNgcHk9DsjyLEvsY4vvA=;
        b=dU6aZfvx0fHPLDRqAtVxB0ldr4RA2lxllpzW8pQCkCajLHjhs/vYNjNiGwFMoTeOD4
         KclQ7bq6NUPc2FSV3FliKTZVhfI5k26njoPfsraVPMYD3r1tukQJNx09tHqIe8HCGE44
         z9KcxqY284csGF4X60Hg8UZHvHREusJhKYmDQu3Du9gkOOsHHszLFM/z3rTMk4VHzGnb
         REUtEFpeb8SkSvEnywhPYKM+eKkoEUTk3aPZMuICn/jpQ3GUSZzWdQkGbTi8JwI5/S2a
         LbeKX2tBaeV8DSk2JkZmKJwrRRUBO9BuuuODzLm+iHGRkjrjDOZsuIcQw5Mpkyr9Z7BU
         FTFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="SVGxZ/5u";
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id z9-20020a5d6549000000b0022e04ae3a44si597563wrv.6.2022.10.06.06.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:20:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="305019540"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="305019540"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Oct 2022 06:20:44 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="729143418"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="729143418"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga002.fm.intel.com with ESMTP; 06 Oct 2022 06:20:34 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1ogQng-0039rX-0O;
	Thu, 06 Oct 2022 16:20:32 +0300
Date: Thu, 6 Oct 2022 16:20:31 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>, linux-kernel@vger.kernel.org,
	brcm80211-dev-list.pdl@broadcom.com, cake@lists.bufferbloat.net,
	ceph-devel@vger.kernel.org, coreteam@netfilter.org,
	dccp@vger.kernel.org, dev@openvswitch.org,
	dmaengine@vger.kernel.org, drbd-dev@lists.linbit.com,
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
	linux-actions@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-ext4@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
	linux-fbdev@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-hams@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mm@kvack.org, linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org, linux-nfs@vger.kernel.org,
	linux-nvme@lists.infradead.org, linux-raid@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-scsi@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linux-xfs@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, lvs-devel@vger.kernel.org,
	netdev@vger.kernel.org, netfilter-devel@vger.kernel.org,
	rds-devel@oss.oracle.com, SHA-cyfmac-dev-list@infineon.com,
	target-devel@vger.kernel.org, tipc-discussion@lists.sourceforge.net
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
Message-ID: <Yz7WHyD+teLOh2ho@smile.fi.intel.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
 <Yz7OdfKZeGkpZSKb@ziepe.ca>
 <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="SVGxZ/5u";       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
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

On Thu, Oct 06, 2022 at 07:05:48AM -0600, Jason A. Donenfeld wrote:
> On Thu, Oct 6, 2022 at 6:47 AM Jason Gunthorpe <jgg@ziepe.ca> wrote:
> > On Wed, Oct 05, 2022 at 11:48:42PM +0200, Jason A. Donenfeld wrote:

...

> > > -     u32 isn = (prandom_u32() & ~7UL) - 1;
> > > +     u32 isn = (get_random_u32() & ~7UL) - 1;
> >
> > Maybe this wants to be written as
> >
> > (prandom_max(U32_MAX >> 7) << 7) | 7

> > ?
> 
> Holy smokes. Yea I guess maybe? It doesn't exactly gain anything or
> make the code clearer though, and is a little bit more magical than
> I'd like on a first pass.

Shouldn't the two first 7s to be 3s?

...

> > > -     psn = prandom_u32() & 0xffffff;
> > > +     psn = get_random_u32() & 0xffffff;
> >
> >  prandom_max(0xffffff + 1)
> 
> That'd work, but again it's not more clear. Authors here are going for
> a 24-bit number, and masking seems like a clear way to express that.

We have some 24-bit APIs (and 48-bit) already in kernel, why not to have
get_random_u24() ?


-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7WHyD%2BteLOh2ho%40smile.fi.intel.com.

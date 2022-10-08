Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBAP5Q2NAMGQE2YRCZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B052C5F8678
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 20:16:34 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id x20-20020ac25dd4000000b004a2c484368asf280073lfq.16
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 11:16:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665252994; cv=pass;
        d=google.com; s=arc-20160816;
        b=uPpxwQ9GKBDgd2ixj8JrmiU5n4kdLdThcqyeqG4uZ1hjL3heXnY+kgZNwmT7tU55QF
         QKl76fSzZ8GxZWceS3oCTahu198q1OgIH8tpaLS5wRa1pwHNyzZCKnghfRYhw7wYkYPw
         pEpiG2iPmWlzhJQpAx6UBmTYYai7Kouc7EmaDC19IYePsEPkN4fR8gBAQanIdyPufLSD
         FhVYu+PvAv+tjmGWzP9UHrCktSgbS1qnkAflVZM1iGioEHVyuZs6C/hqYX0rSsy84h5B
         IpkXarEeu6yUjnkL1HASZyNPFbBAv4W2MQe9ysyAB2iSa8kpNTwg64aZPVtIcqdbkM+g
         kyvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3Uypz6dcr42FJXrnaEy4mzf5jk3N7hOv/tH+TuKvYQI=;
        b=XYuMqWsgOEgiQH3FNqwMMwYxe2i8gm7jfWxPNIuasPio9+fF2WpA/epGNRyyG8nV5d
         djMVSS8OiKzHRNgCEvd2P+d62DkBjHq6OyOO9NePZCwbhapvPaqNxve1NQ85w0X+8dS9
         HfkB4SXEUyToRPJPECm2tbFtQgd1NuC23qUgd1xT+Z+cxhHwEo08aE4gzasD4EYwPVRg
         fKp+QQA+K+gdgRl2R52yepghbO0nY2cA91kmX9t6nXIFBQ0VgDxGI0rmhsvRYIUK6uH9
         YL/3aGgKmsIvwNuwPoLFxe7FAJlaYjAo6/rgTf2Xpda2go3R260m1140+HbPInFFlhFY
         w20g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Cy4RrU9t;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3Uypz6dcr42FJXrnaEy4mzf5jk3N7hOv/tH+TuKvYQI=;
        b=TMTbaT9wQqcPV6Mj1nwvP5PIg5D+hAj1/NUqvXgHUT0+qlSfuuaCjXTQ/7oEu94wso
         Bw704oBpfziERPuDXtdUWNaOxtO5tGy/67GfWvY+/4Ey/zFIOPV95Ib7WEp2A9y1ZNXk
         9CSY/fH6SIL1w0jI9I4AeR+LZy5IaRJbvA/fcE0yiIvOO1Emubrz6PQWS+SXPZbidXRG
         6ros3mtZKEn06TKutpDcpBW2hqemCYqyuSVWvA7tnoageGc0hCoZgtX+zXZ4EojzpWe0
         K777Y+bDhIePlGj+lvN+xE5XWENWv/yKXmKerqz79ANRvABy7YaH3/U2x5YgR+bD9Qgn
         SPgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3Uypz6dcr42FJXrnaEy4mzf5jk3N7hOv/tH+TuKvYQI=;
        b=BkUZR8RihHSSD4r5jqnLcjzUZ7lbtqMoL4a6Vu+9rhByOB/VJUNY4HX5ZRM3OI0+4V
         HQo6VirAEB/m/1MCgmP4TM431yIBqzLyJvk38UsLlzhWeA8YTk49s7dlua11Q4EFGGWa
         mDFJpBqLlXIVmNM4C444/qHnFH6OybWLm14X7GKBgXlk1YIKe1tIXGuYwfd1wFVBGeeh
         fxW0qqNNelY+F91xH8bnaWYOo8KzTP9JezNVZVlECMUZCzEFHYPXjCiqe0RZ3GV/cABx
         EFhw4uhnTV/2FW9UX4I0kGscZxukxBl/cpNy6IMaX57xfK10jvTADp2siZwLe2DnrN1V
         Kmng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2XNGBdE1GfNaQNb/Mc87/Paz7mx7vHI4Ea2vkwb91klPWpfcXY
	0wpimKjMB3DspjGwI1RC4Xo=
X-Google-Smtp-Source: AMsMyM5A/8lVvPTCJJsXwC+QQNGITijSjAjY3+TDy/2KNmd3fYdKoSCTtc4j2QLChfBHGZ3WgunnPQ==
X-Received: by 2002:a2e:7c04:0:b0:26e:47e:a004 with SMTP id x4-20020a2e7c04000000b0026e047ea004mr3694181ljc.55.1665252993843;
        Sat, 08 Oct 2022 11:16:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c3:0:b0:26e:3a10:642d with SMTP id s3-20020a2e81c3000000b0026e3a10642dls804756ljg.9.-pod-prod-gmail;
 Sat, 08 Oct 2022 11:16:32 -0700 (PDT)
X-Received: by 2002:a2e:9a83:0:b0:26e:2202:bca6 with SMTP id p3-20020a2e9a83000000b0026e2202bca6mr3300867lji.401.1665252992501;
        Sat, 08 Oct 2022 11:16:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665252992; cv=none;
        d=google.com; s=arc-20160816;
        b=pL+aJRWyih/g9w4Cc5bZli1xWeCD9QeAo9yyaxG9mAUdBBmWYQSRv04RnC9DSa/Ks+
         B1xPkTQ9nRlo5OLd7J2mqdYS817h3XycmQ6e2d2ot/+GQOtRbYfqdnQQLf5lLWdWGF6S
         x+hsJ1ArtjyQXJWAJ4MXvwBDvCa6PHXpySmC8VE5p0o6lso7/xCklThEBuDCT2QASf/O
         p9sAoZcI0jg/ZZviy8O6fC9UWWkKLMz+wrbCu8H8dV0kXIFBFTJ9S/FcB0RmYyZBNRJw
         sE1hCB1XgoqwTjKunLnbguRYuLOb/1J3xEr+pBdTuK2fff21jMCQDeb0CE1wRwcPHmEY
         9Byg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=gKkERMB1M9xOEPNfE3IrAsq0mJwwY0seKkU7oCng9qc=;
        b=bYfHNYCZkCxh30fI0W5qm2SjNyupi5gNhgIqs7VoqVj2PWR3cRt4vuk1nT8PFGwd8G
         dZ+eW7IePsl/6R7/ghfT1m4bnYt2mKM7lJcOWeV0HIfb17stbF5YXegbFpFj037yVJcy
         Nd79GTI9u8s0w8ZY3r8lvpcjbRxOvywsuUsHtgWPcnDLFdn8dmBT3jsjeGcMX+zKHFXh
         zGrqfG9kQ4C5GK+UeoRcogVWc6d5DJdLvRVTN1ktVw3r0uiOOUwUAlcOGOKqVo7W1M5p
         uKqXZKox6FrTML/hmujCO7lWZRu57x1eg/OHA6uURAkEEu9lPaWUgQ+ls6jXqidfFr9A
         s1jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Cy4RrU9t;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id v5-20020a05651203a500b00499b6fc70ecsi197330lfp.1.2022.10.08.11.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 11:16:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6500,9779,10494"; a="287201859"
X-IronPort-AV: E=Sophos;i="5.95,170,1661842800"; 
   d="scan'208";a="287201859"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Oct 2022 11:16:30 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10494"; a="750899918"
X-IronPort-AV: E=Sophos;i="5.95,170,1661842800"; 
   d="scan'208";a="750899918"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga004.jf.intel.com with ESMTP; 08 Oct 2022 11:16:23 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1ohEN3-0048ft-0Q;
	Sat, 08 Oct 2022 21:16:21 +0300
Date: Sat, 8 Oct 2022 21:16:20 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Kees Cook <keescook@chromium.org>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>, linux-kernel@vger.kernel.org,
	patches@lists.linux.dev, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Message-ID: <Y0G+dP9uGaYHSa9y@smile.fi.intel.com>
References: <53DD0148-ED15-4294-8496-9E4B4C7AD061@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <53DD0148-ED15-4294-8496-9E4B4C7AD061@chromium.org>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Cy4RrU9t;       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
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

On Fri, Oct 07, 2022 at 08:50:43PM -0700, Kees Cook wrote:
> On October 7, 2022 7:21:28 PM PDT, "Jason A. Donenfeld" <Jason@zx2c4.com> wrote:
> >On Fri, Oct 07, 2022 at 03:47:44PM -0700, Kees Cook wrote:
> >> On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:

...

> >> These are more fun, but Coccinelle can still do them with a little
> >> Pythonic help:
> >> 
> >> // Find a potential literal
> >> @literal_mask@
> >> expression LITERAL;
> >> identifier randfunc =~ "get_random_int|prandom_u32|get_random_u32";
> >> position p;
> >> @@
> >> 
> >>         (randfunc()@p & (LITERAL))
> >> 
> >> // Add one to the literal.
> >> @script:python add_one@
> >> literal << literal_mask.LITERAL;
> >> RESULT;
> >> @@
> >> 
> >> if literal.startswith('0x'):
> >>         value = int(literal, 16) + 1
> >>         coccinelle.RESULT = cocci.make_expr("0x%x" % (value))
> >> elif literal[0] in '123456789':
> >>         value = int(literal, 10) + 1
> >>         coccinelle.RESULT = cocci.make_expr("%d" % (value))
> >> else:
> >>         print("I don't know how to handle: %s" % (literal))

Wouldn't Python take care about (known) prefixes itself?

	try:
		x = int(literal)
	except ValueError as ex:
		print(..., ex.error)

> >> // Replace the literal mask with the calculated result.
> >> @plus_one@
> >> expression literal_mask.LITERAL;
> >> position literal_mask.p;
> >> expression add_one.RESULT;
> >> identifier FUNC;
> >> @@
> >> 
> >> -       (FUNC()@p & (LITERAL))
> >> +       prandom_u32_max(RESULT)
> >
> >Oh that's pretty cool. I can do the saturation check in python, since
> >`value` holds the parsed result. Neat.
> 
> It is (at least how I have it here) just the string, so YMMV.

...

> >Thanks a bunch for the guidance.
> 
> Sure thing! I was pleased to figure out how to do the python bit.

I believe it can be optimized

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0G%2BdP9uGaYHSa9y%40smile.fi.intel.com.

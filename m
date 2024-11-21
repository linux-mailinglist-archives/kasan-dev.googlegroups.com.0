Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBPUB7W4QMGQE3H7L47I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id DED249D4E7A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:16:31 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3a787d32003sf9362765ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:16:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198590; cv=pass;
        d=google.com; s=arc-20240605;
        b=if8Mk/Duco6rhezGzHqs9h/bd3WS10TgDG2W7t0XbTFpmmF5EER+wrT1BwdgmvSTGb
         KfRWFWEQWuihRpvTJb947LPC4nJtQUsB/cFhZ2AHBLWteVxoMuQI3mqbEebE4k6QlRS0
         Q2BKX5wl4AwYrTpW8ZfFSpNbaPVR4cmQIybrySGcbbUy8XEw+rFPR4l1OK56/TXPcWCe
         DgzIzyf+HsIGJSvg276NKDqPWZiDUcRQ62rcKBIjIvmZ/q/X5Fr2YJycAHIFNFhdk/Jc
         cATnKkSlNmXh3J5v54LmxRZguiI/gRePk5K5djEHCGsEruglmuh8erocwllDlTUOuprQ
         DJfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cjvGmAwdYfMcTclr5p6cpUHUKsSmkZvr9UokT1yAz2s=;
        fh=6E5EVmDI4CN47tz0YWjhXXBlrkZYM1X5iHlSEWdSKhU=;
        b=WDHQfAyOI3PiAXkKEeIqSgcBpd0KeL83a0Bff6L1WRTGbBr4lIapTnD4uGYT6lo5Q3
         RIDcoKQBd4POgoDIWx3ZM9ggNAfcv86VVsns2x5C4V0hpx26x9gapTyI2GjbkqMdXpbB
         w1SmykKJWFxGvjmv0rspQj9iCtfkZdwsfvemPgU7OPZEPWzBoJ+7F0PBy/lti1y53iUD
         K3ES6GM3EZAUx/x1Cd3ACJVkaJarW4GAKyT+9kZcDlDCmaeYsDXzpfAEX1SMMb1k6WRA
         Agj3ybdAKtQNWG8yJ0fq9YuZSR1Azu4YjJ/IncB4jOI1z12UhuqNfpt5JedvEYkzMwws
         e1EQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VXFXI7f5;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198590; x=1732803390; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cjvGmAwdYfMcTclr5p6cpUHUKsSmkZvr9UokT1yAz2s=;
        b=uwwzfXehGWqHRB9MwMPnlxmOxxbcaJsydfmKT9YTY9XvMOGdS0FLMqz3DryvxsFcLo
         iUoaR3s8FsoKcvmp8eKMNQ08W32kVN3+HgA2aU/oFdiq+IqWW8qhy73cdaK5wc49nP5k
         QBLzmlShZLOhlgbIBfTSj4NmY+iO5ggTy7EMocwxz+Tl10ZGCxVBEGOLMv0hnpuHa/z2
         VW+qURmPXklJVfLCxP4BKdJVt+LVmPLojbt2/xzdO78G3mGj06xkLwDTNmGmrXUKTJIs
         3Va20gUjdnUlWUTarOxHYXDiaTHztA2DONCpbixxeW2Vqma8LnqGVs+c1s6DW4iAcB6a
         pp9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198590; x=1732803390;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=cjvGmAwdYfMcTclr5p6cpUHUKsSmkZvr9UokT1yAz2s=;
        b=KdpfoR/96dZSKyD3orjnkzrC3xNgRMLZi8AMW4Kw5+5Og+igSCvQZjloxUVTeK6cJr
         YFuxLHBefd6P5F4gBF4jOl0JGreganaOLYNUfM97RLrjOVmwP7yZ35h7Mpvee1MRH15x
         NtXYcdM4BVCnEOyvqYb2Jq4bvVL60RuIqNXLQRgXicnGtyCkiGg4rXK6yclMdLDIR+Q2
         B9axdBREpLQacBYupwrdkTVVSnK76TLYKe+B8IZFvCKkYzKjpp0OYIKzRZRZzFtJdAew
         0CsdksIrTwBY/22yzI7/ClxDI0Yg6j3DIpB1R4wjdo8km5Y8j+cFbDZ8KVnOXOcgB+6e
         VwgQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZssVVk7dVKQYK66C7MTSLW67GD+lSRuplBCaurALiUibAVORBwIW0c4Tduux9GpaHESjCkg==@lfdr.de
X-Gm-Message-State: AOJu0YzZoPCGp3A00xk++EPCR3oQyueA8DKbgGibGhO9DdJLHCh+aFNH
	jO248UkD+9R/+h/p4ZKR5gwDxaPvaLdHnWu157Jm3pASUCNw+f1j
X-Google-Smtp-Source: AGHT+IGdiGCg5dCtXlnMLw6WrLA4L0KDr07Aq0Tq1IPba1GPlD61fn34SIeAiRo3l9rHQPxDjRt27Q==
X-Received: by 2002:a05:6e02:148d:b0:3a7:6f5a:e5ce with SMTP id e9e14a558f8ab-3a78640ea3dmr94823885ab.3.1732198590266;
        Thu, 21 Nov 2024 06:16:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d08c:0:b0:3a7:987f:1bd9 with SMTP id e9e14a558f8ab-3a7987f1d66ls427555ab.2.-pod-prod-09-us;
 Thu, 21 Nov 2024 06:16:29 -0800 (PST)
X-Received: by 2002:a05:6e02:1d0f:b0:3a7:9082:9be8 with SMTP id e9e14a558f8ab-3a790829e21mr42522535ab.1.1732198589283;
        Thu, 21 Nov 2024 06:16:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198589; cv=none;
        d=google.com; s=arc-20240605;
        b=PnnnNFGYl3B4jxjl1IQlHTqvNxLZx5nuw/5XdEf6iaDnjJp5R7PwyxRv+25BU300bE
         rXaGZvy4SQq22t3Phu/gQtUMCUWIrj4Jl5ZLvz6Dh/ls+37yvbRAQxrjuuD6sRmQhjZ0
         rY4eIUwWEDrMQN8L/ImGtgqg9kny2ODrgWzY/zSddl6fQ8jbRvEPNYipIafv6+/EHchY
         v1etTWxkrgTTVR8PHQGyUh+8a4GNI6Dkphh5SISmms+XlhYFYegykx63SLD4wZm0kU2m
         yOIOTgvArz1Ybr45ebB/E9+W21j8wQes+6G0CFJwlAAAaXF2J1OcK8nM6vtenbP6nYXP
         hCWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ufu06gwv0tnmv6in0dc9sCGXdRhET7rcugU8q/u4mU4=;
        fh=BuxweDoviiTrvykEWSRNa5gyMRe+aKQjNK6M2eeCyLA=;
        b=fqAHfQCWCuLunZHYIJX1gqbJaZRPPxsbCW8esntpUoy8Vpdu9z7zlC+g1Q4FxY6YnZ
         jL6ql8Iv/LUawJLyjRAgpPT0QupOjv/FDouKOnnVJ1T7IY+Doj/lhmnoMDLSbjyo6pRG
         Pev4bVdznhjVlPJC+L+LcD77GT/V3unKF/Bddx9WoHutSYEaqLtZWy3o2Bk323aRcE6c
         8I5cu4XB8VK2YIusbXBsTGse5AupR0WYHneHWcqAS3Zisbh9qoA0E0lGapAlG44h+2CH
         Teo+9trknGl1YGZGhPkAwF5r1QomL+RklnyQk+zgt6bginc87UoBjQVYNDQ00ktlMTvT
         K8uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VXFXI7f5;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a7925a75d0si514085ab.4.2024.11.21.06.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:16:29 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: 0faSY2KRTAGavaUpPBMEzw==
X-CSE-MsgGUID: uCeTt7oWTeekbFcLcxn8vw==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="43707503"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="43707503"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:16:27 -0800
X-CSE-ConnectionGUID: RG/0PXksS8iaVe+KoV/OYQ==
X-CSE-MsgGUID: GULi1l89RdmpX9kQbRWt+Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="89867856"
Received: from smile.fi.intel.com ([10.237.72.154])
  by fmviesa006.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:16:26 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.98)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1tE7yq-0000000H5L8-0pAz;
	Thu, 21 Nov 2024 16:16:24 +0200
Date: Thu, 21 Nov 2024 16:16:23 +0200
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 1/1] kcsan: debugfs: Use krealloc_array() to replace
 krealloc()
Message-ID: <Zz9AtzWWXW_mgjR6@smile.fi.intel.com>
References: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com>
 <CANpmjNNzFykVmjM+P_1JWc=39cf7LPuYsp0ds0_HQBCzR+xOvQ@mail.gmail.com>
 <CANpmjNO8CRXPxBDFVa5XLYpPuU8Zof=7uvUam9ZFVPP9j8+TEQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO8CRXPxBDFVa5XLYpPuU8Zof=7uvUam9ZFVPP9j8+TEQ@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VXFXI7f5;       spf=none
 (google.com: andriy.shevchenko@linux.intel.com does not designate permitted
 sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
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

On Thu, Nov 21, 2024 at 03:11:41PM +0100, Marco Elver wrote:
> On Thu, 21 Nov 2024 at 15:04, Marco Elver <elver@google.com> wrote:
> > On Thu, 21 Nov 2024 at 14:58, Andy Shevchenko
> > <andriy.shevchenko@linux.intel.com> wrote:
> > >
> > > Use krealloc_array() to replace krealloc() with multiplication.
> > > krealloc_array() has multiply overflow check, which will be safer.
> > >
> > > Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> 
> Unreview.
> 
> > Do you have a tree to take this through? Otherwise I'll take it.
> 
> Whoops. We got rid of that krealloc() in 59458fa4ddb4 ("kcsan: Turn
> report_filterlist_lock into a raw_spinlock"). And the replacement
> kmalloc() is already a kmalloc_array(). I suppose this patch is
> therefore obsolete.

Ah, I made this on top of v6.12 + something most likely unrelated.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zz9AtzWWXW_mgjR6%40smile.fi.intel.com.

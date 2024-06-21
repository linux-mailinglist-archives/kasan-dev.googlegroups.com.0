Return-Path: <kasan-dev+bncBC5ZR244WYFRB2VJ22ZQMGQEY7USF5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B9D69128A5
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 16:57:48 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e02b58759c2sf3727810276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 07:57:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718981867; cv=pass;
        d=google.com; s=arc-20160816;
        b=pTdZVFmb2WBNkln4gHu2bFkPG+oItkiRfgE9b09QbP4lITMKSzPdgUJOUBy/MahRLE
         UP1JKi2/YQTVARyzO7Xe/toXbf7k5ccj8ypA42vPkYOJLHltl7YvGsWujWlERvDGk346
         8EXQ3qSRAisbClTYArm3ZWFF5HLeeyHhH/OYj1q1vXO7aBNJ2WJnPQp7OuoazwuE26lj
         jA29Lxp4hRVk50cCijTrw89JRqx45TZ2V5KMiuOkyh+30nMTWcghTUvv5VQ0goBnKCs9
         DVMpe11+OsUk+2EDDlMZ2rj4rtArI6Hhu97ty/79VuqLNAc65mgBiwxrqiahkd6TUGUD
         XodA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Eh57YN56vTv4k/gP4iDC2HOpxDN4K9AAtC+3VBaAz1g=;
        fh=Jr+Vcucg/iwmjKsMLq+C+Tm/4M9IWtsaq2DD0VUjiAs=;
        b=P2fEfsurOCVxf3h5AJitcNheI4bbongT4DMHgJvQ0EowfD7r7fp855JGxnS+ZxG6Bv
         gauzVr/JZCAQV+/w0ZzZpZTa2PxMP/Ua5jC158Iig4wtClw2dNhPJpLzRta2mRmAF3ug
         ZgvOaCOkRv9GlL3AhXbvfele0c67rRVLq7MH2hCEgRIxcZw1jQMH6fRYdwlQJdsQaNSM
         v/Z0pjW+vdHE+EaLARQdGY8wG6W33hr485ZRafwQZhKxsqnQ3dHOoJsY34wwZJi6x09y
         4ckI7IhA213WSmWtWmjrfndAiXZjYNpu80cIaFbRLwwk+OW+yhSxX3i4a2HmwJTVseMj
         yVdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=J6nwqOYW;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718981867; x=1719586667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Eh57YN56vTv4k/gP4iDC2HOpxDN4K9AAtC+3VBaAz1g=;
        b=nHQQe2++fqTK9LO96gDflpodCEr2YdM1CKUA/NOGTuh8rj/jHVzoGSAqORRwFtzwHL
         6F8Q+YxRawc4jtSCPXIWgJJ5dDqpGwgT3cq4aJDOIzo23CWCy73L5WUauSlpjl7P3Sv2
         /kPL2YDfxXKcYwQF1RR+dOZU7GfEDI3rgBmGBo0ZyajffbmV8eMaM1KtwuCXRzMF311q
         N8Ek8e8qcfMSSk49/vUcBaMUkHuWH3PVwAtwr0mU+vKtn0cQrUn6mOyzgyWGLj9ChDot
         Cut1ys+b3TSZTXrczUBtpdfDawJVtuovo600d1eAKTjrOPgF4b5/TDCpTMaM0zYNn3di
         O2Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718981867; x=1719586667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Eh57YN56vTv4k/gP4iDC2HOpxDN4K9AAtC+3VBaAz1g=;
        b=KWGVE/pD+bpMXIyKLXVqttYoLxhNe6hfRxFeA8aATrpkrcfOp29XMb9pTxtq+9Cq8j
         13YAyF90/yMOwdL1mqKVWEWMZUJLcsKbb59uS+mxVSbDfI9o/+6FYzBoa/mBkvPKZdOO
         pUzqfBtWrYuq73tUEY0faeDXnL6XT/TmVkJVb/FmEEdjcET0nwwTWOBd0fod4IEJQxa3
         tVSYvoXW4FjCEc4nnhqfDsrMJ2w+cmSvsBPtekyiyDvxbhyVAFc/EFvZEBaOc/++zn+S
         A5uU0AMvIqiWrB6X2msTjFzQmDWWPo6lz14/50iJj2SCiJ/G6SJP5lf8tsbmjVIxt5p8
         JvMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrKrzgdOCiYGsdRF0kQj1ctFvHguneeIbHGl3nXzAFMEsrJUpLqgmCOxAahICjmgB6rXh6hH9iZjMFauou5Yq+rLjYp02lkg==
X-Gm-Message-State: AOJu0Yzp0TNwsNIQNELvRhLGz23LpjJnQO2LdcOL7l6aaJRLa/4OSO54
	NlSuhHtHWAerU7wnJYZiKYUQQu1SL1sETkSa/ZWnQTFjBdLW7Iy6
X-Google-Smtp-Source: AGHT+IHeypNut1TCkP9Ta0WK1sfFNRDwcxzfuMx8xdXFqy9WhBqyKfT6RoOvq4iv71hby7qU64tAqA==
X-Received: by 2002:a25:8188:0:b0:e02:bac0:6e6c with SMTP id 3f1490d57ef6-e02be1f4574mr9496434276.49.1718981866684;
        Fri, 21 Jun 2024 07:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:100b:b0:dff:34c9:9303 with SMTP id
 3f1490d57ef6-e02d0abcbbfls3565721276.0.-pod-prod-04-us; Fri, 21 Jun 2024
 07:57:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWunhBu7iHxG1Xw7sd+MihDT00STQd6SBryZMn2MkX4/EzZXoNzZE85IYCB1+JdcRKBTNfNBT8PnoekJ++4Lt7yD7lw9ZFPaTev6Q==
X-Received: by 2002:a05:690c:988:b0:63b:c3de:8403 with SMTP id 00721157ae682-63bc3de8424mr59447997b3.26.1718981865560;
        Fri, 21 Jun 2024 07:57:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718981865; cv=none;
        d=google.com; s=arc-20160816;
        b=F8LtYusyAHmrt9n6j59RAO/ZEc0Rf9zoXM2dOdY6nL1xx0Ea8GfKyYAqfUDCgi3+jm
         Z+NgX+L5HUwfeCEptM6Rt7ZrkQLwgE7OLc/Erd0lINFAKCbeqKmY+xmckpheYPdkTfml
         CQmwW0t1iHkZVbDtuVtPqAuz/mNYmEcutNH2YL1S2VKGarr8NggTxFwgutRxNQil1VoX
         8+P41NsYv2sTPWhXaKUHwT0I8qPssqikwZLby7bmUrprE1+whvHvlI2oOa/G+rZbNRFc
         90TNDOMq2oAJhDIUh5yK3bpfL69MYsyf528JRVdIl+TT9u4SHqffUbyCo9J/Wd1bQLB0
         tJsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BLKLBgOo/6iMoJdQuJj8irRWOIZmI7CLkR6D2OgWGKs=;
        fh=Rd0eMmseSGMPh9TTSECG001hqBGCl4V7ITo+N5A6yGE=;
        b=GOEx9iAAa5sXXIlrPbjDP1pXnAYvUSCqnVFBa5MleS25/eMz8WrQhxZDIH1btDgwCl
         trLQDDBS9mFQht/+7gC1ZZtS5fPUOP0bDSKR9h4LqdmH9Mode6f5UoR2gaECZPKGbS5d
         p9Hg9x3RLved8Prr7zRMoztdzozUXzpRpL8zimWMR6xox+xYOufWnOgYZs0BEkF7rOgt
         KFQYUA6Zv97vnK401/pp3E3b2Ia9cwFe5YZZu4xhVSQpWAgqmR5IlBqjUxw2WRzCpO4V
         5O/7Bb48O2ics/yYEOK7ZNnW6VH2JBn35T8nI+7yPsF2+QAGlN3rmpf9vNQQNYChFRnJ
         /C5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=J6nwqOYW;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f16a0466asi302557b3.4.2024.06.21.07.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 07:57:45 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: hm8piT2dSoGlTDyxcDHTBg==
X-CSE-MsgGUID: T+pegLpqTJeQ0Twj6PQUhA==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="19901450"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="19901450"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 07:57:44 -0700
X-CSE-ConnectionGUID: hbo5rgyHTUKD0mlS+syVgA==
X-CSE-MsgGUID: FfylbZ6vQaaFX1yW3aDQMw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="43296381"
Received: from black.fi.intel.com ([10.237.72.28])
  by orviesa008.jf.intel.com with ESMTP; 21 Jun 2024 07:57:42 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id 4CA2E1D6; Fri, 21 Jun 2024 17:57:40 +0300 (EEST)
Date: Fri, 21 Jun 2024 17:57:40 +0300
From: "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] x86: mm: disable KMSAN instrumentation for physaddr.c
Message-ID: <pi2i2qtsrip43yjji3ao26oqazplbkelma7hv24onxymkisqzm@ee6zflgdgmrc>
References: <20240621094901.1360454-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240621094901.1360454-1-glider@google.com>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=J6nwqOYW;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
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

On Fri, Jun 21, 2024 at 11:48:59AM +0200, Alexander Potapenko wrote:
> Enabling CONFIG_DEBUG_VIRTUAL=y together with KMSAN led to infinite
> recursion, because kmsan_get_metadata() ended up calling instrumented
> __pfn_valid() from arch/x86/mm/physaddr.c.
> 
> Prevent it by disabling instrumentation of the whole file.
> 
> Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Closes: https://github.com/google/kmsan/issues/95
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/pi2i2qtsrip43yjji3ao26oqazplbkelma7hv24onxymkisqzm%40ee6zflgdgmrc.

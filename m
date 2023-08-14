Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBFE25CTAMGQEDQ4YFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8441777B75D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 13:16:37 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fe2fc65f1fsf27561665e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 04:16:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692011797; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hov7ktLEHg5LrBO21bJPOXYRK+l5E5Z7qmU97RWqzYdqEjDu0Zf6TpDFeJGVOf2PRM
         krRgT6tGLTcv4RneVSEvG0y2Ieu43wtzbUeyRh0ZmOMPznuWhAsBYnMJ3k9Y6T4Cdqi9
         iAgNFE/8v4x+Yshh3OAi1pMOO1L4WG8eD/ca+KwBBAaBiSvkdNq6Tj//UfgODdKW3x4E
         onWMC2L5AU+pvx+aGIYYdNWd6AH7Otqc0ftFcqi4Y8TO8jvedsgjLPFShbqd//x7O7DO
         2Wt/HhT4o738q3w5OqfRUIRcprMM0sxPSK3UGOfUl2/I2hO1FfQ7ItsGvlE8IdYgiJ8j
         Ldaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=1XNDcZW462LlrWThOBSvnUSxJ56c+u5C1B7wBfavZHs=;
        fh=fxqyV8DKHMg0hFY9v1JPoUnggwZiT75qjfCzCG9wfac=;
        b=bdH8zHra+YCRTpHKW8mwpnXaobmByEITKAhiIBN2G3MAxX2uTZiq4SOREM+eRE+fQj
         Jb4DCBe+qda8Oaw2dXW5uHwllI04m0lKR64XcEfSb3Okqzx69LAofCpzzF2XVA+dr7WO
         aAXkRmzpkC8jx0A6kx8It/MZsA6s86ft1wy06zY7ywK1+LPHVmpPQ4/8L6Ql2Qky42FB
         D6SpXRQU+wVg2pqL+jRE4PiKaSZUubr4jzdLj/8RpGjOutfMw7F+2D/cz3TkB/32N4UW
         vUg24EEeZutjVySeBygz1nADDw7OZ3wQ0/lpHGkTRvif4VGupqk7mXEaBiWd/cA9Uu7F
         z6QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WwNZRP5s;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692011797; x=1692616597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1XNDcZW462LlrWThOBSvnUSxJ56c+u5C1B7wBfavZHs=;
        b=II+xsJ4cjor+zHIv/G+OUE0IGXQZUh/WgRYQTf3u6Q4FpnaMusftRIVyd00LhINpMt
         SOrpNGXpK8qUDoTMo5aGVP/VMoiJlrjkkEigFjVoYfOxJ9f0eUWzgo/XIzzy1QTGJ9IA
         o/Oos3mRLr3KzsbwfkhjdbwVXgCHu4/dqJkVCWUWeemcT3KsYusjixVsQ+JIJvYRN0pe
         vTq+TitDtupoC8yVmv+5/4BGq5pPXcq/rkMDVGu9bDXSdKGz0ZSpe0WLr9G4jHsolTat
         /Ta2cssV3XIi/qvAIzHVsEchRS2rnnyADEmr849M/jGvpvxqm1rBl6lyKfy/cdtRCKm/
         ftBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692011797; x=1692616597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1XNDcZW462LlrWThOBSvnUSxJ56c+u5C1B7wBfavZHs=;
        b=A9VeyKFNQHYlZCCMIKxUOcMeEGhjTJBGM10w5Ozz19zaKOujAtcRI3YQ9kDBreQhRz
         MUNMJ89EBHH9igpeepAvEyZ1zsdEWJ+k2+0j+ABwUr2R9qzDcdfmUAZwyniwkG/Zu1Lr
         p3NSik+uU++W84bF+JZ0BD/kOQ7doj0kMph5izuGRMFkx4+LyNE/rKaExQiheaLC6RNE
         Re0QL8SkEuMDfqMIXkeeVaeT8i6ZuzeNiIeF/y94C8P4zLUr81JvLv0fKz8KrxzlEupY
         QQXuHdJ12m7eHqqGUUWBCAGKnpLs/bZLKx4iDmdYc70SIwkPR08jYWepwffCccrohKrj
         YwDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxL8GsiOQ6/hkDyukm+ArU9RXTz0HOMFIKjWliPw9ZrSoAQuRmb
	Rt+IXVwSu7gxtMQFGaQLYKU=
X-Google-Smtp-Source: AGHT+IF5s6hU41iiIZr76NlcWVkajPhpmzI2O+UHOG9Z/SRqODk9I+9ox6xcOsa7Vz7cJCRfjZPapA==
X-Received: by 2002:a05:600c:3648:b0:3fd:29cf:20c5 with SMTP id y8-20020a05600c364800b003fd29cf20c5mr7479205wmq.7.1692011796548;
        Mon, 14 Aug 2023 04:16:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5110:b0:3fe:1d45:c71d with SMTP id
 o16-20020a05600c511000b003fe1d45c71dls131443wms.2.-pod-prod-07-eu; Mon, 14
 Aug 2023 04:16:34 -0700 (PDT)
X-Received: by 2002:a5d:40ce:0:b0:30e:19a8:4b0a with SMTP id b14-20020a5d40ce000000b0030e19a84b0amr6804124wrq.2.1692011794626;
        Mon, 14 Aug 2023 04:16:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692011794; cv=none;
        d=google.com; s=arc-20160816;
        b=JRztHl20yWCPx09aaO+YDlmoiUIWJxbBfI67thduWC32qjsWgHsMxP9cXIj6YVJAjP
         keLrlF2z8IKizK1ZjzMU9RZaryzDG+qDmhU1jOskR3mNzk0uG8BX2/zRKOwNG6ErGZas
         Qudub7hmPelVGp+ie7qrQiWIzy+fxW3I13SeMLVZ1uMydo8rDPG9+SXF1RRIf/6pnkeO
         TzhV1Swr8gJZWGgLyJVUs83gZmaCPq/Nlvo7xYdV7uMB/BdyN9jKE9i7Z2UdIBBEae97
         K34j6963Xif7wb1YGYgtGlrEAMdH3BUKDmPBxwZQtO/aL2X8e23//y6DKSHbWGeXhoTw
         k6Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=IgoWbcYv3e9pNd73Tm8tqzTktanf0BlXxMJN7YrrOqg=;
        fh=fxqyV8DKHMg0hFY9v1JPoUnggwZiT75qjfCzCG9wfac=;
        b=v/peV5HB7diZMIVn4t9Dj8XUXIlTzVjxdTKtWAYZdVSQfWexRdhD9zhjToUupM7dEX
         H+itE4N6N8bMRignZjesJLM7kLZbKvczkaPHdUwrDApT/wA4kP5pdeGwXHphFGLN3YUx
         bj6rTULu50gPUXsVQNDOYSE7qF2B8lqqeu3FQQxoKEJczOwet0V2lnH0OQ0pgJ+3M+Gg
         VuAS3Mjmg4E1zWp2TevAOzHbc490ZQHEV/S8zCPU7wso2CU10SkcTEpjZx0hGie+Rtcs
         XJruab+iG4O3sLoBn5ebVrXLWWwhU+6vojNJAUCaFwhgQvAjmuRteNSRaPaScBM/n+Hb
         /nww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WwNZRP5s;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id b9-20020a05600003c900b003177f06b59fsi748177wrg.1.2023.08.14.04.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 04:16:34 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10801"; a="375721910"
X-IronPort-AV: E=Sophos;i="6.01,172,1684825200"; 
   d="scan'208";a="375721910"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 04:16:17 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10801"; a="733416210"
X-IronPort-AV: E=Sophos;i="6.01,172,1684825200"; 
   d="scan'208";a="733416210"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga002.jf.intel.com with ESMTP; 14 Aug 2023 04:16:14 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qVVYS-0021iT-2B;
	Mon, 14 Aug 2023 14:16:12 +0300
Date: Mon, 14 Aug 2023 14:16:12 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNoM/LUhjG2/NHl1@smile.fi.intel.com>
References: <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
 <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
 <ZNTjbtNhWts5i8Q0@smile.fi.intel.com>
 <37faa9c7-94a3-3ea1-f116-6ff5cdf021cd@rasmusvillemoes.dk>
 <20230811152817.010e1da3@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230811152817.010e1da3@gandalf.local.home>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=WwNZRP5s;       spf=none
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

On Fri, Aug 11, 2023 at 03:28:17PM -0400, Steven Rostedt wrote:
> On Thu, 10 Aug 2023 16:17:57 +0200
> Rasmus Villemoes <linux@rasmusvillemoes.dk> wrote:
> 
> > > Btw, it's easy to enforce IIUC, i.e. by dropping
> > > 
> > >   #ifndef _FOO_H
> > >   #define _FOO_H
> > >   #endif
> > > 
> > > mantra from the headers.
> > 
> > No, you can't do that, because some headers legitimately include other
> > headers, often for type definitions. Say some struct definition where
> > one of the members is another struct (struct list_head being an obvious
> > example). Or a static inline function.
> > 
> > We _also_ don't want to force everybody who includes a.h to ensure that
> > they first include b.h because something in a.h needs stuff from b.h.
> > 
> > So include guards must be used. They are a so well-known idiom that gcc
> > even has special code for handling them: If everything in a foo.h file
> > except comments is inside an ifndef/define/endif, gcc remembers that
> > that foo.h file has such an include guard, so when gcc then encounters
> > some #include directive that would again resolve to that same foo.h, and
> > the include guard hasn't been #undef'ed, it doesn't even do the syscalls
> > to open/read/close the file again.
> 
> I hope Andy was just joking with that recommendation.

Too radical to be true to implement. But it's always good to have a rationale
(thanks Rasmus) behind existing approach.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNoM/LUhjG2/NHl1%40smile.fi.intel.com.

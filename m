Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBV77XKTAMGQEIKIXJGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C1ADA771261
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 23:32:09 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4fe3cbb4398sf9518e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 14:32:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691271129; cv=pass;
        d=google.com; s=arc-20160816;
        b=IMhz6vGyM6EjQ2koHfbOxlPOkEv/e2MKRTYy6f//RyIOlhIe5SZBRc+0lAaPvB66cB
         dKci+RsS0qBy5+n3RIbFoJEK3wLJKwjzP5IhD4eOZDzaPRe1rknEnqaGu6DHVE63ath9
         qsHs0lq0vbQmLoNUHP3DUrjRzbPA6OVPKtm5I1B/BOaZJXZSRb8HGGyMZGcPmvm+zJ2b
         /6hh5pL+Qz1g2HQd5t36IlDnaoBraDCvqrS8bScKeeG4CImAOipErBJMvC086qQ09bqq
         PjOrSYK3kLoFkcxc4WZwy/leNFmCTV1rpv1vvs+D8SRFyetcBaye39prKjxMjBppC559
         GWtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lcm1KaW35L3LC+520jSkT3gu5LEeWAo3tYUAphEYPUc=;
        fh=aZKWQjavICzodXYqF8YKqkykQ9aB4sqRNcxR1QPOtDA=;
        b=NjEg/st+pCsP4O82YxB8tfERlDd4qy6UXpipEn9Rwgns5imjJMqj0RtonKznzsv7V0
         g1sFdtJIuGngPKKATbXv6WVlOrbSezg+HIql2eyTL2ddhFXkQRETcpfUSqAMTQeVyQ1L
         gkGIaiNt7zLLIWmsi2kCDkfcBgQJRSgJu6F46nzaEnqvhACn7aSYmNJmdbe2WvufwEzi
         I4uySjsDQPhEQIAWQ8hwPQcuxDJRLZkW8ynlKg9EjcYiCXMyoi3FgJJ/Lfkh8Km0lRZu
         jP+/2LIGfo0nV5pQ1WQXlXWUKS91JCLswLOk1y0dfliKIut4Q9D4/t/hjWvoL36uvuDr
         7mfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lppL3pHQ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691271129; x=1691875929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lcm1KaW35L3LC+520jSkT3gu5LEeWAo3tYUAphEYPUc=;
        b=UpLRQwUuJHrCeo/p85baFsdOlgyvtmJfYoFu8F/5Kgx9A4hkOqP1DTTwIkBia5HGZC
         PdHfmLW7XGUeBO25h7QDF5lhcaZZCu8bf6hYsxfX5+R2MrdxDtqgaG33s+8pnLLNCILc
         qyNc4/pHdH6O0Vu582oGV21rogXjTxYYiJHtGCievJmzhQCl1OKSJ1LJKnX5tagZ3Ji0
         H8chpBbJcOZm6qd10hZpXWp9a43utODHYO+zAj5EMIjXICyMYhPBVWx/4wv/XGRBYWad
         KcSUpVrMOu0IcrvC8VZfAkB/PK5ly6zJJHr3wpu017CO5Pso8J6UZdWN94MW+KSbyS8F
         fhyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691271129; x=1691875929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=lcm1KaW35L3LC+520jSkT3gu5LEeWAo3tYUAphEYPUc=;
        b=C5aZvLnzswDv773qiY9opqfI5fSCb/3fSzx24Ji2/ZEMZ/XHxhv28qYeQ/sMoJbovK
         I9uHtp2UlOZzaa53XVIVpCVNFDMu/Yujr62UFo7B/M5jrLs5UoEYr0fOFZU/BP1Ao82K
         5Iji8JOaiWhh2mQbxNln3NbTbhbiwGYyWLqQyxAvDzcHd3K2k1iVr+dRDwgtlaA2WkGX
         QtwXIHkyxXPIfeJMCdtKP0BpmfGxB1RKzqZJYh3adBmqzxE3pPxUVT/BC1AFRD35+/KZ
         lkGEe+l4tD7hIfyCHabD7q2QKwHlPUtskW46ZDeqX2IlwBI3AA6/1K8keWeF61gROQUU
         LeMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx+vtVG4uCgh5/zcOgwRp0EugPHv7MAiVg3eRz8ZO34ITenI7Xw
	9j5Jh9KR25hOXaRR5OWbLtA=
X-Google-Smtp-Source: AGHT+IGxaGlfXHLw9BxM6YAolC6Lx8fkU8aVgb/agb+csXvZHgHeHqF0WSHQSgvZN4y7CE1mHrXj4Q==
X-Received: by 2002:ac2:43a7:0:b0:4fd:eb37:7980 with SMTP id t7-20020ac243a7000000b004fdeb377980mr33548lfl.1.1691271128124;
        Sat, 05 Aug 2023 14:32:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:da1a:0:b0:4fb:8bfd:32d5 with SMTP id r26-20020a19da1a000000b004fb8bfd32d5ls321627lfg.2.-pod-prod-00-eu;
 Sat, 05 Aug 2023 14:32:06 -0700 (PDT)
X-Received: by 2002:a19:5056:0:b0:4fb:a088:cfca with SMTP id z22-20020a195056000000b004fba088cfcamr1050095lfj.6.1691271126053;
        Sat, 05 Aug 2023 14:32:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691271126; cv=none;
        d=google.com; s=arc-20160816;
        b=e29d8Q4QdkvPEvKmpx8DD1bY7+C9Z7Xts8xdMUlG0r++CT9cuH0D2EF3RiyxhV1ZAK
         GFzOlnFpHYx6C+EWApigXd7cK+kfsqXAbiCilUMOjMuywjGoNAikiWXHaPHPBYZgY9zR
         9Q968ykAqDTSnRvpe65St9SdXdyYrwVHEc0a+OHMODmCBmGtrH0WcyJ4IWX6ciJjf0K3
         pcntCSj+RfRq8osggGtIIt33dE2QX8sbpCB+GVfgZ0F8zgpLhSeN7grFWZme65LR5W5y
         lsmj3xM0tP5ko919ameZTmdtkLFipMDfQ58itjBp6ETbM36q2E0gEW8sik6dh+9o6CBz
         cTQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GzTDWoMA0J4ZT/qxpYx+BlXqMFiWk8LA+fd4CYcqr6I=;
        fh=aZKWQjavICzodXYqF8YKqkykQ9aB4sqRNcxR1QPOtDA=;
        b=0WJ64BSgi6UU4FzjJJfAN8fa0g5gETYTf9wkkulO5JVkHIzQZfxy5zKAMTbY9cVXSQ
         DyDRZ9jSJker7dP5NtPRuY+70BGwCn6QioEbBLxof0+Qn394+6k/Evir9qsXsVQxZG6A
         PXibFFNAD1ylaFJMsqSVAkgQ1sGQNRbg1rgfsuv8pVLyn3MBwPTQEZNQGqZr5HwNW51v
         aOmgkhWSaIm+5l6JPKrKSkjbB//wscltnyE/8BlHHvgUWMt/KsgxSy5oqcHp44VSbxB/
         vgla1faXdtK3TTwmmRcGYbpbHF6m3WxllL2IcxhrwowRzf2nuKr7eASGcA4FkC00XrPG
         6KXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lppL3pHQ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id v2-20020a056512348200b004fe562df054si312610lfr.4.2023.08.05.14.32.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Aug 2023 14:32:05 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="360408037"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="360408037"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Aug 2023 14:32:03 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="730458453"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="730458453"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga002.jf.intel.com with ESMTP; 05 Aug 2023 14:32:00 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qSOsP-004wdI-36;
	Sun, 06 Aug 2023 00:31:57 +0300
Date: Sun, 6 Aug 2023 00:31:57 +0300
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
Message-ID: <ZM6/za76TZyX5tdg@smile.fi.intel.com>
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
 header.i=@intel.com header.s=Intel header.b=lppL3pHQ;       spf=none
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
> 
> And such conversions will presumably cause all sorts of nasties
> which require additional work?
> 
> So... what's the plan here?

My main plan is to clean _headers_ from kernel.h.
The rest of the code may do that gradually.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZM6/za76TZyX5tdg%40smile.fi.intel.com.

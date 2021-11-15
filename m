Return-Path: <kasan-dev+bncBDA5BKNJ6MIBB4XJZGGAMGQEW76UO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id B375D4507A4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 15:55:46 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id bx28-20020a0564020b5c00b003e7c42443dbsf2242768edb.15
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 06:55:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636988146; cv=pass;
        d=google.com; s=arc-20160816;
        b=SDRbsAHhJ7JbArB9TDQH88E+l5Wj5r/juug7yrSm/5Drm577lak7GQYBCeUQo0Yx01
         fccs5P9x0geeuG8vve57F0ajATMwbKlyE46lum+sOErh18VabsEuO5Miv0VcZVrms46/
         PPoflb/5Cad3j8oJu/H5Qc9eLWrlFcRqY2hGBHBQfPvrxueE/Fy0FRQaDJkJqH5fVydm
         PLCDplUti3ifQovptMcm2zhf3sAojILLC//3PJyRovOsRq+HalgxXrR6QKIfsJIcxbVG
         6oB6FinJBxvNyKxcENrvj4YDw8uMm3gmn4G7H7d33wC0z3b+Khaa8z3kZm+6Fvq0yDKR
         NbpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ZzcjVhsn9Hwa4c5xGcOCHRPBk7iRCvFlaa0CGMhZ0pA=;
        b=pNjPI+LafkQLysVfZef8wrilZs0D0B7z+fR4SwtEPUDmNwd/GKMT8l0wIZnt2acp2P
         Euk/Vn4n3G4UTf/bX8GO4c4jI0BWGKTXMNOmJ6Oc9rW+P5OEznlNHoqjzw8S3bieSSGe
         NzH8A0WmpRPawb/8Y9+m2k4DlHoKy9tVZg3T0tNkj0ojCJMy4QE/0qV8X1KeTDR9Q7rj
         JSL/NFeDg8Kux8f4eCYZ4XN3zkuHN2DTLNZnWX7KM2G2UAWXHkiLkrxRNWptZ1qtW4kK
         QnSOfxUQj03cFBE+b8XLFzIiEX8YeyOe9vW+wrfo1Qii6uLGZV+XyOVao2fo3suc/Xdw
         WmlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZzcjVhsn9Hwa4c5xGcOCHRPBk7iRCvFlaa0CGMhZ0pA=;
        b=fuBUCrbScF2++4mxzWJTzX9FPOi7yXXJa549FVVveb4G2S4BscPQa59deN1c25ZXUF
         4m+GoZpLIjdtkYFknqe0FprJpmSFsjWB91+A/IVrgTusPzslBEsrUxr451TkxFc/8Gib
         zF0NN52l9dKkw49fZb6qEDzU/TrkyAOfsLNZmxOLb5zR8tGCwy84UUhMOqQeN4YFQC2/
         8MBkJ6c0ZQUau04J+btfwEgX22t1A1dKcBjGf0FXlt96R/FkPpdre4/K4DTmbO0sgQWb
         BR00ddKsvxOOcnnF3kZxQo1hq91+xQwo8kgkVlDiafjLFi04n7arlioE+W18wzy/dOaX
         erNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZzcjVhsn9Hwa4c5xGcOCHRPBk7iRCvFlaa0CGMhZ0pA=;
        b=fCcxA3hz0hsRdu/foS20n7FOgPd1X7CS27bn5CQh9PNPpz9vTkeUwMjMhLCJJjsKUs
         n3eeajEvfpxZ0j54E9DvCd+fgpAXc7Wzp8t7Ov9YnPdop4yBdfOySjXgaJzBIAegGN7i
         So4X/kMlOXrMV4QI+KCmTQwph0eSv2/dwFqXb5g0NkHNkmrZwrTVgUHoUCLhLBKD8owX
         s+nr0/m6hURu+QRaFWZ8k/9QUw6Fx3y+p/WmrdYCcEq/cIq/YCZMw25c4soGRw/ZaBkh
         eCdpq2NcFGNWQ68mVAioz5VxFE9YsNL3JCBC1ALp1eT+zJdxjg3HBgbM48yq16L2tEqn
         /pgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BturwRVxStljFrDN0p0rtLXBOjA1befJSo2QNt5hDVeuqs7v1
	YLmqiWuL3PYroOH8XA1d1fM=
X-Google-Smtp-Source: ABdhPJypjyuv3Ijz2y3HcQ+SBhfUfkI8rwt1KqiWAd8AdWdofXfaEd5ohObovIW/YABwJi8ErIehIw==
X-Received: by 2002:a50:e707:: with SMTP id a7mr56646659edn.352.1636988146531;
        Mon, 15 Nov 2021 06:55:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:c0a:: with SMTP id ga10ls5719320ejc.9.gmail; Mon, 15
 Nov 2021 06:55:45 -0800 (PST)
X-Received: by 2002:a17:906:8699:: with SMTP id g25mr49703434ejx.271.1636988145645;
        Mon, 15 Nov 2021 06:55:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636988145; cv=none;
        d=google.com; s=arc-20160816;
        b=L2/SNxoM5ftld7VqQDmR8PIaucsYZTEkDiEWegIVZV99dbCpU4Ph3UBIc9q85CT6HM
         ogpbVmbC4LfoK338TSKuofVYLG9sj6EJK4D5gUYN1N4d0YL4Nbd+QgubRvgvs/eqzlhK
         0veDb3qyXm7XlGv2Xh9Afrs7OqAfF7alzcccjqT0ddvqY6wh0wODdsxcjz0nWwskhBU1
         6LzUk5/fk40a52GUH6muAQ9qJwDh9iG1Dq9YxK+JDtvIbXfWYP0b1FiP+w0opOKyCOtu
         ZKa2vVm2Y8FHjRGhMbDQAr4JLDVCUHNCjpP3BLgzz5mwfv27cDGyOKM3t5ZwpI/av6sl
         Ihhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=IHHKmU4diSFq4hqtapWtREnZnfrG2MIQMm/XtutvMec=;
        b=cI6CVaG0IDz8Dxz+v+MdYu2HPhZMlwT9tPKGAhrNDcADhQ446BJ8YyE3JB8s+1YxeE
         5inOXI31mWUznYWFovyyAIWcmIU1eOYP/xUkvxyffSQXfe6Yp9irmFs3BZuNGD5mkOL4
         4a6A2jdbGGMVdewLcF+wJkMnT19Hpj6YQgfC/0qctGdENC4jriWCCBC6YjGhrntMBAVE
         pmKmG9otUeLSOn6qM0lWWEukQcm7DLLEXskkMsWAwKx2BQ/qM7Zl28Rc1BUfOOrr+LRl
         R4p5d5BlKp+18aomIuutMPnQYMc/8RXT+gEtBn/YhB4yHMVy2cVzqxSDBWifxGtg4aWg
         119w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id w5si1020734ede.3.2021.11.15.06.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Nov 2021 06:55:45 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6200,9189,10168"; a="213486057"
X-IronPort-AV: E=Sophos;i="5.87,236,1631602800"; 
   d="scan'208";a="213486057"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 06:55:31 -0800
X-IronPort-AV: E=Sophos;i="5.87,236,1631602800"; 
   d="scan'208";a="471929100"
Received: from smile.fi.intel.com ([10.237.72.184])
  by orsmga002-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 06:55:27 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.95)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1mmdO9-0077gj-Vz;
	Mon, 15 Nov 2021 16:55:17 +0200
Date: Mon, 15 Nov 2021 16:55:17 +0200
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Petr Mladek <pmladek@suse.com>,
	Luis Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>,
	Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	John Ogness <john.ogness@linutronix.de>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Alexander Popov <alex.popov@linux.com>
Subject: Re: [PATCH] panic: use error_report_end tracepoint on warnings
Message-ID: <YZJ01V8fZBlWz4VW@smile.fi.intel.com>
References: <20211115085630.1756817-1-elver@google.com>
 <YZJw69RdPES7gHBM@smile.fi.intel.com>
 <CANpmjNMcxQ1YrvsbO-+=5vmW6rwhChjgB20FUMKvHQ9HXNwcAg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMcxQ1YrvsbO-+=5vmW6rwhChjgB20FUMKvHQ9HXNwcAg@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 192.55.52.136 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Nov 15, 2021 at 03:40:24PM +0100, Marco Elver wrote:
> On Mon, 15 Nov 2021 at 15:38, Andy Shevchenko
> <andriy.shevchenko@linux.intel.com> wrote:
> > On Mon, Nov 15, 2021 at 09:56:30AM +0100, Marco Elver wrote:

...

> > >       ERROR_DETECTOR_KFENCE,
> > > -     ERROR_DETECTOR_KASAN
> > > +     ERROR_DETECTOR_KASAN,
> > > +     ERROR_DETECTOR_WARN
> >
> > ...which exactly shows my point (given many times somewhere else) why comma
> > is good to have when we are not sure the item is a terminator one in the enum
> > or array of elements.
> 
> So you want me to add a comma?

Yes. And you see exactly why I'm asking for that.

> (I'm not participating in bikeshedding here, just tell me what to do.)

Done!

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZJ01V8fZBlWz4VW%40smile.fi.intel.com.

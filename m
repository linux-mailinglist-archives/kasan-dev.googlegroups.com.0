Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBCPTZCTAMGQEPNHQHPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C5E773A42
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 14:48:11 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe3fb358easf5586591e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 05:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691498890; cv=pass;
        d=google.com; s=arc-20160816;
        b=u5BKx4OJOD/naquIFnT++siOfUAKzgLkQLEekT4oko8pJ+HWuSCX5stkupTmXqxJR4
         vxXRe0nHQm/LJnHWp3Jmb8AOtLKNFL9JVcB6ypViTnLiAlIIaPjMztTTPVFmzueg+uAk
         BEaZ3GEYbSUEM/AFeDuA/t3ZNdlVSDWESQ4tm9cEc2EV5/kwtpznYUpS3sRmz0yjsSAh
         imJ8b5yLXMehNFAd7P432jvEqucA5tX9dqdYlvPhB+LWNd1XsFn3017n1ROdCySxGtpD
         fiMZV/PLfTzTWC3PIvadqY2gUy5DN0L71h/7zMpmD0R7H9AKBMa3rssnkIHisNErNAtI
         YK/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cliyRuEGblXzb97xiFabrch2nz6Y5cDyX1+6GDT/mCI=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=Cu2rWjQetA8p0wIAw6oNNqq/F9jn6/O/Gq2XmnRdTAVc+bdTeSU/0aJVx9lz0IMObc
         hTht1Xg9aYDHyvrmhpuF1PA1pIuoiKdG6N+DGQqUIxYhT4cyrni23szc3r7IH7hYpeLM
         D94K0MGCnLIwBcOPPP4UK0EEZ5+8K+1SBBnqsmQry6TEqBJaovNYYfKD1FBBlgQXtcdw
         MQVdUc5KtrujjSXGll//xlDHF55yNE/XZjJ0UJqbShk/qyPCk8MyE0ZuK3QkRX0MRPi+
         XqhKaVCI9t5vBSW2huXDt3mBiITzHJKkgqOr24mMuanKfEzVhkhZ3sY119J2JODQDRw6
         1rtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ui2OVnqR;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691498890; x=1692103690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cliyRuEGblXzb97xiFabrch2nz6Y5cDyX1+6GDT/mCI=;
        b=O5ARTlnAwED4zR0Z0DLPMobFSnS3ckjP7Z04sV+UIxdDMLNc+tm5q1ATGGAfBcYNJt
         hF605W9x5kTpKKeY6OPxYG7VlKwjVE62mT7r87RGnCtoeB7xaTM1pwt2xR0jBZvHhsaL
         DX4POZE8w9qqJFkOQiLeLX6bv2cCFCSeN0/U5Yt2qSs1432EPV2rJ7sOnGDx2baNgXY4
         wC/pGXfzH3Bi7xn+siNGDm3sXRPGv3mF6Jxnnmp0MFqPrl6bVTBL8L52Q4jpL9Yj+nY8
         kSDWr+ubRgYdH4huy4YMho3SAK7q7wIH91pmSnSPqiExLAmae9R05GNqgOVKaM3w7pcr
         TX6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691498890; x=1692103690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=cliyRuEGblXzb97xiFabrch2nz6Y5cDyX1+6GDT/mCI=;
        b=X5JLGwm+6NLHdFE+39MocVkKzuCw1qCMZ4a76+JmI22XCjAqAa/1wznbVCE0z7ZCCf
         XsXkF8PhkElf8/WPIdqjttUYMz4qLN6j3lI4Qd8fUn/hOp/l6vbS+zD+q/zn7gIu63B+
         DUFvDB0o0zaH9NxuJQjKQPWKKfx8jR+1705D1CvcQ6e9GUNHEuKYtmur+g87B9O2Hv4A
         35gzNVCMxJI8FZUh1U7BeopTrdS+GSbOlcPXkHCVM9oX41K5oWq6LtnduOyO+HWeDKGh
         ULW359Gcx2OXuyM50MGw+I7Wr91lQUAYwdmXPOiZFL4RGsqVCx2Jmn2cg+ly8CfrkHAd
         nHPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyBv+B1WVHAVd6fqWHabmoCPI3wc8wLVV8i4oUcICMmsr/JtMNg
	FECROQC/zdixQgcTYNePxoc=
X-Google-Smtp-Source: AGHT+IGpXt5nkqCV4EGf9XvE7s1ivFgU9D8QT2Yl7/rXAXLC5L2JAdbKA+zGTor801XFyTLVCFGASQ==
X-Received: by 2002:a05:6512:474:b0:4fb:caed:95c3 with SMTP id x20-20020a056512047400b004fbcaed95c3mr7339406lfd.53.1691498889721;
        Tue, 08 Aug 2023 05:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:464e:0:b0:4fe:56c5:2906 with SMTP id s14-20020ac2464e000000b004fe56c52906ls40815lfo.0.-pod-prod-07-eu;
 Tue, 08 Aug 2023 05:48:08 -0700 (PDT)
X-Received: by 2002:ac2:4d10:0:b0:4fe:82c:5c8a with SMTP id r16-20020ac24d10000000b004fe082c5c8amr6822710lfi.58.1691498887970;
        Tue, 08 Aug 2023 05:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691498887; cv=none;
        d=google.com; s=arc-20160816;
        b=JFpxBSJqyH92R75Vm63pi76ojoy9ngqROLgwJK9OF318kTeaey86BCRgI1FzrTW9Sh
         B8wYwO9Z3xJsqzOb4pRlkqQlxinFdmX07ehiHdvODweFF03ATyJ7C52spbn317CaB7bJ
         8tv5c5ZQRUpuVXJmbtmW8teXSwXVL1QzoWTslOqfD2nsZkEtKZF2/aHWu3B9OphwgBZ4
         uLN6JjurElTIaL+vs9Ttas2FKfRUtlZHUnDp3AWh5tsSMjh2Q1VkDRb86DUuYQIOo6K7
         nzsc5la7nzcJhe1aMO8U8269v1QMKrmNjTuvF0XS5YghcMIH3FW7jk+v1hXtEIgpXIDc
         nrWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Vmmbn/SYTdAX6khGfnmT6e6vl79rTBhgIsmeqcQLC/8=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=QbXryzkJ/1SJibAJ/tqdWbqFFPxfBuVEpurWa9Ro8SXuAjG7n2gX61P22Ycke+ldQ8
         MIVd42VzS4RUY6kUSyF+PzZIAxqONzbjzzkwJLRt0kymY0f6S5YAMeQDVqPDD0hNl3g6
         Nkn7iXN20ny1No5ocgYDo3j3lK1AFOGxk0vn+g9ZNm7CXx4IIhZtV0bKb+8gKjEha6AC
         s5lAPo0iDO7gVvdnUQkp4mnBEHfSJ8oSlm577yhcOiE3AuD9usbZiP9l75JK7AgEWq7Y
         WQVUfIdoKFMIXOBMEcC3mFWiup4k/lg8ZHPclojahUAeiaiN+xHq63RKl0nyLKGRQmhm
         d4/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ui2OVnqR;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id g36-20020a056402322400b0051fe8b74bddsi763945eda.0.2023.08.08.05.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Aug 2023 05:48:07 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="368258928"
X-IronPort-AV: E=Sophos;i="6.01,156,1684825200"; 
   d="scan'208";a="368258928"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Aug 2023 05:48:04 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.01,202,1684825200"; 
   d="scan'208";a="874710309"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga001.fm.intel.com with ESMTP; 08 Aug 2023 05:48:05 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qTM80-008Nsn-09;
	Tue, 08 Aug 2023 15:48:00 +0300
Date: Tue, 8 Aug 2023 15:47:59 +0300
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
Message-ID: <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNHjrW8y_FXfA7N_@alley>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ui2OVnqR;       spf=none
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

On Tue, Aug 08, 2023 at 08:41:49AM +0200, Petr Mladek wrote:
> On Mon 2023-08-07 18:13:57, Andy Shevchenko wrote:
> > On Mon, Aug 07, 2023 at 06:11:24PM +0300, Andy Shevchenko wrote:
> > > On Mon, Aug 07, 2023 at 06:09:54PM +0300, Andy Shevchenko wrote:
> > > > On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > > > > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:

...

> > > > > How does this sound, please?
> > > > 
> > > > Not every user (especially _header_) wants to have printk.h included just for
> > > > sprintf.h that may have nothing to do with real output. So, same reasoning
> > > > from me as keeping that in kernel.h, i.e. printk.h no better.
> > > 
> > > (haven't check these, just to show how many _headers_ uses sprintf() call)
> > > 
> > > $ git grep -lw s.*printf -- include/linux/
> > > include/linux/acpi.h
> > > include/linux/audit.h
> > > include/linux/btf.h
> > > include/linux/dev_printk.h
> > > include/linux/device-mapper.h
> > > include/linux/efi.h
> > > include/linux/fortify-string.h
> > > include/linux/fs.h
> > > include/linux/gameport.h
> > > include/linux/kdb.h
> > > include/linux/kdev_t.h
> > > include/linux/kernel.h
> > > include/linux/mmiotrace.h
> > > include/linux/netlink.h
> > > include/linux/pci-p2pdma.h
> > > include/linux/perf_event.h
> > > include/linux/printk.h
> > > include/linux/seq_buf.h
> > > include/linux/seq_file.h
> > > include/linux/shrinker.h
> > > include/linux/string.h
> > > include/linux/sunrpc/svc_xprt.h
> > > include/linux/tnum.h
> > > include/linux/trace_seq.h
> > > include/linux/usb.h
> > > include/linux/usb/gadget_configfs.h
> > 
> > Okay, revised as my regexp was too lazy
> > 
> > $ git grep -lw s[^[:space:]_]*printf -- include/linux/
> > include/linux/btf.h
> > include/linux/device-mapper.h
> > include/linux/efi.h
> > include/linux/fortify-string.h
> > include/linux/kdev_t.h
> > include/linux/kernel.h
> > include/linux/netlink.h
> > include/linux/pci-p2pdma.h
> > include/linux/perf_event.h
> > include/linux/sunrpc/svc_xprt.h
> > include/linux/tnum.h
> > include/linux/usb.h
> > include/linux/usb/gadget_configfs.h
> 
> This is only a tiny part of the picture.
> 
> $> git grep sc*n*printf | cut -d : -f1 | uniq | grep "\.c$" | wc -l
> 5254
> $> find . -name  "*.c" | wc -l
> 32319
> 
> It means that the vsprintf() family is used in 1/6 of all kernel
> source files. They would need to include one extra header.

No, not only one. more, but the outcome of this is not using what is not used
and unwinding the header dependency hell.

But hey, I am not talking about C files right now, it's secondary, however
in IIO we want to get rid of kernel.h in the C files as well.

Also, please, go through all of them and tell, how many of them are using
stuff from kernel.h besides sprintf.h and ARRAY_SIZE() (which I plan
for a long time to split from kernel.h)?

> If you split headers into so many small pieces then all
> source files will start with 3 screens of includes. I do not see
> how this helps with maintainability.

It should be a compromise. But including kernel.h mess into a file
(**especially** into header) for let's say a single sprintf() call
or use ARRAY_SIZE() macro is a bad idea. _This_ is not maintainable
code and developers definitely haven't put their brains to what they
are doing with the header inclusion block in their code.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNI5f%2B5Akd0nwssv%40smile.fi.intel.com.

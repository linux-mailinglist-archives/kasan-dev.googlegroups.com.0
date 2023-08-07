Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBPUUYSTAMGQELX6SW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 173E17728D6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:14:07 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-3fe1d5e2982sf26217695e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:14:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691421246; cv=pass;
        d=google.com; s=arc-20160816;
        b=e07Newtq559g1NVmYOtPI8VxYqRN/pdT1GXZrXnVKf2+A+p+7SvWIwJeW4ZyhbR4qu
         4pK0ocvPTrjZm3shexfqle2LXm1L2k1Q1uSDg2KSf1xzOMUbXtSd3yBfC4nQkETfzL5s
         xGkcqBxhX+dgOLEL34pBQ0xktvfJbJbOM4mLuhMslWLg480KPPHyhuwUojesiM+t08/+
         wMrNqPtQqSEPz93CJm1QdGxbYuNxfCZ4ZD4uK42hWe9yDdz4MtkJfhAT93M4rvdMsu/i
         f+bEEjsByEu1zVpGkWj9Jne9Me4jOgB4Fx2L0H7jaJ8rDYRxmchliuVI6gGoeRfcXNmn
         aW/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=7JsG4/styL4A0h0Z1cl7q9OehbgivC0TEAC7IwAOuIo=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=ZHuEys5nshFscIpDjYd4HxEMKlFEaW/91BbdELu+wuJiCAdRnL9flXME7/sVyk7jOi
         349OtWYb5NVMrNgycWB/ffZv4IRp39g+6Yna0GPdI6x9aa3p2x9FZFaj2/rSHZjCV7+2
         RxPcTxY1pPufKniJ6y2hudUQkmqji5/3ARZmCdSXAY1XRP+7y1YbwIEUQyYr9Lw24OYu
         iS7TjbIh4f24EnWlqoS83tD4OpqAjWf9FRydbKUSutBuAvmKvmDcRkWRpGv/ZiohLa6m
         VwxzFM8DL+pRRHjKxNnwUimP1D+E/AYioENA9iA5A3meY5agRbIUwvyJ5Vl2o97n5qvY
         jleg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W5KfPEjZ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691421246; x=1692026046;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7JsG4/styL4A0h0Z1cl7q9OehbgivC0TEAC7IwAOuIo=;
        b=AsfoOsfLta92nL896Ql9frYoGM8Cyuf/0SkFaKElUI2pOIbcB2/5oJKpsbyTAJGmI8
         dgf12wnNX3s0Fh2TxWpXA0i84d8CdLxJs4MkqF+4Tjd/2hAJfeaoB8FkC7Xhpwq6i5ds
         b+EC4h27jAT/94T6A5/s8pfrrwjOJc/z04L/bTPgDlQy6y+NlmUa+SgodZCMzu0PqrwS
         wM8DwU/qCvx+M/MU6HO+NiAhmJwEusehJ9+kcO0xIUVkcxN05ZKF/kxA0V9Z7jI0ZfNh
         VOuf56nI0tmbwgWBlwWJ34FYGmHgjGBMiNhxh3b6OTc13/Fo8LZNTf0CPCYBbvwW/qHm
         JpJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691421246; x=1692026046;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7JsG4/styL4A0h0Z1cl7q9OehbgivC0TEAC7IwAOuIo=;
        b=Tby6l2gTwBPwmGnNVOT+QIepwqM1NMJlxNB1WhiPZKV+Kb1BITU6qWpXynvKRIataN
         Ht+c7je1uWXjmR6cDa1v143c+DzooLK6/e1jKm7RHQKttC0KKVFuiY3ysXw6WviVN1jJ
         Oxbz4y+WjMePdgCQvP5aj2hY7sJAMKsFqVMrgkBJNKqRIV/bAY4OEhW1IGOkIoabH01M
         O79C1Jm7qeLN+/3sVQMOtMPd4IE7QUbXcSFexRjWfuSBRhO6m9W0hR9BeWbgH5wQDZ0U
         ABMTxP+nqiwh1Qcsvg0JD7uPquZF8809nl7PAbhEuktznIxMI4oZFIS08LCGbAWmz0s8
         tsxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJOqsUAbnOyqW6EugrJKi6mJDnXhdA5I5Jx9xbBcwEvkCma+B3
	/owEMFP+mhtKjSRups+w5kA=
X-Google-Smtp-Source: AGHT+IGcEF3tsRQOyNUz5eeeQK7ER1DMzfIgYVwbVCSX6WemHCA6W/WJC7aZe2oEqj8o5GkBktvPsw==
X-Received: by 2002:a1c:7c05:0:b0:3fb:e4ce:cc65 with SMTP id x5-20020a1c7c05000000b003fbe4cecc65mr5936885wmc.25.1691421246269;
        Mon, 07 Aug 2023 08:14:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d84:b0:3fb:f228:b8a with SMTP id
 p4-20020a05600c1d8400b003fbf2280b8als161169wms.1.-pod-prod-03-eu; Mon, 07 Aug
 2023 08:14:04 -0700 (PDT)
X-Received: by 2002:a7b:cb85:0:b0:3fb:d1c1:9b79 with SMTP id m5-20020a7bcb85000000b003fbd1c19b79mr6125982wmi.30.1691421244635;
        Mon, 07 Aug 2023 08:14:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691421244; cv=none;
        d=google.com; s=arc-20160816;
        b=ev/RiPSG4cLlWZeS84dGKTcfvcT7n0NMHglN2aRmQbEkla4WHNFciluWsoFDD8yhe9
         0SxvYktwgqIDBnflPS4JzvUXX31nFQOcbxVwjJoxa2sqItjHhv9AQi0Wmr/93LKL8jRG
         tt+JiIGSb6Sq7KQbt/5JuPJ9Ej3xqT25MLQvc1mKSshMUSfAp4mU5jQXSr403xlTq9zs
         rdy6aijpDmYegWe+gOQ0qYEDxLyBlnWuuOvaky94F2cCBTQ4y/6RPMFi7vLdmBKJZrur
         CgzcK1Jk27wHisA/azKBTG/BZrA8Mu7NOxyMclIc+azfcoEDjfzHh10K7b9ycmVj6PpR
         qNbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=QxjPwDRQeTvf2hrdzupU6NMittQpDDd8u4E+jcGgjYU=;
        fh=butcl/4cb234uvwnd9R+gLoHVnYq1VGIYFV0pEnGZqU=;
        b=rcIFn2UPHXk2lzHCBPsXStdg0F0UC+oa4ij5/IYIesU3MS9Hg8+f9+7Hw6nx4aySE8
         3s4lbPuieKoUAT+T0/6s5gnlVXnmtWO0oFqnw+AAFp7rfbaSmgfLPWQ710kEuOMbDMOB
         KQLtt7xWJ/EDeG+/Fvk+klnuzsiJ4l9liidK8Vh+l02mvkIvKE7OyOnHFrAiTEGPPOgS
         29eFgic7pJlzs24RLFqC/7CjXNk1C/A0DN+CJu/rnCYbPxcIpy0LHAZtMqtVCvFvNX8R
         uLUploL7Gx0ENSSFlM7Jchex0tovTsoJ+aTAEJDLI198Ay1LFtwhMwx60lK4Eeq/lrxX
         Cq2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W5KfPEjZ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id ay2-20020a05600c1e0200b003fe0df12dfcsi651146wmb.2.2023.08.07.08.14.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Aug 2023 08:14:04 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="360656649"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="360656649"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2023 08:14:02 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10795"; a="760531465"
X-IronPort-AV: E=Sophos;i="6.01,262,1684825200"; 
   d="scan'208";a="760531465"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga008.jf.intel.com with ESMTP; 07 Aug 2023 08:13:59 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qT1vh-00GtLP-22;
	Mon, 07 Aug 2023 18:13:57 +0300
Date: Mon, 7 Aug 2023 18:13:57 +0300
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
Message-ID: <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=W5KfPEjZ;       spf=none
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

On Mon, Aug 07, 2023 at 06:11:24PM +0300, Andy Shevchenko wrote:
> On Mon, Aug 07, 2023 at 06:09:54PM +0300, Andy Shevchenko wrote:
> > On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:

...

> > > How does this sound, please?
> > 
> > Not every user (especially _header_) wants to have printk.h included just for
> > sprintf.h that may have nothing to do with real output. So, same reasoning
> > from me as keeping that in kernel.h, i.e. printk.h no better.
> 
> (haven't check these, just to show how many _headers_ uses sprintf() call)
> 
> $ git grep -lw s.*printf -- include/linux/
> include/linux/acpi.h
> include/linux/audit.h
> include/linux/btf.h
> include/linux/dev_printk.h
> include/linux/device-mapper.h
> include/linux/efi.h
> include/linux/fortify-string.h
> include/linux/fs.h
> include/linux/gameport.h
> include/linux/kdb.h
> include/linux/kdev_t.h
> include/linux/kernel.h
> include/linux/mmiotrace.h
> include/linux/netlink.h
> include/linux/pci-p2pdma.h
> include/linux/perf_event.h
> include/linux/printk.h
> include/linux/seq_buf.h
> include/linux/seq_file.h
> include/linux/shrinker.h
> include/linux/string.h
> include/linux/sunrpc/svc_xprt.h
> include/linux/tnum.h
> include/linux/trace_seq.h
> include/linux/usb.h
> include/linux/usb/gadget_configfs.h

Okay, revised as my regexp was too lazy

$ git grep -lw s[^[:space:]_]*printf -- include/linux/
include/linux/btf.h
include/linux/device-mapper.h
include/linux/efi.h
include/linux/fortify-string.h
include/linux/kdev_t.h
include/linux/kernel.h
include/linux/netlink.h
include/linux/pci-p2pdma.h
include/linux/perf_event.h
include/linux/sunrpc/svc_xprt.h
include/linux/tnum.h
include/linux/usb.h
include/linux/usb/gadget_configfs.h


-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEKNWJGnksCNJnZ%40smile.fi.intel.com.

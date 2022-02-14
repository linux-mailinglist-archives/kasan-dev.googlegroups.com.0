Return-Path: <kasan-dev+bncBCR45TXBS4JBBJPLU6IAMGQE3GKUUMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BAB314B41F2
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 07:24:37 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id i10-20020adfaaca000000b001e4b2db0303sf4509823wrc.23
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Feb 2022 22:24:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644819877; cv=pass;
        d=google.com; s=arc-20160816;
        b=RHSJjqU8p9hC7CO81EhkiH0uCNhmpsQF2EYEgwRh4SilpgsUxw+AvvGKsLVs8L/teb
         f3fCZgS08iv5LODBYLcq6sYxHx79hZgxpeOtstGRX5t8vfBv0v+6cB3xTI25GJycURYG
         f8WKWd4NRtMbNUyNC2TXcDqJRoiEmqZix5pq8WafClLJAZPNf+k1NlNfs4sUh9aLwU3T
         Tsam4kJqmMJLuTHmoglrw2mIHJVzBqQopSrdvfBlV6qpvLuL8wYmhkZzlDMN1t0VonjV
         9D7HJHOdg492L4JSoflMm2xPetVjRpneoMXMeQU/Xj7H07Yo9sB9ahscQ81Q0Me3zjsP
         uMdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Uj3usDH62jWNVZFm+lODIY7TvEYsl+9lVVjNoZG1pAU=;
        b=YcCBdBJM5OcnvgYQ/HB42DDl3Qh9r6qJ18faiGG+Ady1a2ZlEHqUzs/LDBrGfFFH4+
         +TV6qSgJ2+C1xLKsiIMJrkX2XCKZ2oCfdOz6wLl0ClrNs4/n+r/5fjsqHnI1CB/o6XOi
         S/VDdWqPuCBVhjjjxlu4e+ljHQlnsfWXkHXRjpmfiAf/pOFaTPvlH9HD/cp65a+kDHaG
         xPDn2/gfmqZYO7NODgzaUUMdnM6e9euHjkTbh5k2ASDbRkkAOOq6mS0Nar/S4falU3At
         dvPUB3MTFpCEES5b21Yq6hP/4y0QT57Co0YFbKPE3UFBAQstvFvkO3o2+o3THo0RKkO0
         hyoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K8TVejin;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uj3usDH62jWNVZFm+lODIY7TvEYsl+9lVVjNoZG1pAU=;
        b=lw50p2BGihzSNfOjoM8Dvw8RXetL7Irt/eK3K0UgCJsKIlCvpJxOWYQcnFKq00cewh
         Nr/ozc6Z/1xlPznOdhUR2mBrFqL0QAtYkdCbLj8Ded9CgtzRUVqmJICn6itUQI8lDK7X
         Grw9pEowdS8iaUzCHsKr0mhJ93rfHP8rPApdO27J1m+zRsYSIfIg2HLAGa783RS4CYX+
         Y5jlFdDQiQGcBPoB4K1mQjAfylrBDX7nJtpVJWf4doGXf09UmE81p9CYoyXofHfQ071n
         nl2DBHKJa1OcwBMa8DNSDiggyS8/PTDfUvjDgH5h9MGntjnJnzRIX3vy1CupquFbrFCq
         2PXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uj3usDH62jWNVZFm+lODIY7TvEYsl+9lVVjNoZG1pAU=;
        b=YwOck3RaeiSgxOrBBYtM18RSNLNv5ZqwKFqdDVaHWde4SeQ3vtEz7CPykyM9naLV3O
         iI6MBNJxDoMaG18dP9c5EKVqB68yuW/HVuv0fsAXsfhCeS134J/CSyiNtON7yMjA2qDB
         xpk/WuQcxEjJr9P6Q+liAy7SPektGShKjyMAOomS9n0bLM0S8RG+QtP3tGSTFngYBCZ/
         9JrBbUaUV4WMMEqTXSbhir/MAUDdIbQEDbt2yYTuXks+auOgMAihjXJ9QJjxo2l13ruF
         IXZiP+I4y57NNSFr5ZrEsCl8/zZKtuXydus7Zny4NLrrPWCNifHfh6ESsS6Kw/0oPHX0
         W9nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308kloRJdULPbO1L4t9TEYmHTrffoFYIhShHMgT65xy7X8UauXH
	efS9MyaUOvhLo2lZPIkS2ck=
X-Google-Smtp-Source: ABdhPJyD9yMt2ZcUXPAOTEmaH0+5nji/oEwCxHktRKIstvX0np8StsGwY3k9MRBkUC/AQnxCTk265w==
X-Received: by 2002:a5d:5983:: with SMTP id n3mr10148372wri.382.1644819877398;
        Sun, 13 Feb 2022 22:24:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:bc83:: with SMTP id g3ls921845wrh.0.gmail; Sun, 13 Feb
 2022 22:24:36 -0800 (PST)
X-Received: by 2002:a05:6000:2cc:: with SMTP id o12mr4479486wry.371.1644819876429;
        Sun, 13 Feb 2022 22:24:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644819876; cv=none;
        d=google.com; s=arc-20160816;
        b=j3L+Fzpj6uvYkOjtwuwe9UO3KZa6GqcbdqSaDNThRFymk95GpzrvVbMwNlh89/j7nV
         I/zFrH9hjLyPvUQlPmtLxRGHOluDBEJgvHeCzoq7xcQxbHapWE1jDl2j0a8XfDTPOidE
         c4FQHAh0zz/DJianDz9G18Z/+RZwrMWxSw15yj4O/Cbe/oAlKz0X3Dk4cA6rQD1upp52
         s/rkn2rSwgNKAPk3NaemZXTy+sRJE4gj0DFf+5u3eFKWSU7VNlqCctDBsnbtiG7Rh/ed
         TvFs1Uvxjtw7SY1Qxqhu+2UPTxKwbRfq3oHYOdhQW0L3q/zKG1cQb5QaMSo90GNOiAFd
         iL4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=dIp4I74yJMinGQDwd1rM/tTCWCjbpxiXexWspsI9UqQ=;
        b=GDgGqSJPgWwpkdeDKntBHMhSl3x+9LD5mwghgP5S2k07eb1PPf1AuW8meqxAqCSlqh
         093roOUdB4ZWQgEvCqtfV5uGieO3ZUmcgyGoUxbnaVpnqpwKc/qmTvxSWJAKSYKTAY8N
         DNMeaFQl+Y1nIyb+LAQWYltaCiEh0QJrl972o2EpuK93iUZ7Tx10EGqjR3/UIVEsblP5
         FDkCEtwqP7zjflMZ3dmjBhV5YuKbC4DmjPpFaB9u//nZYmEGFh2tmWNgftlLAslNnOr+
         KOEPtNa6MyOf/bNTOI4zA/l4K2eYti1K1Gpyx4/zBgPDKSLC5KEcpmpPs8Gc/vVCOWXT
         hr/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K8TVejin;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id ba1si563283wrb.1.2022.02.13.22.24.35
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 13 Feb 2022 22:24:36 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6200,9189,10257"; a="250230852"
X-IronPort-AV: E=Sophos;i="5.88,367,1635231600"; 
   d="scan'208";a="250230852"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Feb 2022 22:24:34 -0800
X-IronPort-AV: E=Sophos;i="5.88,367,1635231600"; 
   d="scan'208";a="631946017"
Received: from lahna.fi.intel.com (HELO lahna) ([10.237.72.162])
  by fmsmga002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Feb 2022 22:24:31 -0800
Received: by lahna (sSMTP sendmail emulation); Mon, 14 Feb 2022 08:24:28 +0200
Date: Mon, 14 Feb 2022 08:24:28 +0200
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
Message-ID: <Ygn1nPpPsM/DDqr1@lahna>
References: <20220211094133.265066-1-ribalda@chromium.org>
 <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna>
 <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
 <YgaOS8BLz23k6JVq@lahna>
 <YgaPXhOr/lFny4IS@lahna>
 <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
 <CAGS_qxp3OHFwK__wCHBGr9cMsLR=gfD2rhjejXcmFNJ276_ciw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAGS_qxp3OHFwK__wCHBGr9cMsLR=gfD2rhjejXcmFNJ276_ciw@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=K8TVejin;       spf=pass
 (google.com: best guess record for domain of mika.westerberg@linux.intel.com
 designates 192.55.52.115 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
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

Hi,

On Fri, Feb 11, 2022 at 02:54:37PM -0800, Daniel Latypov wrote:
> On Fri, Feb 11, 2022 at 8:33 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
> >
> > Hi Mika
> >
> > On Fri, 11 Feb 2022 at 17:31, Mika Westerberg
> > <mika.westerberg@linux.intel.com> wrote:
> > >
> > > On Fri, Feb 11, 2022 at 06:26:56PM +0200, Mika Westerberg wrote:
> > > > > To test it I had enabled:
> > > > > PCI, USB4 and USB4_KUNIT_TEST
> > > > >
> > > > > and then run it with
> > > > >
> > > > > ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> > > > >
> > > > > Unfortunately, kunit was not able to run the tests
> > > > >
> > > > > This hack did the trick:
> > > > >
> > > > >
> > > > >  int tb_test_init(void)
> > > > >  {
> > > > > -       return __kunit_test_suites_init(tb_test_suites);
> > > > > +       //return __kunit_test_suites_init(tb_test_suites);
> > > > > +       return 0;
> > > > >  }
> > > > >
> > > > >  void tb_test_exit(void)
> > > > >  {
> > > > > -       return __kunit_test_suites_exit(tb_test_suites);
> > > > > +       //return __kunit_test_suites_exit(tb_test_suites);
> > > > >  }
> > > > > +
> > > > > +kunit_test_suites(&tb_test_suite);
> > > > >
> > > > > I looked into why we do this and I found:
> > > > >
> > > > > thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m
> > > > >
> > > > >
> > > > > I am a bit confused. The patch talks about build coverage, but even
> > > > > with that patch reverted if
> > > > > USB4_KUNIT_TEST=m
> > > > > then test.c is built.
> > > > >
> > > > > Shouldn't we simply revert that patch?
> > > >
> > > > Nah, either build it into the kernel or load the driver manually:
> > > >
> > > >   # modprobe thunderbolt
> > >
> > > Forgot to explain why this does not run the tests (I think):
> > >
> > >  ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> > >
> > > The driver depends on PCI and I don't think that's enabled on UML at
> > > least. I typically run it inside QEMU.
> 
> You can get it working on UML now.
> If you apply the patch upthread for the test to use kunit_test_suites(), then
> 
> $ cat usb4_kunitconfig
> CONFIG_PCI=y
> CONFIG_VIRTIO_UML=y
> CONFIG_UML_PCI_OVER_VIRTIO=y
> 
> CONFIG_KUNIT=y
> CONFIG_USB4=y
> CONFIG_USB4_KUNIT_TEST=y
> 
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=usb4_kunitconfig
> ...
> [14:48:55] [PASSED] tb_test_property_copy
> [14:48:55] =================== [PASSED] thunderbolt ===================
> [14:48:55] ============================================================
> [14:48:55] Testing complete. Passed: 37, Failed: 0, Crashed: 0,
> Skipped: 0, Errors: 0

That's great!

> Mika, should I propose a patch that updates the test and adds a
> drivers/thunderbolt/.kunitconfig with the above contents?
> 
> Then it could be invoked as
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=drivers/thunderbolt

Yes please :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ygn1nPpPsM/DDqr1%40lahna.

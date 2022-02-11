Return-Path: <kasan-dev+bncBCR45TXBS4JBBXE4TKIAMGQEINA7XJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A2754B2A31
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:27:09 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id q17-20020a2e7511000000b0023c95987502sf4210766ljc.16
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:27:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644596828; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXDh+uVxB6iSiI8NWHwhiGwu1B6HbXFskSL8xy4+UZPiBNmVbWv83C+ge3bhj2a2Rm
         MiW+Y/kZBCGraPm1AJhe2x0jwKem/2eOQr5k/gDj6SCMepSLQIJ42o4wTvvyt7VPA0wl
         YGl32+v7piLloj38krjv5QBETzhywYFDErridFsyxjsLgB1WK9opIaHyaBVGEmDval7J
         yu6749zGXMuNCe4PaNXtrJGi/PvqmIOPGerogOrtwjWUGMZ3rh/YwpM9OAUUpYHiBjBJ
         2Ogon7Ii9E6qa9ZfTLJ3WdZo7RqRMEwqPo6RmO6/LQGN3woeXNv0h++bybvXFpMMqnYe
         xGzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/Fof8IQqMN8ZZNRIaf3zr1E12MAcGWoI3cf6tng1aC4=;
        b=L92CdGCTO+ZIsA9oIXwvdmdpd0v5rMAakvUkdR8TxR1Vnv2hXsmEX/8mXzcgrYoQRz
         ld6zrwo4YkXLTrvcRdjdV6UyfauxL5ogRx4ujiYFiCm+7xro9i37+Se+cqlq8BYdCO4k
         woyyFcHTIezSidnQC6cauHONeJrXGFyndc8u+ggQEGYFzYAZ6PIBGAPFGoQ3uo3r/Awv
         LyG3xGRzlzs+U4dk3p+6LvvYuB/7IrJMOctSG+UkTxsRT1RVLr3/ODyDI95pDmmkFm+D
         huN49j4VX6AjUhIEorqQjg4/iwSS2OnLZgXV/51tZtg1r2OtjkfrWy5UWBAYyj6fkSD4
         XLbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gXj7DyL4;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Fof8IQqMN8ZZNRIaf3zr1E12MAcGWoI3cf6tng1aC4=;
        b=tzDF4EJOPKSoX6ltFVnT/PiweHMAsvj1F4+LNB6J4jdix4d+QhHz+A6bDBwdilIZkD
         Gc6/Ff5O9hhH3K+g5ultCI7OnT0PNKYSWhhIxsgibLX5rvnR6iyIs3ga7lc8zGS0TYvc
         QUZmRQhm4m/9MU+s5TkoL0g4zm7S+WIVBnR3nUjMldWUvlopgQEf1iTeb0X5TqcEtkKz
         0rFhqqkgxVHQqU22fFyBwi7UO2AhpPAkEubkh0T1/xs4//uSzd7tj1qIcjQAnGW4P0A/
         HOyRoAb/0lhnPjaaOqHML9DHyKW+YgfFOHMkF0rg9TVaZIGCzePmMrhYGouiHc8/hKVv
         eZyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Fof8IQqMN8ZZNRIaf3zr1E12MAcGWoI3cf6tng1aC4=;
        b=WwpIVBNcSSxgUM12Hi7SgUBkHuU1nI7F7bt7Jqpj82qMQCN2C52y35zNH+RCNdZ/s6
         b3fpXpg7CWDtCm460HZojFRP2YLejgVs2A4KByNwo1CUPPHZsAOQdSomeoDSgMLrgeik
         pUi6UDgr3YwKsjMG3Tw6AZMRs8oDjDuiwy6OF8tRK5V8kSs+K3B0yvGMc9yoDKpryDIO
         xRGSw6EogZsP3Xs+vMKA7BAjFV3EFZ9JU7j05nyDcWVn4fvn/xGWpaE8nOaGabbdpXWR
         CTS9WHI3bgd/2mhbhNwg2NtAWqE7AAYIie2NW0NAA2WmKIH6L2stl8YThLt+jaaNvvAC
         0hJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wyBPOOv0f1YZzVc9FAjJqgZ0vWjZebWsKmUXsUPivn9g8Xqbn
	OeAQn/y40qxEP43C0EL8ces=
X-Google-Smtp-Source: ABdhPJxKURj1jxv4TkEr+ad6zN8bMNsk1cqNnGX7yNAYxKtCyQfKL1+HHNxV1HCFWI1iq9jHmN2YZg==
X-Received: by 2002:a05:6512:6c5:: with SMTP id u5mr1666660lff.1.1644596828606;
        Fri, 11 Feb 2022 08:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5ca:: with SMTP id 193ls1605754ljf.11.gmail; Fri, 11 Feb
 2022 08:27:07 -0800 (PST)
X-Received: by 2002:a05:651c:1a08:: with SMTP id by8mr1427862ljb.325.1644596827492;
        Fri, 11 Feb 2022 08:27:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644596827; cv=none;
        d=google.com; s=arc-20160816;
        b=wMfRhoXXI1Wb8KWkiE4JtSx+cx/cM5OZctfZCC8tUAKpe+I/vKxhqUFh1ivuqFXFK0
         83VWzOTlI6MOym1SK5YEuh9A4bLhzIJ+cBRqaDQWRF3vboGD7pusuS1+4ntCnVhPKoIA
         eGkL7fhLc0SKHqywoPfXildZ0oCbmAYutpiM+N4oUeO2mrTC9eNabFXDNNnBCmA5nTGS
         TSceqSI2Um4pz5dJ8Rc2p5kVSYkeuzZjlhQABshqIPGgf/9JAzHv/6Yq5KUvQhcRHG3C
         KZOqXcJa0pqGTIjtpyV5KNz9uznEbIuEpy+qzdJc2zGOP5bT1f76LVj30z12eJnE0FQn
         /Eyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vy/L5Wj0bExAIZzDH14fn4eI7xOo4GcuYXta2VwXm1s=;
        b=SxwW/T/Uf920GG84MnOVNBILMjdCcHGnNJlANB8Git6NQceTm/DpGDSh1XRDQjccgH
         Vo7qu7EYVn7nJuWVEQpsxFbqPzv9D0vfumyZAmq8hvmP2IclNfNnZAyvfn27QpNttleX
         2q4s9dHbkVYATsRj0aIt0ZsnT8MovvZ+lPhPAzxwSCAJZeTiIJHUT1aVUYnLJ77Y+hHE
         yOWbBlT3XKXhuGz7/Q32SqmuFlYKtVZYOYDOwF6A58keV4VUfW/YZdU4tOhCiwqUW30T
         LP/AnfeDa/md39KDETjF4NHoUv7a4ORMbkQ/GARQsDQRgN/aPXWWP/15xV8Wc6IWFmqg
         QeKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gXj7DyL4;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id k15si336976ljq.0.2022.02.11.08.27.06
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:27:07 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6200,9189,10254"; a="249707650"
X-IronPort-AV: E=Sophos;i="5.88,361,1635231600"; 
   d="scan'208";a="249707650"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 08:26:56 -0800
X-IronPort-AV: E=Sophos;i="5.88,361,1635231600"; 
   d="scan'208";a="586395242"
Received: from lahna.fi.intel.com (HELO lahna) ([10.237.72.162])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 08:26:53 -0800
Received: by lahna (sSMTP sendmail emulation); Fri, 11 Feb 2022 18:26:51 +0200
Date: Fri, 11 Feb 2022 18:26:51 +0200
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
Message-ID: <YgaOS8BLz23k6JVq@lahna>
References: <20220211094133.265066-1-ribalda@chromium.org>
 <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna>
 <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gXj7DyL4;       spf=pass
 (google.com: best guess record for domain of mika.westerberg@linux.intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
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

On Fri, Feb 11, 2022 at 04:49:21PM +0100, Ricardo Ribalda wrote:
> Hi Mika
> 
> On Fri, 11 Feb 2022 at 11:08, Mika Westerberg
> <mika.westerberg@linux.intel.com> wrote:
> >
> > Hi,
> >
> > On Fri, Feb 11, 2022 at 10:41:30AM +0100, Ricardo Ribalda wrote:
> > > Replace the NULL checks with the more specific and idiomatic NULL macros.
> > >
> > > Acked-by: Daniel Latypov <dlatypov@google.com>
> > > Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> > > ---
> >
> > ...
> >
> > > @@ -2496,50 +2496,50 @@ static void tb_test_property_parse(struct kunit *test)
> > >       struct tb_property *p;
> > >
> > >       dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> > > -     KUNIT_ASSERT_TRUE(test, dir != NULL);
> > > +     KUNIT_ASSERT_NOT_NULL(test, dir);
> > >
> > >       p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
> > > -     KUNIT_ASSERT_TRUE(test, !p);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >
> > This should be KUNIT_ASSERT_NULL(test, p) as we specifically want to
> > check that the property does not exist (!p is same as p == NULL).
> >
> > >       p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_TEXT);
> > > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> > >       KUNIT_EXPECT_STREQ(test, p->value.text, "Apple Inc.");
> > >
> > >       p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_VALUE);
> > > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> > >       KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa27);
> > >
> > >       p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_TEXT);
> > > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> > >       KUNIT_EXPECT_STREQ(test, p->value.text, "Macintosh");
> > >
> > >       p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
> > > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> > >       KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa);
> > >
> > >       p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
> > > -     KUNIT_ASSERT_TRUE(test, !p);
> > > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >
> > Ditto here.
> >
> > With those fixed (please also run the tests if possible to see that they
> > still pass) you can add,
> >
> 
> Thanks!
> 
> To test it I had enabled:
> PCI, USB4 and USB4_KUNIT_TEST
> 
> and then run it with
> 
> ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> 
> Unfortunately, kunit was not able to run the tests
> 
> This hack did the trick:
> 
> 
>  int tb_test_init(void)
>  {
> -       return __kunit_test_suites_init(tb_test_suites);
> +       //return __kunit_test_suites_init(tb_test_suites);
> +       return 0;
>  }
> 
>  void tb_test_exit(void)
>  {
> -       return __kunit_test_suites_exit(tb_test_suites);
> +       //return __kunit_test_suites_exit(tb_test_suites);
>  }
> +
> +kunit_test_suites(&tb_test_suite);
> 
> I looked into why we do this and I found:
> 
> thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m
> 
> 
> I am a bit confused. The patch talks about build coverage, but even
> with that patch reverted if
> USB4_KUNIT_TEST=m
> then test.c is built.
> 
> Shouldn't we simply revert that patch?

Nah, either build it into the kernel or load the driver manually:

  # modprobe thunderbolt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YgaOS8BLz23k6JVq%40lahna.

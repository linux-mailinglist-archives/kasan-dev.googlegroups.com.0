Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBA545CTAMGQE7MOOM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id EECCD77B89B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 14:28:52 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe52cd625asf3814448e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 05:28:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692016132; cv=pass;
        d=google.com; s=arc-20160816;
        b=1K5fEWS/077WXSJfXpY1ySyJsIDyHW/w88PnC3oLbUu6oVPBBdXjmhVAlzFFLp+/g7
         qTccF+CSfXvi8Dsa4TAIkPue20LxzwuWUvPV2T660DDo6yWbXsK1huDnj4fQSHBfDm7q
         /Th6OoZ8PUHnejkXe/ndCfzw3zyH0flMHUvpaa8Q16aNhtXZa/NnvsfXtBS3cCNWzRdR
         +Cfz/uAYceuEdVdbqCvd/TkbFb9wCH09cKRZYbj9kZZql4RPo06fLXdW10nl6fazKHeI
         tDMRbj0+scLibADoHwqfKLsg0GwQufFaD/F3s0qFBxn9lLJSkiZ3BlY2S64KgX7xBu2E
         4Ixw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=o9bwdM1gdAu7Nkt00CvhgiFhan+pu8v1ONHuV7VWcQM=;
        fh=Wba2AWFBNqASIBcxHlMMz7kKbw4N38z5CrvACBIS+uo=;
        b=KmHSHfgGiTlLx84YGRkZvFPdxg6rzHYUBygaDrwDM2Jle+kbQD0rJfAQJ4UdTwh1yK
         QH8JLNvRD/U5F21ZOWfgUIo70cTVzqmbYo5HCPBvHKLtoQN8wPS+PLsb5+ozBtEArb4G
         GQfiMriRJXEmy2qKH9sLroEmkapCgJlHmGfxSrLkJHdDMb6oDL2K2bPgVGkc7+av7SB9
         Cvz0F+xqi5ZjTGHFJrsUYKazZsBESs1mmRkWW5w6VoRU7rqCzsK+lfT71X6fAB71QDtM
         5+sJElkamgHCp92ik6qKhnaMwrcvs80rYlz/9UMTJ3TrRJYIxguoTGQT9ttaACnQ4Sro
         eHPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bSfHsJ11;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692016132; x=1692620932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o9bwdM1gdAu7Nkt00CvhgiFhan+pu8v1ONHuV7VWcQM=;
        b=sm94V7PDmAjAlfwlnGTI9IURqJvDTBy1zMThSFxKEXAKtjGbLzmaxKQfDi84YJoPSJ
         nv0HUkPuFOEYEC9bpaMJGCpVlitHdDkZUFj+GUbSn8WGenIxNaKD761GiG85wStF+jbG
         VYfR+vCzz/u7K9LFlJHzJGkYn4e5tjpDI9i66hC4ANIBx74V+YvrMLozWeWR3moGcxZP
         Lk26JyOAoqsztONPmkIcupj+DaIK9+j+ztBMFIhZT5h976lSoWqvqKS8qo/XY0dcxBdJ
         W3JlZp/o5u8ZtDIPn5F11+CmyNpn0zpJxep/d21pci+R/4ADvTduzfx8XICWjXi9UKrQ
         SspQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692016132; x=1692620932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=o9bwdM1gdAu7Nkt00CvhgiFhan+pu8v1ONHuV7VWcQM=;
        b=ZmOsy9GN2oI+8HppIjZHPK/mRppUlQKm/FBTZtvGyCgpXj6emJgtH2w6AeKiA4TzRB
         6VOFLAGvXRS8cyzGhti0Lh9VYcncOhgqbqoN5bDpHWSLk0Vv2bK0h0+cCk11V4AO4flm
         TZ2eyAzrPrTfzfriTEhPYYB+xf0H4Gw35ipnvfS+T3TVgceVe3/QUIMDehr+Z0IrYdF3
         NWsJlM++HQq9efwCePwwNDtuAvJiW6TtVwX/c6M8HaaboPgWObjoi2pPgMCNDYXMVZw8
         FPRrINg/O9ZFGciyqbZKAmYy/E4C4N10ZTx6Kh4cMqhzD7/QZ5zJDwjfimVTln/+UvPx
         5HPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz5cNxJPVGSwzxPM0IYB2Sqj6I8sMO7m4W6xnCB7tN+VO7DWi2P
	SV8bAzfVpb7lpCbPxkO2gok=
X-Google-Smtp-Source: AGHT+IHMdJlIgDplQj3Xk0afX78+SHsEz3RNDtHqBVsktkXlw3OI4jDNSx/+hhRnAVkK6PLSdXovlw==
X-Received: by 2002:ac2:4302:0:b0:4f8:56cd:da8c with SMTP id l2-20020ac24302000000b004f856cdda8cmr6172087lfh.34.1692016131615;
        Mon, 14 Aug 2023 05:28:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5056:0:b0:4fe:678:6a1e with SMTP id a22-20020ac25056000000b004fe06786a1els1639555lfm.1.-pod-prod-03-eu;
 Mon, 14 Aug 2023 05:28:49 -0700 (PDT)
X-Received: by 2002:a05:6512:3131:b0:4fe:56d8:631d with SMTP id p17-20020a056512313100b004fe56d8631dmr5413328lfd.25.1692016129774;
        Mon, 14 Aug 2023 05:28:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692016129; cv=none;
        d=google.com; s=arc-20160816;
        b=HnQ1YlGBmd4TnrG7N+KRg5DiJy7irQavozy8D416e17E1lPlz0I8iBhEMIyPpAIxVB
         reuSpSriNOvYcj58+T+gv/7z1sB2mBGkqcd+0TfFDTg80lJ/Y5RO4JM2D0db3TMFGKVN
         i2k16nH2fmRJKIAXqdxi6SXe+KCdqg76ATf5UtFYkNilHZpfeV6nJRt2EqTPjvBeskoa
         BsjUkYAQUWJTFiiL6o70nx+/6qY1CrbieXP78P7x1uEqUDn+T75XkHtvne5cJ/mq2Xea
         xYCm2cbXjFhiyek6p7KAHTf9wHjppDnXGrvxW/Gop6sYv5XO0ypf+WzQTid2AUNG6Bvz
         rjHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sW3GoTngdmEh8EJSLPl4WhJdz/gjww5oqwmrnvdAlW4=;
        fh=Wba2AWFBNqASIBcxHlMMz7kKbw4N38z5CrvACBIS+uo=;
        b=AZ2LDHjBJz2nwABb3YnmuL/eN/dA3uXnpdBSxqs9v9RoMlXe6rOHUbtyV/TU0On3QX
         fyWyfoFhOsPR480K0b8HGPlTob0DptTEFJZ1fSgRyBD7pXQfySzDPk1Bm5TYDSALaEcF
         3x/PIiR0CGVb7TK84r964puG/WdsixH2HK+mqA6daSQP5A+LUJTQNkig1lVWK+ObPKiN
         DW3YRl1dTfvZOUYfnfTkDhGSQ71PmaYnavTC7g8VnflRz/9f0KGfIRuiGsSBvI8vV2Iw
         tIP0CvyyrZxKOyPuh7L5rLyewFILSsPZgYP6c4BciiCBkAxw4Hq6Ywk95DD3O4zokuuY
         t1yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bSfHsJ11;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id o22-20020ac24e96000000b004fe3e3471c8si719186lfr.10.2023.08.14.05.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 05:28:49 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="352353558"
X-IronPort-AV: E=Sophos;i="6.01,172,1684825200"; 
   d="scan'208";a="352353558"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 05:28:46 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="823434944"
X-IronPort-AV: E=Sophos;i="6.01,172,1684825200"; 
   d="scan'208";a="823434944"
Received: from smile.fi.intel.com ([10.237.72.54])
  by FMSMGA003.fm.intel.com with ESMTP; 14 Aug 2023 05:28:43 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qVWgb-004XHM-19;
	Mon, 14 Aug 2023 15:28:41 +0300
Date: Mon, 14 Aug 2023 15:28:41 +0300
From: 'Andy Shevchenko' <andriy.shevchenko@linux.intel.com>
To: David Laight <David.Laight@aculab.com>
Cc: 'Petr Mladek' <pmladek@suse.com>, Marco Elver <elver@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNod+ewgF6Ginms1@smile.fi.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <900a99a7c90241698c8a2622ca20fa96@AcuMS.aculab.com>
 <ZNTifGaJdQ588/B5@smile.fi.intel.com>
 <da520d6fa03c4645a28e5f4fae013d35@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <da520d6fa03c4645a28e5f4fae013d35@AcuMS.aculab.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bSfHsJ11;       spf=none
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

On Mon, Aug 14, 2023 at 08:12:55AM +0000, David Laight wrote:
> From: Andy Shevchenko
> > Sent: 10 August 2023 14:14
> > On Wed, Aug 09, 2023 at 08:48:54AM +0000, David Laight wrote:

...

> > > > If you split headers into so many small pieces then all
> > > > source files will start with 3 screens of includes. I do not see
> > > > how this helps with maintainability.
> > >
> > > You also slow down compilations.
> > 
> > Ingo's patches showed the opposite. Do you have actual try and numbers?
> 
> The compiler has to open the extra file on every compile.
> If you include it from lots of different places it has to open
> it for each one (to find the include guard).
> Any attempted compiler optimisations have the same much the
> same problem as #pragma once.
> 
> With a long -I list even finding the file can take a while.
> 
> Probably most obvious when using NFS mounted filesystems.
> Especially the 'traditional' NFS protocol that required a
> message 'round trip' for each element of the directory path.

Right, as I said come up with numbers. Ingo did that, so can you.
His numbers shows _increase_ of build speed.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNod%2BewgF6Ginms1%40smile.fi.intel.com.

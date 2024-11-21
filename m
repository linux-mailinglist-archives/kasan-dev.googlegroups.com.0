Return-Path: <kasan-dev+bncBDA5BKNJ6MIBB34B7W4QMGQEXQ3YKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EC119D4E81
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:17:20 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3a77a808c27sf9632275ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:17:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198639; cv=pass;
        d=google.com; s=arc-20240605;
        b=D6Dez48d0ag1po7AvLp7OWGFJqtwNCUFJHwl+wgsEpQvtfr0j8oZxYdY4ieSQZMeVa
         8RhKIsGL7cnHLY+Zc5Tugf+FZ6RXWmp/jLkF+qJU6Uhlboa1gVg2UyeR2ChAEjlubfnJ
         BS4iw7XZ1zWh6jxX3DbyvJIclp4+gYyiyDxtPwJfBe1kwdemC04IuvKaNBLuUKw8Yh8R
         J97FzEERC0yjMDKpPtVCNlZzlmFxB9ez3LGEaP4nhkyoxprpPG3YWYlwL9I4VFKTjr9k
         TRG+RW4O2r/GjAlVHSxI9HmJdiuZsTch1P8cRtxw44QQKkUcqutyjwBDKRO2le+D4Od1
         KcWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ILqexyZeQtoUl+y+DqL18i26Kbm7hpbwZMCxDSgnsNI=;
        fh=fDnnV4DA65+1Gbrf1wz5J8rG5db2jatLOyCvokKiti4=;
        b=LXbboTlaICQUKbwmf/pfcHmFMEtdmphkC2R1zA+JEZ7mUmHSJ+RkXhAejR3j/HtyHh
         hLR1Z4JeIjeUQuyJ1cnv2p2BljXlQzGysChG6nLzsOPtftW9QA54yAu/A67bs9lptB9o
         SbaLoJ8oPtmihr18kZZjeJYlPUkAtp3eVe7tnk9xIWX9DEd5tjrGbs0/j0N5OtsjYaVn
         HiYyr5iXDx0Yw3t4sgjNpMYzhfifYTi8KsZuH05Sn8qwd2UAuP3vdGIz42vW3dWdo4hf
         o82NnHO1onsppUmLYxhGKogifXMnRMDwFlaIRI+56NhqvLo792aHkaJ1x5PuxCnXEowX
         6Srw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=iG5YGUd6;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198639; x=1732803439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ILqexyZeQtoUl+y+DqL18i26Kbm7hpbwZMCxDSgnsNI=;
        b=N5A3chO4FDXBWPFPSiirmYBxco8IHpaaSNNijXIyRMfGj6po9Qsr+3Q1HnnFPnlmzy
         diSquicDVo6f1ICinbOGHzRw+om4h3UYnhXjcm91Df5DT+i9qXxK6so1crQebZz7+V7A
         eRYldmSJXHz1QaVGO/cl8vMsaSr8uAE4s1dyVhKtDcblpHeToIZEE422NNBzfN26y6TX
         K88OlkxUh1Lc8EQjqOMUWsfy5FSdIAzkqlkZNfB/ZrWmD1Bd32N8mxU1tXS7/7UqxA4l
         Ao9Mta3wLuSAlgIHTWBld9JjWLQq9+I9L090HYYuABFbJudKGTyS/cn4qyr9tLLZzg2g
         YUSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198639; x=1732803439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ILqexyZeQtoUl+y+DqL18i26Kbm7hpbwZMCxDSgnsNI=;
        b=CgwQO5E+KQt7EPFTAuVVPNB/fIMf3fALAwkVff4itXkfkBZuBGR/vUaoq41iDSV1cT
         FuHNTmgf3eY0AB7dQPCNELAKFyxAp01qlYpevU/MIv6yzI5gSrQdTeQJzKFbwXNHIA4k
         w74/hMlZorKOkDkbL4C+PWFVxjv3Lo5VW7J6S6nSvVws2+2HmLp5peo2EHlfhbuuW9ag
         YyLWXH1BsPvzO0QOUVPdcyhad4RtZ4/UdirD/o6nxYp19DK+FYIj1SnAdGtvsYPxnp+M
         iuZ+54iBhEgM+PHEnaYFBz3laCcPSsqIUexQU98ylioeHfBWr5LHpuEXVGtlfUooT2+/
         GoTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBMsYokkso2AAoR13lT8sk1oGGwyRP8uYR0sQr0+q1yvkm5Hmn7ipwwF5r2g1iHAjFZf/KCw==@lfdr.de
X-Gm-Message-State: AOJu0YwB7wle/YwyWEYwxm4/Wt/Nnjqpaexx1n4/i4wJU0za0yp0YuET
	746S7zelfTosZAHbr7rI4OiMkASsNu7FJngHxu0JKV1ZuLYRJsUj
X-Google-Smtp-Source: AGHT+IErAsb5vTL3jBag06B0zOKjTRMHwPkZsCSgaRClF9DuU9mELsfEbUC5Q5rpm9FVQpVolJJVVQ==
X-Received: by 2002:a05:6e02:1caa:b0:3a7:629a:8be8 with SMTP id e9e14a558f8ab-3a78640f261mr83600935ab.3.1732198639173;
        Thu, 21 Nov 2024 06:17:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c905:0:b0:3a7:9629:3322 with SMTP id e9e14a558f8ab-3a796294a7bls1631855ab.0.-pod-prod-08-us;
 Thu, 21 Nov 2024 06:17:17 -0800 (PST)
X-Received: by 2002:a05:6602:6c08:b0:83a:acba:887a with SMTP id ca18e2360f4ac-83eb5e33d27mr794675139f.0.1732198636638;
        Thu, 21 Nov 2024 06:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198636; cv=none;
        d=google.com; s=arc-20240605;
        b=CBi7lvRA55ifhH6mYmnH4xbehMxuHEJt1KyS09IcbT8PPueTsaH6MFhaXCDuoUGczp
         jq9mrZ+Yu6qrcCGNIPOWIYELbhyPejWSy0wLpv/cx934Pirag80YFF/esSOan2Qntytw
         9C9K0JlAScbhtTTjL7zkko4igx5WNAcc6NwpzyRTueaBrOvnfEprsMuKM9nI4dKz8QNp
         BieR3OvoGRmK/Hk3maUcCob3o1fD3yHv0ULWz9qy/P2tlT6wWTYI9mZWX/M9TZnzULO8
         RO1S8URh+IBS1sM4EP6/4FuJg0DQw2DRiXrpa/Mx+/cs/cwppbGKEtoc82miCBzoiIuR
         kGDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sNbxRDDn9vL3ZJ+cmOUsnpkx9qATWDL7VmPwrWoS9UM=;
        fh=oBVpN4AIi3s1tC5mEK0do+pBCGXE7GT0Xeq5X+GEMSg=;
        b=XDmzsyu9v0nZdO7Pp+7ZWJy02OyrGqEzPBu61B7fCi0+dZnjTnhR3JRXeWu2wynQa9
         IMnhaUqPMURTHTTTwdHNbxpjlILWoUdmuc9tGBwKlXK60rTmktJgTSchAQ6TEH7MnQt3
         mP23bFT4F/RBVF8mPDCPp66zVec11sCTUZQR5eJe7rzYhTcj12hYIeIY+kO4OZU67mCW
         TAtr8b9bUyyqR8NtTllqVDJ7VNPLwAoQUz3waaqGuuvYNH9mgEsDHOVHlqG4QTzJ7UJl
         tQc+yE5VRSo/8UXBjiEmMn9TKG1b22VnBbEvCH1l1KXIr4Bygil9fH7xqfgasacnOxaJ
         +5xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=iG5YGUd6;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-83e6e09f220si71108239f.2.2024.11.21.06.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:17:16 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: BXNOx1DBRae0xrAS6eUBbw==
X-CSE-MsgGUID: bLf/oK7nTLWM6rt2fhkRxg==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="43376188"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="43376188"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:17:15 -0800
X-CSE-ConnectionGUID: WAzREU2dTVGKv2M2l999Dw==
X-CSE-MsgGUID: YzY0SPebQeCBN2somvsrPw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="90242724"
Received: from smile.fi.intel.com ([10.237.72.154])
  by orviesa009.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:17:14 -0800
Received: from andy by smile.fi.intel.com with local (Exim 4.98)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1tE7zb-0000000H5Lm-2bND;
	Thu, 21 Nov 2024 16:17:11 +0200
Date: Thu, 21 Nov 2024 16:17:11 +0200
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 0/2] kcsan: debugs: Refactor allocation code
Message-ID: <Zz9A59XQdiHJ8oLp@smile.fi.intel.com>
References: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=iG5YGUd6;       spf=none
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

On Thu, Nov 21, 2024 at 04:12:50PM +0200, Andy Shevchenko wrote:
> Refactor allocation code to be more robust against overflows
> and shorted in terms of LoCs.
> 
> In v2:
> - collected tags (Marco)
> - added patch 2

Okay, it seems I have to check the Linux Next for the current state of
affairs...

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zz9A59XQdiHJ8oLp%40smile.fi.intel.com.

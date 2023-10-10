Return-Path: <kasan-dev+bncBC5ZR244WYFRBFU4SSUQMGQEMYUT6SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 79FB67BF636
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 10:40:56 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5039413f4f9sf2201547e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 01:40:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696927256; cv=pass;
        d=google.com; s=arc-20160816;
        b=n2IXJ3suLT6QtjW+aRZHLuQqcV2+1funFQFQyAwFZ5R40HQs0nw1zEBixIVlWGBRyg
         HbGyu6Tsx+QAEKu2n8CyuuC61JCS89KxlCUxvO4RrusW79RxUMQAdwWAovr8BsV0qfdM
         d5T/PMqpVuZQ14qfDgErTk2ASGarrqr93dLXZ8qFedswVBX/UVVM2brQ13w1MqXZrt+F
         pRLd8PhLpmRebqwTceNJ7iP7IBrvYeqIvK9CUB56YzQGPgEDQ8RJqfJ6g3wgccQQHn1z
         jU9wdu+12x2NZLyynb8yJw7TpU9GZTs4FgnA25MW6GXddvbTrfsa8UmNM95kZ39ixgZl
         kV8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hX6RUGDw4kcE7ecL1MZBnQex3+/lEbt5oXewSrAWI5w=;
        fh=Humky4e+hth+m5LjjwqZefHA/L96cUXUrx8t/v+3zX4=;
        b=kaqVsNd6F3+JHnmMD09gNpqaIfEk3mgHT0pTtHUfEADlScbt44ps6y/Yxh42U620Gu
         5YxfKmcfJcBrxl9QKXB96iy5XEM8IQJSxhKuN7RhOGSqRJHKweuOaxH4n9vCMZB2KWBV
         PSAifEwdxfgOt+eay8Fwk5cHnDB9x7lDXuduLnggP7qhj9m3ZjbcmOz9BUqlxVye70TV
         CWYeVq1B/31U5vpKQ3aYOxc+JTOJ8ski51DtNdN5ZaIHqlIL9dSFCR/wVAWIID0wUh/Q
         kR5GUBgmLcxNmAxbL/Q+W/egjyVPWkxRFDPX5Fg5kDWf2v8iC9MMt6cftVaMAXkLC3hd
         ZYlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BaQLkl7Z;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696927256; x=1697532056; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hX6RUGDw4kcE7ecL1MZBnQex3+/lEbt5oXewSrAWI5w=;
        b=SxXyKrAxqHdS/uGtc9FYzKridfj8nky+nex0Sidgm0oAPEovwMl2qVcF18yKyD5Dyk
         QFPpNPqObqrkjbUWdrIHHr3N/1Y8LADSBPfy99i8C0aj4E28VFNpTZcHErBKsTkDu1h3
         EdTZiRpNTPnBOn1Uj+q8JEdzkzrnzu8C39KtjF74x0ScrE/tC4NMSVlcqpl+fv9MkCTB
         gbtNjFyxgzkrsHAClo1JgtUxupVVmfVV6LzOQ+7uHdQZpUf/cy8e8CfraBoNbVr7duCd
         Nochor9dtwHtxRwSJjvd1iGGKscqKV0sBK2FB1G6DBvifmDcxRJQvdIBDZdBpc0caNKV
         wrOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696927256; x=1697532056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hX6RUGDw4kcE7ecL1MZBnQex3+/lEbt5oXewSrAWI5w=;
        b=Mr3IuO4FHViDoXckc+BcxUAOXJ41aN76QDWlm1PYdfQFml2AEawoZjHPDrh3ENZjIR
         9beKcOee4501aoPUJSAgR6PY8z7cvDZUZGNMg1pR+mdTXjHAU8rpGK83Ax5b6tRvheCt
         ligsc9b1uZkZ6gwrb02a5KsVKafchpBYtoeWqeO76jV3cFkDY3l9vgozwMRxl6RnFjNF
         m5vM6hl9iuuYd7NVjh0qTHTL+Rd2Cf607mjcJLfPI7lMiC74ojCb8Hf2JyZAM8A2zQ0o
         Pm7GXtLeyJWrX0fbDwoapmmrbTv3I01Qd9l+dR7RLW+hIa8lPRRq23pyMEkKH9JbFAHJ
         BKGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwK9d8/8wjZSj8olkN1yvNBjq328qe3nCXcskXzKIFI+cZu5ple
	TCuE8/NTh4J/edUro46W6+U=
X-Google-Smtp-Source: AGHT+IHldCLIb+dOpKliS1axaVcO1amWKbADUeHosxia5PiUtmowdA5/BZoQXv3i71/GJwgNd+y8eA==
X-Received: by 2002:ac2:4bce:0:b0:503:1722:bf3a with SMTP id o14-20020ac24bce000000b005031722bf3amr16268332lfq.1.1696927254649;
        Tue, 10 Oct 2023 01:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5b1d:0:b0:500:7f17:b77d with SMTP id v29-20020ac25b1d000000b005007f17b77dls2609674lfn.2.-pod-prod-01-eu;
 Tue, 10 Oct 2023 01:40:52 -0700 (PDT)
X-Received: by 2002:ac2:5b1b:0:b0:503:2924:f8dd with SMTP id v27-20020ac25b1b000000b005032924f8ddmr15364486lfn.47.1696927252829;
        Tue, 10 Oct 2023 01:40:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696927252; cv=none;
        d=google.com; s=arc-20160816;
        b=abEiwOfK5yQx7m/ynDkuk+Ic9zLhGku8reXtrQqPyg0WLK8vRTDDPlqu7cCX0bHvb3
         pRyPGQR98B6WnjsJFixiPZhighhWDze5Y5Ek2/J5rfLm8zX2BHcGwLN3Fkbtf7qz9y/E
         1dCSut3YZlfJGF0TCWeiPhFNO2BTRGKXrJHp6BxUUU9uWOmKdQBYHiyxN9avwgz2e0DY
         t2g/2oYastgs/hQHgKVThUPJbpMQrLsc/HeyhDYW02vuv5tj2BYYGyw2EyeFmNyFZijD
         cFLa6FRnmJX6CNlXZKQPwKp+54WBO4wtCP5kBBCjnrAuBrH/dnDz9skWAPjFkORfC2KS
         5ujw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9yvMgqoPGHCM1ICdduxR2Gz0ugbAZLayCGVR1FAVNkI=;
        fh=Humky4e+hth+m5LjjwqZefHA/L96cUXUrx8t/v+3zX4=;
        b=fthIJuFYoInhYtmBahdrcE4ZZct9pLEc1V8Vl5R9Nc9cpmOKg0dnA2ltOG1NGku5rf
         His4DnobOLlRr5a9UYi6D8rLytaqPndjhqhZgdi9EufNRgp+qq0galczSPeKlw9+jgyF
         h9tIteQHpN+F6RcvEqGc1hT8kG2w6DJ8H2vajrgSSZDfNWPc7avzu5/tbhbvfUGleFrS
         7Mi53JQ8SpWy94cGSancd50hfrQdryeuO9j62FKYPm44uiutsxMQ3Lz4j7cC+MT/ag6l
         jNBK5Ir8QJA4Z1ZPEPMutD/MyKI68V3LMdcKCuaLxXNc59RVhB+pQHNyArV239f0m6x2
         9ESA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BaQLkl7Z;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id a14-20020a056512200e00b004fe3e3471c8si447134lfb.10.2023.10.10.01.40.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Oct 2023 01:40:52 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="383220525"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="383220525"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 01:40:50 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="927059933"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="927059933"
Received: from albertmo-mobl2.ger.corp.intel.com (HELO box.shutemov.name) ([10.251.208.38])
  by orsmga005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 01:40:45 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id CC6FC10A1A3; Tue, 10 Oct 2023 11:40:41 +0300 (+03)
Date: Tue, 10 Oct 2023 11:40:41 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Borislav Petkov <bp@alien8.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010084041.ut5sshyrofh27yyx@box.shutemov.name>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BaQLkl7Z;       spf=none
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

On Tue, Oct 10, 2023 at 10:19:38AM +0200, Borislav Petkov wrote:
> On Tue, Oct 10, 2023 at 08:37:16AM +0300, Kirill A. Shutemov wrote:
> > On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
> > got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
> > __VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().
> 
> So use boot_cpu_has(X86_FEATURE_LA57).

__VIRTUAL_MASK_SHIFT used in many places. I don't think it is good idea to
give up on patching completely.

> > It seems that KASAN gets confused when apply_alternatives() patches the
> 
> It seems?

Admittedly, I don't understand KASAN well enough. I confirmed my idea
indirectly, by patching KASASN_SHADOW_START, as I mentioned.

> > KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
> > static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.
> > 
> > During text_poke_early() in apply_alternatives(), KASAN should be
> > disabled. KASAN is already disabled in non-_early() text_poke().
> > 
> > It is unclear why the issue was not reported earlier. Bisecting does not
> > help. Older kernels trigger the issue less frequently, but it still
> > occurs. In the absence of any other clear offenders, the initial dynamic
> > 5-level paging support is to blame.
> 
> This whole thing sounds like it is still not really clear what is
> actually happening...

Maybe KASAN folks can help to understand the situation.

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010084041.ut5sshyrofh27yyx%40box.shutemov.name.

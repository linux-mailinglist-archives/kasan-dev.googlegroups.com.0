Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBR6AWWTAMGQEMGWVBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E50837709B6
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 22:32:08 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4fe565bca92sf1835364e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 13:32:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691181128; cv=pass;
        d=google.com; s=arc-20160816;
        b=qpddv7xALMKIkGfkSGJ6+rR2pCTmQBUK+dsUWkLGpZyuGbRYcKWk8PJ9Phu72JPMwu
         bqVN2qOMhiqgNbf0Vr+lIv28zQKWf1tH3vmPAtZwfTu9xCVxY2z2kDLne1MlDgFJS34S
         pOTcZUCd5GBzlJQEssnm+YgkI/FIqEhillUpiuVBzqWbGAaSmUJMbEEEHC6fR4a/mgZC
         4lgLDzmOZxEXHlhh63w9v6EmKtysKd0J0kCF3v5AH+5EtwUDvNZA7yTk17jgEw8QtbXf
         en+vGFfOS3MAKocckMlh8DP+tVY6N8WRPS4LpV3YQPTiFb8tapGr1XS+JcCet0n2H1C6
         REyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cI7Iu0Y1VhBzoEpnqUb3drE8bgwxX3jOQPcTUHVxPRQ=;
        fh=oI/Xiro4+EHjElptEbxeKLLzFvN1qXeWbIHTFIMB7YM=;
        b=tQFXOVUEbp/3uy7CCn73naaNeLW7iRpUgRvWD4ylq53Edzqs0Vx9iJz9ipfTzIqzoJ
         uInzzi1TUvyWm17tJOGzn672yazzw1LF7e620XUt1UIXEVp/ti6yW3zth02XNBovgDRZ
         tD//LWSdwKx4HE9B7m3RD6FnGMDnQ2tOHOtQSpvxYsgfO4bokHXfUqNhgKbFfXvYLoyd
         bc3hLesO6baRpAtnVADo/HgP8riZuTaseK2PIN8B8ETevv0aNqWnIRIT9fVT6Eqx4YHs
         yum99illn07NAdptd/A7Bgf5iJ+lK9V+OGDfVeKn4uot528G/68UN2/fGjnjzvFRDDAg
         69iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nyLuHB7O;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691181128; x=1691785928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cI7Iu0Y1VhBzoEpnqUb3drE8bgwxX3jOQPcTUHVxPRQ=;
        b=souHmaAqLLwOW8t7lVOCh5V7d2mfLKhlZrFyp1M0dahReyRHrtN4+HfxDcc3DSw4gH
         YVYaei+TVklFM0Ds4kqeBIxCKfAUDTa/LcO2dI0I57kl7AYwKPIl7B2R5adF+HZFCPTb
         OCfcfDv0JvHamptzT6qKFKRvWdbqRIaOq6RgOWnNQiOrvWs0OiwsoOtSUIBNbmUdbKU1
         +E0wMvdbX6QOg1Y1EA/whf+nwj3CkkjNX1lw7lmn1Gg5f03axgyk0L5alVajgFGw93ia
         kXVxsipal6u2WrBT8FHaUBDWy0SVisG+E2ZKzidqgkd3WErkzxIfPHvKhnq6mO9MEunz
         CCHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691181128; x=1691785928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=cI7Iu0Y1VhBzoEpnqUb3drE8bgwxX3jOQPcTUHVxPRQ=;
        b=kddi7oK+oTFBvr9nc+C4L9DV4wsmjsTr6+2yTQf2funkWCpoeVRYgnmXlhiFtJSV4W
         /UP43wl2BNv3KrwMmcDvsgVQOGEXpY2rdDMSCDkMuSm0fklIclkc4+xivxGMd8tykaol
         WtjwZy1Fmu8fzS46cpgVWRWYo6vXiQDDGrQdRo0+Hv5p98UsV9jmjp7wMJOAho255+VQ
         S8RpGXSNhd08M9VIYnUOn5xVilGli9xA3IosVIWmaN3ESyGCitaSQofjdSIggepVPnTn
         bekiedUfzBBtBSy21eLWgeX8hmWQp8nVNyM/nWH9K49sE24uC1wo3ShJkJb4/Lciq8CF
         2oGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw9vWipKacfDkWPxoxnrfyAc1JV3oScLJ4/vlx9iIvYmPfofq9W
	nEuGz4KcmKGAVtnreMmkplk=
X-Google-Smtp-Source: AGHT+IGXeGgWTdjH1S0s64KnmcIp3T+VRHvnWMxdG9DZQgINeNOTbyc3UrpS2YR/Fr031R0rfHobiQ==
X-Received: by 2002:a19:2d03:0:b0:4fb:8680:138a with SMTP id k3-20020a192d03000000b004fb8680138amr1919711lfj.22.1691181127767;
        Fri, 04 Aug 2023 13:32:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:313c:b0:4f9:5599:26a with SMTP id
 p28-20020a056512313c00b004f95599026als154454lfd.2.-pod-prod-08-eu; Fri, 04
 Aug 2023 13:32:05 -0700 (PDT)
X-Received: by 2002:a05:6512:280b:b0:4fe:5051:f248 with SMTP id cf11-20020a056512280b00b004fe5051f248mr2876588lfb.19.1691181125811;
        Fri, 04 Aug 2023 13:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691181125; cv=none;
        d=google.com; s=arc-20160816;
        b=zxqJdyGdL2Ew4KwfTmj0+RHlyCaSvdySXwzjTXRjMU7cpIpRixm78uu9evZVON2K86
         FvdHmQbJ4Ds8boI/QHC2t5LSCDE6V8I4ZFypQOkj4dB8low5XR7lZo4mQ8m3KneEMt6s
         EuiQEUFUop0DzcLEyyS2KYkV5UM/82+LTb1fzHpZ/gZ1MnlAQx0l2q5WIqa2DP4TUTD3
         hrvllNKcB825vdZEhos2RTIQOzXrxYi44vkQPzGkzm80w3Qk09g7mQfm7TAc21jlWPjX
         oX2xvEm9L0HtMya5Xshcp11Yd8Jp1NWNpX8O7bBCy13mzXS38/0oZ01HSxPrYFfzDwtD
         HTeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=R+RUWX28hZwALIFj+2L0l1c59KQ53dK04rN66cG/7uE=;
        fh=oI/Xiro4+EHjElptEbxeKLLzFvN1qXeWbIHTFIMB7YM=;
        b=yLgFb89wKkftPO035eEBMSJo70uZBWGBC1prAef9uB+tBx+g361osyfBHmpXN1iTuS
         68kjwtxxrfk/b1hGZnCD1du6Y1wkvUI0q3xpWGAOkB/vA7cZm/6qdiZJc1GzqR/zMK2Y
         lmnwkQnzH0IGreefc+7nL7MzNwHkDPRnm9UzytJHnwKzVVsAYOg/2cSh3tiGt/ZMKU9h
         9xBf1aU0UTSNTdXCvSbM8jYcg5ke2Iky6CtveHs8Bh77HVHwrvqXyeRpsrozos70XrI/
         3+Yd3gOBWlKpfCoDhuxgzEeJpi20jRiAu9SWsVehRhvtpzUS+A/+LbbQpiG/cLy1tt6l
         MrqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nyLuHB7O;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id c3-20020ac25f63000000b004fbaaecae45si202692lfc.5.2023.08.04.13.32.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 13:32:05 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10792"; a="373895260"
X-IronPort-AV: E=Sophos;i="6.01,255,1684825200"; 
   d="scan'208";a="373895260"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 13:32:03 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10792"; a="759701472"
X-IronPort-AV: E=Sophos;i="6.01,255,1684825200"; 
   d="scan'208";a="759701472"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga008.jf.intel.com with ESMTP; 04 Aug 2023 13:32:00 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qS1So-006vh4-20;
	Fri, 04 Aug 2023 23:31:58 +0300
Date: Fri, 4 Aug 2023 23:31:58 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v1 3/4] lib/vsprintf: Remove implied inclusions
Message-ID: <ZM1gPnmGPcheMWj7@smile.fi.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
 <20230804082619.61833-4-andriy.shevchenko@linux.intel.com>
 <33e128e8-9330-c73e-4c55-e56cbc87450a@rasmusvillemoes.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <33e128e8-9330-c73e-4c55-e56cbc87450a@rasmusvillemoes.dk>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=nyLuHB7O;       spf=none
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

On Fri, Aug 04, 2023 at 11:36:15AM +0200, Rasmus Villemoes wrote:
> On 04/08/2023 10.26, Andy Shevchenko wrote:
> > Remove inclusions that are implied and guaranteed to be provided by others:
> > 
> >   compiler.h	by types.h
> >   string.hi	by string_helpers.h
> 
> What? No. That's not what we want. Each .c and each .h file should
> include the headers that declare the stuff they're using.

99.99% of kernel if not more doesn't follow this rule pedantically.
We have to have a compromise between what is guaranteed and what is not.

For example, I'm pretty sure the types.h will always include compiler*.h.

> So if string_helpers.h magically stops referring to anything from string.h,
> one should be allowed to stop including string.h from string_helpers.h.

That's how agreements work. We may agree to guarantee such inclusion or
not. The kernel headers as of today is a complete mess (refer to the
Ingo's 2k+ patch series). But still, some order / agreement is good to have.

> Sure, those two may forever be so intertwined that it never happens, but
> one really can't maintain some matrix of "X always includes Y so if you
> include X you don't have to include Y" in one's head.

Somebody should do that at some point, otherwise it becomes even more mess.

If you want your way, iwyu should be part of the kernel build. And be prepared
for dozens of headers to be added to the every single C file in the kernel.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZM1gPnmGPcheMWj7%40smile.fi.intel.com.

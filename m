Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEW72OAQMGQEEWNDTQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CF3D322A2F
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:05:39 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id a6sf9936322plm.17
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 04:05:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614081938; cv=pass;
        d=google.com; s=arc-20160816;
        b=b+er4/S23fRojxyOfyFnCfNwXVfhMLBMZ0juPGRkq5xdk8I9xrM91vvu2FcVGbXb/V
         z04bd+i84P51M8kC41S/fX3I4hcEUJukF1L6DlGehdtBKScn4xLlbsiJWBpfv63LQYAC
         th1VhTQ6l53fpQ0ljLl1df5JMexH8EWw6mu06b8dR+5CRia0E4Pd6qtdBMc0TY5GsUX2
         mkTdfBWbAufaGgpuwEqhhXAFSDiOV2j+0NS5LvSywn9CnbLOAOgkEDGb/K4s52Rr8Y34
         8ojo1eCD4OyhkJbh9yvvznY75Im/NXAZy3zGE0VUDorGJAn4xUkG1ncT8j0FJL3qzW3j
         BRRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=7zjn+BUcqTY8km2ZNtrff5BSirlvuIaA9emdbmaklWU=;
        b=0csN49zFaR7WUyQAOVjvVKLPTCumVZ5bELtqgUmkbfEfQNfGZCbW502quS7J0zz74+
         c6T3qaN9ZSBQrQYj0M03PEejlQXHSCtX/nNCFDjYfkeflO8eJKuXyvw/2Tg/SlV0VJqp
         ObaXknjZgtIJd+HRuGbXQNVgUfZPrsMSqWWfnpA2jeSTZeUDHbHsZtSn1fSnyQBSAS10
         6UXZSLyEP2QYTX93GMe1gXMHc8KDcrcXYdTIOwcGFDykMJuFBOrCeh+suSpN7PJgaPC7
         d12eiFI1KRp9GI1igUP8gbEhHobrvf+DnDCqqg8DeadlWFE4sGBc2mnTWWGUKY6HT+45
         YGfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7zjn+BUcqTY8km2ZNtrff5BSirlvuIaA9emdbmaklWU=;
        b=o2QvLLjfXVM6DE01oDIxYbFZHbrAgoy5QzxRpMqnXssObyi6PQIFyUnL9KuTDsAjkN
         vm4lQ9biBE05ZM/56DfDI50hlbtO4HoFjFacwfEioBKaLF/N6SU3LMkujkkRX5v8jXrg
         CLme/bDf7HjxRB1ZGeNQDXhEtaiRy5PptYHnyaYojCd7BeUbP1mVcKWMWHnXL3EgbAPt
         YW/t9hKPWgDZF++1K2hfbCz10Q4S62I4Pk/edjpYP/JlnPl3D6HwQAlk6pnmUxpElAG6
         dtiv1cDGbwdU/7lCpBhW5hoEagHuCIsuObDkaN2rV3DeI08VkGGk2bC4VJ/fRytgH9B9
         uiNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7zjn+BUcqTY8km2ZNtrff5BSirlvuIaA9emdbmaklWU=;
        b=mBdYhIRmAvd0nVmtdqL5soHRExjsUzl3Ywm3erv1HxbBc8DwYBCQDOzmDcWtkAoj8E
         5iEu22OMCMdCEmAjc992242RF8PgD3O5v597udOUHHEtK1f+eMrayJ/ZNOS5rfG/XVuW
         2B0eMHfEBvCIOrQRcSn93LSP3S78K5JvqDl5CkRoOiJk21Oozy6UoQh3+SGuvV85R3di
         GHkfASzlP1Qt9MKC67sy+ywfjbMdNI+uvNsjvY3DBihPjilprzHCgWN1TmahPxhtvH76
         H88+8GQ0XKMbMtjCyINR6l9E11/O9yOKIXCCOxQQdLck/XUIEUtLCgqebNT0CDyk0zj2
         A8Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532A0HWiSiCYmcRLvfRH2UAwViSEuAHE3D1ANng29nJPtn+OYPyg
	l6Afmc9gE0RlE9EdUNDLnew=
X-Google-Smtp-Source: ABdhPJwUIQ2/hsx07gx4Lrhxfa2lmndiHIt22DI8oN0zul/P9ari4Qx7FWs/9T6gDLauza+r+F9x0Q==
X-Received: by 2002:a17:90a:3d47:: with SMTP id o7mr28559515pjf.149.1614081938246;
        Tue, 23 Feb 2021 04:05:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:300f:: with SMTP id hg15ls1295275pjb.2.gmail; Tue,
 23 Feb 2021 04:05:37 -0800 (PST)
X-Received: by 2002:a17:90a:fb51:: with SMTP id iq17mr165156pjb.199.1614081937632;
        Tue, 23 Feb 2021 04:05:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614081937; cv=none;
        d=google.com; s=arc-20160816;
        b=GoIOSm93My9kgjBC1LGLPZtut3j5/pZFxxKrUbzyjAbtJO7BpnNz99Tt5tO8U/m3fi
         6oQZtb7z5VxCHctcDOq0xrRmpV2u+bHlahGj1BmHAdLllIlodRicG51sRdYemzRiUhFS
         UXJmjgtQRESkzg3IjIh/uSKXNE7U5BvKXGIq7DOxV/xHTvpbpNuPuDd9c6uB5qzXC2JY
         5ToPh6efzUifgGudwiTagYtZm+HTga3xJjGL7xYgS43R2UTZKNqcEbX9c2DyvvzQ59jW
         A1dMVj8pmxQGVv6PlgTO9exyW7D9Ca77UbYUTeBiVkpfCSRhWi+KUAK8imyIJL3KD7eA
         0J1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=DJEdqVMA5Xb7dfViT2xH1IfEX+edUnN6apkbMWdRj7g=;
        b=a0W5JqBYZWpwyV4vuamq2tL1zgB+vRli/akTCATz9jTGgRwqLoaZ5S3rW96FIhwNIk
         NhgxsVwjTRAthUW9qZAJUmmAFpcfEOfieQTgPgUkRXDOFAd35JnCSFQKzISYz1BMK73W
         FQRkFyV38Ps7VuVkRn1qT93oOZYinUFn9MPgGMTVVnlTYpEuMbgim3vuPWnOSFoJfPEw
         EwADRUCQ/uhXh6hquerOmCsaKGKGZOOBEGSIGbcRZFYokvvlzKFi0QfMo0+ZvSkE3kyJ
         +CplJsy4Bnr2N3tWS1vZm8xEYst3e3+EpqOmOYJ5rnCDJH51ZvijWOOAR79XwrhNCez4
         ZvUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si1106527pfr.4.2021.02.23.04.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 04:05:37 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 21EEB601FF;
	Tue, 23 Feb 2021 12:05:34 +0000 (UTC)
Date: Tue, 23 Feb 2021 12:05:32 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210223120530.GA20769@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 23, 2021 at 10:56:46AM +0000, Vincenzo Frascino wrote:
> On 2/22/21 5:58 PM, Catalin Marinas wrote:
> > We'll still have an issue with dynamically switching the async/sync mode
> > at run-time. Luckily kasan doesn't do this now. The problem is that
> > until the last CPU have been switched from async to sync, we can't
> > toggle the static label. When switching from sync to async, we need
> > to do it on the first CPU being switched.
> 
> I totally agree on this point. In the case of runtime switching we might need
> the rethink completely the strategy and depends a lot on what we want to allow
> and what not. For the kernel I imagine we will need to expose something in sysfs
> that affects all the cores and then maybe stop_machine() to propagate it to all
> the cores. Do you think having some of the cores running in sync mode and some
> in async is a viable solution?

stop_machine() is an option indeed. I think it's still possible to run
some cores in async while others in sync but the static key here would
only be toggled when no async CPUs are left.

> Probably it is worth to discuss it further once we cross that bridge.

Yes. For now, a warning should do so that we don't forget.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223120530.GA20769%40arm.com.

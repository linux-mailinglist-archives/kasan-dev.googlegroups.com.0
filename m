Return-Path: <kasan-dev+bncBCR45TXBS4JBB4OMRGIAMGQELL73ZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B92464AD86D
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:47:45 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id i19-20020adfa513000000b001e33749ed31sf942202wrb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:47:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324465; cv=pass;
        d=google.com; s=arc-20160816;
        b=i85CMkow4U3XB7OR1R+GRQn1Lg+27xYmcyNRI0KP7p0ie3t4EobWodBEZF8MUsuC7B
         oElWcry13jZsfZ/MPkm8RptYfOXIa6sFe3izq9e/2WDYqwM2yyVUa5SsNobYFfRYaF80
         7e1l1kl5jk1TWrsstr68kcEoaLyiURW0h6NQWHC0e/rhaLMEq+q4g5VMVJL01vsXPyLv
         NQKANit75LjNsq3UZiZCWTX56182NLVDqEOG61/UL/VBSatJTgEcFmz3qpBB+JVfLXWX
         giJkpvVuqSpvq+vb9SPddUxI/hipt3jLcvGdUfngfKw0P2kDBJfkPLdBLPGpbkOAbwCi
         y3Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8osBbrXlb/lgtSLtJH5iwYM2oVB9lFseSWGNuW81BHY=;
        b=wvcrjzGbmbTyOwHle71IgBpc+oZ0+15FRAUPFQdWupZlYS3jyTzrHirnNjhshXCkC4
         A88ZheDq5NFmIIgBdPXuWGy+O8PkMvwI505BLNb4oJz2iaixFF+CrjsLjd1neNkjA+B6
         EaIUshl7Ub2u2yrshUyMso5aTlMCDabhOrCU6jGw5BDsnQdL2kiH94y1Vq43PQ35rs1j
         rGkLLUh/8C2URqfyvFpTUQQ+zoS6iQr8CNCn5jNV2EDuICKRKO9Htk4i51mi2l1j0vY+
         H87/PN008mQTV+BxaXebn1kDkX+Mvzq48/Ffs4ZUBBVwS4UR5sfnINKOcCSH2YIvQUxn
         UG+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AjGMnaj0;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8osBbrXlb/lgtSLtJH5iwYM2oVB9lFseSWGNuW81BHY=;
        b=hj3OlZyCOdxa+8Os5bQCUpDXeYr2LY3WPhhMA56Wdh1nS3H0Gsbo9KUorD9BBz/L9M
         gPG8kGBNbGLJDdq1LbVxk4Vis+D0lKlF5f7D0nXgOUzR438wBIlFWD2WAgIrpct9jGjD
         VZ1PdBx77XZpiHjsc3x5EVGt66LcNRDARBBHjuKlIGT45Zm+sLh53NG+vBxUqbkblg1f
         3kmUiiZi8r0rfcGYyzdorpDIu9+wAjYpOKtz3frIvaC3rxKKZiHIzw/TckwNSQU3GnZb
         StZakyKEo7ObEaR6xBG4roVQ4c/yZkqVmKULKoCY4wSH6VPNetmu6scxOC1m6ZCpYZGw
         x5JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8osBbrXlb/lgtSLtJH5iwYM2oVB9lFseSWGNuW81BHY=;
        b=6l2t858xPU02/c2X2ooiszY9JlnNHw5vnrNgROku/pg1KcZQvyCYsMLYDuvMUvH28W
         2YCYQxPyN/ej2JuQc2JXlBVQE2lLx+U2Kh0hSfrr3AKs6mzL9CHfkRMDokWzdG11+N4I
         nfTAahiLXIwnNWaVJcpRyjpzd1ddMhlEyHqT0l0h5eTw/RolemXRKvPU/p5mhHxV0IFa
         gcchhDwlH8lSG8YM90ZaVeK9kvmvUkTNerk5nn68/SvLfNdMlA8Wbzzgaq4yJfvo1MyA
         0t2i747s1UMqgDvyzd0wVwMDoxg7SL3ophbR4dYtu/lSbyGcenxi+YzDtDbm1BYsZCmg
         HCtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530W1ppGo2ElUXQFFOskObm/3FvPwb46tMIFNW+P29Cnj1MJueHx
	Sl3s5Zfx8dhvOFhp5EflPJM=
X-Google-Smtp-Source: ABdhPJxlRM7iMnI2r2jPiK7DWvPYK4R8IeAqY1mXPuMkZ0EQiDO5KFiu8WjNfX0jGdpMAIrin8hBNg==
X-Received: by 2002:a05:6000:156d:: with SMTP id 13mr3408943wrz.700.1644324465325;
        Tue, 08 Feb 2022 04:47:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3487:: with SMTP id a7ls1091863wmq.2.canary-gmail;
 Tue, 08 Feb 2022 04:47:44 -0800 (PST)
X-Received: by 2002:a05:600c:298:: with SMTP id 24mr1008863wmk.100.1644324464267;
        Tue, 08 Feb 2022 04:47:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324464; cv=none;
        d=google.com; s=arc-20160816;
        b=RlZLOV5ZVsAL/9ZSmNraCXTqlSXElULww4OvMD13mEdA2fzDLFyw/ISepE6u+u0aJZ
         HbW3DmNGOppiJqHDobyxktFHvkmK8Z75/Kxf9ALqjsz+BGHw6tMxmFTXaqqEqmF+Clof
         sTcOs0FeNcQW/iGeS2qTC8OTMoRZSEXs1UXxrT81SoU3t2hby5U5SzieNSRKefqzpNk9
         TRqZK090eH8GIsfnHCm4a7cT6BEmhEnLyYJyOqqwaTvWVX9vQrTjU5Op4n6WDI4vwomN
         sSXOk4XpKCG2yFUvPliGQbzIBNZkAZf3bkesQacxKyPy8kgWLtzJuo9OAzHrTKpjDq5a
         2zxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=OtVqrgRc4ZqZDruPN7ynSCR/Em5kGPjSND5/dYlyUo0=;
        b=hPiQFCTM9WRCAbtd7GKgEXvaRzs3VMBXpYb5vx+V1nkuK2oyVrjXsgwS5tWVc3WFho
         aYy58bRia98ZaseRBXqeFJRFtY2ad7fTjknnZjEplRdMiwfAYAP0+x1CmtTMyPs3YHo6
         Y9Az0K517WW+9aQkECIuk8SwHmE9LHs0jYZYd1FOAHHDPveXYJgPq5b06+U2390ejwEn
         WlINuNniSRjDem6pAQtYuxLfYeLsIqU0eCB0dOjK3RfFI6OulUWu82Ry4b+LqMwO8swQ
         n7klGryjAH6NMUjrtzeZP5AqcBlddIUP9vDCH3gOMbPHU8P7zKc6EUXiONEgzedoMhBS
         s6nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AjGMnaj0;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id z15si112364wml.1.2022.02.08.04.47.43
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Feb 2022 04:47:44 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6200,9189,10251"; a="249147292"
X-IronPort-AV: E=Sophos;i="5.88,352,1635231600"; 
   d="scan'208";a="249147292"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Feb 2022 04:47:42 -0800
X-IronPort-AV: E=Sophos;i="5.88,352,1635231600"; 
   d="scan'208";a="632832992"
Received: from lahna.fi.intel.com (HELO lahna) ([10.237.72.162])
  by orsmga004-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Feb 2022 04:47:39 -0800
Received: by lahna (sSMTP sendmail emulation); Tue, 08 Feb 2022 14:47:36 +0200
Date: Tue, 8 Feb 2022 14:47:36 +0200
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>
Subject: Re: [PATCH v4 3/6] thunderbolt: test: use NULL macros
Message-ID: <YgJmaDJTGTmRgNIy@lahna>
References: <20220208114541.2046909-1-ribalda@chromium.org>
 <20220208114541.2046909-3-ribalda@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220208114541.2046909-3-ribalda@chromium.org>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=AjGMnaj0;       spf=pass
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

On Tue, Feb 08, 2022 at 12:45:38PM +0100, Ricardo Ribalda wrote:
> Replace the NULL checks with the more specific and idiomatic NULL macros.
> 
> Reviewed-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---
>  drivers/thunderbolt/test.c | 130 ++++++++++++++++++-------------------
>  1 file changed, 65 insertions(+), 65 deletions(-)
> 
> diff --git a/drivers/thunderbolt/test.c b/drivers/thunderbolt/test.c
> index 1f69bab236ee..f5bf8d659db4 100644
> --- a/drivers/thunderbolt/test.c
> +++ b/drivers/thunderbolt/test.c

You could add these too while there:

>  	p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
>  	KUNIT_ASSERT_TRUE(test, !p);

>  	p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
>  	KUNIT_ASSERT_TRUE(test, !p);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YgJmaDJTGTmRgNIy%40lahna.

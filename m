Return-Path: <kasan-dev+bncBDDL3KWR4EBRBFN4WT6QKGQEUMG5I5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 61F332B03FF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 12:35:50 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id s12sf2374939ooi.15
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 03:35:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605180949; cv=pass;
        d=google.com; s=arc-20160816;
        b=HTvpIcFrq5YGNG3QNgt5Srax15uDVdYOn+TevT8QUy6xYDOuRcCCMGPJVz+/q5Phbg
         467VTZ+PU2bOe7gYKSRoXq6Eg02Cx971qRJNfkZfVJDl8VA/R3XEaWfSM/qYWFxtr3u4
         1E5esOHZsemJze+6zjc0iIRFbUl2kI20riYM+pGcL/gQkWcv23QfB6OVeT1W9nAv7I99
         /5rOZtl3AILjZUa9SouZSB+pxMnOGw77UfvvWLTZhsOsTf195MfSGZ94rPUvZlEoMxXA
         d5TaEm1hpS5ghUlKarhjEcV2UpWwNocXR9KrfCnfLQNh7gwVZ4zxWEkpIXueQ0zpNKXh
         Dafg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=80CuJJYRa7kyLKenZxh7aw6RugpNOpi9x6JRZ2zlb3M=;
        b=pdbWgyNvkHgxeGzO/SxByrzo/vzjTUHNfmAsKm1Kdwe51yb5OfpFq54HE0GHVJA5t4
         6EHoNd2QAsku6LPAIbG6g0DNbnRfz1yQEFkv75DebNoQ9Dlwcb15i3icGVXIQdbJ8NtD
         yX6ZiAoyXqVzlORsZ1jsQDA2SES6E6POi8W0J0y46Wlnya4slYlwAUYh3G0o6SPVWTkv
         E1ZKROFEE1p0zRiHWYz0znXa8dTnX55YaiqZF5wdAIH6mvzdOh36B2gPJnIePfZuFHa2
         E/IG66tNSrpepMFORaEuyVH+en4kDgq5sNs0TNcXYFZ1DrKPtvBrXFEBFvIcgbOG0TFJ
         2ZIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=80CuJJYRa7kyLKenZxh7aw6RugpNOpi9x6JRZ2zlb3M=;
        b=ebiQnFJM4ld76fZlgjLoVJ/H+32biKzS/0kQV9iDndp+yCBkOE4f5i5QUCJ/AquV+/
         S7WxFspyGEg0Socjrp1k83+t+A0tfxCJG6F1AZPNw55iNJE/FGdsFSJSkBxCeax1WBzU
         rHlTvs9y0Oo7CTAm8T60P9Mi0Do/B1Y6RCWt+9a1mr8d9GR2Re0Uxb6QkYqYHdKV8hNg
         W/RY3osKzDGCrXicXN+G2CjXGFS6Bf+ZiSq5ZUzm9A2q2vF/U3Pl004LxCLGiQD8fMC3
         j8POrC+9NXHVPrx2ZKqos5BLELS2V/4Nyqg9377NBHKC6dbRo3OQkr52svfbcXoBYWuT
         jxAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=80CuJJYRa7kyLKenZxh7aw6RugpNOpi9x6JRZ2zlb3M=;
        b=Zwcmw48N8lVeIUN4Sv7Tw/X7ZA3Y77JU1MMChwNzhxRMvazg4iGR89rtgkVGSKYN7B
         5aLHyAYqnS8CmpU8WzX4BS97mVsR6Adj5pZi5znMWKeoC2JhvdRqyKFh/R7DhZA0uOg/
         JrFSvPN5Y+sZAdo3+JWzqs210N+zkZ/PBbHJbc/nRhtLzUI3R+pk/emi8QPN6QmYae+7
         xI3zG9CVCjyYLESusdU8rmtSia2LQg+Vt2fCGUtiQ7f9vT5/ssggnjlj3lvXyajhaTqS
         WMpy3alO2PJZQZ19CmzunNaHeYyrqEAQdcGvHOSZPyVpXwxt/q3fsmcbJIBBoCv6KIAO
         PwZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M88oVGaSx5Alksd2ZnqRO1DSg+VRdMPD+PoWII3TIUCzoVtrP
	REkI1594EgXxj+O16fFRT0k=
X-Google-Smtp-Source: ABdhPJz+SvCsIWX6U+6Q0EN8i5K6mYsZThkO3jLn4GKHwUTvEie1UTAwpxanCBL5dCHTQWVqaPedVA==
X-Received: by 2002:aca:5383:: with SMTP id h125mr5261217oib.179.1605180949402;
        Thu, 12 Nov 2020 03:35:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls653781otk.3.gmail; Thu, 12 Nov
 2020 03:35:49 -0800 (PST)
X-Received: by 2002:a9d:6343:: with SMTP id y3mr21944680otk.78.1605180949039;
        Thu, 12 Nov 2020 03:35:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605180949; cv=none;
        d=google.com; s=arc-20160816;
        b=FSuIYDq++/A6F+gVViO35B9bWxiO7t3dyVlcIzMcdibAxEYzIgH05Xa2mfwB/MAzj6
         GAaV1GKBi7dNjA1SppAztlNNsj7bxg1hQLc16RxalW9zJCS0QOE+PpNFmxgYcaC2TS8u
         DkuxnCFxX0QsGb2nmNVVeEvaAG+VoxzwuRKh+UMHrHdwKO3Glu4+H7f3MnhbxP+25ByD
         vA0nKSn1/+YHSNMGXIwje9zvws7uGM/XVxeVwOwNO2oZDQgT3z5g7/R+Olw0nTaHbWP1
         wMIpAqRMF1NhhqEPYk+AEnpf9q7lehnmkw9SZ8UJ3fGAvZI81IpFUVPFqc1N93nsjvKP
         QWUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=AjsdVaceonTfSri/Ysro3eD+e/Yi2QaQpU3QWyDKJ64=;
        b=0NC0QnsGB2W0U5rCeqv8GVTEsYLs8XtgK9yntXMs+bejtGk9qxU8jvkGAHFDdfDd6c
         Jtb6MeQ4xh3jOF0QXNS5JRUu5eYpn3LOeC1Z4Dkege5O47/D2dU78WhQSZIKZxvWnTI8
         oGVvTCXLr8fAyyvyDWKJTV2pA4XznCPHa+O3ZL+NhyhQL3F7fDtVTEosY+38Eyc3wh0X
         nWGj+eEQ2Fyj74e4C4vmYDpu7pAKCcusZTRBCWgysNbS17l9Xd1TwPzV/b/JWga/0VBI
         0bOvB/lUr8eNW84n0lAYGGzKkaJ4lwEF36LLwEZzXRFSQUzfTTR9pP548C89fh34knhb
         KMAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f16si464526otc.0.2020.11.12.03.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 03:35:49 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 194D5206FB;
	Thu, 12 Nov 2020 11:35:44 +0000 (UTC)
Date: Thu, 12 Nov 2020 11:35:42 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
Message-ID: <20201112113541.GK29613@gaia>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
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

On Tue, Nov 10, 2020 at 11:20:15PM +0100, Andrey Konovalov wrote:
> Hardware tag-based KASAN mode is intended to eventually be used in
> production as a security mitigation. Therefore there's a need for finer
> control over KASAN features and for an existence of a kill switch.
> 
> This change adds a few boot parameters for hardware tag-based KASAN that
> allow to disable or otherwise control particular KASAN features.
> 
> The features that can be controlled are:
> 
> 1. Whether KASAN is enabled at all.
> 2. Whether KASAN collects and saves alloc/free stacks.
> 3. Whether KASAN panics on a detected bug or not.
> 
> With this change a new boot parameter kasan.mode allows to choose one of
> three main modes:
> 
> - kasan.mode=off - KASAN is disabled, no tag checks are performed
> - kasan.mode=prod - only essential production features are enabled
> - kasan.mode=full - all KASAN features are enabled

Alternative naming if we want to avoid "production" (in case someone
considers MTE to be expensive in a production system):

- kasan.mode=off
- kasan.mode=on
- kasan.mode=debug

Anyway, whatever you prefer is fine by me:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112113541.GK29613%40gaia.

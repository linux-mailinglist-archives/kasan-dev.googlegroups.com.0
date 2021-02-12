Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVXSTKAQMGQESSY47BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5CE31A378
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:22:31 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id q13sf64236pgs.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:22:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150550; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cs9vKmN/JBm2/sbALVyKnoo3C/NlQ5+PtWfUPf90xGCKbSB0EwkTKMTSMgSEIk40Kj
         4q9uH/Ld/KdqYkuO9lPRh3XNdUO0UyaTfQWsE/6PbmLbrXdipeheNul5FqFOjBOoxoG+
         oIQ2CMDzocofhR9QowdjDXiJT1saSTyTXVD1IuPz7PvghUXo4vX3hDbIO9M4WxITOGz1
         uvTcsX8PYy0uVjZDTtb/2+9CLDez2/btQveWAKtBoLoSlnphellFHgLP3aNWwSCeSu/5
         RKJHqIFHAFbxLdSG8R+muWYvt2ZiLoqg9/hluYmiSbZ7QELyFAOXJ+91NXvdXfBoNLXb
         8lHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CYz3/U/TzPRDbvRwvbA+FQBUEuNQmx2n2Kd1UeTZqJU=;
        b=ItFnkbpKHKlWarsiRcaRmAF2o4rdyVTeUTEQzIw3dpJixnGkmVYwv9H3G1wC9hY6/4
         wGEVR5gp+ZZ/7A4L+/9sezgGXcxKkrFVAa2+IhNFezLqqRnWEURCpWbQKMeNeJrY+Vf5
         7WW3PfQY4n3DG1OB2HRjTAEgzGqfb1lekMu7Wd4TVI9emrdhzmNtN5LFR0qC2dmSkjj3
         o8iylO+xrbyLhj4M1UfamFVUAJzUXKVnk8JwX8mqK4DPVLXh/SQSMiXQzSCcJGEAhUFM
         4zRAaPnbC+kemxyTe/kZZAhLpKfGYmgEWL548eJHUpFo5aPO2Q2CCKGNioXdM0C5CFh1
         mAOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CYz3/U/TzPRDbvRwvbA+FQBUEuNQmx2n2Kd1UeTZqJU=;
        b=jvjR/lDVEUAREbKuB8p0aOfzaBTI8TfFvHQIEBWu/omFrEPFz3YapKviIJcUaZFEtH
         9iqCoVwxMESGpFJmvpSd1mqTM3DF5fIeglzy/s30ph6N8uIqWnVxM5Sfqo0WmCyMeRGx
         fmrNGbUERyeowNy5hhADBIsQ+pDU7glc/OkycuI0EG+Nt8QpPVp8WpYxItT5wXWchJdl
         GOqreV+coNoJ15+f/yXTFRWF/EYwU9Du9qa7aHe8NzBYw/I90L1iGNein93n/A6rzJFM
         TCnixDUM2qJoruoGvPsSdg/E0ITRF7Q46d3VROpwHxpvPCjwUIehvhec5AJaFxFj73Ku
         ah3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CYz3/U/TzPRDbvRwvbA+FQBUEuNQmx2n2Kd1UeTZqJU=;
        b=Ov+RKonTt3o56ikvZvekFvHFrtudjy2r6bi1Jmdnjfy6BKr3ewqrAd1a5qjRBoIiPo
         EEwRXSBz3WQIE6l7lrusyr7inPolSHQDA+4qMjnI0YQfhekt1a7zPzlSj/N+7XcRvNXB
         fuMoB38p1psYvIORFJfufR2nZsd5c01g9fmiYEP2SIQYFnCJnl+aonZj5gpqBjvHkj0Y
         nMAV1c1qlUIHLh8OySBoQM1cQJbFtQLzIl909jMTKnnoYO4wjPhSX6MLJdbIOtoqijZy
         rJ86iu0q5bHuS1EThmRG+0m395Ja7wBKyhRezbwmZ+G/H0yAphub9Biy6CU0AWWh8yZp
         HrAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iDeAPDXRQsg4C9iZ4c4ZbyDUVzCHza+1XwfwylnOt0CBjgDMC
	xZeLv/3nABmxCb31vBFkxLw=
X-Google-Smtp-Source: ABdhPJwQpVXDYpBmQp/1hYr8CFVazdEEWFAJ3Th8i/xHE+23KeKPRleof95vpPdCVXB21pxZwYs7kw==
X-Received: by 2002:a62:3181:0:b029:1df:4f2:16b3 with SMTP id x123-20020a6231810000b02901df04f216b3mr3662058pfx.24.1613150550364;
        Fri, 12 Feb 2021 09:22:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls4686272pjb.3.gmail; Fri,
 12 Feb 2021 09:22:29 -0800 (PST)
X-Received: by 2002:a17:902:f683:b029:de:18c7:41fa with SMTP id l3-20020a170902f683b02900de18c741famr3622765plg.57.1613150549687;
        Fri, 12 Feb 2021 09:22:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150549; cv=none;
        d=google.com; s=arc-20160816;
        b=KtHbYeJo3dVYN4eWzuPmhQ/LUsY+SJ5qmYM6rcdkMjz3bz6Kb5qpqtUNZkBfa8YTyM
         pynxgPVw37DW8pFTHAofho/I0hKZE57HOQJvC1Y3loXTASvUfjH+xKXp5fFFTAy5TbPf
         BSM0gHONs4znqozJnmssAN6nrpT8NgzmtqYGsf6NXbXd1zZuDb/ftkM8OqE2Gr56KjjV
         +/faVI9O6upMk7ZyTsXZ07DbtRDUtP3Q0VWq4X61d+Wq5e8mu02iy7tiD36B5HFAYEJV
         ZR0O6YqV+0krbOY4CI1EFEt9fDOELgwy8wHNEXIFTwQ/wB+fRifuoDVJ1PoFvJzfIEK7
         mfgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ekVpmv9Swr7Y1hOAz4CbvmvjT1UQ9s7bVnQP7oaGKFE=;
        b=zbg8/PRTym17dFW2Zbmz4WOv5eQqmuaSc+aQpsencecYwVPacGXgQCuCEBPpT24V4M
         4o012Hz3xhWzd1Mjkoqhna5rojvqIPSt71sp/hCFowZscEel7WkRbZs2TRRwDk0kPAuc
         Qa5kXNTSwQImDxl9UobIxWdMAhQ/ojEnaOFnybWlrOkIpVLFYhRQK6rSiRkkFXXUwzQC
         TQAcK+sVbGFtRMJ7W5QLSt2FySTBAr0Du6q6OMFA+KZMPN+cgAkUG7JNx2RmbfG1679Q
         p0qsxdQ1zumX6ki9M+VoctaNKm5E52YbRDfM0lrc47gBgrDesZA1TiaugJJA8A3vIbwg
         ld0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 11si502174plj.3.2021.02.12.09.22.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:22:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3912064E42;
	Fri, 12 Feb 2021 17:22:27 +0000 (UTC)
Date: Fri, 12 Feb 2021 17:22:24 +0000
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
Subject: Re: [PATCH v13 7/7] kasan: don't run tests in async mode
Message-ID: <20210212172224.GF7718@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-8-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210211153353.29094-8-vincenzo.frascino@arm.com>
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

On Thu, Feb 11, 2021 at 03:33:53PM +0000, Vincenzo Frascino wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Asynchronous KASAN mode doesn't guarantee that a tag fault will be
> detected immediately and causes tests to fail. Forbid running them
> in asynchronous mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  lib/test_kasan.c | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index f8c72d3aed64..77a60592d350 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
>  		kunit_err(test, "can't run KASAN tests with KASAN disabled");
>  		return -1;
>  	}
> +	if (kasan_flag_async) {
> +		kunit_err(test, "can't run KASAN tests in async mode");
> +		return -1;
> +	}

I think we have time to fix this properly ;), so I'd rather not add this
patch at all.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212172224.GF7718%40arm.com.

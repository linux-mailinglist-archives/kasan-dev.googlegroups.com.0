Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBT462SAQMGQE6JCAUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D70A6322C18
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:21:04 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id z2sf10140270pln.18
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:21:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090063; cv=pass;
        d=google.com; s=arc-20160816;
        b=KpQ3GkonV46zJ6j03ujU4mqhZADgJfZhKvJXPH0FfBRyknGn6SyknVWSeB2DwaQxSd
         d2mC7kdvhLlKysCFao2fKRzgrBp9zstIXg3FSCovDdlddqfjeBFp/A88e7G9sL3Yg8bL
         9IlDbR9ny/bH0XZEMabylfV4fUCcoyMHXV4nyFGo5yvFJlIKJLenbsBVp2ZDeoJYBlPY
         LSatoROZNZ+bCdrPeCbwpx2qUnF1jD5OUqRofoINsfrgOKYQjh+n5dUwCx9DGokuNpFk
         lmtNYtV7/G3kjyQD62vjxpegCu9iTTUc4TmFqfFTpInI/DO/cAgio5vbKmFmq0Wc4gcQ
         Xo2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=YtgfRNOv6ywjASZfE5/njj7Ea0uuruiuV/8E85oykmE=;
        b=foV8FocPwN6/1PQjnkxluooN3mg1ieSb0J7ac483/ZNMcSqbQXQStZoS0MJj7EB0SN
         N4YpCyhQpczu3V1JBL5AF4zVYxX4Ai+5iYNsEWZHh4VTS1UlwDBm4KFwH2PdS5FaMSVN
         mzi92IirVuE6idMSFAkyC54EkOnPINXAwSMXHmidTin+0xpSz7UCvmd2MkFzUJDmxLoV
         iUMQb1HxiaxMXfjUx72M0EUTIobIfmQIiqro6R4kGS9uOPV/2Uw2NRp8cqCYggiuZJbX
         1shG1kn/XO4QXpmEjwVwXww0jfgK3XfkT01HH47DdxXv6aWTa9VxOVTL8IOyU9ZmtnTH
         wgKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YtgfRNOv6ywjASZfE5/njj7Ea0uuruiuV/8E85oykmE=;
        b=fSAUGb0zLPOudvTx1vLThbQGZEGFmUBwsJgGAfAp7SzeqRxdiCCilbHx1qCdwHpOq4
         vQCKfXmHmeh7y0NnmqfxOH390CbzXDTUT/ZYumTriUuUkRRuUe/roE+97/WuRTeIAx2O
         Du375qdNxvgMsG7mzzaS0K7IIQz1AmLepHrFYqFO6R65cimc4Hyyr1LMHUwbTPb1Hvjs
         0H7pDSz6j3ExTHemiyHAQM9tGaO6JUbXCE8T46GW3JybXiPm8hy2/JTHdOLqffSxZsea
         nmGawmJWUhNiBQSxpczaM6ANxWmerlJJrPyn/cLlZF2Y0vmxBIwjiFMBZUqhs9cKRJ3x
         3Z7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YtgfRNOv6ywjASZfE5/njj7Ea0uuruiuV/8E85oykmE=;
        b=Ln8opy1IfT9L6/rCrqTWXz1QMX4OTUy/bgtUk18lVnGdU2kOznQ/Pykjebyfz2Doln
         mBsB6ZVtRHFm9R7wGUdidiLslzvHvuTAtmGI96i9dc7IeAospLJHfJBKYtLbyO+QUo1a
         pFsvuFwhwW+Tn+nez5Xo2AsrMKQ6ujz1OZF9dYt/ki7PZOZpMs1gyAVEo6c8jKq+gkUr
         Izhxl8tk5ZNcr8GSbXI45Y++4qwdISmVJTOtNQe3b4VMW0W7OpZPtayvWAzv59084Dx6
         /KnwqqRI9JVvy1LOXRAaxR334d9KzMBpUuFo5P/mkTLFfmK+Od/Al+oiYWYI+VHJV426
         0TwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Fbk4Vow161O27oLbyu4kvV7Bbqszter71WjVU0Y4miWIAdtAy
	cwAX7g3olc1H2WrSN17b5lk=
X-Google-Smtp-Source: ABdhPJwzUX8YjRlkqidNWvl0l71ZMwO4Sa0XArEX5eUkn3h9uNU58MRz+N4YPXSzzijUA4YcAU/bvg==
X-Received: by 2002:a17:90b:364e:: with SMTP id nh14mr12742841pjb.115.1614090063496;
        Tue, 23 Feb 2021 06:21:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d246:: with SMTP id t6ls7426065pgi.11.gmail; Tue, 23 Feb
 2021 06:21:02 -0800 (PST)
X-Received: by 2002:a63:f648:: with SMTP id u8mr13443136pgj.270.1614090062853;
        Tue, 23 Feb 2021 06:21:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090062; cv=none;
        d=google.com; s=arc-20160816;
        b=IbVARWcd0InQUZq53pz24Q+vjLml+IwKNRQ5B+AxKFwSwJEZj6VItfHts4Yt6Pj7sm
         r04iNn1FLGCyoU490oC4XJ/kZnv5voMgSCLB/DXUPsWumv3eFEVhHHgqsTafEu3uZkBG
         6VItqlh3lOlppir29cdUrDVZiJJMl3A6h0rYS28VlfbGzwTDVRR+9PX4Gcfcwcf+ll1I
         5V2m49p2ajY8AqCrRYEfx9Fjv3unAhJ2+jEzVLgFNlbWqzxpgXF7HWyiYw6NlQzcm3mI
         A492vSnrxI2PQ8Ih/FDripG6yP2FEYGdxezjwHu4oorcy5ri46bquzkplSIz5lhspptW
         c0ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GZqBYwx2y9FE9Ziq4+OKl0cRPbE5Rtru87ojPxiAYl0=;
        b=Gk9hMNbaMT3hJIYh0zEMVrndFR0jV9CcyPNPEHPHmDqKBuDJLOQaJmLGwCKvn8nb+Z
         NTFFO1mt0Py4sWICW6v7d/+y9daZz2C2CjEvtmOhF38KwOyQ9bQ/hWVxvV6DhkvQwWv1
         KoHPtPPLuw4oYEKQbDZYIeSRgSm6KpWG4rsl4B4vdcyTGnUqdFBttaK+PhXXJ7e4eC0V
         VVby1ik+OzwQBU6OLbDm/ecPfHMKRnKpY5/C+4XAXJ/112WBOVculBlXES5ScwRDMmqK
         mGgBbbIqU1AXDh5kcVwQyxfeCQ2XXYPdUtZg8YqLF+waf0ENRVOY7hWoptNihyW2t+/f
         XQQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n9si175276pjp.2.2021.02.23.06.21.02
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Feb 2021 06:21:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F3DE71FB;
	Tue, 23 Feb 2021 06:21:01 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 03D8B3F73B;
	Tue, 23 Feb 2021 06:20:59 -0800 (PST)
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
 <20210223120530.GA20769@arm.com> <20210223124951.GA10563@willie-the-truck>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <bf45cf22-662b-e99c-4868-bfc64a0622b0@arm.com>
Date: Tue, 23 Feb 2021 14:25:14 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210223124951.GA10563@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 2/23/21 12:49 PM, Will Deacon wrote:
>>> I totally agree on this point. In the case of runtime switching we might need
>>> the rethink completely the strategy and depends a lot on what we want to allow
>>> and what not. For the kernel I imagine we will need to expose something in sysfs
>>> that affects all the cores and then maybe stop_machine() to propagate it to all
>>> the cores. Do you think having some of the cores running in sync mode and some
>>> in async is a viable solution?
>> stop_machine() is an option indeed. I think it's still possible to run
>> some cores in async while others in sync but the static key here would
>> only be toggled when no async CPUs are left.
> Just as a general point, but if we expose stop_machine() via sysfs we
> probably want to limit that to privileged users so you can't DoS the system
> by spamming into the file.

I agree, if we ever introduce the runtime switching and go for this option we
should make sure that we do it safely.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf45cf22-662b-e99c-4868-bfc64a0622b0%40arm.com.

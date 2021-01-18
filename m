Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXWVS2AAMGQEV33G2VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 213C22FA4DB
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 16:36:00 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id p77sf20215817iod.17
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 07:36:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610984159; cv=pass;
        d=google.com; s=arc-20160816;
        b=oA3/mioB1BBnKn7PZY0YyAgHl0Q+roFrhpylRVPOsGFtV3+gex3cjYBoDeRsxJNihC
         MWPm2L5Jqy9cmPnHZPvV42jfCUy03qqUL1YMEcpX2xS97lppJhyv2JlahlvUbO2zeZII
         70WMAH7E6HT4pbwo5PtuDD+cV1mKBCzVtfwowmsUrrJZ3H51Zgc0B0rZJ/BDzwa3VVVz
         UrBNeezNDjnGctGiJAycX6O+7lvIeEmuUWied8MwwneEyS5X2opZgymXlS04e7SBhWUn
         Gs+7xjLLmMy04GtlCDvKf+i1IMrLOHlOUH4txkrrkFf6MOuFdhGjbu99Dc12ExxkyQs4
         6+nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=Ow3pHBEJZMX0p9036M4Wfh5qGnJG3yjxnYEkUJ96srE=;
        b=AvhLOKRNN2UBEyZ9kP9Ur0O5pIwDlcQU/jamXs282VNz289KQ5FWXUGhctGoA6MHHH
         1tTVx/0C+KlUEuAABWNCrTxpCZwrIyG/37I6SKKemmcsJ2JrSzTW5WOUqJhb6AvNp4G6
         cfJDbCuYJ2HFtiLyLgSjJ6cjYYKIllfMalA0F4K1v7KuXfpNP99YF/irb8IhhjLkTscX
         8SEVJGwg56HkXgv+hJbPXe7o5OeEacqv1N80xVJO9xV0dLRtNur0XFFOCwNMMh5wLtIG
         G34gPC8hKqbaXjLfBRVLgdxGvuSLQ9M4Gon67LO668LxtkR9gNjNlVxd7o5OpZIDvn3I
         BxGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ow3pHBEJZMX0p9036M4Wfh5qGnJG3yjxnYEkUJ96srE=;
        b=BOCntXrPcG8ifv9mHsBwgp79Qx5Xt66QpvcOtHsi2cZomIW/+dEN8TcXLLzcubSM9+
         7NmnkDqIb7KWI7+Gkji0hC6d1szdqcSIi0LTUh1ro9Z4LViSy8xV2LM+fhmv2Do8vYt+
         Al290ipXYjTiz+u+YeRWO/Uyif/RG/HDdHeK2N+z2YwpI/WTIDbN/zvMEGi7zpoDcpSE
         5HwejnJAG8D0Bt8pe+tPu1TejFDwEOVb97xjBV6SeFoiAkacYDZFwojGuwdehvzVGtsW
         4K6HctO3yQpwvp2jTsBpjXvy7g9byPerbx78fcUGvwMyTAUDKjoTCXT8U2JlUm98Ctox
         H2Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ow3pHBEJZMX0p9036M4Wfh5qGnJG3yjxnYEkUJ96srE=;
        b=lroD82CKu1dienEW5qJ5i6GTIPOy5HuPFi6eJLWemrhgXTU1p19hI3SWmiVxQtqatU
         Tgn1qONKr8/fBiFx2st8HphnWi7Nm1BzNUwQusKgjyORjjAzwHyHAeoi0ZqxePDAsWau
         V7TlvsrGFsa3r7ROty7tXCxNxV0gNoyrOH+oQAckhh/59OrDvdGLkTBWI0RXoNI3Auh6
         OKIcwZrlKRqwr4urpOamgJKTP0IBpmpy4DyjxFyQa12+uTDb2Yz6nYeuPHcETJSgZC4m
         fepAmrQ3Pqnqzba8SMmG4kyN7m8PKkh8G/kXjCb4AGY3yWmQkPXfI8tr7SiZjj+MIlpy
         xH0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WmazwhBM3mVrcTlJ8HQrMIYMqlPSBOGOGhavHiVt04NtsyaOL
	exs1Cvg7i7Z8AzdIU/jQu8A=
X-Google-Smtp-Source: ABdhPJwrP206EbtCgliT+tBy8K/Ayscki8lVkMgocR0WkWdX6OdXwSstloRheeWikgAzyWQskmKUKA==
X-Received: by 2002:a02:2544:: with SMTP id g65mr86583jag.91.1610984159041;
        Mon, 18 Jan 2021 07:35:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10d:: with SMTP id t13ls3082428ilm.5.gmail; Mon, 18
 Jan 2021 07:35:58 -0800 (PST)
X-Received: by 2002:a92:9a42:: with SMTP id t63mr21765501ili.176.1610984158724;
        Mon, 18 Jan 2021 07:35:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610984158; cv=none;
        d=google.com; s=arc-20160816;
        b=k52I9IILlrN+lRaoj6RlCXUCbO27jKojk9S3QrTyhhXKxybHgcNoA0YEmzewNF1bpU
         kA5a0vVHSL84o0kneaN4yteV4t/IQAXq2bWJJS3q8pUl/DNb4chKFCR+u4epmXbOPFiG
         NxpRw41cp+B4aTqPsnrBB+xZeGY4xAz7zJmklvLSruL8L1U1qjgdsSxj+1+Tl9PtuE+Q
         wgS0JW130MXNHySZ2EoNcgKLheC6YVf6ZOl/HCO1LSY+FSkdyfDKnPfouGXZ56ZtH5Sp
         TApKWQ2lB+zD5VscgQd02XbF32N7hAMq7C5tGOBy3afjrxV6xH+lccJ6/SbpEwYTKRxP
         u1cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=TME6hLmEuKhk6Vl9+AN3I+gVK+38pLhWhnrsla2rM2k=;
        b=zqnDLZ47UPMeWbUfamUPYLeDN3svE1bsfHF0/xy+jtnzVhQt829Ha1PPDUfY1tBDq+
         6JUCBnbPETkXFt6vjDsGVoE4IYxhttBaK4kiwsrJI284bNHsHdBHIdkmmZNSO0cG1dZx
         fQMGZFAV/UJPuaJ4YBE6PlBDxOVYDZnULeEsxB6cWkYU5J1KdZVD2wcki4rZti5PYzpF
         /z44lVaIJl2raOmqabW8AzZWuNhGtxgyVoVlU1B5vQulFfvQOBnoB6ZspMJIOjqEvHpW
         NgocmW22z5h69ysJqqUURFPoSOgM31gepI+F5WD2JNYelr7Hrze6F2+GQkLczqGm9aUb
         5ayw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b8si2096284ile.1.2021.01.18.07.35.58
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 07:35:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1ACD21FB;
	Mon, 18 Jan 2021 07:35:58 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 66E603F68F;
	Mon, 18 Jan 2021 07:35:55 -0800 (PST)
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>, Marco Elver <elver@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
 linux-arm-kernel@lists.infradead.org,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
 <20210118125715.GA4483@gaia> <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
 <20210118141429.GC31263@C02TD0UTHF1T.local>
 <1c0577c1-bf73-2c00-b137-9f7251afd20e@arm.com>
Message-ID: <ff8c61b3-1374-29c7-a4f3-9e37b61e5f3a@arm.com>
Date: Mon, 18 Jan 2021 15:39:43 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <1c0577c1-bf73-2c00-b137-9f7251afd20e@arm.com>
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



On 1/18/21 2:48 PM, Vincenzo Frascino wrote:
>> Are you aware of cases where the TFSR_EL1 value is read other than by an
>> MRS? e.g. are there any cases where checks are elided if TF1 is set? If
>> so, we may need the ISB to order the direct write against subsequent
>> indirect reads.
>>
> Thank you for the explanation. I am not aware of any case in which TFSR_EL1 is
> read other then by an MRS. Based on the ARM DDI 0487F.c (J1-7626) TF0/TF1 are
> always set to '1' without being accessed before. I will check with the
> architects for further clarification and if this is correct I will remove the
> isb() in the next version.
> 

I spoke to the architects and I confirm that the isb() can be removed.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff8c61b3-1374-29c7-a4f3-9e37b61e5f3a%40arm.com.

Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPU4S2AAMGQE7L4T3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DCEF2FA1AC
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 14:33:51 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id t14sf11493931plr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 05:33:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610976830; cv=pass;
        d=google.com; s=arc-20160816;
        b=nSN+T8spzQyvNiacx2G74mHJQFFBI4qW0jBBue96BIB73vNywn/qXRFM8vhplBP+9C
         47zWVopzgUjRincSHSJgl19KD5YLMKKs/3qHJO+QF0ZDgnpt09oF2PLCzU8GdQLJx9XP
         etjdQwRhzvsbSv84xx9uQuEcWGdle4cndQX2wQxtDQYuzIDFkCGIK05OdQgWmvd4VB81
         tjZUevnBivbXf/kJBw/iRRQiKE6gGbbIwYaS5kTJNxkm19Buiu6EEBwIUG1h84ZIAJW2
         +owDLCzDSPu96Fmtfyk2d7N9gYgyFtep44vwPR9tXRFvnZh/1wcZDkmt1S1/vgjvpzh5
         p3pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jp8L0TzG3Pf+syQ+BtsbQoGHMjCrJQ5191vd9ym9mQg=;
        b=kHHvfEvoir0CGvqzgxEynXfdLvNd0ulgp99SLvUi0anbUzhswDfWhoceEQ4dRO5nYh
         JQ8RbBAO8Vp2yncg7lfKrVyWuZZ240MzOuJIp0EL440lOsEhkE2cXgJYyCSQ1N5zNKu4
         QDirMijzyINl1fnZGhRteETOtbbeqt3XzY9khJbINMIJ3Z4KZ+6kcrzM2N8HmLIGiiT9
         ZJlp4s9wXg8QPw9qpvB9gDJEGdhxrmgH4mmsbA4PVjoQrOkN7hZ57i51WKDssRDod13g
         3O/OOShgFWTMAEEW3SB//INkvUH1dGklu2eJ6ajRIvGEyXGnsdfa/7z9JxR2YquuJDpG
         Hdhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jp8L0TzG3Pf+syQ+BtsbQoGHMjCrJQ5191vd9ym9mQg=;
        b=Y6ikuExMWdLJxk4h/pc9IumCXP3JgmBNOZlzcwz2OZX4iXbIj/KjXnGXsmDylNuI0H
         RxKuhlx+6vsgPUO267xiLXVqxR+BIfLIWyyAHu3Bz48Y6wlelJankUdS4ydCQlb3Xm+R
         klI+fchPno6njN3AZBct6iotg2ErTxEv/hG+Sn+HsccjoOjYoS/UaNnGVFkoUxSg9LFJ
         j5pcm6+hif3HC96EoujdJv+i/60U+M5uDF/BuAzejsCAmsKprwnshjmOpZ++AK9JkAx4
         RKU61vKcPOSIXIWxkgIMPZBGR/EJCfhm8zGu9a92chN6xdB93Sgf696rf5ZqnW308N1V
         vJ/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jp8L0TzG3Pf+syQ+BtsbQoGHMjCrJQ5191vd9ym9mQg=;
        b=lGAGnuXcx/1gmpRtlO7aFPOuyVPrI/l7zpCXYdMeMCCOgECjeknoPfKskqmF7El00L
         P3gZQwim9tGBeAQ3RJ2slRkS70jX7CYu/CMyAF/RHYtm7h4I6YdY4w1hxnzz7QsTw4SO
         DRvsXAWlQyJOQKvYco0qsTdZjhWhy9DqmjBTbgzphMGp1llRpxuZ9chvSV7g9Xz/fB8A
         bB69sQhxEV+UVSW8+FBQ4BEobgbN2am+K7PR6zqfhfMqV/yiUAOWJekTY8hoOJyzWHkn
         aqm2gopKWmNhNw/uyo5BKvqW/PREnno38nruxsOnkaDVwozo/2kN6onsa9qNbGVNHEJF
         H33A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YByFCDy3Fjiu1JkORui16r5iXIycf+fuJF6SOG4rvdt5Jht0/
	KbuVDjbule+a+s8xM0dYnAU=
X-Google-Smtp-Source: ABdhPJzxtvS8tKTSEAEf1XNeYSXUqqgxMunSQkLodDQuyYBpXKnKYpdojZUwtrBM0mE2ITHnsn7n9w==
X-Received: by 2002:a17:902:ed88:b029:de:86f9:3e09 with SMTP id e8-20020a170902ed88b02900de86f93e09mr13499734plj.38.1610976830380;
        Mon, 18 Jan 2021 05:33:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls8194237ply.1.gmail; Mon, 18
 Jan 2021 05:33:49 -0800 (PST)
X-Received: by 2002:a17:90a:5501:: with SMTP id b1mr25836219pji.7.1610976829845;
        Mon, 18 Jan 2021 05:33:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610976829; cv=none;
        d=google.com; s=arc-20160816;
        b=LjvAGsAqzEXodaSYNdhgmqx2OfZalV1NYnhU9WVMYybYX9/ULw/n7JtT0a+Ypmwkqh
         C4q+m0qKJE4m0wOGEs0WCeSPqxXP0RjY96e8nPzWF0adtLb0kcyICtmjUGaF7WDhn4mA
         xDjmnBoB2oZmUuMYHqDOB+1qFaYmNq5wGnLQ7OfEfOagNRC/flnXR7IN9sEKjO/+5ypW
         VsdYfkoBxqgs2oOU+lhJsRMcuKBWz3hgQ3IjHpLnPk7WAFmWDoZsGBKK0RUqIUnq0Tc+
         cxtU9vjOHTH8b8h8i1smesX14wlabukzgE39P5GmRdCFECOlDvo0smw10bqxkF5dTjyB
         MSxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Qj3KNE/+UvMUhkcM+mMqLfAr0OXxwmt0TGuLOc+oBao=;
        b=MBoqlJRQc7tNtljzxUzwRf+KYf91MYGFPPYNxkeD2rYb/TyO8hpoOB99tcUW2oCmvJ
         Jio+n8YTthSsq5rkL5iGZfGPat+9WM8AO+VrrdOVNnrXmmY9rauG7qTfY7Ne+2quzo3q
         uSNdKi9ba+wQHf0BxB37DO8tN6sBnJtwryAWv1Am8/I7sAb4k4ec9f6viMbEXIZhgEq9
         d4oGTKeRTHSr35QAiEweFOnyL7XKPEBVZwiKCcvUXPk7hB7WYH6lVs2Xe0B8acwCAZO8
         W0V1/jUnevVGESLBrKLXPYi+VivepaRTT6D2YRcAcC2YhbtBxzET5DELoMzAu2jSplaa
         Dt0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t22si1471598pjg.2.2021.01.18.05.33.49
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 05:33:49 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4869E31B;
	Mon, 18 Jan 2021 05:33:49 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 57ABE3F719;
	Mon, 18 Jan 2021 05:33:47 -0800 (PST)
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
 <20210118125715.GA4483@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
Date: Mon, 18 Jan 2021 13:37:35 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210118125715.GA4483@gaia>
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



On 1/18/21 12:57 PM, Catalin Marinas wrote:
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +void mte_check_tfsr_el1_no_sync(void)
>> +{
>> +	u64 tfsr_el1;
>> +
>> +	if (!system_supports_mte())
>> +		return;
>> +
>> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
>> +
>> +	/*
>> +	 * The kernel should never hit the condition TF0 == 1
>> +	 * at this point because for the futex code we set
>> +	 * PSTATE.TCO.
>> +	 */
>> +	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);
> I'd change this to a WARN_ON_ONCE() in case we trip over this due to
> model bugs etc. and it floods the log.
> 

I will merge yours and Mark's comment using WARN_ONCE() here. Did not think of
potential bug in the model and you are completely right.

>> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
>> +		write_sysreg_s(0, SYS_TFSR_EL1);
>> +		isb();
> While in general we use ISB after a sysreg update, I haven't convinced
> myself it's needed here. There's no side-effect to updating this reg and
> a subsequent TFSR access should see the new value.

Why there is no side-effect?

> If a speculated load is allowed to update this reg, we'd probably need an
> ISB+DSB (I don't think it does, something to check with the architects).
> 

I will check this with the architects and let you know.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c076b1cc-8ce5-91a0-9957-7dcd78026b18%40arm.com.

Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6W3ROAAMGQET3VT4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C83C72F8D72
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 14:45:32 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id 21sf2821282pfx.15
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 05:45:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610804731; cv=pass;
        d=google.com; s=arc-20160816;
        b=uXUNBW8FktE5gsZ/BRVuGLBy5SGbl8e2ghUKPLgIHI1axhhsQk3z0sBv9DE8cNXYfL
         BEOVf6CP5zhmCFLrokdXiWpYoIq51mEcRsblZX21BVQZfXDPGrwsqk8PgyoiPt0boFTe
         4/qMgzQAyVM/OWJklfL8tnKgTqFGYkCuZhKkGKrk/CQFXxiz3GRqUcTW1gzeo00Gb+Ue
         KhvijvBfq6h30ROYRv1Ml/WvpfumZsNH8aPVKI4m12QlDAKaRa2voSz9ntGEaC6ZNIx9
         V0OFcxue3oy6QjSvm+v8L0i0otb2ZDDzeZlYQPVMGFnQo9qNFLUq/+p/kCzT+sip7EiV
         gJ2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=kZDu1htMKe8YGa55Q+WSkzBXsyr8MlVEwHjHrFgjGDg=;
        b=g1lkQwKz/HLSVl8ntkaI9LcyFWx94J5c34GXFOebBdezVICtYTEcanpt3JsVggz/6/
         2uGwziz+Mo6xNQMgqTPK9rguvgnqZeLze4UCBxD8IkI7k/ZNJdwevNIu1S1Gek0rDgLb
         q+tie45A34YCCjhjV1WMChev9/9i9dyfwDwzFRGbEgWWEOHnYB5GaTN2eWoEUeeH48P5
         v2vI+Rzjo7lftV+dd4hFqRMkT8+shI3T3lEMfYTpJXOiPZ2lvdV7mlAZCvJssEbAVsDJ
         BYFf2xgRlt/wc/QlxJXkUbTNDtm1oL9q0viodVnwSELo7GS9ZLPO+4YmteQI9x7KF89M
         Hnhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kZDu1htMKe8YGa55Q+WSkzBXsyr8MlVEwHjHrFgjGDg=;
        b=RwarxS05FCRaFIdBn9AszzlDd7Ou+BjI0qKPwRNU9K3knZm2P7HW2YkYmimaAOXZuU
         KSc5vtyHw378hgmSjLaBAQJWoHtzf+UwI7tbbdh2u84WOMGPWDEELgqKpRVBIhUFiHXJ
         gcCU9T57ZQ1Ysf8wBQuaTaeS0MToqVHEXtDPJ7gSs4kHLN/XslDL5DHZbkQ4uGi6wSNt
         /FotUoEZ26M1HBHJcBBNW6hCfklG1PnAV+LUMq1SPmUONlsgSipIwYkmKQUmjM1M5Pnh
         lYgjL1eh0+FMQ4Fjj2p4+snJwT4a0JX0tSB1jH8DsHXGoNWhsfixp4eHJkXi0hF0bdkn
         RYbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kZDu1htMKe8YGa55Q+WSkzBXsyr8MlVEwHjHrFgjGDg=;
        b=TWM9Bc3NcGxCX7yi6MAzxsl9T+kHXlLdw1BxJ1T1eJQA/WWda/uty8o4HtaDbxrISI
         +4Flz66G44NwsRz5u6dURXHaVzfnToE2wwIxBU9v+Ku35yjZCr4Jc/osPh0RzySZAcoV
         rkn5utOXlUzgqMf65R20SnvNZRJ+WkJbefXbXEjW/t0Tg8j0GPF+KXVO+79dxlzzLX9Z
         ynG8uvgnNcwMp0FPT0lEaHuCiAnP4EYadPuqvdgOOSeFc/B7xZfTR51ld8sAoirR7oHt
         l+t3z2FwaqKCR0naSEqSkPK8G0OyLXNSDd2ISWm5+mJpO/CyzfPxEFW6UIENzKIPHyPz
         J0tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sMLF8FqmmRzuySr7kzBQmbvf9hNUH8ijxPA0LLSLmclBRt8mZ
	a+UwTgSe1qj5OCYfck6porU=
X-Google-Smtp-Source: ABdhPJyjEiPDpZoUF4v7mt2Yba+LW1tuXA7VfbnAo72NM9Lc3iL4i8XxoHsu3KzNTIjsXaoAlN1BcA==
X-Received: by 2002:a63:4f64:: with SMTP id p36mr17491272pgl.374.1610804731015;
        Sat, 16 Jan 2021 05:45:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d4f:: with SMTP id j15ls4563770pgt.11.gmail; Sat, 16
 Jan 2021 05:45:30 -0800 (PST)
X-Received: by 2002:a63:ac19:: with SMTP id v25mr17917992pge.258.1610804730439;
        Sat, 16 Jan 2021 05:45:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610804730; cv=none;
        d=google.com; s=arc-20160816;
        b=ddR0Ln5yUDTR3Q/Eeuejm2VRBONNYR55p7rsxR7AFtnmPfucWP8aNSrbPDWHse5frW
         X2IYzEFVRNowADc0RPYA8hCIdAbQ3crGUMqS0Du7B3bQvkJyIbOkQwcCvz9spMxHHcfH
         RP05HVCs4YObztTEBsCYjgRIX2yY2e64CuWIsv69+HwSlHD3pipjprCqPss+2ekSsHbu
         FpXp0GQDfJX2X6gr+rltBccIVEgK2CMPC4HkIXsvoiMAnoI6+Iy8jcBmGho29eOZDQLS
         Czxisfirt0BpOIArZOfiO89zdq12o9qxCRAHw96u3jlY3dMGPChS5mDJ0I+qVVWPXfYA
         rvaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=N1XcF9/o5Cyu3qAQ6pmlBi9+ZTzrxapvxyJj4SGKYBU=;
        b=kGC4gG6Ui+YN8+8WEruDEHex9scrkzzTJy8QgFkxAvasuGB+CTSmJEc8chlkdhB2Zf
         uJ9dl9EtFCUL50Ou9RHT/ZIi/Wlf261K6gWa/dhrAMUVZCvXZex1WlyeQIpN4q583FTz
         VvophpjpnLYkLJ2QKs3/lZK4ew1wkShnlPfIk0VD+JXo/bQoQPoLQvFion1QJqKrMr9P
         G09ayDgjXe/Q2bNwQgPxnTu62A80Bp+Rhr+tTXCsVzj2+jmQOqYG76gKL5CtHllA2oxK
         YMZWex1uUfQY0WV43Tlv3t7rQlmjjRl27taVsQbFTIq7CYQd+tcyXw6xO5Dja+UkI9p+
         WlRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t9si477508pjv.2.2021.01.16.05.45.30
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 05:45:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3E1A9106F;
	Sat, 16 Jan 2021 05:45:29 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0D44A3F719;
	Sat, 16 Jan 2021 05:45:26 -0800 (PST)
Subject: Re: [PATCH v3 2/4] arm64: mte: Add asynchronous mode support
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-3-vincenzo.frascino@arm.com>
 <20210115151327.GB44111@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <2fde5816-35a7-1e21-e42c-f6e413f30aec@arm.com>
Date: Sat, 16 Jan 2021 13:49:14 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210115151327.GB44111@C02TD0UTHF1T.local>
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

On 1/15/21 3:13 PM, Mark Rutland wrote:
> On Fri, Jan 15, 2021 at 12:00:41PM +0000, Vincenzo Frascino wrote:
>> MTE provides an asynchronous mode for detecting tag exceptions. In
>> particular instead of triggering a fault the arm64 core updates a
>> register which is checked by the kernel after the asynchronous tag
>> check fault has occurred.
>>
>> Add support for MTE asynchronous mode.
>>
>> The exception handling mechanism will be added with a future patch.
>>
>> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
>> The default mode is set to synchronous.
>> The code that verifies the status of TFSR_EL1 will be added with a
>> future patch.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/kernel/mte.c | 26 ++++++++++++++++++++++++--
>>  1 file changed, 24 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 53a6d734e29b..df7a1ae26d7c 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -153,8 +153,30 @@ void mte_init_tags(u64 max_tag)
>>  
>>  void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>>  {
>> -	/* Enable MTE Sync Mode for EL1. */
>> -	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +	const char *m;
>> +
>> +	/* Preset parameter values based on the mode. */
>> +	switch (mode) {
>> +	case KASAN_HW_TAGS_ASYNC:
>> +		/* Enable MTE Async Mode for EL1. */
>> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
>> +		m = "asynchronous";
>> +		break;
>> +	case KASAN_HW_TAGS_SYNC:
>> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +		m = "synchronous";
>> +		break;
>> +	default:
>> +		/*
>> +		 * kasan mode should be always set hence we should
>> +		 * not reach this condition.
>> +		 */
>> +		WARN_ON_ONCE(1);
>> +		return;
>> +	}
>> +
>> +	pr_info_once("MTE: enabled in %s mode at EL1\n", m);
>> +
>>  	isb();
>>  }
> 
> For clarity, we should have that ISB before the pr_info_once().
>

Good point, I will fix it in v4.

> As with my comment on patch 1, I think with separate functions this
> would be much clearer and simpler:
> 
> static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
> {
> 	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
> 	isb();
> 
> 	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
> }
> 
> void mte_enable_kernel_sync(void)
> {
> 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
> }
> 
> void mte_enable_kernel_async(void)
> {
> 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
> }
> 

Ok, seems cleaner like this, will adapt my code accordingly.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2fde5816-35a7-1e21-e42c-f6e413f30aec%40arm.com.

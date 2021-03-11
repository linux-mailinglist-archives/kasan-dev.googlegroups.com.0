Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBEHBVCBAMGQE6VMHXRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D31D733765A
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 16:00:33 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id d3sf5909159vsc.21
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 07:00:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615474833; cv=pass;
        d=google.com; s=arc-20160816;
        b=rajlm8ts9VrVAjejX88jTJ3NuLrjiEpEx2ppf+vaavVj+cn1TAONkuEuDDcNP8+Lem
         odnhbJ+4Ytp54cSA07pfThHbwh+Bifg6bVbGaqIItjskxpBmTVKJHq7tIBWeec2bMmtL
         F2jxOr34ot42tWdz7CqJZpK9Wq6rHtj2AdNHeXx6+o8UFmxh3Rb7c7fCu3tjne1Ji0gV
         3Asi/ye/0dQnv1ZE3hivdaouscOsTzJXBlZP3vu8/UPMogNSG9e2uTE7Na/oanhg6l/u
         S7hACmSNRfW6HOnhSUTttsS8oy4xYqnN/70M+jbtW/FhtZu4NUofDURYyCq8GAdPlGVe
         NUHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=/XHMvi1cIXeKGQ3U9C+R8d9b/KR0pak+MqZgbC6ebCE=;
        b=MFU+Y+BgCOU3U1KARpwq+BnTiocDMLTbFBHjwVulnBjWaPYmSbL8a9AqSD+JbgLp0c
         lPXlevyaMauR870XNitAV88vwNVE8yePWva3JbWdyrCLb9bI1obzV1XYZVOzUOMFge6U
         cMJkRGN7u+XGa0PqmBtsX8HSegZhVDL9fA4KJt0GfyT1Dhv1SDrv2EuufQh2DSP+Wg6l
         mBT3HRhzwItbz0V25U5pZ8GQSSjA+fdUKf9AeQnbSwIcIh5yuCRACOraNODsdSkN3KmY
         ZAn0x42/gaLg9yBSNzqQFNpPtqUvPmr+tbH/EPHa4GWJZTwxj5tZqWspKsXs0OHKWBAn
         Gscg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/XHMvi1cIXeKGQ3U9C+R8d9b/KR0pak+MqZgbC6ebCE=;
        b=KnOsw+CT+t11NlL6XYdf/CLSE0npFwamIs+mZxBghdMDt+vx5QC48j6WjY7bSZQZOS
         9YAo6qhgp90j2srQMhF03mrOG+Z+b3RCB4rZeb9wVxt8jAAxRBuugO6huQOS5AGmGdT7
         zV5rPK3k72ju57YXvj5sqVTrGwPiDtYp0dFey+A9Gg6ANPFRw/CnhLLrvJzENBnvqent
         yZFcnmmkhIdwh74lqA4nuhzDbrR2filub3f8biYpch0ivm7Q8pOt69gauPGclVCSkGdJ
         yz4NQRTmdHnuhWKHpxEpGLjN5HDwH/D4+H6HhOQDHrbOuFekevpS45qScn0UwVjvwsUv
         7jiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/XHMvi1cIXeKGQ3U9C+R8d9b/KR0pak+MqZgbC6ebCE=;
        b=Yb3cdRM6B6Q1QpOgCWmHe0bSFt8rBHBd02/cGX2SMS2A0q9WeBZXhq9IgxxGgES61L
         bhBmLZ/kpy5IU3vjz/U3zfwhNFXK5EAU1xY0g9AyMecrKOiPCE7gPysc9X2FB48t7xGW
         745lKORqYon1imnRaTxoUWPasN6xjcu+yRwHb1T/DINbqLyru8d5OibBzLcmbW2xmS8p
         d3YTHwUjBagHuxEaXbu/oCLUKesfDtUA8n//6psNDa+AwUPNcE/SDMkYmU4DvPbwr159
         Uhge1XfofbWxML7zUleQ4mb37PNyJcWj6ah0CRnu2RceSERlJv1TE9GmdFTlNWr2cPzE
         kJvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zYYMqtUxOhT1+2T5RUvbrjLffr4V8ykuEGMZtOjnXrUeKOGwq
	BLf+yIiU15mIUqrQ/8OBwpo=
X-Google-Smtp-Source: ABdhPJySHmrNMF98BN1cWRrpO5B0U0Iq6a7+LWckZVCMg9Pb2IgRo9Lr1KU83i4qKbYFC2T+O3uK6A==
X-Received: by 2002:a1f:9851:: with SMTP id a78mr5045183vke.3.1615474832922;
        Thu, 11 Mar 2021 07:00:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a98e:: with SMTP id s136ls318333vke.4.gmail; Thu, 11 Mar
 2021 07:00:32 -0800 (PST)
X-Received: by 2002:a1f:a692:: with SMTP id p140mr5087197vke.0.1615474832237;
        Thu, 11 Mar 2021 07:00:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615474832; cv=none;
        d=google.com; s=arc-20160816;
        b=mwJRJfEvFum2RuLiCTSOO/x0aC+XHQqWsMcxoXix1CkEgeXq3FDyV4HIwfWrtrpYXg
         FFOwEneAFZ+5ryy59iP0rJui3QwBBKrhIqhtndWVP+QOozhbx7wbggAanbtlCY/YkO4Y
         8pSuiLLuiasLWxVat7aXVnf/BfI9Qrxn/P5tKuLdX08ZN1eHNn/SB4cTDPeRVnE/TjkL
         BM6FqyDlc7kk36BnKhR1e9mFfF2vrhh/w4fIoM/sxhl/w3V8F8LYFssVCoyGzgvmdFXZ
         xy3XPvkcnHz2ZZz0MlKao3d4XTotSVOKnwq6MG5BCB4cuRHq6YLdqQIpXHkuZ7YE0sxC
         6ukw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=081PurTBMgzBP171lVVAL8RjheMX6jwXSwN2UHeKqW4=;
        b=I7o6Vw0bXt+0mwOqz4BH5MnBmRPNS5DRIAyYEBYGcHz5pxNA44VcLDWADF7cxCzyon
         trqcDkYYKWwxhWiYEktphcmGubrugqtEekhpdWan2z2nTf7tKquwa4o/CFhpbWD4Je8M
         d4g83nyjGJUM2KfBbIJj7L+bdke+oOOiJpM/jpvvhijHhHBwsyKqwmHn7hSUCgkqryQu
         VYFOLRSvFmSitzqPQonUmmImnDhHOtwimx44Ey7yu+PeZa916CEmsoc5MMue4ZPc6CEI
         XGY9vpYOg0XlS3dtb+YWqVToj6gqcHjNBmGwgI2hLOjTGIrCrb0hiVwtV7Vxo48xhZUl
         ODCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d23si181626vsq.1.2021.03.11.07.00.31
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Mar 2021 07:00:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4321C1FB;
	Thu, 11 Mar 2021 07:00:31 -0800 (PST)
Received: from [10.37.8.5] (unknown [10.37.8.5])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 54F7F3F70D;
	Thu, 11 Mar 2021 07:00:28 -0800 (PST)
Subject: Re: [PATCH v14 8/8] kselftest/arm64: Verify that TCO is enabled in
 load_unaligned_zeropad()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-9-vincenzo.frascino@arm.com>
 <20210311132509.GB30821@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <bd403b9f-bb38-a456-b176-b6fefccb711f@arm.com>
Date: Thu, 11 Mar 2021 15:00:26 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210311132509.GB30821@arm.com>
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

On 3/11/21 1:25 PM, Catalin Marinas wrote:
> On Mon, Mar 08, 2021 at 04:14:34PM +0000, Vincenzo Frascino wrote:
>> load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
>> read passed some buffer limits which may include some MTE granule with a
>> different tag.
>>
>> When MTE async mode is enable, the load operation crosses the boundaries
>> and the next granule has a different tag the PE sets the TFSR_EL1.TF1
>> bit as if an asynchronous tag fault is happened:
>>
>>  ==================================================================
>>  BUG: KASAN: invalid-access
>>  Asynchronous mode enabled: no access details available
>>
>>  CPU: 0 PID: 1 Comm: init Not tainted 5.12.0-rc1-ge1045c86620d-dirty #8
>>  Hardware name: FVP Base RevC (DT)
>>  Call trace:
>>    dump_backtrace+0x0/0x1c0
>>    show_stack+0x18/0x24
>>    dump_stack+0xcc/0x14c
>>    kasan_report_async+0x54/0x70
>>    mte_check_tfsr_el1+0x48/0x4c
>>    exit_to_user_mode+0x18/0x38
>>    finish_ret_to_user+0x4/0x15c
>>  ==================================================================
>>
>> Verify that Tag Check Override (TCO) is enabled in these functions before
>> the load and disable it afterwards to prevent this to happen.
>>
>> Note: The issue has been observed only with an MTE enabled userspace.
> 
> The above bug is all about kernel buffers. While userspace can trigger
> the relevant code paths, it should not matter whether the user has MTE
> enabled or not. Can you please confirm that you can still triggered the
> fault with kernel-mode MTE but non-MTE user-space? If not, we may have a
> bug somewhere as the two are unrelated: load_unaligned_zeropad() only
> acts on kernel buffers and are subject to the kernel MTE tag check fault
> mode.
>

I retried and you are right, it does not matter if it is a MTE or non-MTE
user-space. The issue seems to be that this test does not trigger the problem
all the times which probably lead me to the wrong conclusions.

> I don't think we should have a user-space selftest for this. The bug is
> not about a user-kernel interface, so an in-kernel test is more
> appropriate. Could we instead add this to the kasan tests and calling
> load_unaligned_zeropad() and other functions directly?
> 

I agree with you we should abandon this strategy of triggering the issue due to
my comment above. I will investigate the option of having a kasan test and try
to come up with one that calls the relevant functions directly. I would prefer
though, since the rest of the series is almost ready, to post it in a future
series. What do you think?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bd403b9f-bb38-a456-b176-b6fefccb711f%40arm.com.

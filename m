Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB455S2AAMGQEDQ4X7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 44EA32FA36C
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 15:45:08 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id i1sf15448966qtw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 06:45:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610981107; cv=pass;
        d=google.com; s=arc-20160816;
        b=H/CNBFjrpURwWFfoGmeC2RGgLwyC6O7feoDJhdDNCpo7OBpCQS4pmfr338HRJWt/wS
         FftaxrtxjWlCsWnT72bgZSl/HCFIfrSYTOKSiGMzDcYHRIR1LJEQh5r/QJfTz9yLOzfM
         hv6WYU8v/fDpoFfv8MlhRXhZx3jvhMubt3vx00iXY8rZcJWai2T5YeZ/v/VWeyWEI1iq
         2qpxuAq0XT1uKYWYV+qsmlewGkIDD1q/4PK9ttWJcI1wxxZbof6Dv/nt1vdrezI5PdFr
         Blc8QxYguIspAu9bA0NAL+q0Qm0z5FHaei2jQMKvycGcNX06M0hZ++QxTHPxNPMiO+DE
         TTLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=scpxG8I30laEGZvLAcwtGd1dIqLxP0XPv8oeQNL8yiY=;
        b=F6/aKSqISZSK1NdJaATNgE76TJbRVVnuNexq1U6l8LRex9B+k0VZP/akIVW3Yd/UrG
         uZBamukxizEa2+VS0Z0x4BFpjlfMDwtqLpB0Y4m3qtkRUsbYQOmuYNnKqCARCq0gLlUJ
         5Wh1kkW6/J5+f1qNCG9z+00WlDro++4EJl154S3pAT4NihdHKUoKRn8mEjUsVESOMCK3
         VROBs7+svjp3M2RE6V3LAR3l7nxZMmOrHeq3Swz+8zYo3f7L/mUzOa3Xedoyd2PNxuiH
         TM21+MYTRZFZfFaxVTqWU9uRjTXY2F1Y9BLXN/s2u68vcxrEyFmEpnVcI+UPPHu8+LId
         dZ1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=scpxG8I30laEGZvLAcwtGd1dIqLxP0XPv8oeQNL8yiY=;
        b=cx8qeZo+sVPkaPrc4PbpDHoehojkaTkeTA7TexghV0ITGx2Q3lZeIVciSpnRZfdTf0
         k4fjwuFz5SYbDTvXJ7IJJ0f/v9Z9CiZVE9S4/r63wSJMKbfcbvdla4tAg3yJ3R4racGa
         s5u0aQo4CqoZPqpwSCN7vmnUTyC/9u2f21mxlbsCnboHS4/8sfSH2L3sVfHUoeXZlZJx
         PRmQwQgZUCfX2MGSOhh+EHyi/3HNVze46qziPsCidAlgBEJU60ytpiZhkSGO0fcnIlgO
         Dx4p3TJT0HiLw+SM9VG+x/LodyxUX5iaqIWd5sj5w1TDmEk7BcSnVmy9f1l2WU+i4h3Z
         d6lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=scpxG8I30laEGZvLAcwtGd1dIqLxP0XPv8oeQNL8yiY=;
        b=MmamxzYVqt7ZhYIW1X/ks4bbdkOp7dw1NHzfILe6JdfGYxD3+2rXtPNjd9xV5AL5jy
         YaB81oKPwnz3ErA9kJmoEzoDyUrfCjyNV+N9Qhu2cUuCJiWNC0/93Db2EMyL0YOANk/t
         3aB6SAl47AC6+ynoujcHBjB+WgBIxKacNq4hh7gxgYF0e9I6oA8PjKxIQMtDogmT482X
         qGAQ5aoFpksXmOWRJHKtknfUBbtDi0k7PNSo7ujx6GphGg5i/HarJKKuNRO0pHePAy+I
         FUFTcY2EyeEeGLYJHy49opqLk6hzPXF7eEv+psayfJt3iZhzKn4nGhqJLBPiZQT0JhVA
         RF/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G87JzNLp7BA/hgu45uKwFYjHI40iGc4yR2pp75C0rGFOxCG4O
	X0cS1Qe0xHUuG1EI5cKhGow=
X-Google-Smtp-Source: ABdhPJxiNKWmvnuUCeySzgw1St72bs+D482/LX+vph2BrXc7RV3gPN10HhnJuTcVUze1/AW6LMl7Xw==
X-Received: by 2002:ad4:5a50:: with SMTP id ej16mr23396qvb.25.1610981107225;
        Mon, 18 Jan 2021 06:45:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a65:: with SMTP id ef5ls3782025qvb.9.gmail; Mon, 18
 Jan 2021 06:45:06 -0800 (PST)
X-Received: by 2002:ad4:4e8a:: with SMTP id dy10mr83022qvb.14.1610981106672;
        Mon, 18 Jan 2021 06:45:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610981106; cv=none;
        d=google.com; s=arc-20160816;
        b=HOImZ1+91YmGXVf3h8TSk+sirf8ruIpIXaYQXoLgD+SvyL5ySWswIDRPFin11A2gJj
         JZ5oAsBZVnYxR47qN4If2iZwfTc+qbjz6J031eM6NCiQ2hUQlyGTtw2gEqcWu071DYSR
         hC/B6NnMu5FNK0GZanZrkQTh7BL2kfPso+bOOzt+qiIsVll82xAm1x0JTW/6W3d1Feon
         TSEF6WKgI0Zwdj79gK6dlnvPkpFv02eAp7fIcFVFfkcivpRSO59F/DnXssPK6ccQArQY
         4c7lfLrfI7JqBw/HuVjhyypwbV/UNFydJ6tOIXuCVEsCEnrts4EB0Hkm+BigBFAMkAfY
         FSpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IkRXho4WnGnQLlPMenBIIC6qIVJjYjmJOuqEflSahBI=;
        b=uJ1mMaSVKJHdHGnZuj3afLdEy0IV5MuFHBtHA+zDkNahad5WpNwFwn4C8p8Bbv31qP
         rMnXNSvD0zQB8mbR7i3K7030Cxl3sACFTSGQZX3WyY/zX31+k/gU7JHVuirhOchmJrPG
         muqfTduh7tlHyEHsB44tYVzD8+QijaqCom+lu+ANJ/vtHNE7vmDm97vtrBYyDGfIbBQa
         QCCU7SOmoiaGcxxGMUV32FVGJTJX0esRveJlm87+VhHKpSQfiXDWNTqfAjVTRMvMQtn/
         E2j9vvANkEMYMOB2xNsLCuHcgj66oAKecP114hIl8k7EfVHgtiUir6DnZmKq7IpnIw35
         Rnxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j33si1715306qtd.5.2021.01.18.06.45.06
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 06:45:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 18BB81FB;
	Mon, 18 Jan 2021 06:45:06 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 03ECB3F68F;
	Mon, 18 Jan 2021 06:45:03 -0800 (PST)
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
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
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1c0577c1-bf73-2c00-b137-9f7251afd20e@arm.com>
Date: Mon, 18 Jan 2021 14:48:52 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210118141429.GC31263@C02TD0UTHF1T.local>
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

Hi Mark,

On 1/18/21 2:14 PM, Mark Rutland wrote:
> On Mon, Jan 18, 2021 at 01:37:35PM +0000, Vincenzo Frascino wrote:
>> On 1/18/21 12:57 PM, Catalin Marinas wrote:
> 
>>>> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
>>>> +		write_sysreg_s(0, SYS_TFSR_EL1);
>>>> +		isb();
>>> While in general we use ISB after a sysreg update, I haven't convinced
>>> myself it's needed here. There's no side-effect to updating this reg and
>>> a subsequent TFSR access should see the new value.
>>
>> Why there is no side-effect?
> 
> Catalin's saying that the value of TFSR_EL1 doesn't affect anything
> other than a read of TFSR_EL1, i.e. there are no indirect reads of
> TFSR_EL1 where the value has an effect, so there are no side-effects.
> 
> Looking at the ARM ARM, no synchronization is requires from a direct
> write to an indirect write (per ARM DDI 0487F.c table D13-1), so I agree
> that we don't need the ISB here so long as there are no indirect reads.
> 
> Are you aware of cases where the TFSR_EL1 value is read other than by an
> MRS? e.g. are there any cases where checks are elided if TF1 is set? If
> so, we may need the ISB to order the direct write against subsequent
> indirect reads.
> 

Thank you for the explanation. I am not aware of any case in which TFSR_EL1 is
read other then by an MRS. Based on the ARM DDI 0487F.c (J1-7626) TF0/TF1 are
always set to '1' without being accessed before. I will check with the
architects for further clarification and if this is correct I will remove the
isb() in the next version.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c0577c1-bf73-2c00-b137-9f7251afd20e%40arm.com.

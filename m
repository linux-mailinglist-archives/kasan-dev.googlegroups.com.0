Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNOO6WAAMGQEZVCJV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D15D7310D49
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:41:42 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id j14sf816259vso.17
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:41:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539702; cv=pass;
        d=google.com; s=arc-20160816;
        b=dD8iSThSXHuxk0hgD8P9pzjdFOp8iZmt1LErbkO9R991fbULR5UaOIkW8q5LvXhc4m
         1v0YnhGz/qZaTjBNVtzpPoseN3ksR+5bC4ZcSXTuNSyRSKK0vEEWT8sVwT/T5eQsztkB
         BCEZHDKynEE/6Hqidz5Q1oFAAsSIwsJxtu9AT5wBH3ClV/Gxwj+41b4NCvjsbYWTMhdp
         CdcCd9CXvnTDw1djnaQP2a/H74al2ru1meaMEYuehaJghwjUb62fn62XrUPWRH0JPi4z
         qU8a4aFD5uprzurL9F+StGitmhUx3hb0yCTtn4KCOpOeLdeRkZY0gDl4VVHNjF3Xvx17
         frKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=AosR0/G1rvyesBfdq33nejyZsLAvvrFGGw+SgaVc4dc=;
        b=m27uIZ0AmXhILwmJbWvEupQuweRPxtRyx22GrFjYgcvnk1nGOXyT+NYyBYOAUHPbOb
         1mzk5rdJZ8GW0PxvH4FUlGXNX2ckVPX8jfcSANQCO6hwPUrRFeSeLmk0e99p3g2swtUV
         T7N34wtdZoPlJJahu73XRvZGcPYuFvERWbT1bDYlePEJEigrfigQGWoyWyudp2DL31uV
         9Ynq3mNGgJ+mcgsLVnx72GBThI1dwI2IYwdXg88pYAPwhOFxPX5mNDKlfiE70ImkSdMp
         wWcwBHKphXVsVv649Kl9bXE7a6WmLIWjsBAiRzVUFXq2QmqbFHdzvsSvopgYzcOm3beN
         HuNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AosR0/G1rvyesBfdq33nejyZsLAvvrFGGw+SgaVc4dc=;
        b=MeriUXanrtzPKE/xRyU0sjwdMJDZ+GSU2AWzmP8NgK7Qsld2wGTJA+fS9u4bcQuZk/
         FobIGupYztxKUKZr8uZw6t5PmH/K9i5S+Pjv/6+9RS0tOa5UsbcGBJ4oMkd+++3emXxM
         bVAvD72KbTLUiqIU57vzGN/Y7XvPJ23kMGgoeCiVVQGrzvFQT9pVEttwbVALue5VUPMJ
         8K78nVjgou0eDUmHhg0YbFR4hgB899liY1eANQWV0+sqixcRJ+w+fguPLXGXBX+Ac0kO
         wgnERhm+F+0Ozm2RG3rxU+/BLE0ry5uKewWFriZF5vZsk6KOPRzqVXYz0OjVoc1l6Wsv
         NgvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AosR0/G1rvyesBfdq33nejyZsLAvvrFGGw+SgaVc4dc=;
        b=lrSgupcaX8BBI/NisFhR3X0fnyEZjIvLmGeoK0Uz7GzfgWg3TcECF6PGqJSnqWRf77
         p4MzB1Y5kxIPo2IfAI8hooKFXLb7jDYclFqywRzv1FObp1lQflofcQ1IqRyknUS0HBWO
         OI6YT+HgUeqTZoYDSoO+WKCVlTlnvhEGSFi630AvDxg13RldE30/Y26kpWc5x/1GKg/1
         astaZRv11BmBPq09SyDZf/pWRwG0qYANk+iFWEESZXDmZPKGGHNhSAws84Ntg5yMQeVQ
         jA1nBswyo/8FhO2oIw91wZvGmHBf+AL8QxV6kBBWRPGQm2duamq64vEhJ9Xi8Te+5b/Q
         IC2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+ROWGsClsqHZ+Lu0aRVHEfCIDouIeVc+2EuJm9aa6s+vsSU/8
	8N2NFVkT42Sv4U6xvdwlMIM=
X-Google-Smtp-Source: ABdhPJzM6dQMSrxQAxOrOip7mXXpvznC2OcU2kYsBvP0PK0Xr6/6rj3nixM+lS/9R6vcUVRPXkD+rw==
X-Received: by 2002:a67:2742:: with SMTP id n63mr3496329vsn.1.1612539701934;
        Fri, 05 Feb 2021 07:41:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f515:: with SMTP id u21ls1214298vsn.2.gmail; Fri, 05 Feb
 2021 07:41:41 -0800 (PST)
X-Received: by 2002:a67:b445:: with SMTP id c5mr3252006vsm.19.1612539701433;
        Fri, 05 Feb 2021 07:41:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539701; cv=none;
        d=google.com; s=arc-20160816;
        b=AIhtyYL745uxJWa/hopOBB0o8LWiWjUhSyYWpBezHjbBVurRmOhDOwUv42JygkBmCT
         sTPwwL6xHovcvotYlGVjqwuyflarzNiwjQCEQiC/qEZjP8P3qchVEMl/xuB0D2mQ6iL4
         4jsHfNGi7fxt4MePy19p1ECIcSQzCh/DBE6/GWX6uhn5EGXEXNRfhToOdYHPYsSmKVX7
         g39Ky3Tit7El1TQ+5r2WZMr5YCoARDf9PpM8yoBtQR9zRJ23IAjnDD+1sbHx8RIJtUYc
         00xCS3YAEDjkQ0/LP2Tb3MplhR8w1PJ9ZGaQdawSG9uXu2Fw6+3zDLpIBq43IMimqLUB
         C0Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=uZ/qrhycLkN7VM3vllGXgo3WpCa3EVWvSzk7b9DFk+g=;
        b=r7U2AOtWdxxsaCK2gajP/JWJW4UkjCg1HmlSEJ4KFD/kylVHy6Rzx+9XbUBeeoSKvR
         I4/7/WzS7wTDc0FE+VujOHy2aNyOV+u6ds+aC47vtrswgz7cp2n2NCsqiFzfnJlVjszz
         5hQU0Hf9uhRrkAEYLXrQmG2nSDcEqBLJ9zVZgkfW6BdDG843KcHKk/Ee1DCyP9UPQOLh
         9KgSV+Iz8GEIhlvt1NtIswu8biNhDOkxq/vKQXkLi7kyhUpnnexb3h+zKIHA1+zy3DUP
         9S6GkVE9mCUXjYSq+Fx6QBrq5Z/7Q2tdenHpSbibSTg3rwcBiZ32IOH9ykijcKINIm6G
         y0TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t185si104235vkb.0.2021.02.05.07.41.41
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Feb 2021 07:41:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9BA67106F;
	Fri,  5 Feb 2021 07:41:40 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4765D3F719;
	Fri,  5 Feb 2021 07:41:38 -0800 (PST)
Subject: Re: [PATCH v11 4/5] arm64: mte: Enable async tag check fault
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-5-vincenzo.frascino@arm.com>
 <20210205153918.GA12697@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1254c150-599c-d39d-3b83-8af4f3c403ee@arm.com>
Date: Fri, 5 Feb 2021 15:45:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210205153918.GA12697@gaia>
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



On 2/5/21 3:39 PM, Catalin Marinas wrote:
> On Sat, Jan 30, 2021 at 04:52:24PM +0000, Vincenzo Frascino wrote:
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 92078e1eb627..7763ac1f2917 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -182,6 +182,37 @@ bool mte_report_once(void)
>>  	return READ_ONCE(report_fault_once);
>>  }
>>  
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +void mte_check_tfsr_el1(void)
>> +{
>> +	u64 tfsr_el1;
>> +
>> +	if (!system_supports_mte())
>> +		return;
>> +
>> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
>> +
>> +	/*
>> +	 * The kernel should never trigger an asynchronous fault on a
>> +	 * TTBR0 address, so we should never see TF0 set.
>> +	 * For futexes we disable checks via PSTATE.TCO.
>> +	 */
>> +	WARN_ONCE(tfsr_el1 & SYS_TFSR_EL1_TF0,
>> +		  "Kernel async tag fault on TTBR0 address");
> 
> Sorry, I got confused when I suggested this warning. If the user is
> running in async mode, the TFSR_EL1.TF0 bit may be set by
> copy_mount_options(), strncpy_from_user() which rely on an actual fault
> happening (not the case with asynchronous where only a bit is set). With
> the user MTE support, we never report asynchronous faults caused by the
> kernel on user addresses as we can't easily track them. So this warning
> may be triggered on correctly functioning kernel/user.
> 

No issue, I will re-post removing the WARN_ONCE().

>> +
>> +	if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
>> +		/*
>> +		 * Note: isb() is not required after this direct write
>> +		 * because there is no indirect read subsequent to it
>> +		 * (per ARM DDI 0487F.c table D13-1).
>> +		 */
>> +		write_sysreg_s(0, SYS_TFSR_EL1);
> 
> Zeroing the whole register is still fine, we don't care about the TF0
> bit anyway.
> 
>> +
>> +		kasan_report_async();
>> +	}
>> +}
>> +#endif
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1254c150-599c-d39d-3b83-8af4f3c403ee%40arm.com.

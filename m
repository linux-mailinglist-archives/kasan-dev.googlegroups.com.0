Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBFXNUSNQMGQEGHM2NHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 693B861FA4E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Nov 2022 17:47:19 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id m34-20020a05600c3b2200b003cf549cb32bsf8703552wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Nov 2022 08:47:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667839639; cv=pass;
        d=google.com; s=arc-20160816;
        b=u4l3pooEulkfyl0lMYSLC0eJ+OiwuiPazVGu4vqqqHLhBBtw3HnZ7ReN/vEL5u/iZt
         03Q0K4B74D+rri6jfFqurCkmblfPYWeaUAfyf2V7I0AkNAkbJCLjnLi4S7FD+AhIDABL
         VHsST/BWcpHfG7f/LziIoslnBwh8VaPFTe1ndElDloOQ8lvsgjHW5kr4Fa6yeUOx2yex
         h2BmhGS6SPt6n08UCsoz2gnYToXvwJFgkfiEjyqQd7h5PcrBCH79mIpWOnW0DDDh5dpq
         gcDWmAvJTahn/uAiEMOjmsD0/XUDLen/87YWG71Emc9OKNpl/hijEOObk7nKjBZySBGp
         H03Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NpAq9dFbWuCCh7dTGIaIkpMBcauZYYeQhm7oO1/p3/o=;
        b=wM2wcm1p2OGdtNMq1A4TL+QGAg+aNb+8oJd2c6oUBZSbCskRQrQ6mYn8smbdQ9+hr4
         H3BreElz9PfHLqxOGSzwN9UXAi22TKW0jKGvX2XGgj76jNPF/VOjKb5pJ7K3Yd6+PspS
         a+kE/3/K9ZHupxI5HZYYWzngTqPrYVoqfk0kg3z12H7kkkY0kOkTUbQEuf+pS4dcZuB9
         Vw8WawD+NH0x5HjlTp/Z/qUzBWCOujkil1dUHjr5h2WIsDCiVTbyb1J/QfRMa4nkhNOr
         hWXemFHic5HhkerVsT2jVW36/U/A/8PoxNXQwdl27sdAs2c1YT/qhS7d7Q0MB+fpHMJp
         V1MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NpAq9dFbWuCCh7dTGIaIkpMBcauZYYeQhm7oO1/p3/o=;
        b=BfOWfuw6wELLLT5+cdfoTgZ5gHHWNWi6NKKg+KmwNtQ8B/xv+PZdSKVFPKByOB0lZd
         3km2sD7IXuKBWHFwgJvCQSQOMLNxcEaEKcBmMX2k2MjChuQMI0HdZwDQ6MyhUs1THSkf
         fJn73Hyu0U5Qnaseri3Y2P/O0P7macMj2lZpV3dpjBtIXhJxOUbCnewhN8Ll/QPPT+7/
         sq3ex6GYKWkcBt3df9RYe9Z358ugLgyCribgmclyc40wG7C7+Tg6qEK9eAt8/QwQx23t
         Znav9WKvE98+wfrBFbt8RXK7jiYi3G1V0OOlHlO86IkqCMZe1vMOq54AgwK6BuiKUFkD
         qS3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NpAq9dFbWuCCh7dTGIaIkpMBcauZYYeQhm7oO1/p3/o=;
        b=YVNRnwUS5ZE60gDAmDklZVNFs3fxviFccSHv6256j/dvopxmuLip0rG8PtpFTCeO/I
         Im4GZrODoFUQWdJARjqUK7gGe++CtzbLAGlmSnsOPjPHvmWB708n3IX0l0nB6KjBNRJK
         /Yt9ZC5ZcatQear720UatoP/bFWFsdg2PuyL9eo7qIOF2y81XN3NREcGOmdUZl7psd8R
         //3/t2/KjyQDto1RsX0rbVJ52juvKUEfP+pRlwqaRIEyOkqpSxuq+N5AzAO0YaY6E3H7
         bBkRyAKmguAPs02YfRGJ+FH+r6NbJCJD8vIIT0IdhVR4Kb/B48LzQexC7+pX7mr5smEM
         ANAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0BNXc8zTdOz8b8ggLCmj8S4QDR6Wb3L/+Gf5VtTRuwFBM0Dp9K
	FwISYaaD+c0+b7YZvqzYa84=
X-Google-Smtp-Source: AMsMyM4+huTfy/mHFoPcnMWZ+JOsOezgX4wioDn5SJMlKHzPGcrpnsiv7HkZHBZlRYMM5Ne+S1JyBg==
X-Received: by 2002:a05:600c:5563:b0:3cf:857e:18c0 with SMTP id ja3-20020a05600c556300b003cf857e18c0mr20905257wmb.24.1667839638757;
        Mon, 07 Nov 2022 08:47:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:238:b0:22c:d34e:768c with SMTP id
 l24-20020a056000023800b0022cd34e768cls6145541wrz.0.-pod-prod-gmail; Mon, 07
 Nov 2022 08:47:17 -0800 (PST)
X-Received: by 2002:a5d:40d1:0:b0:236:786d:611e with SMTP id b17-20020a5d40d1000000b00236786d611emr33156171wrq.355.1667839637690;
        Mon, 07 Nov 2022 08:47:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667839637; cv=none;
        d=google.com; s=arc-20160816;
        b=IPUULS1cXQntdynCfN6KnIWAz1EjK8hzhnok4iS21CRG1KcaLf4Y25BTsqfrd5TrZb
         lyy+97/+4NyFcvags07UGVTEoybzdb4qdfx/C149Q10XbZq9AWNyKh+9QmNIu857r2ir
         ZYK1vMvxrpRbr9OfZ5qeIX5FHVolbRMRsd5iNitNLy8TuJXARCfo21Zvj8NOL+S3pjIN
         pnkeQtxTL+VukkXkstQJosv+ar6kptriA0AbVpwz/gR1rwWmhmhhfts2K1qK/nSzZRJH
         14hLUVUhpzkA4Qw1xmRvASf0Y+r758xyvXUuXXqUZ1lz+o297qQ94qG/k9s1iaQDPF/s
         B9zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=eTFs2ZLrMMsrsgkKuWIBmiYw45aE/+Pg6bch7N/FgvI=;
        b=u1sV491pVZv0dflxYSLUbIcdfHM880F23yoe3YoBLrGdIBEIAxk0d7bKvZ2fDJz1VA
         yZePUHKjy3dJwzfOR3jsHWefu4stMXWmEABlQjSJBJgxQHpSDhWvpvavDa/ICxaHN79O
         NEgpoQHKMiYpj/ZjXxtSdiA14kFLn+1FFBLVLeOEvxKHnJ4RFDGUroymZ75oSx08lo1z
         NJuXDHmu6pg+RHUtBjbST1EB9gyU/2wDB7JOvjN9V/10CuQtrnYA6Jbr1UWU6S+PFP6F
         PRscb5ZuShdi0MikR/gjGTZJnw02JkeYKwWT+x1rpMSHOu1mODegW4WC+K6Bfi6pTWK5
         QJXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id by9-20020a056000098900b00239778ccf84si250753wrb.2.2022.11.07.08.47.17
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Nov 2022 08:47:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F0A191FB;
	Mon,  7 Nov 2022 08:47:22 -0800 (PST)
Received: from [10.57.36.248] (unknown [10.57.36.248])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 132AA3F534;
	Mon,  7 Nov 2022 08:47:15 -0800 (PST)
Message-ID: <e1d857df-7b6b-113f-1bed-2b5274d887c1@arm.com>
Date: Mon, 7 Nov 2022 16:47:14 +0000
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Content-Language: en-US
To: Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
 <20221107151929.GB21002@willie-the-truck>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <20221107151929.GB21002@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
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

Hi Will,

On 11/7/22 15:19, Will Deacon wrote:
> On Wed, Sep 07, 2022 at 12:00:15PM +0100, Vincenzo Frascino wrote:
>> When the kernel is entered on aarch64, the MTE allocation tags are in an
>> UNKNOWN state.
>>
>> With MTE enabled, the tags are initialized:
>>  - When a page is allocated and the user maps it with PROT_MTE.
>>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
>>
>> If the tag pool is zeroed by the hardware at reset, it makes it
>> difficult to track potential places where the initialization of the
>> tags was missed.
>>
>> This can be observed under QEMU for aarch64, which initializes the MTE
>> allocation tags to zero.
>>
>> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
>> places where the initialization of the tags was missed.
>>
>> This is done introducing a new kernel command line parameter
>> "mte.tags_init" that enables the debug option.
>>
>> Note: The proposed solution should be considered a debug option because
>> it might have performance impact on large machines at boot.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
>>  1 file changed, 47 insertions(+)
> 
> I don't really see the point in this change -- who is going to use this
> option?
> 

I think this option can be useful to someone who is trying to debug a problem
that is related to a missed tag initialization and it is doing it on QEMU.

QEMU by default would mask this class of problems because it initializes to zero
the tags at "reset" (which is a valid UNKNOWN STATE according to the architecture).

I noticed this behavior because I was trying to debug a similar issue which I
was able to reproduce only on FVP.

Said that, I originally posted this patch as RFC back in April this year to find
out if someone else would find it useful, in fact my idea was to keep it locally.

Please let me know what do you want to do.

> Will

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e1d857df-7b6b-113f-1bed-2b5274d887c1%40arm.com.

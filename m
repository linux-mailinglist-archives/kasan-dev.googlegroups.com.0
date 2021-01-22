Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCHKVKAAMGQEHTZESLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A35A2300157
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 12:20:41 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id x11sf2389759oog.9
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 03:20:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611314440; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLO24xWRllWCEH9TyE2gESjBxwlzbLmNxxAk4qa2WTK5rdLzsp6lR9XhRZUUODOJWg
         sfig54E25/QRTOOKiNq45GW1keF7jEcJIaLHfEE3qBYx/5+3CnyQZd2G6tuEz+TRSfSi
         led2I2EAU5jUDuTXIthfiVK6iOmpJeBODc3Yde6e4NfxdQFkQvkoklRRSCLNzc1i99oO
         Ze6igvn+AnSEq0sC7ZqMumBQZErQirJe2Zw7FviOZzNvYsebARXqmpbRQSM4AEA26csH
         +b1u9Ue5LCtoQkqNrryDsvXKcra7sBpISc08BOi+bJ12qKp/EuszXOUCUzbkTP+OMK4s
         WPYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=DPrbeqMXfxaY5BLEIzDGskq4CKCRXQDRLmvYFZjig/w=;
        b=LrR12Ar9WIknj62tGFeXiGU4l2SltBh94Yd8z33Sb3bE9wW/Lz4EJBfHQPTIQVplZL
         NObA2kDlMgRVj7te015i+L8fGnNjwhL8/j2WVMB/TEuYkZLNTZZNLL2TCJXnj2CBRYQP
         igzq0V3kjwFSQq6jvphjwxK4RyPZ9Ni67Eimgtnyad023Qk+EuOFA5FG1x/q6YIrVXey
         v+7jU9hzA9ZumLtqc7gEnGSOkrmmUbYEQ5L1mrMmkxfj1vzWCvF4SrZbck6kxlB6oGj8
         n9XdGRlJMsWWVO8CWYHmaRk8cSZDmUxnRQpjzdAXcL4SipShhbEmRTOF7GiqZ/L3hQpA
         lLKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DPrbeqMXfxaY5BLEIzDGskq4CKCRXQDRLmvYFZjig/w=;
        b=r8+cGxPyLu1C9z23YiItH9NJI/eKJ3YzuSm3uFzj+WjmcEQBWCiDUjbv6etV/z7M2E
         gywX/kd6ZvuXUNPUbFL7aaMuwYqbogpvez0RcbY5D2cCVQBImyp3gzRE5uz90Pgc3spp
         b+0Fqs0vSOuatFbZYdWJpRnSZrDFri5trs6L1Svlsr4VX+s5lQByWpb+fdIuYq9EzXq1
         vGYGFWEjYTaIxu9WYIbGGWW/uszHLZYV6TQgrl+H5tE55zUf/NQ0cWmH6ZVmDl/XEozU
         D/oFvdB174U7NqyX5horywnIJgi8q9Iuhhnq6lvjSxAGD8xUw25wKpWCwYLLwfmT4uvl
         ouiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DPrbeqMXfxaY5BLEIzDGskq4CKCRXQDRLmvYFZjig/w=;
        b=tUJm0n0L68Ipf6Y2Ep6yCT5qzprS04tY/lGoJ4vD0+sw1+RccTaOTz5Lg02Sp8RCKP
         9vjOxj7FO6gNjPtODV2/3rBQ3ihvO1kTCsW9L7WdkBr90cl8/4e0k0KU1zJJ1vMJE62A
         5OLMVfdcy7+A7czh4Hz6rzRAo30gPr7G4CNN1MEDEz5JyofEDIWPl08VJCfYNkMvlbLb
         0J8X0D8Rj3BEW59oasxHuwpokvHIrdX6cyv4pe4RXZX8pTqR07kEDTSnAJdMwsdMVb2l
         G/zfiTJ22UwKGFnbmG4r24fqm4k28GbkPLm+fSZ+ntU7VPTzIxP4jFb471ijEk+Mm1J0
         PZCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533UpiG32ttHD9SoNfdQIHRXzXb2XX5HYqC0kXq1/HTOyKabpIkR
	9iga5+SnAdME+pbLYIwOqbY=
X-Google-Smtp-Source: ABdhPJzoTUXEPR/pXP9mvTDvSazxk+dhEBdgE8vBrqWl+yGvlEDI9WrFKrf754sCNJ1yUHZzitbhwQ==
X-Received: by 2002:aca:fd81:: with SMTP id b123mr2848308oii.159.1611314440538;
        Fri, 22 Jan 2021 03:20:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:52c5:: with SMTP id g188ls1193639oib.8.gmail; Fri, 22
 Jan 2021 03:20:40 -0800 (PST)
X-Received: by 2002:aca:cf50:: with SMTP id f77mr2874865oig.172.1611314440158;
        Fri, 22 Jan 2021 03:20:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611314440; cv=none;
        d=google.com; s=arc-20160816;
        b=jzJ8tJfXmBd29R3BdLeeipx83hFydAxU0PQT+cvLESXQsedZ9qwlh9FVtIkOnUqtHY
         D4ICrellwDN6d74FvDrE5ws7Ms3WBt3Ir5KHEbl8sRcaez9dzlRGAXnesBjUD9tcXfgF
         d2p4NfLI/OhJ71ZhEoNPiu46AbvDJG9UBNGls8geWQCm6lrjHEdEVNc3ZhuSS3kv8KDi
         gO5WTPJvraqHNdlOw6guS5GTMGAs3q985qBZfMgMPAnX7jqcdXrZnHfhZGW8IrZcB6Kk
         6g5i8HwHnnLU5UzDQG+cyzD9P1Rv9Tsnod0XVstTja5c+7JZZN9YPJ83s9fU9LQrJ/fX
         52tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IZvV1WoT0llZHg3GtA7H/p4Sc56e+8LvZ36yfqYWijY=;
        b=KDumHZPSAOKw3zyozxq6ZFSQY8BvM7PY+4Qg9l5DKWqjphiTuLRMeeYVwjn6dNQF9+
         VEaBrhm0fh/+c9fHYlZDo0KTqbCfp2Vz0BpjjIcOvUuKzfUwJQ4XtdPHq78NSABUMQug
         hohBCaQVAGcN5nIzSQTrSg3pM/mhnVZaYSRK91UkWShefpLXFq7EnRMU4ffOtQXziS04
         48nyIc+WGsldKZgHw3VC+SnrCqmNxEJJ8hmu8ANHiv5UobWmAzRnGCfNLKd8ZUvvbxQL
         6qaxR8SYsSV5NrqDWdHJXbAXrxfoHrWKutMpSZYHNsVSkWt9rwZb+E6XSZD1qJXAb/sM
         r0ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a33si475293ooj.2.2021.01.22.03.20.40
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 03:20:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C691911D4;
	Fri, 22 Jan 2021 03:20:39 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D45203F719;
	Fri, 22 Jan 2021 03:20:37 -0800 (PST)
Subject: Re: [PATCH v5 4/6] arm64: mte: Enable async tag check fault
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-5-vincenzo.frascino@arm.com>
 <CAAeHK+y9HbV6yVJ0f819Y=_6ijkKq06rqJSY+mh4NF4qd8t_oA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <04eba2be-641b-ee23-7fa0-436c33168cd8@arm.com>
Date: Fri, 22 Jan 2021 11:24:28 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+y9HbV6yVJ0f819Y=_6ijkKq06rqJSY+mh4NF4qd8t_oA@mail.gmail.com>
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



On 1/21/21 5:38 PM, Andrey Konovalov wrote:
>> +       if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
>> +               /*
>> +                * Note: isb() is not required after this direct write
>> +                * because there is no indirect read subsequent to it
>> +                * (per ARM DDI 0487F.c table D13-1).
>> +                */
>> +               write_sysreg_s(0, SYS_TFSR_EL1);
>> +
>> +               kasan_report_async();
> Do we need a static bool reported like in do_tag_recovery() here?
> 

I would say not because async mode does not get disabled after the first fault.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/04eba2be-641b-ee23-7fa0-436c33168cd8%40arm.com.

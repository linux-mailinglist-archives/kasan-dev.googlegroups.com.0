Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4VBZL6QKGQESYZBHRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 663192B462F
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 15:47:15 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id i67sf11782794pgc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 06:47:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605538034; cv=pass;
        d=google.com; s=arc-20160816;
        b=dcEKVofDuWF4/tJB9OP2Y4Ez1BBBNpHveB5jY8NGFVevGg+cEnSA6nQQq2+e3oSaNI
         Ih/SyrKdktgPJyzjT2d+eq94TW6BazO/G7H9D8qphb8tDdwUVldH2L9J3EOPwE9zF+LE
         aHBNjWdBwhC/0GV8QEtaw0gsWjClqXQi4FAh8TrG79Vs1c25Z7FnBhS+ja8oTy2HNCN0
         jdLuJmyAebd5g6haqYPHs7uYQ1Vpp9HAlpYsRHlhfwHyxb2r+8bb+S17PpYCwBifIMAP
         L5MfZmWNvqlFurDR3tfVCPnT+FNVQt23xRRgIHDCKNt8EzteicoPcCEaMT2dRQfKir7Z
         hHJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=UgIPXmlU9jpA6BdTZJT9U8pQciFMomp4fEWJFlX9tuo=;
        b=Kp5EuuzgPznr5e2VoBop9w4YwhXR0PbpOFsp6/jQkzW5WSBvt9jtPUO1W+OkhOFsVf
         3e5RN61l/97l4WmyINFj3HCCeNtQFc4lMebHWLSDSEJsQBgiF3pFhKhGPF9TSnzHzMeW
         /FjKvCofm7SPsSkbaWmVYDAotSlKrvOB1eynLytBLxUzZThiy+bfjLGKXbz8YKuQi6IX
         yZPNECrelt4IodG+rjMu3mhfgOplrAV+E4RpIWqi65E9RKSn+WsNPY6dw1pd+Ld7+w6P
         0jZMHyUaZOzQoagNUVbXmHCsh4XzNNXMPZZ94J0qxmApyxLwArl8iQh9UFtCF8H+kMqw
         WK2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UgIPXmlU9jpA6BdTZJT9U8pQciFMomp4fEWJFlX9tuo=;
        b=JRZJCKhHBzC3UDBfLTAF6T1unPCQ346KYpK2KHz5d+r/XOb+BK6d5iTlf/sHtH177R
         KPUxK+EEvQnu9SBZebfoMQCOZnNZOZIJADv7MFRmU0fNtvZnyYN5UF4+nJtviKjH3mjt
         TsyZoxqvy5w64D5JkScyF6AVNoxehSLMlhBmTKOHKG8sxPNND5LoaT6BKa9BFodTK5Pl
         wzcfDZmSbErtwLKJmgdIpOCHXWGBXXsVl3rhw+kQBonI9tnzI+EA9ZreSM2hoOha0ZRf
         BNA9n0sWtVMnPwT5rCW+mMYfghkoSGSqmX2E5DwIyEgJ/iGjQiF5+EC/jpw05X6IuQqW
         pvcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UgIPXmlU9jpA6BdTZJT9U8pQciFMomp4fEWJFlX9tuo=;
        b=PzFYo15a8HiKBITlMFxDuh87tXIxYz14jg+ZLSn67ZDNj8rc+nsWoGVmCs6eyDCssK
         00P8bXsXkGyyPUDrqUdQulTNXuYctCMhs3psappdp+KPZlJXIDUVvgtu2Hq+aCeAn40b
         qjvUAKm6OYTA/UWMt0DgFgQ1cWVb/vqM2YYL0/Bm+nZYSmBafMq79lVDTFEMB+Vjmo0x
         ewazV8F9e/ZjEIw7UewKtyn1Uqjxj9WwHICSOt6mKB8ssKGecfwMaTGXXbo7k1Svg+Nv
         dtD/fCdgLelW4+dmYA06EIV/XzP2UHRhy3A9i4fvErHyPkTz3Alp8uvkdeJqg94UUovx
         6ROg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MV5uB2gkPENOJqlYutfg2WaiDDRbrruvqab3WAXqR7H1Lt7d4
	PYa2HrMAedlOofXfF8F1H9M=
X-Google-Smtp-Source: ABdhPJysj/MBSxnnH+/zl953EdsnR3dOvua2Kp70MgpyBQ1gQDZLQIGgCiHN77pUv2sqfJgpQI+VeA==
X-Received: by 2002:a63:e24:: with SMTP id d36mr13137958pgl.373.1605538034117;
        Mon, 16 Nov 2020 06:47:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8f0c:: with SMTP id n12ls5097465pfd.8.gmail; Mon, 16 Nov
 2020 06:47:13 -0800 (PST)
X-Received: by 2002:a65:6a55:: with SMTP id o21mr13454621pgu.141.1605538033641;
        Mon, 16 Nov 2020 06:47:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605538033; cv=none;
        d=google.com; s=arc-20160816;
        b=PtCB+QyHCZlEFtPUrpj+nPHRu3szaeviKPkZzLQ4u05esKftdkxBxWJr8BWCcrdsbx
         WcQGRL8cRB9wLADGo9WYGpPQL19NcWvUsMfPVOcjkz/xQWF4eTJ0ng8bdIRZB+Hpq9Ww
         lJgb60dEIuiWeoUKEbOdNpmOM1wpjST1W87U+4oV2tToppYMwsUS5VA3/7JgTNm1yxeA
         NahJ83Xl/2YiOQBhSUXiMiz0LoDgkWhK6SgRbBdmia8Fh9lMDeKPFvfB/gmTqqe6y4iY
         Sxs9LhR6Y8JOWN2uKDjIxLzix1y0jXn4K9lQT7C6MQ2iPjXWCFjbZD/4AuMXzGfv5GQL
         KfQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=1emDtQc6m4Hyd1rNbCWiESFJ5eUY8+5ZUeF9euVNBzk=;
        b=sE5Gem/YolnXQxKgw5bEeHw+WaJL62cTDyn63113V4LPysTtaYdIp5hb3YqMdH0c4Y
         /CGUNqJM6Ws2Zgd5RUxwVnQvG0QCvKFP/UZjJXV+gERnbi48pRmAFakB2to3rcKHxOaK
         0zlZ/dMyx6b9so9zYGODhgsnGgXEIfF/TEmrEg9j0oWIiNXNdSxwJIWgaiFuAsBrYHgr
         7mD780OQFgJGjSXQR/WNnvBaJfTf91xrb/DsR5K0U3szE5JsLEXnj8Fec+PDjgI83RT7
         AKfk9skQB2h6p4+me1H2vVq1PFe2sbKdcmyp55ZNlYJhWZ+c/T8cvWd7CNGoC6FtRvef
         b6aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x24si1064121pll.5.2020.11.16.06.47.13
        for <kasan-dev@googlegroups.com>;
        Mon, 16 Nov 2020 06:47:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D3E9831B;
	Mon, 16 Nov 2020 06:47:12 -0800 (PST)
Received: from [10.37.12.42] (unknown [10.37.12.42])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CDD253F718;
	Mon, 16 Nov 2020 06:47:09 -0800 (PST)
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with
 CONFIG_KASAN_STACK
To: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Alexander Potapenko
 <glider@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>,
 Serban Constantinescu <serbanc@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova
 <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
References: <cover.1603372719.git.andreyknvl@google.com>
 <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
 <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
 <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
 <X7Jthb9D5Ekq93sS@trantor>
 <CACT4Y+ZubLBEiGZOVyptB4RPf=3Qr570GN+JBpSmaeEvHWQB5g@mail.gmail.com>
 <9d4156e6-ec4f-a742-a44e-f38bf7fa9ba9@arm.com>
 <CAAeHK+xb4w1XSe_cXeV77d3VkHq6ABAKkKuEaFN-uFVY457-Ww@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ea105e7f-44a6-b6e3-fac4-73f057e9226f@arm.com>
Date: Mon, 16 Nov 2020 14:50:17 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xb4w1XSe_cXeV77d3VkHq6ABAKkKuEaFN-uFVY457-Ww@mail.gmail.com>
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

On 11/16/20 1:50 PM, Andrey Konovalov wrote:
> Fixing this sounds like a good idea, but perhaps not as a part of this
> series, to not overinflate it even further.
> 
> I've filed a bug for this: https://bugzilla.kernel.org/show_bug.cgi?id=210221

Fine by me.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ea105e7f-44a6-b6e3-fac4-73f057e9226f%40arm.com.

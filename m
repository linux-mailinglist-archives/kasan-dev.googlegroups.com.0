Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQ6JTGAQMGQEEYMDHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A88319D35
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:21:40 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id bc13sf6136658qvb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 03:21:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613128900; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q1Iaq33sjEx/Tx1wvheyouM9HUJNH+JE3LNYyUtVM/lfAAbYbKkVRbqjpHBBFAGTSX
         TXCu7WmkuqSyuO/3MsrxuNxwQo+M67ZsptW2MfwgsBeUmzkl3dxSuzDOx6kimC96/SsN
         6gxSqlww0HPy2+9mI68vHNCNgxUdnmHkF1V6thrHGGDnKoVfNw+VSCQnkzB0LqnKwm6T
         qzeupeb0mCXC21r7GxuKDPHEfnF31/f6fDyJOlDU87s2ITy6cTS5FFsUAJvS5x55YJ4g
         iZB66Z8500B8mvMvK+93ZAFtAjBMhOgqZjhfTfdhiD51hCGdP9SBs0S95SjNHuhVGZFV
         PGvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=CLqhPbiJV5X9ASdr24JrjPP+9u16g/7RQl98rVG6hjU=;
        b=PpHC9R84r5KT4ZAy+2y0xnN8d7RnLqLNn186T8ZwiZTzCjATz8wNeEbujUtq1fwrM8
         ElU9WXkRrYbq0vPzEFPT7rHNZVHNOEiSIApbk4ARwZhX+AqiYI8UV+8rHPaBch7mdl7J
         vdzWoBR6WXNNSLbJDcy+fpqil3rfx9iHyn8Qx1NXjQK5TFSQazR2R/7yNhu8kZugqHHn
         yp/gleqxUCTZuwl5skBYNJhMfwYghL2sqBdV0o8/BIvVPuQY2neVgJY7vMWxlvlVondr
         edrmFL+9cwqAL/yuQfJPdZd6l+2dY7tIl94gb0ouyoMUTLuPmPSXzqhTgSIScnRKM+Pa
         qF/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CLqhPbiJV5X9ASdr24JrjPP+9u16g/7RQl98rVG6hjU=;
        b=K9VbyQQxKdwvY1177zyVtshGwY55OMrzpRVeZu+fhqsiNEqpT9Dv+1W9+OqeOgS/0D
         R96nuUwWzGlPfVwWjGrNeqUK6lsfzcxB1V+BCndt464EHrvmN9FYSEXsLcOcZvzKQeat
         /xnDXO3MaVZ5Pjsecnv6So4tQ0E5Y3d8k/UtBOlYk9zWq7dqeHPg6GQuQnmySO+cUXRj
         9B5hQSxOPH4WUWrh54jbxFH4yAArFkyMokU2CFMlRZfs1P+J2T9QbWQ9mw8mDgDfIcTJ
         UTNmuTjvv69eOhKpj8Acs1l+0fV9tKRpQ5V0rgX92wq1xToAHtXQI4Ouy7NReLWUu25r
         2ArQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CLqhPbiJV5X9ASdr24JrjPP+9u16g/7RQl98rVG6hjU=;
        b=tAtO0UKlX4ZZ063yPRAtbzKqTMm+HT/TNF7rLtznOEUECkW+9emC34snRknABWSYrq
         AM/Ftks8dBImdnljsy3bnZFkn957KJ1EtQLmEIgSb+5XDh1HxZPx59Y4Q1lvyoopMmBH
         mVYPGH7eVNWpNLJoP+BBT4WZihCvN5S9HyTAeTXanTtfoR07NY9c1MU+pduFZLhC/2h3
         6YGWYs8wVD2dFiRSxxTfQnD/eQgH8vcXoMKh3J6p2YdTAf63ATjq3XwZcvE02q6g0amY
         lqL8g54OQhUB5og7dNmFm0PNGQRs8d5o7eVRkCj9BLWYqbw+Z0IeDvF2fRkh+Ne5ZwPo
         R07w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yD6/RAb4Gm2dLhCzUTc+VbWlew1Wfh3RJ2P81Y/ChvHu1trA1
	6Z8Gs764c9VtLDOq6AYVbmI=
X-Google-Smtp-Source: ABdhPJxGvCCjetp89H3BLvMAom86b4mqgROaSHXm9Fsmo7wVHTRB5rmmoFqrRY9MGum6odQcYnCJMQ==
X-Received: by 2002:a37:78d:: with SMTP id 135mr2176359qkh.472.1613128899879;
        Fri, 12 Feb 2021 03:21:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:d0:: with SMTP id d16ls3126263qtg.11.gmail; Fri, 12 Feb
 2021 03:21:38 -0800 (PST)
X-Received: by 2002:ac8:6716:: with SMTP id e22mr1862139qtp.117.1613128898077;
        Fri, 12 Feb 2021 03:21:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613128898; cv=none;
        d=google.com; s=arc-20160816;
        b=nbT839+RgcXssxnRIxpbDuUrM1HuQKG7OI+88EMLnLjO6RiI3N9I9U/lcx7ExE+D+8
         ifbO43Tl+r8hx/IK96GGpvEwfUmeude1ZAAeKOgvgFfbf9bdKpVVOCF9Oa1wVCRQQ23/
         NIOGOai9GN5plZ04x18p3HcYyMn/nGKf0CtTdngmBQVlv8M3n8JMjri7MbAsdBKx00QB
         h+8Xx9aqZk/kW/iuSY5GPTCQmfF0GgODEz+IM8IeR5g1lVk6CVnbwHv3wK07ndA/dyK/
         arMwh0Ezs9odyoZrgu+RLk7AxX89D8RwzvxqolBhGChXE8NGpXF99GJh2/sGrzrst1aW
         m4sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=kvmvosOYzC6Mhv4NpRwlwmCj2XlQkQawnfrqIsZb8EY=;
        b=fNvasrSsj4yvGTZEGM/fxpXbGMUfB+mjaMpE9WNo8VzzeTId1qqq1hD5HnMKXWJjD/
         qrXzg2L6nEmUStrZEZvIoveUc4JzhjJ+knBzCyqEnjfUzghvS3lE1txL+I094SW+47N7
         j3o82sxNCw9Wu2uZj3BXFQx6J1KYdueqqUuZB2lC6Ahg0bIGbuBmHYM7ZTAEyZ1yQz2Q
         Ivpv6tuSURvEuUUe7vwl2NVBrSk1GicsoundplVarQg6wC217J0sHr6LBwYDjaxnNDQC
         LmR20zxzrHta3uZYgnPNzQBmynAS4rR+GTmk+FH+O0BFtXyqSQ6BMemd6AjyHh10o5MA
         s/1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x65si531220qkb.2.2021.02.12.03.21.38
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Feb 2021 03:21:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2594D113E;
	Fri, 12 Feb 2021 03:21:37 -0800 (PST)
Received: from [10.37.8.13] (unknown [10.37.8.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D593A3F719;
	Fri, 12 Feb 2021 03:21:34 -0800 (PST)
Subject: Re: [PATCH v13 3/7] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 kbuild-all@lists.01.org, Andrew Morton <akpm@linux-foundation.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, kernel test robot <lkp@intel.com>
References: <20210211153353.29094-4-vincenzo.frascino@arm.com>
 <202102120313.OhKsJZ59-lkp@intel.com>
 <CAAeHK+yB4GLCn2Xu4z7FRLNOkVDFr0xXN3-D34BdJbRmWLpSxA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <23dcb10a-7fc2-375d-2234-49f48461a612@arm.com>
Date: Fri, 12 Feb 2021 11:25:39 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yB4GLCn2Xu4z7FRLNOkVDFr0xXN3-D34BdJbRmWLpSxA@mail.gmail.com>
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

Hi Andrey,

On 2/11/21 8:13 PM, Andrey Konovalov wrote:
>>>> riscv64-linux-ld: report.c:(.text+0x5c4): undefined reference to `kasan_flag_async'
> Let's do something like this (untested):
> 
> https://github.com/xairy/linux/commit/91354d34b30ceedbc1b6417f1ff253de90618a97

Could you reproduce this? I tried yesterday before posting the patches and my
conclusion was that kbuild robot is testing on the wrong tree.

I give it another go today, if you have more details based on your testing feel
free to share.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23dcb10a-7fc2-375d-2234-49f48461a612%40arm.com.

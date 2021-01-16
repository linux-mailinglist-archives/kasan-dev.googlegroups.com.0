Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBGYROAAMGQEVMKCDMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 285772F8D6E
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 14:37:10 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id v187sf10014397ybv.21
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 05:37:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610804228; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HHOGhRXBzcYLMO0TioAAPXgHHUU0Lr8WnnyU9iAFFOjdZybKZ5E6t+yMbbjitqz+X
         I1/5S8u7tcS8tzZaVflvDjjXtrXGcnpK1ikr+A1TsY3e7nIW1MkYA8uFb2YsywPElpd9
         MS9x3zvN6YaWema4YWxAs51bFd+XLgs8Feri6XRUedgxXqln89GgPQy6L1P6VAnWhuHD
         PI5vtIAzW0iGu5F/9+Z2LBfvPRBvbbOMkZMoolBaKTammW0+yERa6MKpnA1ItiYr1aGM
         rHnYmoTX9YzK3VVSgsObjS6KxaxWTkQblvcJZcueL464dgMUIMgbYJ+rqpfCPRLP5R8Q
         DmTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=tJs8YWRPIg9rTZtQYZRn9fzxb7tMTgGjurOh2B84qWw=;
        b=K8JXyTgIiwpq2/T6YY/x3826n5dvO0IMQ90UcqAYhrCYlWbb2F0II79hUIQ7PTiKId
         0cGlbt6DPB0ynIQ7oWu2YzWO5wX1wnsGusiBm09ZZrj7f7TtYD5Ewn6bCCM5uqv/qcQ/
         7vCd4bfic+/jjoCPHGmqGYX6Lm4GPWFO1z2iloafqNzasftVidq+b9uk/RY03ugiVhFl
         k/VJUTQp1X29mjd6BP7QjlGlXuPSWM12IFVdm/CQh6pgyPDnhCaDf8YcTerDYVJXnDlI
         8KGLpOr6eAH+CgKRKDbtTyqm94mLK0R+Utl4eIRIoPAl72+csXrkZ4J3AtConrzofvU6
         A71A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tJs8YWRPIg9rTZtQYZRn9fzxb7tMTgGjurOh2B84qWw=;
        b=D5t38WmC0H/w/apgILJYx3CPOR9D1YWFLKTAnB6bW2LFHW7E5plF4dJhPln6hFMcEZ
         CWZ6WxEi8YIh0GVJSkDWv4hlcdD64Dd0B3tvUBjbQzU9YYF+vZLa669D22HJSGidLpZ/
         giWlW6McWCBsCJoXase8PNGorSXKtGCOtObnSKv7MygmC24coOqRccUdX5jwqxm8Spza
         18s2SbSXsSyF4Pc3cnv6nUgGka4P52MCrHx916OtDrL1Yn5OFAvFJv/kKIVKNobqLvev
         NRmPryT9Pzz5LGKtjETOVABBAIdEead40RalpntBkDIP3tMEPZJKmaPcc1K5PSkchmcQ
         Yy4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tJs8YWRPIg9rTZtQYZRn9fzxb7tMTgGjurOh2B84qWw=;
        b=Njn5JnccKJrqXEak0PS8JSH4NMvz6SWQgaj+g/8bnW4W6ue9qoceG8iKW16qmDYehf
         gtPvd1/fEZzTI0H6dxqKQgO5fQMJ2R08ZT5S+rtbMQ01erbQvhMy0eXDjmIMzGD7n57q
         OEGC/rmGPDLPXChkfkX+P6XGumFVA0PhgJqlLxVy8AwitHsGsa86CGg5OmCc902AI8do
         J1EDQz5S/MIc07rcrKdRxbqAJlAgCTuwD0ftZlsb12Xp2EglWCx648r7StQnL38Vfyk/
         emHiwEHPTv3A3oqdIbK0x8j1cIWA1KH+KMZLIqtZdYUkLqf8JZS7byY6YUzSjx0nf0Ml
         JSMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333O3rSJeH73+YkwAQXvdwDl4yOkmooz+wklc6cGMsko8k2Lphy
	jrcXI88pt8YdSJQrKxCZXlM=
X-Google-Smtp-Source: ABdhPJzt6OctSI35L7mtMa8gv0AEhL90YQCwLsefoVzUwfw2qOw8hdV2leb1GWv5k3+VsID4ps0tdQ==
X-Received: by 2002:a25:880a:: with SMTP id c10mr24769670ybl.456.1610804228728;
        Sat, 16 Jan 2021 05:37:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ff19:: with SMTP id c25ls5859096ybe.2.gmail; Sat, 16 Jan
 2021 05:37:08 -0800 (PST)
X-Received: by 2002:a05:6902:6c8:: with SMTP id m8mr24594962ybt.398.1610804228260;
        Sat, 16 Jan 2021 05:37:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610804228; cv=none;
        d=google.com; s=arc-20160816;
        b=j2vs3fYVPMRd9Itdb5wkS1SyeK7GU+ghhKW89s73KqqA9lDDpveXzXb/ptlnxdqefi
         2VX+RhawJEPCdhhEwrL1ZypOQhl2p78Hh8N+aK8nlagIDj9IR49pKPncFbMrvNysoPNp
         6vH7dWmwd/QJQBIRyqYpgCflHxEZr5EuZ1g6v4yJVlNYAShoKyQE8OWFs4EM9Lrpupo6
         +kZo53wIHEH7V5PzwdT8LxTGom6CrOYS5AqKzdJAUmQE6Pvo5jw16GWkowhicbJqrqef
         PcMruajxLwlGw8qCWg6bRJkFZNZoE3mB26dOgQeQZ2D2H1IFzsF5fmMHYdmZznpKazcY
         Ezig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=wsKKsLuNszRxFYRtrbIeCMZ+qtCKx7lJRr49hJfc9r4=;
        b=uXGaTZneRNZlV1XR1NGol4u/K8g1e1sD1awDKNP0u9HfJRtXRwqTuQxW/Io6kAqtV3
         zMZZQ309RtkXxzE7fLG941jEh8+3NOZa0kIe7ztuu19/Hyyv3oTcKkplI+rzZaB9j05+
         gllvFjIPBvLkEGvyd9yJsyePrfkKpx6Vtsa3ucm2udGUpYs/yAMQ2/8TV9Krqz9zpwWd
         lG8wibKkrTlL9dbc1xKhx31BKq+taqr7puyjw0Hq1QFO7QzJ+JftpB9sSoWP/l0PDx6Q
         D+Kx6aTmmU+y7+qtAC8wGafnmLd1zfmL0NjOg9d972EMVYu1pmshUMoR963/A9LPWq0Q
         ff/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r12si1103824ybc.3.2021.01.16.05.37.08
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 05:37:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 689B9D6E;
	Sat, 16 Jan 2021 05:37:07 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7595D3F719;
	Sat, 16 Jan 2021 05:37:05 -0800 (PST)
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com>
 <CAAeHK+xt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <4335128b-60bf-a5c4-ddb5-154500cc4a22@arm.com>
Date: Sat, 16 Jan 2021 13:40:52 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA@mail.gmail.com>
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

On 1/15/21 6:59 PM, Andrey Konovalov wrote:
> On Fri, Jan 15, 2021 at 1:00 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>

[...]
>> @@ -60,6 +61,8 @@ static int __init early_kasan_mode(char *arg)
>>
>>         if (!strcmp(arg, "off"))
>>                 kasan_arg_mode = KASAN_ARG_MODE_OFF;
>> +       else if (!strcmp(arg, "light"))
>> +               kasan_arg_mode = KASAN_ARG_MODE_LIGHT;
> 
> Hi Vincenzo,
> 
> I've just mailed the change to KASAN parameters [1] as discussed, so
> we should use a standalone parameter here (kasan.trap?).
> 
> Thanks!
> 
> [1] https://lkml.org/lkml/2021/1/15/1242
> 

Thanks for this. I will have a look into it today. In the meantime, could you
please elaborate a bit more on kasan.trap?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4335128b-60bf-a5c4-ddb5-154500cc4a22%40arm.com.

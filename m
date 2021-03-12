Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBC4CV2BAMGQEX5NBJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 95804339071
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:56:12 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id u5sf18280072qkj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615560971; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sb8A8edhWUDWpb/41VwszLBywj+pUbv1fppS4LGbfChe8FJffoTsa1XspWGfjZBu7p
         2yiFJr21rkzX4zskn1OhZSnsHxFtxrsKKo34B7/xxfRgHKp0XVD+5fdc2/XnSVgMrbd9
         Z4xQu4T7rY9VBO7sclLMD4uuwNcSbULp8O9Ul4mA2vcgm+18sLzSxV01CzB/LmGTxfHj
         SBkAHIruf4gPceDleT2j55uTImGHwlTkStfnj07E6v1u7a3DObHiYa/QBb2xFCm9AWgp
         0/KFA7zg1WGeVcnfF5IpKbtldMBJqOOZtJV1sroI1N3aiWwLva7mubD9MkLbZn1mmK/B
         Grew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=kwDuMtP37Xm+DSx2TDUOm5pnsrSkZ6FLfxOZG1TzX3M=;
        b=ltptxG83RxgYeCX7xF50ieGKuXz1D8Sqi97ah+zsF+LlGeM4j8e6eNqKZEABuh8AxH
         v6uTD9iNZ0eSeSv/rP4nJQUtMZJxQr2SMMheeXuzItqMbGCGb5qzIpLm+XWgYj0ADdTN
         1yJvxeTYDh1RS3gnkdsdHvxW9ylg+z96q/HbObeidnBg1MHLNc1O7DXdPJNtKzKm1G0+
         rI62GhH/H5W1BQP3KhuiMf4G+h4qdVhZZQ2BrtV7YKULP/W7sQ1+rcgicNye+zoWGULU
         Su+KuyjAaSnojTtFDkYKnpPeqAuLmdD2oeoUY14wCtmBmW4MV9jbrUihYz3lFfvi9oTL
         5NCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kwDuMtP37Xm+DSx2TDUOm5pnsrSkZ6FLfxOZG1TzX3M=;
        b=FqXLA4QkX80nzkmfoDYrc+JOJxOobVbWvKSfrYFAOfm9CVAAhkbPU09bUujeLmHmVl
         IuP+kFZLhFj2osm4D/GpAEnNOpApwXu3YcpvEZlb3hOY9wGn3AyZQejM8iBJRYfIW916
         BDBy5HKW4mIfj/SVfnoyBtKne3Pk9BUUVYYW/iPDUm3NiY4q4S3ILP9l9E8PPur4thVw
         tJVR6O5uX9iussOqNUSAz0qXcNKkbForJgfrBpPCuqsVeuNmDxbyz7mLebL3nIKdXE2D
         XQV/FzGxM4mZyyJu/ycNYyEOnA+s+1OvenG6a9q9/fPxS6040WYUFnUx+bjRtFx5V72E
         /bRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kwDuMtP37Xm+DSx2TDUOm5pnsrSkZ6FLfxOZG1TzX3M=;
        b=nfqCNJmCxdFnRT1nWukUPjW4EpXXf2LDqrXHrvM7++ctyKmED21EdDGW2jgIrFBBFY
         DjIiecg2JipS342UhUJhCgfsU+Qm1Ooua4Ed5zq9TXK6EZee4voNMcI9bJ//+7x+DijT
         X62h6NwYvqdLpCZwhk4zkTmJDPQwJHz2j7JD07851msIXl5QSKOI0RYTAmeG/gmBj1wU
         n12SkyeB/L/i2vOE3ZwqXdXP2+90myO8Lu+fRfGoAjef4kWHNJoTgqBRwzZqIxbzUva4
         Gw2CCrj2ZIxNQvcP7b9TJH9sO93oM+fTRLin6p5kUHhN5/TyevN6RgBtGIgyESynkwHG
         Rq3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531r4OH0W/MwnqTPQrofPR86K299cZczYtgZY4HImYNYSw44aEq1
	ZVqy73JcbzpvdsOVfYl3zSo=
X-Google-Smtp-Source: ABdhPJyXhhunMcdG6QoAoGsZUi5ZB1JQhXjgi0xl70lJagDaA9wJwJVb6WHx0CRb6sqBo7JhEKbI9w==
X-Received: by 2002:a0c:fa48:: with SMTP id k8mr12528456qvo.19.1615560971694;
        Fri, 12 Mar 2021 06:56:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:a98:: with SMTP id v24ls4988588qkg.6.gmail; Fri, 12
 Mar 2021 06:56:11 -0800 (PST)
X-Received: by 2002:a37:e315:: with SMTP id y21mr12945546qki.418.1615560971283;
        Fri, 12 Mar 2021 06:56:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615560971; cv=none;
        d=google.com; s=arc-20160816;
        b=KrRrLxwdmES1oSvdfyUeitBRMyapH74/JSZ/U6boSYtzjdnxC7u3at62lITgjZU0vP
         DApPy/EZLy3amYmEujUp6RAqP4u9sW4uhf+D+1/0UGD769GcbzImN63Tl2PXo5tlAhB6
         Df2SFq7we8wqwzpCoWAwzcGwj9dzr+xn1jAIjqrDyi13FQFuIO/mkZZv5FJaJ8Ulqr8B
         LFk3o9oiKWQDCJrR0r+XXCvw00RqGUPS1tTNBu6m91qLZMSBa4dYvB8XO0LWTAgTLzIG
         0p8PSafTSYVKpr3Vzb6ssIhrh7YbGRJ2ysLz8hYU0zwhwp5+Ax2gOc/gtfQ81nRx0t3n
         AGiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=DfVm+tUKlnM+pK6tJKCAmAxXIe+fdfUhbcASVjNpXrg=;
        b=EpZ/b2HFyrBTfC69Xl00+Do75J6nwNAe3WNLuMgWa2f5RvhJtVH5LbG5W4Hg4h0+JL
         1jZV+dvzRR6FPlyph3VsTqEEsGkHSqbwPhZtlfvMyO0g4ZzSM89IU3O8DM+02okF9Jgj
         8Js5eZJsKrwOUB7yCIqf/OYyo5WyhbIjpdTw03/v71pfXHSso9DGojtd5sTHYZ/ChVxH
         nh1DtajquSkIa547r+VReoaPGycfunKG1NqVZViEld1PdgCc0UjekUaZMO+sm04JyHjA
         0e8fs11ngKUjMwrMNC8Aa6rfTK7drNDyP8V5XMjt2MkBFJQ0TPsnxOC0nAv18OQX0P+N
         /XVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b4si429343qkh.2.2021.03.12.06.56.11
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:56:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EE5171FB;
	Fri, 12 Mar 2021 06:56:10 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F0B0A3F7D7;
	Fri, 12 Mar 2021 06:56:08 -0800 (PST)
Subject: Re: [PATCH v15 8/8] kasan, arm64: tests supports for HW_TAGS async
 mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <20210312142210.21326-9-vincenzo.frascino@arm.com>
 <CAAeHK+yoeLfkztNCifJuZooBwe+9np98ch50-ToOGKi1swC1vw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <8da687d6-9aa3-f419-0efe-b460c3ef3952@arm.com>
Date: Fri, 12 Mar 2021 14:56:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yoeLfkztNCifJuZooBwe+9np98ch50-ToOGKi1swC1vw@mail.gmail.com>
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



On 3/12/21 2:49 PM, Andrey Konovalov wrote:
> On Fri, Mar 12, 2021 at 3:22 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> From: Andrey Konovalov <andreyknvl@google.com>
>>
>> This change adds KASAN-KUnit tests support for the async HW_TAGS mode.
>>
>> In async mode, tag fault aren't being generated synchronously when a
>> bad access happens, but are instead explicitly checked for by the kernel.
>>
>> As each KASAN-KUnit test expect a fault to happen before the test is over,
>> check for faults as a part of the test handler.
>>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> I believe this needs your Signed-off-by as well, Vincenzo.
> 

Ah yes, in case I do not need to repost:

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8da687d6-9aa3-f419-0efe-b460c3ef3952%40arm.com.

Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBB6CVOAAMGQEFZLQ2EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4F730055D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:28:24 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id h13sf3909642qvo.18
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611325703; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQXDolrEuPFNNo4Gv+HsMIsstvmibmqJ5eySzumDjL+XVDoRYobsq050OdQZ4+2s/e
         FnbGjEbNXmbXBRdlyzRQ7sPGhwp4xjF/PtulKM3j7096HeiEiZHe4buc87D9M/sDKUDZ
         gRxppiwkZIQIrP8WUBE2K5Ts2y9OEdFoJoqGwCV0vsZvDVj85pg2r2/eFIuBr5MrQLl/
         jK0VSIzV98c6shEDsuh8vFzYvG06L7GnQax0sp6oV6B8nWzWl3vIr9r3mdZ8iAPJYWsm
         8uQMt969Uy19z87UynsNIpneBP0ZWDF3UNi4N3AWcNB+MiObvqGP7IYpQWzRWNKbc2Vf
         v0Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wTZK7tOBGyaZybRF8ewRcqUtseiHwvTQ18Rce3uR8Mo=;
        b=lpLl82Nwg6Tc6sSRZ1HrUsFTeBB6NL33ncbJeqwyG6ck65T+WfYtvXbJg9FHfgAbI+
         a8gy9DbjJEv3fGU0jz5YxQkFLFJ9iYzJgREbTPugUg1PuHfgHOV+uA9/ini4QbjZZs4R
         SX9fZcX55Z/C9p9MVqdejsQ1O6UeVCuuBEc3R5VUUTEHy09x0X74b9NPZst6GCveN3Mk
         CcFO0zu3ZXuHk5Zl2VfoKicpeMEFN4azu6C/k9G02AJufpQl7WpcV7Yt50alfAx/nMOr
         ZL36uqyAIJ3v/AU5jR+o+V9Xz/kZ3IE8cDlPw0cTfk8tX38c2YOhn5+YrlXjc9ETG5Mb
         hmKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wTZK7tOBGyaZybRF8ewRcqUtseiHwvTQ18Rce3uR8Mo=;
        b=DKEVoU8QaM0dbt/rSHiDDDA/fsfx/KIeCsnZyTZJPHZ1fy/xGL0E4xul1xqRHgn01+
         Il2yYaoZzgCubeBrVvxjpig8woGEOpIfb/Hfz04VjlG6OBWe22n5U1Ut7hSflx/GI3qA
         NtqtbY8aVtDAfszkIQ4uAkbTuzHZ/n7+qmIL+pN3W1z4MmBW8ZntV4FlxFEurBlhLyHg
         8DLVnSKc9F+6x9UmUpiVykArbzYOoMwBguDUSO/Q0noLWxDAnsbOC2SNPJmQOJAcXPkp
         6/87qRbYg4vL8WvYa08UelTXcFBpqe/fETLS+LiLl7RvY9CZyRCZzDdWFPvgjFWqsZow
         p9Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wTZK7tOBGyaZybRF8ewRcqUtseiHwvTQ18Rce3uR8Mo=;
        b=gD2TlEdUBscpm/vNyWZNgxbQb4yfIfNIMuilrGdrNBn6TqB91UwpfYaXEN+/LKba+C
         MxVDjZgfaglWmmKsGUzYU/UkKKuozMYwgP/A6LlIZ5k8tQl8irMWDTHnMbR+7Ofq+m5u
         QFtJ5PjLq9+f48JR2Y7EpEwL2VWFlV8WCEHckgXGH3xzZFfLJknkAdngyNGAMN8jSwxL
         6ah9/iAZZdrvqfak2kG1x/aVdlIYpHmQY/ZJujMk+1mMESbN+fcAb+giqwzOU4F3u09w
         +oWnv7/ktxyoTlkdYU9HnKosBR9/tas/FpfPXk5tmJlnlhojBLZMQ+IU8ZyB85h/izMg
         RNjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530s8HoUdUvg/6Qd1a8CCDKizbYyAHpscHxmnJmK0eXly+S6BG0T
	lONZ69SEpKmMxaN3LhZ0f+c=
X-Google-Smtp-Source: ABdhPJyPoEv+EyrLpom4RE3Br/0G8FyeXpJZANoH86nL/akgBpHxBhGkRn3xwwpIOEn2kv8Y8sRr8Q==
X-Received: by 2002:a0c:ac44:: with SMTP id m4mr4752817qvb.45.1611325703769;
        Fri, 22 Jan 2021 06:28:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a511:: with SMTP id o17ls2889840qke.8.gmail; Fri, 22 Jan
 2021 06:28:23 -0800 (PST)
X-Received: by 2002:a37:4fc4:: with SMTP id d187mr5081441qkb.200.1611325703365;
        Fri, 22 Jan 2021 06:28:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611325703; cv=none;
        d=google.com; s=arc-20160816;
        b=TcGIWrGDATNDNxBxQgui71kc0bkxK0e52bzLMt4UbYTYm58XMuxn/ap9tu2Psby3CS
         iM9GlrA9Jv3TW31Tu0ij+3Aw0vAgUUhryd2cvpBC7Jmm+4pSmhzZ//DjKZdY/Khqffqx
         zliJOSdICsE1xIGj2+XbdMN1RhuQr3IMz+adpnMlEbm3H9bJAxM4EuC3qaScCUf+KP3c
         CWkqtmcXVTpyzqQkct8dAu58U2/J6M69Orna2gaXYz7t17P4JI9WksGwtjf3H9PEdyUM
         9fTfTKe56PLAbcSWpxV7U2AQcdoDeDtFGWNbu6XGkF5H+XBBfZV/sM+P+CQeraHuvxKS
         izNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Rs6ONQGXFnDFrg0A7quRYS8OV4oEEv/xa1aJTQlZ0ns=;
        b=QRsLnCMt+yu/dUt56TWagymGLtW0RfWgv7z+oA++aYj4Ye8hu+pAtgSgRrWekU7YOf
         hM9tc2iZxf8iz6gN3DaO6RAkknd4OFaimmA0779653rT68sYWrSepAeNe9kMpf9EPzYB
         SF8ku1f3jpWpF1YNzAQZisb3f3xiQJaKgSemhWa77t7pGFdzcVwARopym73iuAdPJtGz
         JtE45OUyxPhmJCgkFYN9aUALGSxp516iJVHqYPkX2W3oU1OpHwRVLwH7NJLN7/ewnx57
         v3aSbMRSicvendHaBrZLws+ea46HQN4tGMLAMXLWCMQsLnIdfN05mgrRxklIIVrQSJTx
         REuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t2si502519qkg.0.2021.01.22.06.28.23
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:28:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A8B4F11B3;
	Fri, 22 Jan 2021 06:28:22 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 642503F66E;
	Fri, 22 Jan 2021 06:28:20 -0800 (PST)
Subject: Re: [PATCH v2 2/2] kasan: Add explicit preconditions to
 kasan_report()
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
 <20210121131956.23246-3-vincenzo.frascino@arm.com>
 <CAAeHK+yCq+p-D8C+LgHUSkuGZmZscJPTan9p6GT8GoUAVdnOqA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <b9b3f3dc-e091-0718-8b5c-47801c74fb2f@arm.com>
Date: Fri, 22 Jan 2021 14:32:11 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yCq+p-D8C+LgHUSkuGZmZscJPTan9p6GT8GoUAVdnOqA@mail.gmail.com>
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

All done. Reposting shortly. Thank you!

On 1/21/21 5:20 PM, Andrey Konovalov wrote:
> And please move this to include/kasan/kasan.h.

I guess you meant include/linux/kasan.h.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b9b3f3dc-e091-0718-8b5c-47801c74fb2f%40arm.com.

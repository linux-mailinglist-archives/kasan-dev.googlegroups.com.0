Return-Path: <kasan-dev+bncBC5L5P75YUERBVU42XVAKGQEWDITRVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B3468EB66
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 14:21:43 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id i10sf1366667edv.14
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 05:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565871702; cv=pass;
        d=google.com; s=arc-20160816;
        b=qhhHHUV2BNHJ4sY4dlXhgB/gcTcoeLAeh4+8axWhQNIBLgSqmZhwbSasecrIPQLxcz
         20UBs3jWxhs3azZlfNj/UaL3q/kZv/eOHlsNL4USWSCkKeedKCpKWd4T0VZpUG2GLecQ
         V/wc9lg/M4DLIsKNOAoECRYK1IFGa4CXtInEL1wsxCl2Yo7bNNTTqxmdlmhuZlsmRl6X
         oKXls52AE7cL9vfMjB+fmY82q3Hd6SYHF4k6gnQ5StfV2slArK7rqDSKIAixhPIEwYmZ
         K28E/LiKzFi0yuo+MtIq0uPqBBEzM3h4j/1UiWR6pcEtpVgQxInNu0PtZbvFhXCqDrlX
         Eq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=6jbihbwZvMo0jsYCeaf+q+0B7uRit/hrtQtCqG4FOtY=;
        b=T+8nkD+W0DLwqSeePQ6Rj3zjE0QN2SX7D7shI2qR0bP+tjHmsH+yzk7bHGn1L/i3C9
         HRfWGYvzlo+1+BAQJoFrRykaGubvHNA272YXUKjtGUM8QwtbFkg5umPTjrLZCHNjR4oG
         ZLfRhdQQ52dry/gdolJDiiz8XcNb4f3gV8lBmypbdBz5ZmYpjMFh96wMboXbA/92ebl6
         oDoad8QwoxE+/ucQ4hLvXD/frZcp68mSodY7MNXfYz6CnpU4GXEp7s4fK21+BdRaGXPj
         iq1np+8Yd8/F+LI9bJVWpQtZlBVceLZDjLQqZA/mydnR2gKP4fypxmXfISpcPKwEMU+O
         rLhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jbihbwZvMo0jsYCeaf+q+0B7uRit/hrtQtCqG4FOtY=;
        b=ITTuUZEjGj6d4KbhFvnuni7HqXnsh7Hek4SFJ7ArDPcl2rCrU6ZHr5+KwTms/MbiDp
         W86Y5/lD6cwFbLS3DECi2dkscHbax8S79G66USCYp2ybFT7SisVY3OPNjTgeLZTP+DFt
         gWIygK0PC48npYFuA4diJ+9Kp8efH/KJGuKh4IDffx4DIRCbYm/C4z+FH77IjbYiOXTu
         aeOchQtGYl7ioh9/VRNjwiDhdAJTAhZJdMV41i6u56ofk5ioJOqSRDN7bI4fBE9G07VI
         +KRz4XOsO7JEKhntgAw0bfzjl+LgVxorUMZA8G0XXvmzokXkyDebQOlGamYqeS6ApwSR
         1fJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6jbihbwZvMo0jsYCeaf+q+0B7uRit/hrtQtCqG4FOtY=;
        b=GClhfP8cqsyA9iKAvBf2txe9HklTUBDjhsjTjPNTAkW//iSBQXJJNW48kBSomPtRzS
         ko2Ft7L86giOMCxDHvjTocdRahooiO2EatwDKlRogLB0k36XfPMpEW1HNNl6Q5grFvxo
         ixmLK03YpGYi4rEbD21Ee93OlNlntNMIhjVabgtt1kTjXF0aqtYKbcKqcQYlPGGnJ4k5
         2ABGS2QanCnN25z3FSpXuUu7AFgrKf1lTMQYB4RbmtGfxX9qPsfIKNdF2yd+BFYzSxoB
         Y1U6tPieFtYsfup7tRKE5jDzK+XkthsticSCRhwBSRqe3T1ZTaxpXiwMjgFHI40b3Xe6
         y0ZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWXldWWGYgFUuXvXa46OkXX20KF+CSXG2SLGPYFlyigpHw7eRzD
	JMGKP337GdA1L9z6XvbO4xA=
X-Google-Smtp-Source: APXvYqxWgRuajf50XoVsnNyX/XpvDuMfp/MhAlmA9GrY1ZdH6Rf++q+NtxpZktHnQoW5Tikve3vJMw==
X-Received: by 2002:a17:906:1599:: with SMTP id k25mr4051917ejd.281.1565871702778;
        Thu, 15 Aug 2019 05:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6a07:: with SMTP id o7ls1165309ejr.9.gmail; Thu, 15
 Aug 2019 05:21:42 -0700 (PDT)
X-Received: by 2002:a17:906:c669:: with SMTP id ew9mr4190089ejb.217.1565871702390;
        Thu, 15 Aug 2019 05:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565871702; cv=none;
        d=google.com; s=arc-20160816;
        b=BZDyP7YvuYcCEwFcpdksXQgHayn9a6yDU1tixzuQA8I5f21w30qMdhFJ/lceatZO/0
         IsbjfOpaUxQWrzye+YDlEzpKLZ5HUfa9gq6OLJAmzV2SJCba47k9ls+3XhKfyRdIgk4b
         5dx4XpC+Rk4ywgFVhBin2fjCWwzJ5G58wlLtm+1odK414ZAWpc9zb2TXxpDCJ57vID0h
         B5JE0A5XYTb6MGzmfQl3CqvDROpRixtCwlF/OYxJrklO9VmmHn81vggYsZNsM2VbzMEw
         VPTiSN1zUVDt8DYD/oKHST9NDuR9gO2awcrHx0O0IoWIDX1Ytqk2c3QR9ORLr52V8c/Q
         voVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=I8B6KWcybqBws4OWk78XG2cKtfqM90vDzUBWR6Mzk6I=;
        b=lKVPKs2aQxaN3G2d4J//39+tDakZm3716N+xZkQy9FOVP3jOApTq9GWCEtK3d6d9uW
         MR6dYDhYANrlNkNPiichocwjXDnnhGk0F0ELAOZcFODJaE/I8cePF5mBg9tnQtbZDKgk
         c1xBKAqBfv4OLSwDRyGuE6vJh57Jqv0+DeZ17Mo2GSSPCAzlPjID0USF09nm3R+6a/kh
         /JerPGUiSfaRQ1lienTWa3O9R4Qx5RVGoyvEvbLR5N25pziJMohMWGRwVbq5fw+FrcGC
         Ltd5JxMpdxUu8YkTWocikhEizuZE2p7khM71FM1A6bWfjF0Vu3Pea+ClYs7t7+tmpicG
         EG9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id m16si147737edv.2.2019.08.15.05.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Aug 2019 05:21:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hyEl8-000665-26; Thu, 15 Aug 2019 15:21:38 +0300
Subject: Re: [PATCH] arm64: fix CONFIG_KASAN_SW_TAGS && CONFIG_KASAN_INLINE
To: Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Cc: Steve Capper <steve.capper@arm.com>,
 linux-arm-kernel@lists.infradead.org, crecklin@redhat.com,
 ard.biesheuvel@linaro.org, catalin.marinas@arm.com, bhsharma@redhat.com,
 maz@kernel.org, glider@google.com, dvyukov@google.com,
 kasan-dev@googlegroups.com
References: <20190807155524.5112-1-steve.capper@arm.com>
 <20190807155524.5112-4-steve.capper@arm.com>
 <20190814152017.GD51963@lakrids.cambridge.arm.com>
 <20190814155711.ldwot7ezrrqjlswc@willie-the-truck>
 <20190814160324.GE51963@lakrids.cambridge.arm.com>
 <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <8e472cf5-21d1-be9e-9e47-ec40e35b3192@virtuozzo.com>
Date: Thu, 15 Aug 2019 15:21:48 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

On 8/15/19 3:09 PM, Will Deacon wrote:

> On Wed, Aug 14, 2019 at 05:03:24PM +0100, Mark Rutland wrote:
>> From ecdf60051a850f817d98f84ae9011afa2311b8f1 Mon Sep 17 00:00:00 2001
>> From: Mark Rutland <mark.rutland@arm.com>
>> Date: Wed, 14 Aug 2019 15:31:57 +0100
>> Subject: [PATCH] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
>>
>> The generic Makefile.kasan propagates CONFIG_KASAN_SHADOW_OFFSET into
>> KASAN_SHADOW_OFFSET, but only does so for CONFIG_KASAN_GENERIC.
>>
>> Since commit:
>>
>>   6bd1d0be0e97936d ("arm64: kasan: Switch to using KASAN_SHADOW_OFFSET")
>>
>> ... arm64 defines CONFIG_KASAN_SHADOW_OFFSET in Kconfig rather than
>> defining KASAN_SHADOW_OFFSET in a Makefile. Thus, if
>> CONFIG_KASAN_SW_TAGS && KASAN_INLINE are selected, we get build time
>> splats due to KASAN_SHADOW_OFFSET not being set:
>>
>> | [mark@lakrids:~/src/linux]% usellvm 8.0.1 usekorg 8.1.0  make ARCH=arm64 CROSS_COMPILE=aarch64-linux- CC=clang
>> | scripts/kconfig/conf  --syncconfig Kconfig
>> |   CC      scripts/mod/empty.o
>> | clang (LLVM option parsing): for the -hwasan-mapping-offset option: '' value invalid for uint argument!
>> | scripts/Makefile.build:273: recipe for target 'scripts/mod/empty.o' failed
>> | make[1]: *** [scripts/mod/empty.o] Error 1
>> | Makefile:1123: recipe for target 'prepare0' failed
>> | make: *** [prepare0] Error 2
>>
>> Let's fix this by always propagating CONFIG_KASAN_SHADOW_OFFSET into
>> KASAN_SHADOW_OFFSET if CONFIG_KASAN is selected, moving the existing
>> common definition of +CFLAGS_KASAN_NOSANITIZE to the top of
>> Makefile.kasan.
>>
>> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Steve Capper <steve.capper@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> ---


Acked-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8e472cf5-21d1-be9e-9e47-ec40e35b3192%40virtuozzo.com.

Return-Path: <kasan-dev+bncBAABBS7WV7UQKGQELYI443I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id AC839682C4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2019 06:04:29 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id a5sf7751797pla.3
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jul 2019 21:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563163468; cv=pass;
        d=google.com; s=arc-20160816;
        b=l3OHpu4NE0ixfdf2C1IxHAQuzpnwFM0Gt+foQUoxkTQAvByw8kOg6ZHKvo9H30BuLp
         Z5QQv2hBzxx0NdEwwnAYh7iKNrBdXycxj1xUqlQBM2A5W6KCpp5suyqgcC8BjP7tpbRJ
         PNVcgUBineYi4gYh1NQZFNPckxgZ8VvUcqY+CnTlRGl2fo7vCQrzhFbJoIC+Mf9tkcGr
         w0+3jeQTUXQPDUy8CRU9MlfAZ8S6LIKyQ/FQA7KctLU9p/iVIg7jDnpGRZBwu4MUFga8
         1Cs+oF/iKL2Am/kDT+DTjeYuYw6iPm09srFupQy0IbdXgd+ijo5GDZW20WTYGxkj7WCr
         YwpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:sender:dkim-signature;
        bh=h35AHHiIjDL7qgAA2TMJP7Z4O480waxqmvLIEo/GZVw=;
        b=y/5MqehmR6poqJf6KIDFTOkWEG7EIyjZknLQUCYa5i6aSqGGAB0+5PfTB7H7zY5CXC
         PQFa3F6HSVBWGxN0/36FaRFoPadsOgKvoIwi3dnIKZAZe+hLWfsNq9KCvbRs3lhOjG1l
         jNy0hC2RHEK1TcSWlbFtGZDz/hCi4jDX7Mb5Sgr7w4AIKpgjadB6tejWmd143tSpYmgG
         P7BNDD67GKtCgh1nIJvIAtyC2vTXlBWOa+xZ7qFvTirbmFal6uJ1iCLVg7Yp4c1+5JH1
         wG5Y4doR5zLnAqh8ebkXSB09OehyAinfBjRCSV29TOSfJaV396EozQbEjbmtztnKDjTq
         D0mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liuwenliang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liuwenliang@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h35AHHiIjDL7qgAA2TMJP7Z4O480waxqmvLIEo/GZVw=;
        b=aEuwpEZFHbPPbgnXrrOgk/43v7Cd2j2VSkJpjo0Q/Ak9zGbrniqQlAWBvIUhVEuJ7Y
         iBx8ln8MO9OoZZzpXhRuWZR7Nm4U5QxtKzBKVhqnAzHjlFg27iln1EwbABmixlPgmmQO
         hlhxKG2+/sp5NXbqYTaS4EjpTU6WHe7e3rBUy1kUmSm2jTdaIpsGuio209idTfdmp2kX
         bh7X0jxdAyO/xUxnEJLrTphXa+sIyfgsKpYnusWFjr94rAwywYd8tH+LmQ6yJjt8peJa
         gAtbaSF0IJ+iWZZ2YbnBWiitzD/a5ulT/dPvITDItYTHy2PPAZjY6pPaea7PFBfmUhRP
         V7Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h35AHHiIjDL7qgAA2TMJP7Z4O480waxqmvLIEo/GZVw=;
        b=DfJa1fWRBfKrbHlsLrSZH8ZuQAGNLRIf+iJnKlMga3mXiUPTLFNFY1cCF5rxiLjYPP
         gJ1WMFrxoQsw/tg7196scaLUi4jatcLMbOJ3SOUsTDEGEVZ5HKqhsxU8Q7LGt8LOsEpF
         Xh+Isa0j+t4wMBbVI9GHSkEkIt1MKIOfH56ifYkGkbu70yi87AsguOiLPdDFT82TSQf3
         0ILI/Bebvkq2o1EZd2rX4oA6ZxIgkqc1k8S3Jd451vyEjE1EeXCltEPeXCFDr89EOjhD
         Ngwe9vIVbVRbiubed1epJfFaWbwzkaBaZ4F1PhZuZAuiPxQSCM67wHXCwRyeQsxK6Ndb
         tTrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWy80ZCTSe868LxpUkaxHZAFrPc3dOceknAANBWywKKi619Rnaq
	NgQEcULeKGGWOBDw6ziDT/8=
X-Google-Smtp-Source: APXvYqzXWFYcL3oryc0J+088X+0IUpVo3qOVCwSl5gXSPKP699x5gc3L9TO9gy2iYcdC8PIG2Ba48A==
X-Received: by 2002:a63:788a:: with SMTP id t132mr25047731pgc.332.1563163467821;
        Sun, 14 Jul 2019 21:04:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:52d2:: with SMTP id g201ls2659476pfb.9.gmail; Sun, 14
 Jul 2019 21:04:27 -0700 (PDT)
X-Received: by 2002:a63:4d05:: with SMTP id a5mr23062430pgb.19.1563163467580;
        Sun, 14 Jul 2019 21:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563163467; cv=none;
        d=google.com; s=arc-20160816;
        b=P1wzza81dwRcvbLsBbS0jQ+KyQodweVVQX0rYQpBkwJwOz3zUf+OxcYsnsCF72EmLK
         nd5b0H30GMmbJyO3ROzkH5TEnjdjc1QefZf+L7ruQkFZIgeOBl+NwQDbll5Q/yTHMvP7
         cxX3UZNUMhAkKFuZ46bA/IzM+qoHcSCSsb+3TaR1/Y1OAzsYTzn0iE4B52YXg+2S/1B/
         MXu1JNylalx86dyHCUISl0LkfYW3+eAow6vGbFuJG+VFvapM4WSWZv1Z5PdnoQ2b1opx
         0At5M8t+4OqojNPS8XTo4HUKVCcYJ0gBecqzFI5DB7lLTPMhv2VvO8mQL+BvSrxyXSjo
         f0Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from;
        bh=JnUqUoVF1+Zz4Y8Ud8SNFledmPs2CgWAxYaGuqdJe0c=;
        b=UUt5LBbwtr2m/vphQEa+/MsJ1JIXELkRA/yANj8xfrU4gdeFcp+xJBvT3bTTR0Dnwm
         fiOxOh9YU12d48DJf7sjKF8oQI0cTUKqaYPGSE9w46/rtZCz2DdeLP1dWEgro9YdBiL4
         uVstytohWwe/DrTcD32/bqFVVUNidhzdWQWA1RbYzFN4AXgoUfAXyO1cBBbQg0S2A6Jb
         Csjo+StxNHghVFfx7DgH11/Y3nInMmVhHncbPX38DqG3RRY7vMFxhpPApN583looB14y
         mTv0xv0Il7dhiI5/JhPI46GMz7M1nw14GxvIvI3f2OrGz12jfy+HJ511rQYtMzyo0Wz8
         6xww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liuwenliang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liuwenliang@huawei.com
Received: from huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id f125si745609pgc.4.2019.07.14.21.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Jul 2019 21:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of liuwenliang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from DGGEMM403-HUB.china.huawei.com (unknown [172.30.72.57])
	by Forcepoint Email with ESMTP id E4AF1F52F88BD7170A46;
	Mon, 15 Jul 2019 12:04:25 +0800 (CST)
Received: from DGGEMM424-HUB.china.huawei.com (10.1.198.41) by
 DGGEMM403-HUB.china.huawei.com (10.3.20.211) with Microsoft SMTP Server (TLS)
 id 14.3.439.0; Mon, 15 Jul 2019 12:04:25 +0800
Received: from DGGEMM510-MBX.china.huawei.com ([169.254.12.26]) by
 dggemm424-hub.china.huawei.com ([10.1.198.41]) with mapi id 14.03.0439.000;
 Mon, 15 Jul 2019 12:04:20 +0800
From: "Liuwenliang (Abbott Liu)" <liuwenliang@huawei.com>
To: Linus Walleij <linus.walleij@linaro.org>, Florian Fainelli
	<f.fainelli@gmail.com>, Russell King <rmk+kernel@armlinux.org.uk>
CC: Linux ARM <linux-arm-kernel@lists.infradead.org>, bcm-kernel-feedback-list
	<bcm-kernel-feedback-list@broadcom.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, Russell King
	<linux@armlinux.org.uk>, "christoffer.dall@arm.com"
	<christoffer.dall@arm.com>, Marc Zyngier <marc.zyngier@arm.com>, "Arnd
 Bergmann" <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, Vladimir Murzin
	<vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>,
	"jinb.park7@gmail.com" <jinb.park7@gmail.com>, Alexandre Belloni
	<alexandre.belloni@bootlin.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne
	<pombredanne@nexb.com>, Rob Landley <rob@landley.net>, Greg KH
	<gregkh@linuxfoundation.org>, Andrew Morton <akpm@linux-foundation.org>, Mark
 Rutland <mark.rutland@arm.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>, Thomas Gleixner
	<tglx@linutronix.de>, "thgarnie@google.com" <thgarnie@google.com>, David
 Howells <dhowells@redhat.com>, "Geert Uytterhoeven" <geert@linux-m68k.org>,
	Andre Przywara <andre.przywara@arm.com>, "julien.thierry@arm.com"
	<julien.thierry@arm.com>, "drjones@redhat.com" <drjones@redhat.com>,
	"philip@cog.systems" <philip@cog.systems>, "mhocko@suse.com"
	<mhocko@suse.com>, "kirill.shutemov@linux.intel.com"
	<kirill.shutemov@linux.intel.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Linux Doc Mailing List
	<linux-doc@vger.kernel.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kvmarm@lists.cs.columbia.edu"
	<kvmarm@lists.cs.columbia.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: Re: [PATCH v6 1/6] ARM: Add TTBR operator for kasan_init
Thread-Topic: [PATCH v6 1/6] ARM: Add TTBR operator for kasan_init
Thread-Index: AdU6wdMFianDqtlpTa+Ta2pyAck5Eg==
Date: Mon, 15 Jul 2019 04:04:19 +0000
Message-ID: <B8AC3E80E903784988AB3003E3E97330C4B40D0A@dggemm510-mbx.china.huawei.com>
Accept-Language: en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.57.90.243]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-CFilter-Loop: Reflected
X-Original-Sender: liuwenliang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liuwenliang@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liuwenliang@huawei.com
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

Hi Florian and Linus Walleij!
Thanks Florian for picking these patches up.
Thanks Linus Walleij for review these patches.

Yes, This patch is refactoring patch. But we need use set_ttbr0/get_ttbr0 
(in 0005-Initialize-the-mapping-of-KASan-shadow-memory.patch) which is define in 
This patch. So if we put this patch as a separate patch. It must be merge first. Or we need 
define set_ttbr0/get_ttbr0 in a temporary mode.

>Hi Florian!
>
>thanks for your patch!
>
> On Wed, July 3, 2019 at 5:04 AM Linus Walleij <linus.walleij@linaro.org> wrote:
>
>> From: Abbott Liu <liuwenliang@huawei.com>
>>
>> The purpose of this patch is to provide set_ttbr0/get_ttbr0 to 
>> kasan_init function. The definitions of cp15 registers should be in 
>> arch/arm/include/asm/cp15.h rather than 
>> arch/arm/include/asm/kvm_hyp.h, so move them.
>>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Reported-by: Marc Zyngier <marc.zyngier@arm.com>
>> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
>> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
>
>> +#include <linux/stringify.h>
>
>What is this for? I think it can be dropped.
>
>This stuff adding a whole bunch of accessors:
>
>> +static inline void set_par(u64 val)
>> +{
>> +       if (IS_ENABLED(CONFIG_ARM_LPAE))
>> +               write_sysreg(val, PAR_64);
>> +       else
>> +               write_sysreg(val, PAR_32); }
>
>Can we put that in a separate patch since it is not adding any users, so this is a pure refactoring patch for the current code?
>
>Yours,
>Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/B8AC3E80E903784988AB3003E3E97330C4B40D0A%40dggemm510-mbx.china.huawei.com.
For more options, visit https://groups.google.com/d/optout.

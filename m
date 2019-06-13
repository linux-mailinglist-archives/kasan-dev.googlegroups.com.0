Return-Path: <kasan-dev+bncBC5L5P75YUERB5OURDUAKGQEY2FWK2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 378F04354F
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 12:50:30 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id q16sf8640226wrx.5
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 03:50:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560423030; cv=pass;
        d=google.com; s=arc-20160816;
        b=t5Ym6LDDrblBLDKjPkIrRJShVNl8gIpdaZUULLF1T8WGXU6Eel8XivL+raiFBR7U9E
         VIjANoLBoH2TkJhRu8NZVfU9chhExr4J3XfTJfZxF84x2H/0y/4jHAQoIsyU07A+BLUl
         S00sVIS1K/7R2v921ljh6hAqGcB8LwEiYApjDur7amIJ5Hlb7Dbfz/7TgYOhe9mSSaEU
         b2Y1/9wH/FZJuELbgiSWq0xPwRe4prwVOi4uh+6oy2jaUrXwqGjfnLg+Y0dNfNK1K+G4
         bVTPEYxryWPEZBJ9Snzm+xx+Q7BiRdBphBIV0Gf+l60ACUTSKy6Po/ZY/J2tm2lRsaH7
         mo/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=spXd7NjT5vMp8WCw17jKyBtcks+HCoMAlEy2/4VfGTs=;
        b=QOrIDaXIDRn/dn4f6kbBhqTyECPVlTNLNAtYVOADPRm4IFmPrQSAcXiGK9MPoOQadG
         Wj0TCIXg9tSeRjgop0WIgCWo5oXH9A6MtgAkaY9yr2orzrjaHPDH2hRtJUbcvz8LegJr
         wxX4p4qqoTW/wr9tzRpIhQLvhSbYCjzZMo997sZQ0kiAOqokhUlIQT+p443CIyQ3/FMs
         ErRHoyr9RXYxMYwE3eUMdVRyZfjcKjavQrvG6WZs3/Z20LgoYvOQ0ab1Kmgw6S5bdOmw
         /aq7y3SPZILMeWO67bebQIAVI+Sm4sX0ZCNpKOjeJom++0nQScNd/RgCVlanRNoP38Mk
         uKOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=spXd7NjT5vMp8WCw17jKyBtcks+HCoMAlEy2/4VfGTs=;
        b=YGTF0Dudk1LsEYW15PkihgWX+2pLT2IfWHu8DphP/gfkdxrpv9lrHomaJdkaqN96M+
         iX0ZV9NKQffGv8zdOL5U6mz8lpkN+5meikaFKld/iAVTGHKcVKThuK3lJrWnqAXjFcH4
         21pphMmTsfe5RYwxOOphaQrJHxcISFY3NBYEw2eVXcpce5Che9aZ9M7FIT8MSY026AYh
         iQxxAyIUu3ulWMnqV/V9MZ6kfT1uhHc2XFKZ6GgpJSj/CqHLoxHBROHRkOxqzYSQY7SO
         MeScMHQS2Cc2604/i8vaOA6dWZGCH9w7NWATKYUlWet6uWM/8GYCQxlwmbNYZCuMGmpe
         IAxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=spXd7NjT5vMp8WCw17jKyBtcks+HCoMAlEy2/4VfGTs=;
        b=U5gitk0vcE5kxRABiTNy7rP7dB5e33BNLWA668Cj6tdjhxbtsyZLsFv9/wBHWi2jQO
         Hx8wjRa7ctrd4vULMvAZIy/yf90uBKMDlwcnu7ta/tDQqKW71paCA+9p9uh4j0VBaAwD
         3TlG0b0vquakbJvrlpmzZ7OrbToumXpkh+Nsstd0sFoktHw960WpINf0q+YRsBHv5hfu
         gGHTa4wVUOMcbS1KD7qCblouTY8OAfes/S2YsEMJQjIFpFwD5w5aLzTzjhmHZx+FLewp
         w+57KTDQBmDWJihtjssCSRngrmE5GT1AAyfV+5IFzExBlVH23jCdW/cLq/nb5cojAuMz
         EHFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWiky7WI4isZrV8F4cFVxlqnpT1oU+b3C0cJHfZkXNiEtgDOhRs
	UBNGSQ5GXuF7X6UVLEDXFUQ=
X-Google-Smtp-Source: APXvYqw7vJ82BVZfRCKxTTd7cZEXIqH94bMz0E3VngAe1/nesFgG39uBdmJLc6BXmuZ3dZFJoaiNSg==
X-Received: by 2002:adf:db46:: with SMTP id f6mr43986387wrj.330.1560423030000;
        Thu, 13 Jun 2019 03:50:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:185:: with SMTP id 127ls1611317wmb.2.gmail; Thu, 13 Jun
 2019 03:50:29 -0700 (PDT)
X-Received: by 2002:a05:600c:1008:: with SMTP id c8mr3272489wmc.133.1560423029566;
        Thu, 13 Jun 2019 03:50:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560423029; cv=none;
        d=google.com; s=arc-20160816;
        b=rAkVGaAT9JeBzdfkQ6z9FfRBwWNVIps+Hm6CfmOml1m1AVhtR38/UCC4ijuBz4sOHK
         lLjoDHm4UwEwoB+o3q2wHNRpKCduRRIovUPjJ/ztd2d9zttS6ab6jBhKxWV0JQW0ibQj
         /g0Dy/yV0pkN+YPOuZB9J4q6r2yX88TA5+RsVM2IurejUQu2B68/SfMpzv782GJ4dRPZ
         OOS+xCsNx6WeccUkhQAqudnFpwHEbJHJ41IUPk+UyRua7dFfvkGgQMboJr2vL5pW0t0v
         Ez6NlgRvsLGpKTLZYdmrRoa8cy1Qr1bnoZuikhAy+znO+N2Om1iGCh8UCMC07CBNOWaM
         fbzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5hK3yMvwnY3zH2JsgNq+7IiVoTtZzfmZIgWdSdRL3Mc=;
        b=IDC7bvoV/cpO760hivH3LHpJfHLYmOa4qc3XejHnUStujDXgPRpMNBjVpeR/Z/Wuxr
         dTIw3+g8I2p7W5sKELw+FF8z1QR/bBT4xoD0a4iqtma0uTiLQ95uOJ0S/qxPX8S3kLjn
         TtFtIGHkxp7odvD34JQ2VQizaoh17hKDtFzNvTHDz347v8urJIm3MSy8Wae3PLAbqy29
         Ttpoh8ytlYL2MxU1URvHgvIyXYfcpwoSFJBKsevaUyZbiffbWb04ddzZpnQ8R1QccyQ+
         I6+pD2eNxRuGk5HgpQ9oGCEBDQtMv+zYoqp4WVPJH9UZrJLT1OGnB462abBhSXNFsN0o
         8Zqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id a17si119908wrr.0.2019.06.13.03.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 03:50:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbNJM-0000cp-C9; Thu, 13 Jun 2019 13:50:28 +0300
Subject: Re: [PATCH v3 2/3] x86: Use static_cpu_has in uaccess region to avoid
 instrumentation
To: Marco Elver <elver@google.com>, peterz@infradead.org, dvyukov@google.com,
 glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-3-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <d3f70d55-0308-a2e2-0f4a-1bdf6bcde544@virtuozzo.com>
Date: Thu, 13 Jun 2019 13:50:40 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190531150828.157832-3-elver@google.com>
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



On 5/31/19 6:08 PM, Marco Elver wrote:
> This patch is a pre-requisite for enabling KASAN bitops instrumentation;
> using static_cpu_has instead of boot_cpu_has avoids instrumentation of
> test_bit inside the uaccess region. With instrumentation, the KASAN
> check would otherwise be flagged by objtool.
> 
> For consistency, kernel/signal.c was changed to mirror this change,
> however, is never instrumented with KASAN (currently unsupported under
> x86 32bit).
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: H. Peter Anvin <hpa@zytor.com>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d3f70d55-0308-a2e2-0f4a-1bdf6bcde544%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.

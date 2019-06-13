Return-Path: <kasan-dev+bncBC5L5P75YUERBIOVRDUAKGQEKWT73XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A3FB43550
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 12:51:13 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id a7sf8704989wro.9
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 03:51:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560423073; cv=pass;
        d=google.com; s=arc-20160816;
        b=gahmedGWnn3wDkbTA+lM4Hcm8TnNmioV8TcZ9T5j7MqVRGyK0n32gn1w2b6j9FMivE
         MPhlt4LedwpYUTsPnPt6LD0KWQMjHzXvtDERHAjBFDYely7r85OPe+7Y2wNP7o2tfKuN
         bVB1B0+YCcqCg9GwzetHcF0dNmk4V2Tu/jF2FjvkUv+xNxG66I6RlYKDNy4iJu5mlmP7
         8IdL4dekDvByETAqKHkIt2m5sb7qx5TDPVal2yadFNeiBg7V9jvGPdPkbDKq+eM93ygh
         ByVppC9a5+SC1FbGXXAfkNXhZCNH+4fvYVbWNmv/DEsjrxqaXvzgmepqYUY/z21hTvGA
         esfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GT/Ob3QHQ3rMu47Hp8+hU/QYtieOP+npisXrJsPc83Y=;
        b=ssl5FDq6te4CTWEwckp3samKG2vFTZC3S5QZe4NJlAtpa0ZtlgE/govrLqKBM6yTMl
         DFwZD8IRzqKs/WTpTXSGAbyuUyF1tuQlY5IIzbeG87sr2OpSnDbvom2/zJItnYew82C+
         Tt0GXCaIqI9aloGn6pIYoS1hIUXvd3wEvY0ZeSFHPIuFhXytR25qn/XmGhT4Zl2P3tIg
         J+5v/JB3mVoN/urKTPNAuRsbRhBxxKk1ye89wjP3Jh/uAs+728z0RmgSy1TXF0koUvN5
         NeiKscgR5Bpze0aoQFgVqaKhznauV7uq2CaHp2FPAQKMICKuxlEaaZkmMAVKzkeQVj2u
         5dGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GT/Ob3QHQ3rMu47Hp8+hU/QYtieOP+npisXrJsPc83Y=;
        b=Cfbdit65wiAqD6wNKRrlpV6J1Qi4Q49246tMezC92csCDLrBOe9wn35vup1Yvq8jBd
         nqB0K5pz708Ev0mIWQP7CgmYwLif7kPbq5zOpP9y5r59pw40FEO8jkOg9eihJEvuJvIX
         CrdEa3Z2acbJrWEMlQ1UU1TWvP+IwYWyEk69Rd32EhZ+KK+oibqmMRqmjGKfvpW+fjau
         ULi+5WoK5rYcpXCH9hLRsfXaWm+CSRHbn81wSvzaRyfhhhTc26k44klVFN5Tuj+oaO9R
         Ns+CsWspIAO3Q0NQcVsAekxQCg5SjX46+ZLn1oU7FlL2aGgzExMcr8OtaJ5nChq0JgLi
         9/nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GT/Ob3QHQ3rMu47Hp8+hU/QYtieOP+npisXrJsPc83Y=;
        b=Md8q7rytNCDxLgaTilAt7p4GsaAI3OKuOGoxm/LHnnULO1xiI/pEa7Ae3OEkJr+8u1
         Ef6wsokDi5gM0gpfVZtQBpLtaQKInhmsWk8dhSvRK8JM6FsOhlPJKy7fXSkoQjpxXBAC
         Fd2mWz5vkvUqnuUHaHOYY/b8pgfwJu2oFyV8bn4S0N9awEJmdUb0SPdyQdP0GNrRVk1M
         NueA7eGILINakeh5NpM6fv27BKdOSJvus0CSI5sknnnd7aK7Mmvd70mlQOo7HyCA79qQ
         q2pHuGdLL9gImMcLtMlhificQw2x894u8I+S15il42AgGY7Jb2CtgoGYfUMjmo0I4YRP
         mwHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUqEjnSK1SqjjBo+8FzjX3pECV3NCdtB8Bf0LsuCDRJy1sAY5Jg
	mMDwXxpiD0GgSde8ydSa8Lk=
X-Google-Smtp-Source: APXvYqzrlo8GVpwrUPJU8fVXLWvJQZyMMqT3WKnv8YtOs+RtMlp4ty86aw9Bzp3zglKI3TslHzCObw==
X-Received: by 2002:a5d:5342:: with SMTP id t2mr44346188wrv.126.1560423073259;
        Thu, 13 Jun 2019 03:51:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b484:: with SMTP id d126ls1611069wmf.2.canary-gmail;
 Thu, 13 Jun 2019 03:51:12 -0700 (PDT)
X-Received: by 2002:a1c:5f09:: with SMTP id t9mr3411391wmb.112.1560423072892;
        Thu, 13 Jun 2019 03:51:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560423072; cv=none;
        d=google.com; s=arc-20160816;
        b=M984B8DYU/w6IngQhuxB+wsNVboNU9uypJh4hCMqLIg8kqiLCTE1LfHBsRJcBemF3t
         bI4YiZFY88583KKZ07G1N5VG6lJ728VodChVAbD0G5sMeMq3GA9ahDdImN1XMU3ps3/+
         zKgPewcgCBZ5JPB3EcJNbwX+uBchy2UV9eErWQdTXDuhG+LvFrsiKnG0ltSm2OfwjTFn
         k8JlBxySar7LxxNkOpMam3ScQ9OouhF/h5aNEExdUYDyv8WWgW29GXO2w5QsVx/IJD4O
         NDbQwwYGbSvkdGxQIzB7xeNG8e+HsXw0QQJBh5biYmWS9UAIeb30AdtI98b7DSlXdO47
         6ARA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=c25GTGgYjaq6dIxvGpZAH+AW4y1jf4y6UBSqUZnSNzw=;
        b=kcJn7t5sTjO2hjSQsGSxCne/z7/tzoWNS5zHsfHxMq30pENTcZ3UsO/Gh8/3Pg6dGa
         olkUwbRhgbMJAKwfSzapxT7gBvzHMHLD6nlsC0mO2d38xDSuUSNOafxda7RumCi+mqPL
         eaPG64dneaBTOtomH24cw9RJI8NvUmKviLPkPEl+a8F/0UZ4AevexALfUmZnKjXt1jIY
         HJ1JxLcKQm8Z9O5WTApJxkHSFb7ILm+dVHjMH98BBOsvcBjUW08NOFEi6671oBR+cJOX
         xekm5ToCyVh0CWInOZT/ScZqsRBsBvhMvQGFpVDWakH48cWa3oQGzovQrVG5qRN4c/C6
         7GTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id a17si119997wrr.0.2019.06.13.03.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 03:51:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbNK3-0000dR-IP; Thu, 13 Jun 2019 13:51:11 +0300
Subject: Re: [PATCH v3 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
To: Marco Elver <elver@google.com>, peterz@infradead.org, dvyukov@google.com,
 glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-4-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <5b4babdb-dfae-4006-0608-a9f5814e89e9@virtuozzo.com>
Date: Thu, 13 Jun 2019 13:51:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190531150828.157832-4-elver@google.com>
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
> This adds a new header to asm-generic to allow optionally instrumenting
> architecture-specific asm implementations of bitops.
> 
> This change includes the required change for x86 as reference and
> changes the kernel API doc to point to bitops-instrumented.h instead.
> Rationale: the functions in x86's bitops.h are no longer the kernel API
> functions, but instead the arch_ prefixed functions, which are then
> instrumented via bitops-instrumented.h.
> 
> Other architectures can similarly add support for asm implementations of
> bitops.
> 
> The documentation text was derived from x86 and existing bitops
> asm-generic versions: 1) references to x86 have been removed; 2) as a
> result, some of the text had to be reworded for clarity and consistency.
> 
> Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5b4babdb-dfae-4006-0608-a9f5814e89e9%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.

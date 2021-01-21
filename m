Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBRWLUWAAMGQEVIJSSLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C42E2FE8C4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 12:30:15 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id c1sf730507uab.4
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 03:30:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611228614; cv=pass;
        d=google.com; s=arc-20160816;
        b=LRpJAK0LNnY0VdyYsUZ8D4t6XWVIQnPP/8oMzngbTFi17luBrqnVLfIW6ZHP3aSegR
         bfE7AHisS5R3G39wHjdMpsDBHnglZxwvMpq8U202dIBdLM7LWxDTmGZzTzHpJieoIl6i
         gjr08HWvx43gdVFiQr15i7Ny6VhHEBJBKwqv/KGidMS4rzTJrWGrsySHQZ3alP81BURP
         wbVm6kIbbT/ymcuGX8pc7Q0jQVDaw/5ZAEJBcL6xjFuGF3brm8MUc+6scMh/xwJ9/amz
         LqDNc8LQgYvV2P+pRX/kPac/f2gB4O8vmeerFE9uHVoZLxpUFv8grNSKMB+oqGu9OjXr
         tWcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=rL5O/i+EXl9MaVQ//Rs+fiWH82t9c2ej6qDu+uncruM=;
        b=o+GZUo7yCcxj9Seo1CT8OTpS3RyQ215nxtClMdy8LOTPAZbLEd6AUpjC7bi+f9GXjD
         qkcU00IjSxdBtzaPzM2xVcP9zkcnCtD6sw4Y5Peof3F1cLnJ6gREc4YgLywbR5I5I2VA
         ZvX2WjRxHlG/Bchk/Ko4ct7Fc55mh3gapOFhX1xLaow5PTgDsJ4+2vDARYJhzaNgiIsb
         PZFI7mgOgmuHgcvGdG9mPnx6MBOnVozoNS4ggVjo3Qng8ZDfK5q+VONae/Pgh7dFQjKa
         5pqewoy0H1I/g/EHksqck4cQN0rEiDcthJsq1mB8Ei8bFo2uZreDN3MgWeuShpriTu4e
         W4cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rL5O/i+EXl9MaVQ//Rs+fiWH82t9c2ej6qDu+uncruM=;
        b=dJ6dVSi3dzMHTVg/iuop+N7R+iddUdxTudA4hO0R1TADk08LQiyWTBt182yrk1fuyB
         XnhE6DnAFJwa4NxJ3wx6BNIuZH01Ms+hbmHtQG+8qpJ/iR8/yoCouWRNSQ/b406dCu9e
         ryQVm8c2FLbDmIp6wNWsnkSm0J7oucF6CU42isFhf7ntugboO4VkP+demKjuaT1cD4w8
         5ZgoSHTX+JM2O7WRNpXKxUfCtHsaDWmScE3rDDeWaKWoezzvpA1eYvhmYPg+GiPGspaI
         yZaXVVRDdeTtNFySHbls/UWwmd4bp0zRO5/kwdLQiSWUMddIG37URVNTX1OW3heMJsPc
         6FXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rL5O/i+EXl9MaVQ//Rs+fiWH82t9c2ej6qDu+uncruM=;
        b=h0TZRDw2+Gt7bmIxT9m7ZNJ1NxAkjJqNFIiteR2xFUDtA7D0gVO7ttDIxPQy1xG0zv
         eOmTaHNfaRKY5N8fLu7V2uf98NT1D+RbKCv6UuvdljSFcsXVmRZc9RQyF+ZMIG6twbIC
         2g/e3GkLrbGtOlPIw9QlMvopJFJwADdzbUqYXrbcPfPsUevKPa/MB21h+ri4zEpFrRXc
         LMFGGwAHaafQnsGRjcaUTiWTurwrdlJF/k7sgbhgaCr7bnume5105yXIvkPViOQqxhpf
         E1fWJeUfEL/NFh8J5Ikt3NQbfDT2VuUN4SJf7kt6UTlF8P6Ibo7nzsOFvnwt31QAONLp
         GWUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hHscSVeAsWHYyda80Nc/HW+P/0B8UEvU3K6n1lA5quwihO3CP
	qy9fUvQ5+nTFyrB8bpXl1/M=
X-Google-Smtp-Source: ABdhPJwp9+cbi0fUvSK1w/Z8soo9yoaK7g8OfZG2fwKWt795Wwe7ySV6mubFF1iijrMCml78kmeymw==
X-Received: by 2002:a67:2a46:: with SMTP id q67mr10046875vsq.40.1611228614141;
        Thu, 21 Jan 2021 03:30:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2409:: with SMTP id 9ls142132uaq.1.gmail; Thu, 21 Jan
 2021 03:30:13 -0800 (PST)
X-Received: by 2002:ab0:2d3:: with SMTP id 77mr8934442uah.89.1611228613562;
        Thu, 21 Jan 2021 03:30:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611228613; cv=none;
        d=google.com; s=arc-20160816;
        b=fU+k2orXvJFJI6sRhGQccrxuL5IUVei1nq2BbfZT+BvERKQtp00vDZiDvUIxtb6Chm
         s4E5dFNsJl09/e4UmVIg9zAFTtEoX33PHojw1zfi8Xz0i5/MOBL6j/832xWM9adg8Ri4
         hkQdm9UrNhK9Xmf26kgPC8Hvr/HPqZYLjGLgjBRX01ZbyoCMcW1Y9IZuDoVwHwwGuRZf
         GZ6zEPSRWk1e6hwEWJudJExi+g0cIhhPa41CYcOdahL3RKzBb/Luc4oBvvIrU14IKXaE
         q8eUU0qJzdUMWf+t5iVRh51SaM7qviPdH2yL7ModzY7XOv8uapGogG1q5955ZB7HTROo
         8EYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=2HRYmebgHemXkpv15xC1Fi56jbMpj6MX3EjSQEEv+XI=;
        b=vImkboVkE63nFJ3pM9drtVr30aMiEVSomY2zc0/Xps1W11UugAoK2ojshvs7zBTRkD
         N8ynkikPB1OnVD0d1ktnbD2vdu/Iq1M0hADEimfCyB3zQyGyc61ZnBggrAvGmcxvqIFO
         PEGGzdGyfuv3d0X1AHWtWsk6FZLm9z7OJWiw3A0kvcAxG8UgXinTCIznuJNw/RH60N7r
         PUNqY/JoiaNsvG7Egh5uh+UlnJ0vzYOy5sWlgx/KB0YnjbPoICdMGbY0/4NP4nwHiAnh
         VV1q2svBweCR8s4CpW9y31s0nQIBWPPooPuM4okF/7noDvUmmGH4FV8/MW9gPfF/HCKv
         UsIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q11si693455ual.1.2021.01.21.03.30.13
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 03:30:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D2DEE11B3;
	Thu, 21 Jan 2021 03:30:12 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5455F3F719;
	Thu, 21 Jan 2021 03:30:11 -0800 (PST)
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia> <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
 <CAAeHK+yrPEaHe=ifhhP2BYPCCo1zuqsH-in4qTfMqNYCh-yxWw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <773e84d1-2650-dfc8-6eff-23842b015dcd@arm.com>
Date: Thu, 21 Jan 2021 11:34:01 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yrPEaHe=ifhhP2BYPCCo1zuqsH-in4qTfMqNYCh-yxWw@mail.gmail.com>
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

On 1/19/21 8:56 PM, Andrey Konovalov wrote:
>>      return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
> Do we need is_vmalloc_addr()? As we don't yet have vmalloc support for HW_TAGS.

It is not necessary but it does not hurt, since we are going to add vmalloc
anyway at some point, I would keep it here.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/773e84d1-2650-dfc8-6eff-23842b015dcd%40arm.com.

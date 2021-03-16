Return-Path: <kasan-dev+bncBDR5N7WPRQGRBMUDYOBAMGQEJJL2OYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A339633D5CD
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 15:33:24 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id w10sf15753825plc.20
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 07:33:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615905203; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTdVUfOJzrXoDn5vViD2racwyNgKbIXQXMZ9lvnK4/zmzfpI+7I0qotm11zqu0WstI
         8fRGxdOfrANG2j2xtZ6Oy/lk9zG2KjbHss3zZddjD0Dakf/fv6p0/PdtdJ5Oc2rlFF39
         oo+3bYXJ8IinqnbPVvuvx0v2tbqaR5tiaSHGrkIsRCLU0pVqG+7+glxEF53qglVoXecR
         wMJhPjz+5Y2KY6r1pEdwCYDnCy3qbAdzf2xsjGH0eUYe+T0NBIsqWKKPW8opgPFLjA4z
         y/5IV7vRvGmfWykX9gbIxqlAMU3hsoynZ/XTQDR971NHBHIu46IUCyL3yi6kw3iBxm0n
         5TaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=T7lzMk9qyThrW8Uc9vkOWyWG3LZqjtWDyS9+K7v9nuU=;
        b=zQOs3mpayo4JVma+Ruh6pEe26OXZ/ug9AkuOFgScWtAtkf9/wqu+taO47uMiYKkzCw
         vMSUANthAb+/HUbA5er9nPhwjQ1Un7pjkW6wJMEMwZVjPisLxpHrYz9hye0XOh8bs29U
         9qN1dYj4a2oFkDS9xTv5yQxpme6Q7ojkOgkUwTNfqo3r1JCtw6bXt6rlOrDmzismsPxX
         MpOhBmVFaSPEH9TPn71nI+9S2yu16vP3cW64Ut5AkhvM3dGfEMUWFf0702ciOCJO6llM
         kLpDNkSkZNEYq1uj3aDwS4gFQzJy66fz7CE12medh7tLfzBTNxMsvtXrggEzXC0ymKJU
         TQ0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623 header.b=z76CH+We;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T7lzMk9qyThrW8Uc9vkOWyWG3LZqjtWDyS9+K7v9nuU=;
        b=MN2zPJTpuReK6RpgiiAnE7UGu5yXH9H5p1gn0IKTSe0paPPm96sOhhrgwj6F4NxiiJ
         og1PJAMEAc4y9CBU7y7P5yAxr0y3IKdZTRFh5K8M8KQjJZ+CCKU6TrVZIEDohCt02CqO
         67tl7AO3nag55aA5bntFhNzgMKR70J/vjsPopAW/zMoqVTPw45A4rPe1DMkizwx4rGVn
         n7Iikq1aA4grerVd6xDTPXqEiNzFXb9ofgHsMSCjC2SQ0M1VCj14tbRmn45sUttvW3PO
         X7jgo8cX2B15wH77mda+f5fAB6j6sHkaRPwd3UbDvHY6nihV9iWFhnbFHPutx2oZUYYQ
         CVhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=T7lzMk9qyThrW8Uc9vkOWyWG3LZqjtWDyS9+K7v9nuU=;
        b=sAPOWmW8Ruky3A/xISdpMipIeXzSoBUyl5wWgswGj3plEE9EJ9U0ZMek4DLg62kNtU
         jA48xLlHJsLKe74R8hnYPJ7zQBtAWkXDoH/8mJUfvUec48QCqy4h1AlqdXGyjzPlWAbN
         3ssYSHecnXRY8l4Ud4mo+I4AxIuQceXAWc4qDvzpa2vdLQCU3ve71PK2SPI3NhXCVHnk
         7JPY7kJCZRBy7qlVaT+3Iy5HT+RlPnbZYWyvfmfkdSwbcRwpK1mZ/ozK8EhsxWB1zsbH
         T+sPn8QwCS18cKmBLacsNuAXbtWSX9RqwUAuALTJUrT9jmxLeOyI+IEXmm+jnPB5Lbi/
         RNYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533U66YNqvBjGC5yVDTtKpFtFOh143N29MIz+fOcgExrlyvQkBML
	atNhOjYuZzQYoRu1no9enGc=
X-Google-Smtp-Source: ABdhPJxHjWKc+T8wBMSQNcnwmuNXXc8mLKz0fwhUknXP7AYA0JUQUHX0hDwzmXuOi+JsX4oa6orgfA==
X-Received: by 2002:a62:e404:0:b029:1f1:5cea:afbd with SMTP id r4-20020a62e4040000b02901f15ceaafbdmr15506833pfh.5.1615905202875;
        Tue, 16 Mar 2021 07:33:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:ec9:: with SMTP id gz9ls11758751pjb.2.gmail; Tue, 16
 Mar 2021 07:33:22 -0700 (PDT)
X-Received: by 2002:a17:902:8ec9:b029:e6:c5e:cf18 with SMTP id x9-20020a1709028ec9b02900e60c5ecf18mr16833809plo.47.1615905202148;
        Tue, 16 Mar 2021 07:33:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615905202; cv=none;
        d=google.com; s=arc-20160816;
        b=fPDFWxWNf5Iwm7tUyivpjmfdvxsRigDjp5KX2xtx0ooPdQLz1USSTq2tagLzWMUxia
         4liLsFO47nK9rkOn6UME/gJynXkCeFVQ03dMeDSjzWxWaL7TXltWDHs5PxotyAtJ3fCj
         Aaa7rMRsuU2GTJjFYj25hITRwjCIE6vbDsB+8SGQJtr0Bj0W+jbLZC+lHbK50IAIU//u
         gj7GYNDyF5asIBfsEsnQXE7xa/DMK56Z9YqcHn1TC6My5z8ZxRACcLiVSxahzGq66eon
         Q+Ao9ruYi0BeVqVB/IWb9+Rza6/lZNwMBXYDnN9ahVKNq90cK5q/B4n6XoT435ZbCGYd
         jF1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=q/7bUx2ojAKrW6WgffbugKW8m/FPOBCZYXbC80AEUMc=;
        b=oJsy9F8VpRDqtMaB3rjjNrUub+2c9i9MtYnu1YpYAZTlyvkdtC1VYWcSuoRqNtZ2DO
         3wsgUp/D1/Zm4irmDoljjtzq7QuNp0//kzVKv7nlIsGijlJzA9gMmryR0NxECoLROavs
         yaGYhA+X/8B3jKfayu9lMecdc2dG//7LLQTf8go1Tcc+tKeDSUsbddxLcS3GKiIUDihG
         PmnZljBVhPSjNa2BqA0Caqf66ig9+567uC7jkFziVIjsBb96hp8izTw3WQ/mDnfZ/uCA
         jJ1gkXDiZz4HZjd7pD0kCoopUsujvTfU+w2rLkr7Kgt0CZzTUmdUq/Ptxc/QF/2cih/T
         BOww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623 header.b=z76CH+We;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id f7si969641pjs.1.2021.03.16.07.33.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 07:33:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id n14so37393182iog.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 07:33:21 -0700 (PDT)
X-Received: by 2002:a5e:8d05:: with SMTP id m5mr3570773ioj.114.1615905201756;
        Tue, 16 Mar 2021 07:33:21 -0700 (PDT)
Received: from [192.168.1.30] ([65.144.74.34])
        by smtp.gmail.com with ESMTPSA id d22sm8423199iof.48.2021.03.16.07.33.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 07:33:21 -0700 (PDT)
Subject: Re: [PATCH v2] task_work: kasan: record task_work_add() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
References: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
From: Jens Axboe <axboe@kernel.dk>
Message-ID: <7d5b6e38-2e11-06f7-0a6b-356bdda0cd5b@kernel.dk>
Date: Tue, 16 Mar 2021 08:33:20 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623
 header.b=z76CH+We;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 3/15/21 8:44 PM, Walter Wu wrote:
> Why record task_work_add() call stack?
> Syzbot reports many use-after-free issues for task_work, see [1].
> After see the free stack and the current auxiliary stack, we think
> they are useless, we don't know where register the work, this work
> may be the free call stack, so that we miss the root cause and
> don't solve the use-after-free.
> 
> Add task_work_add() call stack into KASAN auxiliary stack in
> order to improve KASAN report. It is useful for programmers
> to solve use-after-free issues.

I think this is a very useful addition, especially as task_work
proliferates.

Reviewed-by: Jens Axboe <axboe@kernel.dk>

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7d5b6e38-2e11-06f7-0a6b-356bdda0cd5b%40kernel.dk.

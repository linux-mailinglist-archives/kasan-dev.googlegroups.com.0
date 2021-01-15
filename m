Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4N2Q2AAMGQESEG7RGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F3CF2F7D19
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:49:38 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id p4sf1491981vsq.13
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:49:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610718577; cv=pass;
        d=google.com; s=arc-20160816;
        b=CanpTbbQAFdW/LE/AEzkYEHif8ibWYXBZ4Xwk1AQmZOMZ2LJOWGwkTb9GPPGrqRoZM
         QvuJ9dU27c+hgcqI1tqBAc2VKmziIwFEFALu0ewyHJadPnVCPWhPys7I6dHMaRn7doLh
         QFxwm2PuzOBBkAIYsg+Dcd1vDMy/3llP6Kuqh64o7dk9wIyJnu2HTleGrRiTH32nfYrs
         zuRVf/Ozs4T9oIwhO8Iv4wVzne86IK4uOnayW9xKJry/1YB3QJrlxTye3crbiGCgj58W
         lbpzX4m5BN1PpWVa2QxdUoKIDkIGSfkfFbIvyE++he44wkodt59LpYRKXO1kXana5JPW
         189A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=02m+gU2XrYhDzkH0jg+RZ8wtKkJYvmLQTicZhlMyKvM=;
        b=AZpQDKjtEEl8smgiUySLPLP4UEii0No8CD7xy+FGA8gi4lHPq9cW00Hh8Walidghv8
         7YoBQp95ScINEyeZ+DMriuttZ/4KiMnsZ1gzy9aeKXnfaxk6Qjp6dJUX/C+Df+eikAR2
         NxyXOBnV24i9HoFbLQzEWl2Gw37HwbZjni8jbRxeVKq2tBMwSlJZaB4l2ojbCnP6lni4
         3lRmcbD9Wgwbe8OBdnqET64QwlwLUB/6ZQfKSsrz+xr5Elxtgs6CWsdQK+qExpLEHWOW
         wiWWqSECTYBYqmL5eu+iI8jo4Yi8uQBSe7faTVRvbiZ+qoSvxMrAHayfTo4t6ZisqdQg
         CnMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T9JdoQa+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02m+gU2XrYhDzkH0jg+RZ8wtKkJYvmLQTicZhlMyKvM=;
        b=mEC2xzYJgNUa2F4OspH0kpY+5OquoPWGmfR/G9f6YgdbZamj2JZWPLrewh3jvaEDfo
         U9lTUqlrbl5QJy8reJFI1kSdpq+a8TAJ89nl1OLO7YuriJ337J0dr6k5dxrVxGjV3c+z
         OR0y4KYTIuHxUzs8j7sZkbKE6KLcvVYcGtNWmILHa1PmkgCs6Izjeh2fuQf2m01XOjx5
         9xpxpTMCNrK59qMqEu6zle1ZpSytX5ShI8lSTi51n0oh8aEAYK1mUswTBqNg4LLUoCL+
         LlJcbSbhoX8zlZcszCt7rKPL3EYqJdSda1SPVDGhPcVFF27Sbpre0kfxpTX435sL1WGt
         yaxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02m+gU2XrYhDzkH0jg+RZ8wtKkJYvmLQTicZhlMyKvM=;
        b=IT/X6oaycRKzJLzEcUutGt2bJKkli43TXuNVWnVFEisyyY2q67MQCPvKsMuS8Rkn53
         QsPWRiFZcdl9/OG7LsoBNDJHMVMeUnSzPFQ6ZXOJlHXGa/V2D5EZAQ4gXA3rtNpf3Djo
         DziflIcEO624UsB1vv1/ZrD5ML4sokjwZ1ECzdd5N5NWUAxAAfs6V3P5lZSz5ymrEC1r
         uwCsph1k+awonqwSr0pEp5ZypUjH2iLiDB/Qi8eA1ODXjBKzthEuX5Nunn0pRQPjHzEW
         ULuglX6TsHHnOj8rAXAkcEroQIOoyzpW9056B5AC0z7i/8FTidn/olBAkr1Z6/YfkA73
         QbEA==
X-Gm-Message-State: AOAM5306lub3DRfXj+jtKQUeiF5DQo+CyEjBZHrow4xyQNhk7REc/nw2
	syUKXiga2a9ix++6YMufkqg=
X-Google-Smtp-Source: ABdhPJxIqgFkTtA8DjvAy9+K3uWBu3Q5aA8nP6NfxKMkv+0ip4SVk3bam8n6D9gWOyLkP/MQnxdESQ==
X-Received: by 2002:a1f:9e83:: with SMTP id h125mr10457763vke.18.1610718577245;
        Fri, 15 Jan 2021 05:49:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2409:: with SMTP id 9ls679399uaq.1.gmail; Fri, 15 Jan
 2021 05:49:36 -0800 (PST)
X-Received: by 2002:ab0:2011:: with SMTP id v17mr9258547uak.96.1610718576795;
        Fri, 15 Jan 2021 05:49:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610718576; cv=none;
        d=google.com; s=arc-20160816;
        b=gZ8MsqcL41dBetMshzZ0jLh8S9RpHQQpTsEIzWBjIkuZl2M8umTYb2NwF6tjAGWIuD
         8Tc9E+wefJHmIaEjghmsQTbRHZPHRTdL8ANvO322nvUYb5B+Lwab1eAbtz9mbLZhppHO
         fxvgfciBByBEvmX5HiIpnslvt26DuqCJTDryk2wXkQzfaiiajlc9Fj+J1zXOFy/3PfFO
         auJ4e2wZzEriwu98A6ve3vmC7ZbczDtHbvvZTPTkB99gXDC4gwYpV0d8rxAjzBIWQOHX
         1da3z9GV78ku+TY2mKC937NHuJZAm6/8N4Zpy0OgPRnFl00AJNcownFqJVro/89vCDQj
         1rVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ImoEwuTdQjAc7TacOKy8igwa8R9Q6yFQgZN+WOt6oC8=;
        b=IFw5bqNLYtY5BSsqKadX2Ijn8+ESwv3MCLRb60g2KRRCeyNf1My8FNGdod1n8ZJlp0
         V0INkWYypJqAYIdjaQ1J4ODKyUL44w+Ylq1SmON0hGaG+4z9a4y74VPfbeXUhlYyycij
         1hHqW4cJ4L5dm0qaBlTnksRcukURP73QDOKP9rqi9ib/ZkZ1vJTcyARIPZ/rfFLWDBhU
         SUxM48uKu2ljYtI5ua+3e71tkUbF+VEyOcY3PHHMjU4nWslSHBESutYv1OGsyzDFa7NW
         P1JOt1fqh0G8mMnWL6uCq5lw4ahMbf6swe8vyA/SchPAxdxO+OqTALbtKOZNvhB0va8T
         tFkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T9JdoQa+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id r207si498953vkf.2.2021.01.15.05.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:49:36 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id c1so5996529qtc.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:49:36 -0800 (PST)
X-Received: by 2002:ac8:6cf:: with SMTP id j15mr11672543qth.180.1610718576341;
 Fri, 15 Jan 2021 05:49:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl@google.com>
 <YAGVqisrGwZfRRQU@elver.google.com>
In-Reply-To: <YAGVqisrGwZfRRQU@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:49:24 +0100
Message-ID: <CAG_fn=XnF1GmOsJbHNtH0nn3yXq5bghYDXDkeqawEXTzom8+sg@mail.gmail.com>
Subject: Re: [PATCH v3 14/15] kasan: add a test for kmem_cache_alloc/free_bulk
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T9JdoQa+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jan 15, 2021 at 2:16 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> > Add a test for kmem_cache_alloc/free_bulk to make sure there are no
> > false-positives when these functions are used.
> >
> > Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(see a nit below)

> > +     cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
Looks like there's a tab between "test_cache" and size, please double-check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXnF1GmOsJbHNtH0nn3yXq5bghYDXDkeqawEXTzom8%2Bsg%40mail.gmail.com.

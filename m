Return-Path: <kasan-dev+bncBDQ27FVWWUFRB77XZ7WAKGQEWJ32HSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94FF5C4572
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 03:23:14 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id v51sf8936667otb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 18:23:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569979391; cv=pass;
        d=google.com; s=arc-20160816;
        b=plCIDnFkcXpvYpaVVVLYZy9HNC4xEwkiW2kScpgASX/DjXa+BoftXbrMi0CVAKpXJ+
         CAdJ1GdOSzjzPWl4gUtEXYV7spLljw4lZBAeyBxs8jGFiSnBzxBuEzK1MBOQUQIf6iJC
         NEiOf81B9dd7qm2P8HpGDVamcT1kX4nAp8bxAR6qKCqQXQ3Anc3hWVjteEI7YRV6khtp
         /7Xue1dXqpSsV4dYcY/1GBlfOi2HNvIBj/DbZszyk0HrSOloWhLpKQOJK68bLqGpk02T
         9tJTd9oWJjkQ4ZnYR5ohvhHP81P4AdosjZ8fxD/h9moLolqAX3CsrowLHOo/kZTj6P6C
         VCcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=cA2g7CVHncFlAKwB/dqiJ0k3KH+GewFCAk3rqOdTCso=;
        b=Ri60Yf1hWUzjlDIQT78AgenkT/b0ulQaHlQPrSA8jZRr99IdshM/7LwYrylh9Tc6j+
         7IbkbnxoDBa944TKjqyR2YaQX3BuCYJ/9HH65J0tzGvNn4ktOvDTFkF9WXXAbkpNgfTw
         y87i6vZcmoGN1m/tE8P8DQJjf/v5gfYVdqxMsyKG5AcsdVUWCEk9GyzU8EaCLoHO8woT
         uUk6Myjy6tlQUnIA6SGAGW//KI9V/CE8lAgcxkiO1Eb/LBNAncZrXnboC1/Jdk21DVn+
         xptR3zE1UunTRo3AV/1+J8pWkaZ3Z5sWbX1/a4vWKIh17ZBjcSsTzH1TBFNDidoO2kr4
         99Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oEyO3Jbn;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cA2g7CVHncFlAKwB/dqiJ0k3KH+GewFCAk3rqOdTCso=;
        b=j3a/B26RtqNqr7A11ZDj1egfbygfSOh1VFwOyG709IfKyP1vvGOrC0uEcTrXX4wOnK
         ZZV3e7aO7gksMDmo7Oyp4WqSBX6KcXdNlcxQcbrlITYmjOiPcy8CxnB1MS3v99Krmzru
         8welRzgS5paW4sFeTr98cOGtWU89ejYU5gDd996DBVwUKBHusuaFrrcjXkrD9wJyRjy4
         KcY2HwiUc3pcSe3Rr0CuiJ8NN9+iTn86FevL4IpzZVoJ4FFIorann/4drYli3SJ+1W3s
         G5awq2nYWnKfne/l45d1A2v8H2kGs3oUxgSR4Q873AEm9IQNT1OYYW08z4IGGU+V2HjJ
         UKwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cA2g7CVHncFlAKwB/dqiJ0k3KH+GewFCAk3rqOdTCso=;
        b=enMkWbLdBwNtDKE8XVTuirv2IJasMsKP5186cjxUKEOji6htGYhF6yoscfFVQi5jwU
         pVXfBMg3yLyO9tXKhmHChJ/eDQJUQC0WMQ1/tSWKCA63sMAZw/9ET9BCnNXvzSr7Xfb0
         mi8hjz7QAO14R/GQYn3Mub9f2H3NZ58D7nWkkJilNzOkmvhCPYIolUdZ0c9vtKamagHB
         FVZoZ14eNjEyduqJHGg9XQKhN0NgMaftIWBvbgNsxU7x5PPcGcc/y44W7gZrj42lKyeg
         cf410owcHsVclqN0AgwKZC7Ond+93ccV1gphPKO1rouW5AQeNda/LQGsrttYz/N6jm/q
         tEUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWq3LxG6Jvo8IRqPO4GXkSv0sb4CLIfPFzbpU4yjbISclGeP0e0
	DLRlFlCGKt/M+CKeYXcs2OU=
X-Google-Smtp-Source: APXvYqzEcR+MUs/tmIruBJ9Abd248Uoa46eGqIw1EM8Yp1Q5MjS3DLRx63PvpWm3gxR6PDwyzwZTig==
X-Received: by 2002:a05:6830:117:: with SMTP id i23mr681910otp.24.1569979391734;
        Tue, 01 Oct 2019 18:23:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:53:: with SMTP id v19ls149430oic.13.gmail; Tue, 01
 Oct 2019 18:23:11 -0700 (PDT)
X-Received: by 2002:aca:5983:: with SMTP id n125mr820797oib.20.1569979391478;
        Tue, 01 Oct 2019 18:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569979391; cv=none;
        d=google.com; s=arc-20160816;
        b=ueCeuvR95lp6ntogzFyvBCbHIbb+L9n62qt0nGvFMeJORB3FkHU7eygR3QJn5c3kMJ
         8OcKUyosY/+m1P7w5zgNjERkL4bf5S/6EeyIKpfEe+53ZmyNZrZQRcs7MDjBlmMGf2EY
         CCq3ndkHbBmjedlOo2QrEEqGKHjzFjZiev/D+hsvaH/gYqxd3wfzccm6Ri0Gp/6oqtnY
         F4BB4KWk8fr8C0Sy9O2QWzumz0ijOZC6oWYprqYNcta6h4zCiG03LGljwV7rDLzQZGMd
         jQuE0i96s0lY6uGT0Nse6HUgOIv4zoFFZl1plj39/TtW4TFgoLj2DRhrm8K14L2upOap
         P3Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=/C36wUinGnzT8rrY5Cyg+JNcSuMeir+tSfeOcjZGD7Q=;
        b=Wc0FmtdY3214mJ93uKUjyR3INnDCNnj87YfoQ/K6IePSHtKJ84iracz4/QYSB3es3v
         /8mQI9aX6Eg529LTbOeXKvN5PiQOOKP9BVVecS11PqsHmT4nXAI+6bUdUlQDHeUSH32I
         vVDlnd8QYvG1wSJ+dYmsTteBrZe9J0zoWnAz7B8S4vrr9L4ccbcNiHky5kL7YqukFm2j
         v/7RP8Ba/PDKujEuAXdU8g+eilMUjd3ZqvEqWJ0YkJGMwrnKSokMwdNCTyuA0INVhT77
         tka3wJPlSHiUUDDcvxrke2L34+b8GtztjeehnETpxGIL99BTsIhds/L98YJvVgl66Xwv
         78JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oEyO3Jbn;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id k184si1114801oih.0.2019.10.01.18.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 18:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q12so9395771pff.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 18:23:11 -0700 (PDT)
X-Received: by 2002:a62:82c8:: with SMTP id w191mr1456666pfd.99.1569979390621;
        Tue, 01 Oct 2019 18:23:10 -0700 (PDT)
Received: from localhost ([122.99.82.10])
        by smtp.gmail.com with ESMTPSA id ev20sm3561837pjb.19.2019.10.01.18.23.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2019 18:23:09 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191001101707.GA21929@pc636>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <20191001101707.GA21929@pc636>
Date: Wed, 02 Oct 2019 11:23:06 +1000
Message-ID: <87zhik2b5x.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=oEyO3Jbn;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi,

>>  	/*
>>  	 * Find a place in the tree where VA potentially will be
>>  	 * inserted, unless it is merged with its sibling/siblings.
>> @@ -741,6 +752,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
>>  		if (sibling->va_end == va->va_start) {
>>  			sibling->va_end = va->va_end;
>>  
>> +			kasan_release_vmalloc(orig_start, orig_end,
>> +					      sibling->va_start,
>> +					      sibling->va_end);
>> +
> The same.

The call to kasan_release_vmalloc() is a static inline no-op if
CONFIG_KASAN_VMALLOC is not defined, which I thought was the preferred
way to do things rather than sprinkling the code with ifdefs?

The complier should be smart enough to eliminate all the
orig_state/orig_end stuff at compile time because it can see that it's
not used, so there's no cost in the binary.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zhik2b5x.fsf%40dja-thinkpad.axtens.net.

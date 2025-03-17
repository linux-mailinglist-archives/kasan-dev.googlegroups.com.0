Return-Path: <kasan-dev+bncBDIPVEX3QUMRBQWU4K7AMGQEGRT4C6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B4EB9A6625B
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 00:03:32 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e63533f0a65sf6159029276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Mar 2025 16:03:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742252611; cv=pass;
        d=google.com; s=arc-20240605;
        b=hDl54Z/P3aYmUWFOpO0dYh1Ezbdi9CXLEabGijyMQewhMJ0sjPkfEdVk0CvDazf82X
         O5b7VCnVHGumETHxm2JiOsT9baHwO5/KBHVcxlaZtS4XiuTk0o3kmmFORujLWOeT/8Mk
         foQ2zqtqqkI6YoDT68+DG4B1p5hD2Ida8w0CQQoER+VC6b1710/Ycd58r/OUkfcoJQmA
         XsbbAweg23FMgpFdfg8zJi+Txnwq4EA19zOh0FgJxBe6lKWBPTaiGnwT+oiPwQhgyvFr
         t6T7sW/mHnA2VG4LXnR+df5DNafF8b1SjI28DpMzoZJmPyn/elxW4TXeafF/q0PAbOii
         /lfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=zAp8em5bzvtKi9t1gbwC1QIytQXQXEgPn8qOYz/TJic=;
        fh=D3E0uKJhssXSyoSRdjyYoP2Vregox9WkwiRzQ+ztQFc=;
        b=J7ahoaj718FaT4690NfrFBSFzjH/sletWhUjCj0TAoPmPFLv58O8lmrSRc4dwRQcnu
         /zYiCm4zsjG39yFlGqHuYKgdQIDpXS7M9B/kecPnQx3Ko30pR+kgVvMTknilfPTczo6a
         8PMSnrxSA7B3W3Kn0sywMOlZJWaVGJMGUNsNbgTy0JsO3pd3pnjdOPiZRFR5sFcGkBxI
         BV/9p0WYtwUjFcAsBxuotf7TnJBn7BGSnCuc31dCk3THhTYJ3yVwi+3oteg1V8HxFd1/
         +WvCTkbJaC4zyayyc1g5B5tBc6egc30jKbU+h2tDftLjuXzBLY6zEaC3gshrFZ/yusYM
         h8eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=o66rMn0y;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742252611; x=1742857411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zAp8em5bzvtKi9t1gbwC1QIytQXQXEgPn8qOYz/TJic=;
        b=jN7raLFMf9JqWSbhaCgH5RgQTAZFXrvUv8iNifvtlhvp8aCYqq7FGWYdRTaPrORsvH
         2bynBm8XcO0YFaGVkswXBnSeQHvo7pBL7POeRG0BUiBpymWIGuN2BGUKcBAp/c3cuBl8
         dJZCY8i4cBbQ2cQGzGRxgTBfhDNW4vvs5Hg4PwBHwcMfVUmPtp75pjIzR29WzlvD/Wc/
         YUnbIr5C64DIBn+jXqpZz8KtzhsoWaLdsFbsnE5KjzQEBTB9AGvT1KSPKgV117WI9plV
         qUpoYvaKDxj4L9jn8JdJh3tpr/LVQv8Nt5KXtQ0QD3zyCSYysuVzFCak0CGMVjnwHaG5
         tqmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742252611; x=1742857411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zAp8em5bzvtKi9t1gbwC1QIytQXQXEgPn8qOYz/TJic=;
        b=t6dtrb1JDejB2FgTe8V8QHU5LiPbyOj3XVJdSMiGgup+jE3PC5xR5cuxO3BUb8OOiZ
         e5Jqwikn+3OLz3RMcIL7/2wGMCUCim5BQ9b1ZpRodvGOK8U1R9ZnCVkCpaE7Tywp7T+b
         YORaNElILLrAxaRBS3UG01KxX+SRZ6hjK+YFFUf91YI2BMUCntbvZA5+k0bBDy2IW724
         dO0bgVFskp75yGOq3JCvCu6DUu08/fx0h7Yf4LIMxZvyN7ElWarR/DydEJCoYK7th66m
         VXuEpphY9NWNzHbaJUA6dSFFKRr0GVx3HsMhQ/XZW5uWLPmvpDkErhine7TzbECY6oMT
         63Ow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAYeWquQfN04Q8k0/t4alyK0c9hY4yV4QN6xE/FLjip9z3xey8mcF9ukcetqp8BBgwv9gLOg==@lfdr.de
X-Gm-Message-State: AOJu0YxZFpirz9+t1fs5RSZUlCDB9v8xRplUstNWBFtQXDPDjF0IOe/y
	/7EtZmJK81rkUDHMfJtXsMqicyXa/1c4kVVlxL5TWTXEuwc/og8T
X-Google-Smtp-Source: AGHT+IHsnRB5bwz4CvrZGAE0yrUY2nv3Awd843jhCygxwSI1dqOvcUycmn700MreeuZVVoqZHRH5Iw==
X-Received: by 2002:a05:6902:250c:b0:e5d:9246:ebdd with SMTP id 3f1490d57ef6-e6511b72aaamr1781280276.21.1742252611194;
        Mon, 17 Mar 2025 16:03:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJuo0ZIUu2lkmP4qu9apQHL+e4LBCFNeYyLI8ChpgjWsw==
Received: by 2002:a25:4946:0:b0:e61:1abd:b623 with SMTP id 3f1490d57ef6-e6406f81f9dls407337276.0.-pod-prod-00-us;
 Mon, 17 Mar 2025 16:03:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXX+cg4YomHXLqayeMEH4jDZFmcj13X6xgM/Tc1Akldp7iHbyg+MnlwTiBN8oOVF94xbupAo9aNVSM=@googlegroups.com
X-Received: by 2002:a05:6902:2741:b0:e5b:12f7:cda2 with SMTP id 3f1490d57ef6-e6511948d16mr2034840276.13.1742252610215;
        Mon, 17 Mar 2025 16:03:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742252610; cv=none;
        d=google.com; s=arc-20240605;
        b=Oh6z+u3ZDGbJaGPU6kjRbjXhCQba90E5Z9j/1a5hlH64aR9vHMogcJ6HqzuUkXc5Tk
         ZmdicYSLfLonJEBLuDIUPEMj+j7Rba5YVH34VxodL91uM4sC0AE8HpOHdbck5oizBEjR
         d4JmhJ3SzuJ7kf3tCxW5SvmROvHwTrpb1ePMwE/dIUsIMPZ6kug2+sX7Axrdg2jULYJM
         i7yOTacM9IjeLl+rye3e16lIL98zdn3e4DhISk4CzbWGlbAlDgaFAnvqEpOlmTHIhmvV
         tWd5jJ476dWLkHl4sRxEgOqkGOlll66s43evg1m6JZTxipHIssx2gMgw3jIYp+geRKHu
         gMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=Bn+dVkNzGPe0Z7ovmJwNwQJS6CVQZAD2/ACJeTPZJbc=;
        fh=iLnukqbs6s/VNnZ9JSgRB1avv2+g1OeICpVMZt9k234=;
        b=OBTTQ3isc7OG94jS6IuSFUJeMJIgUf4M3lSTZGLpGbrbXS2v0PfyeVWK0oxMIe+fsm
         f/vIQFlWsINVMnmiLY1EHKa//pEZ4cSdY7tdNYO6FI+KcygvXmZVYEompO30mN9TfCED
         JX+eyqCD2ajW2ektaCS9F0BD1+jioYzN+hY4PYGlnHg9j7arXQNTq8ypSm4Qc8CYPTmV
         FXfNChPrwauz+JbgPcbJ9u1zX1/xcBo7Yb2IMeXCZ/Hep0Vp/KV8vgtwFgVr3MrK4jp5
         7m63KG3MG7DU+kCgBXbKRwRlbsVAM6z/1v3r26ZEv2XFhwhaQah7HSndIwL9piuQWtTY
         yiKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=o66rMn0y;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [45.79.88.28])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e63e5494049si561054276.4.2025.03.17.16.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Mar 2025 16:03:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) client-ip=45.79.88.28;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net 331DF41061
Received: from localhost (unknown [IPv6:2601:280:4600:2da9::1fe])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id 331DF41061;
	Mon, 17 Mar 2025 23:03:29 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Ignacio Encinas Rubio <ignacio@iencinas.com>, Akira Yokosawa
 <akiyks@gmail.com>
Cc: dvyukov@google.com, elver@google.com, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-kernel-mentees@lists.linux.dev,
 linux-kernel@vger.kernel.org, skhan@linuxfoundation.org,
 workflows@vger.kernel.org
Subject: Re: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data
 Races" URL in kcsan.rst
In-Reply-To: <9c6298a2-4efa-4f77-81c0-b2132f48c1b0@iencinas.com>
References: <1d66a62e-faee-4604-9136-f90eddcfa7c0@iencinas.com>
 <c6a697af-281a-4a91-8885-a4478dfe2cef@gmail.com>
 <9c6298a2-4efa-4f77-81c0-b2132f48c1b0@iencinas.com>
Date: Mon, 17 Mar 2025 17:03:28 -0600
Message-ID: <87zfhjcla7.fsf@trenco.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=o66rMn0y;       spf=pass
 (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted
 sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=lwn.net
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

Ignacio Encinas Rubio <ignacio@iencinas.com> writes:

> On 15/3/25 3:41, Akira Yokosawa wrote:
>> This might be something Jon would like to keep secret, but ...
>> 
>> See the message and the thread it belongs at:
>> 
>>     https://lore.kernel.org/lkml/Pine.LNX.4.44L0.1907310947340.1497-100000@iolanthe.rowland.org/
>> 
>> It happened in 2019 responding to Mauro's attempt to conversion of
>> LKMM docs.
>> 
>> I haven't see any change in sentiment among LKMM maintainers since.
>
> Thanks for the information!

FWIW, I don't think it has really been discussed since.

>> Your way forward would be to keep those .txt files *pure plain text"
>> and to convert them on-the-fly into reST.  Of course only if such an
>> effort sounds worthwhile to you.
>
> With this you mean producing a .rst from the original .txt file using an 
> script before building the documentation, right? I'm not sure how hard 
> this is, but I can look into it.
>
>> Another approach might be to include those docs literally.
>> Similar approach has applied to
>> 
>>     Documentation/
>> 	atomic_t.txt
>> 	atomic_bitops.txt
>>         memory-barriers.txt
>
> Right, I got to [1]. 
>
> It looks like there are several options here:
>
>   A) Include the text files like in [1]
>   B) Explore the "on-the-fly" translation
>   C) Do A) and then B)
>
> Does any of the above sound good, Jon?

Using the wrapper technique will surely work and should be an
improvement over what we have now.  I don't hold out much hope for "on
the fly" mangling of the text - it sounds brittle and never quite good
enough, but I'm willing to be proved wrong on that front.

The original discussion from all those years ago centered around worries
about inserting lots of markup into the plain-text file.  But I'm not
convinced that anything requires all that markup; indeed, the proposed
conversion at the time didn't do that.  The question was quickly dropped
because we had so much to do back then...

I think there might be value in trying another minimal-markup
conversion; it would be *nicer* to use more fonts in the HTML version,
but not doing so seems better than not having an HTML version at all.
But, obviously, there are no guarantees that it will clear the bar.

Thanks,

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87zfhjcla7.fsf%40trenco.lwn.net.

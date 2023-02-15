Return-Path: <kasan-dev+bncBDEKVJM7XAHRB4WUWKPQMGQEX5GF6ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8AC69794A
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 10:48:35 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id t18-20020a05600c451200b003e1f2de4b2bsf927323wmo.6
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 01:48:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676454515; cv=pass;
        d=google.com; s=arc-20160816;
        b=HeMK+lD3AR6xLtgJhKwQbVzo2fmzchQ+NLxUiQW4mzfjiiaPTkDqEQ0X1cpQ39zLzz
         MlKdE8zSHpWzitMjwybHYdJm/XV9wfKyYJNo0Hj730JoGp7OCepwtQqdwZpXuJCM0fpN
         I8xuLWBJ0LFio1+/JaGNmD24lleP9CyqcN94ychKyB2Xk9FMLq0EsF6yGeMjbHrR7mGo
         K7zbWqdpQFF/moJj1G6UMsots7Ccc7TAo4aDvgdzSf2ln8vdsi8gRkXZWtF5Z4x8ZbZM
         WxLvfWXmyKP9GQb1NZLsB1ygu62M+iA4zRzsmW33OsCL6CsTWQMM4yD0wZQnO7/adiyv
         BCvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=hMMWcJgcbTReGj40G5oXPjZxBwu5l4nCCWPwMyVQAdw=;
        b=AoWl7CaT9lBX708A/XBH7JVl3VKouP6UNwE68pGssxV93frESxbaHeB6sLThVfXxVr
         tsqKDbgM9QH3B118tG/FaYyV30MV70oKPJ/87d0ZgCOwmeCk6hZEowYYgNwu2ZLEifca
         zWkspvlqJqw9IKZuk+hYeL8XPb0fZ0sa4UYQooTXx6E4NSoRFdWkluSb1JpT6pMrEIfF
         m5F/CMdfyjScuvI37/4LBiL1m+vA3kBW2lXlS/vmWjyZ2Q8iTgItyXAONrpxruNxyvxy
         9M42rNFVt5XEBBNWk8pXcAE49kjFKyV4hydhNHV9WRyUeKf/mZsmcmT8oO1tooEm49Wv
         4Zjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b="RxSH/xlk";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=PrEn79tz;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hMMWcJgcbTReGj40G5oXPjZxBwu5l4nCCWPwMyVQAdw=;
        b=IXnpH9vMGQrVwaTpUwjC3qy5duHoumvlm+7xoANLUhnqTWXLOMvMpSSVPzLa1qRbrQ
         X7UkzUpSA2L4SLYxakX7fl57uM3+DhXteRu1gzTOQhlK0b48kV1hJv1FBB/dxfXFYsEr
         LGny2F2bJ5gZdG5B6uJ0+8+s//0wUDOBLaSKqNsVs8QO0NLGy5Vyy/Ox5kwTxAZPWelT
         CmACIQKTLGmP9pFuegsFLZH9HKHy3nWpSdug6IXagvEy2XHnN2GCxSxWMzhmy83pdWA4
         zpMdILy0zmbVhMhiF8bPD1cRV4jU5NFCl7H8X6KMucz7p4Z2HSj9EWRAdz/XiFQ2Hc51
         Ltjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hMMWcJgcbTReGj40G5oXPjZxBwu5l4nCCWPwMyVQAdw=;
        b=heepfOYM2K2WvMbux/JpenvcZxJXUPHg6PLu/Eh5KGh1T0RL6Xxnc30OCgmqu782Qj
         hrFIRSqd4iX03ZKrMH22PhOXsOSKMrHfZNx9R2mdYG9Ey5+zubG2SOvxDUV5rZ/UW866
         kNyVPrwKA1cRQKi3JNyZd7sHi6jKre2KBgKZSdHWkikiOe1qjQVkGHnYBlWmMZ8/dWs6
         5PwSLGjol5ki46a1yfM2R1BGxRO0tQythWlYVeermpD4YC50rbsTc+KAL8GiklAjMt3s
         N0QX1McIhoUG8BiDraEZQOg3MYgDZmNuRIRbDBBJIquka3kYfmpAnpJ5MBaBuBKydWvj
         5CUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW3hRkrBn63WwOCop+nmeWMQ89xFKbzqx9K+L0vnzYGo92oHcFz
	uRsxa6Hz31aZ70fcofqsnMc=
X-Google-Smtp-Source: AK7set8VchHEpXFxVY3ufBUKt2FV9dkHe9pOBcKYArjbv/xC71vVvDSMI7odw5Q/Uz4V4Kv3kuOo3A==
X-Received: by 2002:a05:600c:510a:b0:3df:ff11:674e with SMTP id o10-20020a05600c510a00b003dfff11674emr181356wms.11.1676454514911;
        Wed, 15 Feb 2023 01:48:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c94:b0:3cf:72dc:df8 with SMTP id
 bg20-20020a05600c3c9400b003cf72dc0df8ls720463wmb.0.-pod-canary-gmail; Wed, 15
 Feb 2023 01:48:33 -0800 (PST)
X-Received: by 2002:a05:600c:80a:b0:3db:2e06:4091 with SMTP id k10-20020a05600c080a00b003db2e064091mr1456713wmp.37.1676454513473;
        Wed, 15 Feb 2023 01:48:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676454513; cv=none;
        d=google.com; s=arc-20160816;
        b=nRcnHh/TJiU2t6sNC7hMOdHkA/++c4kAgEBCPenNVjR/Bkl+tAA1qOBhra9h+Fq3Wa
         bLWPN7v9dtVClaWe3qqu8ZrlnxoBaprcleW+ymnZv/dMYmHJ9GCwilFFgQAQilMBp3bA
         4hGNpCChWW90D8F7hi6mDBwePjc49drnjJDt16zB9fdR6d4qNuoV3uHc1xLNM8wWXi5b
         AUN92ztBbLXnWh9rjG2KxMBgVAQEfLAAFaCuUSZOHk6ItmpFhpKsvwZyT16Kq7/r0kJo
         Ipiueocm+MywS13ZOMdisnp9RBmMudB9E3GgzggN7cB7PY7llyaV1l2qh24IUwjSWAIY
         SqnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=jLXjSQkTOn+4ktIkp6EZtl+YKLL9/WnSJEkDg2a+TfI=;
        b=dkNFTDgAXjcuBNpay/hn9vlBx7amc2MW+wIGbEU40n42u1JUBHyhFZGZVK/EfdVi3v
         t9azT+FeCYGHa9KpyJVFM6pQ6q9W6wXmSRrE1AZBq/RibwE60WgYJpwYyVrOd1wys2Zv
         vJvL0NQAKyeH+JyP7ZjwfiS/pjen+Mf2SQxmVO7tieIbMrVL02YqhsPLtjdvAN1HnBwY
         KYU6m0Fm3FE8H+15d6a7+p/ELVEkXgSbcFXxbyKgWES/2B9w/fZpdrHYLCkS+iwQLKUy
         xWBsPciw3Mi33z+Iaorpb+//bG22C73rRJtWDbK0J+Epph+e5fOpSAC6zHFaBaNb9TCy
         8ysg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b="RxSH/xlk";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=PrEn79tz;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout3-smtp.messagingengine.com (wout3-smtp.messagingengine.com. [64.147.123.19])
        by gmr-mx.google.com with ESMTPS id ay4-20020a05600c1e0400b003e20319b0cfsi44307wmb.2.2023.02.15.01.48.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Feb 2023 01:48:33 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) client-ip=64.147.123.19;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id 687A53200893;
	Wed, 15 Feb 2023 04:48:30 -0500 (EST)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Wed, 15 Feb 2023 04:48:31 -0500
X-ME-Sender: <xms:barsY7VDO506yJbtptQM4-5rQIhAOma5b98KwL-Lmoqj6ZJi9-83lQ>
    <xme:barsYzmO4tmgXsjf-9GTr5Zxo7vBAgdMl2Rx5haUdLAUIWMga9lWdGpRIBInuYTEC
    yPV6Y0oyWsjUd8jp7Q>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrudeihedgtddvucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepffehueegteeihfegtefhjefgtdeugfegjeelheejueethfefgeeghfektdek
    teffnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprg
    hrnhgusegrrhhnuggsrdguvg
X-ME-Proxy: <xmx:barsY3YcKtMWUVFhBuvX1BJA57eggeewaElBjWs_HQy1x5pHNnVExw>
    <xmx:barsY2WOK5T0ZciUgY7m7VKnN8gxoK1jaYmNflXUkqiFeAAIg45O0Q>
    <xmx:barsY1kj2k_uBe1ftJVqgrOTSgNHHhiCh3AHljEvkv2cbg3UqTgUZg>
    <xmx:barsY7UY4NuB2i8bxrs9t0wX6WhSKKQjmryrDn9SFBc1SaAMA8IS8w>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 80C21B60086; Wed, 15 Feb 2023 04:48:29 -0500 (EST)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-156-g081acc5ed5-fm-20230206.001-g081acc5e
Mime-Version: 1.0
Message-Id: <78b2ed7d-2585-479f-98b1-ed2574a64cb8@app.fastmail.com>
In-Reply-To: <CANpmjNNz+zuV5LpWj5sqeR1quK4GcumgQjjDbNx2m+jzeg_C7w@mail.gmail.com>
References: <20230215091503.1490152-1-arnd@kernel.org>
 <CANpmjNNz+zuV5LpWj5sqeR1quK4GcumgQjjDbNx2m+jzeg_C7w@mail.gmail.com>
Date: Wed, 15 Feb 2023 10:48:11 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Marco Elver" <elver@google.com>, "Arnd Bergmann" <arnd@kernel.org>
Cc: "Kees Cook" <keescook@chromium.org>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Josh Poimboeuf" <jpoimboe@kernel.org>,
 "Peter Zijlstra" <peterz@infradead.org>, "Miroslav Benes" <mbenes@suse.cz>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH] kcsan: select CONFIG_CONSTRUCTORS
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b="RxSH/xlk";       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=PrEn79tz;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Wed, Feb 15, 2023, at 10:25, Marco Elver wrote:
> On Wed, 15 Feb 2023 at 10:15, Arnd Bergmann <arnd@kernel.org> wrote:

> Looks like KASAN does select CONSTRUCTORS already, so KCSAN should as well.
>
> Do you have a tree to take this through, or should it go through -rcu
> as usual for KCSAN patches?

I don't have a tree for taking these build fixes, so it would be good if you could forward it as appropriate.

Thanks,

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78b2ed7d-2585-479f-98b1-ed2574a64cb8%40app.fastmail.com.

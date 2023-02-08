Return-Path: <kasan-dev+bncBDEKVJM7XAHRBUHPR6PQMGQECPZMIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E7AD868F800
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 20:28:17 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf8002104lfb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 11:28:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675884497; cv=pass;
        d=google.com; s=arc-20160816;
        b=VNuZYujFFfh2KteY5jhN3vF2Sol87IIn6DzmACc8jX2pbF64aBDQjrUM54oj1tAjEh
         ShMiGCsVBkVb2YQgvRUgu8X0V/w9KWs4S5pRlvj/DEp01lieTP8OCH261p3BKcfD/lc3
         DUUMrAmqAbjBMMtUX7YSTN316TbhiakbXVYD67ac2zLL7TxIMUcZYX/UGYtd1Uksix5W
         PH45C9Z7VWBzLIy2udK/dauaZxA6Pl8IB4zePYDSwXRx87GSEBb/1cQiIOsBe0fiTeNe
         BEFNX/CwaEsvi+IKkODAQ0xpxHnbg9Ua/QSSIcYCCvJiL2V2W+ZB2LnATIKhmCdXhb5J
         WhPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=0dQ23eTmJGAwdTcqmzNwKB5se6ULVaKfL1suXfz9/YE=;
        b=ESfuem9/rIZeDql14esN7Rl/wE1IPpg13/C76Mu9OYwDM9OQnRwG7k3FBV5dVbip6Y
         ceaY7Pj66kCDsk3KvDxDnB6EVvtGnK4sHI/Y62sBtmfmKS+4tqt7wUrWoPmKmF/gPazJ
         sKz8Lui17O09CROoALr+qb63iQ45ORz8W9rzFRuBlBXBV3Hf6fleJYXenbg6C4bY9BXc
         6WqddrykCK+QCjL1OXFnXYX7fr1glKVtBF2HpfgZJz/OIs4a7qwQApS0pbq0aJEmXeWl
         NKe9qG8cq/fTKakULoempd/QGhNhVeMmH8ddg64VOE9bCNK9212Iqd1SMdLwkUoSDR1i
         TNkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=qP8CIUu4;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=NuDLXNqn;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0dQ23eTmJGAwdTcqmzNwKB5se6ULVaKfL1suXfz9/YE=;
        b=tRPuEqeWk3C2SRAAfXBGBHylbtsjDYtKsnfWpXqe6s7LflYeW0cyXGdJAWAIfTUpTG
         ka4ZvxgpmMnDBzZPTgXyNiERLF24Bn6FaFfW3jwd/jtsVR3mPcWYDzXKuxMRUk9lk9CU
         +yfbgzTOV2/BT3tRNFcdw+a0020sWoUfayz2Ktr1uINzPz49klEfZ6Zfzr10WwlovewT
         W0uhZ56yIYiCsYisNWek4ZL74dT+Fl3+EMrHullB+eb+T2IaWHZk2zg4xkk0/qjk1WC2
         ABNWu7WcQqrsr427gW1BQVcWV7AOodkZrtQ7Ux8wGVqxSk5FbhovdPMRATM5/4fvXVdA
         EDTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0dQ23eTmJGAwdTcqmzNwKB5se6ULVaKfL1suXfz9/YE=;
        b=e2H33B3sRoO24NDRWAsRxzJSA3xl3ImMVHLOgNU2ZiqIzscJ3AOSmMgAOQeLpNy5b3
         Pdh6AhqbEpeboLaSKMDhT6F183ufRXj+O2L01ubrdHinxNYCEKEWm7rwblffobPX53PE
         /s4+LieEZvWafph3Tw9BD9uHSil6QqNVV+dpluf4GytkqOBi6gcfugY3I33GYMmyS4P3
         O1XWSmSjhfqWw4MEB4MTXrW6sIQEYt6CoEmzEUjhgxtOJd6VJPvZQ/Cwd5w1zwxrjo87
         1RhT271N5mVSV79YLECHtNERfYUmrXH58f6XoM6YOw0cG6rOgnZTrV3IEqZJ+WrO3AWP
         9qBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW7g13Z5oxiITN6mvAN8wbqWyGCHcjdBHAdw1O9aKVaQFN8u2Y0
	57RzEZCiqmjV9T5y8geFop8=
X-Google-Smtp-Source: AK7set8Qf/sJ9LEleBN3ARCykxwBS9ROgc50m/3UTo/tCJhFTW/pRkPTPkFcdjdumS/fndlrzOhxbQ==
X-Received: by 2002:a2e:8554:0:b0:285:7172:61ff with SMTP id u20-20020a2e8554000000b00285717261ffmr1766111ljj.79.1675884497035;
        Wed, 08 Feb 2023 11:28:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4006:b0:4cf:ff9f:bbfd with SMTP id
 br6-20020a056512400600b004cfff9fbbfdls3451010lfb.1.-pod-prod-gmail; Wed, 08
 Feb 2023 11:28:15 -0800 (PST)
X-Received: by 2002:ac2:4c32:0:b0:4db:194b:5a58 with SMTP id u18-20020ac24c32000000b004db194b5a58mr952226lfq.67.1675884495247;
        Wed, 08 Feb 2023 11:28:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675884495; cv=none;
        d=google.com; s=arc-20160816;
        b=LhJuqA0HlhZ0M1qdr7jEugyjS9Q/0MGIYQGO2KCm59T024SlsPhNj1T+vYAPkrta09
         ivizVjFlhpqvAp5BbYO8D3sFOWevhJjaHgEscjgWAvFQWo4dZcU52pOzRWYtRCpb3gsR
         RLvPQIYjieE8G1kuiY6MY/HHBziKIviwAY1znDQkteqcpX6NhHLWLngY37Q0rVfRT7QE
         rwnri2zvXeQPNMD1EhSynmJtL1JUvdW9nmJpQUYb8l9arzI5oYkr6x0oC1906P5thifv
         +WmsROeSUC0ts/sxcrV381UOPD/yrxB/Q7DUuVF9BQ+/0p1Kcfq5t5IZ95ks1r+CeLJZ
         94Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=WyBBIxA586qfgVO4ILEoqSpA2h1Vebgs2QIOv9Zb3Go=;
        b=U5Cf+wHRYl3Xz53ZeyT8XM8TaxUK8yHFjDtN5DYQalJsm3fh3a8+phpnkEwXCkep6x
         WR7wtEzBhH/lU4gZruGGIKmXsztYZfFVE3a6R5gVrJZ/tsRvP4Okz5TAxwpOzje5jjDR
         MG8LvIlBs/IR7Ja7NcRrXXBRqaI3E0x897ypw2YYXCmLtFMlphwDDudSqB+HDfwFFdGt
         b3jNR+SBlhmmhnaIm7vI56DMaAcbI+tipa9ixB0/DL8EAUfJeI4SvpVKCKOJVQYXR03f
         4cCZ8bF3OVU7k36m0s1jTIfATmRVMIO0z7ovyhKOAJM/aexdGO/aufCBZoQmxbFEkaSu
         dKZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=qP8CIUu4;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=NuDLXNqn;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout4-smtp.messagingengine.com (wout4-smtp.messagingengine.com. [64.147.123.20])
        by gmr-mx.google.com with ESMTPS id bi39-20020a0565120ea700b004d57ca1c967si815047lfb.0.2023.02.08.11.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 11:28:14 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted sender) client-ip=64.147.123.20;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id 5FFA63200918;
	Wed,  8 Feb 2023 14:28:11 -0500 (EST)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Wed, 08 Feb 2023 14:28:12 -0500
X-ME-Sender: <xms:yvfjY-i0BRFOJFcqnkIWqNP8fZdixU5WvTVbvjI8ZFK6kvRnW34UNQ>
    <xme:yvfjY_CSzJ3ldjW24Rl43KQPUPolm57SGERfqJT1RR22rbH9_8I1ZyKCt53x0zmrD
    bnh4wcvVyTFWR2Mat8>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrudehuddgiedvucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepvefhffeltdegheeffffhtdegvdehjedtgfekueevgfduffettedtkeekueef
    hedunecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenucevlhhushhtvghrufhiiigvpe
    dtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:yvfjY2GIvogaw1sNrbMHYmY25SLh27G-g0kS0Y3oih5GB9NcamQ6HQ>
    <xmx:yvfjY3Sj9oPLB-nUhwtr1qJnDQAoMqOAVNBvgKMqhZC-NpKTfpyi8g>
    <xmx:yvfjY7yUEUrrxd0AVldEjkjkteszk95Ug1zL8yjSJgx87ydriULFMQ>
    <xmx:yvfjY-qgDcBLyHh4OoFOpgZsCWmOGv-9bpQhQQCniS_nGvnxyE1Wzg>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 34197B60089; Wed,  8 Feb 2023 14:28:10 -0500 (EST)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-156-g081acc5ed5-fm-20230206.001-g081acc5e
Mime-Version: 1.0
Message-Id: <7c257b67-eb7c-4395-a710-818ca1c34b48@app.fastmail.com>
In-Reply-To: <Y+PlZi8mrHray92j@hirez.programming.kicks-ass.net>
References: <20230208164011.2287122-1-arnd@kernel.org>
 <20230208164011.2287122-3-arnd@kernel.org>
 <Y+PlZi8mrHray92j@hirez.programming.kicks-ass.net>
Date: Wed, 08 Feb 2023 20:27:50 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Peter Zijlstra" <peterz@infradead.org>, "Arnd Bergmann" <arnd@kernel.org>
Cc: "Josh Poimboeuf" <jpoimboe@kernel.org>, kasan-dev@googlegroups.com,
 "Marco Elver" <elver@google.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, "Borislav Petkov" <bp@suse.de>,
 "Miroslav Benes" <mbenes@suse.cz>, "Michael Ellerman" <mpe@ellerman.id.au>,
 "Sathvika Vasireddy" <sv@linux.ibm.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/4] objdump: add UACCESS exception for more stringops
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=qP8CIUu4;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=NuDLXNqn;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.20 as permitted
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

On Wed, Feb 8, 2023, at 19:09, Peter Zijlstra wrote:
> On Wed, Feb 08, 2023 at 05:39:57PM +0100, Arnd Bergmann wrote:

>
> Hmm, I wanted to go the other way and remove __asan_mem*.
>
>   
> https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git/commit/?h=sched/core-robot&id=79cdfdacd5b8d1ac77e24ccbc178bba0294d0d78

Makes sense. I've put your patch into randconfig tree now, I'll let
you know if that causes other problems.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c257b67-eb7c-4395-a710-818ca1c34b48%40app.fastmail.com.

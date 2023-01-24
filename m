Return-Path: <kasan-dev+bncBDCPL7WX3MKBBSGKYGPAMGQED73CMBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1C6A67A6B1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:10:00 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id k34-20020a05600c1ca200b003db30c3ed63sf8101840wms.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 15:10:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674601800; cv=pass;
        d=google.com; s=arc-20160816;
        b=HuozKQjUXGIvx4kifZqhS69UVFgKtqGV0/s6w7cfwERwpliBgIPTG/DIFGEaS/6lBQ
         p0SJiRZD+WgEFU6PlRHEScPu6sKxX34wK7PAzIpU2c+b2/bADKyEAIY2cIrkJ1RWNKG5
         z+WbLcUhSnWxhGHxg2yoyR+rqSIV8QI+KXeIErsJExFmhfN9CXtnPUdLdn8ZwubJFrTL
         4VbLTy5y98klKTdQPQOSGS3sVqmuhgxmD2dCTRweSGxb8eSfW2Sqe42fqpVkuxoDgBMW
         0OcFlS/x2RCj2o7pWlJaCDYm6moPE7ldS/4HlJ+xMUJUILvibImZ0+DeYip0LwECee0g
         t4rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=E6bERPQSZyxC228G5ptGgf1wmTXniUB3gJ6HCEqjJTM=;
        b=Phih+T6aa1fzrDHxR+uiSqGf1P0gxSCFZs3nVxRwvsF6scEVbOniW/Xr837mIt9TDk
         ATFj/eZCMBDkNtp1na7N+B00ssxLLKBg56P1zBBxK6126ztOxm8iVATbS8x0Hs7vMlty
         P756rNUmRkMO1/fWZC0Eg+pVnhr1Bb+Yz7dBp9ryDToaGLDJxQLzrkTgiro9Fevzgj/i
         HWNaMuzOzqOIZ8uy9OtIkpqLVMzWY6IWmwZwJeiiZv3NxQNRA4DgFUY/wBzm0XaZCBmO
         g1Fj2/TvgXRuM3mPalBWd6JORdVsd8mPUjpzmHxHNaaDAtmMIdZVwOwv4zA1z0SdxuRO
         K9Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pcdTUIPN;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:references:in-reply-to
         :user-agent:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E6bERPQSZyxC228G5ptGgf1wmTXniUB3gJ6HCEqjJTM=;
        b=DH3jJTYZOOybzcJ+HHEcAswpyziIcDQ6t8gD6whVnBlrxClOUr8DaxuUruSOIK/pka
         Tjs5+uKljMTJtsun0Y5pSN+LtTc+WxjD9xY0Wzk4+5+t8YVJFy/Kxw/Ip8sy3Ml7BY/q
         Fo4D4RSKwH0jnYgUs5G/fMmanne5zgSGDtdGH6eGJ2EV0/NA2/LnhZTCfrig9VwDjLDB
         NoZznGXRNJ7EdAUCBpq8IA47zPiaJBUwClSSII4MLoEKnKwqG6uAMXQSHLdFaWDoDwgV
         n2v3GVcR+wPrluwGqHiKHyVl2ZSilYnZWgHtHIRuRR4KBfRAOozYdzN0y96/OJ+ik6Vv
         HFAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E6bERPQSZyxC228G5ptGgf1wmTXniUB3gJ6HCEqjJTM=;
        b=QmPtO3j6BywP7z1JlEQFBGS4Z/LxtzK1SGsdtS9q+6Llxmyp0j1Cad2ZKgOX+chIo6
         69x0EH/UTTb6+qMncbt5xMMwlIcTq5le41HAPtcK00k6+1cEiHsxmJ5uTXV+FHk+XYUa
         wLDzn6eitkmxViZvjzq/N7Gy1pNm94VmUQvO5ISIlh1LT+PRjMCs2gNBu73KkeJGS392
         ajrOHLlAl5Gqv9ZFT1tWcIVxbIvXuASx/pbE661i3NkwKAQQbdKyIxXmCRnDI71lEE8p
         8z3b4FgxsgiD7gVDKarj3uCgrts+qrglRayoEtcoTkUvINvz9ZKvcIupkavHY7jT/GWO
         FvNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpPEAKC0R3MXUsE1LLl4E/HE81wKH4FWoJPYrRh5aKB74tG0GyI
	mFUQCrNquXRLLWXlFTra1C0=
X-Google-Smtp-Source: AMrXdXsQfHp/SmuV0f3bnlHDKfIZxq5WkWHCh5E/E0F1OYVT244KIhJSOlNwoKr7kmqoSR3fbunIug==
X-Received: by 2002:a5d:5a99:0:b0:2bd:f375:a55b with SMTP id bp25-20020a5d5a99000000b002bdf375a55bmr1029418wrb.328.1674601800402;
        Tue, 24 Jan 2023 15:10:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5124:b0:3c6:c1ff:1fd with SMTP id
 o36-20020a05600c512400b003c6c1ff01fdls91102wms.2.-pod-canary-gmail; Tue, 24
 Jan 2023 15:09:59 -0800 (PST)
X-Received: by 2002:a05:600c:1d89:b0:3d9:f37e:2acb with SMTP id p9-20020a05600c1d8900b003d9f37e2acbmr26521309wms.20.1674601799371;
        Tue, 24 Jan 2023 15:09:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674601799; cv=none;
        d=google.com; s=arc-20160816;
        b=L/ZzscsPIK5BxcUNJ6mX3ZZI33tAxsaB7TUviyDx5ZySXikDmrrFs8MjV1FJVSp91K
         BTXaGnryot4avSGm8Gw48CgxWAaQnyVci6uatOId22b8f8vTkB/4PnXnxbtpLTU9c1WD
         Ag5bRt8fra+ZWWA2QggvfhkpH9NY0vhkYabFUzzuh+4lgwVrL7IzRx0SsA7v5PQyvENK
         5PWpaHy9uksOkLyg4Byoo74SuqeyOx0TdmvYYz99dcl0bxfKu+LsBRxnWB2LELFeHE3s
         is1Z0UwwEoxwHRpQpA8Z7vBWl/TtxD4gtgy2aeqHevgJSHq9PADL6IbHKtJ/3HSLjfnm
         5OUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=wGkrTvwbUrvsMXFde+BwpUrtWLtdKcEhQ4ZYux9Jo2Y=;
        b=AplwiArNTIJxMWZ/3swe8Asme4/6cZY8bIcmYlF7bs5AFjFuPtkzbh9DvGq+W3Ejz1
         ennR6Y7FTv/sCL5pXJa/zAjCaKGzZryI2F4FsIDZTYYhOb9NZLPmJ4tHqErAX/QvlT0e
         RQQQrvF6Q3s06OqV/kmRPs2gKMZAJJuNWxdTfBMoDtWBhkcFuvFeCiFuWcHsB9vX32VT
         xGiZMGZq/MRSt6F8q6JCBHBmlg4BK6ch8pzxGsANyjWqLebplmVKJPRuNe/aPlBcgFC8
         h54BUEQI1kGB9wRdJNwQ9BTg8HKZ8wwixxtojqYKGa2RksPHAEtX6qKrnvrYDong0sGe
         kIqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pcdTUIPN;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id r22-20020a05600c35d600b003d9c774d43fsi205745wmq.2.2023.01.24.15.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 15:09:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 13912B81683;
	Tue, 24 Jan 2023 23:09:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9BC5FC433D2;
	Tue, 24 Jan 2023 23:09:57 +0000 (UTC)
Date: Tue, 24 Jan 2023 15:09:51 -0800
From: Kees Cook <kees@kernel.org>
To: Eric Biggers <ebiggers@kernel.org>, Kees Cook <keescook@chromium.org>
CC: Seth Jenkins <sethjenkins@google.com>, SeongJae Park <sj@kernel.org>,
 Jann Horn <jannh@google.com>, Luis Chamberlain <mcgrof@kernel.org>,
 Greg KH <gregkh@linuxfoundation.org>,
 Linus Torvalds <torvalds@linuxfoundation.org>,
 Andy Lutomirski <luto@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
 tangmeng <tangmeng@uniontech.com>,
 "Guilherme G. Piccoli" <gpiccoli@igalia.com>,
 Tiezhu Yang <yangtiezhu@loongson.cn>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 "Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>,
 Dmitry Vyukov <dvyukov@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Juri Lelli <juri.lelli@redhat.com>,
 Vincent Guittot <vincent.guittot@linaro.org>,
 Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>,
 Daniel Bristot de Oliveira <bristot@redhat.com>,
 Valentin Schneider <vschneid@redhat.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 David Gow <davidgow@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
 Jonathan Corbet <corbet@lwn.net>,
 Baolin Wang <baolin.wang@linux.alibaba.com>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>, Huang Ying <ying.huang@intel.com>,
 Anton Vorontsov <anton@enomsg.org>,
 Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
 Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
User-Agent: K-9 Mail for Android
In-Reply-To: <Y9AzndICHRElk4jI@sol.localdomain>
References: <20221117234328.594699-2-keescook@chromium.org> <20230119201023.4003-1-sj@kernel.org> <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com> <202301191627.FC1E24ED5@keescook> <Y9ApdF5LaUl9dNFm@sol.localdomain> <Y9AzndICHRElk4jI@sol.localdomain>
Message-ID: <E5988762-D1D7-4C8A-ACC8-E623D4B29A11@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pcdTUIPN;       spf=pass
 (google.com: domain of kees@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On January 24, 2023 11:38:05 AM PST, Eric Biggers <ebiggers@kernel.org> wrote:
>On Tue, Jan 24, 2023 at 10:54:57AM -0800, Eric Biggers wrote:
>> On Thu, Jan 19, 2023 at 04:28:42PM -0800, Kees Cook wrote:
>> > On Thu, Jan 19, 2023 at 03:19:21PM -0500, Seth Jenkins wrote:
>> > > > Do you have a plan to backport this into upstream LTS kernels?
>> > > 
>> > > As I understand, the answer is "hopefully yes" with the big
>> > > presumption that all stakeholders are on board for the change. There
>> > > is *definitely* a plan to *submit* backports to the stable trees, but
>> > > ofc it will require some approvals.
>> > 
>> > I've asked for at least v6.1.x (it's a clean cherry-pick). Earlier
>> > kernels will need some non-trivial backporting. Is there anyone that
>> > would be interested in stepping up to do that?
>> > 
>> > https://lore.kernel.org/lkml/202301191532.AEEC765@keescook
>> > 
>> 
>> I've sent out a backport to 5.15:
>> https://lore.kernel.org/stable/20230124185110.143857-1-ebiggers@kernel.org/T/#t
>
>Also 5.10, which wasn't too hard after doing 5.15:
>https://lore.kernel.org/stable/20230124193004.206841-1-ebiggers@kernel.org/T/#t

Oh excellent! Thank you very much!

-Kees



-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/E5988762-D1D7-4C8A-ACC8-E623D4B29A11%40kernel.org.

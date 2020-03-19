Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHKZ3ZQKGQETFH5JCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21A4718BF0F
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 19:08:14 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id y12sf1138649vkd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 11:08:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584641293; cv=pass;
        d=google.com; s=arc-20160816;
        b=BR2//eHArTRWEHYZe9Ie7lIFdGv7kTVmFFI7fywVqyz7mgWlM2l/ywe7pRmREDMY3+
         ALCVm/QEqnVEbw4kG6c0rTRVmbiSDNECzbSdAoql19ChOxyLlGddlgcYA2jRDpwH46NG
         LaNutrBM/5cGEMcYp0T15TKC5+yhkO+u2VYHG/G23LSuvkcLr6ws5yCyw25s1LVE9fTO
         hhPl9X2f+kGdrtNPdEFfBVb0yMzW0NpT9++43405wyqC0+alYBade8DWtndYS7MUglN7
         g21tDevWA7n7F8AWh4IWvSv5HzFroA8T7iB9Ub2ESHfcqSpZqiLBNHau611QZUAmOTWh
         Jy7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=X9DnEban8tQ4aaVvejnRD0Mrb26mJeoujsIhqZ4vDuw=;
        b=sDcRcreGe7QVAEhU3sTSKMvCRg6vFIVsPXczA0kjbYf71Tfxvl66HIvBspg3O5jWWI
         VCoI0crphWk/y6uRiRWWRqBqYyGRfd1Uk1Zv22c8JkScbeXGwUKuqKRE+MMg/qqpcTkk
         PkEYffIsSNvjIi+6Ow4GaB/zmdQjDdMR2Bct6XS9M3/mGTsZfUpMSjjK9eOs9pCw1i/0
         kuZfRbWKYtDCZc8qd6J5+lCOBefCoEfJVRde8ytfd361fzRgveYxx88zlIZl766IdPhq
         WPVzGaaZmSTk6bSF+IORX5iZlHTyEy1ffSSHywbbZIYLLS7c27jZJeF5Tp9Aot1EWJB0
         xVww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=awMAcpFJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X9DnEban8tQ4aaVvejnRD0Mrb26mJeoujsIhqZ4vDuw=;
        b=cNZnwGKSwy2U/wYhe3aGKrNjnEKdjydgqOiyGTMWe5QoNWUaGLvC3iFsWnOZdbOsT2
         2Yybppl+qHB810qrA341SLUOT0cuFfz/iGQCCeorMLSaKHN7xI3wk6eM9IxjRE1LM1g3
         eP/SLdA9LHLZQ7m0GuHUaXk2lATTvh3o+nl+7NNRud5y8Dk2ii/KIFMCu7jD/1+yQ1l+
         oGRRcnkavLI+DQOYxPhyohsx6lnDxoJWMwtF9r35D+kPSmyg6ZisMjYr8OMHPBDyBLS8
         qqrQuuX6lXJr0RlMd5RtlbYf4SD+g1V4t5QRk4fvkELtDcF9rlRLWJ/1CHdzYqxwd6AC
         cknw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X9DnEban8tQ4aaVvejnRD0Mrb26mJeoujsIhqZ4vDuw=;
        b=VwdxkIkTUG+E9XUDc6kXbRaFQpuVVl9QTfJiZrVZjWXH2GQLqA8sz8yhy2LOH/gPoS
         zkb1OouF3Qtag4Nov9uQu1YZW7ccH5mwLwRjkGFexxAvPPIJfCZN5eFavlWfj+wYaMec
         8nLxc4HNBHprGWFR9OJ7+mM0l3RDydufSw9wEhRFo6FmDX2BWqNnzSHD44tMeP+bNqNh
         2kWOh4FE8PS2eohA2oIJUcDvO24GQJ3ioxl2ZMxLb1TaxaNj/I0oOu4DYckszTtQK0U7
         2XA4il6BjUDXbV/13NYsY2Mtuhn+cftezQJjF2ScbhJQIjnz8cP0eLeTKJTK89qkodOZ
         frAA==
X-Gm-Message-State: ANhLgQ0puSYUNgFnIJcUFZK8di2DScPJK9EnI64Zal+zXD6b5zWaND0j
	9A3JjJAYgKQBc4qIMtlRXrw=
X-Google-Smtp-Source: ADFU+vsR4Fi/yiC7b9tOnlnZ7Lc/Bh0AuBE9YRp/JP/nhLvDQwqV1G0giWnAUcgrmT2BAfgoeePsgw==
X-Received: by 2002:a67:fe05:: with SMTP id l5mr3075760vsr.186.1584641292815;
        Thu, 19 Mar 2020 11:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:320a:: with SMTP id r10ls485116vsf.9.gmail; Thu, 19
 Mar 2020 11:08:12 -0700 (PDT)
X-Received: by 2002:a67:2dc5:: with SMTP id t188mr3092190vst.3.1584641292334;
        Thu, 19 Mar 2020 11:08:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584641292; cv=none;
        d=google.com; s=arc-20160816;
        b=xlj1Jk8t295uf5n0+N0XtWC4SZwQtAczTm6HMxENwY2PwTXno8XZjBMF5K6MIjK0x2
         5xtiGy1p797EeTY6Jq1vbwyKbrZmalu27y7F9cG6nZ8xCFCrJP6IPIVutOUq2lfXs6YJ
         hG+/w7Tc/jYQRRpX66EF6l0zaL8dUNIyykwOeKTUdpjJjZFAIZtLRomn4YOW/UhR5QIQ
         gBeeJm7SO1+aoa5X7MneZdtYOFFCOTMiXnqIemJte26yrpWhddbk91GQsEnmipHXZJc8
         4EvilBwUm86fwpcfA3hLNZb0yRDKv/OTBfBM01dmXsEohBwDWy235MesrmL/qH9WNadh
         xXGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4Xu0QrQlsjdldwRC1nps46N1nU7pCt/oK3/9Wj8IKiw=;
        b=GzVV3pS64+y6PHBH3k7sXKNkTKW+zJWxW4wr3/vXyHy0V6AEavp1wNy/GygnX+uHN9
         FSuiVS8lhuHloJSgIGaKOxeuTY8uUS6Yop7llTofMNlUUZuyezV8UDe6XOtWq9EtVg93
         6jQZMKyUTpwHgXpGOb1aCkBD2bAO/uzfhzGRxnK8nZ+ZCGZQiyBCr7a3JCJaUlElT9/H
         4aMIBKlwkOb3o/Al9dtitaT+CWm5wGmCx3KNotAHM9o6eeFRv7cFfKCWjZ7YZlVQJtu6
         sJg0eFoRXIZGg+5EhUtZiNkGIQ5EnKl3CqBvQEejQOB63jFBlJNFvAv5R7ccY5ifUp96
         fBRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=awMAcpFJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id w12si161948uaq.0.2020.03.19.11.08.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Mar 2020 11:08:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id e9so3311740otr.12
        for <kasan-dev@googlegroups.com>; Thu, 19 Mar 2020 11:08:12 -0700 (PDT)
X-Received: by 2002:a05:6830:150f:: with SMTP id k15mr3149803otp.251.1584641290618;
 Thu, 19 Mar 2020 11:08:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200318173845.220793-1-elver@google.com> <20200319152736.GF3199@paulmck-ThinkPad-P72>
 <20200319180245.GA17119@paulmck-ThinkPad-P72>
In-Reply-To: <20200319180245.GA17119@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Mar 2020 19:07:59 +0100
Message-ID: <CANpmjNMN_-bfqinOMG9_FakPVYx_Rk7nQ=AdkW8H6sAAdjxZPA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Introduce report access_info and other_info
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Qian Cai <cai@lca.pw>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=awMAcpFJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 19 Mar 2020 at 19:02, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Mar 19, 2020 at 08:27:36AM -0700, Paul E. McKenney wrote:
> > On Wed, Mar 18, 2020 at 06:38:44PM +0100, Marco Elver wrote:
> > > Improve readability by introducing access_info and other_info structs,
> > > and in preparation of the following commit in this series replaces the
> > > single instance of other_info with an array of size 1.
> > >
> > > No functional change intended.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Queued both for review and testing, and I am trying it out on one of
> > the scenarios that proved problematic earlier on.  Thank you!!!
>
> And all passed, so looking good!  ;-)

Great, thank you for confirming!

Thanks,
-- Marco

>                                                         Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMN_-bfqinOMG9_FakPVYx_Rk7nQ%3DAdkW8H6sAAdjxZPA%40mail.gmail.com.

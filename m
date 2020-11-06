Return-Path: <kasan-dev+bncBC6LHPWNU4DBBHWLSL6QKGQEXCQSJ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 448E62A8C08
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 02:23:43 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id c17sf2634404iom.20
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 17:23:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604625822; cv=pass;
        d=google.com; s=arc-20160816;
        b=nUK+YaLUmpYPqEggqHktLSi3zZGbFWSIfhWUgqvo6h2tSvorDYDPMnKTIeOhZizlti
         ltWaD8FY+hgPyS8nyDT7STrrzMjxag458720MMleWSBJqYyqV7lX+F6YtchjwfxmBsyl
         3A1evzkF8q7jTTAorjHGlDMnPvPOcDx+yX6AdpU5DgwfpkMUud2F3wCy4CQFLjZy3dX2
         vcAeQbiSxuwNhmbYJwmnCHSSXfH/Uy1mnyqhKEpVVw4Kc6Hg6irB5GqfZgybFDg1r38i
         2B7mNe0DrCdGiiscrtMTnuYBdSe8/1kRwbt9qFnKf5J3hqKTyQGidXlmWh5B6STVmSGw
         QVmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=VL/0v3jG+61ZtrOpUxI7WrhS8bX1xUiVW94CNofYuQo=;
        b=WUxc/lemh8FLL00leE6nv7LqyUBZAQJfXanPDmH+sspNCnG7+T3E046Anl5hmP8ruc
         zQdERCZNzRQMD8DAPSIiopzuVORiLqPwZfILk7tTQIfmTPufr5dxe1TSQ+KiIhZWhAdL
         xeVT15l9BgWQSeWmIRg0hx+GnarDpO0C6gxbNIwlc2EDhr8OyGw4g2FfDcFJhTGG0Y0y
         jqUsmpK/5sRJyG7Q9NBo0HGK30nsfY0bHZFbgEc1wjhBWvUIwZZsyRlPc0TZMDdP4OW3
         ZIw3n9imDc6fgDU6t+mVKu0WnXQkPGZPC5TteKf/K6zJFne5cmXtPGjsEd7+oxy8tGFr
         6PIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nDwz7Ekg;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VL/0v3jG+61ZtrOpUxI7WrhS8bX1xUiVW94CNofYuQo=;
        b=mGTzepsRjgzuCcXDTw9hhtIYjJwI8gPKoyUnHxIhc4CBa7+SpwEUWYdZ1z9ScOkS2d
         vulW/KimVhDY2S8T71vTXEIH5TlxEMgCaHN1M0brTMPq4YHxb2t53LXudHytDy10QPff
         TwuuYt4QMP720bsTee/er8Z/3Q1XdTBfJLRaOdDnTqX6dk4f4M2fbYDMdaNMu6Wwg6GD
         PSXr3K1Z7JRxQ0/ouw224XgHY3SSz2Wg9PayQrQA0m/2dseVcdl3edO4WISfK5aGmY+W
         Gycw5rmSDzuHlp38zM/VTG+w4uVckt7q3Y96fwcmBP5u0b7Bnwwm4XjW+B2ub0ZPCed5
         r/tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VL/0v3jG+61ZtrOpUxI7WrhS8bX1xUiVW94CNofYuQo=;
        b=DIrf1Enw9FSL1Q+bLI9CLWCF+BDDb5kfmqWJjv8xxttdWkd/H+01h+crXxUTj8y34H
         /UMqHQBLjH0b0oGNZ/GKtIWlbc8PNsXNK15KKS0tP3r7Ukvo6893Zt+yeOYMfwS/0tXb
         PG9Xos8yHVjHaDjqHmuap99mgAq3RLSa8/gwUa0KnVYI0234ewIqdxgVV4Qox3XhvPWw
         gm9C0ZvrH9s+Lq2olLpyTECPBHg9ogGuyBHI2o3RM+lbbq3T35LWQika18ippNIPGC+n
         tSdn2jdnL6oqyMp0ZVi+CNxH7GcQwRQr1OXf+Fau93sVdt+vjxVOPcBicGhWZ9UAxn6w
         j7XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VL/0v3jG+61ZtrOpUxI7WrhS8bX1xUiVW94CNofYuQo=;
        b=JeyVb3KnFhv2NGeEjvJigV762u7rGh7qUU9UBf8MA/SWYjNmJPzUMjYanWA2SlEKGL
         8l2109xnbqTVyAjl/5OoTVd1FjosFT8bAVnMhIQTOGrXTjU8a2S5JViXDqJqleXKqoFb
         X0aGLF2fXjiKztJHkb+x1L0efJSyLaHN7/3nmRiYhZ5ZdiqUjtdztd7gZ18H4744EwlC
         /1Yf6HB0WrHWjVdQ6gnZLMZOBbdGI2Pu40gUhi+Ka+Z+lhVVK2XsqbrJs3noVE8iR2IQ
         jbxA6TqHLnko8c7QAb87mHVyn7DK0bbd65oEQBDywvPQV6DUzDooew2pC/6nhX0VSdKh
         rUpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n0VZflqle9bQNVbQ4mm3uvD8Lv1vnqn3wh7UOAJ32Acn+sYvQ
	FHMNYJprr4MIutBwJNiFU18=
X-Google-Smtp-Source: ABdhPJy3KP5dvkjl7NgGN5HP7eNkss1YUtN2SD+n9GO6mUCd/qt+8JXuxAqouaoXl9NLFdBKWvyLWw==
X-Received: by 2002:a05:6602:1214:: with SMTP id y20mr3779214iot.190.1604625822144;
        Thu, 05 Nov 2020 17:23:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f41:: with SMTP id y1ls744601ilj.2.gmail; Thu, 05
 Nov 2020 17:23:41 -0800 (PST)
X-Received: by 2002:a92:d346:: with SMTP id a6mr3864256ilh.245.1604625821707;
        Thu, 05 Nov 2020 17:23:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604625821; cv=none;
        d=google.com; s=arc-20160816;
        b=pNv6D65Rwq1fSgnSGmsCxcb+SlhNhWiZcurO3inpp8wvLcf7J49ZVUWWtCfI6hOZD5
         MgL21m6e5VoxWnwpyh6/DThiyBSo54WRM9XeKMW75fa1CsqYK8NFcyAacKDdXywJA7yJ
         bN9JJvMFHAfgc8Tks7if6vW7mMr0yM3nTPhrei0nzG+vplhYkY8Q3CNZNlcDkYqKB7FQ
         OOv+YRSc14tlA7Sg177PSJ1SXz2xvlI3YwHmK2CkLw00ze6Amp/Fc1rtrSIYJyG9DOGQ
         LQ6zc/faMmEplO5iEOOYpbGuVijo2OR1y0xlJNV45lvbyMYHrgQpfbPOcx3PpjVXfZ+z
         lJ1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=taXWeBFo+wT7XX0MW36Hk3wvn7TPVywWpoJuQSvy99I=;
        b=z6nslnN9wnhvnTTWQUWittp4SVWCzmBQ3WnzyhXNfQ6WEyPMtq8vXm2AwA8AOvZEv6
         Tz40PPjghtCAD8/tOxhH/ONi84zWmx25JBZHoXJN8doVTPBF6qXDfpgDrFAWX+1K26jH
         WfaKp/+cKdjTxZjhuWQNjgAgnkrDDv99sUOpcutby1DdQQwAxme3dM2q3zxtd0BgSPuk
         +IbAx0cnyyMWeoy4Ujf7D/8ppZTOewWC7rLQ31mKSCHRscfF+zCPbfFNvi8fhVF8iIEZ
         YE1kJETF5NZSwg9RDX8ff+jgKTLN/EMrqBpziwn6cQ/thWlSJYPk28IlHq40yrfsCEg8
         nLzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nDwz7Ekg;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id f6si175031iob.0.2020.11.05.17.23.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 17:23:41 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id r7so3193940qkf.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 17:23:41 -0800 (PST)
X-Received: by 2002:a37:a308:: with SMTP id m8mr5050191qke.126.1604625821246;
        Thu, 05 Nov 2020 17:23:41 -0800 (PST)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id 64sm2051768qtc.92.2020.11.05.17.23.39
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 17:23:40 -0800 (PST)
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailauth.nyi.internal (Postfix) with ESMTP id 1E1D327C0054;
	Thu,  5 Nov 2020 20:23:39 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute5.internal (MEProxy); Thu, 05 Nov 2020 20:23:39 -0500
X-ME-Sender: <xms:mqWkX5V4B4vtXh9DligBtEkbjfYxntdfcTdJVA3QjlEjqvmtQBOCAQ>
    <xme:mqWkX5lR1o-RVGZaUd4V9Nva0bbD_3Q-qEvFjqiYmEgfkTiZal9ohUwNhYpIHhOlu
    F8EkJ2HH-nLemOUAQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedujedruddtkedgfeehucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucenucfjughrpeffhffvuffkfhggtggujgesthdtre
    dttddtvdenucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehg
    mhgrihhlrdgtohhmqeenucggtffrrghtthgvrhhnpedvleeigedugfegveejhfejveeuve
    eiteejieekvdfgjeefudehfefhgfegvdegjeenucfkphepudeijedrvddvtddrvddruddv
    ieenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvg
X-ME-Proxy: <xmx:mqWkX1aM_KmQrfn0F8bGHHmJqfY2h-GdnLYP5PdNfitJfIVZv74x3A>
    <xmx:mqWkX8VwyH6qN_nPzBJ2-AsjH1Oh-IjwK77bLgVA8X10kdgVuPmTZw>
    <xmx:mqWkXznGiBiJowNaxzmrAWvgP3B9_uykjyjpZFa80biycbL6IqUKuA>
    <xmx:m6WkX1423zDQd6I3QB1QO_tEkZGBWNvb5bsXVxM4Ub7KSA8MlbXcdyA1xhU>
Received: from localhost (unknown [167.220.2.126])
	by mail.messagingengine.com (Postfix) with ESMTPA id 2426F32801F2;
	Thu,  5 Nov 2020 20:23:38 -0500 (EST)
Date: Fri, 6 Nov 2020 09:23:35 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: paulmck@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw
Subject: Re: [PATCH kcsan 3/3] kcsan: Fix encoding masks and regain address
 bit
Message-ID: <20201106012335.GA3025@boqun-archlinux>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
 <20201105220324.15808-3-paulmck@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201105220324.15808-3-paulmck@kernel.org>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nDwz7Ekg;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Marco,

On Thu, Nov 05, 2020 at 02:03:24PM -0800, paulmck@kernel.org wrote:
> From: Marco Elver <elver@google.com>
> 
> The watchpoint encoding masks for size and address were off-by-one bit
> each, with the size mask using 1 unnecessary bit and the address mask
> missing 1 bit. However, due to the way the size is shifted into the
> encoded watchpoint, we were effectively wasting and never using the
> extra bit.
> 
> For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
> bit, 14 bits for the size bits, and then 49 bits left for the address.
> Prior to this fix we would end up with this usage:
> 
> 	[ write<1> | size<14> | wasted<1> | address<48> ]
> 
> Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
> size and address respectively. The added static_assert()s verify that
> the masks are as expected. With the fixed version, we get the expected
> usage:
> 
> 	[ write<1> | size<14> |             address<49> ]
> 
> Functionally no change is expected, since that extra address bit is
> insignificant for enabled architectures.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> ---
>  kernel/kcsan/encoding.h | 14 ++++++--------
>  1 file changed, 6 insertions(+), 8 deletions(-)
> 
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index 4f73db6..b50bda9 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -37,14 +37,12 @@
>   */
>  #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
>  
> -/*
> - * Masks to set/retrieve the encoded data.
> - */
> -#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
> -#define WATCHPOINT_SIZE_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
> -#define WATCHPOINT_ADDR_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
> +/* Bitmasks for the encoded watchpoint access information. */
> +#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
> +#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> +#define WATCHPOINT_ADDR_MASK	GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
> +static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);

Nit:

Since you use the static_assert(), why not define WATCHPOINT_ADDR_MASK
as:

#define WATCHPOINT_ADDR_MASK (BIT(WATCHPOINT_SIZE_BITS) - 1)

Besides, WATCHPOINT_SIZE_MASK can also be defined as:

#define WATCHPOINT_SIZE_MASK GENMASK(BITS_PER_LONG - 2, WATCHPOINT_SIZE_BITS)

Regards,
Boqun

> +static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
>  
>  static inline bool check_encodable(unsigned long addr, size_t size)
>  {
> -- 
> 2.9.5
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106012335.GA3025%40boqun-archlinux.

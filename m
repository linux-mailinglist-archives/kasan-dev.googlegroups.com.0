Return-Path: <kasan-dev+bncBCII7JXRXUGBB37OT2OAMGQELWRZMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3336D63E118
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 21:05:04 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id b47-20020a05600c4aaf00b003d031aeb1b6sf1420255wmp.9
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 12:05:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669838703; cv=pass;
        d=google.com; s=arc-20160816;
        b=XYzkOqwJ7CGiTAAU0xxnpfVAYSy/SCQSL75Ih0BnEIOrHaefb6mysrd9WPo39qBR6w
         6l6K8qY//OMDiz5DforqYrx5Jm3osM8sVRnLThF4NAUoysEWsGVh8bRQwLTvWmvLo1iN
         ZPErNQAeUKJqOEgZMncMDAWCbMcjUTeZ0aktwSUlb6QKsG2XhFB7y8ryY6g5QAP4C8sC
         7LdQ4SadJ3dLgA/a4NbYClfoaEepNBaFb04ZmXm3YgasrPejHu738sqUcQ1cFtX0igOX
         72zatHB1j8V1fEctT3VpGqaHpvvBnXJaKzv3kGOHrpKWpy6tZUsEn4VhLr5hjhsrc/Bt
         Th5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=L1xwlZ77XfGrlPGNnJSAXT4PLZgwaWU/CyZfjQKnlt4=;
        b=AAxDIDYJ4afL4tIhM+sPAEVhH5G7a0usCGlFWjpFX8RiCiy6gOfbsDxeWt7iaaWQNx
         JLK41dOpm4QAUixZH/tdYhtkGQN36Np1jI9j+AzUJD7EzSWDxO1ToclzERxpkvqDUb+Q
         aTFISbcKo3VlNNpKJkP8o1wG40asDV3GE99liiIh9OmusRH4+V440dSlRXmHWLkeyfEf
         WoK/AlMQ/WJ5WDCommXmxvUIbuX42aYtyB0Tl7Rnnzkzll6m9zim8EEoGaRAP3JJGfEV
         VfOcioOPD+gUzycFM9WG4qgFJxQFs4ZoPiaqTGac8vjPAhGsPeUxYM0zpn6fcsmbCb4K
         TZ3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=v2cakNGE;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=v2cakNGE;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L1xwlZ77XfGrlPGNnJSAXT4PLZgwaWU/CyZfjQKnlt4=;
        b=Yn0/H6fex0d+TlR6+3NaIFyfZWPJfpFpzThYin05xlccJ+s0JabutSghrRotnLgAo9
         p8XL+tx/ZRyogRwPZ3Dmdojo+ut8sHNMQpOvNYHmL/kbGYW29fR6nLaoX294qL/Om1Qr
         QsknE8A8AQ5xoUdVtH7JJ8tSqnBMqUTuACdgslIxe8H7uOcoNW6nu8wJZiyqBKC1OtOU
         L6UB7DxjFscr92zsHovzXvKjScJBjz14GyAZJf4UFpWT/eQKQBbKdFhqD8Dd3DTptdXD
         q6hA2ckTcfMOjt5zrtTataLlDEvrbj5oYPfoO3b71RtzDtMVGLhkw6Wa0YLe9Z+REkuP
         7eJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L1xwlZ77XfGrlPGNnJSAXT4PLZgwaWU/CyZfjQKnlt4=;
        b=JggEBvxYkWfvDmxK+fUqwGxoycDhlfdExsH5xFgNgtDAEsSWUjn7qBsrroLaVN2osh
         iUbA07DQyq0W/ycQS8do1IASkM57Z9bd0/4awZZrEN89BJD/AbZjK3RdzoBzUHfediwE
         02khkrpbLyzQuy1UC5V6k3zkqlsD+3d7Dqq2l+sPbTDf9Zdml/3z2EWuhU0FL7tfPfis
         XczXOsz+gZU9LJJIDgMeQsJBH/VFyQ//k51YOka5y+/lhUPQGb6csAz6rdip2fViwVql
         0o0Cx8m3fJFXk9bTF5H+3wprPlgGTXA9kHvkd/pnZjOtPXGBE/oLR14uVFgRXZozeq6c
         grow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pndJ2O2BbKT5rK6YfXiFnTcPm0e9lH0gWGV3OAZqoznGPP0rB1q
	b9tvEYS0BQNHi+gSpx901dI=
X-Google-Smtp-Source: AA0mqf5NX0r7DPkRfWglkaYkSnnaNDdFMXvBtqxyROnnOzT638lVrCWgIHNLZNHyWF/3VzdlQmZlEg==
X-Received: by 2002:adf:fb01:0:b0:22e:6556:da75 with SMTP id c1-20020adffb01000000b0022e6556da75mr34009273wrr.653.1669838703386;
        Wed, 30 Nov 2022 12:05:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20b:0:b0:228:ddd7:f40e with SMTP id j11-20020adfd20b000000b00228ddd7f40els9244570wrh.3.-pod-prod-gmail;
 Wed, 30 Nov 2022 12:05:02 -0800 (PST)
X-Received: by 2002:adf:ed47:0:b0:242:322b:503e with SMTP id u7-20020adfed47000000b00242322b503emr1326257wro.695.1669838702343;
        Wed, 30 Nov 2022 12:05:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669838702; cv=none;
        d=google.com; s=arc-20160816;
        b=xeWefraxrZOv/RKnzUE5vZXhxINmA6Bxs/OY3r+S9EeEgphIN1gPRKjfRU4cD4uCIt
         nJHDh4WUBqiCu7F1xRzZBrS22a9uc5tc168+3mS/l4K9bwWrTcW3L/zCYe0DI8n4LGbk
         P0a6p5uio+SL3bRuWDkjneIPoo5z8/hIR94kq0FyfaJCKb13fvtOHepvkRlGdKVU9nxr
         ILKdx8tZWrv3CX/gXnL/MakoCGSwC0TtnBDZ3T9SNuwiycgubVIDk23Y9KAdGiDUrJqA
         2Qqh1WUOdXtjSMRhpXNojF1YIpR/kNdK1OMMJt+Yt1+Z+Mdmh3tPKB7bL5+Ore540W9q
         IoCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=PrVpEb8uC8MO75/KKnPwfTD4c6f26p9EYuEmyToPrZc=;
        b=FIcHp58sWLpgzyawVeRbmw69bVvCYC/7jrfA+3ls0H3uzBv48DiRlmzDWVy3DRRzfw
         H+xc5jm4BpLeWsThjiSZFfQpN264wUcVPDlNBVM3F1QZ6NwCgmkGtojWLZpxfPAz+HB0
         Qs3ptiI5CuAlocjb3QB+T5Ws5QQkfzvhvQ8UbP2MKuWsEXVTGLHxrnB0FIlGjt3MR/5v
         flpeqcvkkiyaNpBWlPf1AxT1QLKOL7xmr+so30iSmr4LnOC1GIHTj4z4NGeuVTqb9xAh
         xIJSlYI0XWsigi/hhES+VkDLQdEnvyCq5i3PHGbGDF7KGHnb0DYBVm0ePgqIUIoYG8og
         1zaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=v2cakNGE;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=v2cakNGE;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id bn28-20020a056000061c00b002416691399csi105515wrb.4.2022.11.30.12.05.02
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Nov 2022 12:05:02 -0800 (PST)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id 6CEC1C01B; Wed, 30 Nov 2022 21:05:10 +0100 (CET)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id 02960C009;
	Wed, 30 Nov 2022 21:05:06 +0100 (CET)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id 83fc1053;
	Wed, 30 Nov 2022 20:04:55 +0000 (UTC)
Date: Thu, 1 Dec 2022 05:04:40 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Marco Elver <elver@google.com>, rcu <rcu@vger.kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Netdev <netdev@vger.kernel.org>,
	Anders Roxell <anders.roxell@linaro.org>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb /
 p9_client_rpc
Message-ID: <Y4e3WC4UYtszfFBe@codewreck.org>
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=v2cakNGE;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=v2cakNGE;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

Naresh Kamboju wrote on Wed, Nov 30, 2022 at 09:34:45PM +0530:
> > > [  424.418214] write to 0xffff00000a753000 of 4 bytes by interrupt on cpu 0:
> > > [  424.422437]  p9_client_cb+0x84/0x100
> >
> > Then we can look at git blame of the lines and see if it's new code.
> 
> True.
> Hope that tree and tag could help you get git details.

Even with the git tag, if we don't build for the same arch with the same
compiler version/options and the same .config we aren't likely to have
identical binaries, so we cannot make sense of these offsets without
much work.

As much as I'd like to investigate a data race in 9p (and geez that code
has been such a headache from syzbot already so I don't doubt there are
more), having line numbers is really not optional if we want to scale at
all.
If you still have the vmlinux binary from that build (or if you can
rebuild with the same options), running this text through addr2line
should not take you too long.
(You might need to build with at least CONFIG_DEBUG_INFO_REDUCED (or not
reduced), but that is on by default for aarch64)

--
Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y4e3WC4UYtszfFBe%40codewreck.org.

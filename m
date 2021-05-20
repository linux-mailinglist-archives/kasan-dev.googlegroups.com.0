Return-Path: <kasan-dev+bncBDQJ7AHM6QMBBKUDTCCQMGQEX6UTPVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 124BF389DE7
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 08:28:59 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 129-20020a1c02870000b0290176ef5297e3sf2607624wmc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 23:28:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621492138; cv=pass;
        d=google.com; s=arc-20160816;
        b=OqBES7fhZFKVGMXBcH4ubO4JHtSCr4VE5KIIddC/Iz9PiAZCrL5K6sD9hrPxBLmzgV
         DA1ugu5HF4IsW/1nIQ0UvipR4hOaQATknAt5dRMXhQVSqqhv/lA4nS+JSWGynq0NQ4Ph
         IRrFK+ZE+OigZOaDj5F0EdpA0IVDhJjBWWOc1i5M9KLhNCErYb5D2lQmFNZ2heFaNYZD
         Im0GQ8tNGPBMs4PLoNd9vdIIwunUeGsueOq4IiMSeGtlbHM9j5obeh46W4UZhkRSfajD
         3zZiBvy1DO2vv87Ly8PwieXw1V8XVdXIZOoxidh0pk71QTC+cnnlYC2UdVF6G3R6Nx/n
         Nq3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mMpgQch+njuMgZlCAGBnUPY0SxZ7oVxx05A8hNE/T5k=;
        b=M/oOfVbivQ88DaMLHEAUnPQFYTtBpsup6ZoHQvlvNP4/pSfxPuzFBB1BKpL9CfkI0j
         O+rucD9t2dKG0PUr+wH23fOTfB1XkGZamMQIanBnwR6zZXqPTdLRHsTXyLt3fIYpWAiw
         GwVDBjja41ZAZTAPuc7+h8EJkTE5wTCk/7G9870F3nHrMhFZNaDWekyLqd6S0TWiSChV
         o9O7eEdywQ+BXhSUQefy/UyunpTu31OoA8RFrh0Lxe5Jx2fSZOQaTLIFiaj/4nfJwOQ7
         86QNYyUM/zMULXmPUK8Glo6yDX3hnQDa+OEN8XwBvob05VTzx3YbeXpGOy8qefV3jIN9
         LnNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mkubecek@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mkubecek@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mMpgQch+njuMgZlCAGBnUPY0SxZ7oVxx05A8hNE/T5k=;
        b=QgmCNYUj2XfXm5niPRSCGci+U/k3+9j8b4mVGsth75PjOlJQgQIBeX5ECQTIs5KyGG
         PoRA/GNZtP2dq58pJJa/vCekF1odnKwwtvE3wHI8ykEs71jZ4DnAQ1NcuX8xUguhmReW
         8EEhebLtS4hu6KHMbOAuxE5n7K+VItUuNyOlgnSJku5WSAeA1mReme8oi4DSgYkN1SAn
         k1+/eDa3BsmgmBLwjtPhuekLRGnPJL/NTOt3JBE+5X/TRE2UPotrG8wAYdqbRSl6KWvk
         pKYruTRQeouqehfQonTUcIwJtVrlVD4LHtOmKLSbZuLkL8ym7fJBssikuP7tWauVo1/w
         lnbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mMpgQch+njuMgZlCAGBnUPY0SxZ7oVxx05A8hNE/T5k=;
        b=h9cZ0nUO4CDdcPrEKBtBIiZv1rLvQGhfwECN4Alq9cYFKtQNbRlrDZPEvaFZu4gnyf
         OaW/hGKBtFIof7WfTJ+7eXhYhNjbAN0dvbXu+BmZllntQ7mXsv7+N4eJ1nsDm3bQG97C
         hOxdezNNaULMzSuyZ82sn6V401qUvLcX2ONVDG45l4ws930K++pc3o8xa3ArDmm9BaKm
         9RKBVBu2EfqW8c+PlQg6FUXcJdz/nIo4cTBJQSTlpPtuq6R5Tnle8/FCAmKu/K0YkeTO
         aGCon/X4jewmhQ8vHZgxYhg3CGL4y/4/OhVjbon8WGBAPLJ/3h2zaT9N/8akHpRGfJ6G
         oxXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321uWAqjpEn9gp9wpGIbmTNEF7HHCYewBDVwjtekgNNKulypAGG
	h6KYv+8hAUn7rboFnxUXgtw=
X-Google-Smtp-Source: ABdhPJw9FRD1zMsIfYX/4g8sbI2Eml0ND5ZWuW+lNd5l6nQV922NAuN/mnJ40CZNMcABigeXR5kV+Q==
X-Received: by 2002:adf:fa42:: with SMTP id y2mr2495640wrr.12.1621492138815;
        Wed, 19 May 2021 23:28:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:11:: with SMTP id g17ls642565wmc.3.gmail; Wed, 19
 May 2021 23:28:58 -0700 (PDT)
X-Received: by 2002:a7b:cc15:: with SMTP id f21mr2417318wmh.86.1621492138004;
        Wed, 19 May 2021 23:28:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621492138; cv=none;
        d=google.com; s=arc-20160816;
        b=nQVYNNq6CIWDvYJZxJZx4qMXC1n357WOdBMIZT1w13aU9cVQmWIVjlHNWuCRxLBRGh
         +ESOuvM91wNUa/xoyrt6IQ4+X+zyFngStFhiV1csZ31WpDCzuIXEkOZTfgZaYsxxCAAY
         1ByVIvHLjPxUHqUEY9I1tyiod1R/qFgPKnDkERdb7u4CPpSBhnyMX55fBk20kLtXfPYj
         J5UuBEKy/OAZq21dT6sQsemUPzwkcB5hyXJfczJ4tPqzWmQYZFtt7BunEYAAv2t0bl3u
         U5/FxbAEvjOHKqDBNXRuOBc5xDwabHc9A2lJyRvxR30pmrAEXZqq/lkm/uEvAmdqn0+2
         8IZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ZhxODq5D1G0O9zNEkCE1S6C4cNHDYxBluf4r50lkcu4=;
        b=PBUNPTEKUQxOnC/Jt5DcXnAVxX5xuRtdrbnctpcwtIcPndjpEFV+6+gvOBnFbLVaub
         DHG55spVqH8iLRTwJgDJxuXJ8UyCq3Z+JZY2MCrraKavs6NJ7zrQFJ0IIYSoSSdsWlqU
         xkByS/uagtF+i2NXJ/CqYyNLlSiJti935oE2pbpbqZ7NB8Gl/xbdBipPKgR4LLq1fMK/
         h1tS1I3RjDATTbWopBRC1PIwAQNsFi1H+AWEBQvKEgs6dlwuSHiPvjDl57LRtqPVqjmz
         v8rZEkBGL3VXsA+xprNrAyyd1jRzVgbSlisvNKuRy9juI8dLMCLe9n72Bj714GpTPIRV
         zZEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mkubecek@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mkubecek@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id l5si51449wrs.0.2021.05.19.23.28.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 May 2021 23:28:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of mkubecek@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 95150ACC4;
	Thu, 20 May 2021 06:28:57 +0000 (UTC)
Received: by lion.mk-sys.cz (Postfix, from userid 1000)
	id 6A0B060458; Thu, 20 May 2021 08:28:57 +0200 (CEST)
Date: Thu, 20 May 2021 08:28:57 +0200
From: Michal Kubecek <mkubecek@suse.cz>
To: Marco Elver <elver@google.com>
Cc: tiwai@suse.de, Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Feedback on KFENCE
Message-ID: <20210520062857.e3tbhfv2skzyw6n3@lion.mk-sys.cz>
References: <CANpmjNOHSRdZWYcGOZeURYUMuVoCJhrLgWaMLh6VpHahq+GFWw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOHSRdZWYcGOZeURYUMuVoCJhrLgWaMLh6VpHahq+GFWw@mail.gmail.com>
X-Original-Sender: mkubecek@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mkubecek@suse.cz designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=mkubecek@suse.cz
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

On Thu, May 20, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> Hello, Michal, Takashi,
> 
> I found: https://github.com/openSUSE/kernel-source/commit/5d73dc73e62632289a04bfa6c6b60e2d3732c8ea
> (via https://gitlab.freedesktop.org/drm/intel/-/issues/3450 which
> mentions KFENCE was disabled).
> 
> In the interest of improving KFENCE based on feedback, we're wondering
> if there's more to that story?

It was motivated by performance issues, in particular the load on idle
systems. For full discussion see

  https://bugzilla.suse.com/show_bug.cgi?id=1185565

(that's what "bsc#1185565" in commit message refers to).

Michal

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210520062857.e3tbhfv2skzyw6n3%40lion.mk-sys.cz.

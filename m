Return-Path: <kasan-dev+bncBCU73AEHRQBBBZOGYWMAMGQECWBQBTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 140715AA563
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 03:59:03 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id f1-20020a05620a280100b006bc4966f463sf850622qkp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 18:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662083942; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtKIzWfICLvjgY+OIYnGhUPLd2PWe/AkZRsRMOat1FYdCEwChJoRpp/1e9WRuTy/s0
         6+cZeVsYDc/3CQfAbCVykqGHwaJIPh9Z0fAugQdBeNunPkskR2nGpVesz5ipFrq7yM9O
         aQKEZw8XVK2rfGE+LKLySErRaTiWzSHfgzUshJohdQr5HV2w5s24KbBrgqaU0eCqWPjo
         SKwfP6GHbcyns7c1QPadU1Om1GUz7p99l1VM1zCIJYWpUyvdjZ9AVtfeafZn01hncRQX
         tGM1g3slPaXBBp0yhgNyJNxXl+t0DQMMWfTiLL8awI8GEPPAy3ft4c04pKI/8SOUDuiD
         3Qbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KUZZvk62K2xmanSXwztbR0lA/U6aDpFU5hfOMpjENLM=;
        b=thY0aLSa2E7X+UZifrFoTPpWex5Ax+KKbCQHk0x00AlBIJPbK/Jvoa6A0vb1y4Vj4z
         wLTeYfkqEr9KdraE14j3Dg+tpTlhbVBBnOncjZ4tq1WRarx2Rtw+UtAzAn9jEoeoKhCW
         5elWXc3S6/TzakLsUSkl4tNo2jc7oNUGCGIYRF0F/4HTAgRnkTwZJY005jnRG2C40KcK
         p2LgEGLP45sE94JHBcNCR9eJRlQOxpKUM0b6VmEk3IaN79TDGBrLtU/+UTZNDEPU8p74
         qMzcyWioFi1scB/Hh7v2S4/LOFARZQIx0Uk4vPu9ilqOiprtEFpuF9GF5jM6sYDxqgkK
         cjiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=KUZZvk62K2xmanSXwztbR0lA/U6aDpFU5hfOMpjENLM=;
        b=ECK/6w4oCjKKWsWtt5075c1qLjjRsYbC3A8+kAHCJ0B+kl+ftogXT17HbjO7CNeLMY
         L1FgBOMIqLMpy9mjaO34dU7fy787UWOB7UfWBz5+eb2BL3izE4+XRrpR2M9p48wWwa9S
         CIRXnTtZl+3KjHVnFUCOploZpHmn6ikEAbdMq0Jd+FKglsigEeHNtDaBWw4cXqUhcvs2
         B2IBoyKr7LRdkYKyXTvoJ8j5mGr4RKwU3L/FXVKl1gOrIEr7C1oZzR8TdII2q9Bhbrsx
         Re4Wtt5UsxL2ICxxXL6NLLy+BmIDESTRQ4AjZ+XNZjmVZWHmgGWUx7okfRVI+h9jUAY8
         N9LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=KUZZvk62K2xmanSXwztbR0lA/U6aDpFU5hfOMpjENLM=;
        b=jeT6pkvJb8gkp3QfrF0FFvrV4Bw1ZXeE93TOERkyv1HmhgcYE5qEViaVwEpj6oidpY
         86NzEN2AdWgqJWJmNomqwhSnkFE6WmqtHCDdATqx5SGRg3GK/KuzxumcDvWqZqx1sYG2
         OsWU7AjVzKuSDnXrzYFuWwcNh5xne6da/qTOvk0FiACA1cScdm2ziKX3Fgf440BDzRVo
         z9qEUT2YK0Gevvlm/Lu3JpJeguTm06rIEf67UmkozPw7GP+oHKXisqxn5qQsTKgRGMlB
         SB5aOqZ/bAJC+ZRVIQo9uHWgVvme1893o2g7XTJXuliH9DVcDrblcTdUqRaRJKQl/vCT
         iF9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1NuOMxHo2up61wL34rYdFLxWC+o3NgnwE4hZ7qb9t2wu+a0tZ1
	AK7SIntH4O/XO84yW4H1Eok=
X-Google-Smtp-Source: AA6agR7ijEMUSylxdWPRtvbGaRmnPenn8aVOQ16dAO/VgxZYH7LKN1MgPoxQ/k1SP41lZCmMWhfTKg==
X-Received: by 2002:a05:620a:27c6:b0:6bb:2802:21b with SMTP id i6-20020a05620a27c600b006bb2802021bmr21170887qkp.20.1662083941863;
        Thu, 01 Sep 2022 18:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a90:b0:344:5024:9200 with SMTP id
 s16-20020a05622a1a9000b0034450249200ls2728948qtc.5.-pod-prod-gmail; Thu, 01
 Sep 2022 18:59:01 -0700 (PDT)
X-Received: by 2002:a05:622a:394:b0:343:79d8:2e77 with SMTP id j20-20020a05622a039400b0034379d82e77mr25839644qtx.532.1662083941358;
        Thu, 01 Sep 2022 18:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662083941; cv=none;
        d=google.com; s=arc-20160816;
        b=t7BKNc4BZEaB07KnuEgFIGcTu2xTQY2xTzZ6JjD7YFqpzEtRdadZFEE/wtdgJ/xUaN
         oeKAcXBmZqfaDYrqYeq+PezMUJrURldx+8GD4dgfUUJ+rvZijLTJYO/fQTMDqnF2cndz
         WmjJoPiFM/8sYtxFN4QjYSxbJMWlfbvz8eIu5tFU6yGmk33J2cwuz3JT8CFTHXhJSC6U
         YQ0rFtQYF47fJAhIgjehV2uNTGS3jACqlKO/cUg1Eqfi6o89U3X5+FO9+0EMOv+utEOD
         PXxymQy1gvnycda5AWWl6sg+UwLyQDSMuPkVAk4rGxe4wDTajlvInYTMSHpx4m5V0iGe
         xjkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=bw4xL27WFFH9Vz9PdSJxGK8Db/JrmpVUZdq9RcftICQ=;
        b=GJVOmK6KTCyHTAqHdjSR+qIat6t7DYI3ZezFl11vTnC058jD1dmRV8pBDRz/6FSBjT
         Ggk0V7AHPYNq82jnoana4uruUdL0eLbacUHCljmvHNafzxlclYc7d+5TPk7iQF8BU/PL
         dgSjLnsG7Ae68ikjS+3HmZeyHUCtg0w3QH0c1LMs8dlTovOxMZxGeMK26rclgm9jEUHF
         SZqNeALgRdRMdOW3YtxnQIo9zjyBn2bIZIoD1H06CJ/iNiJHQnIxc9A7Wkg9OsLmOBrI
         kcgUauEZK4W+XB2u0nol/bMnQMDwHuFNIMztCVaCcLUM+61TNmunaE+rLpm5Un9+rCCy
         7Ssg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a4-20020ac844a4000000b0031e9f437bf4si17425qto.0.2022.09.01.18.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 18:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BE59C60DE9;
	Fri,  2 Sep 2022 01:59:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 171BAC433C1;
	Fri,  2 Sep 2022 01:58:53 +0000 (UTC)
Date: Thu, 1 Sep 2022 21:59:25 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
 jbaron@akamai.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
 iommu@lists.linux.dev, kasan-dev@googlegroups.com,
 io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
 xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
 linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901215925.59ae5cb0@gandalf.local.home>
In-Reply-To: <20220902013532.6n5cyf3oofntljho@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-28-surenb@google.com>
	<20220901173844.36e1683c@gandalf.local.home>
	<20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
	<20220901183430.120311ce@gandalf.local.home>
	<20220901225515.ogg7pyljmfzezamr@moria.home.lan>
	<20220901202311.546a53b5@gandalf.local.home>
	<20220902013532.6n5cyf3oofntljho@moria.home.lan>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=n35v=zf=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=n35v=ZF=goodmis.org=rostedt@kernel.org"
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

On Thu, 1 Sep 2022 21:35:32 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Thu, Sep 01, 2022 at 08:23:11PM -0400, Steven Rostedt wrote:
> > If ftrace, perf, bpf can't do what you want, take a harder look to see if
> > you can modify them to do so.  
> 
> Maybe we can use this exchange to make both of our tools better. I like your
> histograms - the quantiles algorithm I've had for years is janky, I've been
> meaning to rip that out, I'd love to take a look at your code for that. And
> having an on/off switch is a good idea, I'll try to add that at some point.
> Maybe you got some ideas from my stuff too.
> 
> I'd love to get better tracepoints for measuring latency - what I added to
> init_wait() and finish_wait() was really only a starting point. Figuring out
> the right places to measure is where I'd like to be investing my time in this
> area, and there's no reason we couldn't both be making use of that.

Yes, this is exactly what I'm talking about. I'm not against your work, I
just want you to work more with everyone to come up with ideas that can
help everyone as a whole. That's how "open source communities" is suppose
to work ;-)

The histogram and synthetic events can use some more clean ups. There's a
lot of places that can be improved in that code. But I feel the ideas
behind that code is sound. It's just getting the implementation to be a bit
more efficient.

> 
> e.g. with kernel waitqueues, I looked at hooking prepare_to_wait() first but not
> all code uses that, init_wait() got me better coverage. But I've already seen
> that that misses things, too, there's more work to be done.

I picked prepare_to_wait() just because I was hacking up something quick
and thought that was "close enough" ;-)

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901215925.59ae5cb0%40gandalf.local.home.

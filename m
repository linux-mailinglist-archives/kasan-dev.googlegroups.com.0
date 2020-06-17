Return-Path: <kasan-dev+bncBAABBAP2VD3QKGQEKVMASWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D9FDC1FD15B
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 17:55:46 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id s1sf1938188pge.16
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 08:55:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592409345; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdC+OC2x7JgVlNeIii4Lhs6PXkJ+T8TrSKCQDdi8PDb9eGglEQNHmYJc/hbj0Foo+4
         0MZmeAsRkCf/oSounA6bGc0Gstzid1HqFHCQlA5uSoniAtmlfqKazkDwB1GgCU1PqkoK
         CY4cF3Do1er3L3jI1IebQ1e5ZMqbi6UxrBo2o/9sDOdn6Ph0PRlcSzs8xr65Fz8JWb5q
         VpVEQJeVnt2+b8It2Q3R/Cer3+pNrWALPj7q7sXRobrZldI1IOvXfs5ckab2V0w8c6VJ
         e8HI9NFBvpZyBpwRyJfTHZzCIBd/xyrgVjidWk9za80jfj7DHC8zWWcmgRu5cmkfaiEJ
         6Xmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Q5z56gaW7k591dGcWDEcwfjVwHOqeXc4K/GtXizWH7M=;
        b=pCYV/q1y0owWpNswihD3OuIML6dKBoe5Snp743V6MCLfxUOfeTd5Q5UYVuUwqu5sJX
         eYPpL2p0f6YpfdgRjxcR3zUc/vpe/rqhECj5sv2LMX4NKh5qzuIP8y7KlTie0NgZAH1L
         DeIsk6sLT2nTjoK/4u9n4i/0pGZ8HIdwVYX2UJ5Igk7DB5GoH5Dx5PXW0NIt0DYB/bD2
         NMuVooNtxkcHgieD3q6bGzCXIXO/TMKbDGMxt6R7Yuft7SFVDeUhPYdQ0qIkreyEz6Iu
         a6KoiO/rnpcolN/Nll9+jeOu15ce6X5zLxi9rj1oZfRXtu84iSRpJkDAm45ya/GoJskO
         fuBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bIcNkACR;
       spf=pass (google.com: domain of srs0=jfbq=76=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Jfbq=76=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q5z56gaW7k591dGcWDEcwfjVwHOqeXc4K/GtXizWH7M=;
        b=VBWskWJfIiZedlTsrA8UyyRfgt5jQlo8ZGE+fhnbfU3N/VbPVejYUzcTCpk2sQ5M34
         7H9eMI2mvQ9c0WArLcurk24mCq0WI21ugVa1tAJ6l2yturUD0e9S+Sj0Y8Q+V5ciucms
         k2c5ZVHS95mDQn337FVPZvGHJeiOzHYb+AxpCwfKdqgkOlL87hppIaWonZ2QJAOBTHwS
         DkAx8Uh/ALZR5e2JD/mWWJbj/aMUh2/nJHqcL+MQaSDyKHjzUSybfUbvVHPp80T88M/j
         A+ZuZtuGl+jYyS/Wj86NcQYZNgk0cVQTUCocX8erHEtHuSy3pv9BI3RBmHbV76ZI0Nmc
         AAIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q5z56gaW7k591dGcWDEcwfjVwHOqeXc4K/GtXizWH7M=;
        b=jp8Lxh2B+/c3bZ4+7LzwGqJENtzKdjJ2SE4x1GTfcKs3nw8GDuhPAIvTOHgB1WpB9a
         2S7rnucwvFTySEuzxpVexkMCtWPmlqAHl98rnUc5ISn+jRv+x5ke0eMiWbw5VLrB7Gfw
         gyJutEiAemliIv2KRZ6ycaKYPHSYTwfct1JLqciRVp6ayMu9paLfZTPZrzE4VeZYOHWz
         sL3+azK7w2ovze6fre+cPcKwXL9WUZknhOR7GFKwrghkFW8YnWO7n1ujHkjXVsjmQqny
         UD9LGjQixg0eaKPfSiwVH1yR9IRrUw+Ay3ZVvSph3rKfBnYVYjqtio9pmIsA0cCOsmON
         2aqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tEabGO88tft0l7t7dfmOnBPAD5NB1Ndk1VUZmKCCivPSSCf1o
	+yDYkpRCb5umbwgrtMSPdes=
X-Google-Smtp-Source: ABdhPJz0HaJD9S7zGJFfKjgaicdRLHdQagFOgLWyRNLhcyTHh35jcbQvvH7LolgGYFD6PVAZxL95jQ==
X-Received: by 2002:a63:4714:: with SMTP id u20mr7315951pga.184.1592409345585;
        Wed, 17 Jun 2020 08:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a0c:: with SMTP id v12ls908931pfc.1.gmail; Wed, 17 Jun
 2020 08:55:45 -0700 (PDT)
X-Received: by 2002:a62:8f45:: with SMTP id n66mr7332004pfd.236.1592409345304;
        Wed, 17 Jun 2020 08:55:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592409345; cv=none;
        d=google.com; s=arc-20160816;
        b=HsJRyzbw9qGqtb4P9tsDcwHDgKo9GZXiw69zVul4n7UBGzLuF1bvuFQb9dqCvRn8T1
         /mx4x8am7WTtnMiIXOEeyVF9tHoIAv/Yj1ST7wd2g6PIL5f2/81MYLyhmFHnpFOrx37z
         f/ELFWKPqGspMgi+oKVZl0GZVUZdi4mEXHVjKti8VNzsESyXeL3McsemEA5/17+snKTM
         3+odH9ejJwF+V/JX20bCBuSqUZjxY0Ejz3aBrhjRZ/tU+RxPvX92eI/BercX1HCZXs+V
         rDb4UrY+SVV+oDHX19DSdbMK/QgyRh9AXKiHmgRI3kkbBCQWVyl92psk2LlVa2ZCPXJ0
         Eo6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=W1/Mre7UKqolI7N0Xc8bLf5Hmu0xZUwDx2FSbJF6Tl4=;
        b=ew5PWqnAcdRaKQWveRX6N0KAy1cTgzYRNoxV55g/HWoO9p0bdvQKcOLkWHZYi55A8N
         GVWjAHO6OTLjly+2EczF24CpKXoRxNj6aN7CJD4w2adq1A2AcKuy8BFA4hcpD2pKNxSK
         W9L6750gyuQ+c6rgdMidrj9oRRE+T8RHFG5sQ3AV2/eLY8pPsc469WNmbC+OQ8zWYnnl
         II5RxNH73BQ93ikRYFTKIPp6bdj/GsTCprtpifp5xFl6Zg2zC7A3fmzFOZDUpzUpTVvo
         3ku6spS2ut770j+RgXTVUPA1Pb6oRyIy1jFDN8WFC15ZCJqDDxWHFeuvIMNlUCiOpurH
         sXfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bIcNkACR;
       spf=pass (google.com: domain of srs0=jfbq=76=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Jfbq=76=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s81si23108pfc.2.2020.06.17.08.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jun 2020 08:55:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jfbq=76=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F0AD1214DB;
	Wed, 17 Jun 2020 15:55:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D5A7F3522653; Wed, 17 Jun 2020 08:55:44 -0700 (PDT)
Date: Wed, 17 Jun 2020 08:55:44 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/4] kcsan: Minor cleanups
Message-ID: <20200617155544.GA10347@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200616123625.188905-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616123625.188905-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=bIcNkACR;       spf=pass
 (google.com: domain of srs0=jfbq=76=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Jfbq=76=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 16, 2020 at 02:36:21PM +0200, Marco Elver wrote:
> Minor KCSAN cleanups, none of which should affect functionality.

Hearing no objections, I have queued and pushed all four, thank you!

						Thanx, Paul

> Marco Elver (4):
>   kcsan: Silence -Wmissing-prototypes warning with W=1
>   kcsan: Rename test.c to selftest.c
>   kcsan: Remove existing special atomic rules
>   kcsan: Add jiffies test to test suite
> 
>  kernel/kcsan/Makefile               |  2 +-
>  kernel/kcsan/atomic.h               |  6 ++----
>  kernel/kcsan/core.c                 |  9 +++++++++
>  kernel/kcsan/kcsan-test.c           | 23 +++++++++++++++++++++++
>  kernel/kcsan/{test.c => selftest.c} |  0
>  5 files changed, 35 insertions(+), 5 deletions(-)
>  rename kernel/kcsan/{test.c => selftest.c} (100%)
> 
> -- 
> 2.27.0.290.gba653c62da-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617155544.GA10347%40paulmck-ThinkPad-P72.

Return-Path: <kasan-dev+bncBAABBFXW3L3AKGQE67ZB7RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0098D1EC3FA
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 22:48:24 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id f21sf39093otq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 13:48:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591130902; cv=pass;
        d=google.com; s=arc-20160816;
        b=iU9soagoX++mvHgxVW+ffBZehD/LZzsL9Jvr9lbiFET9cK3u3WE/vbHKBCDT6NPrUe
         B36/R8P41YmnYJVxgQcJFK33vlWHAEQpO5S3LA/zI5jpeAfNfGKvdqGk6asAy53VVvZK
         qrLfEft3OIAMk2q1SKyHiUkfuZ+2dh2pE2WBFk7aOLH1QpglZIxb0HAnRFEseoL3UbiX
         LwDc2GzwD4Ebkz9WdW47HdrxBLAfQ6rP/ik5E14Pdnz7kC8eJMWBjamdzIXTCFIvvAal
         t996oaSK4FdVyjVhbCGydookti2ekv/q9rtZ7eOpHbvA2hCbhiRmhUPNms4im7Fkxx+B
         fJNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=D/GHbyXnjttDreCjRovWbsr7bm7066Ig4QFbNAAhnNc=;
        b=wg56saaI0XSiUevpE2eD537SXqQebS4c7w7748Mb1B93iSU/puWt04kHhZvoFZ/uaf
         9X322SB8m+aXe8W3wOOGI6D79HLdQB3JJ9Ax7JYQBGJ58IYPspWdpOwIY2ssTkDMDOLQ
         /OWOGByMzjzztNQfhHOwhw4Xu7xVSKX1CBQhNes5Tw4ORhNZtQG/ixEk0WQWYjOZQpiF
         KmzEy75SxsFMHUD2tYhLSPXEmma3BRuk6JyhzVVGfPlIPIE9EKxh53nIqyC1KEoxsIFt
         jcgKplj3SrupkmXwO8j/MGanmitBmdS9+6oT1tE4SXBc0p159TBcttPluWVCMrrEqCJm
         LseQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Ah7vSqvm;
       spf=pass (google.com: domain of srs0=ggxa=7p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ggXA=7P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D/GHbyXnjttDreCjRovWbsr7bm7066Ig4QFbNAAhnNc=;
        b=U7IHUbWO9RMzEo6A5y2gE8Pj55Owsazr4ZluMGv0RW+Dro5bpbF5qDlbcSwKecxZ7u
         5takY5Y20N9/FrI7kAG526Iu1gTygE10qWcTbkhk1u38Ou6Bev4LnKrJjc+ZwinKoA8+
         3L23zV3Kyba3UwCY1Dkd2qOvuGYI1rJVszEHnwukTnVhLnIalUAYUlpGUX1RlUHI0VIl
         GATrPVH3mt5DrqGGYn2P3xOM4BV/zX36UVwPJ17k2IQu5oKQ/CAP/lsBUc0XWhCVoaTd
         zmvBsGOFjBmZFPkYipvHGrv6BE8zNMdzHUnG+IKonzuSb9f7Q8pbuv7I2tXgU0zkdUTJ
         plVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D/GHbyXnjttDreCjRovWbsr7bm7066Ig4QFbNAAhnNc=;
        b=p7eKFexyfGjGYkhXfsAzURTQoUNeBDQc7CwEH8zjNZdxaJx3sptFTzlmxwlbgVBgdK
         HHlHwuysQRSh/Ntzqm3wx45oN9sCqJE2X7zpSR1NnbYAREhFJ7XPVMcewxnQDdGJ+tSn
         k/cAF2An1XoRsNOn8kSLQt7Qzc/orXWNhIXknmKVEy08gU0px3VT9HB9oAsbMZSMpR2y
         q0neWrJjms1abUIZ4IEDeNxfhcA6TaT49iqeLDBfpl2+v3RGtjd1t5WjpFdK4plYxMWq
         nic2esF1HA+l4w95rnLdQhFw3neHr/iH5mQ0tZmp6g0NZYaigzZiIH0jtHDyGlMiryvm
         qOAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w+jb5g2fqUPtKzQluJodOd44T8hBUyY+Oo7F73wdqENmvdRwm
	r2rLzZxUQJ5sVSEDSaHFRAM=
X-Google-Smtp-Source: ABdhPJzd7prU4AulT66dXfXu5EH4Oini+iKvh4KVpe/sIhWLywPDt3SvLZg9Zc8JZ0q/lJDSXD9FFg==
X-Received: by 2002:aca:48e:: with SMTP id 136mr4197751oie.18.1591130902679;
        Tue, 02 Jun 2020 13:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:16b:: with SMTP id k11ls3446ood.4.gmail; Tue, 02
 Jun 2020 13:48:22 -0700 (PDT)
X-Received: by 2002:a4a:8890:: with SMTP id j16mr21962241ooa.60.1591130902420;
        Tue, 02 Jun 2020 13:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591130902; cv=none;
        d=google.com; s=arc-20160816;
        b=FEg6IAPWyc4FxwC04s1rKWL9q+KrAzT+giUaTKQnI0KwMyX330ZqGZ/WRuGNDCeR1a
         0maNEGcHqn28FuZWBiTQ7orifHmq6QVXeQzguiv1F3N2QO2AYMwkMx+ViWuOhE4PUTF9
         lvNe94EcNcswusJGm7EpDYL2RAlPiyWAn8ybITlksW1glCqrsQAiQ+ScQyDvYrnJntOt
         4Z5jAqVWkRaSTyZwhBxz3GiKrdCl5TKSRmQllly+opbk6mV62Nh4Zin8UCA+MTRWtSGu
         Gu6Urb1kwV2sD9vFVBRd08Y35bkyelQpY1zGsXg/UPKfefirdZN4Ir9/VEsB16pYnLYv
         GLow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ft29W8Nvi0tl0Om9V4xLGJtcn+mwjihUuQtoWB0VLqc=;
        b=bJoA8tXTqIxhr4UdxFk/BDvx5P2ixsgpLHzDdyKXojVVgfxb3GrITJPA0gCxh/A63K
         abDgrovMEIwsZ+pkNPy92qkvraU1A1+15kg34z+PRY3iWUEHJP398pZwys5Ja+NIXfWq
         5vK9Yx+Ur3npXa7J0Fb5Zs/mWAby0I09rJCdT8JA5vca9EnAwR6rzFKPvqxyIgdRRLL6
         Jd+73md+C7hm0mfFF2KVo8VpOvOlLfw01jx72Bmw2VRbk2TAuQG+LWYVfMg7WfiBXOWX
         xjjSaCIzkoJ/fK5qgbSICROfdNyR9oP1/t1q5O4EqXTxnJYxcCWL7R2Jy7gKaCh0+AZU
         J4MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Ah7vSqvm;
       spf=pass (google.com: domain of srs0=ggxa=7p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ggXA=7P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l21si5733otp.0.2020.06.02.13.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jun 2020 13:48:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ggxa=7p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8794D20674;
	Tue,  2 Jun 2020 20:48:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 6968E3522C92; Tue,  2 Jun 2020 13:48:21 -0700 (PDT)
Date: Tue, 2 Jun 2020 13:48:21 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] kcsan: Prefer '__no_kcsan inline' in test
Message-ID: <20200602204821.GI29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200602143633.104439-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200602143633.104439-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Ah7vSqvm;       spf=pass
 (google.com: domain of srs0=ggxa=7p=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ggXA=7P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jun 02, 2020 at 04:36:33PM +0200, Marco Elver wrote:
> Instead of __no_kcsan_or_inline, prefer '__no_kcsan inline' in test --
> this is in case we decide to remove __no_kcsan_or_inline.
> 
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> 
> Hi Paul,
> 
> This is to prepare eventual removal of __no_kcsan_or_inline, and avoid a
> series that doesn't apply to anything other than -next (because some
> bits are in -tip and the test only in -rcu; although this problem might
> be solved in 2 weeks). This patch is to make sure in case the
> __kcsan_or_inline series is based on -tip, integration in -next doesn't
> cause problems.
> 
> This came up in
> https://lkml.kernel.org/r/20200529185923.GO706495@hirez.programming.kicks-ass.net

Applied and pushed, thank you!

Please note that unless you would like this pushed into the current
merge window, it will not be visible in -next until v5.8-rc1 comes out.
Which sounds like you are aware of already, just want to be sure.  ;-)

							Thanx, Paul

> Thanks,
> -- Marco
> 
> ---
>  kernel/kcsan/kcsan-test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
> index a8c11506dd2a..3af420ad6ee7 100644
> --- a/kernel/kcsan/kcsan-test.c
> +++ b/kernel/kcsan/kcsan-test.c
> @@ -43,7 +43,7 @@ static struct {
>  };
>  
>  /* Setup test checking loop. */
> -static __no_kcsan_or_inline void
> +static __no_kcsan inline void
>  begin_test_checks(void (*func1)(void), void (*func2)(void))
>  {
>  	kcsan_disable_current();
> @@ -60,7 +60,7 @@ begin_test_checks(void (*func1)(void), void (*func2)(void))
>  }
>  
>  /* End test checking loop. */
> -static __no_kcsan_or_inline bool
> +static __no_kcsan inline bool
>  end_test_checks(bool stop)
>  {
>  	if (!stop && time_before(jiffies, end_time)) {
> -- 
> 2.27.0.rc2.251.g90737beb825-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602204821.GI29598%40paulmck-ThinkPad-P72.

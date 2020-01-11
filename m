Return-Path: <kasan-dev+bncBAABBZ5U4XYAKGQEYYBFKRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 307F2137B7D
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2020 06:17:29 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id c31sf2646101pje.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 21:17:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578719847; cv=pass;
        d=google.com; s=arc-20160816;
        b=YoGqlGxXicmDJXaVc1/vYfEMu8J6i5Ejz0uOHzA6wu3VnUd88/3v1WSHYznrYcJPeq
         hFUDXZIs1nTrALgPVSZZcA+Qv9RylPPn4fSLimjiVJ+alReeOxOOTw/5zt4BRCMpf9nh
         tRb/Hw1g83TjWpw3bc06M5G4h8zFW0D32t0hK3YkKVADG0zOQEIoO8JbF39EbwIVqnZr
         4YpAJYtPU/qYSRc+7bTSZfn+veTORDbSwyO8+xv+rg82v6fn6V6umdn+YPxu937dN6Zh
         Yo+vfrnTkZDzqcYNLCzKAMIIKxraQGmENVXWekm4qfhl2jzbuF9lJOTBTIHV6YC/tx6g
         iOfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=EsUMmr3suuPqNGQw13o0e4GbcokuRupSKAbN0zG6FvY=;
        b=SQs+dE5mUQFEsIznRh8b2MgAA+P4i7mX0Hiij8kz+9COkGCta0+fvjsUeU7mCVfLZi
         xpzsv0NO3gLHvy+cTrau31ucRfJL/p/RTYrsEe1bLmps2txEkxlD5dAw7VMJj4cpL1zs
         6PwH3u9JjKfIjKn8Aci5K+3Av/N3kJtmqROjrD8rsIdV1GIvqy2QWchZHVTCis+DbFFO
         NZZDKPE69yW8SCSTZNhAVYEwrLwsLIrg1RlZPHAS7mhpG4/4iY60nN7HrKuiYW+wfm4K
         S2RYpMHC3kCujze7ksz7VlvBbZbnXvE2QLGC+PfyLDq9Szhv5aElzodmUB/mg++L2OzH
         9XBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="R/QhIys1";
       spf=pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EsUMmr3suuPqNGQw13o0e4GbcokuRupSKAbN0zG6FvY=;
        b=l7hngax4M7s+zXDRP8xDbhuaATJ4CbldHPa3PZpoxRNFzmHq1o/hoGsyGTmOWYgFVR
         bUyzhzoLoVw/Fu4E0tf6mCg8f0K7+Zp/ZM3naUwywcCD5UkM/Be8EvWBLSfe5UkzF+eC
         eePSvSfkMyd5o/XpnJu5tE5d/al0nqRRdNl7RXU5HGIQa5xDm689DqSs5Qe8js2QYoQc
         ci1EwO3nzMW0mdykedzGiVhvFBPy4uMwk7rPyBM8/K4EJ10bxucHGksm0kTGBnCNrVYI
         4+oNrNgKS6NrkndYX/mIZpeOTgUjHIyJQtG/H2uRMOG/amzIvWjH+IFAtNDtQEnHsv2t
         98Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EsUMmr3suuPqNGQw13o0e4GbcokuRupSKAbN0zG6FvY=;
        b=mOPDw33mvis5Yq/Bd96nGTBcjdbe/2SHAa5IS5mIdx0KF3IqUxzP/Qf8Y64FrBxYPw
         DoRQtCu0RDUaq9/rQkxkjftof/sz7055HmruXZ4iVXjG1/soRmbiSZnpYODAi8Xx+Bgi
         5jwI+QdpbWBKdMVZ5cCLnyYjju7FoKOhUYk473EFZRZ6USBl5mwDBHBKDyLZlvmfSQe/
         tV/flYApqtjCUzJ7vUeD6zVb+QoeiCfm6hOvk1Vyp8lvzoP15ENXjF13QnDgnE7cg9+a
         QuFm0nB94uMjrt4xejvFMxJzr/WlOUXiN1zmHO3OVT+JYJFCZpv1etMhQjTvkBEjahmW
         CM6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWfyN7S+np/Uqq5sYy5XuXLuICLz5j492qzqlEsNStg24PwBVZ6
	v+eCrWLgaHaQHCS6lk1irOo=
X-Google-Smtp-Source: APXvYqzd/qK5H2qRgNC3IvB4S7EDdvo6sTLW//5BEeWN0NVF8178pEPb4gGmM+Qbuk6gbHKZKIQ/mw==
X-Received: by 2002:aa7:9562:: with SMTP id x2mr8305300pfq.147.1578719847489;
        Fri, 10 Jan 2020 21:17:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d207:: with SMTP id a7ls2004015pgg.1.gmail; Fri, 10 Jan
 2020 21:17:27 -0800 (PST)
X-Received: by 2002:a62:1857:: with SMTP id 84mr8380753pfy.257.1578719847193;
        Fri, 10 Jan 2020 21:17:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578719847; cv=none;
        d=google.com; s=arc-20160816;
        b=Yp9Lb7ZgEE30XqL/oFLRn0XbVBw4aoMkWxwF2YWIRG3np+bCHvmcUqD2GFMqGXyy2s
         JaeoY32HUr3EPeiUKF5sDxqis+hpI32fDV45A1ffqHUsrGJBArV7Zd9oQEuj+viGUnlf
         4SMCDXgf1UlBPYeV3VwWRv2AUFyFi4bZuvV3sf9qV0S/sh81GaDmtlO4FCA85C+tY6wu
         xu9eqbIciDO6C64DcoI7O3Amhz213nL+D0fSoB7ld6+7IE3DlzPJ/cWS0cxPzOyy0db8
         RNJs4ppfP/9au2jjV92P1xHdbCdtD+Fr4i6U2H9/ODdSaLU0tCjl4LiWW2SJV7N8e++z
         dyPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xsog978os+5lHKlMO9Ph1/fcrJgoy19AvdAF1wSn4Yo=;
        b=T0gMBYaH1pP/KVIeG9MTo2GflhGLytZ+wpnbr6pQFfIlsCJWaF5Qtv1P8S3HbWovsO
         IiG4GjoXYYL63+Tp8laHG0xfTthqOkaACUvZR7RMaB/pvUzeExD/JjqpWbTkCwjmhQxq
         KHoU7/QihV7K79qY12WmCRx1eYQ30IkaCZEIGmrnvAu4CkCxoaMLbNKwGTlZGeDFpBc3
         CvCvTjHV46H7ctTEj6vU+0m5ME/VPkTx54JtjnZmAj937+d7TmnOmgW9epbjAr94c0dj
         vYCeP/7JYn6kD+jcVSbl+8dwpMUemjL8z0pcXRkr7xw6eF6WDWilA4ccMbpHtbeIw+5x
         faiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="R/QhIys1";
       spf=pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c4si192859plr.4.2020.01.10.21.17.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2020 21:17:27 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DFDD52077C;
	Sat, 11 Jan 2020 05:17:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9599C3522887; Fri, 10 Jan 2020 21:17:26 -0800 (PST)
Date: Fri, 10 Jan 2020 21:17:26 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH -rcu v2 0/2] kcsan: Improvements to reporting
Message-ID: <20200111051726.GH13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200110184834.192636-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200110184834.192636-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="R/QhIys1";       spf=pass
 (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Jan 10, 2020 at 07:48:32PM +0100, Marco Elver wrote:
> Improvements to KCSAN data race reporting:
> 1. Show if access is marked (*_ONCE, atomic, etc.).
> 2. Rate limit reporting to avoid spamming console.
> 
> v2:
> * Paul E. McKenney: commit message reword.
> * Use jiffies instead of ktime -- we want to avoid calling into any
>   further complex libraries, since KCSAN may also detect data races in
>   them, and as a result potentially leading to observing corrupt state
>   (e.g. here, observing corrupt ktime_t value).
> 
> 
> Marco Elver (2):
>   kcsan: Show full access type in report
>   kcsan: Rate-limit reporting per data races

I replaced the existing commits with these guys, thank you!

							Thanx, Paul

>  kernel/kcsan/core.c   |  15 +++--
>  kernel/kcsan/kcsan.h  |   2 +-
>  kernel/kcsan/report.c | 151 +++++++++++++++++++++++++++++++++++-------
>  lib/Kconfig.kcsan     |  10 +++
>  4 files changed, 146 insertions(+), 32 deletions(-)
> 
> -- 
> 2.25.0.rc1.283.g88dfdc4193-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200111051726.GH13449%40paulmck-ThinkPad-P72.

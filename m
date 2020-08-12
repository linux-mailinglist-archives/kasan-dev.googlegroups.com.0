Return-Path: <kasan-dev+bncBAABBTPC2H4QKGQEHKPJ2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52DA524311A
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 00:46:38 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id z10sf1533242oto.11
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 15:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597272397; cv=pass;
        d=google.com; s=arc-20160816;
        b=jmCsU/z9nY/BOl3rkVIwd8RkeszlVDC83QYOQ8ubkgeoaqdX089j4Wi1Nl8bBOMkwP
         01Fv/UhL4S8g4pYw7P+lrkFR8NsNlgO+3czpMrGKnKQiTnfuwocYSuuk6xX+BiEASaBx
         teGYcBerhKDdWSY2vChTw5fu/XVgKYkcdESwm36euP67mGwLSkDbsG0Ny8jUJc2crSB6
         R+2X82ZWUUay7wvUCop2qv+5gVYt7LuokVaLz/9DXcwOWGJptNmNVf9+Rn1kHqed40ai
         SgFhFilCqZmkbJVfHD4q5Py7PUwksP8BPFwh5RkSf5nzU7/iXdYmpIYN5AgXwWY9Rcup
         /fuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=YLvn5Db/uM3p3H5EsBWDDZFExDby4I9ESoSIOva9WlE=;
        b=vn2W7KdipQCznApOjSYLPS/KMZPwBWDtc83IVUSxSgz4euVL89cRd2EcTCv0TdXLkv
         LDSkJt0lllb5jfDbu0cU5XsSxhMVxD1iD5OK77tuyLQRPIdkIBroYaZoDUk9QV0hiskW
         9usWAX+PvSA9gr1UhQbeU1ym6u9rte1g3Qj8epXbQnFTzj6gMJBFDT0BbHxLic1ZKx4x
         Q71vfmHZ+3Mlu5I7+z/CnSs1JFBbwzDAjT+rEJE54EywGXr9iADLMsITgQQ2j8fz8yMs
         VgbhXZKLxJ9C8VmXZR2+xOGAp0X4/S+3GDhNAXhHom2ueaXzygy4hVUp1tpGbzF5ewpO
         QFjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=INtZAQeX;
       spf=pass (google.com: domain of srs0=j8kr=bw=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J8KR=BW=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YLvn5Db/uM3p3H5EsBWDDZFExDby4I9ESoSIOva9WlE=;
        b=hRwquHSdGz0k44kZOqpjZ1O3xzG5cyr6ShNfNLZRu0vFBLUtQPXClh47x8iuHy1hZQ
         8JbfVtRIELSvQGYibk5F/DUCpLTrNfMBs0OcEruIujjhrrN0tdHYyZN5+tKfpEB0/adJ
         mcZtUdBds5pNIxqjTQ9vuu7y4eFGhrCgt/xsESJwdOB1OeJi/bIuHPhB95UGl2TkV4ma
         c07jXj/pCNWgbLSmCuQb9sBov7G870+rIKgqdnksafgp+zxnZDjuCbgV/6+seTkwQfeG
         OuSJI/R0s5huxoKy2x/ULbIt2n9OwidAUI/DGvJ05kfwuyTh9dMx8z3VOuc/kthEGknC
         V7NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YLvn5Db/uM3p3H5EsBWDDZFExDby4I9ESoSIOva9WlE=;
        b=cQ3zWouXLaXmU8KAzd8lqVMf7YHtUhKhJ8626gZ8VYxBxb9QjTxoghth16KeqOI9Vh
         +O7sbcPgXhzyIVzVcgM/loqSXZs6GkCtfNPpnAC5DJBTWfG8og9tyGz2JPquRe91HCtT
         hXHwvCe9y1I496bmDRhsepjuOz06SRwCkUyMcVS2U9NT39JqdTTpYhVGz6SiCR7Tt5gf
         otb8eo/gCgqFM6+RhBKncEWyoEEK+YqXWXRu01Mcdmog2kAZdnwVXEn0F6NqHdg+AKaT
         kSYuBD4iGGgn2aUssn2W9/CPgyMW188kroJSm3z1ACTWlu9YekF9N7Euu3jWCtplFzxF
         LBlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kk961lM94gvRXQhL7FMwCi+RkJsncKZ87xt3nqlkVYXw2WZZT
	NCn8W0prXSkPr95m+ztTg48=
X-Google-Smtp-Source: ABdhPJytE28HdJMAiXXSD1RuZyy+acuK+6WShiRShkOzdF2bER6L+O4pavX7VIT02Aqe6GRdtvdc8w==
X-Received: by 2002:a4a:c587:: with SMTP id x7mr2121238oop.60.1597272397251;
        Wed, 12 Aug 2020 15:46:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:310d:: with SMTP id b13ls820927ots.0.gmail; Wed, 12
 Aug 2020 15:46:37 -0700 (PDT)
X-Received: by 2002:a9d:2968:: with SMTP id d95mr1793392otb.310.1597272396985;
        Wed, 12 Aug 2020 15:46:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597272396; cv=none;
        d=google.com; s=arc-20160816;
        b=sqkmaQxFMaXWB8AVVIoDH9EimdgwqGkG9rbddgxj0LNEr3hB00zs11Tu0nohepxJ4t
         yjfCQ66XvQrTUhPNeoFuPNf/kixOA6ycK+dFghRDrVJSKjEmabuaCm+3bVb+39GMFLYZ
         MuXabgyYZopxa7HKQoqAukBJau8Z3UzaTaiLef7MIN8zTbMQVgZNeGz2OQOkJhe+8U1O
         E0D6aRnbjz6YD4jTO4ChzQu67vujvLpUKJZZMrUcKTRMk94oQopwL+x5KAQ3g+Ts73LN
         TdXZher276qMZOkcBLW809yWIeSuQGlnqkME6JIq8rwRbeKOkfwFMKlyz/TlzNUW88OX
         ktJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KOPIbjiThkuORvQcsj6IuEIrOQQQKq7EOaz9y08pPsk=;
        b=U2RKXd2olvrXItmzdeFGcbpu3wtdB+yEvmCrwrLkJr6LQcVN4GR5IfyYZtRu7a2J9F
         QrrlG5sAusCQmUaP7gNE3xzuHS1f2gOVA0eO+7903fRP2vf272h3nBfKDACn0SH+MhSU
         Ul6rrIuZnhq81ijxpPSEoM/FFB8cvPrsEP2XqrjrDkCbbQBYzdcUxgV1geS+NRaEYlzK
         b6emozKXtEn4ot9uP/WPPH4l20z/BW8s/d4LwTBF603cD8vxRE5oKxNUbKVuo1zDaRWs
         7P7LklWBgKh60Cv5YH63syXZf2hxYWkHi78HSTGE0II74NlwI7zRSe9O+n7xyGud4Ko2
         rbxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=INtZAQeX;
       spf=pass (google.com: domain of srs0=j8kr=bw=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J8KR=BW=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w1si160693otm.5.2020.08.12.15.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Aug 2020 15:46:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j8kr=bw=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 197ED20771;
	Wed, 12 Aug 2020 22:46:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id EF6943522615; Wed, 12 Aug 2020 15:46:35 -0700 (PDT)
Date: Wed, 12 Aug 2020 15:46:35 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Optimize debugfs stats counters
Message-ID: <20200812224635.GL4295@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200810080625.1428045-1-elver@google.com>
 <CANpmjNP5WpDyfXDc=v6cerd5=GpKyCmBKAKH+6qLT6JrBGPqnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP5WpDyfXDc=v6cerd5=GpKyCmBKAKH+6qLT6JrBGPqnw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=INtZAQeX;       spf=pass
 (google.com: domain of srs0=j8kr=bw=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J8KR=BW=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Aug 12, 2020 at 03:02:14PM +0200, Marco Elver wrote:
> On Mon, 10 Aug 2020 at 10:06, Marco Elver <elver@google.com> wrote:
> > Remove kcsan_counter_inc/dec() functions, as they perform no other
> > logic, and are no longer needed.
> >
> > This avoids several calls in kcsan_setup_watchpoint() and
> > kcsan_found_watchpoint(), as well as lets the compiler warn us about
> > potential out-of-bounds accesses as the array's size is known at all
> > usage sites at compile-time.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  kernel/kcsan/core.c    | 22 +++++++++++-----------
> >  kernel/kcsan/debugfs.c | 21 +++++----------------
> >  kernel/kcsan/kcsan.h   | 12 ++++++------
> >  kernel/kcsan/report.c  |  2 +-
> >  4 files changed, 23 insertions(+), 34 deletions(-)
> 
> Hi Paul,
> 
> I think this one is good to apply. I do not expect conflicts with current -rcu.

Applied and pushed, thank you!  And as you say, no drama.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200812224635.GL4295%40paulmck-ThinkPad-P72.

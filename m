Return-Path: <kasan-dev+bncBCV5TUXXRUIBB6X5T33QKGQESOJCO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 24CAE1F9F66
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:33:31 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id p138sf14946789qke.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:33:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592246010; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7c1D7bKXwzMf58dFr2QV23IEwFgzADpxTRxhZaREwfVhNxdFZfG9fflN5/QjfQhKD
         v8J8gOaR2ncrm5zWk4auewuktD8mfZLd9FTw05pXtJS9WZnFA24UGJZkWB6aN8hUohcV
         FYoNbGlr+gBIMXsGGrRnMVttyL9Vp5LMgo7GVw+RlTh5W4jN+zHIwhJX76uXjcyQ9ofA
         mJ7+3Sv8t4y3hshJPlkLBCLoL8+RksRfp3DQyJkeqk50EMQc4+xba+0DMp8vU6X1K1IA
         ZuMmGBG9mYBtRk+KwUlQoo9HIcjUr3JKzPG0M57A2sn5ftXTvb/92UtO0d+CMEi6Iw+T
         epVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XAJCkw8VSmOc3U5zQcfs1vzQie6q5Hkz+x7bq9AkkCs=;
        b=xrMtB2hTbpDicEyZVBAp8+/GYUssai86p/i4JCn1g+erkv598gtc/A8WF6Jbhdavvh
         9mLLu9A9vOGHu2tR4hEUyyzHScOpPUPdIXeiRUt8FQ3tIcgBY2urM9GYOM47tSxxZ+o5
         Ulxwlo2w3N1r/wUk58eFck21J5YzTaGM6VumQAIyQhUygsscV+iZmBQO746ZW19l/c4r
         mAcOcBWyfZJkJx9JU5IaO8QV4E1/Zc+vkCyAv1Fogk5oXiG5Od97UF1d+OHMccJuW7il
         YE05EGn04Ao5uTrLCiiaCQGxoFZkTYFQGmWSYMhL2vGe+WT9p+WK5GNFmj0JHAzfpk0H
         SlNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=RpLFBYYH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XAJCkw8VSmOc3U5zQcfs1vzQie6q5Hkz+x7bq9AkkCs=;
        b=EGjbk2Fb68T/06K41kLQ5dpKBa3eeYZ+NDlayNT0l/sVCbYO1eSkduw9gAgFIhuO4U
         kgbr5ZwruA8ceaj8B9IgG0csj8WRe8GXzWQZWF5866Wvfo6m4ZVqys7epKaLEAryzmmV
         h8uCFzW+Kv3zdPqSLgI7ppfV0tVfHvFtLLniPAWuNCYJVS+8aSepajBPARTI5PZCTl9a
         +Ok19w2adictyYKKpCqPMuepdbW2svk0jZMPV9QvJmqDubDFJSRQxO7p2QzAAHol+6z9
         7Xe/qbvVGVohPag6ZkoEDnaisPBHbrfhQUaZRm8NigV2/PGYznXXMd+0/TdHsW56B0ip
         ttwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XAJCkw8VSmOc3U5zQcfs1vzQie6q5Hkz+x7bq9AkkCs=;
        b=pfqD9AQXUcOD4j+bkOm+n89HQ8Jo9dAZBC/HPViCs6s8unuQukon/IinRkyCRmq+nd
         40JsYXHa+ECSqnOjiUW7blBTb4RUXK19yoZbftnaGGhRjsN1SY47rperFRoUHAmx+8Xe
         2HwLK09pV0etxA9WmBqq+h0Ax3zlTpAm9WHzSbbmhEPjpkgUr5S/uxBj74mv1eQpSwhI
         syAfj2lcE6nmqkhDabJXY1m27xVkQYnLafYuX1aZfeIGDBD5TRNCDyOiVaP+QlRW5ZRw
         PMpjPcGBmfL8DpOvMrSL/IdkIfuWAQi3X7i+7/cm2wZIK2MFE1CV6C8uKhcZ6ohxPUIS
         r66g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y+HKMKGHRtnlTuB0dlgjoVeSxnSMPmT4KRJ1atS4CZxf+UEIX
	pLQrPRGjVtscSrP8UJ1UbbM=
X-Google-Smtp-Source: ABdhPJwOuoItJZVcMlbe0rigRjwodoj4veRg67gNhMAwNEHp94fb8LWdjf1fP2XcW18PLMWY/PFZFA==
X-Received: by 2002:ad4:44e9:: with SMTP id p9mr25984985qvt.180.1592246010141;
        Mon, 15 Jun 2020 11:33:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9e92:: with SMTP id h140ls7084210qke.5.gmail; Mon, 15
 Jun 2020 11:33:29 -0700 (PDT)
X-Received: by 2002:a05:620a:158d:: with SMTP id d13mr16853647qkk.327.1592246009767;
        Mon, 15 Jun 2020 11:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592246009; cv=none;
        d=google.com; s=arc-20160816;
        b=RjKUFiQz+/y9TJbd5hiGHEf6lKdo6G1VU40zLbGxohh8UlvmoOu6ao6v4kc4fV8q77
         +FC6isjnNX2TRC5+NILFkvf5bgam4L6H5+HlaTFlfRGykxda5bXURmh27qIRZP+FHtEV
         /Cl3foAgzm4FNx4WoViifmdu+H3btHZjqCN29a53ewVhqWCPjdUr3LrRlrr2gNKbgZa+
         QpZ3LmM3wRzSh9BiarA31XpEQh0sBiZMLHoutbk0eV4oI306ylRiaE6tqlp83+3rfikU
         /LywPqdEhY3cEUhkPMNl4h3A6nlHvNkNmBxgZm3+PWA5WqpD54KV++WFFUoJbtg1Lh32
         bn4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9U2E2WaS+S1jCvMfX0bEl4HRXYMqK3fD1PXTOMCvK7c=;
        b=FfqpPoh/oqRvpZRTcBbv7GyFmtIza2co+ZEmxZnlcQqmqdOItMNZvr4L4BJ7bJuL8W
         GM1mXH/H2wcW/V1Y62HipjbohdnqCSSJiWgbBFNTTM1xg4dsjQGMZvnHW08VN6W9dH+2
         hfBGF/rbiep0d6FqRbqEshhrj2P3fSHE9jNkv4QuiCBhPa7dcxyyPdEjgpwVNh0NwouH
         7rImNiYHHnVmtG/sn6FbCrWgD3h6XCNGDXmbGhD9ohGmlEKfKAGJN9YB5eis1vNmcT5K
         443hHlrOqTTfjOwcKOZQl4x/ypdAbf/1J8in2MkzCJ9KjO4HxK5J2ZPimey92CpcMPsa
         MujQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=RpLFBYYH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id p45si891976qtk.2.2020.06.15.11.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 11:33:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jktvD-0005ER-Kk; Mon, 15 Jun 2020 18:33:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C42903010C8;
	Mon, 15 Jun 2020 20:33:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AF8C8203B815D; Mon, 15 Jun 2020 20:33:25 +0200 (CEST)
Date: Mon, 15 Jun 2020 20:33:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615183325.GF2531@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615171404.GI2723@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=RpLFBYYH;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 10:14:04AM -0700, Paul E. McKenney wrote:

> This merge window has been quite the trainwreck, hasn't it?  :-/

Keeps life interesting I suppose..

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615183325.GF2531%40hirez.programming.kicks-ass.net.

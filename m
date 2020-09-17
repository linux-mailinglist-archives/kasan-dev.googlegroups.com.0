Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHNPR35QKGQESJJOCYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D51A26E1BF
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:06:39 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id f10sf1675365plo.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:06:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362398; cv=pass;
        d=google.com; s=arc-20160816;
        b=i27T3DbsrS90UW1K4xmkRrhBDtHZkpxuxZJ5XNrvFIJaTzVrjElyNTY2fdFmE4dy0r
         h+XFriyUTGg/P0t2ietduXGoESFGT9l/tg7r3mq0rSWdxSnaIVU+6kXiuNiZ2+c/7SwC
         OpYhSBspa3Pawlzz2QeWzaneTJZGDrojI26gREF/7Bq42zZo7TccPuQx1iziebBYzgA7
         vJw8WQV6ISES8FjB63G/tcDnvJdcuG9efyy3Os8HdU0nCFxAauZjHbhYpr6RwM0WVqkF
         YBKZAJtMAkgMVrFjhBeI5tMTn8btHHr5SevNGntmwsW4J8LGAuqIttb/MYOvteFHHiZ7
         u/Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bNA0WLaBggzUQ3ugm3jyw5z7f3Tb1yDj/8UeSCWs3tU=;
        b=IO0GG0cn8OIiSVKkaeJibzL+VS4jri8l8FJHKyDVbEoOlLdIEfMKieIaUDcWOujk3z
         e/uzxaTrSSGoNbLDUaG3/GU32BYl524yd1P3C3y2cWoK1du2ikfO4G5mZ2W3vV343AWP
         yxIqglrfOePGFnMOHn8aNukOa/MoazrVTJIzuPmz0R5lMcW5vmQvgdVD9YHIVe7BzR4y
         Hj+adMVTcrBJY7NN9Y8r+UQhwoytArlhpses8gkzI3Vav5MulAOVaRP3tQOXPc6fZHJb
         CNevt89CS3b0VO5qWtUujhD3fbKF9wGLDvDF1XN2C3ztNZyen1jS/mNLUz1HN//ndNL4
         gWXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bNA0WLaBggzUQ3ugm3jyw5z7f3Tb1yDj/8UeSCWs3tU=;
        b=fX0rAd0puq/zHqEpM2X5XtMSjLPmd4SXKumKJLB6NZQh8AlxbTCPcvYyuYA95qJDxT
         G1GuupxW7WwaVc2iwm+NsHX3t7piXKpRZNyGii4+Ip3eroX0d3AEsSHaxPSVx+Y0LDj7
         0LairMDUUXBKVzzX3E6erVPPekWNFP6SlPTBvr/LWHmLte/9Lsokac7a4Q5HRfo0877t
         I7ACazgbTXgEEUgzn9BmgzgBZ9ymNEfbcoOqzM51VlWvJUs+RWQcbC0rXhAW+DLOur13
         id0ZyhplrS6cRo4aVNnovUsOmG4cgwPnhbX+NIorG+AW7/z6VB6H/gy/cgFM37tFFlUk
         vKfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bNA0WLaBggzUQ3ugm3jyw5z7f3Tb1yDj/8UeSCWs3tU=;
        b=rRu9fGS9n4+06L02FHl2cckofGBDoacUB3oR4EMtcXHimlD5bjHPEkV1wXZsPJYdXO
         BxKOOoCQOyxjApY3CswsSP87iUim3/8eY5Bhiya0w1gY+jccps8hEdSEsDFUAwQavF/m
         o8nw7CC60TZpfSsrk+38qXF9pi61TaQHvtorIxOcnRvFRPv70PuKnsxPoYWch7fC2kg5
         pBQ/K2sbzhSMqbkapMQkvh3dhwSckvjiX0VeueZ4oGOhyD0geRzryr4gdqCRezoGcLWC
         lKBH/96i2bHdldvNuWnXB5gseNZwoUDQ4wqz9yUbCCVj6A1yG3mAiQjuSbStHlqyoWVA
         abGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jPYlRWT9nm16z0E14tTKrnx17moc9xbRVzBRqCv4Idmn8U9Sz
	6hg/qfGNFBd6xugOUSV3Eyg=
X-Google-Smtp-Source: ABdhPJzsLH8hZug7ds/Pz27P4uMMJ7COgEyiY99OH5jpgMt7tm5Rq/h9QsquValcw0Cn2Xom4ef8cg==
X-Received: by 2002:a17:90a:5a48:: with SMTP id m8mr9372822pji.181.1600362397953;
        Thu, 17 Sep 2020 10:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2a2:: with SMTP id q2ls1056794pfs.5.gmail; Thu, 17
 Sep 2020 10:06:37 -0700 (PDT)
X-Received: by 2002:a05:6a00:1491:b029:142:2501:34e0 with SMTP id v17-20020a056a001491b0290142250134e0mr12372429pfu.57.1600362397253;
        Thu, 17 Sep 2020 10:06:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362397; cv=none;
        d=google.com; s=arc-20160816;
        b=EsTCf+73DcTicshrnpptCJrcximYowIiVtDARCjQhjsY3XnwCZWWxLbC39t8y4MGt3
         jWHQXmy/Nte1inW8eguuwabU/O8pIt8cExCTBs4f+sgj/+9PewpxAI3YPnhUzvizs3EB
         AD9s8VcgOyVizzGFck/M/lXFgGgWXC5ARKgXlqhr3T3LBjIHSndwvw2i2hGbmbFcQI9p
         IObwV+wepDF52f2YhpxV7wdVcDFdBTgD8OvfOPWt5NYVB6QntY/TiYR+YLVYxaaayDkX
         iOncqjnoNzBq3r6TbEMjg+Uc1LE/acKUeCqVbJgJhPmexprqiKf+BMCqR4A99Lm+zPjc
         89yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=zMfkVAQHDOREnd3oU13UrtJEKYmAlTEVhF76yrj7W1w=;
        b=WdCkk+gNke1/ohtkadDeavXOcW9/6Pva182Z1v2+5HY5IRP8LVqIoacpdk5boE3KkH
         1oWFxpskS1csJcvvTNGUKw92xpvDBXyQKYVwT5IwPgNN5s7n2yjR+Kx4t/rbKFxh0xNZ
         UNVj1h6t1N3T/BoC7WCdZqZpKhY2BStE3b/ECk7fXu5EfIfTxiO9ghzwsNFuCm8gX6Xw
         nHN4yXYtQJe0kJdrtqhjDosMLpzvGKoq9tBsGIV+IiV1ODWgETW9mHYC2Cn49b1c8ZjD
         nT9+F4kT5sIKlPDGo4qWyfwWSzFOXDJtvqhDljyo888O1d1tS4nBzhsmnq03BDLknisV
         0vAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h5si46810pfc.0.2020.09.17.10.06.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:06:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7A59A206CA;
	Thu, 17 Sep 2020 17:06:34 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:06:32 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20200917170631.GR10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:15PM +0200, Andrey Konovalov wrote:
> Provide implementation of KASAN functions required for the hardware
> tag-based mode. Those include core functions for memory and pointer
> tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> common KASAN code to support the new mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

For the arm64 bits in this patch:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170631.GR10662%40gaia.

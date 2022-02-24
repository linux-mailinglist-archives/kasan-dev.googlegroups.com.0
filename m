Return-Path: <kasan-dev+bncBCT4XGV33UIBBFMJ3SIAMGQE6YFCREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id E77BF4C22E4
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 05:07:50 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id 199-20020a3703d0000000b005f17c5b0356sf1147181qkd.16
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 20:07:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645675669; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kb47YjvvjAJI0uOgwMRm59otyQk9w5VeCVGO/5I57xbb75CC+vp0e2+qdlkn3c0KJK
         yWyPQssxAQx3icnv0guk4bYZq/f5UdlgbdL84/QRNqAtbVkgYE86kqsOpOjjEm/9Kt67
         wmPE6kgf9b/1NgXuTKHhgPsk5MEWQsR2hBjT6thvXiIzOskxKt6FtTzynstOSUzn3Hua
         lSXipdu5MdljMapGjrotBXIi1MBClnUOeNmZ2k3rQxumdGRvcYGoI9F09ztV00bIMkzY
         gYP1X7spGrVDo36F8Aml7n7lLC0y/spGeadDBvl9/DfNkP/TBRBpzKj7B2Ky6P1c7S4V
         Vq9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=N5rsCBItNQaCRMBEcd+S2JR+7pBtSGPolyGWGzs8Jus=;
        b=uVrbxIGh9GK7LP9Fezp3HHevRML56GZCeOhBzJJxaikOxWtia530c+dOm52xZN0yNp
         KcgLbljjzXJ4d9gADcyso3x44k/o0w5FY07znvx/oV2pXfLanjob/AbcYmw9tj/RTjyK
         jpdQF1DIaB8pPyUtSPyJFmFT8tuk/9UM+OEmq67Gk0B3eXKBoKdI0rD1Vv/7N9/IwTiM
         8RCowxT28pdGhNULQPGWMurEueS2l6jBOR1JfaMRwZ9KH6tHkUHeOCsQHPlxfzv8c9ZD
         mleawh/GLtLVIFl8S8DtukRI1Ne8Nxj43rv8IvQC3vjgW3kODwff32GUXVtFNM00v3hH
         vNnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Dqb2UagG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5rsCBItNQaCRMBEcd+S2JR+7pBtSGPolyGWGzs8Jus=;
        b=mBvPLfXJeAIgE11f5Vwf2uFXpbIGzK1z0miTE/BeONXiIiP36LWPlFrxaf2Kt3D+xD
         Hgm5co9C14qpt01bDBpWarz5afNprLsNzSae54/Z8Z3wjNTASMON4XL1zuG7yG/OU36h
         tzsF65/khm44/5J5FNEkyqPvSO4In4zz0vqWTfMGXNp2WGD5sTYJ69/Ciu07EQh3x7hs
         ko08idTWb7WBubO7hCJYz62o84L4Cgj1DU0z/AURbOgv34PdUWQYZYm0TqgCk8j0hzd8
         b1YP6MHas4/AUedEYCoT3fyHgMozgKs5RAElJCPBZAosxic8jCdeMimJUnC14/6mw4MG
         j5AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5rsCBItNQaCRMBEcd+S2JR+7pBtSGPolyGWGzs8Jus=;
        b=H7P7UB9U5W3mL5AkCjYipOUmat6kSyEiHzxvvwLlRPAWFFuiwlqCYgYM+e+AWKZYuT
         MdQGB9uY63hzxsguNUB/mzqnlup5mpY4YhWO7A9YqNBzKYzo6robR4J5M8148LlPp2ZX
         XXBAgH6xWoKmKLMTLAV0N1R/K3r5dgpWTHmfP8iE9m7RXqBbcomiX7d6m13Yws9G9A3g
         FnQW/5bhfNNZkT8scDoIvzbzWgZhE4Ibuf7XgWWP18mz5IP/3JH9CG+AxkZEvksJasc7
         H3Ozdgbc9IGAzLKbLyi45StK5Na/fJzBzCTCSD2BiNHOhardtQse7IDg2Fp8kN7n3sDe
         WCVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TmsR6BGhTfRDrIXV8rW5zxa1byaJounzy3V5lPQsOMQKzf1N5
	tTGhyIU8oTk9Kb8nU9LMTz4=
X-Google-Smtp-Source: ABdhPJxJbhqjMCnXTbUiUvZIwPWgoV4uBoLWJLPsRGeUnpw90t8etocYeSe1xRcBenk5g/t71tRfwg==
X-Received: by 2002:a05:6214:d42:b0:431:d89a:66b6 with SMTP id 2-20020a0562140d4200b00431d89a66b6mr646586qvr.58.1645675669816;
        Wed, 23 Feb 2022 20:07:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a96:b0:2de:93fa:caf9 with SMTP id
 s22-20020a05622a1a9600b002de93facaf9ls704188qtc.2.gmail; Wed, 23 Feb 2022
 20:07:49 -0800 (PST)
X-Received: by 2002:a05:622a:1483:b0:2de:2d6f:7b3b with SMTP id t3-20020a05622a148300b002de2d6f7b3bmr731748qtx.545.1645675669394;
        Wed, 23 Feb 2022 20:07:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645675669; cv=none;
        d=google.com; s=arc-20160816;
        b=ObhRWh50bmy7+GPFUNX4um7A2dI6xDS8OEfchT1ivYeufJwYgzw4MbrH9HkmIlx1Ct
         l94lj9rXNPJqZj3AWl5tcJF8Ix8/KhkrQI91PXvdtuv0JI1iyylPTHknFqu49V6Lw0vZ
         s5qI1PNz1FjIynw+C1fbpwDZ9Q2D8AZZH/vjxfCEtZ2Ug1UwzsZ7PrYCdzivmHVxYOeW
         LKs2cFRrt8SOQdT31LIYD9DYufkhtmibl6lt5Nw/v4ALjM9zng+67GKb8GtGsnTosHCe
         e/N/db6f2eH1Qr/v47FbusB5YDfGBcxexyitHzclVZTMIl+ebHoksDsE0M1RDYm/H4Nk
         0v0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ry2+7xhVKMkEGqn3DxjEUx4x2sgf//lEwCWmEu4xIBg=;
        b=Bbe6R1G5G9AnTCQtAbHPzRViGXFiF4ocNcvaTVWMkYhxL+hQBCC1FJVHiITNFGdGpl
         gfC18+vr7GKUKzGigdsKE1CUQpYC4qwfk5EOi6TzoRYn8Dm81a8esy38pZrK4+sOByIK
         IuyWifHXrYo0awIXxCZlp3zBEMyrx2Mpy4Z620SD8WCJD4YL20QCgd1HHqxFKM0k7Md4
         eJkjpPMlFGumenrnISDbHHFCXkssSuulPf+ZqXks8koYKM6oKofEPhFDxu8fC0RD/XQw
         Qaa+FUWjxc6oqQYkRS28JoRR3h0fxhEgF5x5CpjRcz8JSGStOOWxyD5tbxkSlwWJtePi
         9Gww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Dqb2UagG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j5si166438qkf.0.2022.02.23.20.07.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Feb 2022 20:07:49 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1655061745;
	Thu, 24 Feb 2022 04:07:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2FA19C340E9;
	Thu, 24 Feb 2022 04:07:48 +0000 (UTC)
Date: Wed, 23 Feb 2022 20:07:47 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Peter Collingbourne <pcc@google.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Linux Memory Management List <linux-mm@kvack.org>, Andrey Konovalov
 <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
 <linux-kernel@vger.kernel.org>, Sasha Levin <sashal@kernel.org>
Subject: Re: [PATCH] kasan: update function name in comments
Message-Id: <20220223200747.2487235367d74255d8e13ba9@linux-foundation.org>
In-Reply-To: <CANpmjNMyuQh-G0kLOdoFWXyhw31PJsjXgbv7Qy+774v8iq9NWw@mail.gmail.com>
References: <20220219012433.890941-1-pcc@google.com>
	<7a6afd53-a5c8-1be3-83cc-832596702401@huawei.com>
	<CANpmjNO=1utdh_52sVWb1rNCDme+hbMJzP9GMfF1xWigmy2WsA@mail.gmail.com>
	<CAMn1gO7S++yR4=DjrPZU_POAHP8Pfxaa3P2Cy__Ggu+kN9pqBA@mail.gmail.com>
	<CANpmjNMyuQh-G0kLOdoFWXyhw31PJsjXgbv7Qy+774v8iq9NWw@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Dqb2UagG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 24 Feb 2022 00:35:32 +0100 Marco Elver <elver@google.com> wrote:

> > I thought that Cc: stable@vger.kernel.org controlled whether the patch
> > is to be taken to the stable kernel and Fixes: was more of an
> > informational tag. At least that's what this seems to say:
> > https://www.kernel.org/doc/html/latest/process/submitting-patches.html#reviewer-s-statement-of-oversight
> 
> These days patches that just have a Fixes tag (and no Cc: stable) will
> be auto-picked in many (most?) cases (by empirical observation).
> 
> I think there were also tree-specific variances of this policy, but am
> not sure anymore. What is the latest policy?

The -stable maintainers have been asked not to do that for MM patches -
to only take those which the developers (usually I) have explicitly tagged
for backporting.

I don't know how rigorously this is being followed.  Probably OK for
patches to mm/* but if it's drivers/base/node.c then heaven knows.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220223200747.2487235367d74255d8e13ba9%40linux-foundation.org.

Return-Path: <kasan-dev+bncBDDL3KWR4EBRBFFPR35QKGQEOHMI52Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 19B4226E1BD
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:06:30 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id c26sf1768112pgl.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:06:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362389; cv=pass;
        d=google.com; s=arc-20160816;
        b=QMd48gNumyxz8YqNs+zu2Y2lyiq4rH9N2PCKvENjPeVjy24WT1zcn/dWTW1vGlPiCF
         eiVLcL2DY/DOaMMKFYGJxsj4N1JqD6uwAS0s2fwoUIyqp2c5zHxLhyNFVQbP5rrpZPfd
         0InwNDU6sq/VKjDGjlp5x6t0b+1mtksslXPDFvvNEW8BCoNwrdlpmwqWG5tReO/RO13M
         zDKbxdwWW+kOuyai/S6RM9sPn4FXBK9LFqeE419gUxaZ1pLvw6sCVCs76cyNQJ0zDHdq
         +ZJ7n2cDNH2vJ6EVHB3pqGtYMSE/0JWZtLqEemAgvW/ScxTGFB8tDR0nXKRyxLYbcPYU
         /lDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ru5yq5Ah0AYGh8Yq+hvR/6ryF5kYbzElhhw/25QhP7w=;
        b=iA9/ApzkrUbi+4c3PmwWrczPKhMGl8MccifOTAiL3hlsqF1sdZhT0s6TeA3Xc3z7yb
         +StkIxgRPi1cUK46O0uS/Qre8mUqVZHC5KytM/GLZXSUcpnXaG+sNzlaL6OrEl6hV0Vf
         s88CX2SXfvlTCaPKvgKyfilPBX2qDq4gw7hxf8mfmf6WUtXQmkgVybiPSfCBO5VJRtQF
         KyMqwn15BD5OJGTMj6nkfyAzOfnNkWunIgmcDYpaY5WKqxANGxR2Ni56xOLOmQ9LRXU4
         szF0lnLH/zORth+7B51r8C0u6hegmqdTwxyggOBfNNwdM+P0ppppf6/o62H/JOn+vXxi
         gfkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ru5yq5Ah0AYGh8Yq+hvR/6ryF5kYbzElhhw/25QhP7w=;
        b=KLX55I0uIh6zGTYue1ggWgqs5dPGPLB/bLZVNh49Ph93RyydHF3+KWxmK3RKliFVkf
         0wypBJfy/VuoypmvkGd3GtgEfRVoxA8O8cdGbfuHWr+PlFJqkIwsOdX0gkKtP3dn3sY7
         16fIDRDfEY7F2oR8s6fgH5cTS1VAvvkaaskl+XNmJqCK8NProYJA2uDImgTpTW/gxxCp
         eevKZWXYTdAG9/aJdP/QiMFVIQO9ltk1SB27k6ShqIOWnhYoUzMPD1nzmnkrHOyLfPAf
         8CHwP6sl+Z5/Z4b3RtfZLHUV3GvBLiqYz3GHW8lB76BM1z/BXJdWqhddTYVRJ+Chtz8+
         QnYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ru5yq5Ah0AYGh8Yq+hvR/6ryF5kYbzElhhw/25QhP7w=;
        b=mk/ULEox6yM4aYsRb16XG+HEg5+jZuKcLZiAw8f5s2Q8NsUhR2YwdO55xMGTzwZxuj
         NGxSQnOyfIVk8Ayf3CNPb9OHYAMEMK3ABje9DjLloJQYLUk9vsBWzA3OsLpJE1+DJyJm
         nYOIBwViW8E0WByJmYWkA965oD7gRE30GR/vOHqxNNEWJO7Ab7BR0knvoVIPBa/vxK4H
         wsH38u0hJJ7WIRkKYcXBk07Z1zkGD9Nm8qYC1A8DaqgWqAcE/0M7P+sD8if+vJ9LFiHt
         OyTJrbDJywT4xHZ6b+iibUgYUPC047mxXPQOvdO7qpvo8Xa+izH+5wUhQhog856Bwktt
         vTrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532T2cunKbPd1CGZASJAOtuAhIegik1hzkev2sZfvGNIuDDYME+e
	Q52qxDK8CEfu0+OjeugF9uo=
X-Google-Smtp-Source: ABdhPJx2bUgWc9c1xB/hvc8SuBW+twoyZzKtAVdLgEetoEpq67kMGS18M7M1Cbg+wWvtbv/VIDFPhg==
X-Received: by 2002:a62:ed06:0:b029:142:2501:35de with SMTP id u6-20020a62ed060000b0290142250135demr12441158pfh.62.1600362388779;
        Thu, 17 Sep 2020 10:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1363766plr.1.gmail; Thu, 17
 Sep 2020 10:06:28 -0700 (PDT)
X-Received: by 2002:a17:90b:30cd:: with SMTP id hi13mr9459063pjb.82.1600362388185;
        Thu, 17 Sep 2020 10:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362388; cv=none;
        d=google.com; s=arc-20160816;
        b=bQkgkFH/Tpfw9yvb8LVIJa5rIUia7CYzrxp4DQouF67EQz0wOsovPvTpN3EFp7kp9+
         lNfj+J+LBTOzPtfPxvZkPsKhLbYdT2DDbLgI19k0gTJlj7CxbYeH01vZUZUbjtbIhk9R
         I1IpwgCgSg6FopIV0mUiYAnmTLTCzT+ZTleoZm6rV6pHg2VjB7bu5vkQuxxxyK+o4zF0
         lSNirDp+VsLS131CRm6FhlLQ2iolVu3BGV/auaBRFnajhTlTk2BTFfiuQNiV2hMgVHDQ
         fHV0pWrBTynBUHv9pqxfo4THZ43wWjYUBKE9Jj62NC7RZ0vkGI6THng/kjNZ5kectNzc
         bW1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=TVKyxPq4GswHOx83qFjCi57g24OieqaYxNd6rLhecHM=;
        b=yOBFlMl5e81M3/oWJatXg6pGc36uL1vcLkLLusQtuJ+FP385YB5YuyiZ0oKCe2OoYj
         c33+nDzP02Bhxkra5CnbnQhGjmxbypeimeqA1xw2joSfdbH1aYftLHPFhymeMjLj8CsC
         rI0SKucRkrLemW/LB6R6aZPIzl8DBeR7ypsXGxGKkMybZFucuGd6oPJ8J4vevMO1eCSM
         TS3xlKAaA5mhvLPrnTtRXWdgHemOLUKdNdM7Mi3qGb0RttS+zLeA50KSmGfS8vSXd+XC
         BntiJToIT/9rPvKhlmKq8jnnGXmzIUUS13r/prx2zhcVxxhNrB0SbtozcfN1sNARcpll
         kX6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w136si66659pff.3.2020.09.17.10.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 41B1F206CA;
	Thu, 17 Sep 2020 17:06:25 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:06:22 +0100
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
Subject: Re: [PATCH v2 32/37] kasan, arm64: expand CONFIG_KASAN checks
Message-ID: <20200917170622.GQ10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <ffdd9ee771394b4c36ce6b1f2b846f6a199ff194.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ffdd9ee771394b4c36ce6b1f2b846f6a199ff194.1600204505.git.andreyknvl@google.com>
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

On Tue, Sep 15, 2020 at 11:16:14PM +0200, Andrey Konovalov wrote:
> Some #ifdef CONFIG_KASAN checks are only relevant for software KASAN
> modes (either related to shadow memory or compiler instrumentation).
> Expand those into CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170622.GQ10662%40gaia.

Return-Path: <kasan-dev+bncBDAZZCVNSYPBBKMGTL3AKGQELND4FXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BD3071DCE12
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:33:30 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id m9sf7105105qvl.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:33:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068010; cv=pass;
        d=google.com; s=arc-20160816;
        b=taUg6Se4353tsQVX9NORMWKz3suz+FGw8L5Q3QwOIQBCY74fOcp/mcO35M+JbBNRBo
         9TXMqyefGoreTs2qXD4SpdTd28NCEJFV8IkrQ5yVBvpTzLkZUo5VcT37/q0SOXf9mLAK
         zm1+hFu/ybgnuNHbk1YwykMgM/9GvqnxN7Duv6UPcAfgDMhD1m1Fn9SIGYGfxWjhOdEL
         qMSi0n1WCNg1w/1J3s55KT48wRYOJ41FC5FvflxG07SzEpZurXNbHkG5MtQSWRrnvaTR
         0VUVYCnIDrE95vVVEd9LUehrqR+TlLDrj8mMETCmxgcmk+VqsZB10ahbs+0PDGHA4UOi
         rX3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=flswH2or02nNjTBm1fmBa2h2uNBqEJEBaz+nIxfPYV8=;
        b=kxUDPoTF59U41sbCvIKoDZ1YKn9jI8UDHSLmqInE1F7mPxoB0Tl/eG7uNow/DiK1Hw
         XkPHUZtrYsaUawpuXyi6D8PnewpuMqBBXBft6oDnNuZuTXOxYHYILy3JMnRvR+Q38yZY
         TcRTeqox/XIMwYomop7M2/iAScnBz56+n9toKNq2LfE7LO/djkwLCbhQpTZRp2OEhsMJ
         JoeagJrpm1sNRJQQRed4PHONX65378mxKEc1BMzFewd1FDbhHC4mDj+jKaGV8If9+1H0
         59O+Gbuz+oHtZk1hHBoWhm/cZgTcuKny4UVOG26PYJ3uGC8R3Ddq0ubcjcHpoCs2Jbes
         1v4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="N/t0vsj3";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=flswH2or02nNjTBm1fmBa2h2uNBqEJEBaz+nIxfPYV8=;
        b=opjZhDaj05zdo6uNDt8Ksk8gAuHTePwFznA3ofpe+Grl6EF5fOnCGnE9+ErZK/Tzk9
         AD3jgw1Wf2M50ho+6eMObT4bnRyK1CxqXjlAppyBWVZ9uP8nY+0bR7XFrml+XxXBXxE6
         H57CuCyn+vYAHwSIUn3JZVx5opj2dYnYjzpIPD/VkPkKDz5Jkv1fz8VHJDfd0fvDUduj
         MRRjCF8Qp+oAHbFC2OmcTXW2kGFZFzIKAn+07/iveovYr0oLSIPQqPMlgnZ8o8mk5NH6
         Rz+0H1lrTzo2B5XDWkbx0FZnVWzHjaJbhCEMjNxAUBhVEIvVtN59fiCcDhwY552OvSbN
         qdqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=flswH2or02nNjTBm1fmBa2h2uNBqEJEBaz+nIxfPYV8=;
        b=YZ+Q0hr39piDds8ATZFwkJ9ACCDOEkVh33ZH+6hQgG3t/zUJYjtFhGtz1DQCCYic02
         IFnjXD3qzRcpZwGQGnq2pQaX4jrodixQSeluooXcFery2YboGGdk+mCURDPyHjvGlICi
         Hjn6x9KAp7oSKk6XJEGNRmT6yTLegUgwEs6Q5yPsOkXC40dk/6rm++OkcdGxGodPezii
         YH+6yoBHtcb/riRehj/T0acsgdlqCsbRcfR7NEVNK/C+MRKSPCK2luA2HIMyKjZzPneQ
         5nwoRSI30vu0nu0Q5zTQ5DAXttACozr3CpVr+bgisPjW4hyDPhPTHkl3gVaDKfN4xQks
         71xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NKK0Fgf6KPzXxE5Kwt3HEuMlxpJJ5QN0uLwtXxJSCImWJOLy5
	aWF/Bx5h2VAoh0JlFulqBzY=
X-Google-Smtp-Source: ABdhPJyB4jNAZ/4lTREuNL4roiElLNgeL2igO6T4jJ78R0In8hnUd1akkkgYoxrZiAyRIdW4pY9/fA==
X-Received: by 2002:a0c:f94b:: with SMTP id i11mr10331671qvo.218.1590068009830;
        Thu, 21 May 2020 06:33:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6288:: with SMTP id w130ls1024922qkb.10.gmail; Thu, 21
 May 2020 06:33:29 -0700 (PDT)
X-Received: by 2002:a37:9ecc:: with SMTP id h195mr9952953qke.312.1590068009499;
        Thu, 21 May 2020 06:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068009; cv=none;
        d=google.com; s=arc-20160816;
        b=DNG27gDX6Q8w1UxeWTFm2BjiwZHeA/SoRruBDqjP6BEY3XGIwOdvPRCIx96W1Nm9a7
         aStE3fBCkeWuf7gOI+INeom8FPPM1Uf0amkA2lpinuyHs0DMCRKpx1wXFCjKLFISM/hA
         U6MumaGHx1EZyyhQPIFfQqYAT6oFjxL7ffkAcRTrcz2f0jaYcvAlfRYA6gPf5+l24xCQ
         RE6aKiTJ90VsNTSew2xcaFxx3tyAGRmg/q9Ikh83JipMUtnQtK6RY0kwMty0dT7ot8bO
         O8duP5GvAJMZQaM+DHnWlgPrCZT76tiri/RyE8UzBbLzoC+MoAD4g3ltEp5YHtu4xSFu
         iO1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Lv81cVo53b5m0z+cm3hv8P5md2jUOQ5atM6bB5aENx8=;
        b=mil98sKbYj2mDLnGCucZUzEwkS8mNwm1Uy78lxWihR7S0kh7NZJj+0sX0lVhSikWV/
         33fjr5qBYdNN6aEMpTzJvCwqRFDyqp88QzQQXK1N+w2bI5QN6np9X2bHjI1qsQUacjmX
         qsMBUZqfyF7rdV/GSFyyyhX4Xzwwl3p2GGNR4utaVjzp79cg7jYI07hXhK4M8JZqkP0U
         sXMPhHt/6QlCSfiFNh70k+qzZYbbuY+Zq4iPJZ03FGUrNBbO06LBBbwLYTJyH3W+CPoO
         IRqRrViDxQzNVLYTuK0t/76jNUmp/0dK6wBQvZD7nDFrOCo6rREoND4G8mUPQsu23/vj
         CfHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="N/t0vsj3";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c186si394262qkb.7.2020.05.21.06.33.29
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 06:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A1F3B206BE;
	Thu, 21 May 2020 13:33:26 +0000 (UTC)
Date: Thu, 21 May 2020 14:33:23 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	peterz@infradead.org, clang-built-linux@googlegroups.com,
	bp@alien8.de
Subject: Re: [PATCH -tip v2 07/11] kcsan: Update Documentation to change
 supported compilers
Message-ID: <20200521133322.GC6608@willie-the-truck>
References: <20200521110854.114437-1-elver@google.com>
 <20200521110854.114437-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200521110854.114437-8-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="N/t0vsj3";       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 01:08:50PM +0200, Marco Elver wrote:
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/dev-tools/kcsan.rst | 9 +--------
>  1 file changed, 1 insertion(+), 8 deletions(-)

-ENOCOMMITMSG

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521133322.GC6608%40willie-the-truck.

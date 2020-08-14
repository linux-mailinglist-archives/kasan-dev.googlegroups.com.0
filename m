Return-Path: <kasan-dev+bncBDV37XP3XYDRBK7M3H4QKGQE6CCA3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C1B42448D7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 13:31:57 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id k32sf5878612pgm.15
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 04:31:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597404715; cv=pass;
        d=google.com; s=arc-20160816;
        b=QYKYNFnheEz+P1gSRkNNyfEO0d5ChMkKSBYpdC/v6swXDVdTipWHV8olLq5qWwhHDF
         h5i2/pLikfQOD5DcjJ4WN1Y9FAllqiZnOuNv7JsAExqnx5HfKen2zri5XzpzI31Mzgp8
         +AzQbPbL1m3p1IyBnbILcud+Tg6zal/slKSNKNi1ub3Yn3b8kHON9UBAY7liP65+8CpX
         COcjU3AtQFoy6ZfQJ9zINauSeFUlPe+4FWC0j7/Fgl0lSYX89uHwtiE7MsNiXPYlA1lW
         pXpt1GrC63CEF2EVsmIwdphuNNLDa1TaPvPLf+ZD+o+pUxVfrPuSARjEnOnRcxsRtCSp
         HZYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ntEvngiBld9YLU0747oSd1TNAYwAva6+GVllkWAl9yQ=;
        b=fbZKBPBe+UZwZGz7XbflD436adIKdlb1UDRoCfoc6murMfRZDUZtMRq8GuFuz79JiJ
         qjGJeJmFKnf41eyHty82mJuen5WrYoRPWnFDYRpgLLLuXMySuC4Y/OM8dkYo/X20XiS/
         +1iFKxwtV8fD4egCk4VMayNaAwymH/gNKst6S3G0teeuENtUDAAmzTGf6IjDSDmmZ6oX
         ZSr9wNj3RYI5i8vXPUo8pxBvsOsa1GFVm5xRigBAmlARrPCuYOpse2T2M1g663oKeEg8
         DRGzPbQ19nMdw2A3l37elwcA+iayTEVdlJ/BGgf782+9JG1FAZn/pGEBDMrIEBlb+XMK
         AOVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ntEvngiBld9YLU0747oSd1TNAYwAva6+GVllkWAl9yQ=;
        b=Ek0f+somA3crmi3WjuX4fLDNvbL3C2KST/ZV3YM2Sp69Wt/zPF/Cmyz2jWO1kDgVmk
         ON2S7BvzptJ8DTdMjk2SpImlK/MAPftzuAmodr4eANN8oqz6sXR77X38Dsnfa+QHy2K6
         sXNyGWBqfUQWwKLxEyCVjg2B+LkjSv85IYw/KdPDiEJvVFOHCYB5TjtuW2MSJ3sMXt+f
         hIxqrcYOi6CTDmiKXG1vDm22DBJyIwH+7Dyc6agT6m/HYCnbOpKYz+fFZu8c2h3WuDdq
         BqidhH9CHIzf5u2MoOrdaRoKm3Mrkx6n09LqmA/GDkT5tvX9wQ0f5Yz1ra3jkZnp9GsC
         QNKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ntEvngiBld9YLU0747oSd1TNAYwAva6+GVllkWAl9yQ=;
        b=OKOHcl31taAvTOTpCoJIaZ1TMgAHcUYygnud0Yp+RDFlvnOZ0CRKFhjYPv3XJEe5a2
         +6YyaWHnQeXgeN/uFzQkhUw1TRh+AErwat23ghWa2HtPVstkQKQNEhhxJgu3Bnd1OXFr
         R3+8wIrcu67SzqR+AArqLPqOAZ9uC++SJSzdcFK//8q1xio+PjszbiotVYdFZl6R7cMl
         ZPNH5ngaq1rZ/F6ckswNyUO2uwteDibgDEO3mtPioacjU1Gf1XjrjIz/u5bJp/RwZLOZ
         hR45tU1NrtBLwr77PAN0Ne3n4X/w28F5C4+w4Jdpyi+3zY3muOJbL578b3purcQqvmy+
         0KsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325r9YkWuP9yxkj9rMi7/OMRKTqZRwTo5K9IWTrWkdBEvWbXDkR
	xbEPnZfM+gDCrBiKCUpGKqI=
X-Google-Smtp-Source: ABdhPJxuENT5qocF52A+f4MLvCzAAkYNJkyBqQHpWFAOQIJxL8wSBRX7bSomVvm9dfaLTzt3xr4LRA==
X-Received: by 2002:a17:90a:36ee:: with SMTP id t101mr1989914pjb.47.1597404715569;
        Fri, 14 Aug 2020 04:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3367:: with SMTP id m94ls3556333pjb.1.canary-gmail;
 Fri, 14 Aug 2020 04:31:55 -0700 (PDT)
X-Received: by 2002:a17:90a:2207:: with SMTP id c7mr2020550pje.206.1597404715128;
        Fri, 14 Aug 2020 04:31:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597404715; cv=none;
        d=google.com; s=arc-20160816;
        b=SFUKF7HZWf11CTBame1r9lHsvBnJDOaOogERPlIXqCSDm6PuhEIWmsMEPt/tUtlwRg
         xv53ruBtWHTy/cvDNNRg8BipkMhJvJIXLQnQeDdZCnbElCzq//dLzB0tDbkEZlIVc6Op
         cdCMpeAINZsg/vfigyHnV85IWzlBha1OhrJ6/v7sco6UP2NGeFRYSBI0sDkcfr4BqyWl
         93Wy73TOgciyKjYQP5T+oeGndhG0A/5B/dRTvT00BacM2P8C+8AQ3PNTRM8mKX38PUt2
         k6KCP7wrKMjlztqQ1CNmnhgLwxQPYhKAaNBKZ8zoL4PiSZapWYZkHMobgyD+uwYTYY9o
         LTEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=u7+amVqt37apuUzOjozjS3tkntRCbFkqWzBZd+wfL80=;
        b=N0ziGBi+kjXPN58DduOkubbpjY4Ro+6G9VWWLj0nZzk6gQrOHJVkwTnTw64Su0NKtC
         QCOYpmoPym5liEjelJXh+uFlcmBCyIpCRZ5QZYiNmip216TEEgfkwdQjDRy9wYYfsgzV
         7KlZ5UTsKZgw27HNNUyoY1YKgzCzMrFW40aEyYdMSK9qBeZjKOuFCitnv32++lJ0a1Jw
         GvjzIGyZFrUHx5u/x230tI0VxmC3/ZS1qpYKVNUsP6rEU8gsvlXIPi0nPQAXq+dISufN
         KwZc1AlBFFMgSmkzCJw1Ao0EpYqQ5l9eGKRmYCj8kilb94BTQumGYZa5Pp6ytKw+NjOn
         uy9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t13si485146plr.0.2020.08.14.04.31.54
        for <kasan-dev@googlegroups.com>;
        Fri, 14 Aug 2020 04:31:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 177651063;
	Fri, 14 Aug 2020 04:31:54 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.33.165])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E25063F6CF;
	Fri, 14 Aug 2020 04:31:51 -0700 (PDT)
Date: Fri, 14 Aug 2020 12:31:49 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
Message-ID: <20200814113149.GC68877@C02TD0UTHF1T.local>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-9-elver@google.com>
 <20200721141859.GC10769@hirez.programming.kicks-ass.net>
 <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
 <20200814112826.GB68877@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200814112826.GB68877@C02TD0UTHF1T.local>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Aug 14, 2020 at 12:28:26PM +0100, Mark Rutland wrote:
> Hi,
> 
> Sorry to come to this rather late -- this comment equally applies to v2
> so I'm replying here to have context.

... and now I see that was already applied, so please ignore this!

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200814113149.GC68877%40C02TD0UTHF1T.local.

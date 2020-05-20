Return-Path: <kasan-dev+bncBCT4XGV33UIBBWHKSH3AKGQE55KDU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D3AD41DA633
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 02:10:01 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id g15sf1843262qvx.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 17:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589933401; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wcqel5PEydD3Jg0+U0OY3ZTBADkU5S64uG/a2DEKb2xHmwM1qr6B/BQUTsRr03b55C
         HKcoq4dRvAyPTIo7g1k1OPvnTzGiKEK4BPeiKNixfo3Urqbr5nZaenFGQdh7oQmcov1n
         2Um5Gk16/A55+0J9GvHUotYJ4AzrmoVwP/bOA9kae2sKHsvkCxvq+lzHbRQJtP120YZu
         vPh8pfV/m315Z0quGCANoCL6rfEgtp3IeWaiWZgM79NewmoXvqjl8P1RVYFJWahEE5Mo
         7B2Gv9c/DiMK7goGV+VerlfY32P+ZAT6EIdUoQD5+gkARr1h1H/AuNnuMeXYwgEraiSm
         85bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qSfB+hMOVJUQzbNqW3qUYecE6QTvvwAl1qREYF1mrew=;
        b=BtxSZcCXun5HdxzqFbLZRmiB/MV6ZlAgo4OXmHggXMskpsNZK9sQIRntrRZfTv8rK9
         uYq6jcAW9XCebojm0K6auBS9ombo/rClUOOG/Nx3RN179vWkknWeZSKAEnMjMFqpkOWP
         H2Cal/YuFvZN7XjzDz4Vt/EwY6rwHm11P9VxNcQ+gfCeR6uv+LL2ZPawUGxLnE78F8TD
         3SgcaSBlieTM43UrcDaHUPpiUPbwHAadKlRIthJN3c7J+tyQNDW/5Q/SWW8nDge0xknS
         61phC7J42+wPsvFY3pNb+bWBhqRoo8G613vQHCnagJiWHA1r/GY8Cy9rSqhvc5PaX6aV
         ly4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=T4knsEdc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSfB+hMOVJUQzbNqW3qUYecE6QTvvwAl1qREYF1mrew=;
        b=KwmSVjNezs7lu+Y/ohU+qTEM9i74w3pcU0qj1qrvjJ+ndO0aLh7Sv4q+8zUxADvsSX
         GLnj7/dxzVkjNCvfrVN3ZylYxduTyxAh7XvhlYJcPVwTigxO+tmTEPV2RqF+ZcF+1rpO
         lRxs28Jw1tHwDGuvGXpMnnpCjrdeP6kih73RtJtwb8Ib/JDTnrEfEiMPAHA8t9B1AXMP
         DegLDoJJpwzzPHOZDYbN9mmXg2aKn2u2KnhfOJFrmC1uND4iZMGOkDPzhrtnDOG0yc/f
         9aaLWHcrMeAq/95vr6gbVSdZ67YVXIXosbJNRwCRwvsxlxPCZDASB0eBpaerwGbX0CQo
         NSMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSfB+hMOVJUQzbNqW3qUYecE6QTvvwAl1qREYF1mrew=;
        b=DEbghYZz23Hd6HoJNuc06aa43X29s+fCa4Z2GHHq/9g3Ca+HQ43sxNg7elclnQi35e
         LkgiGz4La2zTnd0uOdo90IKjnAKXa1lqW3CCGd3tRu9kofQfvTti/lhU8uJ1rmcMWpRt
         e/sBOe4+pdColpN5guEVfxzkXVcNFiw5hviBjpcALtNA9V0KHMzt3jed4lv2+R6a3t88
         5dswrLqb6WMN1IRS8xLpZzxWf30DrNxxkUrQ43ig5I1A9YhPcSNSVvOsCVFNPYaPdvSh
         lNt38aVu0jakbJtwgAVGWlU5wXvOr/c5HU5S0cqdTWz49B3C2K6MlWIQe3RoB+56xn49
         LyzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YHKW5mjCHMMScXAclJ38eBoemZ3b6BdS5rZZMR8VSLnqLvSAi
	hJveNyJPdWkMxzMB1INDw1I=
X-Google-Smtp-Source: ABdhPJzeq/TwJlyEI3+brOXWxrGShGsQsJOho6GzJfF8ZmS5RAXMPP6iO2Xe4Co0A8iWqnyyUoldPA==
X-Received: by 2002:ad4:466f:: with SMTP id z15mr2426338qvv.101.1589933400919;
        Tue, 19 May 2020 17:10:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e001:: with SMTP id m1ls748255qkk.9.gmail; Tue, 19 May
 2020 17:10:00 -0700 (PDT)
X-Received: by 2002:a37:9b0a:: with SMTP id d10mr2205058qke.31.1589933400536;
        Tue, 19 May 2020 17:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589933400; cv=none;
        d=google.com; s=arc-20160816;
        b=mt88D1LNxcHYLOPpzH4bNm823CF38sIAYJMraHXaVUQUuKacdeBk1l+r6lIDoHTvsA
         sCiqXgjdBK0PAmfbgXh46Zb2o+WFCHBNRhKfIFuUUjLJ/Pqh7b7Ck2p1Ce2gTFJXtqWb
         jEaZ8FkKmdqz9cnK0xe2oNe/wIhWVAVtdjU/NH8kWzKC7P9x93TOXhBjqYXM7EU3OJO7
         CYiAounoePNSbZQx4Au7nnfXdBLmCGA7BntNR5PE7QGIznZss6mkxoxSSXU9O43X6w8l
         vNGOa6RfzrUTpaSqYc9m6q/Rl3z2TTAukgZ3Zy9+praxeoMEB95K0wVNaWS8V/lrnd5F
         1NNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hwWR2yHVa1A2JtfihWCXgxQkskbxJ2qEYdBbDkSECeE=;
        b=EQgFP0bDThgXk0H9L4heOf7udpJDopdJ9yvxteRlRaJE2fJwFCbwvgimNd9mDqrAGv
         xPwxE7QxNrHBfZIXehWjxWwB4+X7GgwPh80cjVuh2hd+YSBdnd48jVaCBDwhP2PmuZWZ
         xSHCz+qZ7V5hmSdf+WoBLWsA7b7LI6QBkfN/uNZ9U+JSHk2IclHOeOTDiN9KDHwfdK31
         J8HyTX0K7i9itCDFUPm3mhSWkMnMRM5BAQBVsPO59Rm2Gvtc+5vHoof3Xd3XJjm1OxlU
         SOZaIodCbvOyGr8hZOCji1t2JRSgTP806B8Tf+ukw2k4L/iXS5zk5F+04k5in1ga2jNJ
         Gn1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=T4knsEdc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c186si88490qkb.7.2020.05.19.17.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 May 2020 17:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 127CA207C4;
	Wed, 20 May 2020 00:09:59 +0000 (UTC)
Date: Tue, 19 May 2020 17:09:58 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, LKML
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Linux Memory Management List
 <linux-mm@kvack.org>, kernel test robot <rong.a.chen@intel.com>
Subject: Re: [PATCH] kasan: Disable branch tracing for core runtime
Message-Id: <20200519170958.d6e399f7f98286c1162f1383@linux-foundation.org>
In-Reply-To: <CAAeHK+wcrmo=Hhwvqzd8kC-=5UR+fzRcA_4mo8wccWCTdrEzEQ@mail.gmail.com>
References: <20200519182459.87166-1-elver@google.com>
	<CAAeHK+wcrmo=Hhwvqzd8kC-=5UR+fzRcA_4mo8wccWCTdrEzEQ@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=T4knsEdc;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 19 May 2020 23:05:46 +0200 Andrey Konovalov <andreyknvl@google.com> wrote:

> On Tue, May 19, 2020 at 8:25 PM Marco Elver <elver@google.com> wrote:
> >
> > During early boot, while KASAN is not yet initialized, it is possible to
> > enter reporting code-path and end up in kasan_report(). While
> > uninitialized, the branch there prevents generating any reports,
> > however, under certain circumstances when branches are being traced
> > (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> > reboots without warning.
> >
> > To prevent similar issues in future, we should disable branch tracing
> > for the core runtime.
> >
> 
> ...
>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks, I queued this for 5.7.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519170958.d6e399f7f98286c1162f1383%40linux-foundation.org.

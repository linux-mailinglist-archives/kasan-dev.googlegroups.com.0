Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXNUODAMGQEQG7IIUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C557F3A88E3
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 20:51:26 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id q26-20020a19a41a0000b029030eb7c42df3sf4164297lfc.18
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 11:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623783086; cv=pass;
        d=google.com; s=arc-20160816;
        b=sBFzEpJkQ/E3Yqzmeegbygp36RkBXiwWzsFH7KTNxzH5DGeH6gLhRkdC+iLnkvx0qz
         vkXhFSaJ7OaVFWneWKviODZf8dvVv6oq31JDeTRZoXBqXYt98svWceFna8uf+Z+sTRk6
         QPfeHoSP0U/vicfpprroLidVeDJ/25oJeoUQMYQNfpdNJ4TkCYAOqwaaiNePsb/Zsr+s
         ywhmxYiR7dC1zMr54ocimByi2NZzfGzLVRhrpS+3NZzqdKv9g8aMuOZNtV4xTje4xF06
         CoLvfzFQ57ukssQsAtNQ1ROZDz1STs0yXVwFMbjzeP+MhN2SuXDLnfBNE8AS58OFJI6U
         plxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WHSQI9OzIFgbwyRkUNMM50zkgRHgbLcNEXsPEU/dJMs=;
        b=lPGZEjCTqwj5ATxF1NV/wMU2Cfx/U9+LVreePRVWr4M4oNjzf1QCWmcLLjzVE02Q1j
         CC5N/g3UvTc8l4WgSp75iGY1bn1paLzPRwetFu9dsr79mvyN7BNy5MRLPFuktaR2HGOw
         EAc3UX2yJmCJ0hhZHuShP2SHlJdw1K/xR/Hx9ufO7/AaVT+GhXrQ2QB708JOC5kL8n/1
         6DdP94LZ5ECt3HgBTsvhri4NrR0qQj1yOlukdqhfm1Qah9l8ouzAlVlAQ2dg3XctE33F
         7DvKmZ9Plmao43EvjjHBj48SJAKokyh7uPLuBuo5ya0ZdkB0cEIr7IsbKGlvKLwGcKgj
         wnkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SNM+6i9d;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=WHSQI9OzIFgbwyRkUNMM50zkgRHgbLcNEXsPEU/dJMs=;
        b=sZHZjbdTwOXXJslf3ZsevGjFzbxj6cdfyG1FUh53q6xY0pjDsVcEEZwZT09pIm1rg2
         d7oUt+oqYqojAxEMQOh6D/D2cm+fg4fAUAKn+jlUbtt0kpGj2SeTbK5ZX98kG38wjHXb
         qBKCjLEhTdfZ5RPDTvFdoiOjOTgId0wTCD+iUR5xtH9w9cuLLa9vOX4oX8Hm4TzQQIBP
         ZKM4ltgUAEZ2fsHDzd9JyKjiZfPfS+dWKZTnw62uZL7+r62K+fOMyWc6Iw5uBzbPTpGq
         eRmExdWae/4igsBKoBKxsQlj0YXhyKj02Y5ejQz5y8op35q1u2iM6iScPRuONo9CXQNK
         qwQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WHSQI9OzIFgbwyRkUNMM50zkgRHgbLcNEXsPEU/dJMs=;
        b=qAFQf942EA6o431YnDHyANu44TEyloEG3A/nx2UZdaWwU9puHqYhxnlRHgnsE/M/zq
         qoWufaF8yIfr9QQFvwyziEZnmUgxjntEa/2WKzhuHuUGo0LHWDnZ8F8SuyxqQCQ/YynZ
         oClOCRJJenB/L9UrZu+akClhCAZsUbjxHO1CDVOH0GZVjV6VsRClk8sgCv0cIcXbr0RJ
         YB1oaGmqgatlRq0N6YNquEs7fSkXKwS5r++fSn8eWV+RJY1G8pH/h9tKmVKcRkDfNwWH
         iSSVS1YEueGod90rqdMqaYhrZtqf1a02coet6YrV3uGvotFqQ/u5SJXaANdqN2WRwPnO
         5RJg==
X-Gm-Message-State: AOAM531j6U7pGML3qYu6TK732qQjLNUDomoHyZuPpyv9KwwedJXsaBTm
	Ndzb9OamDAQBQ5mX3ywC+zg=
X-Google-Smtp-Source: ABdhPJyPPExcini9b4CeGa7Gnx4dZIJcYYMerVsB0vJ7kLKKbLK51Sr2cvjUE2HU250AZ8K+Y1pljg==
X-Received: by 2002:a2e:5047:: with SMTP id v7mr926410ljd.510.1623783086419;
        Tue, 15 Jun 2021 11:51:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f94:: with SMTP id x20ls1464532lfa.0.gmail; Tue,
 15 Jun 2021 11:51:25 -0700 (PDT)
X-Received: by 2002:a05:6512:3d29:: with SMTP id d41mr595615lfv.546.1623783085246;
        Tue, 15 Jun 2021 11:51:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623783085; cv=none;
        d=google.com; s=arc-20160816;
        b=LxJYv0bbDRDr9jxyVSi+vqFrKi206rkxQcCOpbemqcSK4I0RRYBRFLCf1Aj49Wwy0J
         yWnYpzn6uIFxvdjcy3kBzf360q2ph/gDynJV7ZDecVdQqLrsMmrD40Y6SGNLlZP5uyye
         dDiqBGQm32a6tLhr0Z5wbxx4qC6eytun52TAruurE9PDhYKVmtQSZY1ejpYSv4tyecOX
         0IHYMDY2paxRuTA0xgNgTg0BMY0S+pKqFKrzK5Nf+hG6+M1nX4OACf/YQ1P2U3/aoKQM
         rNm8NBBzGPvueYA4OdWf4apUg/yVP8Tej2wHWK7lEUxgJZTNnKBZ17R8nU8mZlkfNJd4
         UMHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uwIcPiwJdf3jh813ElBB+grh5aH2j38/LFNqkrYcIlU=;
        b=pONwf8Gf0il89ehO7ZEF7SK5knEKecMMWJmCvjmKzLgCK998qkKcMV7iCBduVZqYFt
         cmbfIcVw18Qrp3BpY4EiXdy+H/8/ba//aMjGaLhWzGjbm0FOX1GuyuBdDdgp/Yuo1SPb
         Z1FELjqc3PL1xSbCr1zzkxK4ITB/F4QpwBNocuat1VS7dDEer5q7iTfTj9U7xb6ugl4P
         ZYKUdmt+Pu5L4WXVO6ZJ++6i1KjM5jynr9+U9Bb4nPxkAd1+oFSOdDdoM0+LO65IEfba
         We7Fu2etdr0JRhJ/lRCcWKkfMAZeK5FdOGfYFvW5HdzRoQdI0/eTYszFgDPB4pJGgqEd
         bXVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SNM+6i9d;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id d3si126862lfl.12.2021.06.15.11.51.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 11:51:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id d184so14750467wmd.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 11:51:25 -0700 (PDT)
X-Received: by 2002:a7b:c10b:: with SMTP id w11mr6922360wmi.186.1623783084817;
        Tue, 15 Jun 2021 11:51:24 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:87fa:cbf4:21a6:1e70])
        by smtp.gmail.com with ESMTPSA id j5sm11544847wro.73.2021.06.15.11.51.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 11:51:24 -0700 (PDT)
Date: Tue, 15 Jun 2021 20:51:18 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, boqun.feng@gmail.com,
	will@kernel.org, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
Message-ID: <YMj2pj9Pbsta15pc@elver.google.com>
References: <20210607125653.1388091-1-elver@google.com>
 <20210609123810.GA37375@C02TD0UTHF1T.local>
 <20210615181946.GA2727668@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210615181946.GA2727668@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SNM+6i9d;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Jun 15, 2021 at 11:19AM -0700, Paul E. McKenney wrote:
[...]
> Queued and pushed for v5.15, thank you both!
> 
> I also queued the following patch making use of CONFIG_KCSAN_STRICT, and I
> figured that I should run it past you guys to make check my understanding.
> 
> Thoughts?

You still need CONFIG_KCSAN_INTERRUPT_WATCHER=y, but otherwise looks
good.

I thought I'd leave that out for now, but now thinking about it, we
might as well imply interruptible watchers. If you agree, feel free to
queue the below patch ahead of yours.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Tue, 15 Jun 2021 20:39:38 +0200
Subject: [PATCH] kcsan: Make strict mode imply interruptible watchers

If CONFIG_KCSAN_STRICT=y, select CONFIG_KCSAN_INTERRUPT_WATCHER as well.

With interruptible watchers, we'll also report same-CPU data races; if
we requested strict mode, we might as well show these, too.

Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 26f03c754d39..e0a93ffdef30 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -150,7 +150,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP.
 
 config KCSAN_INTERRUPT_WATCHER
-	bool "Interruptible watchers"
+	bool "Interruptible watchers" if !KCSAN_STRICT
+	default KCSAN_STRICT
 	help
 	  If enabled, a task that set up a watchpoint may be interrupted while
 	  delayed. This option will allow KCSAN to detect races between
-- 
2.32.0.272.g935e593368-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMj2pj9Pbsta15pc%40elver.google.com.

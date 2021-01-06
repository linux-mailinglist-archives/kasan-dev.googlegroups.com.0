Return-Path: <kasan-dev+bncBCJZRXGY5YJBBZPI277QKGQEC4CEV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B5502EC248
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 18:33:26 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id p10sf3551366ilo.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 09:33:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609954405; cv=pass;
        d=google.com; s=arc-20160816;
        b=uXoSTdvANJvAi+kiExFDll93sfA9OXo+wvfOWo4jcK4+Bcson211S5oZZm3wgCAIvz
         ycQVw0MRyEu1hoDZRU2vDWEDs6HfmShrZ35dSLZkvOy/HHdCfV76i42A8zimGVK+TNC7
         mp6jI0aYkq2DLCCPNCUotl/wZ/CVSUV3ih4JyZ2bqTs5Tn2CmwuzAbC8slPoVyEdAPuF
         sybtNYTt63PUP5rhkNsx9zipOZuZwpoTlMzW1Fs6i1o4UWJk6YN8GwaQammgNvcMKSvP
         pJKjI2Fl3Te30enAAvO/HVkwDGIb7u7jexMkYQ8bej9QyA0Nw3lL5mNp9XW3DdnE//nw
         tdbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JdR5Ke1cI0osvSovegkTZWnRgyTjBHpNAploTYqqkM0=;
        b=RrjZzZHG/dtqcg0loRJtpenBtJiAR9lC7Z0P69ufzSg0ynNsJ6TB8a7ke//zZsL7NI
         sKcJ+hiv4OJC7T3flsiNmBbJdJWAtsOt/KpOkdEICEqQ/sALgMIRWGRNt+IEfphHu7cT
         D9I0vImgNXhOaWtc5kHRQX4KoyjLTbKbYRl4MGGpzPyNbuDyXOZ95MWfJLNPleS0qWFr
         W1k00Lk9UVjG/JekepBuFMcML/HwrmDROxtPOjgsoQB56fSsqJeDV8VokOgc5R77NKeG
         vv45j3vXJQnDJKjAX5QJZJvXebNC5Xvf9Wh4nKoI0b76fSVBGH//3z+uZp8JjdEoQFFh
         2pVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MbHL6xaJ;
       spf=pass (google.com: domain of srs0=z/5o=gj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Z/5O=GJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JdR5Ke1cI0osvSovegkTZWnRgyTjBHpNAploTYqqkM0=;
        b=H+O9Tdd7bmUBJxqT1APHAqu4u0ffCX5HctHP8ZXBrp2/Sm9avsoyFpiPBOljXGPmuk
         Dtsqlc28WeMOfW68EcMYFr7KTlTwbnZwpNNmUkMcmjFzq+bQhBAU7Fvr8934e7Cq45Fv
         u66uk+SGjZbdHENB+2FHHGAkpbu+MKHLEr3qq1zwojc1Q2i12WEWnu6bQa8S7Y0D8UIE
         h748GACB9WAN4dJlW+yIcfMuHYqnECz8Lgv145g7XqDj5XlnFniWg+S9gak1o/cb9ne2
         4uG3+/Z4IUnL2BJV73ZyF3MD+jt7tdbLGChQ2CN8sLGkn7+SLVwW+VzQOutQ3ZIqXNuH
         QkNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JdR5Ke1cI0osvSovegkTZWnRgyTjBHpNAploTYqqkM0=;
        b=ebhO1UGNiPrfAA1/pd0w8jIIFrvemqgu3ZWAuLV5n532zwieZlIeNgZpc0YRrg+z93
         x97yNyv7lehidhqaNRNttNNLeRoU1LFXB2Yz7219upfjtedYwGtjI9JHesRjqkGg0lAg
         tKNGH+4EwcDR63rPA7nMHAWEKm1/5KbeUGvaJbxKNbPfa9hy5dZsLGp5bx7aYI6ZlMdr
         jsSjpQFs6iFi/Z9iZP5B4loWLaswb/BpM0N7Smuzy8CYoL0K4qh6kajGXyh4HbXlC1qU
         HcKvG6zIzv6xJaH+FrYfytCMV6KJ+tNRFHabYEyztiyQduDAkzYDPE9qQOKf+ij0WM13
         Gp9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301i/hgX/yGuUgm20DeSJUyJnhVt8fMfhIiQwGNzxz7egq/Kw/k
	bKR5tlr+BRdagvbVEISctrw=
X-Google-Smtp-Source: ABdhPJzAKX36orSOxAsZo+dEynMcofmWnZMJzrCMpjMfGNZeey4Nh6skyPLGpig9f+yM7fZogI1VUw==
X-Received: by 2002:a05:6602:1cb:: with SMTP id w11mr3634304iot.45.1609954405407;
        Wed, 06 Jan 2021 09:33:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca09:: with SMTP id j9ls1038232ils.11.gmail; Wed, 06 Jan
 2021 09:33:25 -0800 (PST)
X-Received: by 2002:a92:da49:: with SMTP id p9mr5224686ilq.236.1609954404985;
        Wed, 06 Jan 2021 09:33:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609954404; cv=none;
        d=google.com; s=arc-20160816;
        b=wbTsCJgJwVgyxxFoLOYlrPrvBsX5rzE7xSoB53MiD66v2Zmct21XcYzqeIFCIuQT1k
         jy4i+BFhCafwDEH9nL0Teqd/IvI+EhF8JfvIGe6JtO1nSJp14e2daVBIuRH9ctEerFZA
         /PttFhLA6m4fllB+muusg77nOsA9xDk7AzDPScnIgbH2soDPi6suGVPU0cHvEblNRXqe
         cLlo4E2FmYUQcco7xWCfUAIeS/JEoFh/U/Wrj6xhtgmp+zpHI5DPQpB2B/s1IdRAyfcr
         OZNNqHAiDOF7mH5/5dqMRZsTB3/Z9+FuMZdForHxEI2FjVNtMOTpzeZfe8m8l8pSdtz6
         TKNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vu5vI6Os1OxdK4MmFN52/wHIBxuAkUH2zzSQFXygUCs=;
        b=NryayBhHzPhS9dogfdSg5nbgqTqy2MEREBfsH/k5qPw7esF9FDlSD5AK1+lv1UTd1j
         na2SQbgwZn/nMsd274Bu1nqf6NoSnQhoCHOePUc8TEHeoRHMIGy8svoRaOGZ1BDRWbRA
         wvsq0zVbDZ3S6RNqu+/I7iWKm+gMPkR2raClMdwVWB8C8aHJMxCpA3GvSH0+W2JJC4s3
         TQXa4znfdXeKzgHBX9yVW33PMggymp4WSMSZS/avcaZGcc9aaKCm4orkR1NkKxUMJ/T5
         cck1V28vy3U+m9rWggSxvkimD1McR9Gh5S0pl+dM4rMf5J8sY6NXZCWBbTmv9VX3N7bt
         0fng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MbHL6xaJ;
       spf=pass (google.com: domain of srs0=z/5o=gj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Z/5O=GJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b8si386421ile.1.2021.01.06.09.33.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Jan 2021 09:33:24 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=z/5o=gj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 340FB20657;
	Wed,  6 Jan 2021 17:33:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id EDFF435225EC; Wed,  6 Jan 2021 09:33:23 -0800 (PST)
Date: Wed, 6 Jan 2021 09:33:23 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/2] KCSAN updates for v5.12
Message-ID: <20210106173323.GA23292@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MbHL6xaJ;       spf=pass
 (google.com: domain of srs0=z/5o=gj=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Z/5O=GJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Hello!

This series provides KCSAN updates involving random32.

1.	Rewrite kcsan_prandom_u32_max() without prandom_u32_state(),
	courtesy of Marco Elver.

2.	Re-enable KCSAN instrumentation, courtesy of Marco Elver.

						Thanx, Paul

------------------------------------------------------------------------

 kernel/kcsan/core.c |   26 +++++++++++++-------------
 lib/Makefile        |    3 ---
 2 files changed, 13 insertions(+), 16 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106173323.GA23292%40paulmck-ThinkPad-P72.

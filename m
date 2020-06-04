Return-Path: <kasan-dev+bncBCV5TUXXRUIBBC4Y4P3AKGQE5ALZGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D0E341EE260
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:15 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id n6sf2242497wrv.6
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266315; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWn0gwgSWiFT8BtD7l7rXHGTQiAnDWa+vuauplhXXbkIj4GYcEuS6ov95AWihu5OhD
         hcBlbDmW0F+34pBqj95SN43aDDxzhf3gcQ6iYdSl00BcNI3BJspq8iTv9Ucrga7Tzrbx
         M0xbHv83JHk/cEXZ9GB7yFT1t9dB6VHeCYL6SwPN1VTlfg/OZyEP+G7rZ2y2hAcyDE4O
         ETG6LlBJr1ldrmrvl+Jmq+2fTRDEuGcY3E34dxdyIfKcccMzQAF0L4j8jJTpn6oDVEN1
         /xMVp2wcsI16C08/eB3S81mNVEGnfjATDpGIDMys7ZIr53iXDMYBSZRW3KSQ9VSiIxRk
         KVKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=hN2D+CHbhCzVnP0ZzZa5MGlHcpwXlhdVV/1AFGuaYao=;
        b=wxc8Sl8bwHsTQ6ka+cwBugSCK5OmpO/9cERcVae28v7iEf14ODN3hk9JShXKP3k+8+
         DJHHJrkelqWsfyjnEf15wGB8YzgPVBtuXl7YZYmwj7xKIotb2puvUfKqxwHOAKkyvteL
         DC5xEldtOJxy+foENtUv0qrDic/jHY2eA9QInJkVlOq4S93WkrerWy53CNuyjOkfftXJ
         2IvYF5h/YoXHVzkorKtyXm9gRuuJSyeftN+/1E0Qk/SqduE0bGehajIbpmL0th3rxnwZ
         5uBuefSV+etMrmnc0JNVDrpnGJ9COBeboaPWJaSfzsRqlb/FfFOuKk+56YsUwVK8fO7k
         wRhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zzqrnKvo;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hN2D+CHbhCzVnP0ZzZa5MGlHcpwXlhdVV/1AFGuaYao=;
        b=piHvn4RWvVQvjIojddhq4RJY+YaBdY1A3YkxD73Kr0wKUMtoSztb1qoswp24ucleHM
         VpsOfLtzZs2VjrYI123i4h98rmrxT+uS22LrUhCwMP95Il814mtRR4P5zEJ4sFXPdo32
         oYsUJb43YKb2SXZ/jYUvyNz0EVcqr1MKLT4gf8696lXQ5I0E3UjlL+ncO6SaN6zJBiB9
         +e4DZ1YS4G8AN/xqgtD+467ohedK4G9iddlCT727m1wdD86T95yKAt+NRWk0UUSsqkYK
         /5KyHkGNA51PPl8+r0IB7CxiFq6993FvV+0aSY2tyQFUkQair5XOSP50ru9XRh+fY0YJ
         iYIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hN2D+CHbhCzVnP0ZzZa5MGlHcpwXlhdVV/1AFGuaYao=;
        b=gBaL2BGj8ujqkdyBUaZtqbi79K1plTyI4awnlk3haef1PkwgZTRcWt9wco7OmPpR7g
         aaanNtJPDsiv2w+lKBwBSm9GbZQVFrCJmDp5qjusatKhKljTt1WkKlN18HradCf60Z6H
         V4RULTIRtDozpa+oiA5BRbJIKjF0ph6JwbG0av8BBg9nahMmV5JsNfV5eA4xp7DXyd94
         xB6TcnXHtP5IqQjYxeOU2/cOS/1/u3BzigLI/1HhzzvTq2++K3eJxFQKANEPPhn/YbeT
         a1LQpEdRLEtBp8SMjTQkdbrfbLNCSju5HuTmHRUUfP3Z/vVoXbTU2OYGVN0CpmqUQ9f2
         6o+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CiZCq3zGFKiyF4ksjJJBpTrz+2oXlJTbWTYekeeuckX5aQr/h
	8F4A5LK0L7Q0R+rQ5S0cL7U=
X-Google-Smtp-Source: ABdhPJzEmZhuA78hzrLool5M3e558jDP4P/SpTZhqzwfAlbyMTvn6ELVF6+eV+PPsrqM8w3fnozLTA==
X-Received: by 2002:a1c:5411:: with SMTP id i17mr3529540wmb.137.1591266315575;
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82ce:: with SMTP id 72ls6188266wrc.1.gmail; Thu, 04 Jun
 2020 03:25:15 -0700 (PDT)
X-Received: by 2002:a5d:6884:: with SMTP id h4mr4048950wru.198.1591266315179;
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266315; cv=none;
        d=google.com; s=arc-20160816;
        b=ANP6N0Ry4VZ2QLENXCIFd80fua8HNkkN21cfpmPMAI8A2gt7uG9NBgBkaNS2yUnGFZ
         MF0HUL22U6zxHiUX3yZT+TBCJwM60SEEaZTweqsU36/Ypuvsdp38aYFDunmSwEE2IuhQ
         h5c7QJfP/LLpp6TyTQKKtbi9VAaRlRKVUWQDg8muChZieE29tYBlEKGvQTDLJnKfZnNA
         NgZDpUo0l3wta5kl+Q128CDeEgprxl886cQjh6ftlEKrBlcGqpD0iDUzz0ckjANDw3Gr
         JyBX0MW8DrJapgWfNTG63aqxnBUG0C2LpMUQ9aZn5yzrd9XpDOXQljQO/JqkNkpbETy4
         d1gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=oykwMbU7Wmvh1ZGkCXwhZjfvHzNP7lFFbQQT7fF0pCA=;
        b=HhK51dqfbhzidM5YWakJkkoXGEnhrUVA26VdigUe6UuASKtZnRNGP/So2Kdl/NzX4e
         lJRnK33eLwaO6nvKdgCQVJbCC1sWE1twDAN4Vx89wt6KUHa+mtpb/NduOojBriRBfEC+
         ZDlCpyhQgcRjqsq+BWfMdathYG4/i2aYVuGex2Eoschf+bbxsmXcwC+nXCmcBqZ8xaqA
         FWjHylKVqD552WwFbqCOlPxkBhNNDroVgtN29F/DqRfOVsp3IDEA4J1bnVGA20O9Zrs3
         LhZefjTYMBeD1WYQJcle2yf24J9S5NsSQwvpf7KgqwFfi4ZnRH51PbM1GkCvb4aADz5x
         ahYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zzqrnKvo;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 61si183081wrm.3.2020.06.04.03.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3e-0003tl-Jp; Thu, 04 Jun 2020 10:25:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 10E6D306E56;
	Thu,  4 Jun 2020 12:25:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id EB8E620CC68B3; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.364746275@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:49 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 8/8] x86/entry, bug: Comment the instrumentation_begin() usage for WARN()
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=zzqrnKvo;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Explain the rationale for annotating WARN(), even though, strictly
speaking printk() and friends are very much not safe in many of the
places we put them.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/bug.h |    6 ++++++
 1 file changed, 6 insertions(+)

--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -76,6 +76,12 @@ do {								\
 	unreachable();						\
 } while (0)
 
+/*
+ * This instrumentation_begin() is strictly speaking incorrect; but it
+ * suppresses the complaints from WARN()s in noinstr code. If such a WARN()
+ * were to trigger, we'd rather wreck the machine in an attempt to get the
+ * message out than not know about it.
+ */
 #define __WARN_FLAGS(flags)					\
 do {								\
 	instrumentation_begin();				\


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.364746275%40infradead.org.

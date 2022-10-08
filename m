Return-Path: <kasan-dev+bncBDBK55H2UQKRBEXAQWNAMGQEKWEJFVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F8C25F8538
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 14:41:56 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id z34-20020a2ebe22000000b0026c18a910fcsf2975792ljq.23
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 05:41:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665232915; cv=pass;
        d=google.com; s=arc-20160816;
        b=LjiXlhuMQfhhCx7+RjvMjiKyIUptwWzC8ldnghWLZPHoqfvAkk72rx4CflUaXrkhRl
         HbkJHg88dlSq+E6G68rxDE5QVipV0E0rlf95eOc/w+PXNx1bd8wFndPcvKzRUqjopx2e
         S9jX8k2BjkmfyqMAmjQyVO7/w4ooJ8DVwGUzpS7+MwmsYcnxpqWqXzxgG1DcSvjXWyCR
         bc8LEi7ZozUh7b6JEsG2aJT2O6duI8pHksdxCRHRoW7r2NR12rTQ/25qlO3VhBm+Y7J8
         d26AFClBtlonJJGekAY+e1t7lxHT8R4fNuVz8dpnp19n3+GRuEAav9sdHxMP78H5sqzC
         xw5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0twvEfXltUlLgH6Zov92PYD4WEeK7X1AG+PcS6r51pI=;
        b=GOScCc1f0w7HhAbsUiriQus4zSxx9sAj0URvMvrQlDJvOSE/tZlJoZtVPE5nNRHh64
         TOVVujFzRkmlD6rzjUIxiEo8Hw5qRjojLhn1SN386HVmpDZP1K1B1DPnOd2/LhapCxwp
         4gF/F9Cw2+GjJGWN4PA/glnt8BSNADJrz6QJDFygBcLY77Z/CGOq4NXk5DzEpNmqiJcc
         XrXIB//yydbWqkimDFY/RVw2KHwrOrQ9242HzNy+CZqeDjwqhjxItYOi/M3DxCUBxRGX
         Z/4Uxip/y4RqEEr0kNcuxgLsM+u0x4wJRvTKIRaFzEXR5WmJNZTmjTt36C1TUC39r+U9
         0ZVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WWuA7kbA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0twvEfXltUlLgH6Zov92PYD4WEeK7X1AG+PcS6r51pI=;
        b=B4EGtu2p8xPyRRytk4M33vWnMaVEL/bpW4zM1B6vji+KuVPpgVpZLPI/AughlUyJRY
         7xFLIe0gxLTtZ0B2F3BFD1CuCN6MW/QC3wiyaekycimzmYprhmLsl8/k7dVqWrMqBRf9
         IFom6uLxSdD3DNMXbl91BfhdikaM5Zo+wz4sU1iZQMFrRc+K5VGow7V35merH6P+pe1F
         SGnHIdrduB4vcTY5L0alOpz+6Dx5lUW/atpHdh0sJc/2U++NZoMal8LlLvkRHiQLWLFU
         VDqA33QvFZYvKicyhrK7UqrdkXjjH83rDa2sB86PbhwnAprjxxeH7EhyS9YesUcGsGQg
         /fsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0twvEfXltUlLgH6Zov92PYD4WEeK7X1AG+PcS6r51pI=;
        b=bLVrt937o9w7ABLCn/Z984RbISOrZuGxLVzHQDfWrrlqx7qQBYg4tF+FH36HfZuylF
         8tZyv+vyFYwJAONj36keRFTwmOUU1CriwnC0KGpcArqNw78zjRblA/dpBKFwdvc2nzcE
         O84hBUoTe/RzRqKCyCdbBiJWsNA1P74gRK0zDZQlIoF0eaaQr2+sZMg9qerMi3xFd1VN
         Jin4Db9l7UHmfuobHBhwrsyUOxS8jOky9LKHimqS95PnG3FL7vk4BxSeBRcPXRIXK8qB
         ph4uarMYKHLCf94VaTlecDnzl/wEi21Vy4j6VlSsimwc1Wf2ZBCbrcV2BDHICJDm/cj9
         JBjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3e6zIkttA74Tj5GgnXnVb/3BSYndmPKBlhPoCW3jryurpzT2GT
	SzwgkyrbOggSZUizlTFbhz0=
X-Google-Smtp-Source: AMsMyM7XShbOL7KdibkGvim3ZsA/7uKCcJZgp/leIJrfag8EVDUuALFoKH9cWbYTtw9ovCZoXbTXtA==
X-Received: by 2002:ac2:4e93:0:b0:4a2:3007:d8ab with SMTP id o19-20020ac24e93000000b004a23007d8abmr3460227lfr.596.1665232915278;
        Sat, 08 Oct 2022 05:41:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8907:0:b0:26d:d082:6fc with SMTP id d7-20020a2e8907000000b0026dd08206fcls1403777lji.1.-pod-prod-gmail;
 Sat, 08 Oct 2022 05:41:53 -0700 (PDT)
X-Received: by 2002:a2e:552:0:b0:26e:4c9:bcd1 with SMTP id 79-20020a2e0552000000b0026e04c9bcd1mr3298710ljf.529.1665232913658;
        Sat, 08 Oct 2022 05:41:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665232913; cv=none;
        d=google.com; s=arc-20160816;
        b=KhNDKtqRllo4W6ix5MA0FDTFRegS+3XpuOOBC173v+3QWBcbs/vsLEs7VqYTPnmMnP
         1V9dAXm5HZzf5cqva2ZcA7x/oyPElRSKbnVOiR9qppIhARg22koyRYPqPdYin6mGjoN5
         WSiMWk3fHW1dQV/6eLD8gduz9xV5eCXdgHpGN1G5h+QfHnUtlPvSgZvMmeD/CKtgGvt6
         VJ/oPQ+u22Dr9k48kR810om7LQjBxkjqrk+FNXDJqmOEMKIoMY4ntQFvDTllh5GyGWWQ
         GiI2nuYCAxvUCJjb9kwkpuDmc4gIwZPiMSwb7AV6hqegzqmErXIYiQVp8QdYJEBtirnH
         VDNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1AqpcDikuJJT8s474v7vbDua4kAtza8/IGevf4nKFXc=;
        b=RIMaHWIyW39E0psVzBr1BM4Rf/SwaPEAucsFK4k8KADiC+Jb665IYsG1IRfw/4Ze6c
         ebwnp54l3vBl/y05a1ztc5TIvxzpdTVGrdB2zk3xwlvhgbXOsLEtRaoT8LCt5jP8I8m1
         bECByNlLTE6WCeHZDfcUYjGcprhvblYl7TFZ+CMZpgdpkEFSJeRpI0zzGvv7IYLcC0cr
         rJVUXoB+Ab7ir0zLJa2TnYK4ym6Q7IoXaXhgyfJWo6fzADqB4Ud8V4twwlvKod9rTdiD
         pGzJLRj/1NZpHjeBMavgRsoPjXVNkPxh4Bg/E/getDt9ZGcszt6mZ9Dkb3Bt3AV+oufh
         C96w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WWuA7kbA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id v18-20020a2ea612000000b0026e8b14ad83si80399ljp.6.2022.10.08.05.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 05:41:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oh99J-001i1F-Ak; Sat, 08 Oct 2022 12:41:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EF64330017D;
	Sat,  8 Oct 2022 14:41:47 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AC72B2BD85715; Sat,  8 Oct 2022 14:41:47 +0200 (CEST)
Date: Sat, 8 Oct 2022 14:41:47 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0FwC1yo1pcyL9J/@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
 <Y0BQYxewPB/6KWLz@elver.google.com>
 <Y0E3uG7jOywn7vy3@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0E3uG7jOywn7vy3@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=WWuA7kbA;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sat, Oct 08, 2022 at 10:41:28AM +0200, Marco Elver wrote:
> The below patch to the sigtrap_threads test can repro the issue (when
> run lots of them concurrently again). It also illustrates the original
> problem we're trying to solve, where the event never gets rearmed again
> and the test times out (doesn't happen with the almost-working fix).

Excellent, that helps. Also, I'm an idiot ;-)

The below seems to fix it for me.

---
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3441,7 +3448,8 @@ static void perf_event_context_sched_out
 			perf_pmu_disable(pmu);
 
 			/* PMIs are disabled; ctx->nr_pending is stable. */
-			if (local_read(&ctx->nr_pending)) {
+			if (local_read(&ctx->nr_pending) ||
+			    local_read(&next_ctx->nr_pending)) {
 				/*
 				 * Must not swap out ctx when there's pending
 				 * events that rely on the ctx->task relation.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0FwC1yo1pcyL9J/%40hirez.programming.kicks-ass.net.

Return-Path: <kasan-dev+bncBCV5TUXXRUIBBA6DWWDQMGQEEOOWD3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C32FF3C6DB7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 11:48:52 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id bu14-20020a056512168eb029031226594940sf7500329lfb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 02:48:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626169732; cv=pass;
        d=google.com; s=arc-20160816;
        b=HldfqIynGnZfLru2R1OuccwsPJIxsvaiGVeLkTf3QclrWTATl14I84I628QprS10/8
         +2eO1POppnv8paE2gtN4QVKwC/EDDgJVpu0919fajHTbTTc6NrDDo0p2DGHrH0Mxrnbn
         T+x9gwPoMDY4N8oFHR+sf7CjOXB97wdfFumefRyop5ISbVdsI22AcqWqCYdiKrxtPSxb
         vL2PTvgNOBMdwzCL9mM6CByBPSgGM0aqWBGjzffloOqwV2brJLAO8dY43loJndP/JEOY
         mbMYZ/hsYtccXnCTro7Mt563j5+uFResS/uE/8It1QO3eRwIFgleEP97wWIGNC1XzX+V
         Z9pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9DcoeN6uPys2rLVFF0bXA7fS78kwZpZnWUG8r611oZ4=;
        b=pUITDVmido8unvlRjHyYuCHrGuqr2H34ZRfjAcseXotqsncmFc1+3PHYLSfbFj6MdM
         BEFnGjuI7IpPuyhvJJxWxykjy4Vx8Hc7Z4UPB6lf94G+UMI51B63ycc4/0pYNazYQz3S
         kYYSK7qzCir8ubD/JsfbntBd/Ehe5OcCdrwhtQlohawN3e5ITpax/XDjX9BYrLZNFrY1
         jx/JR4/7ovc7h5QThfJwGZ0I6McHdPyKYpdLPEaNEF1We9UsqieKdcO24kDxTfuUFchi
         IHqsK5Pct7LWk7Ytryc0ANz/PdPC4K+Qa4vaWPYSWzYzwKn132ngELXbLFqcx1A6Ujje
         /sGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=B7IJS4Ly;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9DcoeN6uPys2rLVFF0bXA7fS78kwZpZnWUG8r611oZ4=;
        b=YaPmmoJxT7BYP0UZew0+eVRsoQTZRptiQKt7nH4n5AZpgP7zxVy7zAcqPd8X0DfzX/
         3jil26XYjgTnxi2OcTzTosNQZzw43ehMnwpp++0ZYPZoCyXljm7qFeowyiZKDM4FkqLI
         3FkoXLZEnv2sfhRsgFuM9LHnWGAlujqZ7yMmf+W5RcvW+JB6VAsELreP4zyNzYVbWs9c
         jDgCutk3g1eTAG4XQKVHlqPUY9pLRpRNy71IpcBWM9raLmDbBteyYpvD2PKw9gH+oSuL
         BYDj46MgvrexqKGdiO3Ju7yeLXgcK/Dq39FwddBVFqG7JXSNaAdfkqr+Eo90CkxxU6RQ
         Lxuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9DcoeN6uPys2rLVFF0bXA7fS78kwZpZnWUG8r611oZ4=;
        b=oSjoWhFisVrHLnt0RZQeKCeqw14RKxVHp/5JMUrdL6pSzk4mBFxbQC0+FwjKqxIMq8
         T66sdLdEP6rhqt0lLd+zWKt0tehuqJJOihb37/DrKcIOZucz/jlz614f28KXe/SPd1GK
         zwLCPupe20Tmnu/ZO5up1X8J3+TfZDKWukBzO1rlmGUzp7pCoeRuONYsu0d6t5TZ3caw
         zLdCHII6qBG9kNSJk7AEDbZjU/6pqFnnZPG0evLMTNuEhl6uNGDRibsUvuX9yZrs7dG6
         tYz8ADL8gEJBciujy+xRibiE90Tk/yomRRZizghPj0p4B0wBUXx/wyrSXcJjxDVWOhCh
         cqAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x7GWriWEsFAhoo3UjVahr3VsqEZRS++OZ7UT+6nEXHwIiVztf
	WqAlC+2tnyGlnnpih6KHl+Q=
X-Google-Smtp-Source: ABdhPJwqg5MQToJRuI/c3vLlAIXu3LZHcbBwoPuUzdBJmBp+WfGG2DoaZYmGfRfpJr4OYpPHX8cgJQ==
X-Received: by 2002:a05:6512:20a:: with SMTP id a10mr818024lfo.205.1626169732250;
        Tue, 13 Jul 2021 02:48:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:430b:: with SMTP id l11ls3818383lfh.1.gmail; Tue, 13 Jul
 2021 02:48:51 -0700 (PDT)
X-Received: by 2002:a19:c46:: with SMTP id 67mr2837410lfm.482.1626169731214;
        Tue, 13 Jul 2021 02:48:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626169731; cv=none;
        d=google.com; s=arc-20160816;
        b=cmerbFOPRzwYaajGhl3QS8Su6Dgi/2Q3zjMb5x9kv8D75pzp6BX0Q6vIGvTusQYWtU
         1nEcWAF3gUVWG5AVd6BvJKlfwTvUN4pxqNgkmPt5wg7GWAY+vCPtV38irxKcGO4QBvwt
         Ht1J7egZlKJYrRQCd4Dw/uANvffPxdRkQkj61JECD6YM41U4UTMaBc3E28ULYSC6+VXT
         /UNx8QrvN6H3zVdNfmY37v7N3KKbQJzpaXEfMFpKlGT1by0lYSONZ++EZ8Lp85w/pP3e
         eyXgDD0+N04MIuWOqXcmbV1hRRXxtST93vFgDOEkaEMqn/I5sQri6P9iSE9tWwCApuMB
         xHjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DsRs0GWZtjxgV/G+0LfR+smdacS384gtQB/dib23CM0=;
        b=Bi7VvjleNS5qeuMQMCVsPlIZkWwvIgRCanb6Ug5Q2j6SflMdRUZYMecxJF87IvW+dB
         +Iu+Rc90tLPTEo1obhAl5qtPQsbzShBnmUhCrFOIMqdsZGETwy754uVMjFzEtXyGm+Bl
         iCtDX6dZi1hf62LEI7YzMG5YjcVwB4rQZXsUonHJgiVQ/gNyUNafwjzsA8bPdW03X3o1
         ro8nkvyGIBEogK3nUZwcaN1VTs01K42dg7s6sca7InAhc+arD3VSC45B0UbjxOD4nMEw
         yVObf1GHQ6OvTBw7EmvzKZvC5bDTjcsXZZefYTfq0EHtRV6heVS5afTLOs8k8cGtnWaR
         QSoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=B7IJS4Ly;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i12si727435lfc.10.2021.07.13.02.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jul 2021 02:48:49 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1m3F1e-000xYr-VD; Tue, 13 Jul 2021 09:48:32 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8B9839866F6; Tue, 13 Jul 2021 11:48:25 +0200 (CEST)
Date: Tue, 13 Jul 2021 11:48:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: tglx@linutronix.de, mingo@kernel.org, dvyukov@google.com,
	glider@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mingo@redhat.com, acme@kernel.org,
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com,
	jolsa@redhat.com, namhyung@kernel.org,
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com,
	omosnace@redhat.com, serge@hallyn.com,
	linux-security-module@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/2] perf: Fix required permissions if sigtrap is
 requested
Message-ID: <20210713094825.GC4132@worktop.programming.kicks-ass.net>
References: <20210705084453.2151729-1-elver@google.com>
 <CANpmjNP7Z0mxaF+eYCtP1aabPcoh-0aDSOiW6FQsPkR8SbVwnA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP7Z0mxaF+eYCtP1aabPcoh-0aDSOiW6FQsPkR8SbVwnA@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=B7IJS4Ly;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jul 12, 2021 at 12:32:33PM +0200, Marco Elver wrote:
> It'd be good to get this sorted -- please take another look.

Thanks!

I'll queue them into perf/urgent.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210713094825.GC4132%40worktop.programming.kicks-ass.net.

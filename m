Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXW3P4AKGQES2MTNTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1A8C228216
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:27:02 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id d3sf9699085edq.14
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:27:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595341622; cv=pass;
        d=google.com; s=arc-20160816;
        b=UIFSBs1bHUII/xzbywqy5xyNAZ9bLHRbO5E12owG9P9QoREXVm6iVPz0vASOS+3Fbp
         pY6cDRbvPKhw1gsehg9M0GyOwbGimc9hBm3NWCGZOAu/g3o8BLFU1I0AA29OGvjbHNSM
         f7Ey7DwRjm1+nbH1Ax6fB9tpvQ0slehZ9Z2xoVZzNMcHb+sJCZ8na0/4jWjRSccv2hfu
         m9ouVIoV7esvn1a18dlttiWS4TYCFMeiQivNUmSHDQTglaLmc5LrnnRbOgXweCvSH1/H
         Q0+pyce/vBsPIph87pKlwJyZ0x7mqpfZasgKXnbY5UkVjEpq5+Tzg2Zc18aaYcq6szVZ
         o4Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uam5awoVfmHppl8pXBQ2PxHQArOx73aJNLu3TVjbHQA=;
        b=lB71M4OHdVY2LajbE07fLny+yskexqrqaFM4vHgdX9kPPZ7UUfcyGHKGPO4ERfDSyF
         MBtf/oiW/eS6n3NnLG6YMJkyp9/oqak5+txL8lgPSVCGS9tIW4fBUW+xCpR7bKNbkG2Z
         fVsAqTJXMXB7r8BHC1byBHmk23UsN5hRtuOnOM9nXScgKVCA3djpJkO1spCM7qlDnmOP
         chNrrG5D6436EFL8GWgBA9BlIob4fL1z0FFqnEzxJa4Q867Iso+9NII3hSUmGu0Ows4Y
         DQuuLoMKCNmvqwFpKeE0onU2A7FB8lC3R891GX4FyYOWNPkHhIpRoV944Eh/kJkAtC1i
         Dl4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tn+r0hMi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uam5awoVfmHppl8pXBQ2PxHQArOx73aJNLu3TVjbHQA=;
        b=kzszziRt41XnTZpgmOJ4aTi6+gu/TY7DyEpoZnC/NHFdD0vIAXed1oL85UioeFHQSj
         zQpuuoH6EQeev7ZQp7pqPRpRG8XozbkFlDVkZyGAXcy0dopHdgBhGjOy9ne09zQQm4L8
         l47gnJc1Z7RZUWmEMakz4KfaW0xbJ/PMqx/Q/n/ZqAN3B54xfO9F4jq/iXODOuuqdL39
         yTQadHDkOPi4dQd5vmt+ZGqTaw9QnCGMb18XCLTzg8Fn5zZE6rhsYsIxFZjz8HmwGhk3
         vbdmyv9G8FRtRJEsMMJYCGsQnaig1YSkqUpdz0xy32Rr83PhLnX65I/jiIK48JKkjud9
         eYDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uam5awoVfmHppl8pXBQ2PxHQArOx73aJNLu3TVjbHQA=;
        b=K0z20eN589+x74GOSYjbMPq6emQ44NBBUutyp6n5DVpvU1NzRosydYSVJsp/joAjKw
         LRtyJiboTT6ShzXF62gVqupxH61FsBzyIZwNfr0ixu+goTssJngtU/fUSF7aiKo4IqlA
         WTKIXxXtGhPmEOOCofl/XM9FURSYM6XsuJEcoVRBq8IryA56/CMpleQJ13P4iJI2xIgr
         yLPNVQjtUPvjluDnZrOY8tJJb23APkjNFqQmIZ35UImxETVPij9hgXyFtPBi0TwWxzB/
         GBE1N2fuIMVqmMRx42Mv1DmHC/N5+XCHmf5Gl1QEqCh2v8na6qCnOg5AD7BqjM1vVxeO
         J1LQ==
X-Gm-Message-State: AOAM5329757pgi2N97CvLoxNlxto0iXzcMfU8Wj/vkzaveTmROMkoK0S
	yzN7RKBqbAx2ptDEdyepItI=
X-Google-Smtp-Source: ABdhPJwGjBKdp2KrwdNAY1Bs9fD/8Zp8cbca1kzL+3DznHvJAbjk6mJttrzNZPykeVN8cvdE3nRp7w==
X-Received: by 2002:a17:906:2988:: with SMTP id x8mr1315716eje.141.1595341622752;
        Tue, 21 Jul 2020 07:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d37:: with SMTP id dh23ls3875591edb.1.gmail; Tue,
 21 Jul 2020 07:27:02 -0700 (PDT)
X-Received: by 2002:a50:ab52:: with SMTP id t18mr26658541edc.195.1595341622172;
        Tue, 21 Jul 2020 07:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595341622; cv=none;
        d=google.com; s=arc-20160816;
        b=iwK+rh208x64tq/BEWQx3oQErAIedySG3XjvLj/gFaHKKc5Vn8O1U/WMMWXcwqNLE9
         k9EfM5h/o6Knw1fS4wtv2sWwtEWj4gCEzUjeSN961ZOlkA3fsIKU+akY8elTGUw0J5TJ
         4zVOl4rfCDzemEE7I0SbnznAST9Wpd9FG8b9ROk5UxavLgDXbH3SAVitdLr6hLu0hiPL
         tLy5WCNexkbfT50hkn9QhEMwBI/3ZNSISI7AvLryH+KHPd922SL8pIiKFccD3VANSGNq
         UGZqoAP6bOmRP8QLRGMS5cl2G5W7jcg45mXT6I1vKvPaFcWfRPUuYdL5WucbVKXvZtWb
         Ijag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kvJLCEgw2Y91sCTQ6JSG1TMyYmzQtuSE0ssBK5vqs5A=;
        b=FEWUDDaMjfTCoDaDAq0WYSCb0rWPtaCnm8xNay+adtMMFlwq5Jy8FJZLEI8bYixJn0
         CNK7PpyRhI2H5UdZ/lVQrWNgWD4zkglhbEiLwa3m2IU05HtDTydsLoqxaijL0FztkHOt
         mMYgbM8FMNIsAWbRRaBxdNZMDXfvf7kRK0TwEHBxua8X57FhJ42+W2Tay7eqevwNs128
         7EZW32olhns3KPA06+dGJV+RFRM9ckwO3jtiSyGFAvy196dEeaz06GJk5TwOxg0pWPsm
         kPxn6v1kinNO5YAgFNAX0kR4GkZnc40m38FnJXkGUkpW8dr9jov+TZtqOG7eutB8jxHQ
         DRqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tn+r0hMi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id i18si1060499edr.1.2020.07.21.07.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 07:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id s10so21353236wrw.12
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 07:27:02 -0700 (PDT)
X-Received: by 2002:adf:dfd1:: with SMTP id q17mr25505561wrn.94.1595341620825;
        Tue, 21 Jul 2020 07:27:00 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id b18sm36258317wrs.46.2020.07.21.07.26.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:27:00 -0700 (PDT)
Date: Tue, 21 Jul 2020 16:26:54 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/8] kcsan: Skew delay to be longer for certain access
 types
Message-ID: <20200721142654.GA3396394@elver.google.com>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-4-elver@google.com>
 <20200721140523.GA10769@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721140523.GA10769@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tn+r0hMi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Tue, Jul 21, 2020 at 04:05PM +0200, Peter Zijlstra wrote:
> On Tue, Jul 21, 2020 at 12:30:11PM +0200, Marco Elver wrote:
> > For compound instrumentation and assert accesses, skew the watchpoint
> > delay to be longer. We still shouldn't exceed the maximum delays, but it
> > is safe to skew the delay for these accesses.
> 
> Complete lack of actual justification.. *why* are you doing this, and
> *why* is it safe etc..

CONFIG_KCSAN_UDELAY_{TASK,INTERRUPT} define the upper bound. When
randomized, the delays aggregate around a mean of KCSAN_UDELAY/2. We're
not breaking the promise of not exceeding the max by skewing the delay
if randomized. That's all this was meant to say.

I'll rewrite the commit message:

	For compound instrumentation and assert accesses, skew the
	watchpoint delay to be longer if randomized. This is useful to
	improve race detection for such accesses.

	For compound accesses we should increase the delay as we've
	aggregated both read and write instrumentation. By giving up 1
	call into the runtime, we're less likely to set up a watchpoint
	and thus less likely to detect a race. We can balance this by
	increasing the watchpoint delay.

	For assert accesses, we know these are of increased interest,
	and we wish to increase our chances of detecting races for such
	checks.

	Note that, CONFIG_KCSAN_UDELAY_{TASK,INTERRUPT} define the upper
	bound delays. Skewing the delay does not break this promise as
	long as the defined upper bounds are still adhered to.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721142654.GA3396394%40elver.google.com.

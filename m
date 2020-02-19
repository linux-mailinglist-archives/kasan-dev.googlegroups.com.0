Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJGPWXZAKGQEKYRHUZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id A7D9A164AFD
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 17:51:49 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id z73sf658685qkb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 08:51:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582131108; cv=pass;
        d=google.com; s=arc-20160816;
        b=iNDvf5Qp3mLkYpgVi6rTuhsNedjJX5loY24/n5ZNNZJu61tH/P/W+07MkVtE9ZdExM
         I+JbDIu0NL3N65f+1WhXL4xC/dKrfAkA/XXmfPlTcYjf3+9k/0Sq1GU7E7MQvWwuUfHS
         3roJDdweDPEL00s1YVWubz5kN5u+iOmLhPnDT0Pv8/oEoo16/mnf38gmBxK3bV7fyx44
         w+tDWaleHBXNbWacF5yOe2kvq49hB3Ljbkrmee9D1AVIaWnSvNtO32bIcrnEzngEMBOL
         vUMVNMyX/t8Z5pSZ5iwvt1n/JUVnJC/hE++yIrM/GhBAVTaHtTaRGGXRhli3K7YlMJxE
         8dAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=geBmGyUsFvhS0P/Ba3fDf6I2p88MjmtUxH6MhzI7Ong=;
        b=vlghZWIESbvwUTjboN4akYyZIZ5hiHu/ZPM70e7a9+WwxiG+1TirV71Ir12j5CF8c6
         AR5fbK7Zgz9KhOXzyNfK+z8k5OZzjvWTObiLRq5vfp2Y1c4vSgGr8sF5vUg51BoCpGDz
         GoeyYEInWrGw1jd5nkcm6EUyOf+Sw+OfmS1AyKJQtLyrGgEDTUDmvGJSLwdexJ1sblH3
         nYsMxcj19kCbbN1r5V8sziHW9sZehyc4kPD9SblgcrSsxUJmxTti4ieH2J1gJGAusRta
         HBideN3SMUI33JPLcvs9RmGMn1N1zfqjqSd5Tq/Kqw4Sstumx0x+3p87LfgdBms9rBLP
         tThw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=aPCcJ9zr;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=geBmGyUsFvhS0P/Ba3fDf6I2p88MjmtUxH6MhzI7Ong=;
        b=sTweBSUo+THR6C/o9FMjhXBr80ElZr78OQaKn6UKrO2avSfE66L8v+rOvT3IywyWly
         Lm6QctSJeXrLRhY1EG4rLUugLWWaVSNIxi2L8E2nVsF9oHJ0lo2AjrQf3bCcVPtT3nXo
         QNVubeMM8QlgEef/H4b+m9qcR2Xq0miPxvrC+UBee5AiP+hA5eG36HLOftFHVRtGBOwW
         hjJQcobytJjZVFD7oMK1wjVcQvn4bK25W+tNfTk4kMKVJSE83a1IdX3cxsImRYn5Oei7
         o1rwHfI41F38dUOq+cRV8Szo0iVWE+Rf/F2IEtDMfS+6QyrXB5vRFAd6NE0NRJR4RDCL
         KKLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=geBmGyUsFvhS0P/Ba3fDf6I2p88MjmtUxH6MhzI7Ong=;
        b=hFwudxp1Bt2QF23kk+kyCcLqn1Ozgy5/BLyY3oe/ixCh7GDevJOCuUX8wiVtnIIP0y
         tlwGuThg49Yg/q/XLDHyMbrzv8wsZXI2jNeMQsdDOEVj+vgt1tmnHI8d86DsrsP8O5oa
         a7KodH2RxP4CVaKZ7JB44SvNwZPqOj0NfqW8cW6GQUzXld/wTa5THiHg8VBbX4P6mur+
         XAW6AbAkvJfaYskRHTsbcFXDd6WfzY/9TsEauN0IZYzJmZVbDnjjODPFsG7hYOuDJ5Pq
         wPlXM/jdq1IAth92/9i+UPN3GrRZx4LTlfwogTDbWGMFPGui6x+XB1akAt/CIek4+s77
         TH7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUSjf1DKCAeKOYFcf0SS6N/O05DMtjBkzM3tGj1kqIPDn+J9QfL
	rD3X+ar6x1fqticzz2eLKNU=
X-Google-Smtp-Source: APXvYqxiluwWl5DUwL6A6X8bJuSXRnU5FtIj+j/P2i7dtKtGQlpS3wpoKL5X9pH2CV+hU63ogzu5CA==
X-Received: by 2002:a37:6717:: with SMTP id b23mr24945332qkc.353.1582131108575;
        Wed, 19 Feb 2020 08:51:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:63c7:: with SMTP id x190ls34034qkb.1.gmail; Wed, 19 Feb
 2020 08:51:48 -0800 (PST)
X-Received: by 2002:a37:a404:: with SMTP id n4mr24528136qke.247.1582131108145;
        Wed, 19 Feb 2020 08:51:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582131108; cv=none;
        d=google.com; s=arc-20160816;
        b=Y6a7fQS0Xc4iZ0NnMf8GY4+bgXgdkGqY4+N31/JkM4+XnpkMyjZBfGO/OR2iG27xjf
         YrfWSiCLLHH9aK3uz7paqjGIHQgHV/sMxBlMvyxEHQFDYf6K4r+nYz9fq5vXzDwZA9lA
         NPDrq6/pWZg9E+ItlJUB9GRAcVN2H19FT1GrmbLAtB+3HWlM31UslSQzaDDKsnzCVPhq
         rTYFntiBzUByDbtbQnnD3pzIDFAXHwxjcJfmQjkKZ5pPSQgmD4ucvSU/o29YM/rarUF/
         GYwKstSJUX2+It1x5H3Ri3072RiFgX6cpM6AvyXMz0XYrkm4HFHIUJFmd463wGkZEUZy
         idjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aOY3HVNQlxhNJtO2V3TApKHEpYE+w+Db2fWfBxPBg70=;
        b=WUsZxUhiQnZtycPhL+/j4pTjVzWOlQnL4SzjjEs5fSR5Fx84Jvgb60BEBW115ap8w8
         pFH35ftk9sQueWMsix3cjw3/K1hhOQ9whm1rpOjiVPOYdRIgnyJQ+H6UpOYuMUzGJq4w
         N7c1byGdqonb4P3raEesA/0ewa2PpjfXQHmdhDR5ZHMehiqGkhsSitf6CBiN2gWL/ky7
         PW5W2e3qtLiKctgNbhRLqf7jmJk1JoKE7PtumGReX5FjzkF3r9IDKGsvTInT9d9uJN0p
         ZnBqZN8TrMheQd5wDO0Br4A0e64BK47tVuM5gPKJuko6dGAGWmXblZAWjoRcNF1XAbgN
         TxIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=aPCcJ9zr;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id m18si44311qkm.0.2020.02.19.08.51.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Feb 2020 08:51:48 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j4SZN-0001JM-FA; Wed, 19 Feb 2020 16:51:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 75EB4300606;
	Wed, 19 Feb 2020 17:49:35 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DB88D201E478A; Wed, 19 Feb 2020 17:51:27 +0100 (CET)
Date: Wed, 19 Feb 2020 17:51:27 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ingo Molnar <mingo@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com,
	Frederic Weisbecker <frederic@kernel.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is
 not sanitized
Message-ID: <20200219165127.GF14946@hirez.programming.kicks-ass.net>
References: <20200219144724.800607165@infradead.org>
 <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
 <20200219163025.GH18400@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200219163025.GH18400@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=aPCcJ9zr;
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

On Wed, Feb 19, 2020 at 05:30:25PM +0100, Peter Zijlstra wrote:
> > It's quite fragile. Tomorrow poke_int3_handler handler calls more of
> > fewer functions, and both ways it's not detected by anything.
> 
> Yes; not having tools for this is pretty annoying. In 0/n I asked Dan if
> smatch could do at least the normal tracing stuff, the compiler
> instrumentation bits are going to be far more difficult because smatch
> doesn't work at that level :/
> 
> (I actually have

... and I stopped typing ...

I think I mean to say something like: ... more changes to
poke_int3_handler() pending, but they're all quite simple).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200219165127.GF14946%40hirez.programming.kicks-ass.net.

Return-Path: <kasan-dev+bncBCV5TUXXRUIBBQVK5CBAMGQEXXN3CYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CA73464D3
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 17:20:19 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id v9sf1667884ljc.9
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 09:20:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616516419; cv=pass;
        d=google.com; s=arc-20160816;
        b=HV8hXagzw8vfHJqZ4ftWbxKvghJNJxyUOyQ0UOyVQT1Wxo5YFHxsfKwFrC28knZo1L
         VADRmbDnvQiflgoTN2y0tk35WEKdEvQHr6IPF+OMBr0diE+4HF/ss52C87CtXszO9OaC
         7Zutxio3Lmn5qVrB6xloQl3DHnUBFuXeOi2DPl26iTVn7ZW7Rp2/BSAWSfKBdsxXGmaX
         3M/nlkL/vPv9aEgbxaMRMt7+IGtVgY+NlECN/25TEYTRq5byBqw616EHW8SId7XxZg1K
         61/9N9SmXusKDtldLA8+/J8R0JFoTuwvbi0px7mgPw7LLC1QoxMqYPFuD1oXJDQEhEpk
         dSdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4k5OG9piIF8OP3xeVf89E6CxIouYiusnikBVueyIZt8=;
        b=YSi48kEPvE6+yraOrJ8O7e26kNzX0+9KxT0EAx7GuEyPSEcGq+0Fr+uU42v2+LnZP/
         q/5hSRT7V0m2XC5quSL/A2jhnJ7bX+j5jzd0jij6ouB9xlBrj5Mep7MJNfvDvzdkXitX
         tn80B/jLYJb7DZhfhUltflvGdw26aaRsRMViJ4ponEMlDaR1fiUvEH42tQfOaHat35Ck
         C0F4c5cSkFfxqLt3LPpYHNwb7O766wq6xTE3u1lo3id902J4qc3XnjwJ6YTH7qUoybXb
         5BFS4dwSgwpwI5VxLcgJMAqd/j6MlEkqnS1VQhaxrMqq/KI0R2tS6mpWduqJw5wIsZcI
         anMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="qZhDkGk/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4k5OG9piIF8OP3xeVf89E6CxIouYiusnikBVueyIZt8=;
        b=E5uavJGybT6OawoNUH1X2PcfTpelhCW1NzGWQzN+O37HMBIG12ahLQ9Y+Fe6dEUduf
         Nx+JtIafsMZAl1tfvN3rpR50mWlJUXWQRnO8lxNML+Wb8FDmSMiXH0bIicLXUm2/nuHI
         PCIjMRDtweOinbgx4nV/29ZBmIkOJtZRTX9GxAsRrpSLyEFD6LM+xek3ohvpOMDdaCOz
         Njdz8qHovULtNM7TCDeGEEbFHj3wU0w+mq4F9ZjSR0VdenuqsmdKf1WcyVLIdchMPh1L
         jiW/kj8ai8XbiHvhrEv9K7snU/k+Vs/M4Xkiof49yALYvQ2sPzEiE1lcC6Um1gF7snYF
         L5mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4k5OG9piIF8OP3xeVf89E6CxIouYiusnikBVueyIZt8=;
        b=FRKuzwoRSQGVyj0uCElQv00o3bNfK4jftZ02ccMNH57aFNCdcTc3MjSzD2smGn59gj
         rlV6+mj78mZUIjLi2gFWI4k/Q2tT/JyiAsLzf1SHPE6zXRydj/xC9ILi5hsFnGnmZZ+N
         Qhrojvv00I18ajIDNQ2/c2diXGdkCUy63IreMRx0H4gJlQjlu8Zun4PK8HJyj2hn7s8P
         x0XZzLnAhfAOW1fEltyLlSkMeFmjG06r5phyF1/tpVKxF9ThUChTCf6XHraEDbtd0cK5
         SsCfUBqMqkRv8biIMEwkcgIe8Nzd57fcfSxMXxtUbLEWHRMWx05qRfNxUiXEM61TtN8Y
         WUQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53098q2YtvCteh/sKMXLp4oviBo2NkL1+XfvumGHZpuheqiYe2H3
	Pz570jJWnONiQS+P5bhgDFw=
X-Google-Smtp-Source: ABdhPJxgK3q1B50EKztu/ec+q/eEXPd/XWnWAveUB2ZC0pZp7kfBpcw/8+PSAE8HQmnXTDda3IRyLQ==
X-Received: by 2002:a2e:b5b9:: with SMTP id f25mr3652130ljn.90.1616516419215;
        Tue, 23 Mar 2021 09:20:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f8:: with SMTP id v24ls5579780lfo.2.gmail; Tue, 23 Mar
 2021 09:20:18 -0700 (PDT)
X-Received: by 2002:ac2:52b6:: with SMTP id r22mr3056801lfm.498.1616516418126;
        Tue, 23 Mar 2021 09:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616516418; cv=none;
        d=google.com; s=arc-20160816;
        b=eeRZQQq0MK7t9aI/CflZ1/H1lIb4CfyJkQssjSZWYKBRbdv6a577CU1a0fpKkzSQ1q
         hL3ZlQJzrHX1PWd4x/UZmrZSQiaCTtEiAD//amkwm+n/JcKLTknlequjziWHVK9EqA3Z
         SsTQGIJ0ETTzfC+6Y40Sf8l0swAmeCxSbvvJLD4qHzvyxRO+rPSBlWeyEAIrGpSN7ABG
         c738jQK2P+9ZX85jR+84Z+9d/yjeDNO/z4nrLPz9M4sIoGVmpbp3bRGy3/sb7609jQ5M
         QBauPZZjmTbUVqoF0DZBZ9vgz/SM6V/J1eblbbRGbstB7eXizkgTGwFi34aPVf9aNyDL
         2VUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LsoqY/Vbr0roq3HT0l6ahhm+8UPgKl2dxZXa/dA+n00=;
        b=b6GRSVbarfik5PyO+IaDEidvOk6Bete87vC1Q8tbKsga9ZzVsiniUpofp6/CnIksE7
         k/lP/gOmdtVDzq/KmINYZ72vDUb75KcHc3q85DXuSrnCX5HRPI5c8R3F2UcQMCgShyAC
         cSX8PpzZwrHYDlToVPXy2ZD8EaIvnWWAgJEZk3Zv0LFd50uv+sSscN7m2mN1I8vMUyoK
         R3UBkku7qwJ3S+BbZLkNGkKtM89FomSBd+gKRsDrc3pIpLYVAuSO2JP54Qwdabde1++R
         d/l7+GVydUrpuTqNftQj8m1rnXgq/NoBQBcBy7DHXTu7tYMqQVyWTF8JG25CewLo0I+S
         bzLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="qZhDkGk/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id f21si696233ljg.6.2021.03.23.09.20.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 09:20:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lOjkj-00AGgi-S7; Tue, 23 Mar 2021 16:19:44 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C53EF301A7A;
	Tue, 23 Mar 2021 17:19:32 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9FF7625E587B4; Tue, 23 Mar 2021 17:19:32 +0100 (CET)
Date: Tue, 23 Mar 2021 17:19:32 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for
 remove_on_exec
Message-ID: <YFoVFM+xltCUGR/Q@hirez.programming.kicks-ass.net>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com>
 <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
 <YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net>
 <YFoQLfsZXPn9zuT4@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFoQLfsZXPn9zuT4@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="qZhDkGk/";
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

On Tue, Mar 23, 2021 at 04:58:37PM +0100, Marco Elver wrote:
> On Tue, Mar 23, 2021 at 03:45PM +0100, Peter Zijlstra wrote:
> > On Tue, Mar 23, 2021 at 11:32:03AM +0100, Peter Zijlstra wrote:
> > > And at that point there's very little value in still using
> > > perf_event_exit_event()... let me see if there's something to be done
> > > about that.
> > 
> > I ended up with something like the below. Which then simplifies
> > remove_on_exec() to:
> > 
> [...]
> > 
> > Very lightly tested with that {1..1000} thing.
> > 
> > ---
> > 
> > Subject: perf: Rework perf_event_exit_event()
> > From: Peter Zijlstra <peterz@infradead.org>
> > Date: Tue Mar 23 15:16:06 CET 2021
> > 
> > Make perf_event_exit_event() more robust, such that we can use it from
> > other contexts. Specifically the up and coming remove_on_exec.
> > 
> > For this to work we need to address a few issues. Remove_on_exec will
> > not destroy the entire context, so we cannot rely on TASK_TOMBSTONE to
> > disable event_function_call() and we thus have to use
> > perf_remove_from_context().
> > 
> > When using perf_remove_from_context(), there's two races to consider.
> > The first is against close(), where we can have concurrent tear-down
> > of the event. The second is against child_list iteration, which should
> > not find a half baked event.
> > 
> > To address this, teach perf_remove_from_context() to special case
> > !ctx->is_active and about DETACH_CHILD.
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> 
> Very nice, thanks! It seems to all hold up to testing as well.
> 
> Unless you already have this on some branch somewhere, I'll prepend it
> to the series for now. I'll test some more and try to get v3 out
> tomorrow.

I have not queued it, so please keep it in your series so it stays
together (and tested).

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFoVFM%2BxltCUGR/Q%40hirez.programming.kicks-ass.net.

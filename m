Return-Path: <kasan-dev+bncBCV5TUXXRUIBBTMFUSGQMGQEDF3TZ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 373CD46691B
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:30:54 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id a85-20020a1c7f58000000b0033ddc0eacc8sf2036973wmd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:30:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638466254; cv=pass;
        d=google.com; s=arc-20160816;
        b=tusWTCkEXzRzi2ZCNxE/CPyr5heJiEr2YTDE7L8lUcPMvA1s9QIkw/jQ6223+t0spP
         jC2RviMVkakGFzxD7bcZ11J/g0c/yqRQyKq9Ogxvj5eWP50tAisAcTFpNQWzepoUTvM3
         OOOSAaD8GESZvdgAMQzNOnrkyxB1k7Shd5QUCEK4IT6AND+EfuLO1Esby/IKtM/ftVGd
         L+bxSqKPZzgrnvpClLwS/Ox1VBK1JpD7T7EO4km4pdI5+poA0hVWOVgHqJN+9QjQbc+2
         lLTuau8zp2IHnQNv1bumalnNjYglokggHT/zWqZUqEb36l6swumneAFQx2sdjihttlaO
         CyfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5786EDyGk3SfHNlCuqF5FhNhzeE4fLeEe+IBNPoZzkI=;
        b=br49H4mZ9gcTBA4B9V3xv6r5Sul3AT7Ib0HnXqk2cpjZTDfcqaXp+8aP+J8CW0zdrd
         J3if2LWPvV6H+WYgUABMJGmt6ypxSQ/2Cg0+BMjPORvpepRxWX/HuKAYFTiaB5CUBfhY
         1upL5WnDcTme7DYucpWhcqJ5MgzcWPF4I6CIc+Eqr463Cc4n6Ap0jjDLu6BTqBVJ9kqg
         vyhjviiTexjsxWtIvm9PGrr16L2XkOEBvDJSR92TdUz6NB6XVo29XtzFdpstts3cayno
         7uC2bLWqXeTM+mud0XhfyeNP7HTnovVePsZgBtaoa5npedR0K6ISOnt8nsqNx+o5/gDV
         6HIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZyNtuhbD;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5786EDyGk3SfHNlCuqF5FhNhzeE4fLeEe+IBNPoZzkI=;
        b=ndEK2GspAh/aUtq+cjM5chgl2gcilTuHOXiJ6GslL0I33hBmWRzW195yjQUtYZFPs0
         vuGmTd+xX0908SA6y/c4GD80LXKKPbWpMVizGALM3uVXBv5aiFHDxdoIXi0D4DOXPsjv
         dZomFfEQOaiaWcoU54lnkxede/H2Gb/qJZFgQ36P1goos0qHNkmuqPv2EPHBkCIXuSa+
         zPNB9Plrwows2mGOIIdp41RcAaMXds6/0B3PFyJYILvh3lAtrVo36SITwZEJSUdgMJBR
         Aoj6MSTHBCl1nLiio/4cttimmSjMhhKOgXr2L+psJa+JOXqNGKKgJY31DD0L/Ou6T65l
         j1CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5786EDyGk3SfHNlCuqF5FhNhzeE4fLeEe+IBNPoZzkI=;
        b=Gtr7FmsILqExueC09+0ivUx3uzucbTyTPAkSofePBe8AQfULx1W3G1047unKLyKHKa
         gAtZkfT5ALIwokqtKI6S7sIchlq7mw/bW2UtEY9+hSYPd0Ab65KhP1xSbACqYSuey0r+
         jCIl1TG40KRI8eS0RikaFQDklnF6HpSJgtmh8nZfFRjB6E/NtZ5ykyoJzfDuhQ8Z8R5p
         oVo44xf8TWjOfkDaq10wjsGDMjnHmIk4/jyNCxyL0AKdLexdJYBv7m4FuE3UpmxCkzVc
         LF8+JuDRClihk3m37ae0EFXY1aLo/dKOuMCwogXXi0fOhsVw6Zva59QqA+WLbJIQYdRo
         +oqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eR9D+l87nB4I5031RrXdB3GAECzxAfTl7mZDuyv+t97pwsQlF
	ICDG0EELCh9QIO/on8ZAkR4=
X-Google-Smtp-Source: ABdhPJwBrs83pHv31iLVtCy/O+Cm7m0qNB6sMy9OG8zbje2IBRw43RpCjRrxmrKrJC6JS07Sd1eMSw==
X-Received: by 2002:a5d:47c9:: with SMTP id o9mr16127661wrc.348.1638466253908;
        Thu, 02 Dec 2021 09:30:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1142126wrr.0.gmail; Thu, 02 Dec
 2021 09:30:53 -0800 (PST)
X-Received: by 2002:a5d:4f12:: with SMTP id c18mr15382801wru.547.1638466253049;
        Thu, 02 Dec 2021 09:30:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638466253; cv=none;
        d=google.com; s=arc-20160816;
        b=DCCSI26bMFk63OBHvwExnAdssVwLvUAqsbRCpcF2nhwd7DUCmsqn+reZkKCLcg8NIR
         gZPDErX0WMEJ4jpIHY7LgVx19O7uHiKmRnqF8P2lmx32/rnTL/l6qblPda4CytN4Dyga
         ztbmJ/GiItWbsmqNiYFaqC+cki//RIQ3/nGMWAX8E6H0594bjLQajEAsWRAcc7qlbfsU
         URmqX3BXaoNbhENx/UfMihS4w8ORniUZwexbieL1WAldYGqmFUTPsJBfF9LKtw7WwshZ
         7ke2wLzwLIEB499EHA3tYiPVE4dFlGERBJQ4ytkhDnMv/yJJ24avHRPfutpPpETcqzTj
         /zKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ep84lIAEm6xTBlFgZLnob8SiKfPdfbP+dMspC48ZnQM=;
        b=Tv/CgYotvZD9WdOeg0nIA6WtcqjVPt0s94m63rDJsPjgc2AAWc+un1zy6WLFqf5Ya5
         YUUiQUyqsuP2aThSadBOB7LTAbklKOKw3mJ1MN4UG9xd/jDN9rwLd+ZOAPc56ir3hfIg
         IeI4h2nvILg/wY7h2ZqrKbtFDsNzXLdnNCWBPYdaWYV5VTgoHLTNXEtbOfIG9ZWbnCZU
         6B5yqqu9x7fQJ49M8U7wWxAabWHchc3F+xce3yi18nGkd9DFGXSuwEA28rqQP+d5uhdJ
         512UUG/4DXr277ObGvkVh3SmmzfVfBQUtd3l/3FsMB165Kf8ciViUWT4GLu3hCdwn7kO
         q2og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZyNtuhbD;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id o19si79113wme.2.2021.12.02.09.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 09:30:53 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mspuv-001qkS-Th; Thu, 02 Dec 2021 17:30:46 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6D1E430047A;
	Thu,  2 Dec 2021 18:30:45 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4A9D4201A8A52; Thu,  2 Dec 2021 15:46:22 +0100 (CET)
Date: Thu, 2 Dec 2021 15:46:22 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH] locking/mutex: Mark racy reads of owner->on_cpu
Message-ID: <YajcPt04S3M0Z7oR@hirez.programming.kicks-ass.net>
References: <20211202101238.33546-1-elver@google.com>
 <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ZyNtuhbD;
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

On Thu, Dec 02, 2021 at 12:53:14PM +0100, Marco Elver wrote:
> On Thu, 2 Dec 2021 at 11:13, Marco Elver <elver@google.com> wrote:
> > One of the more frequent data races reported by KCSAN is the racy read
> > in mutex_spin_on_owner(), which is usually reported as "race of unknown
> > origin" without showing the writer. This is due to the racing write
> > occurring in kernel/sched. Locally enabling KCSAN in kernel/sched shows:
> >
> >  | write (marked) to 0xffff97f205079934 of 4 bytes by task 316 on cpu 6:
> >  |  finish_task                kernel/sched/core.c:4632 [inline]
> >  |  finish_task_switch         kernel/sched/core.c:4848
> >  |  context_switch             kernel/sched/core.c:4975 [inline]
> >  |  __schedule                 kernel/sched/core.c:6253
> >  |  schedule                   kernel/sched/core.c:6326
> >  |  schedule_preempt_disabled  kernel/sched/core.c:6385
> >  |  __mutex_lock_common        kernel/locking/mutex.c:680
> >  |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
> >  |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
> >  |  mutex_lock                 kernel/locking/mutex.c:283
> >  |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
> >  |  ...
> >  |
> >  | read to 0xffff97f205079934 of 4 bytes by task 322 on cpu 3:
> >  |  mutex_spin_on_owner        kernel/locking/mutex.c:370
> >  |  mutex_optimistic_spin      kernel/locking/mutex.c:480
> >  |  __mutex_lock_common        kernel/locking/mutex.c:610
> >  |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
> >  |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
> >  |  mutex_lock                 kernel/locking/mutex.c:283
> >  |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
> >  |  ...
> >  |
> >  | value changed: 0x00000001 -> 0x00000000
> >
> > This race is clearly intentional, and the potential for miscompilation
> > is slim due to surrounding barrier() and cpu_relax(), and the value
> > being used as a boolean.
> >
> > Nevertheless, marking this reader would more clearly denote intent and
> > make it obvious that concurrency is expected. Use READ_ONCE() to avoid
> > having to reason about compiler optimizations now and in future.
> >
> > Similarly, mark the read to owner->on_cpu in mutex_can_spin_on_owner(),
> > which immediately precedes the loop executing mutex_spin_on_owner().
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> [...]
> 
> Kefeng kindly pointed out that there is an alternative, which would
> refactor owner_on_cpu() from rwsem that would address both mutex and
> rwsem:
> https://lore.kernel.org/all/b641f1ea-6def-0fe4-d273-03c35c4aa7d6@huawei.com/

That seems to make sense, except it should probably go under CONFIG_SMP,
since ->on_cpu doesn't otherwise exist.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YajcPt04S3M0Z7oR%40hirez.programming.kicks-ass.net.

Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7HO5T7AKGQEANCGA6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5070D2DCFB6
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:48:29 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id l8sf34663357ybj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:48:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608202108; cv=pass;
        d=google.com; s=arc-20160816;
        b=rrUXXcuKcWnEvGbyaNnl+3vNY3WIjfzgrJwECKEAxQh4OJXbgQX+L6M9tVuvm8Raav
         kjg/Cx+c53GYJ73ZFOh9CUaRlgSEakbeN7/z3lipp9Y4sZo4Z431NMKVDmv3AoKI7hPx
         EuBf2oayujX4rU1c1Z+gCrT8otfkCAmFmAXalwF3QLM95NR7aUXfH3i1rteuS+pKvyN/
         7tVAQBAno3q5eRtX8YsFq1UcD2RTSUhJzIKor/GH8OvCngHV0LCVvvOS9Vkzo7SVcLWl
         AnhAFGVvT4Kb6SWK9mUzouk3hgs/3e1/NfE+rEpVLfZ3TyYMApoef7n8dkCkDXXTRair
         sFsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qpGiBAjDA5FyzNz+FgrF7031F9rNMh0caQmDKJj1Mio=;
        b=RXK7Kmm3ixyDOZO6SF31y/VamFoM2sP2HIwCqU4Hf3UovyVTC6dUbqX0Lx14RsgxK8
         1pxeuOCn9Jh/4Iwmf/vnNHwUH7f1zngGOKdWypp7NitWzzOeMRFZdSpEsMEtYLggVbXv
         r4YokQf2X6IRXZ+T+aQGd5ulN1nxlgDwZsG9uEfeRHDCnhdNWpXe1+n82x2KljRyR79i
         kHrHT63o5v9qJYSDyRjTVJGmlaMLV5cmRsmYhTyYUu7ZHWvMISyIPsAocdSIfinql6HO
         Yx4h1RfMasFDpDZVpaMp0r8Sci3FGz/aK4LE4eDtuPjpDhxEL8feUFEsYuY4aw9pmW35
         qdag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=l9KCtMAy;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qpGiBAjDA5FyzNz+FgrF7031F9rNMh0caQmDKJj1Mio=;
        b=dKsys9RNk4nwXBqLALkCjbOpfYnqKkf2lJfwpAP1jkXT8S117wujumcPY/0jLjQkbk
         dvfZf4fyv/Qh+Pu1K7h6fBHPUcihycEG+TGm8Djdn4LztALANWvEzJBcTAmZeIjCDFzu
         tgsW67C7wjqXPTsRLUgixYwzLHYhCsy6lJRN+bzPbiEczLcPpPKw7kmWErtTv1as2o0x
         LKsTstNMTWk33EXSC5q3pFjk186JvR/GZMKFtKgycP9aYz7hvkvOQBybMzExxLc+z1mA
         Bd/GxOwNa5aDmPQKkwdff2FMFXoL80FcGFNwlHt8lsByNofF4H9YBavc11ePvXSrF8Bw
         LSDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qpGiBAjDA5FyzNz+FgrF7031F9rNMh0caQmDKJj1Mio=;
        b=cGsdJYhzI8VzR9P5F4ltz6O4glCLesC/ExsZes2iu1vHmm7W5ypYqrYNk43EhBMUpg
         ABPVOPVKOgcu2y06ktMSDt2TVyTFqrtLoYhjSQSycmqjoJq1/gGE2qIBV5tZsKoz1sHH
         qo9sdFPO6FCWukBADXzJ7GPum61YZrMfPzmkJpXeL3dF/XGnA2yJP6VL68bYZdqRkgVC
         5Gs4+dZ6I2OVT1Ih5ju3+fYJ1xiCNwY0O2buLZRCG8JNpHTBUHT0o+5S/EuYavK3NnQY
         U4vFS7RSIiFMYg6W2aKJxsLRpprlGOzW4UTOv9PP77cZ1y0G5udcXfkG2ZitugOoRPV1
         v25Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sNhDhHt+O2aKrAcgFVA0qB9SjuqvLpkbLLhvdUliE35V7HTyX
	BH8gQtQEwUrkSpgUksAoHBI=
X-Google-Smtp-Source: ABdhPJwAURJjGDjKmRuONDF9AhKkT1gPpnL1+vW5AQE0VoyHcS2x9B4Cb70ZsXaWTQN7AkSMkzklpQ==
X-Received: by 2002:a25:ae14:: with SMTP id a20mr26047741ybj.410.1608202108385;
        Thu, 17 Dec 2020 02:48:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c802:: with SMTP id y2ls5867140ybf.7.gmail; Thu, 17 Dec
 2020 02:48:27 -0800 (PST)
X-Received: by 2002:a25:5:: with SMTP id 5mr56538999yba.478.1608202107876;
        Thu, 17 Dec 2020 02:48:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608202107; cv=none;
        d=google.com; s=arc-20160816;
        b=iBHLQ7fMKeRnlnCWOK0LgXsfxZzZhpT9B52zoynKK94RO+/d6r+UeJ26vJY7mFOeJ6
         KuTL3KKb7p/whzp6ku93mWmu3f83zW4wxfc2IZ9j99ai3zoJGKCk65Im5sE82/IyB8B1
         mLMF/iz/fhs3jh6yNlUrn/mk3eIP7ADUqj0FkCtyoGpbyNU414cnzbtfoM5qlqAN9Xq7
         cN87k5JbzE7uBaUmuQ343rPDnwl4RYxyKbcnr86MA85+BuBaFlRc7sOfo2HvMcUtURph
         TC62daqh3jTNMKcWAPJ21O2zhNFRa5mLoP/Ns/5/jype3gjGckVqbQtQxRD8l07svSrs
         SBlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gjyTgh1UagQyigQH76YaZvKk8RwMBB2TgkJohxIQuyM=;
        b=V3NGmPMz38wDfdoW45BYKoamVCzV8KZaP0Xszzcqcw0lA0iGy9ddLp877tqxGFoxgF
         iyzKx7JeZuErIRsUJpoDsR1OkDg6RSvX6j8vs6H4WWAMRz2maYu4+kENeMMZ/ClLbnrN
         iUrOitFp44hWLjx+y6oqHZymVYYWU++x41aChLn/r5xWUy9GsARCkdYkFx/ceP+oRTIA
         dBGchOXIzPgiY8VKltrve5uPUkAtCQBBcJQFBgylXF9T5zS87DiQmYRrsVpzT6Lm40M1
         KFVcPNL4XnkNrf5I0Kz5Uti5gIHE2HATiFLtBmOVBVWJpzNIPB09ayAXrUOKQIobIbrn
         Dx5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=l9KCtMAy;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id e10si634524ybp.4.2020.12.17.02.48.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Dec 2020 02:48:27 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kpqpc-0003jS-TP; Thu, 17 Dec 2020 10:48:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6250B300446;
	Thu, 17 Dec 2020 11:48:23 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 44297202395BD; Thu, 17 Dec 2020 11:48:23 +0100 (CET)
Date: Thu, 17 Dec 2020 11:48:23 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201217104823.GU3040@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
 <20201208150309.GP2657@paulmck-ThinkPad-P72>
 <873606tx1c.fsf@nanos.tec.linutronix.de>
 <20201216211931.GL2657@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201216211931.GL2657@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=l9KCtMAy;
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

On Wed, Dec 16, 2020 at 01:19:31PM -0800, Paul E. McKenney wrote:
> Given that there is no optimization potential, then the main reason to use
> data_race() instead of *_ONCE() is to prevent KCSAN from considering the
> accesses when looking for data races.  But that is mostly for debugging
> accesses, in cases when these accesses are not really part of the
> concurrent algorithm.
> 
> So if I understand the situation correctly, I would be using *ONCE().

Huh, what, why?

The code doesn't need READ_ONCE(), it merely wants to tell kasan that
the race it observes is fine and as to please shut up.

IOW data_race() is accurate and right.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201217104823.GU3040%40hirez.programming.kicks-ass.net.

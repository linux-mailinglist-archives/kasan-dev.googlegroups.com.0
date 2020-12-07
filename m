Return-Path: <kasan-dev+bncBCBMVA7CUUHRBT6JXD7AKGQE5PPXUJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id B79092D10D5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:49:20 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id o17sf8616691pgm.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:49:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607345359; cv=pass;
        d=google.com; s=arc-20160816;
        b=pCbEt6Lxm4HeQqD935lqPu7E80yqUveuWs2jRI+MiHggeCZTNUIXTlwt6jDsy6/0tA
         pA/eMpT8ME6G2wLVSoR/5Y4IjKJiHnLJSWwF7pqL//rgmCZXf/1TWzQFhg7jseP3h9t0
         G5Ou7oUa4arj+ib7fKo3A0Q6L8PI4UGRX4IkziJkZebBJOfo2KGhofsCkfUCk/feYAti
         P2ArPld/u9KZry1BLw9dWAmtFqG3mJ7aP9F20/+SlNl6vs4roR2DK4Ym29xdSGjFo5PY
         C4Ag5qK3XvQ7/E8blR/OwRa29mba2KbFqrLk6LVIO44xbaomJi5QMMl18SzmWMoiexHC
         UPQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+55g2Kon0cWZtCSWI9ooql4NvzNPt+4zNx4qYpSOMfc=;
        b=orvawF+klSTgmh2axaaby1y8jXSbrkiyxrC3JVQpR4lUh/DG6GO0XMjX87pFYcqMis
         hohgt2EFgYbhF7RWcHMwG6zmpsibW/YC7g/lagR5ZjEJ+Qqjod4FF3g9XdgFQMLZ/HX/
         /3UOUG55QGN9dnUu7cQUaEmBsp0vq7480RHcjEsbZOxjuNHagHGyZS9UI0O7asilZwCi
         KuWBu1rXj0flU7GM/Zr5f5qS8H7eCMYehDy5j9B+GwHQjeJbSlgjc6oNBaOKwWj6N2ox
         MFRib86YXkstfwLeyI+cC4JhzxGaBJE+6UA1bkdFmpxMX8NE8tEO4lVbNUI6F3WQYO4l
         Dt2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IE+TIQ2Q;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+55g2Kon0cWZtCSWI9ooql4NvzNPt+4zNx4qYpSOMfc=;
        b=cT1e2XXa8gmNv/rnjGKSsmWCSJK49VamYqbNWoF1It9FaHuB7WAnF7bWOv1WJ3L4sd
         5jWVZYeaPl71teJpKNhvI0CHZvQPEjihsktkk9fSPPuVosC6LYwAsO5BtyF6R+aB/83n
         PWSzYlSZfXApxA2UhTpOkriwYryu02osbiZ5ctRF1ILaDqfucD8wn4h0kiX70CqG8Z2o
         4s0VO10vWmTYyd5CLmHDLsbqGAq5MgCNnusXlaYUSRrARs7f7HrxfBsmEluyvu2d6xlx
         VSa76mZEIZRF83OhPHe/wpLsK1PB6kQtgcQdbQrIQopcnyhbWfgCCgrhYc7m2M5+Lv3t
         ECaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+55g2Kon0cWZtCSWI9ooql4NvzNPt+4zNx4qYpSOMfc=;
        b=MNdLcSBjKm4KikpTHDulK8N5Aof7jZB/U6Twy0tuMLWWtI7hhz8AqtezFnLAcRmM1E
         PlBL6Cg1hS7DJvCHvDe64/F95TrVSn1H/wrhZ92nP8WFw7weznh19TCHGOZCDvLdMR3c
         MiHunBol/alx9rwHTawxXt6Yz9tb3VsqNXSdybfgwh9aECT1q15uuprQJHNJlUo7P0O8
         9p4jmNIOgMg5GWG8NYXczLBibVigmngG1O3xxSvPyybCdFKlAaTOj31dwny0bSgNdKMd
         dq2Lwn2Ss8J1t8oIQ15EWWj5HUzx8dPVnFyLwnGyAnRpOPpt7Sagh6nR1Ps1oQ8JK9T/
         o8cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HCWfyIdCAojtip99vTY7uiFz3IS62MpBD4wCrtBj/tjYBBOqB
	/OfM4JozwZixSDfbGwIhKrI=
X-Google-Smtp-Source: ABdhPJzE/Sr6O6qTCBvl64/lgLDTWaQrQ/seT4VbJkS8fYdNxCkuQFREVweaJqPiuNT5zcFQq9umhQ==
X-Received: by 2002:a17:902:ba8b:b029:d7:e6da:cd21 with SMTP id k11-20020a170902ba8bb02900d7e6dacd21mr16209927pls.38.1607345359357;
        Mon, 07 Dec 2020 04:49:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b187:: with SMTP id s7ls8054630plr.3.gmail; Mon, 07
 Dec 2020 04:49:18 -0800 (PST)
X-Received: by 2002:a17:902:52a:b029:da:989f:6c01 with SMTP id 39-20020a170902052ab02900da989f6c01mr15755013plf.45.1607345358875;
        Mon, 07 Dec 2020 04:49:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607345358; cv=none;
        d=google.com; s=arc-20160816;
        b=UwuFmR3dLW9R1zo7z+vAxASU8hVVYQa6+nj5gg8jjbPy1fE4cpXCRnXO1hwDSkRYTV
         aSMqG0VuriKqUhxEZB9p2Sqcnoqz4Fra/+SKFuX0muDmOKfY1IAYx39Rvgn6tPqq/drs
         w9VrIWjWsQ3tFgYth9XN75kcZI9t+RhPIqB7r2sh1xmFrqKVPrmDWwDSUIcwiP8FCdCa
         9pTb3FJuyGpRqwCFHnmg2RiFAQ5E97JyqguffkxVFkjGuXnTGTcmRhLR5CkLKN4kgfrI
         2OSVlplJiaz2v2ih3mTQ/cnrfdvvLCOyGxy5sL3iTHiOMDG3NNPpPml2rQTAFsrVEC3r
         CcAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=4OxObmWGvOgqV0n6YlLY/gTI3vatRIOVe6686mZrMD0=;
        b=Aabu77QQsRre7KXlf5ow1ibmxPFItrJv9zxa2kGa1uhqj8xPQvO67NlIqlSN//qZ4k
         aXUcySg5RbuYv5Vr4K/NsNSeVUGMtbY+dHAmitfU5wGaQ38Ob6gHCY6gMgBXkpdc6eXN
         op1n+TlU4D3Mst3b8iyNAQ8Fq4xcaIcp6ew2FiDkD05YWJG7wDsx83xCw6Bhq3QcCdSC
         dHPiPqqzVxN3wz+/OWaAVKGjvp/9es8UVcserzDcvaD41azsIvjD/61q+wHj84wsV1Rl
         lAmCmgqe17qRL1NzzozBxaSVena/w6YaVKqiYmi45OnMdkW2Zh+9tj5mqseHe+x7sH1d
         WkWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IE+TIQ2Q;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id il4si44734pjb.0.2020.12.07.04.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Dec 2020 04:49:18 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 13:49:15 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207124915.GA122233@lothringen>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207011013.GB113660@lothringen>
 <20201207122513.GT3021@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201207122513.GT3021@hirez.programming.kicks-ass.net>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IE+TIQ2Q;       spf=pass
 (google.com: domain of frederic@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Dec 07, 2020 at 01:25:13PM +0100, Peter Zijlstra wrote:
> On Mon, Dec 07, 2020 at 02:10:13AM +0100, Frederic Weisbecker wrote:
> > On Sun, Dec 06, 2020 at 10:40:07PM +0100, Thomas Gleixner wrote:
> > > syzbot reported KCSAN data races vs. timer_base::timer_running being set to
> > > NULL without holding base::lock in expire_timers().
> > > 
> > > This looks innocent and most reads are clearly not problematic but for a
> > > non-RT kernel it's completely irrelevant whether the store happens before
> > > or after taking the lock. For an RT kernel moving the store under the lock
> > > requires an extra unlock/lock pair in the case that there is a waiter for
> > > the timer. But that's not the end of the world and definitely not worth the
> > > trouble of adding boatloads of comments and annotations to the code. Famous
> > > last words...
> > 
> > There is another thing I noticed lately wrt. del_timer_sync() VS timer execution:
> 
> > Here if the timer has previously executed on CPU 1 and then CPU 0 sees base->running_timer == NULL,
> > it will return, assuming the timer has completed. But there is nothing to enforce the fact that x
> > will be equal to 1. Enforcing that is a behaviour I would expect in this case since this is a kind
> > of "wait for completion" function. But perhaps it doesn't apply here, in fact I have no idea...
> > 
> > But if we recognize that as an issue, we would need a mirroring load_acquire()/store_release() on
> > base->running_timer.
> 
> Yeah, I think you're right. del_timer_sync() explicitly states it waits
> for completion of the handler, so it isn't weird to then also expect to
> be able to observe the results of the handler.
> 
> Thomas' patch fixes this.

Indeed!

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207124915.GA122233%40lothringen.

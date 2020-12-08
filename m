Return-Path: <kasan-dev+bncBCV5TUXXRUIBBOPKXT7AKGQE3FW2SKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DADE2D256D
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 09:11:38 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id r20sf15291504ilh.23
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 00:11:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607415097; cv=pass;
        d=google.com; s=arc-20160816;
        b=K4rkqwWiX9gJlpD+ne6XxnLQzB5qKP9XCevL+iKM5QF3dXDR65fC9vzvYRUv7Vw6Ud
         V0KHueFEAwwJN+XNxjN3z6Ni1sI95moYupA8F9khBk4Jy646iViM8+56CuuSMA//TxqD
         nzhICEvss8SxgC6oh6qH/5nMAoHE/BtcbElUSTpnz2yuEbccGEbkeIXh6EdyIKWr8Q+H
         Gfr3cHrpHLj1ANCvPL2gWi9krHGry//HFY7084S9p3WJnhEHEl1jORDO00eJx3qmiApd
         GhJbgSDGvfQEruMEGuHI8j8BD/D2Ow1E/xm/RNcART0wi1bt2vJ+5lZVtsC/beMnD6KQ
         yZGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rvrb89nUg7sryB7yvzCiWnt8m5tUx1gjCMK6mZlWup8=;
        b=CkRyQZDLnp1bgnm3wfcBUn7Naz9z/fJtxcjATZTsJ6v6mxar271sxSq83G0WmS2H+4
         xaHmuhuaP2zAcQQA/Wje16RKSPKy/xyFfMKhj8d5NcaAnueiaruufK4zAKx8dORzJbJ+
         ysenc+0PA6mJjnESQSKsIDmBGjiiTYv3v5YrR8ldrpPWNs/GABqCM5mLojGbH6VbS33S
         /YmW+BO21CdVivJaT89B1nwtadyZ/zbF2vZLw0OU4yxIg5niIXzatD1EzD+VfNlX3mht
         KkG/mcT1bubMYhG9+gbbfbsufYIy/NIzxt4SkI43cFYKpsBfK0qSSrY3G7vt9Lo18WxL
         GhvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=UEP2qNx2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rvrb89nUg7sryB7yvzCiWnt8m5tUx1gjCMK6mZlWup8=;
        b=VV9y300zeRJtnlNuS3gq2K2izHUsB/j3lt3w6ltcKscfKoWZJwYd+j2EKiGZgBg+g6
         xA9OPsUGz/2ms0WFnamU4gFxXHVEvMSUVLzm4oQo4GOKR/mu5J6PDyu4xU+LMa4Ig+H9
         Sgnk+nVgi4i97JbDC37uqv7wJkmthOh50g7lWUK2WvzLSakslJsFlcM+kmB4bnT7OkiZ
         BS5dRykpGygknRgVIOGDbTWTGxOPZ6R7svOYVL0TY2KmA4oicrBDyc7r32tnZlxuRbSn
         ukPC6prdLh5sIUHXE2+1jc2e72w2sk6m7ZilBnSJjhrJ8J94QSiSI0KI7hVt00GDLfvT
         dq/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rvrb89nUg7sryB7yvzCiWnt8m5tUx1gjCMK6mZlWup8=;
        b=Ucre7/oAqcGvoFLBwlbe+k8ClqMnb61Yz2btpX4pTdw7pQ9lMyIFye+BD8ZEhTSy4t
         47SGSC3AgyfU1u1+xE2couS4yIA/rl0WOqDYKVi9BEUesq1NF6g1J2Gs7qKZMl+/FcWK
         bdoLdqfsu0+bESacPQ58AGdESz0IB2bghJW0yzyTx+A6J0wcExyPtnop8YYsvlD4QPGD
         ARvUyHSK6aCmgXOBmRcmv66gPNXAMAdPkwC6pcaGFXOyid1T3YZqBsXRjeJdLzB9gwzG
         +m9L4t9cDQLwmC7oi0oZMBf5tNdsLcO6H7gpTRY72o6w14dc8ZHUTnYPKjz+fEGPhw3J
         T9Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312+a+7queR5GoflIu+i9ykDEGnzIoC0/BMQzUzni1go1c4qEcC
	EADmnRHb/UlOqg2Zw/JeUGw=
X-Google-Smtp-Source: ABdhPJy+rUG7SYN9P/NJdE+ZQLUMa69NAYOrjuItR9J9/DKFY82hPBjdOqn+BI2tF6LQ2LllmKCZVA==
X-Received: by 2002:a92:dc46:: with SMTP id x6mr708990ilq.122.1607415097092;
        Tue, 08 Dec 2020 00:11:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2616:: with SMTP id m22ls2467473jat.4.gmail; Tue,
 08 Dec 2020 00:11:36 -0800 (PST)
X-Received: by 2002:a02:b709:: with SMTP id g9mr25651772jam.90.1607415096796;
        Tue, 08 Dec 2020 00:11:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607415096; cv=none;
        d=google.com; s=arc-20160816;
        b=CPXcl1+r7ZQdu16IZMkUuZbvnDUru5L5TAWFhF4ST6pICH6Ste1EXdpjWfZ0xg7Hfx
         qsDtceyPNlluUe3SD6cUxReaQm6wcrHU/NBpkaaong44EC20N9NA2OPtPnDb5we97X33
         MayKunM5WYhvNfjTuJKse7qWJk/fkpkitLHIqHCUfTM5vcDpsFjOmlKhA+NdFVh+secH
         g+zjtHp9nNDGIGS0gLGN3jprcrJnOOmu2YIgb6ym7M335xKvE7Xp9vSL7RkeC5jYxTfy
         S1V5qTJOSokq1V3a2B8eXoeOQ67GBONflvKAOtwSskA8bwFzS7ZbACFpeLbBT5QMXgcQ
         2+fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8wGUeauYQffXI8deK/t5tpiJqZQbKQ3feyEVhMUeoio=;
        b=zJnC6KX2c5Tyw/0gxyYf8DKrUUzsQCpdrpcONau+YiAOufDMKwn58qOrTtAZwVa+FZ
         DqvYNmgh0m4E4Ud4x3h48OPAgJuDBLGLd+BJj/Ph8y+lr9rh25k5sBtrw4uLkxQKwUu9
         ow0hU4UHXBIBVDIzHvoKTUigHGcXoGZ8YVe4koAA940fyuzPdupkjjb+FzV1VPBsoUdX
         cPdwxz4JuaN8LlgGUMM7YwWc5owoq2TYVQggKqq1K56FEe9ZreuJJKk0sewVlBhXeyWK
         KnDAefPzPjB47ifX05tlX1wML8m47DtM0dpizkRqpQfgK9YpEzXfAbVYTJ0RvLxFniS3
         se4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=UEP2qNx2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id r17si1093083ilg.4.2020.12.08.00.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 00:11:36 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmY5r-0004Vv-5b; Tue, 08 Dec 2020 08:11:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D6347304B92;
	Tue,  8 Dec 2020 09:11:29 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id BA68B200AABB6; Tue,  8 Dec 2020 09:11:29 +0100 (CET)
Date: Tue, 8 Dec 2020 09:11:29 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Thomas Gleixner <tglx@linutronix.de>,
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
Message-ID: <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201207194406.GK2657@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=UEP2qNx2;
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

On Mon, Dec 07, 2020 at 11:44:06AM -0800, Paul E. McKenney wrote:

> Also, in this particular case, why data_race() rather than READ_ONCE()?
> Do we really expect the compiler to be able to optimize this case
> significantly without READ_ONCE()?

It's about intent and how the code reads. READ_ONCE() is something
completely different from data_race(). data_race() is correct here.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201208081129.GQ2414%40hirez.programming.kicks-ass.net.

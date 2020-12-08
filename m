Return-Path: <kasan-dev+bncBAABBLVLX37AKGQEZU7NW7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F0D32D2DB8
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:03:12 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id r13sf7495963oti.19
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:03:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607439790; cv=pass;
        d=google.com; s=arc-20160816;
        b=v9AfuEC1KPci2PUmPd4ZDesPxAt7MDOTmV/v6G9PM4EDDZXp7zEuktrPuC7AmC+Dc2
         L+oCvjjaV1/1lqpi51WWGtOK7zugHlQifQt4p/OX06vQ4Ps58+72oSIYCqPIocIhZeEA
         aaaSb5zriDkGkao3K+5bHncrRMihWP+6He5l3Gt2a02NJS8KuGi4vDQu0rYgt0jCafNy
         sxkrZ9CbNpqsZwrZIgeiVbFjtb5EyzYzoRNwg0tcap9VPYXGV8121VeEamin3lnASuPE
         EEGHVh7CnvzMkIhImPKgobiVZGdAkVz+AY7afCwpZPsc2JyBHZi4PSyn072vRfXzJk2p
         76XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=nXmaw4K7uWsYoISaawHaSQmgUD6TUBSj58XVzC7ggos=;
        b=HVK4KJKXGL30CPl3eGkDJzu5vlxOw4Y6I/PMuj639/Iomo+enbjZRuOhdK51P1x9SS
         jlKDk0eQ33VbrCSNG1osPOXRNHM/PVvwitw3F/RXj+6mBtg4XgDGtNZe8U8SIXmrppjY
         cNf3YtvMdJsSJHerG097TZWBLof2BhptS/nkZyaSxJUK03g6hBBeTqB4qya98tBPh3lc
         Di21tOXpwYbz8QwMRxbhah5KRu3TtWC2C+dO84btlnjD8RFTLEyxKBFWg6FCwsXVyOnH
         ZFeF/RvYfoYGstbr8Aiq7nShTv51u8xcz0tEQTbSSqvgIw/0esBB6tNPFiDtel3YQIsW
         ZUwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aeauVlPd;
       spf=pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nXmaw4K7uWsYoISaawHaSQmgUD6TUBSj58XVzC7ggos=;
        b=drpYLNrKOXJhLdF33KZC9+uBspnjnitQm3EczGeOHzZedkK0+aKAgU5ap2VmNXlf1J
         jedHB5E5G56+qNpK9jzDvCA51NNuKJwG9Y8VDWnFje1zmYIpzYwJDtAL6jMwuFeqaDXf
         vQ8j/O20tQ4x+GAA2zghfCcvly8yWRcOTc0myEokGAB/VpTeXvv7bbKOiyMPXibJNwY4
         MmAKDaln2ArMRdJ9P3k1a4KVIvkcXsmf3H5yy66wHRH7MbzEDmIEFwT+gsouCP5EDGIV
         qF94J1MBPfaH7nRht+TF/bRXueIuxwnHt0f4z+fBEQ7GIqKv1KAAv39k3PN6IXShfnMi
         inPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nXmaw4K7uWsYoISaawHaSQmgUD6TUBSj58XVzC7ggos=;
        b=hvlhOu34RiSVBC/fm+h7E7Cms0SzDPMe0FMwn83YoQuaB9+xf2VpoO4uzPzoULcy/8
         +PgbvHn2mVVNrkBZca57msSmune29fgqY8psJVsLDcRMlrQ5hniedzZ1i1TLDbNO52X4
         RyAxYqnOdyHtTqqqq+Tgkn3NHUXVFnoa7ylGVvQQNLPYoTrn3unRwUAaULzRbKphWUzb
         lzj+O38om++pKTXBwKT/r0LviWlhsuVxYU1PWSVFvsxtePfoj7/ZnRjApNjQw9I+mbRY
         qS/geMPfBnbHRAFTebf9+oQBkhxlgx32V/690ZMuHLX8vLT+B4sJTJGD6kO6oEXBxHn6
         flYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DGRdzJ9N4afMwYA6QpL6GQWFBF8j2IlQYH7GuTT/fSaGqA5dU
	Hi9Cu+rl2NJmh3iUUsq5eTM=
X-Google-Smtp-Source: ABdhPJxcRZDhLnRRcxB9hQQem+vl5QEHZhoPzQD8/iG3PyJagx+cLmrgIuDpBKKU5NB+HMELuytAFg==
X-Received: by 2002:a4a:a289:: with SMTP id h9mr1489565ool.86.1607439790740;
        Tue, 08 Dec 2020 07:03:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4542:: with SMTP id s63ls5272605oia.4.gmail; Tue, 08 Dec
 2020 07:03:10 -0800 (PST)
X-Received: by 2002:aca:3b57:: with SMTP id i84mr2981486oia.17.1607439790431;
        Tue, 08 Dec 2020 07:03:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607439790; cv=none;
        d=google.com; s=arc-20160816;
        b=gRCV/O5wJ4Te70fWjlA0AYIE8r51fB6MRQSZZix/0F3Hmq/quv8FSv6b40uxK/fy99
         PGtjcpUwyv0+VtieBA5/aZI2BBYKmchT1um5qsFXsxgW+ShZEAWKbSUJzh9EwM0mLHiN
         2kXfszbk1pP1FqMooZzzcLf6bBySS6yaz2Z0y0LYjTl1GbmV6NAY89Zi+HlAfv/powBo
         OrRQDlq8j+t9j8ygBjbQ1rVNeEt1cvWbJJ96l348He/pjHCKNCcphn1kvzfAMUIrE0O1
         2RKIymRvraQEi/vNkAriES09ONsQz8Kj2cyid48gYBDdEPVYmlZpZnPxiTdKguhtqBui
         3iBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=JwyCpsBsEnh7msJOt6yTA5sxP39thxwaPr7/7mqjlss=;
        b=Ip0GV0kQjM6xKMnyVPSlB25qX27PjmQLfDQWuPiswl8MeDmWpyi+zPIq7Thpu9l0ob
         R5MQc5dcZtU3+DEIkaVWU0SM8tTd6umt/XT6kSHMFTfJF8hf9ugAmA8xBLLLSlZwUp69
         Q706P3/6XXDuhJK/MA21ZCA/ZpaKRXgAejoOOBkDsddgHIABuiN/IzXoCk+m2ijnKtkt
         rmQV7rtHbIfkkhSFgZe4zSRefSdezb4vNWTrrUUz/llffYMVG+3cyWqniFdISjMh0Auh
         3jjlijfwheWA+03PJRDqO3KrtBmBAr2ivk90ZMGN7zSUfKwbtKRmOY9p1XUT/qIRUezo
         h12w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aeauVlPd;
       spf=pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u2si96125otg.1.2020.12.08.07.03.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:03:10 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Tue, 8 Dec 2020 07:03:09 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20201208150309.GP2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aeauVlPd;       spf=pass
 (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Dec 08, 2020 at 09:11:29AM +0100, Peter Zijlstra wrote:
> On Mon, Dec 07, 2020 at 11:44:06AM -0800, Paul E. McKenney wrote:
> 
> > Also, in this particular case, why data_race() rather than READ_ONCE()?
> > Do we really expect the compiler to be able to optimize this case
> > significantly without READ_ONCE()?
> 
> It's about intent and how the code reads. READ_ONCE() is something
> completely different from data_race(). data_race() is correct here.

Why?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201208150309.GP2657%40paulmck-ThinkPad-P72.

Return-Path: <kasan-dev+bncBCJZRXGY5YJBBLMITSFQMGQEOT4AADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D78042C5D5
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 18:07:10 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id v62-20020a1f2f41000000b002a41c96d713sf1271639vkv.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 09:07:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634141229; cv=pass;
        d=google.com; s=arc-20160816;
        b=TCG1+Qsx9i+T7W+pb5vgsHEYSttXCtaL2SzzQmyk2mP4+NrwL2iMViUe8S5GMNn6bC
         +ONfkJQHbj83AzB4wIYr6nEljzD2Q89RIzJ4RU87VNBEMUfQpn49YT5C+P+UKW11sceW
         aA4X0GnHFOMsYgY6TppkcaHiGrgWwMC6kupWLjspAEmlXmmViiMWu7JAWEFLko7oCEId
         xp6clUsVN2NFollhF0GZJhRIxVeE8HPcRy5KaqT3t2dkZx9S9bXmFb06wmPnJdPQcL69
         6YfCYCWQOxuKrVj4ZQ5+pFAuCr93vsif0mld/YNzF5EvH4zI3QuBpHs2l1/2ZN2GZ8Tw
         yD7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=9Ieio6caWSmgF0LBwADRwymFYhTIdfs27y6vk1gKnig=;
        b=hWViTnecc6r4BBMk3qk53Jpwk840gocky6fP/WgQ+NrfUdH3L8xwtGgv1cZW9MaRKQ
         hGGW30KX+GkhHjfVYFJRdWzpD+BzxAeg+adbP7wCtMKul4Qi7xtDjyaBLUr8lZaLBPpr
         Om7Rw0BK/DOsT1NmTjKyzL7BKar66dX2v71wiNXS5hwYL2BmBWT9MhwJicn5fSaGxhSB
         2X7vdhhPkZJ7nbIhzZQYCcG2yY+g2N8SzTh8ZebGAPxAKr12LP1mOKIwJBi2us8DVYX7
         MFI1rcJX658yeaB8KicmOd4NmM1cAvZI4jgv6hko15+TCsD2AxPMq7+l9QfJeMHjH0oi
         +Suw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bxE7Qb4C;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9Ieio6caWSmgF0LBwADRwymFYhTIdfs27y6vk1gKnig=;
        b=fdb4xJP3whpY8DxAFPgXFVMm3D4Q935SGcMRh3vAY0ZJqzcY9IJ3vPg336ozMtdbMG
         wHb8Brmzm8tv7v7dmNypthoOEWVAbqGa8flSDQY4SlpQWSnq/WcMYs+VSQVET654jiZG
         fVm40nKIvd2oDBMkzZNE2YFzp0CNI8LoBWS8iN69R6tXKzsOWTg8NNe7GsracuyL5VCj
         JDZ58oDnhBzpsbXe2oIcN/j7vE6tR7MB5eVfnwW/cqEquKNjBMtG7ZW+Y9SQRVkIJ0O1
         /zA6OyxJ2RV/UrMIIHNZzz6RnhmI0GBp6z0+hGc0sMF7s4K4oMhrivCr2h9L2SZB09eW
         b29A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9Ieio6caWSmgF0LBwADRwymFYhTIdfs27y6vk1gKnig=;
        b=p+WshqpI2Flu+HUkArzWs3havsIFGF37EfEbYh9T+2BDp39e0t6a8IrwcklRupCTvb
         bm64WcKZ6oC5pY9TFViZZdGFHxkTS01dUG/FM+S1wcdfZomhm7kP4ghDhS2t55mBncQf
         x6dybAuDI3lqVdEq1fAxvOMnB6y9xDVxrQr0bdj+pKgxXEhqub5Iuh+Ce4UqDhuJgrYP
         ncP0ZKHy+i2MWCrcPkl70pIZhL+kcYkTavhKex5m2z2ibwgY/rywovOJ+4eM7GiN19iu
         LE/J32oCc+Cw70wnB97By1WtVAJKwP0ZGKBnXJpiXj8ElDdGnjqHeQRnnXUQSeg1W9yB
         pPxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PG/tLxCOqBlXsfViR6slUm9p//Pec8Dow3sPirBYDGrgPLKlH
	5fBz/1Cm+D6HDdHQLA0WBlo=
X-Google-Smtp-Source: ABdhPJy+4sWSGqKHy5fOo4KjkoceEpAWh7jDxLARFSRJylA9nYTZhUH0KhoV47+33d88reeYaKkf8A==
X-Received: by 2002:a67:c886:: with SMTP id v6mr298805vsk.40.1634141229250;
        Wed, 13 Oct 2021 09:07:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:9a4:: with SMTP id g36ls321778vkd.7.gmail; Wed, 13
 Oct 2021 09:07:08 -0700 (PDT)
X-Received: by 2002:a05:6122:218e:: with SMTP id j14mr57012vkd.0.1634141228783;
        Wed, 13 Oct 2021 09:07:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634141228; cv=none;
        d=google.com; s=arc-20160816;
        b=mMZA7rn3tcAuA0aYgelDwmPN2MMesUgU5BvQy80lz/SsX28/rW32P6sZYhjbGvEs/P
         9DVpW4JOWkXOdKVPY0Ntr0Rzgb1TwrxFLahjTh2ya1vl/aK3gN+mGdFn9eLv7HngTiWq
         AtYCyo6ECjhfQFpuzJfBlvWtEW7EL8NVQ/OG0BkbITrWyBQTqbjRlBUw+oZIea/FXi1a
         4UWX6jFaf7b75VailwzmUVBcKFNc5pk+1pupO/SK1fSjjoRwJZi/Lj3FuxLasp+zeIjN
         X4PEXJqzrkjDfUT6lK0wh3FN4eKRWk3u1Pg/9bJEiIAQx8hSQHAHSvyeIC3Wwe/RqrQc
         FyOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8bSYXKEDuAO+Qvj027Or3102LmAtqz02zb7R4T2789c=;
        b=rx0Jvgy+RJ6a49lf+BXXrSW84IBE1rO0W0CSML7pq82w47KK72JtygJRXs8z5SpKrH
         y1PpwRv8oCVs5zfLlAw3j9s/Bvb6bdcvl+FtHIQHvbHUY4sT+8MwpjBGL6B3TJ2Cq+kg
         Fckjbb98VM7/VrNjwQdXH7NCUMbEDLz2bZ/vMk5y2VOuk5/1CXvKxwpYd79xjnMiYZDo
         eMHFjN/1C9gO6JzcMDI3IYIdl1mCkz/jHSqyfk3WStO9PeOPD7LF4cHYLtALTBhzsLtu
         TatoVTSaRW8YVz1jtnta7FUjMdIGdgi6dFn+6ctByjZcMGguofYFwX/V147aYYLuK8TL
         6/ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bxE7Qb4C;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g132si3245vkg.4.2021.10.13.09.07.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Oct 2021 09:07:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9E47460EE9;
	Wed, 13 Oct 2021 16:07:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6EB3A5C0687; Wed, 13 Oct 2021 09:07:07 -0700 (PDT)
Date: Wed, 13 Oct 2021 09:07:07 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211013160707.GR880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
 <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72ny0RCnO1+E_wBgx0C6NCaMfv82rvkLVuwmW8Y+7Kii0Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72ny0RCnO1+E_wBgx0C6NCaMfv82rvkLVuwmW8Y+7Kii0Q@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bxE7Qb4C;       spf=pass
 (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Oct 13, 2021 at 01:48:13PM +0200, Miguel Ojeda wrote:
> On Mon, Oct 11, 2021 at 9:01 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > The main issue I was calling out was not justifying Rust, but rather
> > making sure that the exact same build could be reproduced a decade later.
> 
> Yes, but that is quite trivial compared to other issues I was
> mentioning like adapting and requalifying a testing tool. For
> instance, if you already had a team maintaining the configuration
> management (i.e. the versions etc.), adding one more tool is not a big
> deal.

OK, close enough to fair enough.  ;-)

> > There are things that concurrent software would like to do that are
> > made quite inconvenient due to large numbers of existing optimizations
> > in the various compiler backends.  Yes, we have workarounds.  But I
> > do not see how Rust is going to help with these inconveniences.
> 
> Sure, but C UB is unrelated to Rust UB. Thus, if you think it would be
> valuable to be able to express particular algorithms in unsafe Rust,
> then I would contact the Rust teams to let them know your needs --
> perhaps we end up with something way better than C for that use case!

Sequence locks and RCU do seem to be posing some challenges.  I suppose
this should not be too much of a surprise, given that there are people who
have been in the Rust community for a long time who do understand both.
If it were easy, they would have already come up with a solution.

So the trick is to stage things so as to allow people time to work on
these sorts of issues.

> In any case, Rust does not necessarily need to help there. What is
> important is whether Rust helps writing the majority of the kernel
> code. If we need to call into C or use inline assembly for certain
> bits -- so be it.
> 
> > But to be fair, much again depends on exactly where Rust is to be applied
> > in the kernel.  If a given Linux-kernel feature is not used where Rust
> > needs to be applied, then there is no need to solve the corresponding
> > issues.
> 
> Exactly.

Thank you for bearing with me.

I will respond to your other email later,.  but the focus on memory
safety in particular instead of undefined behavior in general does help
me quite a bit.

My next step is to create a "TL;DR: Memory-Model Recommendations" post
that is more specific, with both short-term ("do what is easy") and
long-term suggestions.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211013160707.GR880162%40paulmck-ThinkPad-P17-Gen-1.

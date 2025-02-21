Return-Path: <kasan-dev+bncBCS4VDMYRUNBBY5M366QMGQEIW5MLWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id A82E4A3E9F0
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 02:27:00 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e57b1e837fbsf1826187276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 17:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740101219; cv=pass;
        d=google.com; s=arc-20240605;
        b=IJFKPWinV1/cfq2FkbtwNy6m4aXyA7GxC6EPsJ2mT/49bMbFXRjzTuMw8094fJBmLM
         TInpjTv80zCAixhTSA2KrFmRWGWRyYNAOF9fQwjEtyhCIQorXbVojkYn40s4BHF9TtDw
         UU3pJirSXeNzuhemXfDZVS+wJetdZXUtO06fiaxWobcag8okOt3DrN5aV7hOEXTvZuUq
         pPR3asDhE66hw4Ka/BiGybOAkPlhXS6yb9qO2g4DarZW6bQnNjswZc+aYoAi1K4yuXHR
         AIpwzq/oBB37tppkuVWl4hKcU8ZoKCLEPh6c2itAlryVJiSU+bYlWWq4MsACwaRf4/5i
         w2nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=0suETxrUhbk0+fakQVRoSnI6oNzFgru3Kdt9vDzBjtk=;
        fh=KAH/5S/UEOv8Wciwq6XDuYH/CZ+QFqCEWUYcajuim5A=;
        b=SJnz8WQ4YWp0sofq74I6gkBWt43PIUWnFvDVYC+oJ2fDljBL51Qlku+jsOzFSjm+lJ
         I+5v2su7QkOWThK5LkZFp42n6nT/FVyrXgfGD+ELdY2uuEX23vDk4XjxP28CmuHXaroU
         GR8hfZ7CyDPMqxf5+pa5/S4nch3oY3lQJ6Qg3FluHQxNLlesAZcRwt47ACvjbtPL7yyE
         s4U0R8VmPeljWryDpW8XYWdNMij3pCcXrvbCSmsd2pLXM3/4pCVXmVgTDFU/zWh7nfLl
         M9Qkqrmza7147MWYs3tPdupSivjUDv+2PFX8Sz3zP09gf7A+YxLQZ3oe1EqEVEb0ZElq
         /acw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XzSceNiJ;
       spf=pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740101219; x=1740706019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0suETxrUhbk0+fakQVRoSnI6oNzFgru3Kdt9vDzBjtk=;
        b=Q7/w6ohT+NCkdvfu2auwQRqZvWDrVA9QlD4OQbjIVJATLygxDSaysSrFqDEC/YLbDV
         zySWkLn57DdjiYqVapPJmJwRR3HyynqTd07EBvmz4RE1MLEM2ZW0xWe0rKjoO6A9AjAL
         PBEy38cIk3o4aaAtnhl91QVAJz8IVA3OvXXhgPhZE7fXlj90HdUmVSo6PFVOtAP2Jvil
         FR+C5pPxwG/WHVBtVxMuPkOE84RcZlrj/lNq3GrbJncrJhBMWm+t8XZq9KIW3bOzQ85d
         51nvaI92+q9jquMX3IzDd+Fw9awGTckhLZTbCpMNMq7fFJUal5QaIH1kXqgGNHwpa0kv
         N9tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740101219; x=1740706019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0suETxrUhbk0+fakQVRoSnI6oNzFgru3Kdt9vDzBjtk=;
        b=H0xrgoXqVx1c6s93DXpMFgepY9g1yZKvFO1i6ZfupcPKYhWHRnQtNzN8ZXyNpEwLQr
         FadCYOw6v9tDmixOIMjDbBOf7lCE+fV7GQBRcSzjo4cYnquz9xxWc2rFetnRyifZssFj
         4BsqnHgrGvfm8p5L+wvTmcp0oDUjbSH6scRk13OsCDHpXVAU7c8dW5NnHlkPbVMzAZ/m
         17WuuHMWPSkRY8kerqVdFP1sTWG9LlN1AjnLON1u577lPuk2c83U+rOTf7kuli/AD1ra
         gxeTXV3FaWvMN5L4rK2zrH12M9BLXFdx6aXVDmJuI0kNKJts1lrG1XMo9mVBWAS5ELSh
         o5Tw==
X-Forwarded-Encrypted: i=2; AJvYcCXAgKrEPyAUZlbQyn4dJJlhVH8MWOfhZsri7xG1h/rqLPPZ80K02FEa1Iy8dvkrVM4Fg4wz7g==@lfdr.de
X-Gm-Message-State: AOJu0YzlT7IO9OahX3G2lQA7k3rb19Ju9AWQQEmNRXXYbY4ZSYNXhxWL
	TkF4bkp7cz6x6X+bZ3os/8q7c6VIml4xwgqh/vyTJNE5Ti2mwgxs
X-Google-Smtp-Source: AGHT+IEjMa9qVEdiRsAxX2JcQQ7KlMwNlfxh6P+UAWQjneYwthbr1QI/JMzf6mb8ZRNxoNNgodA2lw==
X-Received: by 2002:a05:6902:2488:b0:e57:4254:a765 with SMTP id 3f1490d57ef6-e5e24603e02mr1234997276.29.1740101219458;
        Thu, 20 Feb 2025 17:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE7wB8AXrG57Uj7fEuJyus1n2N0qINxHTYcHMj0O6OvjQ==
Received: by 2002:a25:9b48:0:b0:e5e:1412:d7d7 with SMTP id 3f1490d57ef6-e5e18e09c2cls1466703276.2.-pod-prod-05-us;
 Thu, 20 Feb 2025 17:26:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbAYY5PG4+p4545zrD86Oq/ULT7G9kxuL32/0WLPq94n0NrVMCgyN56y94N1X5UUrd7sl5AWo8g7A=@googlegroups.com
X-Received: by 2002:a05:6902:1ac1:b0:e5b:149c:d8d6 with SMTP id 3f1490d57ef6-e5e245026b6mr1215975276.0.1740101218260;
        Thu, 20 Feb 2025 17:26:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740101218; cv=none;
        d=google.com; s=arc-20240605;
        b=D/p6+5hqvpvXiAR8yk7vCiJf6/GSC7UYWLGB7OTWLs/Ct0OQU143AV1ndhMxZFRQb0
         8+8vmTB2ToJwgHfYsjBoh10X1h902zaMfkYo9vQahkezxWHJbwtF4M4L6qIDqPAYaOP/
         0ZmffsMn4UCm7niaEqNSKuQ/GUhDetT/p3vElFyZM5/Cek7t5lbdESDHQPXCS3h+1oXn
         cnwcRHo+9zH+fALuInrbvOG5g2DnHaQQmqvxzDjW/Mo0gFqAg5KEbWvPAgLxXmT22vJc
         BlX2DybjS6BG8lYWfGBZo1Xmk/kVOy7u7tVNBwCBmlWq7hI26cTXlSk+KOFoBpPvVAHw
         z6lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1SLgbbm8oBBv0rWxOPdOkGGDrSbkPNORKrfT/Z/nVbk=;
        fh=6daLWNj2ng9AC7k6NsHppG+JXGUhij4U/k8Liihd2jM=;
        b=btKwOBi15fV8eOjh6bWdRP66Vrv0yr4wnG7JhS3Qy+foLem2nxTY4up7ohlNkP7LrD
         3J/t5TkSxkDGbERAKAdmmI/zSvT/q9amZxkD8sDQioZp6htYtTskAZiB0kV9YAZv4g5B
         FtEWDpP7z8MjfOHhVg5biCzwdJA2t8tXDG+AhkzH9A154HqvGyGCHyfAdi6eEm95pgjq
         VoUwSRqcP0O/qjTX04zlhsN7FatdhydexL02hxAUihp08Y5QrI6YvZEtSTwdPYqygZoE
         s2DlGqco0RjQirAoE2F964lr6Q3vLH4cngvYMTpIMsZ9NiM128MEuCJhGmI3rfdhzQlj
         17rQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XzSceNiJ;
       spf=pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04::f03c:95ff:fe5e:7468])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e5dadffa6f9si552825276.2.2025.02.20.17.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2025 17:26:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) client-ip=2600:3c04::f03c:95ff:fe5e:7468;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D473A6838B;
	Fri, 21 Feb 2025 01:26:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 18B53C4CED1;
	Fri, 21 Feb 2025 01:26:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A122DCE04E4; Thu, 20 Feb 2025 17:26:56 -0800 (PST)
Date: Thu, 20 Feb 2025 17:26:56 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
 <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XzSceNiJ;       spf=pass
 (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender)
 smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Feb 21, 2025 at 01:16:00AM +0100, Marco Elver wrote:
> On Thu, 20 Feb 2025 at 23:36, Paul E. McKenney <paulmck@kernel.org> wrote:
> [...]
> > Suppose that one function walks an RCU-protected list, calling some
> > function from some other subsystem on each element.  Suppose that each
> > element has another RCU protected list.
> >
> > It would be good if the two subsystems could just choose their desired
> > flavor of RCU reader, without having to know about each other.
> 
> That's what I figured might be the case - thanks for clarifying.
> 
> > > Another problem was that if we want to indicate that "RCU" read lock
> > > is held, then we should just be able to write
> > > "__must_hold_shared(RCU)", and it shouldn't matter if rcu_read_lock()
> > > or rcu_read_lock_bh() was used. Previously each of them acquired their
> > > own capability "RCU" and "RCU_BH" respectively. But rather, we're
> > > dealing with one acquiring a superset of the other, and expressing
> > > that is also what I attempted to solve.
> > > Let me rethink this...
> >
> > Would it work to have just one sort of RCU reader, relying on a separate
> > BH-disable capability for the additional semantics of rcu_read_lock_bh()?
> 
> That's what I've tried with this patch (rcu_read_lock_bh() also
> acquires "RCU", on top of "RCU_BH"). I need to add a re-entrancy test,
> and make sure it doesn't complain about that. At a later stage we
> might also want to add more general "BH" and "IRQ" capabilities to
> denote they're disabled when held, but that'd overcomplicate the first
> version of this series.

Fair enough!  Then would it work to just do "RCU" now, and ad the "BH"
and "IRQ" when those capabilities are added?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/772d8ec7-e743-4ea8-8d62-6acd80bdbc20%40paulmck-laptop.

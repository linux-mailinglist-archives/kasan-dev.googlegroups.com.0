Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NRUC7AMGQE5Y7FSCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BD20A4F9F1
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 10:27:15 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-22368fafed1sf132287805ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 01:27:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741166833; cv=pass;
        d=google.com; s=arc-20240605;
        b=QU7NBPzUxw2erLNFU+0KL/1IaGBcXNuqUx0cs+spD7Xs01FyHSVwG5OLGvxD+Fa911
         RXDxXKQNLXU5kK01m9sMZfioyLntTWOBagCa3l8tMvR0sjxi9tDR1EXfadngQz2wzf5t
         XaZ5feFZLahN8NzGc4GTlKXJf/n+0FCERHSYIVS0yRieRYJqDv7QxZdZWbL62RGKdHN5
         zQxXuqcdHYGJg8fYhyIAZaOBkLGCL2lBzD+7LHoR0Fb6j/onKUU09im/eUFMElDsbd50
         N4RSZXWXw528rUT3hMZ8A2EbGqkUn5hXF1puLvd1yT+b3iWVyuKx9W5HvExOwZDMecRD
         p6EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jE0J0nECxmTX6cg1yIhW2KDFNS2EIHlNjASy4LuIPj4=;
        fh=nIKEU6Hz7g2hB2xyRZYGRiPDcMZFcgLLGgRKcdHF6l8=;
        b=QG8NqjdIO54UiHm5B1on2Wm3j40Imysc/Deo26mYePbPRcRPB3VG9e6k2K8OCuRd0Y
         5EF39FDA3baci8qliJuD4dMEw/Uv8CwPoxZiPCUJnw5KT2CzDWJmJwzi6V3bJ8seDH1S
         r8dxa83xlcd3iO54P5DIvRG+bRKA1ceZjC7b+MFaakWMj67pSU5SV/sKgaU2tNXz6/6X
         BibkJox3baU1wX13UTfJ3r7JrBU0kG+PrjzWGMR/p0WH+X3OWlIXBrd92c5eilise+MN
         IbQyrDQpmjh/yEOmcNBCwAdO9KoyiVSozxWZd9NoOvzaL7dhwE/cd9dB6pirZ5G9sQJr
         uzCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MjG2Q8PK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741166833; x=1741771633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jE0J0nECxmTX6cg1yIhW2KDFNS2EIHlNjASy4LuIPj4=;
        b=l3edAWj89ks8Ey+G5yx7fTfJTFT9ee7YqKKhpU3UQwmJ4qLDuzEBs0Gr0rPyqeDc1i
         KG6+1ZosE4z1T7rmeg7FRAnYR8O1CoCElBUw5xgkERxHMbgmo22bpRL5Q+byIK5LZYgB
         /UVJehQTalCkcdXJEM79iYSm9uOX4Uh76e18nx+22IePgIDVZOav8yHTRkchTShIyqah
         T7oqtEtYeDcEtRpD3iKCXvGEDRahf4le0Bh2p1aYnIJ4WAlQigLFNMkDcZpAYjNyd7Rw
         6zbfLTCxbEdsG02zgpc7mbv5YmlzmgXyH5EnkN+JJt+aamOB6f1xttp2hJxYW+0yeh+N
         YRSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741166833; x=1741771633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jE0J0nECxmTX6cg1yIhW2KDFNS2EIHlNjASy4LuIPj4=;
        b=f60dg3IuYcGrd/CHsCvA/ooCgmbxU+zqbpOM7T63uxlJCSUl5ZmXZz6Od/B32Q3VCK
         yW1zznqvjW67wfy2DWM7OzXC733rqftarHyWvoZzoIOlBmrfkn+bx8GKBJ9OCMM4p7au
         HLskhfnSg6YaAYnPgpq3eJUDkYoMMrhRNNKOTHoQ407eSDZMtvOzOyKAIlrIRJ7pS/yf
         0LPI/+u7ms0S43SX3Rs+ULipexMk40omQTpIjzGvt1LJ36M5jdviBBhiC61ydRwR7jNS
         a/vAXrZQXAwScN/BXZZPp09ylfPG4dpsWCE/1u+WcqiUwe9qZR4Ztn7TkHLWuKH9MXg2
         46iA==
X-Forwarded-Encrypted: i=2; AJvYcCVvrI3vxYgEkPTmB10XRNRRNdWn/FTIuyMPO31e4lYOgl+Bjuf/CUBYzKqqUrpuGrfZxL/b2w==@lfdr.de
X-Gm-Message-State: AOJu0YzYTl6XtSEi3fVbAeZt1PZvj+Lud5c5eCFuNcoKpFdv7vGiynYA
	RzPsmdiocVH24FovWRs91Bwv7UA3zb7+CttT6VL+qUNMYVYAEIAT
X-Google-Smtp-Source: AGHT+IGiAtmyYMsxp0/6TlSJnQRBaoiiNUxSyu8v1QWjbdAEr3dZCozFwQM/bAXcxign4zfBHAIvrw==
X-Received: by 2002:a05:6a00:4fd0:b0:736:42a8:a742 with SMTP id d2e1a72fcca58-73682be0f40mr3007760b3a.11.1741166833568;
        Wed, 05 Mar 2025 01:27:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHRD2pd+C3dIW3x/5l8qbrfMnG8eCXORxE4F2TKgw2RXQ==
Received: by 2002:aa7:86c8:0:b0:730:99cb:7c36 with SMTP id d2e1a72fcca58-7349cbadba1ls6130074b3a.2.-pod-prod-06-us;
 Wed, 05 Mar 2025 01:27:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjq5xhap71I8BMByFeWuzUR/xa+9/h7uBgEsXIKCIv/kEWo0NNkJKOvwPy0R3zsfYeUB4o7dOKJzs=@googlegroups.com
X-Received: by 2002:a05:6a00:c8f:b0:736:6b94:146d with SMTP id d2e1a72fcca58-73682d101e2mr3820185b3a.20.1741166831821;
        Wed, 05 Mar 2025 01:27:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741166831; cv=none;
        d=google.com; s=arc-20240605;
        b=ZITopo4VvAfLhrIJlUJqwuBaR5NA34z2Cafmwsdcg250VkhLqbg3OJlL+0KrQtJzRr
         kdCRevua/RfeesDtx9YchAxw2704wTSKatTfMyoM8Q16pUvdDg+/jv3KkGg1HfZ7mV8P
         Ux+Cvxczb+AQsKxHhoTkgB6ZSEcmhWZd/WINGSXlIs/pp2wSWiRBgn1/sIvaZXWi3Me8
         fC6JUH8IKaKs/d9EXwTJv44BekrT17GRwAxifmwbwyJ3dm/9YUhlZyNjBSsoNCvFuRPC
         tds/ZeIltl/vnl23bHG3BbyXJLOoehnTKAWZY52km2qAiE97G6tTu/Mv8ZUVGY46XVsw
         M2TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/K733SUjRr/UJmKpRHEDrbtF8c66tB7gTHAMMFw3t0g=;
        fh=MmhkNzWoNEiyWjXAJ1JrLa7BJIiFvsMR3/xhECl3jas=;
        b=UFbf5B8q/Z4fX3EbkaGZeJTZ2e0QMi4qDvBNs+EKWYT2QzMOaAO93omyL8V86OJdhC
         +lEqGXd6QgjE7p3EgOh7NU5MycVccmITbeQln7Sjp1djNFQ+ebvevnKqoX1SmxGsNhVA
         78V8dPzSP6FeK6rYLD7wfTwwJKwstR8nCGGEd/KS73hqbaOwRDYrhmb2FpI3aZU7YaSA
         lzANkjwXTSTCwpb62d439PbuVAtjyv6cfJ4AoS2vV++FVY+Pf74+BM2BNUdLDGg+/2me
         xlAV1S1iPmhs0WSf/tgM4mGAuvhRPcP5qWdLYtB1TDI5gKePVTqlfDsvTMrmlmdB3vnq
         DASg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MjG2Q8PK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-734a0060044si665440b3a.5.2025.03.05.01.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Mar 2025 01:27:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-2fe82414cf7so12935548a91.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Mar 2025 01:27:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVXIfX6CWRNtslltgec4NLEFmj+elczvv8BQj6RQxzbZ/pEU3AZhAAh9CviNOW5bXyD53lZKmjNRt8=@googlegroups.com
X-Gm-Gg: ASbGncv2t3AAlXYR33VHVGTRtY0CX0Pxp+4FynaQpqtKKYztekW8o+co9dNZoQL4tDp
	e6V2DwLlAEvPKzYgXGE59KsC9VzVQoxdaWFZtE8sAy/ZWh4M9nIoAUggk9KouLZSR730ZWd9i5X
	AFc/nDVxrsOmKbQgkAlAxg1gncrlsqYb18WgqwDoHYTlici1Mg4D26P069
X-Received: by 2002:a17:90b:1d49:b0:2ee:8ea0:6b9c with SMTP id
 98e67ed59e1d1-2ff497a91d9mr5296650a91.12.1741166831231; Wed, 05 Mar 2025
 01:27:11 -0800 (PST)
MIME-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com> <20250304092417.2873893-32-elver@google.com>
 <569186c5-8663-43df-a01c-d543f57ce5ca@kernel.org>
In-Reply-To: <569186c5-8663-43df-a01c-d543f57ce5ca@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Mar 2025 10:26:33 +0100
X-Gm-Features: AQ5f1JrzAOwhwvy95MFPvjsEXdGkKN5XEE-rlSH22cDbqIsJIlrP0-RVGS5P53c
Message-ID: <CANpmjNM+0xWRUmeyQ0hb6k5zHakw=KAaQN7VZ=yMyz0eyBa4xQ@mail.gmail.com>
Subject: Re: [PATCH v2 31/34] drivers/tty: Enable capability analysis for core files
To: Jiri Slaby <jirislaby@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MjG2Q8PK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 5 Mar 2025 at 10:15, Jiri Slaby <jirislaby@kernel.org> wrote:
>
> On 04. 03. 25, 10:21, Marco Elver wrote:
> > Enable capability analysis for drivers/tty/*.
> >
> > This demonstrates a larger conversion to use Clang's capability
> > analysis. The benefit is additional static checking of locking rules,
> > along with better documentation.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> > Cc: Jiri Slaby <jirislaby@kernel.org>
> ...
> > --- a/drivers/tty/tty_buffer.c
> > +++ b/drivers/tty/tty_buffer.c
> > @@ -52,10 +52,8 @@
> >    */
> >   void tty_buffer_lock_exclusive(struct tty_port *port)
> >   {
> > -     struct tty_bufhead *buf = &port->buf;
> > -
> > -     atomic_inc(&buf->priority);
> > -     mutex_lock(&buf->lock);
> > +     atomic_inc(&port->buf.priority);
> > +     mutex_lock(&port->buf.lock);
>
> Here and:
>
> > @@ -73,7 +71,7 @@ void tty_buffer_unlock_exclusive(struct tty_port *port)
> >       bool restart = buf->head->commit != buf->head->read;
> >
> >       atomic_dec(&buf->priority);
> > -     mutex_unlock(&buf->lock);
> > +     mutex_unlock(&port->buf.lock);
>
> here, this appears excessive. You are changing code to adapt to one kind
> of static analysis. Adding function annotations is mostly fine, but
> changing code is too much. We don't do that. Fix the analyzer instead.

Right. So the analysis doesn't do alias analysis.

> > --- a/drivers/tty/tty_io.c
> > +++ b/drivers/tty/tty_io.c
> > @@ -167,6 +167,7 @@ static void release_tty(struct tty_struct *tty, int idx);
> >    * Locking: none. Must be called after tty is definitely unused
> >    */
> >   static void free_tty_struct(struct tty_struct *tty)
> > +     __capability_unsafe(/* destructor */)
> >   {
> >       tty_ldisc_deinit(tty);
> >       put_device(tty->dev);
> > @@ -965,7 +966,7 @@ static ssize_t iterate_tty_write(struct tty_ldisc *ld, struct tty_struct *tty,
> >       ssize_t ret, written = 0;
> >
> >       ret = tty_write_lock(tty, file->f_flags & O_NDELAY);
> > -     if (ret < 0)
> > +     if (ret)
>
> This change is not documented.

Fair point. This is because the analysis can only deal with
conditional locking when fed into zero/non-zero condition checks.

> > @@ -1154,7 +1155,7 @@ int tty_send_xchar(struct tty_struct *tty, u8 ch)
> >               return 0;
> >       }
> >
> > -     if (tty_write_lock(tty, false) < 0)
> > +     if (tty_write_lock(tty, false))
>
> And this one. And more times later.
>
> > --- a/drivers/tty/tty_ldisc.c
> > +++ b/drivers/tty/tty_ldisc.c
> ...
> > +/*
> > + * Note: Capability analysis does not like asymmetric interfaces (above types
> > + * for ref and deref are tty_struct and tty_ldisc respectively -- which are
> > + * dependent, but the compiler cannot figure that out); in this case, work
> > + * around that with this helper which takes an unused @tty argument but tells
> > + * the analysis which lock is released.
> > + */
> > +static inline void __tty_ldisc_deref(struct tty_struct *tty, struct tty_ldisc *ld)
> > +     __releases_shared(&tty->ldisc_sem)
> > +     __capability_unsafe(/* matches released with tty_ldisc_ref() */)
> > +{
> > +     tty_ldisc_deref(ld);
> > +}
>
> You want to invert the __ prefix for these two. tty_ldisc_deref() should
> be kept as the one to be called by everybody.

Ack.

I think in the near term the alias analysis issues + conditional check
of < 0 aren't solvable. Alias analysis being the bigger issue.
Two options:
1. Adding __capability_unsafe to the few functions that you weren't
happy with above.
2. Dropping the whole patch.

I'm inclined to drop the whole patch.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%2B0xWRUmeyQ0hb6k5zHakw%3DKAaQN7VZ%3DyMyz0eyBa4xQ%40mail.gmail.com.

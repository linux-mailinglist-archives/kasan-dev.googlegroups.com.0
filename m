Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXFDV2XQMGQEGL6CBOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DF43876D24
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 23:31:57 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7817253831csf196976485a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Mar 2024 14:31:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709937116; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRcmQBdfT1d+sQWgy5YJtSHOqDBvWlhnEfDBG7mALrFIUAE/sNyyULcY2wDVe5Id9w
         LDgZMqbYwADAlk9yDMT7Z8PNHca+EtEvIFpxHkWxd1+Zh58wsRnXI+PQKrgFchnAjhs/
         wS6zcovqoxIdlzlOqN05cLSXatBkhqyy+Rv3iHVIJbQ1UB5aTVTi0WrfVL8dKL3SXVFE
         OTWvI9SSsSdG8MBOMtTF4k0MkcKuf/xrl3PH1EF/0sgym/vHQa19NGcc2Q1g8puoBNWN
         th6FJIJdn1FU0OfunN00kWaWYpb+D+OIKfCh78IRVMz4utNn/dZUAB017mnlgWrnaug+
         mYdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=9mPyVY7NQLX63a7GpLISTwSatnheVMkiub3LfOyyfUw=;
        fh=awrt3b8fZvpEU5ROnQE0F8pWi7XMTE9wG+N3XUXcyeM=;
        b=UcqZL28lcg3i6FstDJHpMVRGYYLQKK6W0moAUFI12QyrEejNGCu2+pRHQhXc5p65Xh
         mu7XHti0cFBd4EPfEpBhDKbFPX4kJhKmThPMhQ7PGpNiFf/l6mHDnyFBPglzpgqR9xOC
         pLtw0DruRmqlqRVQyd0JIQPL09Kkl5it6/KfZf9Kr0zi3xBx+gOhUzUzEMOzqnOG+gKm
         m6eHGCo4OWY13GC7jRCZ0rybV+CCMECv8IrEMyI4YeO8f0e95lMh6HZPzoocnXgH1Gh5
         15UP6yFpAjunneDIQNX6g9iK7W/78bhJD1BMCJ2yVjZlXQz07UIOILbaRGlEe6CjSv7g
         +1NQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nF6oy0c1;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709937116; x=1710541916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9mPyVY7NQLX63a7GpLISTwSatnheVMkiub3LfOyyfUw=;
        b=puh+Eazfkc8YmvESd+JWp1ucpnHdd3VHSB/nkDAEC7JtyncAfHzmXoKZnwPYPzrPVh
         kHAXmXXWXlsCIuv7qdbXTHTxe5HERv1T+uVMwrCSY4sk+eP7r7k5iP/JuRy9oc5Rlalm
         XaZF8wkmC8Q/EmOYMYKSBHJpFR6er1PAF8VkK6g3Xh4dosS3EzXolfoocIrGj9u8GrH1
         rWKIPOxHxo/rg/GN+TOHm4tVycRYZ2Y7/2Ch8BDkvGWvBF1/EVg/V+SteYDbyh5eV8QI
         qdzwhAyt9zGG6pYpWPj2xASpSol48ehQ1iqkPymCFvQEhRgevZvQu7doOBRRaIlPswvY
         fNtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709937116; x=1710541916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9mPyVY7NQLX63a7GpLISTwSatnheVMkiub3LfOyyfUw=;
        b=R7Uz8jbwkPZ7Lm0dDSVOVINO4zLAUlnY4VlBURP6AIK8ACipsUTSK4lQBMUy1BXREX
         o5P892zO+3eYMxkZwAZNS/TU7KjM91bRnmlnnPv3rSFz/p01XMItc1LJqPoBGR0koot3
         5G6+ow5ut25vZ4II04oijsTUmmBseQx8fQCOdGbGkgAJbWIphtFkTX+PFrcsK8Ynq9QP
         tbFA3nq6/1vJ9dS4pHyuVTU3aieLUJkPyx4qp+IpbAPm0sdUJo5zoYpGSyWM9TjQyosJ
         R4ms4IIav42L6zLHLlugFsSIdm0Lmsez2arWJ+DP6gWW1+huV1e93TI8q+vPvzh+XlgY
         At6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfim+M2coZyY5mM30JNsgtFwGPlYUfPvpX1xJ01+6il+maRbzEvVaqrQuv6l7QkPhDCJTHfS4Ii0RW8A3MfLfVvGczYKvHCw==
X-Gm-Message-State: AOJu0YxsTjBLdTIS8fMM0urlQ1/PLF+BHh0Ovdl6X2I/7WFci4q2c/px
	81BScwMhnxPWn19cXki92emgMVAbaZOUkJE6rWgffpOtHPGj2HAu
X-Google-Smtp-Source: AGHT+IGVxY3Fl1Ojefwz6lNq+5EwVu9HHthvZDrKLFk9lsAHuk/lyazJO69fNCgQV81MaACew4heKg==
X-Received: by 2002:ac8:5c8a:0:b0:42f:205d:dd27 with SMTP id r10-20020ac85c8a000000b0042f205ddd27mr691039qta.45.1709937116196;
        Fri, 08 Mar 2024 14:31:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1211:b0:42e:e99c:976d with SMTP id
 y17-20020a05622a121100b0042ee99c976dls2960504qtx.0.-pod-prod-04-us; Fri, 08
 Mar 2024 14:31:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWshzW8r4nGhrfmxhp5tk6yS5oWQdo8owPpnjcj3JV+sYJPOOmFEhW6e+RpjIRdH2ZzWOD2EZczmEygNLf6AV9rz3hdwaBIDATZQw==
X-Received: by 2002:a67:fe92:0:b0:473:14ae:b411 with SMTP id b18-20020a67fe92000000b0047314aeb411mr401835vsr.19.1709937114643;
        Fri, 08 Mar 2024 14:31:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709937114; cv=none;
        d=google.com; s=arc-20160816;
        b=LoPSc4rlbXxfe4I0CeH7xMecwD9y+XAT1EctOTsmFn1M2UoFFTydCRbugp0+EdaG1Z
         J3RCsKkDMEnvy+QdCd/mGSZZ+XdYcJP5ya88BoQ2OtRorRcPe/bFgtlSAoCPWnc6o8pN
         gxDpFFZt1RJonGNO744lGjnfqwDT3WzlhXU5nLKg1g7UAch+mgYYlDl/jZNhYMJP+dQI
         DgC8Welw0wbSge/bMjiHS0cNMetHfe0vmcg8Ybx1YC/hKH1rgVaHUtGBMy6yiaSIwwBY
         QgxJr58ZjvCTo8UeZdqcqKTP4pGJ5wzTHOxhBHyrO8csuVS/RC4D0zV9aO8pgxMxbgiM
         NBKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=u1QSbXG0YEy9go+kARKd4RwhC/VK2ofODeel/TxdtUU=;
        fh=rQPPKocvcSdU/KZDT5a1aA+odI3+PtCpik6mL0wgMXY=;
        b=dpL89bLvF2doMnj49LvfVDH5Hiq55VXBp5yKT5PUAUV0JbzLywsa0Ad8z5Qnsyy/CO
         zZfm/JYDTDWaye0oXGm4cIHWGfWHwa9/5+OZyEeE4tx6V6Wchr+LXwr4kpwRmqt9/7/y
         FQt4RGIg7LDaj5NnCN0HhNEpWR6Hs+P7Fp6TwaSdltxDN8AQFUeZe0/a7K3VygLMMPf3
         Jnfnht2qYtn+5TpMNvMLcBgR/rM+FvOAjECYGyGQ8MvmdAM/SmDwGX3hKrTmqT3Nbh8X
         //Wh3Xn40/I2CN9toe0OI3y76AR4QpHIb3rixMVuX0jTpiICjiAi/ys6xisnKc4LSmWI
         9ebg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nF6oy0c1;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id f10-20020a0cf3ca000000b0068f6c8ab31asi19372qvm.5.2024.03.08.14.31.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Mar 2024 14:31:54 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2D59F60F95;
	Fri,  8 Mar 2024 22:31:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4128C433C7;
	Fri,  8 Mar 2024 22:31:53 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7C8B8CE0548; Fri,  8 Mar 2024 14:31:53 -0800 (PST)
Date: Fri, 8 Mar 2024 14:31:53 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com,
	glider@google.com
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in
 rcu_trc_cmpxchg_need_qs()
Message-ID: <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nF6oy0c1;       spf=pass
 (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> 
> Because not all architectures support 1-byte cmpxchg?
> What prevents us from implementing it?

Nothing that I know of, but I didn't want to put up with the KCSAN report
in the interim.

> > Therefore, rcu_trc_cmpxchg_need_qs() emulates one using field substitution
> > and a four-byte cmpxchg(), such that the other three bytes are always
> > atomically updated to their old values.  This works, but results in
> > false-positive KCSAN failures because as far as KCSAN knows, this
> > cmpxchg() operation is updating all four bytes.
> >
> > This commit therefore encloses the cmpxchg() in a data_race() and adds
> > a single-byte instrument_atomic_read_write(), thus telling KCSAN exactly
> > what is going on so as to avoid the false positives.
> >
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Marco Elver <elver@google.com>
> >
> > ---
> >
> > Is this really the right way to do this?
> 
> This code has a real data race per definition of data race, right?
> KCSAN instruments the primitive precisely per its real semantics, but
> the desired semantics does not match the real semantics. As such, to
> me the right way would be implementing cmpxchgb().

No argument other than timeframe.  ;-)

Plus I suspect that a straightforward emulation of cmpxchgb() by cmpxchg()
would need to do something similar.

> Otherwise, the workaround below is perfectly adequate.

Thank you very much for checking!

							Thanx, Paul

> > diff --git a/kernel/rcu/tasks.h b/kernel/rcu/tasks.h
> > index d5319bbe8c982..e83adcdb49b5f 100644
> > --- a/kernel/rcu/tasks.h
> > +++ b/kernel/rcu/tasks.h
> > @@ -1460,6 +1460,7 @@ static void rcu_st_need_qs(struct task_struct *t, u8 v)
> >  /*
> >   * Do a cmpxchg() on ->trc_reader_special.b.need_qs, allowing for
> >   * the four-byte operand-size restriction of some platforms.
> > + *
> >   * Returns the old value, which is often ignored.
> >   */
> >  u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
> > @@ -1471,7 +1472,13 @@ u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
> >         if (trs_old.b.need_qs != old)
> >                 return trs_old.b.need_qs;
> >         trs_new.b.need_qs = new;
> > -       ret.s = cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s);
> > +
> > +       // Although cmpxchg() appears to KCSAN to update all four bytes,
> > +       // only the .b.need_qs byte actually changes.
> > +       instrument_atomic_read_write(&t->trc_reader_special.b.need_qs,
> > +                                    sizeof(t->trc_reader_special.b.need_qs));
> > +       ret.s = data_race(cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s));
> > +
> >         return ret.b.need_qs;
> >  }
> >  EXPORT_SYMBOL_GPL(rcu_trc_cmpxchg_need_qs);
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53a68e29-cd33-451e-8cf0-f6576da40ced%40paulmck-laptop.

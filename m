Return-Path: <kasan-dev+bncBCLI747UVAFRBMWKQ6KQMGQE4RQSF3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7248F544B94
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:18:59 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 1-20020a2e1641000000b00255569ac874sf4474652ljw.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:18:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777138; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSZZf9M291amdjaaJfq+FO9mxWlA6C6wnmLOSXM5WWWCKlIyK1ylwZac9BURQwIwac
         0KG6Y8GewsvzTI8bkqa0IJUZico6M1wEvtED5sIb3GYTt4lgsLqq0ZRnoXuulGxaJa/F
         IqDkxJKS1n5WiSqRmAA1zUiAs362JIgDxhM3l/FNk6qHouiHV4oghLWlxgvG6Hcw3Drf
         gOuAvZqHGUFtqZtPXgFbUKL/ebmpXkbuU3o920GC7aLS/kZjiUiHmg8n91JFh1LCf11C
         RLfWcIC7LSo6xnkX2nB52rU3sLVwYswAqnPIfBco1ji0/+KIfmvPtDXtvrDlOmWE9yJi
         B4nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gLiwYDSbak0/9bF8GYmVQwEdaKx+fA7hOnTy2MXIEB4=;
        b=vJHFdU9ATmCMROpcMgbEqME6z07q8d1N19HJHWfWKR/tbPQ0smul3YE1WiTTXnZFEc
         /5t8EWXArDpljT32M9DxiTN+nXJVJA76Z7E6VDuNEYMtSCQ0cszRpDtmlqDhnlybolHL
         qjzkYH4Lsz1qDhOtbjqbOM0+eqf3nrthHfw5yVrJF264ayQDLk0B68k9CX1XX3ToPODV
         KiiejrYgY3A7kC/3g8xGTfDgEZFy4biBqulfPKWGwwNswk1xR2+3ZR054hlpucIICNc2
         p9+a76dNjl9ZR+rXPGHpx7B8MgeEjrtG4eIlKmoFCIqTvUA+MdH/e5AFD/7K9ug4QDDv
         +aqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=nPButqce;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gLiwYDSbak0/9bF8GYmVQwEdaKx+fA7hOnTy2MXIEB4=;
        b=J3vluoPuX1VgMiDcNEjmvcHDj3jjMiFLtJDaikcfCI2yeN5oXuCnWELfgBtfjlOKeW
         HWUxPn74p0ag1QH4OAhFNpCmqDfkDjkZxOz4WgyEHb05WbdZcFHqWH5+n+t6uvmdLn43
         UZSoD+2ZxXhfqHeuN+1puy44l+wC0KjsSrFYHmfwxI1uge6Fg/GO4+O7P/8G+3yti6vR
         q4OyIZ/BvsBV2CBzg0D+qHTx+cCRyAv/gQ158fQ3DNeCMP4R6Kh6zQRiZrI7yilQcWi6
         7QhX6/oYAolr9+Db2VbTpuWzoyBOC80/DPrRZliSlvX0aT+66lrnj2oylHiyY+3187h+
         /YPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gLiwYDSbak0/9bF8GYmVQwEdaKx+fA7hOnTy2MXIEB4=;
        b=NwD15N59vgDkJmif4tonZ16CLdA0RhUtCCALccwpPet8xLAvEaZCUZjtNdFsUAsqxf
         2exdZihxXYsxsbsYmxTdzxYrhSVC8nX45KL081a7Fpy6bKS3okljvOv0hRvumWRHHUed
         77Lgt2CMPlmPHjftyjFwTWnbB1UyVdJYHYqFRqJwuyGhM+raisqz3mLeql0tNGBbPSR1
         CZa0dfms7z7bVzPl/bS+GP4F/19mvGd2sk4y/MsXos4XqpCgDhB99WUHEeT4yAHhbo9C
         fivEH8mllrPn13URIN0xN0oWeia7RDq9goFS7c/Qu8DPzsV19k16qPSjE2bjX13AUwwL
         4xJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331HuniBZ1J5mqAl04AKtbhgskqZPcgSg9NiymCAyESFzM2Bxm+
	geeDbj8jF8n3DhP385HbTLo=
X-Google-Smtp-Source: ABdhPJzDttxf9Ni+fMFzrF8HF/79xaKS6zQ2GlJR6NDINq3j7CHFlDiYKFO0+GRC4AvTBBgmEdafPA==
X-Received: by 2002:a2e:f12:0:b0:250:bf9c:3d2d with SMTP id 18-20020a2e0f12000000b00250bf9c3d2dmr59531915ljp.452.1654777138432;
        Thu, 09 Jun 2022 05:18:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a22:b0:257:42aa:25fe with SMTP id
 by34-20020a05651c1a2200b0025742aa25fels584663ljb.7.gmail; Thu, 09 Jun 2022
 05:18:57 -0700 (PDT)
X-Received: by 2002:a05:651c:ba4:b0:255:94a6:6935 with SMTP id bg36-20020a05651c0ba400b0025594a66935mr12174662ljb.343.1654777137262;
        Thu, 09 Jun 2022 05:18:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777137; cv=none;
        d=google.com; s=arc-20160816;
        b=NLjZN5R7bs6a1qTt27RERMbRTBul7Q8mJJJy1vOZvCNP4aABVelxHT8cC2BRAOiL5h
         XLtH2d6n1+rY1xA3/8QIH/DYz1HfLZYtbGKscgpfsV2mqzymzqDzBYApmxtzGYcOrKLp
         O5/iEFVVHOaLjp6SjaofsWqxZTd2xky7DnHc/xcKeY4kbkDsADsRs1NqwCvcbN1IYx/Z
         j0bX1FKMhtbr+YhL0RTtcZSstERcO3Dp9JvMjTK9rOnaCfZjrrAtfU+TYSGIps4BXtbT
         QqFGqzhhx/JG9IcgTOy/CyaJSJZYpagZrujigHRFk/Aid9JNidfk1APBbL51n92NcSv2
         PMVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QcC0C5Avs6rzR+CXyutM5LVS60s9Gr59fufuQSrdYzU=;
        b=hFrsSSiYoubR6cVduXnNC9Qc+2BIpMriG5lu9HkyYe9ocdnprzxZeC+hIi6wuH408J
         rZ48b5/ol9OpOUDj5tTQmCgs5GwRToJppN9IrIZe4UV3smOoKQLjI0U0bKWucTtPyADc
         hIBdjcdyKa86koUDOpIF8/NrxJ9Sjcb7fe8Saf7dqt14MZWcMfmKu4DZBEFVQtJv1Hx1
         jIQtC7cksu7VX+srcF0vnY5Up9BE/wt6snvVY/4K+GbeXrnTTS7+K5yYFEB+VcllF2Rn
         ecSf3Cu0/jtrTrkJr3OwA3hVwIwi0z4jjeJiQ78BSbn7zXjj7VpjLXQyIYG3qQQvbJm3
         mRgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=nPButqce;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v9-20020a2ea609000000b0025594e68748si553937ljp.4.2022.06.09.05.18.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:18:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id F136EB82D3F;
	Thu,  9 Jun 2022 12:18:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 74CBFC34114;
	Thu,  9 Jun 2022 12:18:53 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id de5c4ac3 (TLSv1.3:AEAD-AES256-GCM-SHA384:256:NO);
	Thu, 9 Jun 2022 12:18:51 +0000 (UTC)
Date: Thu, 9 Jun 2022 14:18:44 +0200
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
To: John Ogness <john.ogness@linutronix.de>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>,
	Theodore Ts'o <tytso@mit.edu>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for
 per-console locking
Message-ID: <YqHlJDh1MSYJWBnu@zx2c4.com>
References: <Ymjy3rHRenba7r7R@alley>
 <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de>
 <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de>
 <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de>
 <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de>
 <YqHgdECTYFNJgdGc@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YqHgdECTYFNJgdGc@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=nPButqce;       spf=pass
 (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
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

Hey again,

On Thu, Jun 09, 2022 at 01:58:44PM +0200, Jason A. Donenfeld wrote:
> Hi John,
> 
> On Thu, Jun 09, 2022 at 01:25:15PM +0206, John Ogness wrote:
> > (Added RANDOM NUMBER DRIVER and KFENCE people.)
> 
> Thanks.
> 
> > I am guessing you have CONFIG_PROVE_RAW_LOCK_NESTING enabled?
> > 
> > We are seeing a spinlock (base_crng.lock) taken while holding a
> > raw_spinlock (meta->lock).
> > 
> > kfence_guarded_alloc()
> >   raw_spin_trylock_irqsave(&meta->lock, flags)
> >     prandom_u32_max()
> >       prandom_u32()
> >         get_random_u32()
> >           get_random_bytes()
> >             _get_random_bytes()
> >               crng_make_state()
> >                 spin_lock_irqsave(&base_crng.lock, flags);
> > 
> > I expect it is allowed to create kthreads via kthread_run() in
> > early_initcalls.
> 
> AFAIK, CONFIG_PROVE_RAW_LOCK_NESTING is useful for teasing out cases
> where RT's raw spinlocks will nest wrong with RT's sleeping spinlocks.
> But nobody who wants an RT kernel will be using KFENCE. So this seems
> like a non-issue? Maybe just add a `depends on !KFENCE` to
> PROVE_RAW_LOCK_NESTING?

On second thought, the fix is trivial:
https://lore.kernel.org/lkml/20220609121709.12939-1-Jason@zx2c4.com/

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHlJDh1MSYJWBnu%40zx2c4.com.

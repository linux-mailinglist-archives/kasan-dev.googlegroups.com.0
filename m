Return-Path: <kasan-dev+bncBCV5TUXXRUIBBVMX7PUQKGQEBUEKW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 99935789AA
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 12:35:03 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id n199sf23072483oig.6
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 03:35:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564396502; cv=pass;
        d=google.com; s=arc-20160816;
        b=Njm5yLFdy5v0ZykxnvlOmFRxKuxKbSuxzwIsM+lScqrXhUyV8EdbzBJXuvTVssCdfG
         FpmtZCWHSDwFwJESLvZuUzyqODhSG+R3Q4ss/S5rBP+mvyWNaNZRDPj8dJ5zHx/yvMwh
         tubD2SoHDDTcz+0NyyQrmrO/BohKuL/pcDfPfXnSFZ597w3SX/f8/uz77tjWMZ20Oyo2
         ROPThzw8yX3qHXrJfg0zMpUCQS9Xipn3IzaxDqDPUXMF5cxRb6CU6B6QWEmnT1p6GNT8
         wyE5GY8IDVLLhPx2R/XVushL9xf7S+QVwe3UmwTxGrlWlvR+/C5qI7TGPPlDHe7EopLX
         BUlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wlTADx92x73dZwDnxnAVeJn7AybTonIPykuf2ksjGqQ=;
        b=XMjGjE2RUDiRbr/O9NLRjqiNCtgr4wVcDEXTiB1cVCGNDeyYhK6draSEsUG3g7kcQm
         zswZkIXJxdia1g7axj3a1z8sM7gGwrUGEOfgJ1MeBHkbGAJS2L4A+GCWhNuRGcxZO4GM
         NCESnZIOvKeGXbyFJoF/HWfdCM8+/aYvWD2dgk4ze+vcHhVw84HTNpn2DxIM/aA+Nj4t
         FqdTRBXac5eOaBVYoWQBzwknAkEKHvOn2rpwjnCK7YucpJDDIlvFxdsYf+DzHpKQvvaG
         Jyr1v4gqJZWXxwWG8KmYz8fV4mQX3RPBijYJq+Yf6LBd/8kVcf3ii56kbvDj3ZIvbvMG
         /PPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Ij+8aVx1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wlTADx92x73dZwDnxnAVeJn7AybTonIPykuf2ksjGqQ=;
        b=m18CyynJWrQN4dTEPSlVs0ee9KqmwRpCwZYPTkscm9YJ+0DwztUECua3EZ6CxKv1vA
         F/fg/e+5rsWtXokBcj/8PmhYpvQf8B8e73jWgZFcZbWQexq6XYwQpUmcscu07ZZmJ483
         g2PljDpNGioqwB+/Fi2VWHfXWisPO7M5fcXz5xd2DdTMT6kIzvc/o89xJfcv/ftgr9wx
         BVefmbmhu2+JCsouIADN4KA43Orwba16QkdYvgx3SYBEuevnaofsEWqfCnbLv8eTN/He
         l1vt3YXZs1qD8jupYtl2cUdOB/sqF0agbsqqGeeNtXHMXXnkQJVznEcZEx5i/T0t51fE
         YzgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wlTADx92x73dZwDnxnAVeJn7AybTonIPykuf2ksjGqQ=;
        b=Xb2uSNW4h1eNX31n65Q+MtG1sTr5m+QEZohX4gKX0SEMJl4amKX61L7Es1ryV7Kg9H
         tkY2aTeIzzogSBJQ+jfACQU1DQNV7HQ9CEfYdLiJGSsBEystQHQJaxrOFeEpEcr5re0v
         u5YoEGJGVzNBhfxVh4yHoguwb/l/eb6YuOahoT+DCvas9VISNSwQ/oNvauiL3uu/gEVS
         ojztiLR1QwLT6+YHbl+wsmCiLHmBaCpvrnDchoIzLTZiC6fRFB3PPu3wXbXFu5atPFT+
         T+nb+YHSA78/+i+jxV6zu/a0dQBPfURX1lJQJ/0ied8790pEZdD5xW2qxxdQRzLABllM
         /7Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVqueZKgZZdpO541bKoIzdeX7BiES71r6hOkr7XLQr4QJFmjIJ
	9Crq42WHv04tPPnwKF0m6F8=
X-Google-Smtp-Source: APXvYqxaR9uhSJymGxtX4kUCgovBiNCPP5GCe0fNA6rNcVnouuVfQPxSRV35o+yC4H0Z+B1ikKVODQ==
X-Received: by 2002:a9d:66d0:: with SMTP id t16mr86260226otm.153.1564396501997;
        Mon, 29 Jul 2019 03:35:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d7:: with SMTP id b23ls11633413otk.14.gmail; Mon, 29
 Jul 2019 03:35:01 -0700 (PDT)
X-Received: by 2002:a9d:4546:: with SMTP id p6mr15673318oti.34.1564396501674;
        Mon, 29 Jul 2019 03:35:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564396501; cv=none;
        d=google.com; s=arc-20160816;
        b=FgKno8kidfvKTMw/nAO1JZE/zj/QeEqImxss94OrYmjEmK0+WZx5tSrBECCHWUmmDj
         vcE4G+lvkoABgTpAaWWGzCi5aD+xNcdn4kis71VP5XTFa2CDMmsE5hUMvMC3ekP0hqHm
         32sbbLW0hhbpphMJe4/qr9gxkhjW+Y1LwsLyGxbegru0ejDxKiUL0TF+IjMb80iUw4zI
         fk4cpO/4NzIlemBM974ijj7eYixWr9E7s5iL+LRskiAJ/mJEKA8Q7lJw3GsvItm3gMti
         dQuw+uDi9Mvb0M+ovYHIaYKMKEpFpygE5ifhmd5+M+fIPYrgZJQbEknVL4teibwPjySR
         d7bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OLcOQ/n8nsV1J24avjiNzRxgd0bDdez3laTxyYU6tyw=;
        b=UIdVzBlvSCuoQn0rrhwPiRrvLCTcwp4GI7wCpZBH1eu0w7Cb7QIN3Cp8Swc+qLgTyS
         zQ+JXUOhCA3JoHVCkB98AGxVucfkaAtOAFmqHeoGGZa0s2tZAYfm5UfCPBZWd0wg6iCU
         3fjO0Vdj6cTyYTxnCXo9NpJMG1OTIVl3Tq+ovjtbxzoCqKT4DXlsSYo47wF1r4zvEPar
         HCauU02mLMBtXZYYHk203/Yhxgoz0naRpfQ0gydAIP9EGs5e5XtAHQNiZgBJ+Ii8nKMS
         fiRZpBvrMgQnUNpzZvITZ/Hv+z5884gRFmWJA3H1TIkKjtsjXg79Kli3xbM8wlc3rGnw
         wXgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Ij+8aVx1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id y188si2931470oig.3.2019.07.29.03.35.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 29 Jul 2019 03:35:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92 #3 (Red Hat Linux))
	id 1hs2zb-0001V0-Ob; Mon, 29 Jul 2019 10:34:59 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2AABE20AF2C34; Mon, 29 Jul 2019 12:34:58 +0200 (CEST)
Date: Mon, 29 Jul 2019 12:34:58 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Andy Lutomirski <luto@kernel.org>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>,
	X86 ML <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
Subject: Re: [PATCH] x86: panic when a kernel stack overflow is detected
Message-ID: <20190729103458.GZ31381@hirez.programming.kicks-ass.net>
References: <20190729015933.18049-1-dja@axtens.net>
 <CALCETrX_+_zT8iKp9QMpaN0+NPS9_rmhZvPgG=ejN-5KkBbfdQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALCETrX_+_zT8iKp9QMpaN0+NPS9_rmhZvPgG=ejN-5KkBbfdQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Ij+8aVx1;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sun, Jul 28, 2019 at 08:53:58PM -0700, Andy Lutomirski wrote:
> On Sun, Jul 28, 2019 at 6:59 PM Daniel Axtens <dja@axtens.net> wrote:
> >
> > Currently, when a kernel stack overflow is detected via VMAP_STACK,
> > the task is killed with die().
> >
> > This isn't safe, because we don't know how that process has affected
> > kernel state. In particular, we don't know what locks have been taken.
> > For example, we can hit a case with lkdtm where a thread takes a
> > stack overflow in printk() after taking the logbuf_lock. In that case,
> > we deadlock when the kernel next does a printk.
> >
> > Do not attempt to kill the process when a kernel stack overflow is
> > detected. The system state is unknown, the only safe thing to do is
> > panic(). (panic() also prints without taking locks so a useful debug
> > splat is printed even when logbuf_lock is held.)
> 
> The thing I don't like about this is that it reduces the chance that
> we successfully log anything to disk.
> 
> PeterZ, do you have any useful input here?  I wonder if we could do
> something like printk_oh_crap() that is just printk() except that it
> panics if it fails to return after a few seconds.

People are already had at work rewriting printk. The current thing is
unfixable.  Then again, I don't know if there's any sane options aside
of early serial.

Still, mucking with printk won't help you at all if the task is holding
some other/filesystem lock required to do that writeback.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729103458.GZ31381%40hirez.programming.kicks-ass.net.

Return-Path: <kasan-dev+bncBCMIZB7QWENRBTGQQ6KQMGQENFKGJYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 97A99544C0A
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:32:13 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id c187-20020a1c35c4000000b003970013833asf8210955wma.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:32:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777933; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkKvZbV0cdXhr+I4qsDzaZruj2f6B6WC152w8m7eD/+PoQR+qnhv+1eXZMCYj6Af1x
         KBcmGHkL/WrrKAw9uVMI9CYkNdTOR3VbGfbg+bSb3HBf7MSpX8r6K26/ko727fxZLAIQ
         8gSHYx3sbg47MlCSRuebCrOBMvgTiQL/NByBUeBiXDk4fkOa8U3PXm1+nkYrZB3PaVw8
         ww7T9madsm/Sy0uneo6PsQDq2xYrIRAdaGvJ18RYM097lfFKQWsxS/zUn/8Gc0xTIPn7
         JQMWJ1qKPufjbagOFvxuoxjOB5bghNIOqnHQ09+77ufjltNUq4K39YHJLlH4hkXDrcYd
         OCcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IyAlk8/AGolagYnb0SLxQXXOdJOXwFeIygK5nULONIo=;
        b=CjgWQ5wD3OUXtAJene1jt/B0Mx9XkhOl/QcdATKSqVqLTcpHpGMURtzzrvkoWvIUTI
         jX7CEvjH6ytKoeaM3mP1MD1cDBY2GfHP3yu1zTsvpsn2D+BzQhPnPlGcrjvfgBgque83
         BRROMdznozvHgsGHMQerScm7HSEQNjXZdYMY8IZKb0KdO0CXzWvPBZZvAuH4bjNNePHa
         1LZl8tL+Zsom49C+/aIcgX05kX4jobyTcMX0YYjg+wXEIBKVVQ0kUzziceoa2Rf+I4PX
         a4J7b1R+8QV0LElkTE771XdkgxT+RFpItCaJ7BZPp6gRz19C21aynG1Lyo0TckykYeOX
         UByA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZuexHRJp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IyAlk8/AGolagYnb0SLxQXXOdJOXwFeIygK5nULONIo=;
        b=egAOZZucGtq1uVafO6I1bsxtqnaKxH5IumzvKCVyzoo8yoNELLrUPcouBXeGhwkeIr
         f71RBG6GylBNIFKEY96vpnpuodHlejn38Vj5Zbmovv/npPlOe7EwzgedA6wqXKiIMWKl
         3OAuNOKB3AYhF5izUcSLe6bxx8prTLEANPVebFFl2vx6OH6R/6NBVkvM/TSCkn9yYZw4
         1WOqQ01Qtaox47I6Pb60+BxNW+eA6CjDtlUq7xUejCmaW5cxLwazIPItvaYBqFNlThx2
         oLWguTAPfHdX+gWcfyc+8iz/csL5n5vlKyO88qew6HqOa2W5gPko7QHvjtYTQUEBXHsJ
         YDyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IyAlk8/AGolagYnb0SLxQXXOdJOXwFeIygK5nULONIo=;
        b=I7g7fr0WbecidzhA4tG0vzA/reKOzqqZjNRbbuV/cPvq8v+VMCBuakADSqQ0IGYlir
         LwnLjDSGen3CjfCAlKPETsnPKNLVEoxqTyiJgebYZBiIjrkadPoJahJ8bXc7x7Ps+p7q
         gDYFO6UCsYOVvr0GGzqNMFc9i7LtWHbEu4lE9f4pOflKT36OwWxysSpdoWFtWhmLR4fS
         cyjg+72ca4GONsfaCDuA6XYEK0FquZEe3tj7VZ+TAeGFQRPoZloYp/mfPz1WWVQmcxOD
         8d0R2HszGfJnc0HJFh6fVBR8Viwkow6/ghJAdhNhq5rIBgQq8lBYSzx18AtRPYVcLd6S
         ZtCw==
X-Gm-Message-State: AOAM5316zN1IyjxQLYbmm5rMM4JCk+P1PBUoBkSL2tdTt3skK8Mvz6Un
	61hYVGiFGqEqxuq1tbjYyyg=
X-Google-Smtp-Source: ABdhPJxTNRsw3LtyvnDiDFU2iIoaZ/oN5xdCHN8yQl+nyiMDHTuyMAWZOZ8uQQS6Vxggtr/lSKEwNQ==
X-Received: by 2002:adf:f08e:0:b0:213:b7f7:58ff with SMTP id n14-20020adff08e000000b00213b7f758ffmr34258547wro.123.1654777932991;
        Thu, 09 Jun 2022 05:32:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3586:b0:39c:5b32:cf40 with SMTP id
 p6-20020a05600c358600b0039c5b32cf40ls811623wmq.2.canary-gmail; Thu, 09 Jun
 2022 05:32:12 -0700 (PDT)
X-Received: by 2002:a05:600c:228e:b0:39c:47a8:a870 with SMTP id 14-20020a05600c228e00b0039c47a8a870mr3146716wmf.136.1654777932022;
        Thu, 09 Jun 2022 05:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777932; cv=none;
        d=google.com; s=arc-20160816;
        b=bqRCVJBiTuxJ05MVGx0GXKC4fDu/LFrQ49ECRFv0mqOsve4LVyhtSWEnekwxKKDxxW
         THOpuB75f+kNzAP+MsN4GFv3zRj1kpKLRJim45crcAogJsB/Q8YVzAH1CMWIktT0lphj
         FIilHtNZcMpUTnz/Um3RFgqjQFW6LbIj7hMMON4m7IIc8OQaXECfftc9f9kJr1TTEeHT
         jCY1wZ5j6U5fgzQ9DuQKjORmO16x4mcoVyL9S6nn7Qo8WstbibIn6vNB2BDpr4+9FQho
         Oiqlt+PDJsqZPuMsCq/9HcSZtTljMK5lggIlkDpnivteMA6JBOXn+Cmyu5i5fD1eZHdW
         Ty4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SfBdadjjVbuYsWcHjyT2JNkeKnRXZofpQUc3M0v3lw8=;
        b=pGtG1EaHzCti1uXo9EtflE6SFHZY+EZOKs+vISpjpzjweg/Xnc5xedEdjV2BfmzYU7
         eTEpoaebVU6A/wN80V9GLDcspLu/eJTIHdxCvwEztOz3udeu6M+7xRMyMuFzWNCUiDgA
         IL56yQowiwulwtCLB2kl7twoRpx+Xju6X4zFH3XtilUPAqAUDctZXJrqqAEcDjy4PMGc
         D18DrjzbPeJ2nR5/Jb5olacidFmkJz+SZqHbotGP2TgVKh0QIm2dlnLyddjwNgiETWcw
         y0me0OcpVQf7o4uyalMRwgGTaG2DWLdViBpd+JtD2ZN8NHjnxYhhOXkiMRmjI7WIIbbn
         gxeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZuexHRJp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id c18-20020a05600c0a5200b00394803e5756si1037210wmq.0.2022.06.09.05.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id t25so37716430lfg.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:32:11 -0700 (PDT)
X-Received: by 2002:a05:6512:1588:b0:477:a556:4ab2 with SMTP id
 bp8-20020a056512158800b00477a5564ab2mr24638097lfb.376.1654777931483; Thu, 09
 Jun 2022 05:32:11 -0700 (PDT)
MIME-Version: 1.0
References: <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de> <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de> <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de> <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de> <YqHgdECTYFNJgdGc@zx2c4.com>
 <CACT4Y+ajfVUkqAjAin73ftqAz=HmLX=p=S=HRV1qe-8_y36J+A@mail.gmail.com> <YqHnH+Yc4TCOXa9X@zx2c4.com>
In-Reply-To: <YqHnH+Yc4TCOXa9X@zx2c4.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:32:00 +0200
Message-ID: <CACT4Y+Zf8=DgaAYfFWL==vbYF13omtMUGaP=LzKEbsuVzrTe9w@mail.gmail.com>
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for per-console locking
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: John Ogness <john.ogness@linutronix.de>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Petr Mladek <pmladek@suse.com>, 
	Sergey Senozhatsky <senozhatsky@chromium.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>, "Theodore Ts'o" <tytso@mit.edu>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZuexHRJp;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 9 Jun 2022 at 14:27, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> Hi Dmitry,
>
> On Thu, Jun 09, 2022 at 02:18:19PM +0200, Dmitry Vyukov wrote:
> > > AFAIK, CONFIG_PROVE_RAW_LOCK_NESTING is useful for teasing out cases
> > > where RT's raw spinlocks will nest wrong with RT's sleeping spinlocks.
> > > But nobody who wants an RT kernel will be using KFENCE. So this seems
> > > like a non-issue? Maybe just add a `depends on !KFENCE` to
> > > PROVE_RAW_LOCK_NESTING?
> >
> > Don't know if there are other good solutions (of similar simplicity).
>
> Fortunately, I found one that solves things without needing to
> compromise on anything:
> https://lore.kernel.org/lkml/20220609121709.12939-1-Jason@zx2c4.com/

Cool! Thanks!

> > Btw, should this new CONFIG_PROVE_RAW_LOCK_NESTING be generally
> > enabled on testing systems? We don't have it enabled on syzbot.
>
> Last time I spoke with RT people about this, the goal was eventually to
> *always* enable it when lock proving is enabled, but there are too many
> bugs and cases now to do that, so it's an opt-in. I might be
> misremembering, though, so CC'ing Sebastian in case he wants to chime
> in.

OK, we will wait then.
Little point in doubling the number of reports for known issues.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZf8%3DDgaAYfFWL%3D%3DvbYF13omtMUGaP%3DLzKEbsuVzrTe9w%40mail.gmail.com.

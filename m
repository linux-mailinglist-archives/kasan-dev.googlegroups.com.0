Return-Path: <kasan-dev+bncBDGIV3UHVAGBBKHCWKKQMGQERVB5IIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D3E154FB82
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 18:51:53 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id bu33-20020a05651216a100b0047f598077c1sf132657lfb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 09:51:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655484713; cv=pass;
        d=google.com; s=arc-20160816;
        b=MCtSbpBOoCK3xs7kFxqcXdViV2viu7ssK0mCVa41FvmeSnhSkrsKT5q+xDn45hMjAh
         izFWQLXk25xBu9eJRLB0Vg5vMmBpJfomplnTTiffwZnmc13xO9SPd5HuzHLq0UuZ74Aa
         lJ2Aa2qGcV08pagZlmulMb/QxlqfggfCJvNROnpSVsSe04MRFKU4apRY3v7xyBzo78Ea
         t9hox8GYrKG+xzNySLrctmKRIHqIVN2mFr5d04bLrULuTIq9VS3P84H+k/vrMMGJg7Op
         X9/VxmyerpQ8YwK4pyRVM42KRLbtQNGv2nH84/kRHdFrqhbMVB5GM62YNeY4vl/Q+nTP
         gMYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RpoMmXqiS3m9C14vXW7CyI/GxXiObupBzzWvnXuqJ0E=;
        b=MAab4w5Bp24hZtROsMx4t//i8RbJF3pGQptDWm5vq0L7LUis7ZKUx3HLRWrcxBvMIE
         gUn/TC7uSNmug0RT4gOmE38NtKp3M+8ssRMfTMIUiQW7s6hKdELki9D3nbLo6QTfePM/
         0jyJTUPznDUC3Z9MyH72/4+z+kI/MYWvA/v/QPM0PJgj+gcsBgZd3rST2RhLysBK5R13
         ASn9ZcIlYqDdCv3vfx3W4GPFOObvL2b00h1jUF67q8QdXQJdBIos71Aa2A0RaE6SrJ0+
         BbDQyf19/KkusFho7n/EntWvl2DuKIttd5smvSxc+oi0HlfzBNgdyRXpP88I7KhmhCYG
         x16w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="eUu/qClC";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RpoMmXqiS3m9C14vXW7CyI/GxXiObupBzzWvnXuqJ0E=;
        b=c7I3XUgxim0ndc/5juesz0oNUQSWNbBwnWwBCs46JqYHHq/KPG0c5GAxb2WbxeT3h2
         zudHBYuEN4mqOe3OvOKdwynMY0zQhv1YZ3ySM8o8GaC+FGND/tAxEYPA0vqzlTAjlxoj
         6/uhCtXuzxoiSQEEWFBkxqKjwQfa/KCwshBfq8ZzYG1H/mM859Z4jG0ksWwRwINRSLer
         hwcZsOKIW4Pwp/riTR8YKv6lxL+/yJOC5nZrpFoZdGZdidOiWb5v6ehDcAJEfNkojqgM
         64elhBJ1H+7QD24ROmyOWoNTF/5pOigBwQC9mqnOhDVgF+YF2eWTFMJHzJh+Xz0ozfVj
         9HUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RpoMmXqiS3m9C14vXW7CyI/GxXiObupBzzWvnXuqJ0E=;
        b=Msnn0QrGsE/TiW1rG/jExG+6i9HNzbiILgldT1N1zHgfC1lPmWvyWi1kjF+/3Ys4sA
         LbSi9Nf2XhZk/bvMChVPc9/bNhKAt+b/o9uFy2F93kwxgzrpje3S84QaUDyWulAU6cC9
         L3G5jvextpVkOneUp6D1qDydK/UGvi1MdSC/hONIiehsG1wQOAk/780Zyti2+EJVCd/Y
         6bL5ORMeE3bvJZ0LLv14vcgt1AfXX3KjgpVwgw6qAbaJUuvjPN1gZfohgHtJbrT27qU7
         Sqker8YF9yj9BW0BxnX0vOmTiaQphLHGttkPDcd9XsE6fQCv0Hc3ciAKtvGaigthciu7
         QNMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/FDGbSunqa/3NnOyZyCKC+SPtnwLHCIiU9+fv6TZ6zfX4nH/2U
	ClYML48mMIPVmimmSca2Kjo=
X-Google-Smtp-Source: AGRyM1tIrE2T4mRxDpQ1gnQM0UxgA0xj3AkpgRxOM92siqaIcPXWE62BWe7pEpwz7o39EPn43EhJqg==
X-Received: by 2002:a05:6512:239c:b0:478:efa9:9533 with SMTP id c28-20020a056512239c00b00478efa99533mr6202463lfv.661.1655484712720;
        Fri, 17 Jun 2022 09:51:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als374478lfa.2.gmail; Fri, 17 Jun 2022
 09:51:51 -0700 (PDT)
X-Received: by 2002:ac2:4e04:0:b0:479:6916:4f1f with SMTP id e4-20020ac24e04000000b0047969164f1fmr6256409lfr.366.1655484711531;
        Fri, 17 Jun 2022 09:51:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655484711; cv=none;
        d=google.com; s=arc-20160816;
        b=sflzGq1DMGTpdjryWZX+QjbLfxpU/YGdCI1OXoqlHqqtmbJVYCtRFBNaKLbe1Zu+8b
         cIfqS3j4OAU4BvHyGkJTr5DV9Y3vjysMzYVGcRGr6LJhdOA8d0lqeh2pNfo3yGx8YDGw
         OF8jscCMfoYdFgTH3Pjra7IdGaPzheZZdXJ3uPry8wq0DoCKV1sT3po5lGFp3T8TivCY
         JIh/7Xf++ZDUjfdqiYm1wfx8g3oBK7OEp6dRkgOh4ro7R44aGLizR9J8oyENwahC5/ol
         GVGjMiH+raSGJNHOhFBhGzSExN3rhaEdTL4k5LnDLhhHDh/tvfHNkt2JNhUkw1zppzSu
         ig8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=UykvkKuHPgfnuKIJnIaYfKgo9S8iB+wmFcj7vk45wVs=;
        b=y7Sk1uhDF4jwdyRrPtuo7xwau3N9i0332CffncADlzAOOdIQqJLhl6xkVB065OedfZ
         W1rsBDPsqfV8SntsTqq1cAC7RAmOs0YV69atXNOmLx0TBIz2+s7wSWinUPZ6uyJifPHv
         IzXtMwPzDR+bJRge5aWypo+btrD8tAD8i3yBBqgBbssZSaVoE6FPUJ2RV7tIgWxrR0mv
         miWY35GCFLyvyDbAK1v12p0fF20sKb+qw8gdEtD94QRJfoc2VLg7yIZjzJulgjlLm2ZV
         Hz902+Ly6H8kkQMCkvftlPgc8N4pRzCPEwsFlzaVusDvByWSJlDOp7B5y5wwugPdQeXN
         5xbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="eUu/qClC";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id v24-20020a056512349800b004793442a7f0si223758lfr.6.2022.06.17.09.51.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jun 2022 09:51:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 17 Jun 2022 18:51:48 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
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
Message-ID: <YqyxJJ8Jrr4zEPmM@linutronix.de>
References: <87fslyv6y3.fsf@jogness.linutronix.de>
 <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de>
 <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de>
 <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de>
 <YqHgdECTYFNJgdGc@zx2c4.com>
 <CACT4Y+ajfVUkqAjAin73ftqAz=HmLX=p=S=HRV1qe-8_y36J+A@mail.gmail.com>
 <YqHnH+Yc4TCOXa9X@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YqHnH+Yc4TCOXa9X@zx2c4.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="eUu/qClC";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2022-06-09 14:27:11 [+0200], Jason A. Donenfeld wrote:
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
> 
> > Btw, should this new CONFIG_PROVE_RAW_LOCK_NESTING be generally
> > enabled on testing systems? We don't have it enabled on syzbot.
> 
> Last time I spoke with RT people about this, the goal was eventually to
> *always* enable it when lock proving is enabled, but there are too many
> bugs and cases now to do that, so it's an opt-in. I might be
> misremembering, though, so CC'ing Sebastian in case he wants to chime
> in.

That is basically still the case. If CONFIG_PROVE_RAW_LOCK_NESTING yells
then there will be yelling on PREEMPT_RT, too. We would like to get
things fixed ;)

Without going through this thread, John is looking at printk and printk
triggers a few of those. That is one of reasons why this is not enabled
by default.

> Jason

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqyxJJ8Jrr4zEPmM%40linutronix.de.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF7L373AKGQELVWA3TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id D79021ED687
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 21:10:16 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id q1sf2104153oos.17
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 12:10:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591211415; cv=pass;
        d=google.com; s=arc-20160816;
        b=mcJmzpLu8+/0EBS1DV7eSjPu2lfWxifB84SBQlP+3Ysa+sqCjKwHymiBzxJClUvmWT
         jXU0HvA0tUZVn+3P1/sCdI+p4IVhGlViU2fcWbflgGuXffIVXGJ823qpCIcg7nY1y0Ut
         4UBCIm5PJeiPPiOeIojKhyMvJkLMltl1ipXxKJikzRCOeCumH5GZluYq+miJZ2gWgQ2e
         c1sH+fF7HBj+iDMy+8aGGPqSKStciu3K29wAcBM3Rgd2uoY0Zn1c9UmMkyeaUbGWqCNM
         eQdFWNr6jQJm/RyNfsDSS42Lv+B0GnM1rzrTxBaUnLfpZR7RhWdpYl8XfQH7UW3sZetd
         f5gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+Xvih3qYhjRWPgrAQWuRoTy1/mYbB8v3ZBma/O42Om8=;
        b=h+zJB3RbtM7gAOc1iclTeLDHOmEfRk/zGNPhEU3pVOQcmcZzZBXWbOdBaY8QDSj8rq
         cKwMTeD+EBYlJZR9EPOpCkHGP7trwnJqLt6MNTmJIRuw04GZLcIwEoKmmU/BvQR7jSBa
         FlLWs/d7JvGMfvH5VZ4r0GvoS+vpxxn1ipp/xXsSF7ddHgUDYU/p3yoLIsFpa/sIY2T9
         6aCTFyrYwDptKO6dudGVY0ncNBVRbSK6annzlqn5ybqGBWaFXfmc8c5qD6R+LIqz6r/M
         d2wueKC1e9VQg/H+AdFj+Ncql4HTPhGKDF1ZhDnjNAsp1F6+9sMs75NYTVsmk8QO7UfI
         TKng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=egSBgEUc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Xvih3qYhjRWPgrAQWuRoTy1/mYbB8v3ZBma/O42Om8=;
        b=MRsFFYlnZXjcdZW6Ygv8EMghODbRFjCvlDCkO2824yerzKUvqu5GuBEUOL5ClV35dy
         4K27TsBI8d+tmciYc9kG+Fa8F+4q4u9tJJuULMoTcZlOBd2LanrC8/J0w5eadHz2kIoS
         xEoFEPp7muwmiySj1qXGfv9IxZkHr/6M3TVCXCHhIw08SEvWp79amVaT8T3Ydb4kKFCi
         7zQlh51Q9bwqA7f6Nl+PoDE0H5TttGtBeVii9UcVnsVpPWvGErzxWchdWli1T32nit7n
         MUxMUOnu7ofYuJjmr9dWS2c4gjuIhld50VDUG0ItL5Umw5tmafJE/2fV6ezduMFTnVj3
         CEIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Xvih3qYhjRWPgrAQWuRoTy1/mYbB8v3ZBma/O42Om8=;
        b=sBqxxGrcj/OqxGP8x/7l8MnqR59BUqUmyi9H1LO8xBfiVR1oPF6+FyWitXlAyCyVSU
         INo5oVZcqVtQotUv9uRMRBtW8N1dVc7/fgawLCv0uh8w+eheGBiU1mobyfiimIbgLYfA
         wgX1rkMv/4PmdnxkzkLud7d5EUxj7pA/r2924l9iJdAfQqw5gSPHMWJy6g+4DbXUvQ+E
         Vj7+N42oX1mOv0ScSbHdis6KmbpdyfT30k3apzlbCvBHkFSSw5+JgZL64uc+C4YmcpRV
         OHJbk6oIfkINh8ZtlrDnZBX9dST4+lmPn50RRAfy/tIRi+DPdnBoC+LmXrqKI+SFR3Tr
         twhw==
X-Gm-Message-State: AOAM532n1uHMZbKtQfCyZ1/1hRThUwKatHhdt23FjWiJRqVcQo2Qd/34
	2TDe+dTNK+rCvzhIlCd8x9o=
X-Google-Smtp-Source: ABdhPJxE9jbmkGZUJ0YPdWjPbbwFi/on1AL8YECVcfdi9AgwxEW6ksSIET44RaHOe3VYcYEUhwaFNg==
X-Received: by 2002:aca:d493:: with SMTP id l141mr902624oig.20.1591211415649;
        Wed, 03 Jun 2020 12:10:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:11ce:: with SMTP id v14ls830746otq.0.gmail; Wed, 03
 Jun 2020 12:10:15 -0700 (PDT)
X-Received: by 2002:a9d:203:: with SMTP id 3mr1146773otb.248.1591211415255;
        Wed, 03 Jun 2020 12:10:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591211415; cv=none;
        d=google.com; s=arc-20160816;
        b=JDDmHv3HsYEL6qdzT+eQ0Kt6nrL/oF1gjlPNALKgk9fPGvq1Z6DJ4WxeFdOvF3Xh9O
         9xSVp9zNisVFE1t8FQUdCw2etIn7m4M2W5oCuo82i5ooKTiD9hfrhz2JjCQJuB/hZVtl
         QuRhYwxKQUHPFWUNviEag7dUhHiHZ5SDbGqCL7wYOEE/i1a/LrMDm/AAzFm4jYE5MSZv
         r5LPHj9Ja7Cfv2FTUYfqbUsAhooI7zFbV/5maZluXZSWUIZWHHwfTg+xdbAvAbgMhDgm
         I5AU3mfQijJwkcfWDg+JCQAIVWDPc4gIrlkI38pfU7zXIK6f+28boZ3/E3rvyhDPAIf6
         Mw2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=67IcpGYjCT+FsM7zbHjM+OI8M/GSYi0Apdlq92IAtKw=;
        b=AziI+tIluQqe3NFH5lHunBny4CwmfFyxxenWEwCwna+x2VPV1vSsy2BtqZLuVEx74T
         WyTNHtWlBLfVy0bWu5I1sSIdKkukYEXhDfa+e8OuR1YM53dd037Zwj+Gn2hm4Zf5ud4B
         t7QVAMPlquj4xvarqTCecVajFgTe4n35HRuu07Z9nMyLFB07r3f703ULRa6KzdFjW0PG
         hMRCze7xEcUUepo8azgcqBdozJAnMPrjKwLQn/kaAHOq6dZT6pLaUZbrjlz7k/qUdFcD
         AHXHVW+mZGII1UiKDkdF/s6u6Snu3Dk3xhzT2+0WMZ2c4fdtLjVZXhWzuueTQUEsoxJH
         OOWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=egSBgEUc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id e69si270464oob.2.2020.06.03.12.10.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 12:10:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id k15so2791420otp.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 12:10:15 -0700 (PDT)
X-Received: by 2002:a9d:7dc4:: with SMTP id k4mr988102otn.251.1591211414645;
 Wed, 03 Jun 2020 12:10:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net> <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
 <20200603160722.GD2570@hirez.programming.kicks-ass.net> <20200603181638.GD2627@hirez.programming.kicks-ass.net>
In-Reply-To: <20200603181638.GD2627@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 21:10:02 +0200
Message-ID: <CANpmjNPJ_vTyTYyrXxP2ei0caLo10niDo8PapdJj2s4-w_R3TA@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=egSBgEUc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 3 Jun 2020 at 20:16, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jun 03, 2020 at 06:07:22PM +0200, Peter Zijlstra wrote:
> > On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:
>
> > > With that in mind, you could whitelist "__ubsan_handle"-prefixed
> > > functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> > > case is quite rare, it might be reasonable.
> >
> > Yes, I think so. Let me go have dinner and then I'll try and do a patch
> > to that effect.
>
> Here's a slightly more radical patch, it unconditionally allows UBSAN.
>
> I've not actually boot tested this.. yet.
>
> ---
> Subject: x86/entry, ubsan, objtool: Whitelist __ubsan_handle_*()
> From: Peter Zijlstra <peterz@infradead.org>
> Date: Wed Jun  3 20:09:06 CEST 2020
>
> The UBSAN instrumentation only inserts external CALLs when things go
> 'BAD', much like WARN(). So treat them similar to WARN()s for noinstr,
> that is: allow them, at the risk of taking the machine down, to get
> their message out.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

This is much cleaner, as it gets us UBSAN coverage back. Seems to work
fine for me (only lightly tested), so

Acked-by: Marco Elver <elver@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJ_vTyTYyrXxP2ei0caLo10niDo8PapdJj2s4-w_R3TA%40mail.gmail.com.

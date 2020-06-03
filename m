Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH5O3X3AKGQEANIGXYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 202CA1ECAD4
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 09:54:09 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id ba6sf1172622plb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 00:54:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591170847; cv=pass;
        d=google.com; s=arc-20160816;
        b=mAOkWZmcYB70rteKARkFf1sFMi3lhJEqROCKnuQsHfB7wsRTH8JyBBkQRkPfaKm1uX
         LfIJruPc3uy1LnupuHHTK9rkArbC/TjQADHuKcqEuDJxjd/xGnf8T6k9NDd/BjnxFvHa
         GvvaO+VKSXkKHuE36i7qk0mTL9axLrLfJZh/vTbuylEeWrxfxouHX5wc2LIYC9R3tC0I
         FwpCOHLbKFFpOVeL8xR10CTmz0Uqmwuy3JDG61yVY3EeW49XfzhghIv3+PPuIDAzcuGA
         54rRKei3jNNxBLrx2qf/qBNQjlVjKO4sy+fsC0HOqVXgjzYogHHpNKUeiEJS1wVwIGDf
         v3TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Ch9HBcfMYqOdUjxBN7mdCb1RHhys6XYFwH17n1ouVI=;
        b=E6Xdnf4cb2apfDTlX5y1SFSFi3eezKkjIDhdKxI0SxgCcBdtZl2LGdx9fN2Fi54YLx
         kZEtBY0vPlzHLzlQMC90q90qF0JsPW8eQ33blgOwtGKUe2WDpjr7IBiuHyS+6WLKE/Yt
         n8feYLiTsvJ4NkGiPy48HUzrvVR/MtVomfWsilW+VXXbtdtPyDIAvR7JFq7LizUnfRzQ
         CBx3e7pjzMZH7OqgETF+urAZMKT6tbpubqTF7dlLsrhIfomCiAUINaYsbG2bppXz7R18
         RBWBxp8rSN5AOBcrntzlVHAQPA5C+bzSx7pgs5zmD5Aq7zD7c6332tR23moQJfY5GhVj
         L2YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vXRX1vHT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ch9HBcfMYqOdUjxBN7mdCb1RHhys6XYFwH17n1ouVI=;
        b=i+M1XS/8H/ZcEw2KCrOVxyPEPhmJ9QXguwpTFkM8IXW0EFWxf67uGxrLH3gBaXT9XQ
         iLKmNrfxAxJS9XLPKWG0SvWmOnjlhG7Se0fbGW9KUPrWhjlfumIKW/zrm94rgUZOJpQ7
         57FS+Kyvg+nzwRSnqRp8Gbw61eRuNhtKlcbY0ly3/KBnbd0P0T27EgYS6eUMdOiWXEfU
         pMZapaH2Y0zZXo6B9xykFwVR5/JbTQ7BWN5F8r4CRZTxUqlJ1Nf369HFj+n5kJSKrY6b
         wxw6vnvtO4n8cQqi7yZBWSyiDVkRoZBMeytnxDCrmGhoBnI2CESRYHsTXqxZcQ/J6IIu
         vTTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ch9HBcfMYqOdUjxBN7mdCb1RHhys6XYFwH17n1ouVI=;
        b=mrAuP2MMQ9Al7CDDLdbIY616bXra1egKEMJGEcBTI55F3aaWlkGXXPKuUd/tQrJ1VA
         f3O4yoZMrsUijaTtO795LlCMPCHcfDWm/YDSgJxIM7VFIWCWMyIQ1XOvXyFuSjCKA74r
         arlm0/kEoLvxlz8G/pjI40u5nDNG3Evp2U10pdR2dK4hrJVlntxoLhm0SrnDKHRXBLcC
         hQH7F2YheLU8zKwGHQvspSAg0P3Gw9ETdcWni17dXPy3zVMOR22nQ2HvwaFCTQNBBMbD
         FsQpbwXUBp2NJlSAvHCBMOHJI/QASEzvCZkeDNErZn0KhxHrLCQYo2Yz74HEzp2xvgJ3
         1WAw==
X-Gm-Message-State: AOAM533FGVT3lc8AREbB14E795F1IVKON4tz8ylZXMon/Ad6AtoqSK2I
	CluVqcpQPxc5Rly/0DlQXmU=
X-Google-Smtp-Source: ABdhPJzlzZoi+e3pWNoSiKHeoH77KfBOECDUpVqS5W1CUFEIN85tb0Ro+gE+O+Z7e59AU8HM8KOvtQ==
X-Received: by 2002:a17:902:a588:: with SMTP id az8mr26851252plb.318.1591170847522;
        Wed, 03 Jun 2020 00:54:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9a84:: with SMTP id w4ls540229pfi.7.gmail; Wed, 03 Jun
 2020 00:54:07 -0700 (PDT)
X-Received: by 2002:a65:4487:: with SMTP id l7mr28002820pgq.221.1591170847030;
        Wed, 03 Jun 2020 00:54:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591170847; cv=none;
        d=google.com; s=arc-20160816;
        b=ZG4cFqbNZqQ097m8ii2T2o7WJNmtnrsv0mZlObsFGFXwr9LJvQW7DDi8UcxeMB+Und
         db/hb1OmsVrXZy2BmbFHITZlp6ykBAq/N+jxf5esskIPEDbtyMiKO/zwDRg0/Ekm5DEL
         V5Jb7wsWf5EaYwYHHUbDZnWUFIrRjmT2viJ6XnT5o32WJPS6SAxIu3ujwTm7JE38UGRh
         V5xnmf1nPpI6PYipxL6gSJd6kD4Me5svspoPmxzOBtHpYJ72SyVjHKDByTMImlGSoXbr
         lge8rrMwikdo9w3akEXWPZk5Z4WzM3Ko3wul9m9cy5+6XskK+pcW+OoUn1BjwXUX7qGZ
         /6zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AeXRt15TQGTY/w/H5jyx7Z2hUzqpKQwPq+EYur8wP5Y=;
        b=styHzqYv/uVEuMUo0QcWutragVgC/OoEUQIREfO99cJ3pthQNBEEMGPOKHh6IDh6wi
         RliIkvOSRa0axwUdlv3bFcqFecOJ+f2vnI3+B6A8QPtXHtX17g/gaZWzNOJBcMwtbBJR
         NFuSPPFSL2xLg/HZJi5bLB5KELPpdkZBs0FcHqTqAbfQ9WmPhRtDVZcZlQZmvo5aBuB4
         L9RfDRTRyGPyKbw5e2kP4YN7+EoOyA9xL1M+/luuTBm8b7QAVtYfQbhXVU31FS0zgeXg
         3NdcqGKDqV/Go5lwMkHh+iH7ltXFCL/b3/a2wuEtwT/ydK9UCJjdldAiDA4h5ChTKwzs
         e3Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vXRX1vHT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id x70si75082pfc.6.2020.06.03.00.54.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 00:54:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id k15so1156304otp.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 00:54:06 -0700 (PDT)
X-Received: by 2002:a9d:7dc4:: with SMTP id k4mr2096456otn.251.1591170846129;
 Wed, 03 Jun 2020 00:54:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200602143633.104439-1-elver@google.com> <20200602204821.GI29598@paulmck-ThinkPad-P72>
In-Reply-To: <20200602204821.GI29598@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 09:53:53 +0200
Message-ID: <CANpmjNO_V9iOrcAunehJW7XLzzk5pyS6VQEx0pARsjO0pvA6bw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Prefer '__no_kcsan inline' in test
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vXRX1vHT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Tue, 2 Jun 2020 at 22:48, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Jun 02, 2020 at 04:36:33PM +0200, Marco Elver wrote:
> > Instead of __no_kcsan_or_inline, prefer '__no_kcsan inline' in test --
> > this is in case we decide to remove __no_kcsan_or_inline.
> >
> > Suggested-by: Peter Zijlstra <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >
> > Hi Paul,
> >
> > This is to prepare eventual removal of __no_kcsan_or_inline, and avoid a
> > series that doesn't apply to anything other than -next (because some
> > bits are in -tip and the test only in -rcu; although this problem might
> > be solved in 2 weeks). This patch is to make sure in case the
> > __kcsan_or_inline series is based on -tip, integration in -next doesn't
> > cause problems.
> >
> > This came up in
> > https://lkml.kernel.org/r/20200529185923.GO706495@hirez.programming.kicks-ass.net
>
> Applied and pushed, thank you!
>
> Please note that unless you would like this pushed into the current
> merge window, it will not be visible in -next until v5.8-rc1 comes out.
> Which sounds like you are aware of already, just want to be sure.  ;-)

Thank you! Yes, that's fine. The test and this patch I'd expect will
go into 5.9 earliest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO_V9iOrcAunehJW7XLzzk5pyS6VQEx0pARsjO0pvA6bw%40mail.gmail.com.

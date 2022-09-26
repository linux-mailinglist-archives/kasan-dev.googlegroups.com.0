Return-Path: <kasan-dev+bncBCT4XGV33UIBB4UGZCMQMGQEZTIEVTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B3FF25EB1A8
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 21:54:26 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id i26-20020adfa51a000000b0022c8fe3f26csf1380617wrb.15
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 12:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664222066; cv=pass;
        d=google.com; s=arc-20160816;
        b=h58O4NG0YANo2bMVs86Vxuc9rLIH4ytDkU3PSKTZWWMDqZ3I4LyvN2nFi1KETFQkPf
         nxjHLf1P7LDCg4MSBduVjg0qOGkghGBQGYLu2GrajlMUnCAv+TdMxwCnvYItceh7NWeE
         Q4PY9VggRL3m/6MwH9wrdpOBBvH3L7GHct1ARnuTFBox7HASBsQcHM3WXiADiqAGDRjf
         f0i8YuH54UtZMJe7tMb2Zz4IwtYPrKE8du2FlDJQh0DUsEkZjBBc6Quxcmzf94ZvSNPx
         2il6wf2iy2cWi7Kkftfs868xOss7IjT3N2LpPMEgIiR7i6CNYi9LT64tgyarmVKAvGSP
         lwdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=agxFn1KZ0CTbCrJpWeSFc/iWgcn0MMvLk2RZ03jEI5g=;
        b=XcpYAHPWrcS3JaLo5Ja+36WiswzWyqNOYmmk+3JufiE0j7YoQzY/CG9iinjdQiGpsX
         J0sj6536Iv3skXtJFOtcuB4gMkHsBYlr4vJ4rS/2k/YUog44ZYFgk2kjY7Q19Q4evytJ
         vlq+lSzQp7x7+lTWf577pwSkFC/yGVEt+Q6SAXMYABAX8tZs6QmfvCm5L6/LoZ8bFgxD
         ZLISfvFzdCqDxDQxkc9rm1k2g08Vj+WdINMdqcGFDqiwQcDSL7JbhyAov08YdaD0/Uzf
         ahGI5NhA4MEeCNQ5aeP6LIk3HKVxnLymRdENfYxKhrEKoBV0fQakm7kZQuAt7j/9/KrP
         nXhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qMZTRLAu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=agxFn1KZ0CTbCrJpWeSFc/iWgcn0MMvLk2RZ03jEI5g=;
        b=Ryqg8lsdgtoYKLCqBPLMjb1+wONaXx4gY5bzRwh8T8KQyX+V0b6oqpKaBCTE+ExPXc
         LLgymDJ6/meoCkPEFvHCu8WmHtZ844z62mcIHzHm+hqb5r5NP2p55v97QdhtTK+1buKc
         F2VivXVLjRikOSVqN1XrhrE4HtdmgtdA/Kt2wvPqfTjOX6gkCyeX/wswMHAfQPLw4YYt
         ueh8UjzWqiRnMrN+tjxInXmdBOLAlo0WkGdUE24YofYWaYkaBC3BgHda3SEaC2Qb/gh8
         mCAcKqPV1Y/+aNO3ipiQtqxvOvBHaROlgxLWKYjzFJgs44h56ArGdMMXcTyzrL6uN83d
         On/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=agxFn1KZ0CTbCrJpWeSFc/iWgcn0MMvLk2RZ03jEI5g=;
        b=qAk7MVeWSR+g4EagSXRSkXjTpn1oFVXOcemmgBbEUifVmYTLSfmH7BrimseipMdJEd
         P5ZIIJTuyaE15zJNGnZjVsiMojNm27ML9UbF6HdicuJ2w0y+9vzplPIosyhm9xggD8B1
         V5GKXVjl3n3J5vh9eXk9PhYRQWtOrrBcI5AZzUYavpeTFobHyNmGCRAJWGqVYCb+nTMo
         Iq3MRrV/3fCWsnZlnJsy6mFiSluLPXMA7LZem76gtF3xIr0aPMLf5pSqWdqfBaOQJ1hB
         FWPCMR+9pM0JoxO+lROQowAJUeuQWPR6ghut8chRCVVel5byXylAM9+X6MhvSx5le5k3
         v2ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2olltpvFyXvrWH5EXCUlDSeGuxai7CieaPcAsb7CjilCPuXvi8
	RodpKrvTLSVicoKOuuRFHaA=
X-Google-Smtp-Source: AMsMyM70rwRbiWembGVP3sTMdipYlngMgQwwYr/mfcaXrr25+hIOptrW5sIZyDvnzLm0VcUnOOL/sQ==
X-Received: by 2002:adf:d4d2:0:b0:22a:d0c1:185a with SMTP id w18-20020adfd4d2000000b0022ad0c1185amr15069786wrk.16.1664222066198;
        Mon, 26 Sep 2022 12:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f609:0:b0:22b:e6:7bce with SMTP id t9-20020adff609000000b0022b00e67bcels409709wrp.1.-pod-prod-gmail;
 Mon, 26 Sep 2022 12:54:25 -0700 (PDT)
X-Received: by 2002:a5d:4a41:0:b0:228:48c6:7386 with SMTP id v1-20020a5d4a41000000b0022848c67386mr14700677wrs.649.1664222065020;
        Mon, 26 Sep 2022 12:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664222065; cv=none;
        d=google.com; s=arc-20160816;
        b=GPCE3xIhc8oWs9sZVTYH9s0G0ihuUkAqiFWfIXV15pw/eGypUZ+sMBJAkhSfYyWJTn
         HklmSw0G+5zl+iA4i1HaKanchd2Zb7KDkKaEbQPLDs7r7YS8xTxHNZjjftcVlh5Ark5q
         2LEANXkcw/+s+yRbYswTBgJLA8DhwQu9ELSGmwo+eWpmewArs5IZ3v6KNRI5W5hO++cc
         vIVbJxSGQP/ISyvhqSLCh5rJyOpXq/JxnwpGrSjidFRDEk7saudLhwmZq1n2VFln6+v8
         olL607NXMU8kAhPT+uHBvDVANzzyzYiyqeauYVcfZlN7T+VJ0TAALIUicZL0TM2t3FeU
         wIPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=udNFbkljY8umDp0Ovch5EUxs6WCQeL7rXwEeo3AEAFE=;
        b=pfG4zRF18kE8n5Bxj6vNxxPRXIKhweOU9K4TweXLhkOcRupAEPfM2Vr7s6Da5CwpYo
         Og8YqT7igCBjtn9RUSt5qv1zeY5KJ/pYdr51rqJspkk/DcThUw8HjTZN1lYa8UUvcXe4
         NAWj59h+B+6Q3JztG/K7FZI/d+rdSRGjA36PH+/Vef0Cb+0roPu/mo7l04+d0hOU04Of
         pIIwT+2s2EBcCyWa2LUTRv5R/Rizqja8SN5pr+EYLLx8CnQwfeZH4PdtxPwvULhXSshq
         9Rc3Rf8aXEmgeBwUFBpzqU8R3xOuxDwExR3U8WBtqQZaWH6YenownyplxS+ofhZUGnDy
         vfhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qMZTRLAu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si913208wma.1.2022.09.26.12.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 12:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8B016B80E57;
	Mon, 26 Sep 2022 19:54:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A1CD9C433D6;
	Mon, 26 Sep 2022 19:54:22 +0000 (UTC)
Date: Mon, 26 Sep 2022 12:54:21 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>, kasan-dev@googlegroups.com,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] kfence: use better stack hash seed
Message-Id: <20220926125421.64a1abd22a1d0b697763c9f7@linux-foundation.org>
In-Reply-To: <CANpmjNP2FskJ4-pArVd=pT0MFokafPOYZiEg3tspGtjQ5OtuCg@mail.gmail.com>
References: <20220926171223.1483213-1-Jason@zx2c4.com>
	<CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
	<CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com>
	<CANpmjNP2FskJ4-pArVd=pT0MFokafPOYZiEg3tspGtjQ5OtuCg@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=qMZTRLAu;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 26 Sep 2022 21:31:16 +0200 Marco Elver <elver@google.com> wrote:

> On Mon, 26 Sept 2022 at 20:01, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> >
> > On Mon, Sep 26, 2022 at 7:35 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Mon, 26 Sept 2022 at 19:12, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > > >
> > > > As of [1], the RNG will have incorporated both a cycle counter value and
> > > > RDRAND, in addition to various other environmental noise. Therefore,
> > > > using get_random_u32() will supply a stronger seed than simply using
> > > > random_get_entropy(). N.B.: random_get_entropy() should be considered an
> > > > internal API of random.c and not generally consumed.
> > > >
> > > > [1] https://git.kernel.org/crng/random/c/c6c739b0
> > > >
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Marco Elver <elver@google.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > >
> > > Reviewed-by: Marco Elver <elver@google.com>
> > >
> > > Assuming this patch goes after [1].
> >
> > Do you want me to queue it up in my tree to ensure that? Or would you
> > like to take it and just rely on me sending my PULL at the start of
> > the window?
> 
> kfence patches go through -mm, so that's also a question for Andrew.

I can't seem to find the patch anywhere.  Was I cc'ed?

Please always cc linux-kernel on patches to address this problem. 
That's basically the only use for lkml nowadyas :(

> I'm guessing that your change at [1] and this patch ought to be in a
> patch series together, due to that dependency. In which case it'd be
> very reasonable for you to take it through your tree.

Yes, please keep dependents and dependees in the same series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220926125421.64a1abd22a1d0b697763c9f7%40linux-foundation.org.

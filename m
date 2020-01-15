Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXH27TYAKGQENEXNT4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C78613C94C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:27:09 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id b4sf7149102plr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 08:27:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579105628; cv=pass;
        d=google.com; s=arc-20160816;
        b=YesNf8nynZlPGp9bW82xBg+e8PzjHsd3MmqhlucLAryYSpyiIUJfpWHnS3NRt/CPsY
         U0CBjqqmlPfxpKP5gBk2D6rdn/x7IkeiSA2JGElWb3xJNdKnKmRNTfue4SBmubT2qhPH
         PMYtnnKkIiMRos1aNtz/zxXYq4V7aqkqiCdRpBAHDWE9PLPPfC3FYxsmVCCtnPcl7HoM
         5D016hP14MV0+UfCsq97y1knUj/KKwve94POp2ue3jaqpWdPKDfGZAt7JxAZBgVGfn/5
         1wh6wo3pRonBKe7Y6lxUS7fCrlSUrn3JQFREknUq3s2BdtHZIUAdt6AYOujXQ9APZsjb
         HB3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W0R1MLNhZykwMQP16KpOlYbsV7CHPpUtqRc0XOSgd2c=;
        b=OsYnqED6xsBHIUNueJRXDrc9wQcYB5LEPY1bI6ubcio9/16vmcjGJwWGNAY1TTznmO
         z8sJh+fz6AgmY/FNeJ2Xjjo1aLFMUKD/yRNQQi3bwC4POLpNhHDn9fVGbZoRi5CgPb40
         6xnSxTlWU+n5uBIGqjea1kRHM3ogJGFqb5sNxSnrOpocOfx2y85OX7lN5T809rXt8z/6
         rSD7AMYxkWEmHxeWgC3FDypISJgZUQS6rfPYeHmelpJRADnezD0iUyWdyZ+mw1d8MmN0
         kTGyqafAOAj0uv11hT2hCby+/jGwkJgsVXuLobp90siv0bbnwPJSDuBp2NhBsarlKSi7
         Bw6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B/+xH4/E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W0R1MLNhZykwMQP16KpOlYbsV7CHPpUtqRc0XOSgd2c=;
        b=R0rvjSusGCiXIfJqE9SiH6WYVZfK2Snr564AcEZ2ZB9Wf4vVOuNUWpNNeCbgZD7Uun
         F2jW0GxFQZa5ihPUnXsHdVUoBCaolwyJCcKZgQrGuOtGv/wuNa6ZXJBnHaPwtZMY63U1
         V25SGz8H0TSHccF6APZ8v21l3br9PlkJ3DmeqfY2o/04/CDuJcFFHvLGJzo1PLSxrQoQ
         QpDNLS6zhvePkNZs3IFmunj68gJbux/4MF8qhfAm+VtPCgN1VQyeYXvgljManumiKdKd
         /yfJtBCY6JBW5JK67In4on1LTTpQXOlSnXzRy0pgYDrVRsx3KXJKKDPV2jkbRHB4oBWt
         yuSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W0R1MLNhZykwMQP16KpOlYbsV7CHPpUtqRc0XOSgd2c=;
        b=LJCbKARCUYr0nwpDRO1YqgJaaZb1tHAJqGERVg6pPwrQ2xvwCqFiVUGrBhxLl7KaPW
         K2vEM5PoZaZpZUrujagK7DhiqkewYxEDqCcUfiEfohlhcJ0Lj8gH6i8jfAEf7IG2MDq+
         SisSNXt/f9VBMFVcgr34IlMH92M8HtYCVd6oQ2/Ajy15SpZ2J0L9c1cpxnzbiKb5XTR4
         RHuMDQF33/sOWzACvnpM0Vz/ecGTa+uVP0+HWZISl0fCSbdSWXTHgfckS0NjBDNAUdvM
         uhRo/UH+RCuAEraGOmGEiIZEYc8SAPvK3daw1ds8wk+ISOAq56BlOkQ6bpVUCpCkj8Zi
         8dVg==
X-Gm-Message-State: APjAAAWTEtXQ8PKyUQL3/oFXyCV3BFFZFp9jzgZfRczmLcYQuOcI+4Lh
	FloQ9/dvuVNMy9Go9+W54uk=
X-Google-Smtp-Source: APXvYqyuMPLifIDwqJtiVlCMRH3hkKF2QOJa/g6ZOf2M/LMoM7dbXeQ4EVgnvXAGYqSl7gFvsvpfww==
X-Received: by 2002:a63:bc01:: with SMTP id q1mr35841348pge.442.1579105628098;
        Wed, 15 Jan 2020 08:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c94:: with SMTP id b20ls2059562pjo.0.gmail; Wed, 15
 Jan 2020 08:27:07 -0800 (PST)
X-Received: by 2002:a17:902:7e4d:: with SMTP id a13mr27508580pln.281.1579105627621;
        Wed, 15 Jan 2020 08:27:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579105627; cv=none;
        d=google.com; s=arc-20160816;
        b=pRpXfuJOVrdI7r1UTqK6KcBpLIQR0Qs2YqIZ+NcB/lH18zijqHprgEaBt1IBUmWfgM
         zH/qDVZJdZQJ2APfm0B1RfnEl0E7YMkgXDFxpfOjwV5OUHnAN/6BPLDptXh/jhoiYWCR
         iZRi3r01BuCv0LBysP07TthCMdUifZ7yUrShwl2phfWtX1JFkxPkSCSklcWMMeg1Ps7Q
         kf3zDgo1nYYbmk4mW2DmGQv2GjqtIjrPGCAn7vXy9WBFnKJIy96nOZQ5LviMSdm0i46x
         pfRbtKn7RsNwejw6j04vF9rN9p9pbS5NlgSztubFX0J9U/w6cdtW28tPI5SJ+j1skS1P
         y4eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J/jN6ywbZWrd/e8wYUMEIXDZGBzSANaQq7yRDAP83uc=;
        b=dFnI2wEekdDMul8+6aIkvj2hNBQ9nMe25wC0JIwpwPUQkCz5Zejz9vOGnr1qQawfws
         1+YShlt1K3E/no+vaVdMgdS+pPt+Fg5GdnvTVw5PdgQKNjQoDL+SMzMzvUbcCf/2jgf8
         EAfA3qyrmgXwYhKkiTs2eVSC1bvn9cxoxbY95GMgnAagCtRrzu3IeLtTiPVBEGpte7ou
         IrCTkgaP0CDHas9pj0CXLkXZbF1uZNzp7ll0FW2xZu6FEIChZylkMSVTOkYMtw+5hX5A
         l8bHGbK2oZ0PzQfQg+gK6xGFZFV/8TY5heOW9FRIW07bWBpyGJYf/Wj4a1zXufi1XhnV
         RHiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B/+xH4/E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id d14si858600pfo.4.2020.01.15.08.27.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 08:27:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id d62so15899055oia.11
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 08:27:07 -0800 (PST)
X-Received: by 2002:aca:36c1:: with SMTP id d184mr501516oia.70.1579105626648;
 Wed, 15 Jan 2020 08:27:06 -0800 (PST)
MIME-Version: 1.0
References: <20200114124919.11891-1-elver@google.com> <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
In-Reply-To: <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 17:26:55 +0100
Message-ID: <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
To: Alexander Potapenko <glider@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="B/+xH4/E";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Tue, 14 Jan 2020 at 18:24, Alexander Potapenko <glider@google.com> wrote:
>
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >          *      detection point of view) to simply disable preemptions to ensure
> >          *      as many tasks as possible run on other CPUs.
> >          */
> > -       local_irq_save(irq_flags);
> > +       raw_local_irq_save(irq_flags);
>
> Please reflect the need to use raw_local_irq_save() in the comment.
>
> >
> >         watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> >         if (watchpoint == NULL) {
> > @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >
> >         kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> >  out_unlock:
> > -       local_irq_restore(irq_flags);
> > +       raw_local_irq_restore(irq_flags);
>
> Ditto

Done. v2: http://lkml.kernel.org/r/20200115162512.70807-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6%2BNTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q%40mail.gmail.com.

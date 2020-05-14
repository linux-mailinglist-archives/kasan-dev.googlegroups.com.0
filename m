Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWH6X2QKGQEN6IPX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 667771D3517
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 17:29:39 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id o21sf2680740ioo.22
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 08:29:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589470178; cv=pass;
        d=google.com; s=arc-20160816;
        b=PXCeeG3hUpn4pxHdlT5PAxmSKAAWUr3CuFqUC/jSU2WCTVEXmaBdll2ka1FHKteCld
         tqjGkHeu76b3qz/+VxIQaija1g7PzYUU5fjj6h6d/3rCNNTmKoZMjb2PpeaYjh3hhCaX
         BY3OKoG9rfuyNVg9rVgTWlAuRZCu/ZFZW93JWVL8DrAmfwQDKuER90CHg+/XDqzjZZod
         L7Gqb+trW4HTyQzVyQcsGG2YloRoqwN37tiGUQWn4Uqw6CdxVtlkTpMvRJHeoMhIHZXS
         aMH4+0osOKXWcPEB4ipv8HJDxueVFsgXWvWWT7Acai0ttPoE147ftEIt1UsoQixl45n/
         ayAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r//awYdpZMztJT3dt/bmcMCU82UZ9tzburRqqcYODgs=;
        b=IcRUvND55Vv/AWIxDg0FNA+MziZynkoQZpnzVE/BerVPnbi3V/PcC3uP/VH4ITKkY5
         IYtmO8+3edjh58cWlhD59wgmZO+brZLtn0p89YwSHt7DWXMDxK/1B8rHrhrL9byMZW1e
         D6MBgvnBOzWpfzP+J6+ZyGyGzrA38HKJCURf0UjZT+ppMhP+ipLhJoKUBi2jd0MsK16r
         KQcehPMBbsl1Wud7B09PV2rhqF6JSlb34DgLnVZ74R7dmi2eeVPVUlNK9UxjNyz6CYME
         VJdIGsPGfZPdCx/1NagCkBkzVcnybJBmKK9Tdjgsgl8UATChlmOx4KWQ/1wOGo7H8+a5
         yRXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYVph7M9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r//awYdpZMztJT3dt/bmcMCU82UZ9tzburRqqcYODgs=;
        b=oQNSdLMDD6HXruh5mdXVhl/YEMxqG34NOKDoQn+f+TE6U3DLRqbAzvoEQ8M5XLsU+r
         GM4Eyh03YUwq8oSSo2yvMLQTKXNPa0qJQObcqoJoYTpyuszI3ePqzwuEViYWKJ0uhJl9
         VSasLdBb4pmmf85+JkfLJQTJkGlQkyrS0ubkAsviZW0C4+AoXnpHkoRZNvvTLVdNkjpH
         F2nNRmSA9OogdolXVbDF4Atc4YR5lVjrJ5PD75tkWgVIgdAqrx3z6zUYxt6jn14hbVrR
         SS1LSBRvNMrfvgGSUn1jwGJMouS2B4lbeRNcwLgemfULNPbBwa9auVRHtgPlAQ6fyw2e
         /BpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r//awYdpZMztJT3dt/bmcMCU82UZ9tzburRqqcYODgs=;
        b=UfQgmlnCgmeF8x+Vn04E8cqdMykSziYw0dHlcK0GnyScPqYuuEw5wOJR5in9yuxkR3
         zQIlrC1OEe2R2Ojl6zsylHzSlJveJfp+3GURwABdK17Qmuy7UubI1uPsZoxRgWoGs1Cf
         YbbJhJanJOu9wzwLQlXNOJdPExT6VVhUnkcM5svuURhUnz1E9jOQPdRWSt3gq6qao/WG
         gUNOMlMxLOF0qdYugnzudlcIsnqbk1CGoRC3cDsDhq+93lEcAZJWQjhj8OZWLb8Bpqjr
         2IHV/jZ2KnBT8TgcH8rK8ErCkPV+o2AvZ9Gqh1vVw6SXxhhO+MB8aX9PZ54GsxyA/lS3
         z+6g==
X-Gm-Message-State: AOAM5300/ryKW8oV09UQIN4T8/ajHcRLi7erJ7YFyfAXaPxGbAkesQ6N
	jyaFdc+Hd4X0gki16Z+80eA=
X-Google-Smtp-Source: ABdhPJx1nwL2feGnwUtw8l9Jqyg8PfePjvCF0fyg1DCBprTFqfaBF0Fbe8iwyb6W3IeJn6hR0Oa69g==
X-Received: by 2002:a92:740e:: with SMTP id p14mr5081391ilc.57.1589470178332;
        Thu, 14 May 2020 08:29:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:99:: with SMTP id v25ls579822jao.7.gmail; Thu, 14
 May 2020 08:29:36 -0700 (PDT)
X-Received: by 2002:a05:6638:44e:: with SMTP id r14mr5068463jap.53.1589470176027;
        Thu, 14 May 2020 08:29:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589470176; cv=none;
        d=google.com; s=arc-20160816;
        b=wOqyFHdv9OhNhyWBUTgxjwIYcluY3JlQrbP76rgDK2/6MfxGpLismw1XKw0Ag4wvpf
         UM9qOsqdbRcJLughoSsCzXakYkYaixCPDrwHPIRNbU6ZLmJTj0RV1GW7p/Wr8Wooqs3e
         T/mnv6PqfznMiIpzN7aI3afEcH4qAJHi2rI0kHTY9Eyv6sGBo3Jtnxjmi8lCf4tWQOsM
         klcjorYFSmHNJRXsSYiZu3rTdoD/NrKbAF4M1n1xQAD4KxjZKRx19eLFyTG3OlXWplna
         iiDwNYegi5Qb4DWPzkh1zDUIKIm18jLXQUwOt9mCGb1Y9uO8EEc3pT+GKno+Um/1ycUw
         u8bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ird8FEm72ENlHkterOqnEy09/dOc2zCxjzNTKKGHbAU=;
        b=N/CHOpXYO+w7BKdx5Y2hHogt1hmqhGMqda+VjfJKtcHTG/VwYUdOI1MtbYGB3xwcGR
         DTI1xR1Vwrv8CV7ZRn5sJAxTggVPyvC2eGv9KCcr2csXv4+ceaAidhc1wWAF39hKaB3C
         UO9qDKFQjQraF9xexRsw1nqr4l43YweFYlZB7ICLtbD/9N1jdnj2orDNXRM4DmCo1Afm
         fZL+24wXWni7VTlNsMbBRoXQke8823aIYj23LM1vb9K5DzhWwVUbdmWWgXdF9pIyO0nP
         YAfwR31zwZM8Ac7mjUFxwUWd7g3hDUEMW2O4uhJdTNLSAuCe4EqHg99/bke1rY/3acp3
         SgBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYVph7M9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc44.google.com (mail-oo1-xc44.google.com. [2607:f8b0:4864:20::c44])
        by gmr-mx.google.com with ESMTPS id s66si290428ild.2.2020.05.14.08.29.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 08:29:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) client-ip=2607:f8b0:4864:20::c44;
Received: by mail-oo1-xc44.google.com with SMTP id q6so191972oot.0
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 08:29:36 -0700 (PDT)
X-Received: by 2002:a4a:2809:: with SMTP id h9mr4056657ooa.36.1589470175434;
 Thu, 14 May 2020 08:29:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200513124021.GB20278@willie-the-truck> <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck> <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck> <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck> <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck> <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
 <20200514142450.GC2978@hirez.programming.kicks-ass.net> <875zcyzh6r.fsf@nanos.tec.linutronix.de>
In-Reply-To: <875zcyzh6r.fsf@nanos.tec.linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 17:29:23 +0200
Message-ID: <CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eYVph7M9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as
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

On Thu, 14 May 2020 at 17:09, Thomas Gleixner <tglx@linutronix.de> wrote:
>
> Peter Zijlstra <peterz@infradead.org> writes:
> > On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
> >> Any preferences?
> >
> > I suppose DTRT, if we then write the Makefile rule like:
> >
> > KCSAN_SANITIZE := KCSAN_FUNCTION_ATTRIBUTES
> >
> > and set that to either 'y'/'n' depending on the compiler at hand
> > supporting enough magic to make it all work.
> >
> > I suppose all the sanitize stuff is most important for developers and
> > we tend to have the latest compiler versions anyway, right?
>
> Developers and CI/testing stuff. Yes we really should require a sane
> compiler instead of introducing boatloads of horrible workarounds all
> over the place which then break when the code changes slightly.

In which case, let me prepare a series on top of -tip for switching at
least KCSAN to Clang 11. If that's what we'll need, I don't see a
better option right now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA%40mail.gmail.com.

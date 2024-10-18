Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMLZO4AMGQESYY6V4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id D6B399A4802
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 22:31:39 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-20cc1fddb87sf26930225ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 13:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729283498; cv=pass;
        d=google.com; s=arc-20240605;
        b=VtoXIIHW6e6TqE1gwCmZ1uMEWQxHXGTqf4/rCLPvl8k6RULvhHKZm4c46g0vE3LBA0
         bukaFI1ucBN0r/pNgaLMX5Wfv8SYeVErombYu4B6oLiMXxdcIsgqneUUhhWcnXX4qXKY
         DkUIl0ihIp8HxuR3scsuqJzcVfkNBm1dJqniPqkHR+E5PTfHFXHh75UqANv60YgGuzFU
         Ved9sKKAymRio2lmeUgKDgIWeOewpD73pLwvVVipGwVtfa4b1c78SXD/87PfoK7vpQRM
         +KxFpti21a6WViKHgkLEfGg1XIUaLNwj8ddijprTaGsccmzpwD0SLjtGr2XIvhuF+W3d
         1KWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Ui7gnhSPU+7ncjYfIKY07ZTS23taClbRdK6pePvxjw=;
        fh=wbAgWYwx/FVqK7qs0hR3DYXByAzt3ovAfwLlyE25jO0=;
        b=dChMWKEE52k3pIsvWnEfLW8KfOFPoCubvsOXkQaEos0G0MWSgOq7l3WhK/Ys/Rj7AQ
         wS9V1I3QAJtvNJ73W77ufINjkfnEneTrILQEt75yEc7Rp0n2v45M9Hax/b+PgrFCYfRM
         A0esvsRTlOhExYwLbdlfARB4cbYInbjy5OPQgSgqeKHO0ulXW+sXGkp6tbvIykpM7Mr0
         YU0WzHpYntmHYaP/GsEfqNxO3vv7GXhHQ2BshDfjlCwUWUpa44owrE1pnWf27iNL+RgV
         ZG/G7m3Cvg5UHgIQi6ZVkR1at5KLYJYZ3TxzaPdmiYh8yjthwewjJJWZZrdG1DadCB/U
         yzSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mleNSnnL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729283498; x=1729888298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8Ui7gnhSPU+7ncjYfIKY07ZTS23taClbRdK6pePvxjw=;
        b=E29MzZireT+2VWhAB+pjzoo5sHokE3x5+lTT3YhKUUPhG2vcwgsZBstkrYannkG9D9
         M2yZhDsjStGYlLm0ZQEFSgLE9O7V+dT3by56b6hDUDYGRlHRCy1E7gunX9CHFFe3GlNF
         +Yc0mWW26MznnbaX+Uzei+tWEXy0eQLuNIgRkRXBU3jmuR9/TMVabohr7QeY0PLY6XJX
         zK+OfuQvsmQ/S1Z4N9HbpM7JWGPUNosq0R/ULuXxynqpfz2t950dzewe+CpetmRnw/W3
         SPhk9E00WpmZh21M4+v4NaGCSFJeyS98iBK48pZ8d0SsMkm9Mp8R2UwFMk+IZEBB9uFo
         fH+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729283498; x=1729888298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8Ui7gnhSPU+7ncjYfIKY07ZTS23taClbRdK6pePvxjw=;
        b=K/zKeBc9X5QnJc1yzn5AIWGqgORVIy8mXITDrYEOpCt/ibPBaC5h77YystO82r3LvS
         7Gjkoq9/jRhNGGhr09gjXvfS8G23mL1WNHN3Q8F9Rf5PsW/daqotz55YBFJDjsghrBLw
         pbf56t8/frpqdY0k7x6oISZzlp/+4MLL+3PunYnQS6XkBXafgtiZ3CezyDzeg+D32Gks
         03gD0gUxo3nNC3Kv985LB/E64t/YExTmafwaiUvbKRoL9h4ItkD5DtTLY+HIRBYZOzhl
         Cg4RA5kB0THGqGxGSaaKMXKsZrmf+cE6fU5MSau4vJ/DfMmyouqervhKR4ugwp0WBZkm
         3YMw==
X-Forwarded-Encrypted: i=2; AJvYcCVhG1/sLtI3UprzaixWsLotWPUv8o/KzZdlk4UmetlWStvz5SCkCFkxPQSGTQJhP+ftj5aiBg==@lfdr.de
X-Gm-Message-State: AOJu0YxockY0OdBwBji1rUsAe7pWj8PNWcGdl3r9tr9/QXa6azaDWN7Y
	5BsKqlPF6B7uTyEnrtsA5fx1eZMX5S47LW0NOalLzrl8K6QL6hmb
X-Google-Smtp-Source: AGHT+IED2nRBAQuhNTiOvikqy48mMA18cOCpCGcbkUDi3GJH80FIdie8FxpEPNH3tYdoEEdeIDCudQ==
X-Received: by 2002:a17:902:c40c:b0:207:4c7c:743b with SMTP id d9443c01a7336-20e59a9637fmr41902375ad.0.1729283497998;
        Fri, 18 Oct 2024 13:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da85:b0:206:cbad:e63f with SMTP id
 d9443c01a7336-20d479258b2ls21196835ad.0.-pod-prod-02-us; Fri, 18 Oct 2024
 13:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6B6O7FdErVSkt1Pjal90baXA6XPEyPylIA84P1WO/6a+tqNgTas8fWnPokM54e5qkPKtbROBZfxI=@googlegroups.com
X-Received: by 2002:a17:902:ce81:b0:20b:9379:f1f7 with SMTP id d9443c01a7336-20e5a8f3d72mr37979285ad.40.1729283496562;
        Fri, 18 Oct 2024 13:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729283496; cv=none;
        d=google.com; s=arc-20240605;
        b=ATq80tRBG6es5qcy6F9RjgygBfURf6G7EEURe80j2rspW/aWbXBXmoyT+plwWvYVPI
         /fKaFUyXvGZ/jD9b4XXH+wwRHGpHSxfrpc37o56VXWgk/1/RgBtfc1xBJh1bF02Cb60Y
         dEhWLBoPh49EETqn4SsdAECm4criKmMD1yjzGsOa+Qq470NYOQogjZUPshp2NDeGG/Nd
         5ubKbuFEwvXpvvU79jHuT8DztSgWWlWq9/2lCOl+5KsYqdRnOhUodMs8NGkL86+ChIrb
         fIpjGaW8ZWZ8rvsefP4bR/ofxNwQMjpzRu6fIN26and6h7LflSdAHy3RUnj9Yk2EqcMo
         18oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GCZHBsLr9Yv/sVgX6G+ehlGmplsS8D5LjwzJdkkRRMU=;
        fh=TLBGQ4kWYjG9Uqhh/N+/Thp46jRyc/Ma7ZxPKouXyhk=;
        b=aw+KlxkE9TIHw9/Z33H0aEosYLBskTGX+AoePy9jFNQtNaltyGDWqcwn68Fm6cejZM
         mzI+MskxITygf4wOZtyZg8BvcABR5nd5SKlsIxilTCuYgFx2+uin7BN/em2ilidbQONv
         RhfKOfFrgcXwbLmkmT5ZLyh1DIACcbO6FKrvqrJ/hE+TAOW3xRQRiN78qiwuc7CZh7Ws
         BE/1fpPuyvbGHwcX79EST3YBYFpyshvhlqkTlUBBDhHtea17Zo/jzxpcnkJiKFYd7n8m
         ovTXmlg8mZ71vHAE3P/o02LGO361o1B2Ci8IsdwxRHCV7DOiADDRDHHAum0V5pdglXhb
         gECQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mleNSnnL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20e5a9162f5si908655ad.12.2024.10.18.13.31.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 13:31:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-2e2bd0e2c4fso1966131a91.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 13:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/YWhjWQ12v4vFb6MRkJ7sbbRMEF/9c9EAMqO3GVXK/Hjc2TbTAYm2k3wwkfRf+05wg2zxAmMkpew=@googlegroups.com
X-Received: by 2002:a17:90b:4d0f:b0:2e2:cf5c:8ee8 with SMTP id
 98e67ed59e1d1-2e561612dcemr3965121a91.12.1729283495614; Fri, 18 Oct 2024
 13:31:35 -0700 (PDT)
MIME-Version: 1.0
References: <20241014161100.18034-1-will@kernel.org> <172898869113.658437.16326042568646594201.b4-ty@kernel.org>
 <ZxIeVabQQS2aISe5@elver.google.com> <CA+fCnZc4iNa_bxo8mj52Dm8RCKAW=DQ_KUSKK2+OzjmF3T+tRw@mail.gmail.com>
In-Reply-To: <CA+fCnZc4iNa_bxo8mj52Dm8RCKAW=DQ_KUSKK2+OzjmF3T+tRw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 22:30:57 +0200
Message-ID: <CANpmjNP5Sny0Xj0JeHU8SFFsNvgnQQ7-c3PGDmiH9RVnUF5YTA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	catalin.marinas@arm.com, kernel-team@android.com, 
	linux-kernel@vger.kernel.org, ryabinin.a.a@gmail.com, glider@google.com, 
	kasan-dev@googlegroups.com, Mark Rutland <mark.rutland@arm.com>, 
	syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mleNSnnL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 18 Oct 2024 at 22:25, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Fri, Oct 18, 2024 at 10:37=E2=80=AFAM Marco Elver <elver@google.com> w=
rote:
> >
> > > Applied to arm64 (for-next/fixes), thanks!
> > >
> > > [1/1] kasan: Disable Software Tag-Based KASAN with GCC
> > >       https://git.kernel.org/arm64/c/7aed6a2c51ff
> >
> > I do not think this is the right fix. Please see alternative below.
> > Please do double-check that the observed splat above is fixed with that=
.
> >
> > Thanks,
> > -- Marco
> >
> > ------ >8 ------
> >
> > From 23bd83dbff5a9778f34831ed292d5e52b4b0ee18 Mon Sep 17 00:00:00 2001
> > From: Marco Elver <elver@google.com>
> > Date: Fri, 18 Oct 2024 10:18:24 +0200
> > Subject: [PATCH] kasan: Fix Software Tag-Based KASAN with GCC
> >
> > Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not disa=
ble
> > instrumentation in functions with __attribute__((no_sanitize_address)).
> >
> > However, __attribute__((no_sanitize("hwaddress"))) does correctly
> > disable instrumentation. Use it instead.
> >
> > Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> > Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> > Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> > Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > Cc: Andrew Pinski <pinskia@gmail.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Mark Rutland <mark.rutland@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/compiler-gcc.h | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.=
h
> > index f805adaa316e..cd6f9aae311f 100644
> > --- a/include/linux/compiler-gcc.h
> > +++ b/include/linux/compiler-gcc.h
> > @@ -80,7 +80,11 @@
> >  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
> >  #endif
> >
> > +#ifdef __SANITIZE_HWADDRESS__
> > +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddres=
s")))
> > +#else
> >  #define __no_sanitize_address __attribute__((__no_sanitize_address__))
> > +#endif
> >
> >  #if defined(__SANITIZE_THREAD__)
> >  #define __no_sanitize_thread __attribute__((__no_sanitize_thread__))
> > --
> > 2.47.0.rc1.288.g06298d1525-goog
>
> Tested the change, it does fix the boot-time issue #1 from [1], but #2
> and #3 still exist.

Thanks for testing.
AFAIK #2 and #3 look like false negatives, which are tolerable (not
great, but it does not cause serious issues).

> However, perhaps, just fixing #1 is already good enough to do a revert
> of the Will's patch - at least the kernel will boot without
> false-positive reports.
>
> But I would keep a note that SW_TAGS doesn't work well with GCC until
> [1] is fully resolved.
>
> Thanks!
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D218854

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNP5Sny0Xj0JeHU8SFFsNvgnQQ7-c3PGDmiH9RVnUF5YTA%40mail.gmail.=
com.

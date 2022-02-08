Return-Path: <kasan-dev+bncBDHK3V5WYIERBU4JRKIAMGQEGP3JGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E72904ADBC3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 15:57:23 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id a13-20020a2eb54d000000b0023f5f64ae4fsf6195326ljn.4
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 06:57:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644332243; cv=pass;
        d=google.com; s=arc-20160816;
        b=SA9gLc+oRufqnh1gAlpF9XnDk3qbIs9RUh+eQ29iT7l9V0L3VFIgP3hG3/C0eLkYHt
         HMZ9J4PJp46NYbFniBMsPcje7HRlbinwMjjjv4Wg8YOWEtDG/d2ygZz7tLw3dXp5z/Kr
         2VHbukM5WhM0fT0+ElJEgNZ6FEMklMI6tdORHymsYiicFfdEopQoMWQqqap92Xpq5eLM
         QxQtOmRDnGLhBccKW+2wfeJEQjR08G3AhDjJ8InE6ytYYJqtawDsWwAPGJYAqrKHlCJj
         sk/5h1rrI7TrqnKtwLsL+qWa5hdH4FxUGcRY70gsnO+cLAeRZ/A9DwLLZ+7qVbLP5RK8
         /f7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=uekAxYXBFgmleqkSrP+Hk+rEzKtAw2SmBeG6GFPkWbI=;
        b=GiIHTy6JX0y9HEBUVwHC+dqdJsmy+ZIdBYPdvaKnKAZb6gIgqPtMitkqvVDbb/Lwzg
         4/KcXrxeNvY7uO3SSWcvlIW76QXRlh3oDsVUmL7Xww2GYRlyJf2LLBfb4nqZRw4wlimU
         H3aTAxc2HznNgcp47siKP/RxQimIRspreZVfyvDQmlx8LkQm3VpjzIts6zkQZR5jCUeH
         QFgZMsfLpRvwLSzBradD4UTTTcYLUhY+G/k6KiktSOTql/fzso4ECty2x+DuYEU4Oi5L
         CP7TowZD9Lf6BusLQzMXXWXCZSOTUWmXQ7qJulgUPTLEPsydPSMW3jgRzEMJF3S4t+Ts
         YBLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jeUTJv7b;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uekAxYXBFgmleqkSrP+Hk+rEzKtAw2SmBeG6GFPkWbI=;
        b=MbuwEWOM+7xkUtT2r6snihgLm0IKfY4O3VHYX8QlOw8as5zoOa0bwH7C3Rx1FjAE5g
         Po2obqmwBBrdbq5JgHW/gOUZjzlULjgEFMcpr6jR9eYj729zjempQFrcr7yDdX6dWxfe
         1bcRU6LS3DakiIqrSkFcyUuRjdzh3L+URjeNNvjnBNbvbI0xe4+m4ugKh5zpPBTBdCYZ
         mDnm5bU8yZ9GNsT1K11jTPoJ0ZA0+TKWE4nDaxZbvWkBCPxmv5KBjqMVdezb+ygu0i1R
         sU1AuxNjshtvmqfcz92GZ2LmvEkcykF/MBACqzpKFhi+Z582sRB058/H7O5poxDic6RD
         A4mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uekAxYXBFgmleqkSrP+Hk+rEzKtAw2SmBeG6GFPkWbI=;
        b=w2FvVnmfLqgLD2p+CpiXEwpw/5IuMzNnBxbIXXQwQzvTCz0OLIrjmB7TeeaVaTC/4w
         hF16UUWkGDKIuXxFPTRb4lAd9ji3Ry3yxbq3UJ1ex6aaMK6aZ7He3gllTNUr9v75226L
         H2XuTYWpmB/uULGtRfFIW0Dg9UKrPPPNBBppV/qVRLeqFeu4ElJOyPlU1eeQm8SN5UmZ
         bAOFrnaYaCRXMqxxCnr5x/L8aCbSPQw+JhRrQtXtK8Md/lzge2axaoBP0ZG6l91Gxymt
         sKLljbJri2JsqO1h+k/j1kbw8ciIn1OnU13R1wx8PD3TnVSW9yShyI2/eG8DuvupXd1b
         q7OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308f6gpnU73i96noSQ+S38Onde+ge26/egrsnC9+RAgZ5FJY771
	CuGCrW0nbXnCnDY9VIsI474=
X-Google-Smtp-Source: ABdhPJxwz/Jh1XsrwNhL/osVXKNb0l72jmvyWX6QJD2icmkfrRDOmaEyLlPzcF7UFLBv9sjnpoiPVQ==
X-Received: by 2002:a05:6512:308e:: with SMTP id z14mr3185935lfd.104.1644332243409;
        Tue, 08 Feb 2022 06:57:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1599:: with SMTP id bp25ls8127452lfb.0.gmail; Tue,
 08 Feb 2022 06:57:22 -0800 (PST)
X-Received: by 2002:a05:6512:3d0f:: with SMTP id d15mr3241521lfv.77.1644332242443;
        Tue, 08 Feb 2022 06:57:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644332242; cv=none;
        d=google.com; s=arc-20160816;
        b=bTYWIBqo2jWfPZVQN8pjNi6jrVrUoXlHjNzI8kRwyC+bQEwmiQsgUI+PZ9JI7j4B5U
         c1SAfhXk2c3jy03z3drTl0KIGY4mqs75+8gAB9jprC0ooF3L40R+EpXyVvFfRgTiuS88
         R+R0LDpDZL1oPzp3eJ1IaP0n3IATMzgpxGoPpduL0e9cXfX7SWme6BdSh20QKCjp4HiW
         3emwN1Yy6+9h9gz3NgZBkgEsoURfobtW3hmHnfV7zXKlG68VZ1oeikRoBsCrunFpdYkK
         WuUXOdXlL1mqXYnw9IMH8C3Wg/8m7DR68tcT3WPwfE39OuYemMTXEDjBkQ8AJyJko2aM
         2pOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EPGckZDXD5dKY+OHvFvXimjXLNAanNMSNprTgL/Df4o=;
        b=dKswa7MleTvxXhx+vIO2SXirExkgDdEScpcaYbBKh9UUVaQsRFfzuRLgIeTz3ZEpYB
         XaIDuuZbKUUUh4i9ftrI/ldyKbviDs9VKqgCWtBIj60JDrTAhQaQ5vqP6XEvEcMm/yoX
         ywgZBDMYJZAJ0V4Xk9ejIjoLmc/xi6fRP5cXCXiloKBCZhHeg8nvNn8TAdWlrF65XNuK
         f7J++8jxHD3Pnq4rC5FxYAMWI+ivJrhRA03kmlNriEMlVnLRWpPQmOFLLqmf6h7o8H0N
         uzZUnsKZAWbCGUMw2qJ49Y6c1HEjIthzdlNALEkjL23Pxuc0V9bOVA+vHwO3nQUthWph
         Utzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jeUTJv7b;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id w7si619271lfr.2.2022.02.08.06.57.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 06:57:22 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id ka4so52900729ejc.11
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 06:57:22 -0800 (PST)
X-Received: by 2002:a17:906:7497:: with SMTP id e23mr1166199ejl.62.1644332241776;
        Tue, 08 Feb 2022 06:57:21 -0800 (PST)
Received: from mail-ed1-f53.google.com (mail-ed1-f53.google.com. [209.85.208.53])
        by smtp.gmail.com with ESMTPSA id re22sm1594582ejb.51.2022.02.08.06.57.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 06:57:21 -0800 (PST)
Received: by mail-ed1-f53.google.com with SMTP id co28so10928618edb.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 06:57:20 -0800 (PST)
X-Received: by 2002:a05:6402:1681:: with SMTP id a1mr4855489edv.167.1644332240523;
 Tue, 08 Feb 2022 06:57:20 -0800 (PST)
MIME-Version: 1.0
References: <20220208114541.2046909-1-ribalda@chromium.org>
 <20220208114541.2046909-3-ribalda@chromium.org> <YgJmaDJTGTmRgNIy@lahna>
In-Reply-To: <YgJmaDJTGTmRgNIy@lahna>
From: Ricardo Ribalda <ribalda@chromium.org>
Date: Tue, 8 Feb 2022 15:57:09 +0100
X-Gmail-Original-Message-ID: <CANiDSCu_QCbTmvrwDsrEeoMKoc4JN1HmQDDCKnYdQTtWUgWnPQ@mail.gmail.com>
Message-ID: <CANiDSCu_QCbTmvrwDsrEeoMKoc4JN1HmQDDCKnYdQTtWUgWnPQ@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] thunderbolt: test: use NULL macros
To: Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jeUTJv7b;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi Mika

Thanks for your review

On Tue, 8 Feb 2022 at 13:47, Mika Westerberg
<mika.westerberg@linux.intel.com> wrote:
>
> Hi,
>
> On Tue, Feb 08, 2022 at 12:45:38PM +0100, Ricardo Ribalda wrote:
> > Replace the NULL checks with the more specific and idiomatic NULL macros.
> >
> > Reviewed-by: Daniel Latypov <dlatypov@google.com>
> > Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> > ---
> >  drivers/thunderbolt/test.c | 130 ++++++++++++++++++-------------------
> >  1 file changed, 65 insertions(+), 65 deletions(-)
> >
> > diff --git a/drivers/thunderbolt/test.c b/drivers/thunderbolt/test.c
> > index 1f69bab236ee..f5bf8d659db4 100644
> > --- a/drivers/thunderbolt/test.c
> > +++ b/drivers/thunderbolt/test.c
>
> You could add these too while there:
>
> >       p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
> >       KUNIT_ASSERT_TRUE(test, !p);
>
> >       p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
> >       KUNIT_ASSERT_TRUE(test, !p);

To avid keeping spamming the list. I have pushed my series to
https://git.kernel.org/pub/scm/linux/kernel/git/ribalda/linux.git/log/?h=kunit_null-v5

if there are no more comments by tomorrow I will resend it to the
list. Maintainers can also pick the patches from there if they prefer
so.

Thanks!

-- 
Ricardo Ribalda

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiDSCu_QCbTmvrwDsrEeoMKoc4JN1HmQDDCKnYdQTtWUgWnPQ%40mail.gmail.com.

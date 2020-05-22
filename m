Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJOVT33AKGQE3RA3LMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AA7121DE486
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 12:34:14 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id s199sf3139990vkd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 03:34:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590143653; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtwlQEMdStWkH0TZmnuf/emzDUs7gwCr2vmzkLupmUnm6OOmSJDQY2fVKXqB/fGcp8
         lbADgNnUi477pgaRBLHt1GThODn6BV0uFduKmGOGE+YhoSaKnV0q0mbkSTDdHfVJfKAP
         cU/iKbSOV2rs7Z1GpJzPjHfHUc3H9LFj4okWxPY5/jYpQf9/MfO2H9OmxtJVzRZIrkV0
         DVrEVjJ36NM+Na0bK5Ok0cEJao4ZaIY3UKhpItwXgCyC7zqE2w8RxD9oKsq+QWutqVBl
         mnA7RAZ6HYyftwFdWlAJ6y93bDW4l2VYJr9/hGRj4IIOOLBuAqSoKlzyRCXjVLpDx//E
         M6fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nJizu8THsoxnOhZquOmivg0EohDdCeeqke4dYFM2zqs=;
        b=sPWWMyt03QU9nFCfMPDQ/L4eYcfNrmGAT1fTwZ0K4x2fjjVoVjRznmmMKtW7lkEh1t
         RgIVGcxuVjaWS9BImxR7U/FeCjJGHOyAOh9cfv0BtVpBbVIji3JGZLPB0uN6eiqs2WJU
         J68pXDlnzSjB3619+HVP0RcgMsy+wcpWEUqCIlhsVrW7zX7NM/PO9OtwTg6g1xZJxCcj
         v+85Tp7iD/gAVJTtlqwuAuMjutdGdhVoQWzBMTI7AVrHgkgmgFq/wOI8WJ2MDKHOFFFN
         sjxw6VX3vDj+wasIgcwITBhNWvVeolhgNW/a6ZsAWDx8BeQ5cFLawlckVDZ0Ht2Qx/hn
         wlTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+p4rL6d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nJizu8THsoxnOhZquOmivg0EohDdCeeqke4dYFM2zqs=;
        b=W3eJqfrmNHFtjGtlEuHIs31HOYuUNNc5EFFBJUT71h0JrZZcGow7n9aB7SHGALu+dS
         bFu2JOTxjTxyzrJGA45wz/tk6GZlzYNyyB1Zio2upIBcAJP+zG1DegywgJpVNVywZgiB
         rRalHVrBPcHEsgPiY4PMdxvoXgYCyR7EW8+KyDemKgyWbCAmGJ34PMynB0thgCBvjcOS
         sRltNYOygq04z6riWZ4qc8WNMKjecbx32E66ggaKbuqv/YwL3zrj/zCvTEA6bSN1cBXP
         s1g3EaUFc9aTTaEonxtdTPc/T7Qx6V25KNltqXglHbVr7PShuaQxh1S+vRi8MbSUR3r5
         SUYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nJizu8THsoxnOhZquOmivg0EohDdCeeqke4dYFM2zqs=;
        b=ltdWu8uNaUIHPY6qhC5qSjZvXOkCxp6C2ralndKM7BzLq/RHVLuVJEeXMUug/DCUfk
         dm+GhsJ4O5eIlu0Yp8Up5RUULHFeCZ+Z9YjG8b7C8cNBEPrhn/7vQYm04yIfdjVQOcen
         7YAW+7qnly6t7Jv+sazN/18hMJ28Bz0Cm+q8LIhyAFUZd8HHUabldE3nCJl0SmEt22Z/
         82y1BECdjY+w3FCVSBfAPH2et3MYlXdKWWLhuS1vY/dwgmbsRERkgSYyuucL6VYYxWT/
         yr3eQ1+e4OXRh4r4usIr/iWG3jdFKXorjU/CRm4xA7+iRXbJrV/PvyCdGYpwFFi9fneV
         ynDA==
X-Gm-Message-State: AOAM532pEOYargYOicT0dD0ZnRQ+PjaoE8zdXltqNMFA4XWQcXJAtkG5
	/D43qhxReXve6T4FWyFclew=
X-Google-Smtp-Source: ABdhPJysiupK1U9/evH9omVZ+tc1Iwh7YRPLbaea2/VvAiOm8RxZMKssVoL39l53gCg+nsAeIUdwIw==
X-Received: by 2002:a1f:a786:: with SMTP id q128mr11337437vke.86.1590143653594;
        Fri, 22 May 2020 03:34:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:7b8:: with SMTP id x24ls80869vsg.11.gmail; Fri, 22
 May 2020 03:34:13 -0700 (PDT)
X-Received: by 2002:a67:c299:: with SMTP id k25mr11060714vsj.153.1590143653078;
        Fri, 22 May 2020 03:34:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590143653; cv=none;
        d=google.com; s=arc-20160816;
        b=Cc/XNuw+0G3LvznntKfyjlUjtmJ/vbzIYpYlZzQYoHNj4IGT/ddTNW8eUyxt13F41U
         b0Kzwy136aHmXsXetim4aNlqX1c83MgXQeIu0M0FXseOJGGdkAj1O49Vg/6XmemhsL3p
         5z9BOlyS/cpFi72YQfHcvPuYpJdriWDRMjFjptadrfYhAS5KgBRMYp4wibc7Bb28PY0T
         L/dGo/1DAZSNWQIzeNKSJe96y0rlvnWiFwXoNbEjvmjx1ElxuQBfJJX/lymd3chDdHvM
         w8jKbr3lw2zclbAiLfuebTwHJKggqM02QIeYNWwYKWE4rE1CwD+ld3BXJXsJSiyn5jsn
         GzAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5ktmTy4SBF1rMKSXisJeFl7NM4HKoH9GRsdYqKi4Yhk=;
        b=kcUhBrDJiFyUYJCspZV5Q7rZ8auk6oAfm/dDmowQ9Qz8gCbZoUEJ1kQEz9s46pMiu9
         QBTKzTUGViQsv3plX6jXG9bsOQqiiORlEBg9DEOBwWzaw+qCGl2s5x1Am3CbN5dLomMF
         ovKRx7WF0KoLmfUQ6pY134XU0FZW7Hk5KGXLEGAFy587WaKvwko2WrKiNqmP5IWOZs5f
         gRZq6sODJUfcqnUrgTqOTl2LuiKHRxvNt+LoQJj1w/T7cniCRirVdTaoguvwe20Y+/NQ
         /WSXA3MgszQFHwyzAVoWtGc0dj+vg6Yjl1wQZk14QWP1PJIBEVlvNnJfm7PCljnU7bgd
         epKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+p4rL6d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc42.google.com (mail-oo1-xc42.google.com. [2607:f8b0:4864:20::c42])
        by gmr-mx.google.com with ESMTPS id a126si396979vsd.2.2020.05.22.03.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 May 2020 03:34:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) client-ip=2607:f8b0:4864:20::c42;
Received: by mail-oo1-xc42.google.com with SMTP id u190so2051970ooa.10
        for <kasan-dev@googlegroups.com>; Fri, 22 May 2020 03:34:13 -0700 (PDT)
X-Received: by 2002:a4a:e836:: with SMTP id d22mr2501899ood.54.1590143652013;
 Fri, 22 May 2020 03:34:12 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-4-elver@google.com>
 <20200522102630.GC28750@zn.tnic>
In-Reply-To: <20200522102630.GC28750@zn.tnic>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 May 2020 12:34:00 +0200
Message-ID: <CANpmjNM=aHuTWFk45j8BwRFoTQxc-ovghjfwQr5m4K3kVP8r0w@mail.gmail.com>
Subject: Re: [PATCH -tip v3 03/11] kcsan: Support distinguishing volatile accesses
To: Borislav Petkov <bp@alien8.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r+p4rL6d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as
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

On Fri, 22 May 2020 at 12:26, Borislav Petkov <bp@alien8.de> wrote:
>
> On Thu, May 21, 2020 at 04:20:39PM +0200, Marco Elver wrote:
> > diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
> > index 20337a7ecf54..75d2942b9437 100644
> > --- a/scripts/Makefile.kcsan
> > +++ b/scripts/Makefile.kcsan
> > @@ -9,7 +9,10 @@ else
> >  cc-param =3D --param -$(1)
> >  endif
> >
> > +# Keep most options here optional, to allow enabling more compilers if=
 absence
> > +# of some options does not break KCSAN nor causes false positive repor=
ts.
> >  CFLAGS_KCSAN :=3D -fsanitize=3Dthread \
> > -     $(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=
=3D0) -fno-optimize-sibling-calls)
> > +     $(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=
=3D0) -fno-optimize-sibling-calls) \
> > +     $(call cc-param,tsan-distinguish-volatile=3D1)
>
> gcc 9 doesn't like this:
>
> cc1: error: invalid --param name =E2=80=98-tsan-distinguish-volatile=E2=
=80=99
> make[1]: *** [scripts/Makefile.build:100: scripts/mod/devicetable-offsets=
.s] Error 1
> make[1]: *** Waiting for unfinished jobs....
> cc1: error: invalid --param name =E2=80=98-tsan-distinguish-volatile=E2=
=80=99
> make[1]: *** [scripts/Makefile.build:267: scripts/mod/empty.o] Error 1
> make: *** [Makefile:1141: prepare0] Error 2
> make: *** Waiting for unfinished jobs....
>
> git grep "tsan-distinguish-volatile" in gcc's git doesn't give anything.
>
> Hmm.

Yeah, my patch for GCC is still pending. But we probably need more
fixes for GCC, before we can re-enable it.

We restrict supported compilers later in the series:
https://lore.kernel.org/lkml/20200521142047.169334-7-elver@google.com/

More background is also in the cover letter:
https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM%3DaHuTWFk45j8BwRFoTQxc-ovghjfwQr5m4K3kVP8r0w%40mail.gmai=
l.com.

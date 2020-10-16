Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOBU36AKGQECW4SRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EDBD4290655
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 15:31:42 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id k9sf2458533ybf.18
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 06:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602855102; cv=pass;
        d=google.com; s=arc-20160816;
        b=Duloff4D8pc5VLx7TeIQqlb1D6NnkYE6BGUcAkqOrk/m3HpimkyyCvjcBtMBOilp5A
         BLVJIRaHBndBafi9WNDToI1Vvo67Bu/yFhXwC8nYaWRRtANlcU5zI7jL75RwMvvSPNUv
         Z9HGqJcMrztIzOLK9KZqjm2ZJ3u/GipNW3d3VIoi8vnNNWZVIWrjICTnJZtPhKWp7G2o
         irPc1sgyMejHN3YVx4t5cds7wElqvayxoJ2T2RX1vhFHOV2ixWTZN7Gmn+eq4/GISkye
         K9fdSaLw6Y36r31fCQxi2JsvchhWczKfxzFTi7IYNWLotoQ+gNHorTeK/uInpkBCpvCB
         0NJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xHojmpQ6Hc9yJBmg4ogbYvsZ1PSOGXLJfkkrE8WY3co=;
        b=UdELxrYVQLk+d7T2klMY9On0Nwhq6sd743WQ23gp9EApiQJuZ1U4+IYuNeGteY7b94
         wr5DEvmsf/XQ05vM85rUnBEiy9IMsTyPPYqvjyIvFzwzWN/M7mxgLuT66LYkvzlAixmP
         8Q8xxxD7oGEH/cKOM3ZYqE6pUPilqMflnVqxo0tTTi4Q/2zNEwN58jckvESg0ovCt1o+
         KuThCTv2TD7UY1UAVWMEr8ESL5ITCUsolvcRXRZ254JiF5tn93F37HxFnj8oyL8eWZk4
         5CIMYwFosJwBOwh8xxIOYjDGByBXIcTuEu3d3ZI9lMQOr1YqVAuycycxRVCWXmxPiYpg
         +lig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oiLCg7IW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xHojmpQ6Hc9yJBmg4ogbYvsZ1PSOGXLJfkkrE8WY3co=;
        b=E1gfSLoLrmNrICntlTkAEkoME/w3Pc0Hbb2Ekhjpt2pSD9G41uLhoSFc4QFkwzUnSV
         4i4IIp7ICNsHYPlJzQX1nQy5UBW322byXjKGE/5gOljwbjdG1+/cvHHKrVdLHtHM4N7B
         baM3584OOcla+XQ/jkr2BEgKKAjPYpCAWTG7a1WiAg6pSxedWJBRPgmgP8JRN4aiD0r4
         Pi5IT157EfZIohHzVJoMuaM3chx65xrtIuMYmarZyZAKD4zp+4/suQnVph/JblR2OJ51
         lBVnO/xlNplCvbwXAYULVz+Z/lVrK/gpQ0yFg+UzryBhVlQk7QXel94Sq+8kNI3n8iKO
         bxhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xHojmpQ6Hc9yJBmg4ogbYvsZ1PSOGXLJfkkrE8WY3co=;
        b=STMJVkA6SkKAkORV4JbmVHbtPNtwnDiUpdIg7hyCP1uQ/Wr4mUif1ynNUrVx6L8mhR
         wqPvWddXicgsOuZoHkfsi+yoLjVYhDj0C7B76jHpHi7kmAZWpdb7y4Git2SiyCpC1+3u
         wuXObFV+NkZtl7O/XNJah64lv9OSukdz2mgoyMg0Mol0Wjdp6YLsvRbmRmfSKNtLufzd
         57GJPwiss3uYBWkYr1pvtAC00XaR0N3QvXHyDxgvy2OL8wwp/ExfXgzdLXJUWSku9+cp
         6XqugpNiQ0QFXMMPUfi0jSreSGPmqx8J+e8igKm+naNBa8yf/u3fidY5+KdsMmaYds7W
         nq6Q==
X-Gm-Message-State: AOAM531KhthE8HNUlZKRTsO0rxqfKGaOUmw9HoR8UUuFKD4SiN/njy+9
	tZAkc7gOmomFX6i+3Vj3Ajc=
X-Google-Smtp-Source: ABdhPJzMukc45kxyHk05lGeIXrFe1XKqdGW780886CZ5iM4asGkR0Ae/EPg60qssH95H59NjZWAblQ==
X-Received: by 2002:a25:e087:: with SMTP id x129mr518596ybg.242.1602855102033;
        Fri, 16 Oct 2020 06:31:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a0b:: with SMTP id q11ls1361952ybq.8.gmail; Fri, 16 Oct
 2020 06:31:41 -0700 (PDT)
X-Received: by 2002:a25:6585:: with SMTP id z127mr5540709ybb.33.1602855100504;
        Fri, 16 Oct 2020 06:31:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602855100; cv=none;
        d=google.com; s=arc-20160816;
        b=YK+lrM/b24TC5FSr6lJhX6NCL1R+ClBz+bD9GuSQ6hlfXcJcsw+VQ1tc5C/a7/9TQq
         X3+v98suvMTUYoVpM9yeNR8+DxWYZjoWGy8RlB9VuLp4IUeWNUDGcB5wE/y4fdcqS4UK
         dqEup1xd4zdFa10/E8q1xXWkYZt9y2hcCHtbaCp799XfI2Ve7MeHeO180gLxJPypPjlw
         0WNc0KPv6iKyuXSnaozSGxl+15sHIIUD/9kA1jOmOfK9ssZy6jJa6PWNKKzLJN6N3qsy
         o22/2Z8IBPCiI13vqoceCmPbi9qC4UB1NO+z51UpAZ7TUhToNR6d/XHjSGn+9IYE5s7Q
         n9jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5QuvgoP2s4jo0WikDSiJUcCamsSLK3zQlawt0pcsDSM=;
        b=X8M4+cIJKLNFg3l/DkmsiUA4mw+tNyJAKi9UiNnZIinf4x50SzzHqEgbzVvu5Pwd5e
         dHCo29mP1gu3WqvXqqLeuI3njb/4yiYWzi+nPBx1/O5zMGPsDE1BbMxdDt4C1B5XeP/p
         JP5EEMH4crhyhHR9PdPj6AnBoecBSuUtVDJD4WAHdQtlIZWS1EjmXIwXOqsMAtplzQ/Q
         4zWrqn2pcrTiLf+Bu9hbk822EN5lO+O6XY9og19rfRiORjDmZt9Q7X/7TWscj3CXqdlT
         YRF2y+ejoJTFWxTlG96EaEtO/Iiixg94SYE/tpB/+Ffd87yn7K5vr4Sf+zdooDO4fYGn
         umWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oiLCg7IW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id t12si182486ybp.2.2020.10.16.06.31.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 06:31:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id d28so2421792ote.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 06:31:40 -0700 (PDT)
X-Received: by 2002:a9d:34d:: with SMTP id 71mr2403102otv.251.1602855099909;
 Fri, 16 Oct 2020 06:31:39 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
 <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
In-Reply-To: <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 15:31:28 +0200
Message-ID: <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oiLCg7IW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 16 Oct 2020 at 15:17, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
[...]
> > > The intention with this kind of a high level switch is to hide the
> > > implementation details. Arguably, we could add multiple switches that allow
> > > to separately control each KASAN or MTE feature, but I'm not sure there's
> > > much value in that.
> > >
> > > Does this make sense? Any preference regarding the name of the parameter
> > > and its values?
> >
> > KASAN itself used to be a debugging tool only. So introducing an "on"
> > mode which no longer follows this convention may be confusing.
>
> Yeah, perhaps "on" is not the best name here.
>
> > Instead, maybe the following might be less confusing:
> >
> > "full" - current "debug", normal KASAN, all debugging help available.
> > "opt" - current "on", optimized mode for production.
>
> How about "prod" here?

SGTM.

[...]
>
> > > Should we somehow control whether to panic the kernel on a tag fault?
> > > Another boot time parameter perhaps?
> >
> > It already respects panic_on_warn, correct?
>
> Yes, but Android is unlikely to enable panic_on_warn as they have
> warnings happening all over. AFAIR Pixel 3/4 kernels actually have a
> custom patch that enables kernel panic for KASAN crashes specifically
> (even though they don't obviously use KASAN in production), and I
> think it's better to provide a similar facility upstream. Maybe call
> it panic_on_kasan or something?

Best would be if kasan= can take another option, e.g.
"kasan=prod,panic". I think you can change the strcmp() to a
str_has_prefix() for the checks for full/prod/on/off, and then check
if what comes after it is ",panic".

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A%40mail.gmail.com.

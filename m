Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2PP7HBAMGQEWG6EQ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20BE1AEB573
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 12:52:30 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3df2d0b7c50sf20460815ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 03:52:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751021546; cv=pass;
        d=google.com; s=arc-20240605;
        b=lpKV4xZOoVvh+/uAU4TpStpDvfWrJumf20U9TRVYlc0zAYhHjsoEtqFYfjIXOmx5jV
         KfbenQDqAdA3PpxibuB2SQ/MXNcNr2hFFHSctKdM3MsTA011ijZNwKmM1zsE+WrUVwWE
         aI7cABwpW7Pev0fcsPtg6Xma/nxo5Ese0HMh8kdegEX2OTJmgH3aS7xmKDz6mlG/BDDM
         fjQ2JE/ojBBzZjtcC/mJ5KHZpe5wpCLqHXh83CqMl9e0a/SOlrIhX3zNDKtmtUz5lHDR
         0inY9eo21TtAcH9otDN7f+uxnvNIZ6aFICH68UaRQv+ymrcnrfvl6IbAup71xHuZoM6X
         EMpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0vT4i+KbTVCxUv1kuEnnlFwogibKsPyxYrjQHaIj9+4=;
        fh=ExKW0oYYmts8CEdqwr18SBBl37fKJddxK9pdkSI3oAs=;
        b=YdmlvM3VQEDZTjQgHM8fNTy7hIwH0qb/ZDds/ISr6JaMUBURAEgeBc6440X4V5BgQu
         jm0E6o0YJyWUbqSXPLRZcyqicl7TTxJLytPoiGCngDviD7I5YjHRoZUAW8zWlXFmIV45
         kD0byFcrnE4bu7ZsOJUH+1T0u4IeguM6ZVhWnrj1Q9TPloqK9Z4mypZjqbgaLez7fYzo
         ShTVW7ZHmFbId8IZPxhNQocyl+7qiRDAbSHgIW3Bp1z4QAfy+CDMBDACXeOFkkhYobcX
         2dCJf0t7D6+wK5+tltfQH6jqS+DfBJwJqUh5/vZ2NSCg9EqTJZ2geLblallmkyfKOOQe
         l/1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qCcylkQ+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751021546; x=1751626346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0vT4i+KbTVCxUv1kuEnnlFwogibKsPyxYrjQHaIj9+4=;
        b=k/FfybBwSZ+BkxrsUFceUZMVzDK7IpdRA4HSi341Asb7Jx9mK4EsUi1iaohX27sYUc
         Crnj7fV+5YxnIUIv0rl8IOe+6POIfm+SRTX++NF+3Wm/CyHeo49d8pAaPDKFFD8cputL
         ButTVk86+4i80iDmKQtTl3M77ZqmOBA63scVKL7XWEy1zfj9ww0yZrn/eL9KZ6RKBftu
         KM8/jkyogKHaKnzOKgKn07J4WygBeSeS/cTY5iq5ZZvIiQt2IyJlamVi1mWkKG+HVRlT
         9n2JEGzfljtHUC6uzwP01qs7EE6rhTF9o9EKnhKnQVJYDZ1VzeeVijiKNT3swhwfeV63
         ylsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751021546; x=1751626346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0vT4i+KbTVCxUv1kuEnnlFwogibKsPyxYrjQHaIj9+4=;
        b=p30BarAOBw2xuTOq0kEbKJSaUiwaMfOWTf2vK6UFi/Qxz343rUfVXkMzck3ZP/+5rg
         NQctBbsdtY8AMzwrmORMJ1DVs1F1vedeOcu+2RPcC5M/h8Wsswvpi4i9/5FEkD4EUTLU
         UpiS8YyeyCGXSyGgTVz2CpQOu5suI2L+mdiR3lCsHlM/NJ0jNl/Wm6ku92Icr+bnktME
         qlkjtJH7fSmgK4Vaz9oLvJ0Lu0V2gSDFtigs95VFFGrTMyB+RQqrukw5irF0FiIP0f17
         L0gjevNR87koJzMxiHYQWQTWBjiBaK04lDaeUYecZfl2RjYhnKqap6KWki9ER6ONcZ/3
         CJeg==
X-Forwarded-Encrypted: i=2; AJvYcCVcPe+uj1slDVQsDOkO/s7zi3WhGJI40tg4vSQ306MybkelQQUXjs1Ys61e+fYzjJQft472Ig==@lfdr.de
X-Gm-Message-State: AOJu0YyRyp/hCOYyh6aw4uRn4CutuN1nD/mK+QyuHGk7xFTcCVGmkySp
	pCFVS4Mf/KTJc+t+tTHt/QToJwMC/TzI411sp1tCsM/M+I3OIjFTbeJt
X-Google-Smtp-Source: AGHT+IHQx6XmFmSXtxws5Oj/2kSRQ4rjsY3a7QCcyl5/ALolCeDtkmY/VPh95UJK0gQBpZOhIi1dag==
X-Received: by 2002:a05:6e02:b49:b0:3df:3a07:a208 with SMTP id e9e14a558f8ab-3df4ab2b877mr37446575ab.4.1751021546114;
        Fri, 27 Jun 2025 03:52:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdH14hZ6BNsbL0sb6w+Bkl9DD4uBoJFZAk3JRyT2q/PjQ==
Received: by 2002:a05:6e02:cac:b0:3dd:be02:185c with SMTP id
 e9e14a558f8ab-3df3de17ae9ls13357615ab.1.-pod-prod-09-us; Fri, 27 Jun 2025
 03:52:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMvZ7U2nmIiqEAnyf1Cdc6vX+fh8T2pVDoryHw9FteqvHhc/XwuPUxeidn8T/cOqu5tcRBzxY46eo=@googlegroups.com
X-Received: by 2002:a05:6e02:b49:b0:3df:3a07:a208 with SMTP id e9e14a558f8ab-3df4ab2b877mr37446245ab.4.1751021545269;
        Fri, 27 Jun 2025 03:52:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751021545; cv=none;
        d=google.com; s=arc-20240605;
        b=W0JJbFYR6aR/TMPoC7/os+9kwXAD13hmcTlkgaPAaOjb+beSZK5ODJTcMzFS7NQ44a
         e9ibYS+SbPeRjHyHF2SsPJMy5iNx7mVXfuWc4nLMLnCEPcT5pNXnYTzfNJR0o6sUQSZf
         PqOz1Sj7HGfvFlB9SpGiPqxESEmUMalSJBRyWl/9BmYrdW64Y+MD92U9mCmigMdABOn3
         SbOO9Mp+1BiN4nszgTUdesiT1rFthfBpNmPOCBoKXrP8FzTwzf6cp7dKrSVHIx0edc8+
         FlMZ4JruP5oQn62y7wmnyh5i1GwkXSyAfZva70lsLhCWDsS3ssznH5jtY+nefcZjVZiB
         DC0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=viQz2FoWAMoMRBrUB0vOI7MJY+U2udKXiQsPy3/43Lo=;
        fh=6kAcesfr5VygF1ETRUXvjFta8E2m+TeclqvLqDmDzxE=;
        b=LFCvNCj68v/x9DkU7g67qLOEm+3+yoWRQP/vzRbIGCDWwdGHDAy9nV1063I4KEI/lj
         tLg0Wix38IvMEfNRwkoEM8618wDVP84eS3yMAnIds9T3w3Yo4JfuMAHepM3m0e9auPFp
         WYxIkfFLDZoAktoY2CAyAguuc4sm3Pfa8Gzycrtzq6ba7tXCiGdCBF6P4JQ9Agzq7ybj
         YsNm+aJZUtRVNO6YOAlnDhOnwxg09hvPJPVLiYf9g3gNudy55FggRXrN7w+87FN6Z6Mn
         hpj3Gm6cAE5fTALImnWl3ipdUpwbgBYfqQIEoXjq9AxYMCIksAMZmtdCXjr9VYItogMa
         yKjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qCcylkQ+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3df4a0bfe65si997865ab.4.2025.06.27.03.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 03:52:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6ecf99dd567so23076786d6.0
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 03:52:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVK3Ia4OW5uHb8fYKDSp9TzBd/XRGZ9NnONozGOCHFyOjt1TxtnTjYfU2WqiKBFqOY+Cz88rogfsHc=@googlegroups.com
X-Gm-Gg: ASbGncvHUgOYqTtxQ3pGtbCZvQBQoqIvkKMUIWZSOHgbwNtrpSCwIE6db3WAlTvvMP3
	WVC2RDjElYohLlrWgoor0dYuLN6dmOYbFh0h1acsSaV+dqxA6hhDnN55gHc6aIX7jyfAUD5Sse0
	gRnGhhzbgV/35j0fAEOoNhgNbgy1Dvn5Gha78CRWL5yGPmxD1z4CWc+rWdgdAAfTBhi6f1N87mg
	+7KX5AWzsS1
X-Received: by 2002:a05:6214:2aae:b0:6fa:c41e:cc6c with SMTP id
 6a1803df08f44-70002dec8ccmr47072906d6.15.1751021544651; Fri, 27 Jun 2025
 03:52:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-2-glider@google.com>
 <20250627075905.GP1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250627075905.GP1613200@noisy.programming.kicks-ass.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 12:51:47 +0200
X-Gm-Features: Ac12FXz9ZmEhwn6682BBmZphT053hwX6JSzJtoiQLmtu_EeKs6Hkmz1YSAuN-mU
Message-ID: <CAG_fn=XvYNkRp00A_BwL4xRn5hTFcGmvJw=M0XU1rWPMWEZNjA@mail.gmail.com>
Subject: Re: [PATCH v2 01/11] x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
To: Peter Zijlstra <peterz@infradead.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qCcylkQ+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jun 27, 2025 at 9:59=E2=80=AFAM Peter Zijlstra <peterz@infradead.or=
g> wrote:
>
> On Thu, Jun 26, 2025 at 03:41:48PM +0200, Alexander Potapenko wrote:
> > sched_clock() appears to be called from interrupts, producing spurious
> > coverage, as reported by CONFIG_KCOV_SELFTEST:
>
> NMI context even. But I'm not sure how this leads to problems. What does
> spurious coverage even mean?

This leads to KCOV collecting slightly different coverage when
executing the same syscall multiple times.
For syzkaller that means higher chance to pick a less interesting
input incorrectly assuming it produced some new coverage.

There's a similar discussion at
https://lore.kernel.org/all/20240619111936.GK31592@noisy.programming.kicks-=
ass.net/T/#u

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXvYNkRp00A_BwL4xRn5hTFcGmvJw%3DM0XU1rWPMWEZNjA%40mail.gmail.com.

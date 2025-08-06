Return-Path: <kasan-dev+bncBCMIZB7QWENRBFOPZTCAMGQE3F3ZWEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC8AB1C3F4
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 11:59:51 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3b785aee904sf2884903f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 02:59:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754474390; cv=pass;
        d=google.com; s=arc-20240605;
        b=F9JM+B9wYV8fNvlqLAlKpH5n4EfHatgGUKUHUo3TZ+syMBeOMA5CYHqFsIxt56VCkV
         UNhY+/8nEs9eVIgRgOseq4IaDCc2ySkoedkHas54L9J1YnIE8Q6vP3I8jdYlX9Ji2sWS
         Vn2bO6QzNiUXrmaREshiiM2TwYuUZ9ifSz+cSUEYcBvmRIrILXsU8/gC5YL3L+cqqibO
         eGjjZxWCnRcCja76pNiiBVWEkywSxZ5zBJ0fazvsJAOQAbdBUHsaGMVLXCd8iqPUDkuL
         +ny9TsyQH0zlmwU8Y/h3v+x3auiNl2qxmkIgKorwZMNS/q2FPldmOhNTzvBrjKwmKh74
         aTrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sdgQ59qfzzvgooDUj1ens5fZ7OxfOul+9Aa5dtQ47gA=;
        fh=Pes73798uPq30JGAqYo5jj8BxvqjMI8G4xvokgF65sc=;
        b=ZV75gDD6uXKSwdW1xY7h2JEBsoV+haUi2JnmADbNt8b7QmGY4EoG6Jd5MgB/lnOPzM
         AxIGdSGziE8jIJP28hkaZ66outBJBny+0jkgWO4oUwQHZXbGsVsFt+5RrRM4NHHthlo/
         nsPZYTHFYGrazIz0Ty1SeB8gr0SQ3IdH3Rje6ur59bbF3pvtw2JKrn607cLCur4ZSM/L
         XWKKHhuijve+ZhwF7gZucZvMtZYsUaJN0bcB48B2XDZlRihUTxTGHH4tZpGdW1d8ar0T
         UfxZd5rJIgznkVHaBC2n0Ugbj/DPkR16xp4uTMoxf4/wyHhLod8vck0Xhrn+tCvU5fq8
         SsnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="T0KX/xke";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754474390; x=1755079190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sdgQ59qfzzvgooDUj1ens5fZ7OxfOul+9Aa5dtQ47gA=;
        b=UTw+EI0dvMuGEE7GiZIc4FR6Kz4mner5ub/qvsP/5kf3TR1uss2+tCoTKf1AuDh2AQ
         SBWX2fgGD++thKv2ZGb6rH3+XyNwgYwq5JA4nfQXFECzLhT16wCifW/uLHxd39gcwaDd
         tCj/ghz4c20BDQnoIXVO8sf1AQX3KxTHIm0btLBMAG4NwOUePKGmFx+D2JWYS8Ess2GY
         hUBPDwZj+H7a+rz2wErW/3zoh9Bk9dyagAFEsxweTBOWr2F4GnvB5SbQazLyKHwbAh76
         sAu1DiyFTq5dIKrRQ+gnIgpf9olwbPkfoiudFuJNoXxXLFCHfzcp2qd7B3jvx3NR27k9
         jT3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754474390; x=1755079190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sdgQ59qfzzvgooDUj1ens5fZ7OxfOul+9Aa5dtQ47gA=;
        b=A6eZavl7bVwf6iWSvnPTHRSJLQ7m/+tIciYKrnHWYIM1qiu9Uwomasf0UHW3eCgLRF
         v8Ka8+PKUatVV4VXw+EK/Vi+j9PFycqohncVYv09+0lkcJfvQEQ7c3zUI4SDuzeaS5N5
         8lmTvFD7iHsyDvDHMqsv+NyY9hTiY0Lxw3PT0/D1Xy7HXJryp+QcjlP1DuUxmLz6Iwpa
         SPfLm7XwC25uHE7QoRezRLutXKlR8i75bb+MD3wwd6C9k5f/M2OHS1c7WogUtdf4AVCO
         5BD/XFtZM3eE9jrU+KThzJHxCRKGx/dHu1T/awILPEW0uXqvvtZk062lACZNNSygKBko
         6SWg==
X-Forwarded-Encrypted: i=2; AJvYcCXgCrnvH5AKuXX9dffnQ7sTG7kEZPZ6x5QqRnvr+pCE1JavdO0ZNtDjKraaez3p+HjQl+9l0g==@lfdr.de
X-Gm-Message-State: AOJu0Yx1A9D5lgxSXTybxjNb5AT3Vk26GmYcoAe4YW6MhJoHaUYDPXlH
	s2rVru7D2iasMMF6lXyNbay/jq0EYtCr2ulzRBT2QiQWIMzhN9Zim56y
X-Google-Smtp-Source: AGHT+IEupJENcmWAjChQT+9wJLirWs+gURW7KzN/768nh7gBBRSJQCEinrgqG0eQAX22r3qR19Bdmw==
X-Received: by 2002:a05:6000:24c6:b0:3a4:cfbf:51a0 with SMTP id ffacd0b85a97d-3b8f41bbb72mr1636947f8f.21.1754474390192;
        Wed, 06 Aug 2025 02:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBmzK5y39ri/aRfPaq0pKI11WlHCnkpcQSzSK8jSudmA==
Received: by 2002:a05:6000:400d:b0:3b6:db:74a4 with SMTP id
 ffacd0b85a97d-3b79c3ceea2ls3165719f8f.1.-pod-prod-01-eu; Wed, 06 Aug 2025
 02:59:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnrfQSigtDHnieuSOW7krFlIroTjzD56mMiBkq43G+YZJB/ekhPDYU2XhXpIPqxCZVgluKQr5X+xo=@googlegroups.com
X-Received: by 2002:a05:6000:2282:b0:3b8:d2d1:5c11 with SMTP id ffacd0b85a97d-3b8f4220c45mr1885445f8f.51.1754474387389;
        Wed, 06 Aug 2025 02:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754474387; cv=none;
        d=google.com; s=arc-20240605;
        b=fiMrmd559mkmuTQDUQe7rNNzf2djaO1W2GvhceO0Sy/xHSQdFhXfejCmJsGrnINXkG
         /gd6Xx0cdsbUrj5C9fKBuLlO0tnMEI/poeZ53W6wfhj/CGhMUs5yKAkJqHF0e13V/XQ7
         w1lAUQ4T3rXDKn/rB27nKFnlwqvYCUbanzbDfZmMB0QKDaNwuWhd5NmQTZfCCiSR0dqA
         VTSMUCtVCh/LEYh4JAFCQWjjZYXJpp4b8+PNRBJa3chq4bmCG6Uk80vk532/nvTNw/zj
         kHxeDdhqx9WEWPcRQPjnVo0WyHz00XT8zlKFh3Sd6FlgMM23scUJ7yQyvBlZ4rj915jY
         Ym/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sAOW6ml3mToRpwXvdxnqACJOhESSTx6u7j8K1+IsIcI=;
        fh=dUYU8Jf0ebjXtHQI1WVZeANJyGGaW4KOQ4W06nM3ZJQ=;
        b=ky5aQ0pcgdSBPejh/tspmPAF/e2CCyLQDzFvDLp/ai3g9YOheFqupeyR9S9FBUJspE
         VlQzNLe14UnGDEFa6oMx9Ard/OtQ5ysmesKj/ac/G7oIA3NEdfKwP253gS7YOZswwgpE
         xIGi+pI6dEZrGuEN66wLRsbhGCbnCyUV1Q05KqYO+6Ppv6v49Rz5zRxwP5Tw/cnaZawA
         SJdXDeSobWIpRZYYFYtlvw3rzEdNxYPUgMZN9jNgDkcZ5uSvlmpSrAQxRN7ypkxs9+AZ
         4J6KZAvjsCv5fPvHhqBpxoq5GMNjhPFLUw5+ItSjb2iUoXGOUefNsItSocqA9HHUmFlJ
         MlSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="T0KX/xke";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-459e35405f9si759505e9.2.2025.08.06.02.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 02:59:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id 38308e7fff4ca-33253a73769so32709151fa.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 02:59:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwGF2WhlqTLY5HQcag9JkJ6tmzI313u95IfvPp4TZrtPa7sYpafc/sCWoaS+cp3Msh8YU81j5cji8=@googlegroups.com
X-Gm-Gg: ASbGnct1B5uu9klVcdhg2D+TK8PmzjJmfp0IzgqS5jynbr6GFANBijlpSbT50UN4Mo0
	e8Wj1/WCmnmCzODjkwqn801kIyiWEcR+U/J+6Xv5g9A6oos88S0nh1x32CvaedVNQr1ZK7yu7A6
	QsOPlhCDcWlZICgDuDIYjW4wdKBDHOqbt4OnEkmefjeh6NBQCqALRBfbRpaiui5KCO1Wuy/fbrM
	9fvaGidzJgijgnTDMCtjq6dKRvHImwziYA6Gu41
X-Received: by 2002:a05:651c:555:b0:332:6304:3076 with SMTP id
 38308e7fff4ca-3338120ce2amr6683961fa.1.1754474386475; Wed, 06 Aug 2025
 02:59:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-9-glider@google.com>
 <CACT4Y+aEwxFAuKK4WSU8wuAvG01n3+Ch6qBiMSdGjPqNgwscag@mail.gmail.com> <CAG_fn=XYS43pefo1EEO6jTTkPHKhB0+hpbh9KGQ5kodAJm3Ncg@mail.gmail.com>
In-Reply-To: <CAG_fn=XYS43pefo1EEO6jTTkPHKhB0+hpbh9KGQ5kodAJm3Ncg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Aug 2025 11:59:35 +0200
X-Gm-Features: Ac12FXyI3YUGwZ39tZWMZ9Wsw2WfrqCosnn9hPEGLahbYFj0RRIAWr5mkPiiOgo
Message-ID: <CACT4Y+bmmYuCbV6g9yk8aFZdzhGhct3K78ii6voHR4KAa6oE0g@mail.gmail.com>
Subject: Re: [PATCH v3 08/10] kcov: add ioctl(KCOV_RESET_TRACE)
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="T0KX/xke";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 6 Aug 2025 at 11:47, Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jul 29, 2025 at 1:17=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com=
> wrote:
> >
> > On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> w=
rote:
> > >
> > > Provide a mechanism to reset the coverage for the current task
> > > without writing directly to the coverage buffer.
> > > This is slower, but allows the fuzzers to map the coverage buffer
> > > as read-only, making it harder to corrupt.
> > >
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> >
> >
> > >
> > > ---
> > > v2:
> > >  - Update code to match the new description of struct kcov_state
> > >
> > > Change-Id: I8f9e6c179d93ccbfe0296b14764e88fa837cfffe
> > > ---
> > >  Documentation/dev-tools/kcov.rst | 26 ++++++++++++++++++++++++++
> > >  include/uapi/linux/kcov.h        |  1 +
> > >  kernel/kcov.c                    | 15 +++++++++++++++
> > >  3 files changed, 42 insertions(+)
> > >
> > > diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-too=
ls/kcov.rst
> > > index 6446887cd1c92..e215c0651e16d 100644
> > > --- a/Documentation/dev-tools/kcov.rst
> > > +++ b/Documentation/dev-tools/kcov.rst
> > > @@ -470,3 +470,29 @@ local tasks spawned by the process and the globa=
l task that handles USB bus #1:
> > >                 perror("close"), exit(1);
> > >         return 0;
> > >      }
> > > +
> > > +
> > > +Resetting coverage with an KCOV_RESET_TRACE
> > > +-------------------------------------------
> > > +
> > > +The ``KCOV_RESET_TRACE`` ioctl provides a mechanism to clear collect=
ed coverage
> > > +data for the current task. It resets the program counter (PC) trace =
and, if
> > > +``KCOV_UNIQUE_ENABLE`` mode is active, also zeroes the associated bi=
tmap.
> > > +
> > > +The primary use case for this ioctl is to enhance safety during fuzz=
ing.
> > > +Normally, a user could map the kcov buffer with ``PROT_READ | PROT_W=
RITE`` and
> > > +reset the trace from the user-space program. However, when fuzzing s=
ystem calls,
> > > +the kernel itself might inadvertently write to this shared buffer, c=
orrupting
> > > +the coverage data.
> > > +
> > > +To prevent this, a fuzzer can map the buffer with ``PROT_READ`` and =
use
> > > +``ioctl(fd, KCOV_RESET_TRACE, 0)`` to safely clear the buffer from t=
he kernel
> > > +side before each fuzzing iteration.
> > > +
> > > +Note that:
> > > +
> > > +* This ioctl is safer but slower than directly writing to the shared=
 memory
> > > +  buffer due to the overhead of a system call.
> > > +* ``KCOV_RESET_TRACE`` is itself a system call, and its execution wi=
ll be traced
> > > +  by kcov. Consequently, immediately after the ioctl returns, cover[=
0] will be
> > > +  greater than 0.
> > > diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> > > index e743ee011eeca..8ab77cc3afa76 100644
> > > --- a/include/uapi/linux/kcov.h
> > > +++ b/include/uapi/linux/kcov.h
> > > @@ -23,6 +23,7 @@ struct kcov_remote_arg {
> > >  #define KCOV_DISABLE                   _IO('c', 101)
> > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_re=
mote_arg)
> > >  #define KCOV_UNIQUE_ENABLE             _IOW('c', 103, unsigned long)
> > > +#define KCOV_RESET_TRACE               _IO('c', 104)
> > >
> > >  enum {
> > >         /*
> > > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > > index a92c848d17bce..82ed4c6150c54 100644
> > > --- a/kernel/kcov.c
> > > +++ b/kernel/kcov.c
> > > @@ -740,6 +740,21 @@ static int kcov_ioctl_locked(struct kcov *kcov, =
unsigned int cmd,
> > >                 return 0;
> > >         case KCOV_UNIQUE_ENABLE:
> > >                 return kcov_handle_unique_enable(kcov, arg);
> > > +       case KCOV_RESET_TRACE:
> > > +               unused =3D arg;
> > > +               if (unused !=3D 0 || current->kcov !=3D kcov)
>
> I think this is too strict, in certain cases it should be possible to
> reset the trace not belonging to the current thread, WDYT?
> E.g. syzkaller does that for the extra coverage:
> https://github.com/google/syzkaller/blob/ffe1dd46b97d508a7b65c279b8108eea=
ade66cb1/executor/executor.cc#L920

Yes, remote should be allowed here. There is some mutex that protects
remote trace buffer.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACT4Y%2BbmmYuCbV6g9yk8aFZdzhGhct3K78ii6voHR4KAa6oE0g%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSWJZTCAMGQE4NXFTJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 71A49B1C3B0
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 11:48:13 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-7073cd24febsf49169286d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 02:48:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754473675; cv=pass;
        d=google.com; s=arc-20240605;
        b=eT8lcmOF9nJqb6WgsiYBSjWKlHevFYVyeAcbDIsdAlVG9qm3zRdHX5bZYvFLaTK/O6
         PrMsxzoSE8cGDihaOUD2rOPZO9P8IRcIM9Cd9B6EdWIy1fPszxpPm1KsjOrTDM+l3zwt
         5hOSR5vvv8HUgZmMC3meTYRAHN8yZkYH0h9ydxSp2FoJR3RQVBqOAMj0YasrBxKSWmwi
         gT2MdhVDfvGdHoX69W7GJm8PbCGohgj1KOpsFdVJYJwIkPOoSNp4ZyjtHRQwaICNy9Rb
         w/i3zB/cJe7OqmNGWbRpeYrEKamzZIqCHDTrNTi5YmPx28bINa8aJv6VgL5uIdYMyuTN
         mDKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UDdkfBpN7zmckF2x30WpNTXYecpWe6iY490x+s9lVcw=;
        fh=va3t7P1ofeziXNYWORjl3IWiG45HZ7Ylvc59Fq9DoLM=;
        b=B8aRlBNtFfYHim0gA8g9BaoHFZbBT2/SsKhBffiS0D9vGcrEskWVkyY8a1VkUR0gET
         bjRpsrlS1AsZBUWG12LyRFK1uyTgozg3fc6vg6aY6AH4VmXZQ9P+xfYOXCVrnOujn5hq
         v8xXi5BWQtuVaI2IEOyVVrm6Pn8xKcXmCxUsdEayasB8cfgziF2W4GyxAKtPSPILgfcZ
         wwZS8yazOAwWuryzCK6hQOrc2CegqBt6npaM6Z74V+gkCx7sbM6KWaZyn5Fw+BoHYXCA
         3mR611NVN7Joam7gawcySliokZQZpbj0fF5r6ZL5VuC8IJ5utxc87DrTumncTTspE+0/
         5NEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1VZd1fgI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754473675; x=1755078475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UDdkfBpN7zmckF2x30WpNTXYecpWe6iY490x+s9lVcw=;
        b=LaODY5hNjd6wTDPPr2ECl/QK3NF5jgtwccm65wamHQ1U1/0w4hEXHVQki5/YN8MuE+
         ekmXrqSVPjrniom6GuA0oYaNwshm1plPwPCVcjXyPdFtZv2C4AeiMs2/EgQv3q0t7FO1
         mefcpW0cZ1h6+ZdQoneS8jmP/gIe1LrYFi3s2LesfJJXohMx89RTpv0yzcGGi5wtiW0R
         AvHOq+ntwt6L8p7Yg3hZR+3zl3BeldExiXCxwHgkj9vX/gYBpKF47jQDZG+Oeymjy0Qq
         zq3r2G6EFiNYfYOf8lmHL6hqekOa2cS+6ib9gTIwVIZH5Yl20J2zGVDv7AY6KKDBVulf
         yqYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754473675; x=1755078475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UDdkfBpN7zmckF2x30WpNTXYecpWe6iY490x+s9lVcw=;
        b=OPEtUojgXmCYbyg/mIWnjYrI2+M5C83DKmWKHJOpDpgmlnSMWTc7bXOTf/ZF4AsoLP
         CUGcG2U60huZ9eOv9tq/uc/EIAms4XH/rnIz2sDK4mwjmnoytQJnvFRttvvzTFBchuRt
         cBKaBBvewnZZK3NzSvCfW5TopJOZbalEzbRf3AnBx2VdBYlYI+e5O4bnnX7MT6cSIDfb
         YXp7wE+awWeVsD+FAuTtdVNZM3n6jGPi/9sR5Oh4hI7Yxad0uJVcwtwfF7I63OT2OtuO
         Yzk3d3jq85Z+1TGG8jTl1WmuHipjmkj/bVYwKmRc0Z03C0/cU/dyLM4x4otwCDhRYUh3
         yQhw==
X-Forwarded-Encrypted: i=2; AJvYcCVpv4PAda+oQmcHeAaHa60CRlepbMYBLakmXCCBREQ0bivEhE4al6GMjIcLkDLmNXudq1zMew==@lfdr.de
X-Gm-Message-State: AOJu0Yx46vbalv0jOVfTEeUvuzM5DRiB7mjBYIPabfDlNcwOyJzqKfPC
	COA7S2oEUMxpSXecQ/E5RTmZeLoXPDAhhWtcNhT3/hF5/1R2ZcOaplvt
X-Google-Smtp-Source: AGHT+IGptzV7Wv9uNl0dzN2S+GDS+4GQTMPzLNt8vrYQjLlYgBEdavO9SViLp1KzopIDA/Xz4Wc2Xw==
X-Received: by 2002:a05:6214:2466:b0:706:aae8:ad48 with SMTP id 6a1803df08f44-7097af56f1fmr21832906d6.35.1754473674756;
        Wed, 06 Aug 2025 02:47:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGciImNzE5Lr0iVViXYtzpWZ9yXFDRpcLadP0jnKNbbQ==
Received: by 2002:a05:6214:2687:b0:707:71f2:6be6 with SMTP id
 6a1803df08f44-7077686aba9ls102859216d6.0.-pod-prod-08-us; Wed, 06 Aug 2025
 02:47:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNiRFY4b37075o+1afspPaGV0dHjaZrHoOxfQxuALmmYWQAI/Hklub2KKibiPAQUbNAA9hnxpBUgA=@googlegroups.com
X-Received: by 2002:a05:6102:2923:b0:4fd:b71b:c66b with SMTP id ada2fe7eead31-50378b38174mr722446137.2.1754473673963;
        Wed, 06 Aug 2025 02:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754473673; cv=none;
        d=google.com; s=arc-20240605;
        b=kLIk+EfSFK4/aa7mG847D7+Odd8MoBCXUC8LKpXXCx/Cx9NB2a6LW2M7vyQpEqZK/i
         hqDCFtcpnfAdUGihh8o+wpFA0bR5JHNMKEvCCEFfdlsZbPSmHCkJ6eeHLx7gtncGUfzO
         BHY+FbgHjIIhTho/oyX2oe/v5Hw5/oFvuZAH+mGz5iMC6ta9aR9YfBPcTgqvCbpcInM8
         NnvkPuVp9y1WchMZCErDGSMbSG/lbWwrZi+Eyprg90coqKyp92y3GGe/shqXdVM8vBpy
         utH4Vv9v+5EkFgW/wt8F0QQapLmIEyGFphT1msgAqKoqs5aPkRo+Z31/+dd73Q0RXw8Z
         9rYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PrFRV6Sffa931ZKYbAVq2fB7yUmApGnWVEH6wPxtcxQ=;
        fh=u32oPKRMEhP3UtfvxS6nyjcwzJiHtN662K/X+c7MzJY=;
        b=Cv6cgrDJ66gwzQswfPTN/LEY9ieR8SunjWLNtDlawYzBv5a1iwFMFFcHBwsZOPtFTO
         nPrAhgF4TG6c7chQm6N5g130qAebP2faR9dq7uIdu2MJzH0vtcZme1Yrw4ICZcTtAC3D
         /Vj7BkM2Fpcc4SGTtnjegcYMLU/yaxg1SuMqWt2i9dj3BzATY4pspCnUqZwvM6D4HjlH
         6lwL8bzhxPSA3rLUH37U1+TKHyg8PjFa1PW1cnS6Q+ULkMU6uGR5kTUpimTihtvoMrlk
         iXJtVMSGwY8BejAobzEMEqCX/CnKCMyILU3OFjX/MznfXrwcLeIvtO83YfNdhEzgo20w
         ohtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1VZd1fgI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4fc0d1e0750si622865137.1.2025.08.06.02.47.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 02:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-7074bad055eso33214766d6.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 02:47:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXphUGhNkmxN477r6bQSwggQAnzlCTo7YOy0A6Kyp3OAzyrZC9GD6Mdyf4kipEgEwn4h29utayuoLc=@googlegroups.com
X-Gm-Gg: ASbGncsAAX7/xP/XSvlSpJzr8Fua84Oh0dFTH9O9VXTd2OGsSEnNI1DNgoK8Qypv8Y/
	cw35yIO7MGqgfCrh0kJWYEjRbsFM0Fx6O/H30Kzzv1JMxZXfxl+PdI02vRgehLxq6cuXVcyXnVQ
	3CUlrZaji5UZi71Bnr5PeDQbI9d0TBLh6Om80F+np/pIPfPG1vAK7mrxDDsW3MHEaUg9UuNehf6
	FsQrsW0tqYNo2bZauqD+3tCoWWiWuuuKaD67g==
X-Received: by 2002:a05:6214:1d24:b0:707:ce0:d1b5 with SMTP id
 6a1803df08f44-7097af5272fmr18873576d6.34.1754473673048; Wed, 06 Aug 2025
 02:47:53 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-9-glider@google.com>
 <CACT4Y+aEwxFAuKK4WSU8wuAvG01n3+Ch6qBiMSdGjPqNgwscag@mail.gmail.com>
In-Reply-To: <CACT4Y+aEwxFAuKK4WSU8wuAvG01n3+Ch6qBiMSdGjPqNgwscag@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Aug 2025 11:47:16 +0200
X-Gm-Features: Ac12FXyvMPPkAYf2aXAAJO3vWviF9023u78zwU7TwAkbbhnCYNLNaIfIom9VqF4
Message-ID: <CAG_fn=XYS43pefo1EEO6jTTkPHKhB0+hpbh9KGQ5kodAJm3Ncg@mail.gmail.com>
Subject: Re: [PATCH v3 08/10] kcov: add ioctl(KCOV_RESET_TRACE)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1VZd1fgI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

On Tue, Jul 29, 2025 at 1:17=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com> =
wrote:
>
> On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > Provide a mechanism to reset the coverage for the current task
> > without writing directly to the coverage buffer.
> > This is slower, but allows the fuzzers to map the coverage buffer
> > as read-only, making it harder to corrupt.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
>
> >
> > ---
> > v2:
> >  - Update code to match the new description of struct kcov_state
> >
> > Change-Id: I8f9e6c179d93ccbfe0296b14764e88fa837cfffe
> > ---
> >  Documentation/dev-tools/kcov.rst | 26 ++++++++++++++++++++++++++
> >  include/uapi/linux/kcov.h        |  1 +
> >  kernel/kcov.c                    | 15 +++++++++++++++
> >  3 files changed, 42 insertions(+)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools=
/kcov.rst
> > index 6446887cd1c92..e215c0651e16d 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -470,3 +470,29 @@ local tasks spawned by the process and the global =
task that handles USB bus #1:
> >                 perror("close"), exit(1);
> >         return 0;
> >      }
> > +
> > +
> > +Resetting coverage with an KCOV_RESET_TRACE
> > +-------------------------------------------
> > +
> > +The ``KCOV_RESET_TRACE`` ioctl provides a mechanism to clear collected=
 coverage
> > +data for the current task. It resets the program counter (PC) trace an=
d, if
> > +``KCOV_UNIQUE_ENABLE`` mode is active, also zeroes the associated bitm=
ap.
> > +
> > +The primary use case for this ioctl is to enhance safety during fuzzin=
g.
> > +Normally, a user could map the kcov buffer with ``PROT_READ | PROT_WRI=
TE`` and
> > +reset the trace from the user-space program. However, when fuzzing sys=
tem calls,
> > +the kernel itself might inadvertently write to this shared buffer, cor=
rupting
> > +the coverage data.
> > +
> > +To prevent this, a fuzzer can map the buffer with ``PROT_READ`` and us=
e
> > +``ioctl(fd, KCOV_RESET_TRACE, 0)`` to safely clear the buffer from the=
 kernel
> > +side before each fuzzing iteration.
> > +
> > +Note that:
> > +
> > +* This ioctl is safer but slower than directly writing to the shared m=
emory
> > +  buffer due to the overhead of a system call.
> > +* ``KCOV_RESET_TRACE`` is itself a system call, and its execution will=
 be traced
> > +  by kcov. Consequently, immediately after the ioctl returns, cover[0]=
 will be
> > +  greater than 0.
> > diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> > index e743ee011eeca..8ab77cc3afa76 100644
> > --- a/include/uapi/linux/kcov.h
> > +++ b/include/uapi/linux/kcov.h
> > @@ -23,6 +23,7 @@ struct kcov_remote_arg {
> >  #define KCOV_DISABLE                   _IO('c', 101)
> >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remo=
te_arg)
> >  #define KCOV_UNIQUE_ENABLE             _IOW('c', 103, unsigned long)
> > +#define KCOV_RESET_TRACE               _IO('c', 104)
> >
> >  enum {
> >         /*
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index a92c848d17bce..82ed4c6150c54 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -740,6 +740,21 @@ static int kcov_ioctl_locked(struct kcov *kcov, un=
signed int cmd,
> >                 return 0;
> >         case KCOV_UNIQUE_ENABLE:
> >                 return kcov_handle_unique_enable(kcov, arg);
> > +       case KCOV_RESET_TRACE:
> > +               unused =3D arg;
> > +               if (unused !=3D 0 || current->kcov !=3D kcov)

I think this is too strict, in certain cases it should be possible to
reset the trace not belonging to the current thread, WDYT?
E.g. syzkaller does that for the extra coverage:
https://github.com/google/syzkaller/blob/ffe1dd46b97d508a7b65c279b8108eeaad=
e66cb1/executor/executor.cc#L920

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXYS43pefo1EEO6jTTkPHKhB0%2Bhpbh9KGQ5kodAJm3Ncg%40mail.gmail.com.

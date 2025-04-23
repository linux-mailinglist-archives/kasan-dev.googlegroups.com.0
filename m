Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7GMUPAAMGQESASOVYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7506DA98A8A
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 15:09:18 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b06b29fee16sf6532170a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 06:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745413757; cv=pass;
        d=google.com; s=arc-20240605;
        b=UdjV7ciTe6zJGebwDYC0siJ+6ibdACh7iL+SE1reOqTkZH4pqB7T/UZC2AF30pSNN7
         MWLmZOKxRWKQwMgg3BRItSJNigt1m6QJ9R/bQH/eAnGz3BXKDhSH63esQX0SFoDGnUvv
         ZPGOg0bFBDwlOwzSTlwFP/UA70+E95Pyoj15TfqTRbEKI0AkMUpXS9LP+/VRpjt+FfSy
         RIJ0r0UFzS0omeJzaTYvHadkKKqjffjYdsgd6tkxPePQB8notT9l6sO3Q1xtUyTPGIc6
         aTVJDprDGLv+3Sj7gFmjSq3sJJqjrTdgzJxGn8TKPpYYOPBrQcCHYTOdO5k2s4Rt7d3f
         Uy7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aF7r78z5uTFbm+SAJKhCMdjsNBIhLzWGiy+swm8OV4Y=;
        fh=gQ7XHhsw1v1a0oEuoZ9VGPHoEpVUt+AwG0Oe+xNyOWY=;
        b=g5l+hXLRFaMRv8oJZYgpsM2Bd2QgBp73m/FZkTJ1TapQrcU/vjEnnujGz0IeVSZgpZ
         eRuyWYYVlzdvz/wY0/krrUZdPY85CzbxFndUQGNjCNxv0kHjlpcwIXXsdIOkWmD2FZMS
         1HQFnN70f/Gx2iLBsQX6JdpMrkwOEg81letCwD+dR5503EntM08Y3fHQrdpEhXDAiG5e
         ePXQoyJyoKb2pEN49PkVDwULBpNfMW0OrOU1sknB7SQVihlwmppcnwWnFNVGbmzPKm08
         lXGRZN2B5QAhLwjny92xPHKlSHLzzx8j2C6efmWipHyzH9yxEMn2cPmJtESxVkXucUy1
         KFww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EEPaEDiR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745413757; x=1746018557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aF7r78z5uTFbm+SAJKhCMdjsNBIhLzWGiy+swm8OV4Y=;
        b=YznRGNXqtzxe2v/eMLdt3lQ085ztiV/aQjYvN4wFKaFse0Q1xwjSnQCdj6uufKd++9
         zX1akGLrRAm37yM/Z+0uGA2RJ4yyyrzaITw1lTgO7OIeCLAUuwsRaEu5XmchQnIaAd31
         /Q4t6RuPv2OX/GJ6TStrHlPakSrpzvT7Bf8Aq9A7FZ4KgOm5hjVXVOABa9YlEbYdyIoS
         hSxXg/JV7JdT+IY/IC3sYKWVwWFWNDwYSU1LwU2UnYDELhHrOlQf+ax16LYf8I2PMYyh
         Al3pR7grm6K+o5659dyZ18ZqMmnB5PrGIabhfX6C+5jKzI1PyFW7/zkOpss3ZvQFBXHl
         j2Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745413757; x=1746018557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aF7r78z5uTFbm+SAJKhCMdjsNBIhLzWGiy+swm8OV4Y=;
        b=EEvBN/582WzyNH1Ivj8snvYKmf5svCBPMq7I5rR4/QLh55kGX7Fp1SbYx4x2aJWqnU
         FPB6495w3X6DpMXT1MAgFYc1CXxG9KnL6Dm8nVKz96KWsHpffCjol9dkYwChoGGfz12t
         O/ovcX9l2AAKU3zlqnFIZW4Q9hNeneQEkY4ZC4dwBoEoYiy0HcRHLGgUzSLhLudVMgyJ
         1TTZVCEtzQeqxyr1VR3RVGsT8PC5kJ+0k7pVFsUe/BX8fvtuj1izMUZ/6yCtv/xzuQyH
         FZi9bs4ujNlKmOQlm3SOz3p4wj8xlKVZ3XCpekBC5cR7O17SeX778HSRhVvQb+n/eAId
         O+pg==
X-Forwarded-Encrypted: i=2; AJvYcCWuTo1ZsCa5wmEwINhI0CLX7ORMea/2cu+OYoS+uj1rotAtqsWmn66n6kkhQTeySqWFz7Nhgg==@lfdr.de
X-Gm-Message-State: AOJu0YxVgjEAmFxmhaVIiVZAkahPBLjGjvfn4rO8QcxwvEn2svj9QKaO
	d9wp+/6vv+YtdcyY8TWFKtLOXYxjh84X2MyzrmiQn1MgQ30XKuMm
X-Google-Smtp-Source: AGHT+IFlXFdZ6AJGJ2P9thJnkNt5c9QahhEHSXopuNjyV13DAtUUB5Z2WaFIiqm7Z/Yu1NLGBvpU9g==
X-Received: by 2002:a17:90b:2f48:b0:2ee:ee77:2263 with SMTP id 98e67ed59e1d1-3087bb418dfmr30722723a91.7.1745413756462;
        Wed, 23 Apr 2025 06:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKWXk07Age+d+tWk8elBvlqmwcrcEx/Oi8Ch9ogo2uCjQ==
Received: by 2002:a17:90a:9381:b0:2e7:8a36:a9b7 with SMTP id
 98e67ed59e1d1-3086db2abe2ls217934a91.1.-pod-prod-03-us; Wed, 23 Apr 2025
 06:09:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUqezCdDGORk75ZlhYJBAJh0vv1jUMFcxEAsL/NaI6j9JBrR8nRman+sctvJEA6DOhpL7+Jka0jmgc=@googlegroups.com
X-Received: by 2002:a17:90b:2751:b0:301:98fc:9b5a with SMTP id 98e67ed59e1d1-3087bb4150cmr25551454a91.6.1745413755078;
        Wed, 23 Apr 2025 06:09:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745413755; cv=none;
        d=google.com; s=arc-20240605;
        b=MHfKCFXdC8O2/UxgopwAW2k72IvLzUkrG8bdorJwDynS9pu32rC2uYV0eDeFJoQxeX
         BSR97uuCeR69eRRov6kMnNwaEmoihSyW445RvF47AZ6pWzGPSdCsHRFPJOOOg11l8pDi
         sM2mtd/QIJwrBT8DSkAP6O5vUzht37Pxm9ATLoVIJYj4m/8vWyw8eZKC5T5xbzfaLFtO
         DaT6eDS6Xy+YRtKtRC83qQDjCZ/z0mBOZ3ud3Igovcr+wWACgshzD2w/atqTGON5mstM
         OLOUAPrBoXODF5JwZlqzm+iRMFm1y7nlR2tGNPp4LfEVGi5meoPP9Hta32fyOSmM2zn8
         c4iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LTn7cRGZVVZ7I+m7141mdiqJRDEUM3mUP+2DWyqwfew=;
        fh=Ne9Yup5Dc+zLAPNHAde7XpXcLFNyW8mjxjKTv+1iIY4=;
        b=IkIJkXsQEiik/u6WEqydlBwm5wqDRrCZuZXZtMUoQz2tnwLnxqIV6+5Hz9snGcaDno
         rbGfft8ztT5pv557suC2Lyqj3PjPqsKN/uX5XxFnqNM52jkhQgSd1WI9DJM4ipDPDAlQ
         OLQERPfpggZJYBch6TIY0lSvyae2XBwN7VJYO3HHRN7Wm5HzDQMKoTeiKmOJKqVwjuio
         9LBaIc4Nwsr+UqUAm/I2iejn/XbD1Zsw+graPNmPl8Cb+CUkXz6BYpRFGcyNYVim5QFs
         AKgtDQECfvmvCQRWer2W2bDRmcaRm2Ljxo+eEJopvpgLUz5ADw9AuM4NkaynML+NdT4D
         0ziQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EEPaEDiR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d34732f0si313152a91.0.2025.04.23.06.09.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Apr 2025 06:09:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6e8fb83e137so55304126d6.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Apr 2025 06:09:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVinKrs/B/0fKrSqHEi0b/Vqru55IYwySN+1LOgGBW81yo9FPpDFCW+It/bJjwe1OI9CCknUcjOroM=@googlegroups.com
X-Gm-Gg: ASbGncuI0oA/Qdeu/mffiTme/VpnzzDTWXvCO/Mts7hpZ32RWDQ+H06AUTVF+vKaafN
	cfA+J2FjsBaPevONQ1oCmN25xcK5RmLIzc6Oa1oV2t6CNpco9FSyOs4VN+Xw+glhPSVwGfKNZqK
	dXyFGgwBV2j/z5a1EZaIK8vbb8y9PQG5rn0AggvhtCa++s8qP9iED4a+B+jW5MAg==
X-Received: by 2002:a05:6214:224d:b0:6e8:f8ef:d659 with SMTP id
 6a1803df08f44-6f2c4545f64mr382868476d6.10.1745413753568; Wed, 23 Apr 2025
 06:09:13 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-6-glider@google.com>
 <CANpmjNM=AAtiXeDHgG+ec48=xwBTzphG3rpJZ3krpG2Hd1FixQ@mail.gmail.com>
In-Reply-To: <CANpmjNM=AAtiXeDHgG+ec48=xwBTzphG3rpJZ3krpG2Hd1FixQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Apr 2025 15:08:36 +0200
X-Gm-Features: ATxdqUHkZ-mVJ4_aZiiWoW4d9GlOyr_vj4jQP1Yr2bqSKqCDppY1saT2_VuZnWQ
Message-ID: <CAG_fn=WD3ZuJCQ4TiVKXLhn5-=tsaW0d=zrM-TuEokP5zEvOSw@mail.gmail.com>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EEPaEDiR;       spf=pass
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

On Tue, Apr 22, 2025 at 11:29=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> > in the presence of CONFIG_KCOV_ENABLE_GUARDS.
> >
> > The buffer shared with the userspace is divided in two parts, one holdi=
ng
> > a bitmap, and the other one being the trace. The single parameter of
> > ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> > bitmap.
> >
> > Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> > pointer to a unique guard variable. Upon the first call of each hook,
> > the guard variable is initialized with a unique integer, which is used =
to
> > map those hooks to bits in the bitmap. In the new coverage collection m=
ode,
> > the kernel first checks whether the bit corresponding to a particular h=
ook
> > is set, and then, if it is not, the PC is written into the trace buffer=
,
> > and the bit is set.
> >
> > Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENA=
BLE)
> > returns -ENOTSUPP, which is consistent with the existing kcov code.
> >
> > Also update the documentation.
>
> Do you have performance measurements (old vs. new mode) that can be
> included in this commit description?

That's hard to measure.
According to the latest measurements (50 instances x 24h with and
without deduplication), if we normalize by pure fuzzing time, exec
total goes down by 2.1% with p=3D0.01.
On the other hand, if we normalize by fuzzer uptime, the reduction is
statistically insignificant (-1.0% with p=3D0.20)
In both cases, we observe a statistically significant (p<0.01)
increase in corpus size (+0.6%) and coverage (+0.6) and -99.8%
reduction in coverage overflows.

So while there might be a slight slowdown introduced by this patch
series, it still positively impacts fuzzing.
I can add something along these lines to the commit description.


> > +.. code-block:: c
> > +
> > +       /* Same includes and defines as above. */
> > +       #define KCOV_UNIQUE_ENABLE              _IOW('c', 103, unsigned=
 long)
>
> Here it's _IOW.
>
...
> > diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> > index ed95dba9fa37e..fe1695ddf8a06 100644
> > --- a/include/uapi/linux/kcov.h
> > +++ b/include/uapi/linux/kcov.h
> > @@ -22,6 +22,7 @@ struct kcov_remote_arg {
> >  #define KCOV_ENABLE                    _IO('c', 100)
> >  #define KCOV_DISABLE                   _IO('c', 101)
> >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remo=
te_arg)
> > +#define KCOV_UNIQUE_ENABLE             _IOR('c', 103, unsigned long)
>
> _IOR? The unsigned long arg is copied to the kernel, so this should be
> _IOW, right?

Right, thanks for spotting!
This also suggests our declaration of KCOV_INIT_TRACE is incorrect
(should also be _IOW), but I don't think we can do much about that
now.

> >  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> >  {
> > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > -               return;
> > +       u32 pc_index;
> > +       enum kcov_mode mode =3D get_kcov_mode(current);
> >
> > -       sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> > -                                      current->kcov_state.s.trace_size=
,
> > -                                      canonicalize_ip(_RET_IP_));
> > +       switch (mode) {
> > +       case KCOV_MODE_TRACE_UNIQUE_PC:
> > +               pc_index =3D READ_ONCE(*guard);
> > +               if (unlikely(!pc_index))
> > +                       pc_index =3D init_pc_guard(guard);
>
> This is an unlikely branch, yet init_pc_guard is __always_inline. Can
> we somehow make it noinline? I know objtool will complain, but besides
> the cosmetic issues, doing noinline and just giving it a better name
> ("kcov_init_pc_guard") and adding that to objtool whilelist will be
> better for codegen.

I don't expect it to have a big impact on the performance, but let's
check it out.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWD3ZuJCQ4TiVKXLhn5-%3DtsaW0d%3DzrM-TuEokP5zEvOSw%40mail.gmail.com.

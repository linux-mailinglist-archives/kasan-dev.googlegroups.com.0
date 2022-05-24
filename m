Return-Path: <kasan-dev+bncBCMIZB7QWENRBDH3WGKAMGQE3ROQXAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E03E7532354
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 08:39:08 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id l18-20020aa7d952000000b0042ab7be9adasf12058637eds.21
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 23:39:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653374348; cv=pass;
        d=google.com; s=arc-20160816;
        b=qEGMosG93jATcJQMfmk/MhYoLxdpPQdt/jEGnLdneMKZO4usLkRDeu0KyJfVI1il/P
         GURoZepHJYB+IL0qzgTusf7z6z4+Q/ZNvpWKP3HmP7krxU1OxZVRJ7WQuEo90tZPrUAg
         BuA0MVDPoTe97UDiAW2LfMFVfbAYIzAb7yW5lcS36b8DGwYvyKMsbgLp39WlAhlnjz8K
         t6cgao2wdFfgoDXhUiHfyofBYsWkQaMkaE4fW/rBmr4oircewnwXBMzLanKIXCGrftHE
         imNR96SQFCTVA+fzIAWoT/HvNoZYtp01v593q1stFjC1sKlgGEBqO+i+MbJFOwwEuyJe
         pUQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sdeAvoeOxyQyyDu0BL+4xOFt2R6xoC2X89GvMHE6/wg=;
        b=vWv9Qa2TMBL1Fu5gCJ85klRNlffyg6eTPEwnDmtQjceAHAPFR4zeForBnLx3faY6fo
         wTi9fqbK00tTrKF2RPc+aauBJtK2hMB6HiMKSAuFNfE3lTfW5OCMXp4joJG01BneEDJN
         crWszP5VXecTBqhj3+lLwjdieYK8EyB43iNCLKu2FEUh6RK8YnBAKXd47aXGaXPIgayB
         KKanKY2WCtOobu6R0Ojpdfkt8Py0KDlRwRO/ac2eea8Gd6YZjGO5XZtYYv7xm00lFdwe
         vlaodciNdV9G29T5mc9QSpc6iCSBd0glT62kaYjdJKVPXaXmvfKZQ0BlBos969qE9DUg
         dmQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="oCve/KDF";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sdeAvoeOxyQyyDu0BL+4xOFt2R6xoC2X89GvMHE6/wg=;
        b=ErvRlaVFbrt67V1jl+jSKduimeibiZ5Ejwxxc1ZLaMpazVjuiNj4c6BegMH1icxutE
         yv1lTGHOwSK8ZHLAWMG3p2Rf7+4EKnbcK0CU18Yxz9ITFztL0C7fYQ85N8k98FsplaE3
         39kpOXalXKeUsONDSU6XSxsTHeOxnp4Xnbxg8Sno9i2T06EaPd/SVIDEMiVoOnqxbgqa
         lpGMGMI8Fc0C6xlJbKj269kNGe1IcsbDM5cpzUbNC0MdJV38v9hFONpiRJcohsgicuBs
         MbchHnCO9BG2eUqVZurS3QY5Cd9QRZEV7u6+AdNYUl/JwjURtrydnXhEzNPF/j7UAanq
         ti6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sdeAvoeOxyQyyDu0BL+4xOFt2R6xoC2X89GvMHE6/wg=;
        b=cs52LDL1FL+TxdTvtrqN2Mp7LMm2AsvinjF1t6h7f56bSSS1GyybbnP9nWD89vvMFr
         B1sMix597Y3RSjn3yi+AsbXAZucHN8gOuXYNsUtF9ONzbPV/pPFlcS3UadY6KMAs5YQ6
         J2YDvFCn2fgteIsgtvwp1oVHKVcSKlG9mv4/BaAndH3jcxAL5nTXD7+lsL5S3M2MKrSo
         w1BDs9Gv+GXPrGCvTNp+9gIbgQEwyerjuy08avRk5nB80cVexw2Q1bXS1LI7emmKgRnI
         qqHuzLrYAdp8ZqnfL0/oEgQr51YjyaLZO/BbfkmQOEvmBiyRgZ7L8akl7wuHjxPgzV2L
         6xgg==
X-Gm-Message-State: AOAM530MlVdI4TAumDrikcBoIEMwGlINNQrS2WL4ULu6q/OnyFaMldQk
	eSW74ybJ4WMUWQCm8zBFYmE=
X-Google-Smtp-Source: ABdhPJywLeHDnvsSADFWvRtvs/YKHpgvThlAsKSYomzw2BlMIWlE8h2PRdbLw04KqpeHqrNpcRBltQ==
X-Received: by 2002:a17:907:9626:b0:6fe:bae9:70bc with SMTP id gb38-20020a170907962600b006febae970bcmr13426704ejc.150.1653374348410;
        Mon, 23 May 2022 23:39:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:fa10:b0:6fe:bfe2:528b with SMTP id
 lo16-20020a170906fa1000b006febfe2528bls3775293ejb.3.gmail; Mon, 23 May 2022
 23:39:07 -0700 (PDT)
X-Received: by 2002:a17:907:94c6:b0:6f5:287a:2bf2 with SMTP id dn6-20020a17090794c600b006f5287a2bf2mr23857497ejc.124.1653374347330;
        Mon, 23 May 2022 23:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653374347; cv=none;
        d=google.com; s=arc-20160816;
        b=IvatOyxcI7RYkyhJ7BRXNCn9tUuhC7dmZ9SrF+uvD541yg9sFx12ZFrGvDAue/wMuh
         Y9d9d2VrAYcunMamBQTuPjxPAVB8XYfhl4gjgnuZwHq0+fbFiZA77Ps9cUmRHh3iKfdd
         o6e7tO7jXTeYb7pT2jXkdtY9tK82Vt1yPlit7lc8t2ISL+7IN+QC3S0sHyw/XJTrEWt+
         UR5IfM49LrTCLn1J972fyVQkbWaI1eGFlHSbf1PKBVqV/FK13XzCx2oPa4kUMPO4h94z
         lBPqjTOG25ym/gLC1rgmCo5+B7e96jxJMOo7QjJumrOH0yCYu9bIaJLeB1UzgRW5F4Cr
         oj1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vBkx9/je7nDyB+6MMJGNSqtAxz9DvJ1+u+v1K7otlCo=;
        b=GDQTD4xkWoKaH6+NJH9ARIogGGqDarK0PoPlNxqPz1MWEcKjwCpnYxkZc0fLblGMrn
         MV5A/xNxwOVep6gU5/ND+nTjbybOEg2b7AxOV0Usbp5dMe8wpMKsDHONiQI0gwRBIwM+
         WEbWm/rAdcOQWeyEbtSmZyhQd92tEL/+aMm9SDSB0ofLQx5jfjAn6wIBH6C0L8sY1IzS
         uW1Wc9Xy6MG3QjhIGRlSiha+jtiLNKt+WKlM2SMrtNnbB7Gmv3aZ2OmLupiFGABkrT5F
         dYW/C0kP4r5qFZvtsqrYdunhYPgrfGhWKgHePxAujLCia2GSGZrcbyqXjfdn5D0dfpv+
         NGhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="oCve/KDF";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id k4-20020a17090627c400b006f47118d7bbsi939869ejc.0.2022.05.23.23.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 May 2022 23:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id w14so29129479lfl.13
        for <kasan-dev@googlegroups.com>; Mon, 23 May 2022 23:39:07 -0700 (PDT)
X-Received: by 2002:a05:6512:3da0:b0:478:5b79:d76e with SMTP id
 k32-20020a0565123da000b004785b79d76emr11591958lfv.540.1653374346548; Mon, 23
 May 2022 23:39:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220523053531.1572793-1-liu3101@purdue.edu> <CACT4Y+Y9bx0Yrn=kntwcRwdrZh+O7xMKvPWgg=aMjyXb9P4dLw@mail.gmail.com>
 <MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
In-Reply-To: <MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 May 2022 08:38:55 +0200
Message-ID: <CACT4Y+Y7cvG-iHjGuca4rCA9jHRa8LsjQ=bfayNKkOeUjU_4Lg@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function
To: "Liu, Congyu" <liu3101@purdue.edu>
Cc: "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="oCve/KDF";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 24 May 2022 at 05:08, Liu, Congyu <liu3101@purdue.edu> wrote:
>
> It was actually first found in the kernel trace module I wrote for my research
> project. For each call instruction I instrumented one trace function before it
> and one trace function after it, then expected traces generated from
> them would match since I only instrumented calls that return. But it turns
> out that it didn't match from time to time in a non-deterministic manner.
> Eventually I figured out it was actually caused by the overwritten issue
> from interrupt. I then referred to kcov for a solution but it also suffered from
> the same issue...so here's this patch :).

Ah, interesting. Thanks for sharing.

> ________________________________________
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Monday, May 23, 2022 4:38
> To: Liu, Congyu
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.kernel.org
> Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function
>
> On Mon, 23 May 2022 at 07:35, Congyu Liu <liu3101@purdue.edu> wrote:
> >
> > In __sanitizer_cov_trace_pc(), previously we write pc before updating pos.
> > However, some early interrupt code could bypass check_kcov_mode()
> > check and invoke __sanitizer_cov_trace_pc(). If such interrupt is raised
> > between writing pc and updating pos, the pc could be overitten by the
> > recursive __sanitizer_cov_trace_pc().
> >
> > As suggested by Dmitry, we cold update pos before writing pc to avoid
> > such interleaving.
> >
> > Apply the same change to write_comp_data().
> >
> > Signed-off-by: Congyu Liu <liu3101@purdue.edu>
>
> This version looks good to me.
> I wonder how you encountered this? Do you mind sharing a bit about
> what you are doing with kcov?
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks
>
> > ---
> > PATCH v2:
> > * Update pos before writing pc as suggested by Dmitry.
> >
> > PATCH v1:
> > https://lore.kernel.org/lkml/20220517210532.1506591-1-liu3101@purdue.edu/
> > ---
> >  kernel/kcov.c | 14 ++++++++++++--
> >  1 file changed, 12 insertions(+), 2 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index b3732b210593..e19c84b02452 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -204,8 +204,16 @@ void notrace __sanitizer_cov_trace_pc(void)
> >         /* The first 64-bit word is the number of subsequent PCs. */
> >         pos = READ_ONCE(area[0]) + 1;
> >         if (likely(pos < t->kcov_size)) {
> > -               area[pos] = ip;
> > +               /* Previously we write pc before updating pos. However, some
> > +                * early interrupt code could bypass check_kcov_mode() check
> > +                * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> > +                * raised between writing pc and updating pos, the pc could be
> > +                * overitten by the recursive __sanitizer_cov_trace_pc().
> > +                * Update pos before writing pc to avoid such interleaving.
> > +                */
> >                 WRITE_ONCE(area[0], pos);
> > +               barrier();
> > +               area[pos] = ip;
> >         }
> >  }
> >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > @@ -236,11 +244,13 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >         start_index = 1 + count * KCOV_WORDS_PER_CMP;
> >         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
> >         if (likely(end_pos <= max_pos)) {
> > +               /* See comment in __sanitizer_cov_trace_pc(). */
> > +               WRITE_ONCE(area[0], count + 1);
> > +               barrier();
> >                 area[start_index] = type;
> >                 area[start_index + 1] = arg1;
> >                 area[start_index + 2] = arg2;
> >                 area[start_index + 3] = ip;
> > -               WRITE_ONCE(area[0], count + 1);
> >         }
> >  }
> >
> > --
> > 2.34.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY7cvG-iHjGuca4rCA9jHRa8LsjQ%3DbfayNKkOeUjU_4Lg%40mail.gmail.com.

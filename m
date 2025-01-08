Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWOK7K5QMGQEGQJE3NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74927A06188
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2025 17:18:35 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2a01cedda36sf12599481fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2025 08:18:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736353114; cv=pass;
        d=google.com; s=arc-20240605;
        b=aYgiuL57Z1xroegnxW9AWURg2IXnOeS8I7PBncIsta4qp4DX0KB+4KOma2bSglmTxK
         d0cNmTHrkhc3kJMNwqOJ7ofmPVNkJ+DiS6h4HVmdDVFSXP23KuUOoSaJowburPou0IxT
         qxL7JD+YQs/nJA5Z7QiDCSIPcFhp9oTJrouqFXSp2hm9A+Fv+8emg1GyOIUWmuCc4Y5U
         HhP3Nv7W5xo+tHZ41DbdmOuuUTfY36iv3ZbwFQNdlyA6ocdvlKpPXMOGm7t1PpHNA34f
         KU6rwys6Ee3aPmsspdJILOAkjVOaftuJLsAMhohVhuVq0zST8uixuHgw3O3o9T2l0WdK
         u+zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SLqE93Cuiqt578bIRvjYMmAreLS6nQxrYsRM9G8MY9g=;
        fh=jjRrnQLvD8Ufw0+Ps3lI3SX6G9zwG42W2fHmCwAlXL4=;
        b=H+i/kb3EASKONiesKYI76tJNlt66R7fR/M0f0ctg/Mag8K8TlJMSh9zhRgNMthEtyg
         cK2MJlqovd850jvLAWMzWr8ZZ1ukLEtQZ/PV1JX/nMaA7BkFTTQpwFsAS5NewG8lkOV0
         FiO/1Tbwe86VoxukNlsLgsDpDlmviwQ1T7v5uAYxnLoTaoMt+q1nn0TxZHMYuzKZtw19
         KbpNvAYPyqQvt6zMZfoHnu6kqNpdeqfFVc7v4L7KWtSO6b0uHfr7XwrR9PZ79pS/iNfo
         sew74hDPf713bvJ40bjM6SD9Qqdz+JTdupFN33Cb1nKH2tSqLENnyp2R+IlvwCEq61No
         nN5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PlH7I7Ck;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736353114; x=1736957914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SLqE93Cuiqt578bIRvjYMmAreLS6nQxrYsRM9G8MY9g=;
        b=ukbwUkCUxAy15qmwbj1RfxUa7L6Fms4JHLG/EPqwZIGrMbDEec2s5fvIesDiZEIv+Y
         l3rXFG/0kvGcndLMdXv8IxA1YelPQgx6F70WPVFRtDbnoMCM1c+jKTuvtPeFe8jsUn/2
         I62YGOUd+uNdBCxmHAjeswoZbuE4EvkYc+xOxyO6geagxRmGHGP5Snn5dHZyBSDd4d2a
         Wq+0RijNPfJg0EVx4FJi2YfUztNoEuUKK3hLDFbZaXc1BlzezT4FzPdQJIR1zAGf9lwP
         DJtY6qJyyc2JILhl63wr6IWipjb/uBdL8INY3rWEAEal/4eJeaUO3BJF2JvpmBFWFMA/
         aNuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736353114; x=1736957914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SLqE93Cuiqt578bIRvjYMmAreLS6nQxrYsRM9G8MY9g=;
        b=xAHgsgX7Wu1tqvT05jVbozfyH2/nwzyTGo3tnq8/Y3P2Iz/dvL461nueqKQYS7Ik2n
         HKB5Ll1o+6gwckKOowKKqAGVEl5r6LO1RCbkx9MuejQMBRHDGrGUBFBXQJsyULl0+3Oz
         hGrQ5r3ldfaSQGsCdj4VBoQE0h6IIk7IPhzWKpve+ynI8B/YUIbMXkhoA5r4i8XrTmnE
         U79mLg16xyutFGqJ65NDIj2WtfetEspD3tYNtt8RyB+617An6JS9UGLypv1KSl1lzSNa
         8OEzfYF9p5TsS9Y2xyCh3MCNoxTz+3Kt087wph9KKcIUcnuySXv2/H++U1dwYFmni6Am
         DhmA==
X-Forwarded-Encrypted: i=2; AJvYcCVdD+Wvd2amWhfGifNLovmrfK2xJU6Dm4LTEd/DSZDKWVitryPCOL03Juab41uqgJDlhM9a4w==@lfdr.de
X-Gm-Message-State: AOJu0Yy9UnzCBwSEjYSBP7zmRrNIidn6qp21CwJDiR0lTSG15/UHizSC
	T63RslETznNdORKXlIOWN4mmXw0riPj5xYC+6O9y5GgEcnKOkDRR
X-Google-Smtp-Source: AGHT+IHsMQkTC52ssdYf49Buqej1kJYLc6QETXUvmvdgwwqm/xXKHrrU2F9VaSG5ag1NcB9U+jTbwA==
X-Received: by 2002:a05:6870:6e06:b0:296:dee4:771c with SMTP id 586e51a60fabf-2aa068d65b1mr1657561fac.33.1736353113945;
        Wed, 08 Jan 2025 08:18:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:af89:b0:2a9:4a3e:3cb5 with SMTP id
 586e51a60fabf-2aaad6c0ecfls1130fac.1.-pod-prod-01-us; Wed, 08 Jan 2025
 08:18:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9pZhjbdL/UJ5CN4Sqb303BN9ML0nfHjIQFVXolUzR6cArfmANUWHRzejz8OjQaTO5qVnVS/5iH1Q=@googlegroups.com
X-Received: by 2002:a05:6870:ae94:b0:29e:6394:fd4a with SMTP id 586e51a60fabf-2aa0650b8f1mr1865597fac.2.1736353112817;
        Wed, 08 Jan 2025 08:18:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736353112; cv=none;
        d=google.com; s=arc-20240605;
        b=bqM55Rdy/uxI4FKDwsnE46g1tRnTRfW8zEwLJBqsIOvUp+oJmbKF8FP/b5EtqkTu6F
         w5kzdANM5X+xJozNRXDc2LDIixKlQrs2nyevPd7YO5l+tCHvjsGIMBOp0+slKPbST1aj
         JB1d90wMX4taSqhKb1S7plpifjC2jZsmNCxnv6o5dth19D5Vbdmnhms5aUsI4BiimrrV
         xFfcePUIDa9gTsP0Uf7cS3bnaMAvAh+ZEBLB9A1Rwf0JfOtKkSVHoJJIfGja0JpFZb2O
         9eEmDanCc3EowAeYzNOYHSSm8LJj3bVX9Ibg+FPyLbofkjgRag6kncQ+4I5vwznfjKp/
         62EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nYBwKedBpwUWC3cKVJBWMxPYf46S0f8VCDzmlfCe2AY=;
        fh=5QDSM9kELRWq3cZ4pb6iakiLW7kYeSZHFWZtq5AbVsw=;
        b=im/AfaKS9eGR88ShvJar06gtloWWMq3fD+Gq2CezcWTbi/4cNDPkoljj4ACVOc2BJB
         qNeLX5YnkNDNouktn/HC5rb/EcnlaKYDweD7ea3mvaPY10AdLw8FByuQJDcr8TosBogX
         RvCzKnXLrOPvoRFyOiUzBlC0/VexSbGXMfI/O85OtdtFxnNRxjiLschM5dhsycHRo3Wy
         2O7WL9/lTuaWcAuWAQkLAC2vhCpsUNi7KxqEyzMJJZezWBmBtWBeF01t8uYf+hrxn1S1
         uR/6SUwC/t5mneirR4YDHcSXNzHW3DtHAfJ42zD61IvFTs3sh6dGkHXVVAwxr8Z6S/4S
         utTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PlH7I7Ck;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2aa10bf5a98si57665fac.5.2025.01.08.08.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2025 08:18:32 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id d75a77b69052e-4678664e22fso149916551cf.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2025 08:18:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWw/5Om/Op2IDnK+q3XHEkf9FkOelKgg4DrwGCso1EuT53Y4f2oBTtz1eG2j+QXbc8ikGCstnWVeJA=@googlegroups.com
X-Gm-Gg: ASbGncvHmvGbF1qwmkEhNyKJW0+zupLtONFhGgu0JYtB9nYdtDPRdvlq5ibJ2gZuxrT
	Nt8yJ6u39fpvailKsKsR5kfZ4vB8t+GgOnHP7Xap1FE+zOcSUgJoAaDYF0a94Bp1p2Wew
X-Received: by 2002:a05:6214:4a0a:b0:6d4:1813:1f20 with SMTP id
 6a1803df08f44-6df9b1d1fdfmr58811076d6.8.1736353112313; Wed, 08 Jan 2025
 08:18:32 -0800 (PST)
MIME-Version: 1.0
References: <202501081209.b7d8b735-lkp@intel.com> <CA+fCnZfkMuk8dtk+5_7DK_h0Pxv_JNgJDL3D-8pBXOByzVOtzQ@mail.gmail.com>
In-Reply-To: <CA+fCnZfkMuk8dtk+5_7DK_h0Pxv_JNgJDL3D-8pBXOByzVOtzQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Jan 2025 17:17:55 +0100
X-Gm-Features: AbW1kvb77COVvgnlxkmKtvn-ildT60hL_do9GKSf5jMr2fmOWX3EeIvrl7heeRw
Message-ID: <CAG_fn=UKrpQCQu__nJ74C4xqn5VOcYRc+hbXX5wwmLcR3oKdeQ@mail.gmail.com>
Subject: Re: [linus:master] [kasan] 3738290bfc: kunit.kasan.fail
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kernel test robot <oliver.sang@intel.com>, Marco Elver <elver@google.com>, 
	Nihar Chaithanya <niharchaithanya@gmail.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PlH7I7Ck;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as
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

On Wed, Jan 8, 2025 at 5:03=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>

> > [  118.348258] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted: G=
    B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
> > [  118.359770] Tainted: [B]=3DBAD_PAGE, [W]=3DWARN, [N]=3DTEST
> > [  118.365490] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.2.=
0 12/22/2016
> > [  118.373542] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [  118.381677]     not ok 4 kmalloc_track_caller_oob_right
>
> +Marco and Alexander
>
> Looks like KFENCE hijacked the allocation and reported the OOB instead
> of KASAN. There's a KASAN issue filed for this problem [1], but no
> solution implemented in the kernel so far.

If for some reason we want to keep both KFENCE and KASAN enabled on
that machine, we can use is_kfence_address() to check if an allocation
in a KASAN test was made from the KFENCE pool, and repeat it. This
won't look nice though, because we have several different allocation
APIs in the C test module alone, not to mention Rust.

> Perhaps, it makes sense to disable KFENCE when running the KASAN test
> suite on kernel test robot for now?

Looks like the simplest solution for now.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUKrpQCQu__nJ74C4xqn5VOcYRc%2BhbXX5wwmLcR3oKdeQ%40mail.gmail.com.

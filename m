Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV42TXAAMGQE6TETQBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 20AA4A96063
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 10:03:36 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6e8feea216asf98087826d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 01:03:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745309015; cv=pass;
        d=google.com; s=arc-20240605;
        b=ayMDYIyuKg2nkc5OQOl0XYdk1oo9XBXd4EAtljuyHNeGkd1gUOYgcd04sc10uOTj5F
         NS55tQbfTxpX0BTf+HmIl70n5e8tu2+w7zCEMRe7hQEe2GXDxGLrZNE565Z+d0f0x9+6
         OrW50itXhRngko7FCjTOm/qbcpVFD0i/XLI8agzRc57nEmA53usw3CPHOEc0X6c43OT1
         yxW+enkbhlwrJSWNSWSfq6BdqUZEu9sg4fYs2gl7Fv5M95EO+rrCbrRsMcXiqJGMoMi/
         wgZNo8R8eXWE/O0lK5tb2iid3HaKJ8corqqTNjulP6p+5YSlBZNwzds1epevwD/sgZjg
         IJ0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zu9ecB5MuZQTutcJJZyQlsNloM5Edeyo3ZFlCLYaWb4=;
        fh=ucvHawEVKRCmNpK+F3V6iBrrIzQfMk4XkjzKPyg2tws=;
        b=L8B0x5k328WXNAbjuv6KpoU+znKhSfhqPKlX+kZ/nVD/McE2zzqofhxZ0zn/3asrwD
         RXXZnx9Z7RybdfkLfZpFnvAcRQZzX91tXbr3RRY7teK5+B5ENoMtMQD0+S+fQ2844ntR
         bVaEgeL90YKiw3CpHqAGzGDAqePJYhgqQA1M+9s6A3e3SvMlDt1Nv3LN6/PAn1jLBfzv
         tz4OLm8SNb/Q+2x2/hIeERCulwQ3lyaDqwY1kNygbT7lBZDg1fu059x/Vj7WeUcmzsLB
         QODwq8ZiWIRUvyqGdueuLtsCTLUvVTNc9Dp4DwPdY5UziGBBsbDDk4ZXmfE4mUq6Uwzh
         pJ6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iSwn5dnq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745309015; x=1745913815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zu9ecB5MuZQTutcJJZyQlsNloM5Edeyo3ZFlCLYaWb4=;
        b=ZAK2q/qJZtsKKSoKP+0kjHDK9IYQy4vvk6ZGW4Jp2lPCiHs2RQJrNRzur2bSAwn8Mo
         HK2e2s3BiehPIVN2xYiDpt7Go+GyYJ9G61FPBV07CDy1iCrAJVp9t88FLGWMZZu15NFQ
         r1NLjdylKA5JCgFvEcMADg80g1Y5B1X6WGjYOdDFJcZfR7vCs1dPBcqZ3BrcATwEJN+l
         GJAR9GYip7907KimDdV+hCnqluuXtknlnqDz7FlTqvqmhtTMDoLBYH1AzZS/yd0diUyx
         0kSWVP04UoO+04Hs0iCnn+Gsmf76dmG7F03gci/9fn5ZdSMkZVT+xGqLqAEGS5+gPiOh
         Pi4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745309015; x=1745913815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zu9ecB5MuZQTutcJJZyQlsNloM5Edeyo3ZFlCLYaWb4=;
        b=U0p5RX14hvw6YMSgWTvRkSczrCe1dgNEtfYj689B28+6AyAz4ajvWKZbD1Qv0aJrFD
         fuS0aZesbyTT/iwTaglMDIAG1R47bcsf+zamtsT6VEc5A0psIgYez0B3NYNr+NlLCPyf
         NEL2zW+RBbfoRqALl2+K926O+DDDzC9yKiGlSs7MBzygQAhD0rF3S9lvDElpWtsJS0g5
         n3c402T9JVnDYJprnVHVY2gUDiCHijBk2LyLBldWjtNvjuXUhp0hNqxKVPRu3qrCmjhE
         DPPBTfmnkVZhyX8D8mqXJeD7keRLC5W8tJdg2vLcvG4g27R7tleefamCKDU66pWRCGk4
         9GUw==
X-Forwarded-Encrypted: i=2; AJvYcCUe8cqxVjEDdyAOUWuyfWP7Kz/4Y4V5lAa5NOKybRefIFjSycK6yO5wH0uB+2o7FLJeP+udxw==@lfdr.de
X-Gm-Message-State: AOJu0YxtYb2Nej5edDtbhOdfPFzQVX1ESYqiMzK194zTG8lP7NFFeQwh
	Oh8nAEuqTFjiihVSh5doXc1Omuy6b4iGzq3jk6N0USP51Dsdsdw7
X-Google-Smtp-Source: AGHT+IH9LHnS4RZasWwVFprh1XkY9GgbldCYitnoP3ZEOAZ4iL3zpOZc3TYU2mbinEn7denkSw1u5w==
X-Received: by 2002:a05:6214:ac3:b0:6ea:d503:6cfd with SMTP id 6a1803df08f44-6f2c4ef8628mr281624866d6.19.1745309015640;
        Tue, 22 Apr 2025 01:03:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKJFxnPIYksrM2cpdxD65W/JLldYkLqPHLy2Zsg7g+TQQ==
Received: by 2002:a05:6214:4189:b0:6e8:ebb0:eed with SMTP id
 6a1803df08f44-6f2b9a8e494ls519346d6.1.-pod-prod-00-us; Tue, 22 Apr 2025
 01:03:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWzUHW4yBiLvWY7uelpXMIJtF+0ONmQDLw2bI4/mK8nPCbQTeJ9VCgm4p47GCRe4y1vOxaf/9j+qoA=@googlegroups.com
X-Received: by 2002:a67:ed56:0:b0:4c3:878:6a62 with SMTP id ada2fe7eead31-4cb7de3fbb8mr9961376137.8.1745309013666;
        Tue, 22 Apr 2025 01:03:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745309013; cv=none;
        d=google.com; s=arc-20240605;
        b=fmuU7I6d26gBu03D7DrdtM/E+V6sVRf3C38d4tzGLqz2iba4XmH9NoEmchDmbIv4fG
         OKWYoxpdxZ8RT1AtKbKWTRCCElWEsa/xvkv9hrplJku0SePd0JqqA2fvyLfZmWREhmwI
         IpD5f8hXJyNXywhzroJjQyhRB5cPEsBYmjL3r+QdPg8MhghGbMao2EFveZx6uoXtPk3g
         /M4HBooNAd5Hy3sgMicJaVPSdzDXbOMVp2MbE+PCGnfyvzWMhxbDal4pI89405xyrZSY
         Vrhn7fmUlCU6Xwd9AWidG7/ZdVEgVOFtiJfywnkwJ08htFTocm2BjjVznfZPI8aVKsc1
         YbhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B15xBAPchz5ywMp21Obx8RhOKJ8Ncht56THHaOS3fYw=;
        fh=yo5MpHMAGSO+AwqS+ZfCgWcNWEnCBHnm9aNsc10L9yA=;
        b=M1J1Csr9OEWgJJq/Z9qXFVM2CDZms6/4BcFstl5aN9RzRZbylRL8/T6peAFTRDgH4A
         7pHWJHFt0TvqQ6A9XcfL5gy+V/1rftblgR4LV+bLDS984W2R9zoK+A1A160dfJYWGgRL
         x7tAC4HzkbZ1TvAxFPUDoH+/4T6UtHxVOkBVZlM752kjLIPDA7BLxyUa+PTO9MMyDwvp
         J7HyHl+k38ErjPmQMxmbskSyDZqzFxFbRcckNkliW26FbyPHPgIDlp6FbBAJ3o5nRBUo
         unhEdHULOqPthXBEZTKEDHSmTaxTQGlSOhXnN/MIKmzJlD9K2Oy/01e0It/wWtxvdnYM
         xp1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iSwn5dnq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4cb7d9d14a0si386034137.0.2025.04.22.01.03.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Apr 2025 01:03:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-7c54f67db99so569208185a.1
        for <kasan-dev@googlegroups.com>; Tue, 22 Apr 2025 01:03:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVjnKRbpQhohAqHaQG8TWa+XK5ABmNVvNK3m+oVAVJpBcwju50B1SnVE2GbmZdAkRoR5nPJolR2FNU=@googlegroups.com
X-Gm-Gg: ASbGnct3pCeABAO/WwoRaI8r43uoZOe30q9ZUaHLf+9eQwqLVfeAAoTJsDIQyL4E0+W
	I+hvyLx4+M1rbsJUK3+LNZ7Db/lzJp5LswQWYhj16PyAWoD+dFhADKE1uJJaFSME+S9VbjFgvl2
	LwoIvEPph6NNfeJyo5E0O+jxIpx4MNzYjdN5BVWBZ76OfcrwNGtCgwi+F2HMaD/Ds=
X-Received: by 2002:a05:6214:d6d:b0:6ed:18cd:956d with SMTP id
 6a1803df08f44-6f2c4f23ec3mr231676876d6.22.1745309013089; Tue, 22 Apr 2025
 01:03:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-8-glider@google.com>
 <CANpmjNOZyFeX2OfPsZkB3DfcFrdSWO9m+yGwB_rN3Mc+JySqnQ@mail.gmail.com>
In-Reply-To: <CANpmjNOZyFeX2OfPsZkB3DfcFrdSWO9m+yGwB_rN3Mc+JySqnQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Apr 2025 10:02:55 +0200
X-Gm-Features: ATxdqUEV3LLGO1BgxF4pNLM0PztS1Z2EZNeNcVdBnMd8dzNWwGcBT20VpzP0_a0
Message-ID: <CAG_fn=WX4kK+dktmFbUsMqiNd2zumRNTafYbFXd0662Rob4YtA@mail.gmail.com>
Subject: Re: [PATCH 7/7] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
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
 header.i=@google.com header.s=20230601 header.b=iSwn5dnq;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
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

On Tue, Apr 22, 2025 at 8:47=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
> > are inserted by Clang when building with coverage guards.
> > These functions can be used to detect initialization order fiasco bugs
> > in the userspace, but it is fine for them to be no-ops in the kernel.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> This patch should be before the one adding coverage guard
> instrumentation, otherwise KASAN builds will be broken intermittently,
> which would break bisection.

Right, I'm gonna move it in v2. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWX4kK%2BdktmFbUsMqiNd2zumRNTafYbFXd0662Rob4YtA%40mail.gmail.com.

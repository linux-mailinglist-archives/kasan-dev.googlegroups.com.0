Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VC723QMGQE2IL2JMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8B998FD94
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 08:55:43 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e25d494faa4sf2162762276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2024 23:55:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728024942; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z90nGbVwv7PoK5PxMm26ragdxFgAxbtwA/mfozOLXlBZocb7fUEy4dgKHhYkhzWRH4
         /fWO6DVb+i8GZMcQryRl3mi2msBQPgPiKbJkTdCioNTWKFFdiaJORhNaJuY2zQLeIp25
         /CgESmluYk6+9uW+0qM14cGTSfysKFCvuWc3nOfq9645jOFgVjw4FPkerohX/ry6Cv0l
         amVsWbYmMCKmHdC2WJKK+himNAbUFDMQ93MsG/S02HB4YEMZa6MLs+WVoMkxsrv13wND
         W5iSte8fp7LRMbPU5UlAEEpv3bbk0k5P6ChULJnXJylzoqZJ+ttjuzog8iLr2m03/gkv
         Q7nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C8SFGxGoqm9Re87Faz7QMdGr5l8VywKViqguKwGtTwg=;
        fh=alfm/HAXFSc0Ey+A46t7KUB1KbWSDNxB2+cArBFzbnM=;
        b=akjaAto29Q4HPw3ysJij+8cz/JVshL8JC2VgkobGRv1mORzxjvHLFkkn9byWvNK8uw
         4FkDjbZNgDCnHE+Gx9/9jb0YIapAAtudQnhIcx3iLFRdfwYAnflXyQQtbDgc4HRaG0LF
         mNa2yZMfJ862BSVgJEzEbjW4g6KjiQX91bQCgBet9AXi/aaAdiEV2bxRNKd9X9Z3OiTz
         mFF4oEB6RNJldjnR/aud4Kmqj3cpzn2+hpY2CtQ6w3qEorMaF3nE0zVvrj/mXfFzseUG
         VPYRqc8hexgCXLXN5WGVaii1Uv4S57XNboeu+437jH5nfCtH/iP3hEaIwffJQR2HrOW/
         N09A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g6BUDgda;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728024942; x=1728629742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C8SFGxGoqm9Re87Faz7QMdGr5l8VywKViqguKwGtTwg=;
        b=t76BxBjjMMsOmyoNLygQTHHG4efGX6EpYiSfwxsXTnwOiitnBpE/kSwEGRyJsZvOds
         qNnrPdvtGF30/cAhpOVmxj9if0m40QQTFS2L85d5uAieD9uiopBjFoONJN36sy6ukN3M
         o/wzAncXoVMI+ozie/zhEs3r2/SzmsvKFVZj+JK6vB8H8rInTFjk5JecftekgNcbHD7+
         4TTFXoYOjSXOsiR1NrDOT3o7KVaPq5FQ8q/ZtALBHqUrG4R4t02n/aq7PezdbdWMDxx7
         cnm0cRJjQCY3LSWP0Oz5Kjx2/8hlDhyqGoLg4KpQQIIo1zFsYHKveq8TbqWGluArSzZo
         +AEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728024942; x=1728629742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C8SFGxGoqm9Re87Faz7QMdGr5l8VywKViqguKwGtTwg=;
        b=VcOtHQRoALy0qgxoQL4bkFDpRCTrIq/xgNSyjiPukCy8nHZENRCnnuiq9UgZCafFCc
         API0UU9V3Z/Lvk7FDwpQcnMaWrqN7NrEMW8doR7d7VAiZ0hhztt/QDq9BsGQGyPoiwJH
         YtLHQ4z5HHeDmP3yqoiyK1rsi1t/3Lij06B/uzr0bYgBWAXFPyKOEKRXyNQpoAwcGSzd
         ZBPUqHlp3CmQfTIKJ+mlkXpfugiNf5RV3+JhdssAiR1p2wpuR+8HmEcxKpKb5BiTRXTe
         effCSvhZYwCzttWWXRmYbDZB3b5oLkS53krDXEfZmbXREHPk4WvrTslyPF3gCCjJ7WfW
         2FBw==
X-Forwarded-Encrypted: i=2; AJvYcCWEYG13TPnfATvzad2mhnZXMSmYw9a/bXLYFBlTrRSd6I+AaYU/kz4T89DiFnfMc8ibMdKrvg==@lfdr.de
X-Gm-Message-State: AOJu0Yw3BW3gbkI14KOJC6xLM64w0wvL9WHpM/cOViulIdiZ4GCiBhUw
	Twi8Cog29jmXTEYlQKTxMpAfWikZT875p7RIxkQtQWQQfIqQbNyI
X-Google-Smtp-Source: AGHT+IFOljyFZZdAxYD9ADc08yQSG01FCGIxCLKNLKEuksr8hIRHik5TTa09vJvSYGlp+6qebChm6Q==
X-Received: by 2002:a05:6902:e0e:b0:e24:fac6:fad9 with SMTP id 3f1490d57ef6-e28936dc1dcmr1278724276.16.1728024942222;
        Thu, 03 Oct 2024 23:55:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:120b:b0:e1d:a081:e017 with SMTP id
 3f1490d57ef6-e286fa6c604ls2227194276.2.-pod-prod-09-us; Thu, 03 Oct 2024
 23:55:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQxJ/OkAAYMZnSzfyeXPw5dJgN2n7NqmNXP3RFOIdILwYgnYW5MB6qwDKqPjG4M64Zt5RcR6foK8c=@googlegroups.com
X-Received: by 2002:a05:690c:d90:b0:627:24d0:5037 with SMTP id 00721157ae682-6e2c6e90c3amr16524517b3.0.1728024941322;
        Thu, 03 Oct 2024 23:55:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728024941; cv=none;
        d=google.com; s=arc-20240605;
        b=jy3r3GARdM4Bc8iYe8w21tONCVVJR6gx5iM/MVsxHHFTIouGYy7ckJtMaPS0IKs7bF
         kUxVTn58SJtTyUuHJ6QRPe8hNLbVm/gg4GQwIke3tKLG0thf1jL564Zkk27OQal7xNoB
         p1gVNmgSNJQ+MfwkTG7gPSzWwsqMgqRrfZQwhm/1Jj/070Rw/vOprM4FQkPiUale8EuJ
         /eT1nkMI+sQu+C//VN3/2xJmuxOFt2jyv8tLlGWxNKBfx+C7Qxqs1Es74UYG8fjRvfan
         VFHiYd8egK3eb440abFamg46P+N95J8YcAp43gPQ8+CzvsjFgYq2Rbkd3O967fZ7a8kp
         Mxkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=q7o2gtlpEVASHHeeVwEYiWWRZirGk2x9V5M6y6RZYrM=;
        fh=N2sLcP6QfTIq7gF/xjl/2yQeSr/RTm246rz7q60nRFw=;
        b=V3vaZyEv1gjXMzPLlM0Ta5pJzvnOC9d/SODMD0r/fEkMuOzmNsmuJI3/pwreh10cdd
         9TPaW/RYmkH3bcl/nHN3pLQZ/tN9WLS+YcVq+zzhb1O8+jiYoCoZgAWyqoCrFDCwmiwB
         U4TCzulHtc1n42g5QxdQ7Me4C6SrwfpnNNyBSmI40B2RXuu67ty69fFoLdvmTinlovVa
         L4YI0h/L+jRDcwbZuPE0abMGloxZceKNiaC21pYEDByHI1U4Xc3zuWwAQGi1EH+q70EA
         HE4piDlPDsE1rPXUFPapKxsv+omKPxzDlhlgcFUjieSUZi9pU6hj/pZ5FXZXf+LztDEq
         fG+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g6BUDgda;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e2bbcad91asi2236577b3.2.2024.10.03.23.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2024 23:55:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-20ba9f3824fso14097865ad.0
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2024 23:55:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsI65fGzI7BNJcqUvRJ/ODakRbr3CL1etda89UMmTupWRRsf+1ytMhxcyf0slofftbMok86aEEF5g=@googlegroups.com
X-Received: by 2002:a17:903:11c7:b0:20b:9f77:e8bd with SMTP id
 d9443c01a7336-20bfe04aca9mr24574365ad.36.1728024940031; Thu, 03 Oct 2024
 23:55:40 -0700 (PDT)
MIME-Version: 1.0
References: <20240927151438.2143936-1-snovitoll@gmail.com> <CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com>
 <CACzwLxhjvJ5WmgB-yxZt3x5YQss9dLhL7KoHra0T-E2jm=vEAQ@mail.gmail.com>
In-Reply-To: <CACzwLxhjvJ5WmgB-yxZt3x5YQss9dLhL7KoHra0T-E2jm=vEAQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2024 08:55:03 +0200
Message-ID: <CANpmjNMBJJ4e8EGkfFB2LmtPNEtzx2K7xLhK8PXdRsO=KiAS0Q@mail.gmail.com>
Subject: Re: [PATCH] mm: instrument copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=g6BUDgda;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 2 Oct 2024 at 18:40, Sabyrzhan Tasbolatov <snovitoll@gmail.com> wro=
te:
>
> On Wed, Oct 2, 2024 at 9:00=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> >
> > On Fri, 27 Sept 2024 at 17:14, Sabyrzhan Tasbolatov <snovitoll@gmail.co=
m> wrote:
> > >
> > > Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault()
> > > with instrument_memcpy_before() for KASAN, KCSAN checks and
> > > instrument_memcpy_after() for KMSAN.
> >
> > There's a fundamental problem with instrumenting
> > copy_from_kernel_nofault() - it's meant to be a non-faulting helper,
> > i.e. if it attempts to read arbitrary kernel addresses, that's not a
> > problem because it won't fault and BUG. These may be used in places
> > that probe random memory, and KASAN may say that some memory is
> > invalid and generate a report - but in reality that's not a problem.
> >
> > In the Bugzilla bug, Andrey wrote:
> >
> > > KASAN should check both arguments of copy_from/to_kernel_nofault() fo=
r accessibility when both are fault-safe.
> >
> > I don't see this patch doing it, or at least it's not explained. By
> > looking at the code, I see that it does the instrument_memcpy_before()
> > right after pagefault_disable(), which tells me that KASAN or other
> > tools will complain if a page is not faulted in. These helpers are
> > meant to be usable like that - despite their inherent unsafety,
> > there's little that I see that KASAN can help with.
>
> Hello, thanks for the comment!
> instrument_memcpy_before() has been replaced with
> instrument_read() and instrument_write() in
> commit 9e3f2b1ecdd4("mm, kasan: proper instrument _kernel_nofault"),
> and there are KASAN, KCSAN checks.
>
> > What _might_ be useful, is detecting copying faulted-in but
> > uninitialized memory to user space. So I think the only
> > instrumentation we want to retain is KMSAN instrumentation for the
> > copy_from_kernel_nofault() helper, and only if no fault was
> > encountered.
> >
> > Instrumenting copy_to_kernel_nofault() may be helpful to catch memory
> > corruptions, but only if faulted-in memory was accessed.
>
> If we need to have KMSAN only instrumentation for
> copy_from_user_nofault(), then AFAIU, in mm/kasan/kasan_test.c

Did you mean s/copy_from_user_nofault/copy_from_kernel_nofault/?

> copy_from_to_kernel_nofault_oob() should have only
> copy_to_kernel_nofault() OOB kunit test to trigger KASAN.
> And copy_from_user_nofault() kunit test can be placed in mm/kmsan/kmsan_t=
est.c.

I think in the interest of reducing false positives, I'd proceed with
making copy_from_kernel_nofault() KMSAN only.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMBJJ4e8EGkfFB2LmtPNEtzx2K7xLhK8PXdRsO%3DKiAS0Q%40mail.gmai=
l.com.

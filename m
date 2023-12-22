Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJPJSWWAMGQEKX2WCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 570DF81C938
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Dec 2023 12:36:07 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35f8dc26895sf17753595ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Dec 2023 03:36:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703244966; cv=pass;
        d=google.com; s=arc-20160816;
        b=be8YRgmISkvfcn2YTPkDaVwGGCvrb1JtE6eKfKxjCSfqW1G2b/WJXtavtGgkqY2xRa
         TvI8feXIacf2JBllcr48pwjvmkt22uc1Tus8cooED6fBG1uTcr0nWaAwz5ejQQtwTMTr
         wJWtVqj8j1Fko9Zc+OlnWkPPTy9Yv/cCOtdBBNpI9boL0DqLKYvP94PeLBhHxQvf7ew/
         hrCgCDgsfVOSz2fFHv52iBmClBhv614qZqu1oYjv8bpe69QG3C31ajv11df11I+Vmsz3
         zoET+kzHSqbje8Lv3e2CROCcbYqZBsrSCZmPd9PfPnUGfaWs5CQRyfvOQJQj8cLnb/Wh
         criw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Ws3/MGwmzuhCS3f0ostAnu4b+Omg2Goyhk/dNDX9M8=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=rnJ/S6R1h/Tiap7kflORnU/cjAGnafDa4Ux/7dtcRLL1NgUNuOzAE3/qZBwRJJ9bqy
         PbPuVfR/wW/KHMLDsZ3Wv9y3UqaGYr/EzekKUZXZ6WyW5cyBEyv1fYBnfrzPFv9+p5mM
         nZbg3d09M3awKdtB21PWzwo5xSkER0/EMOwLEwC53fi3N84A1ii70N64IBgoxT6FWveF
         0W5WFq+fRNM9sbYL0daC7nmijuAacxagPdQyxVGQipnxSANtAOw6QYln6D0Iw+d5FAoH
         tdm0rXcsEGimjWRFF+pJKGd9QmI1XLDSM5N9Vu8MFd6+DSNQDji+TXXObqwqsLZdRHTH
         TWHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NGy6mLLf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703244966; x=1703849766; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8Ws3/MGwmzuhCS3f0ostAnu4b+Omg2Goyhk/dNDX9M8=;
        b=mfD13DE5lw5QRe99iUBg6Ac/FRS/YYgag/Zj4N16bqkI7vg43RYZTzBP1/++/BIJKu
         m8A4jBRMj7pq1SJiea0/muIhZVCr2zzeqxuSUEpL1pKCcjqCVIdrTk53Yfn/DjSik4R7
         jx8QixESqSK4IP0obWZJrJfph9Pd4GqrKhoElApQiaNzDAcuO3Prx0f3Au1im1MDdBM0
         no8LyhZ2TzYSlKzPCxB2NTa5E2SN5lx7AJQJVNbMFfd5NmJQWQ1p5mcYgQ9XGHF/tI26
         dCZ5uNwOI70JN68L6jlA71yAZ0faB+ee3GS3cr02lTtlKE7UIRft6E+lPM8KL+rAn0lI
         RcAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703244966; x=1703849766;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8Ws3/MGwmzuhCS3f0ostAnu4b+Omg2Goyhk/dNDX9M8=;
        b=eOZ74cuMiTRpYDQEM6YBiWmBjl1rrj4yUFbXE/hKsuPc2TChqQFsqhirLWFLDfPGM0
         Kl1OAc4xtZhQkeU5aCMLzvWz0E19o5+qQNCU3qlw+PN3ZRZc8ntBSx7B5zowPsc1RwXt
         iIRr8fR6LJ04ImUEbi85W/FgJWLUaRx9LRhOkmdEm4Jx8ITojT5VnKANGcr7NhYy9A+k
         GhCVYS7brkzoz3bdAi3RU5ng8FwqYMpqxIVXHNIThmdd2/A4VnvZVzBbnD7vxjzTm3Rx
         bpPWMRdiX1H/kVxl8Zg92PguiwuOVAMqkH0MVn9UBbtkAclSPquDHOsdvAZQXjXS8wbz
         0YWQ==
X-Gm-Message-State: AOJu0YxrfbM3jv0TCOZfTNQz2Cu2umcRhPddUenTo0eqmQAUHsU1bO42
	lrmqJwplBsnbKBw4mQ7LH+0=
X-Google-Smtp-Source: AGHT+IGFbJawJWftMyfAyxWbBCWI5IboRlBnQ34H0LwfteBQrytufHECeY7Y69QLeCScAryftgL4tA==
X-Received: by 2002:a05:6e02:194a:b0:35f:c91d:927d with SMTP id x10-20020a056e02194a00b0035fc91d927dmr1449425ilu.63.1703244965870;
        Fri, 22 Dec 2023 03:36:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f09:0:b0:35f:83ef:15b6 with SMTP id a9-20020a927f09000000b0035f83ef15b6ls1660681ild.2.-pod-prod-09-us;
 Fri, 22 Dec 2023 03:36:05 -0800 (PST)
X-Received: by 2002:a05:6e02:20cd:b0:35d:a39f:8ff9 with SMTP id 13-20020a056e0220cd00b0035da39f8ff9mr1325420ilq.11.1703244965179;
        Fri, 22 Dec 2023 03:36:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703244965; cv=none;
        d=google.com; s=arc-20160816;
        b=1BtqaRfvvip/S5ftO4VRPn3nEQ48fo/NyfymeD2dTyE8yOTgVO9O38vqcc7rnqX/Y+
         nzSi8dr2/oAddPZd02hEJTitkbpe4u1RW71bl6vwlakNfsCxBLg1p4RE+PTz2XJQTOu1
         +X3CT0lCNfYU8si1gTqK7EjhwwmJVeJQ4VuQ5A1uLU0G2nsv3mb6BZQGbITjdysypMh8
         0DyPR8kTAbILmhBKROqMOgITtIcsCykxtJLow7I0W/zg2A5EhqcHsr9b4hoMhzG23UUA
         gOR2IT3yLeySkbr+xKCgods11X1WV/FrWMGJYWyGwvbgzQzVB0yCugD57cSMSkOzUGyq
         p+kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HlozJj1f2kvO8UJMaafcew1dPPV20AWiBo6Zcv/BbcM=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=IEqkUFttAICStS9g4oHya38RbQYPZ70P2FYtgJMmXoZA59ueHyuZihhvUH+PB8PNWz
         TjIKvKU40y7B3lptXD77qRrwvGoWRr9YvZl331es70fgitpEzL7DrzD3AzqFhqRwTFhJ
         lfuwshIxn4miCP+MI554qNlk7QN7OXS+IR2AsX6k6EuRh4iMz56vhCIfPiehBN1wXdtB
         yYSuoQtj6JHbveeB4CWd1ffWk6KOjB5llSTKHlwpNv7o0Wjgg0wyveD2Z0amlAdZZfyV
         CeCg+xqmmi/53BY9NQgW3TPdWSLyoatuOOcKv4HD4meCdQS7lOgiJ/Qqv3HX1vTo2l1l
         F7hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NGy6mLLf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id u12-20020a170903108c00b001d3536821fdsi256867pld.11.2023.12.22.03.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Dec 2023 03:36:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-67f6272e7c6so10537246d6.1
        for <kasan-dev@googlegroups.com>; Fri, 22 Dec 2023 03:36:05 -0800 (PST)
X-Received: by 2002:a05:6214:b62:b0:67a:c46c:64e1 with SMTP id
 ey2-20020a0562140b6200b0067ac46c64e1mr1305854qvb.8.1703244964059; Fri, 22 Dec
 2023 03:36:04 -0800 (PST)
MIME-Version: 1.0
References: <20231213233605.661251-1-iii@linux.ibm.com> <20231213233605.661251-18-iii@linux.ibm.com>
In-Reply-To: <20231213233605.661251-18-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Dec 2023 12:35:27 +0100
Message-ID: <CAG_fn=UNdruNOkyQ8c5mdWQGC1-xP+86GX9Zsdg3VSc=5itNaA@mail.gmail.com>
Subject: Re: [PATCH v3 17/34] lib/zlib: Unpoison DFLTCC output buffers
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NGy6mLLf;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Dec 14, 2023 at 12:36=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> The constraints of the DFLTCC inline assembly are not precise: they
> do not communicate the size of the output buffers to the compiler, so
> it cannot automatically instrument it.
>
> Add the manual kmsan_unpoison_memory() calls for the output buffers.
> The logic is the same as in [1].
>
> [1] https://github.com/zlib-ng/zlib-ng/commit/1f5ddcc009ac3511e99fc88736a=
9e1a6381168c5
>
> Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>


> @@ -34,6 +37,7 @@ static inline dfltcc_cc dfltcc(
>  )
>  {
>      Byte *t2 =3D op1 ? *op1 : NULL;
> +    unsigned char *orig_t2 =3D t2;
>      size_t t3 =3D len1 ? *len1 : 0;
>      const Byte *t4 =3D op2 ? *op2 : NULL;
>      size_t t5 =3D len2 ? *len2 : 0;
> @@ -59,6 +63,26 @@ static inline dfltcc_cc dfltcc(
>                       : "cc", "memory");
>      t2 =3D r2; t3 =3D r3; t4 =3D r4; t5 =3D r5;
>
> +    switch (fn & DFLTCC_FN_MASK) {

It might be a good idea to add a comment explaining what this block of
code does.
(And that it is no-op in non-KMSAN builds)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUNdruNOkyQ8c5mdWQGC1-xP%2B86GX9Zsdg3VSc%3D5itNaA%40mail.=
gmail.com.

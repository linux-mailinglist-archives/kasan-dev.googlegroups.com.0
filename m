Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMMI7HFAMGQEXQHUTBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 06245CFD66C
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 12:32:03 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4ffb4222a4esf20355551cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 03:32:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767785521; cv=pass;
        d=google.com; s=arc-20240605;
        b=YTBI+54uH5Dc9mJ+MoaDSspICRhxB3uwEbrmazt05GOTiXD/4eInBy4fXYK4dIe1kY
         ptX6xBibti2LCOp/AkAxbNy+Kymj0zJKvK6YqY0X88M5NCLxlAmcbemGrB17N1wEerDa
         krh0NiNIMaZy3QZJ+nIq9bxveXXmvw9tKy28r2OsE71rguxb9NfWCEKOfaP5ImC5gX83
         5k2UU/RxPmSSDSm2S3cydxIwKgaZdVSMovFN5hiwTEqiZG/ItRp31UCiyc8Ou4rR89TV
         FB5Iv2JA/rBzhlOiMJAsc5F92PGB6cxYHgUEYYy79AbF5MuqVEB5JwDIotV3Kav4fzSv
         a8jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V/M9HbIUK9U8PDasrw8ZLO1oLCgUaL0veq8H2Ub/+68=;
        fh=jMBjIzXHgGkwSR72x5B2IGs80+i5FxLgelXOuJVvL80=;
        b=LmZq2RlUUjB/Ul5NIvePlbJnYV1CLt4g1vWJ8YooLtWQm51F5xdBDWwUBUCffEUNUj
         oi189PVeS3gpQ1s1QkacN32ukNvn3W76m9kzVPuA9ceUmUZkCms0duz6Ko5xL4wNQaNb
         ztZ0uuC1EDtnVGGQRVTGpbUAk5O4DDxrP/zQXTnbSYcR9Cav5ICBNCSQzV1ufqKUiFUp
         3PPu3EoZ2TU4fLyV8C/oaJnW/HKoIXkfBS/DS233Z0uVLzmHO0tQvO4p5DCZk+L9AVPD
         ptpazDryEAtyegvnu0KKS+u0nj/kD/WMY7LgDNUrMLS7wcxMDhI2uMCzF4xW+5PJby3e
         rl5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1xK5zhvY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767785521; x=1768390321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=V/M9HbIUK9U8PDasrw8ZLO1oLCgUaL0veq8H2Ub/+68=;
        b=eDhg+ejVlsC30z8CHrYnMmkew954VGsRTNPOcJEs3pt9OQKB4oKPkuOEePlOrhq6HX
         0EQ34FNeH4Al9/LMCBHJtnAXD4ijdVEHil3e4njPq5ENG1n4Y0IAooANqNuEGiJTpa1K
         6riMValgG/2/gyI4oQNMdc5vRKJ/rA5M6orK91Ipei8xZevEhxj2BgHAHgKHpde09b28
         QlelKXTJf38rvYyjwByBjXK5FblOjI6kxU1q9QQ3GSzlafT6TzT0K3WX07cCkHkxlUSd
         k3vuFVmDQSGXmn3Hq8PGCc0C9FLMfobt+1xmuWK+PNMvXbOf42yiHq1rm9OrYelEyLug
         eBtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767785521; x=1768390321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=V/M9HbIUK9U8PDasrw8ZLO1oLCgUaL0veq8H2Ub/+68=;
        b=Qps2s98gM2mEvYvtZl4BHfbuIdYCPF3wAOZururkQkxzrJRm5x5yzV+DsPVQqDEg4M
         HpCSgfcCJW1CU4jFsd38loY2bskVIyAO3/F/86rQScylb59nOTXQaR/gQGD+oNSyysw4
         z2omdNolqLIZApmwVsJsbraBjoAXiAxwhrfXgDDCdrTHe7h+GsVoUihhU0LsYKu+hyjZ
         PGPJIvatwfob923BTcPTyzhcamoPlxoQqiAh3QONs8viLUX0cb7CuOjZ87YI50JPaFNF
         HrapHjE1KsfMSPJOIsZL5pGExcjsutQ1vdbqRreCX1qGVJ3CLRMjg5VhTgGPpghMvs6h
         p1IA==
X-Forwarded-Encrypted: i=2; AJvYcCW42ilWCYxsgYqvZW6eBnpROwErrRKo9r3fFeMxvdigsbvZyv3L2QnIgnrIsrLNfGkla+BuBw==@lfdr.de
X-Gm-Message-State: AOJu0YxMvMA2UZsXRVBDXQOSh/XrkFzhHGlvY0VCCNprkZXgTOlA7a2Y
	heFGiJPPJT4Ci8EuL9iIGmpTDe4RpnskbsZx/c95XKxX64pFHpxHhWkB
X-Google-Smtp-Source: AGHT+IESDA8WJZbBLjMedUfan/ujySpaQ6f2WRVrq6wO2x6vR9SBgWStEXuqnWEuFN6e4vS2tMFALg==
X-Received: by 2002:ac8:5dd1:0:b0:4ee:14c3:4e65 with SMTP id d75a77b69052e-4ffb48d4191mr29642741cf.29.1767785521550;
        Wed, 07 Jan 2026 03:32:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYeul4OHzX1ZpKt4ggRMQ9IuaUsAjQ8oy5VCIabIfifZw=="
Received: by 2002:a05:6214:f2b:b0:880:31e4:d7e4 with SMTP id
 6a1803df08f44-890756be9f4ls40911596d6.1.-pod-prod-07-us; Wed, 07 Jan 2026
 03:32:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWij2QQ0OsTA/Dj52bWDJ7jezElsF6eqTbm3aoWP+sP0Qbp2zQLMQLu8LppC1bSEiUETUSNVEgmyVI=@googlegroups.com
X-Received: by 2002:a05:6102:554b:b0:5db:cf38:f506 with SMTP id ada2fe7eead31-5ecb68d3033mr772563137.23.1767785520656;
        Wed, 07 Jan 2026 03:32:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767785520; cv=none;
        d=google.com; s=arc-20240605;
        b=LRoOb3DsEesDVP++Cxnzgm/9iJeuapCZpwdAjq/i+KZFQf8w7o8mettCSqPGQwf+1O
         AkVGUEZQgPNZo7rKPyPRlevPuRQEIyg8XtkRglIE3EJ+mHw7mbbQTEOppKNBrN5hd0KW
         b9g2PukRRtZLv1XLs5otNfdOnXZcDsq3H1jqEqIMliK1fyPLs8ViNV0iqdFls1ADtY17
         hYq3pLsvBJEGVHBzIPSy1hfjlZda2NnF2qGnoFoeK+rJSKrGm9yFSG411xqMMdns8MD4
         L4h0x+tgOuWHrJDB5bKPwkY1qOmnczSmMw+DERojiOkuQmHCSTRdvrn6XU8fWJqUbsSx
         4MIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=litZ4e7M86cARFl5FkYwdJNu7NqLPWXXCL5QptokvTA=;
        fh=eBfT6mHfGR3aNXhfy4zGQXV/23khCoR+TJ2SbvQlVQA=;
        b=TySLuLhE/JEaVYcxjOllYNi4efiGj97nWCklXaYIyytIjVaTLywbb8dWQ45ytKLG0g
         CUgpoWfjV5Pao018526U06UtnkXPVhJo7/ayF1Ccmh5x5z6pOuFgEbU5E4sEuzLJ0IoV
         VUSHWGGlbSsaQE55SnnbKMVppO2U6M+U/RgvrbU4I/P+B5UFyKpPEMuYgeXm2l5v08Zm
         QnQKlQkdpWGPeacFjBZ8zAwBMeSy+ijn41TJYrG6BihvJJdRyFBjRMC3vePPTq0o6WQd
         CiBaocnCfdOLcRsDs3I6cSAWioEbrWIPEbah75flseRAQL0WSHoL85bFmDCnnMxG0RB6
         aUuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1xK5zhvY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ec785e1a72si80382137.2.2026.01.07.03.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Jan 2026 03:32:00 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-4fb68720518so19911781cf.2
        for <kasan-dev@googlegroups.com>; Wed, 07 Jan 2026 03:32:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXAKKaI7xRTjgxkSiK6inbvMw3ceco0PH0mnLpavbRUfS6wliUTMop5hHr325cVoipFyA9/n/ThqBo=@googlegroups.com
X-Gm-Gg: AY/fxX4A0Mo9EFHhkWV/VxOUwNN9ZBRUbbERYHXOXFxZmGl03sTzcALWCTGFyd6iP3F
	zAC+vncDUCZAXzBHM9z2rS8bsdIDHSKKL2yqFg8WeXg4RENO3OuFpBwrNKRZTXf5hLV4p+zJpqF
	4clyAXwUobXM9ffuT5DsEhK0GnOJYbattwqkFbAB1EUPfO9HbhZps8XIenL7qd2Q8PwgZAjx1ow
	C57liuEWaNV7WnIJaso5k62VNtdKNc7bknXMF+bGYrFSpRtR4zq8lT7St9+DZPG8GBLxmXIJi0l
	e7EbjrE1Buay4l4lrRPGOCASXw==
X-Received: by 2002:ac8:5888:0:b0:4ed:de14:b374 with SMTP id
 d75a77b69052e-4ffb4a30b4emr27238821cf.64.1767785520019; Wed, 07 Jan 2026
 03:32:00 -0800 (PST)
MIME-Version: 1.0
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
In-Reply-To: <20260106180426.710013-1-andrew.cooper3@citrix.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Jan 2026 12:31:22 +0100
X-Gm-Features: AQt7F2rBtp15cIbGMz4rlQJXTGY_KN5GqiCzBzz7LDiwe2G7Izjvtsx-3g--OVo
Message-ID: <CAG_fn=UnyVPSEt1bsWMw6QLRFkeMF8UcObVXv01j8FPYDV+__g@mail.gmail.com>
Subject: Re: [PATCH] x86/kfence: Avoid writing L1TF-vulnerable PTEs
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, Jann Horn <jannh@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1xK5zhvY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as
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

On Tue, Jan 6, 2026 at 7:04=E2=80=AFPM Andrew Cooper <andrew.cooper3@citrix=
.com> wrote:
>
> For native, the choice of PTE is fine.  There's real memory backing the
> non-present PTE.  However, for XenPV, Xen complains:
>
>   (XEN) d1 L1TF-vulnerable L1e 8010000018200066 - Shadowing
>
> To explain, some background on XenPV pagetables:
>
>   Xen PV guests are control their own pagetables; they choose the new PTE
>   value, and use hypercalls to make changes so Xen can audit for safety.
>
>   In addition to a regular reference count, Xen also maintains a type
>   reference count.  e.g. SegDesc (referenced by vGDT/vLDT),
>   Writable (referenced with _PAGE_RW) or L{1..4} (referenced by vCR3 or a
>   lower pagetable level).  This is in order to prevent e.g. a page being
>   inserted into the pagetables for which the guest has a writable mapping=
.
>
>   For non-present mappings, all other bits become software accessible, an=
d
>   typically contain metadata rather a real frame address.  There is nothi=
ng
>   that a reference count could sensibly be tied to.  As such, even if Xen
>   could recognise the address as currently safe, nothing would prevent th=
at
>   frame from changing owner to another VM in the future.
>
>   When Xen detects a PV guest writing a L1TF-PTE, it responds by activati=
ng
>   shadow paging. This is normally only used for the live phase of
>   migration, and comes with a reasonable overhead.
>
> KFENCE only cares about getting #PF to catch wild accesses; it doesn't ca=
re
> about the value for non-present mappings.  Use a fully inverted PTE, to
> avoid hitting the slow path when running under Xen.
>
> While adjusting the logic, take the opportunity to skip all actions if th=
e
> PTE is already in the right state, half the number PVOps callouts, and sk=
ip
> TLB maintenance on a !P -> P transition which benefits non-Xen cases too.
>
> Fixes: 1dc0da6e9ec0 ("x86, kfence: enable KFENCE for x86")
> Tested-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

>         /*
>          * We need to avoid IPIs, as we may get KFENCE allocations or fau=
lts
>          * with interrupts disabled. Therefore, the below is best-effort,=
 and
> @@ -53,11 +77,6 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>          * lazy fault handling takes care of faults after the page is PRE=
SENT.
>          */
Nit: should this comment be moved above before set_pte() or merged wit
the following comment block?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUnyVPSEt1bsWMw6QLRFkeMF8UcObVXv01j8FPYDV%2B__g%40mail.gmail.com.

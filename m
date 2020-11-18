Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXUN2X6QKGQELXKK6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 10B352B8176
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 17:08:00 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id n7sf543752oij.15
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 08:07:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605715679; cv=pass;
        d=google.com; s=arc-20160816;
        b=jXpN0B8c5mZe/0LUyPs93idjNj9Qk2KX6JnjE9CdzqKLlC3JxdXlhvTG7i5Ug8E5fj
         qPnKmiDew4bUjKixBZV5xBlM67CUF6oWJvHYu/EvTzmdC9J16bkFmgy3rjDqwZPU5TQZ
         Y9UZKwOKF0f0MxXvSab4oCohyTbNaINQXNJgUF5Pu/oiRha+Np0WFFB5qsewoy2DCsBv
         w+hv/O6//OX/9sJFORlzYcxFVUxByvxK1yMMQaLqTVqbXd6DhfJqcIh6xbiz1xDCd7aZ
         WXJWyjQu5qDvDn2A2Bb0aTA7RHtDjGtZ+wEpvFssrdKtQYigXeFPIrZ12UakHx+o3iB6
         8hig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VzNOSdkbYBkOukDT+IUr0ZiF2Bt9ORApw5cW7gcrLnU=;
        b=LHhup4W4VQjW//7jzNevgwWUutm1Ukf649S8iQ9/Vrf/MW7NWz0UkM8hke2FEesuvP
         afDoaCKr+F1j6Cfnf9FLLH2JmO7RKTip3tJ3wLgC0qFTGzPtw6b9emw7TY/RY5mSmCpq
         sqZB2eksQLNi78/aK66Tee/Af9G3RCMrDwS2V4YcnGjaYXzdShYiLEfjmqeKKX2yVjhC
         1dxPEhiAOxK+OW005eTv3NR5Vah53eSWbd/1JCYoKMM4VdLjVhDFvBJ2WbP9gHveq281
         KrFVn5/EqhId2hGCGPFPCDVacl9FrKVI+vTq5sjzTuDNwb5/D5r9kVPh+J/8FJ7xOsaD
         6vnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ga/ygbCV";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VzNOSdkbYBkOukDT+IUr0ZiF2Bt9ORApw5cW7gcrLnU=;
        b=IBxV2pJ+KULsdM31vmUxzD12xXBbJLYQBAHZiqA3Nv0xT96YMyq/A/kXZVoMJUuwIu
         vCjod5wYEK7Y43IiKPvfRi7wqLrMi6qYbRlM+LB1K0x38IuE0kG0Ql95X6Px6QxBCaMw
         wWOu9b6ZWKjHpD/Zz2lUYtun/UGiUzspI3xRBMJQMMaMODZlfhSOQRiOtz3gz96+JIND
         Tk1HJ8Az1ia0I8YZannMXWaTtEKtt5pVTnDb6bTBSmJT75cHJSJ2DpNjrLp8LMsXleZo
         ir4wYDxsFA9KecszYV7TcmNJF+VzRtulTaUdztKratUCiPENxQ725vixEdexW8TNRlXY
         jbhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VzNOSdkbYBkOukDT+IUr0ZiF2Bt9ORApw5cW7gcrLnU=;
        b=DzMdNrovgGm6g0uP/jNTnmw2KU4edlE+sn0vOakBUTkMow+R5UMuVPrqnGOjeAdvbB
         /6zgjz/0C6mG1oxNfZPOlcem+1qeBhLsKNVbsGUxyLLXtEb1DOJ2tugmiOgy4sAUTkaf
         qAobEmRkvFXUPpbBBiE7RiiM/Z/iqsH7fHoTHL/KtTvRYAqUXbPGkFQtFg+QU9G2W2Ye
         Z63BlCuD01wjIQBTU2uKiu3F/4SHn1sJ4oqfTTL8XgJB71hEiLyYsmI3HpNcYblGDxY2
         +rV5FDgAoiDsoDd3wRwRtSGvApqgKBC+SMmDya4ryqGFHrEd9yGJNt1TBOI7WiyjW9ZV
         I/tw==
X-Gm-Message-State: AOAM532XEnHijL6vxmKwDK4opEveqffp0jqHyN+M/QtHeszPRDsn/MKn
	1PNN7mbzraGRfLBilv8Shxw=
X-Google-Smtp-Source: ABdhPJzq5x5lOoODpyHLLybfdeQ+Xx75LRucwLSFFw5nyr0dYyavjRwD96Zi7op6j587X3q2Zur8qg==
X-Received: by 2002:a9d:4c92:: with SMTP id m18mr7247274otf.248.1605715678876;
        Wed, 18 Nov 2020 08:07:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls5161337otm.2.gmail; Wed, 18 Nov
 2020 08:07:58 -0800 (PST)
X-Received: by 2002:a9d:4b81:: with SMTP id k1mr7123897otf.371.1605715678530;
        Wed, 18 Nov 2020 08:07:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605715678; cv=none;
        d=google.com; s=arc-20160816;
        b=rj8ytzMU0ic5A12mpJ/ZWdk6QYiRfx7ta5rYF+kod8Joop9iBZO7Zf7hLv9GdoC6Bs
         x/STXkYIleUoO/SmLYIFkPsRYCTZHqBLf/4YK+HYD4G2j2Cv0mBmLIGMdZujAmC91QUZ
         NdioC4DHgIJ2bZOTaqSpxLuRCEHnlCEAlcj1xVhhZ6cUuNHsMrSHiSRN3BsdRBcFFVYp
         D9CCggsgxG6Ccg1TQIVueDDjWtF4N9U1TX709hyipS3KEEd1L5LYSKnTXPK2kDtY7Ilc
         QI1SFePsMXvv0NJwiKP1GNUX8Z7DFqBJkny8o05UoJ0lVSmksTd30l1rY0yoJTCzAj9U
         VBbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ikA7PYEQ/L2cKfevJds4p4NjydPxn3K6IT3FVnbYGLo=;
        b=o19uRsfPZgS9iytb7E8Mim5BHMqHiygtgQ7l6yh8HEq0SNlo0ZRBPVpdtAA6e8JKY+
         A/nO0Tx7QJBmFGJxsiz0h3YHEbNroot2O0Y5ghj/CrUCCXsjvLNSBVhL8iDZm9jdIqHG
         qOU/nefBHID8aSFhvZEmhNFChKkf8fezyD2YhBgDgbUIgVY4RNueNGCsEggdWsOzPBTn
         RVWynFjxfhwNCA19gmlEGvU6HQJIysq0jRS1dDwj/SCKH11kmSb9AAdE9xWiJyYs7wFu
         7H3f0WxBR5PdtXHduEZgNNT8akMdYZ+/Kzt7/E0DFxZfnnwzGjNCH+li1Lhgvn9KRjJq
         ta1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ga/ygbCV";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id w26si1719113oih.1.2020.11.18.08.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 08:07:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id a15so1266280qvk.5
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 08:07:58 -0800 (PST)
X-Received: by 2002:a0c:9e53:: with SMTP id z19mr5497551qve.23.1605715677182;
 Wed, 18 Nov 2020 08:07:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <b167fd21b86e7d728ba3a8e20be4f7e8373bc22c.1605305705.git.andreyknvl@google.com>
In-Reply-To: <b167fd21b86e7d728ba3a8e20be4f7e8373bc22c.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 17:07:45 +0100
Message-ID: <CAG_fn=Xc_OOtqE5Q-fFejBBCfLGtc_kOmZAuE1wdTsjCOmpQ4Q@mail.gmail.com>
Subject: Re: [PATCH mm v10 31/42] kasan, mm: untag page address in free_reserved_area
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ga/ygbCV";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as
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

On Fri, Nov 13, 2020 at 11:17 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> free_reserved_area() memsets the pages belonging to a given memory area.
> As that memory hasn't been allocated via page_alloc, the KASAN tags that
> those pages have are 0x00. As the result the memset might result in a tag
> mismatch.
>
> Untag the address to avoid spurious faults.
>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: If12b4944383575b8bbd7d971decbd7f04be6748b
> ---
>  mm/page_alloc.c | 5 +++++
>  1 file changed, 5 insertions(+)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 855627e52f81..4a69fef13ac7 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -7653,6 +7653,11 @@ unsigned long free_reserved_area(void *start, void=
 *end, int poison, const char
>                  * alias for the memset().
>                  */
>                 direct_map_addr =3D page_address(page);
> +               /*
> +                * Perform a kasan-unchecked memset() since this memory
> +                * has not been initialized.
> +                */
> +               direct_map_addr =3D kasan_reset_tag(direct_map_addr);
>                 if ((unsigned int)poison <=3D 0xFF)
>                         memset(direct_map_addr, poison, PAGE_SIZE);
>
> --
> 2.29.2.299.gdc1121823c-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXc_OOtqE5Q-fFejBBCfLGtc_kOmZAuE1wdTsjCOmpQ4Q%40mail.gmai=
l.com.

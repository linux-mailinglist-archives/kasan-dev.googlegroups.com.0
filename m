Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUXF5P6AKGQEYTZSUYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A9C29F21B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 17:50:27 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id m26sf1465717ooe.8
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 09:50:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603990226; cv=pass;
        d=google.com; s=arc-20160816;
        b=r0sLUXGLKc3PtP1fpI/l6v8rjdajTqrdPOpZJd56OHyF+kRKuY9Qoma30OfTriG4i7
         4M2phkmpdkGR3iP+0AK9ipgOyLUOLsSOt+VaykMuWP9EV69ImCDT/PLyituCmQHHB381
         iqQaUamvm2wqOofEJX93f+Cgs0UnYQz4C4SwLjCwTqd3yCEcQABdsDc7v7tBcSzPrQok
         fMf4T4+V7gB3/Tvg7zv/E9FxwidbHGy6y1wZSq22yHtXYCoBmT5ObtvUZt4H3EyZ0tsF
         LbvvT1FKqRHjrgJFVIFipVrq2vLyPRK566dmyWKa7PsaGk7WiZZb+ROjGhbwsc7QdcGD
         moVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q2pAhBAuEs/e5BPDRNzd9kThiujjTakLMF3sCzmpg+s=;
        b=ocntpzpHdHCEiX7LOIKiYQx3ACUTFlO0vs+a9GQz+wpqXJomFNACu5c6BLPiZDCPRc
         LhQrWqjxz6C91ad16q2Zs5jHvEkLAmEmSSkGsIIW0sTCu3PsR86sRYPXsPVpXYRDkIC2
         zQZnSf0wcznxt/QYR5BiKIcUE6uZUgZ2aEXL2TsADC5sK8n/Sl3m19yEkZ6gJLCo1/Ml
         RumUHIYCvcaaUOxZuGDtCpEbtncTx+vMxeM+ZX0NaIplF2mY3qgIk1gtZmuVjq2/JbCD
         VO5jSX0zGa5KlGZ2h56yDoF+hemkmKSuEIzLWEiw0ZXt18kqHAjMu56LIVi5nrBlr+Md
         cQvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qc8xa9Jh;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2pAhBAuEs/e5BPDRNzd9kThiujjTakLMF3sCzmpg+s=;
        b=RVF6MmonjxEsH1VmrcITWiFsNNjmaVuKZ984A4zoKnsIGCekSp8rH03WUka0F21se3
         EZKGObvguF56kzhxI+xiZsH2f9yL1PXOq/lHRKVtx2rGH9wzTDqOI9FPdeejo+EYirJk
         uF1z2jCghdSjRmXIpWu22iaC195B77wNjs6ye+qXQrzAP3mXiai/q+qwzjCD8PoWWzaT
         tx8WOcq6a4za5Aa+uE52a3NiQSIorCxm3WyaJ+fTw4TawZOkKTYg3XKX9Y38KhPbwN4m
         pW4z36L88+zMgsjeo/77Eig6SMUQb95vg/XY0g+TSklkoPVSN+JgZJ9t4K5iuVd2O49/
         EzOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2pAhBAuEs/e5BPDRNzd9kThiujjTakLMF3sCzmpg+s=;
        b=r9vLIHJuZsKdvjhNBeBtHsg9Wa6ym5HJTBMlg0j9v1Je8BM6/lJjt4SsPObdtsX4Ay
         XjsCigpwk36Iy/2d4BANOe9PS2kBV2IeWK1vuwLk4/m7qDKNVevn6U6AkhvPzQj2DEDy
         KCJoq2nheupSbpjFCa/5QOIxaxfBpu5z8PnK8/opazTNYwK3ZHBgIaeJn+36rWZlX6wf
         0ANzzyzSGokLLG5om6470ukeniRhZo1n1IWJHjNgGWRERqYh8h83Z/lZckaoYrz8oaFm
         jTQJwjzp5aqOD90DQGPJ8JUQWfz3olwO5qZP4u/YD0efwcZpM1cqROCNy8DUJHiAEkND
         YItQ==
X-Gm-Message-State: AOAM53101ExAOiXcpUaiOsi2a5O4ytY4W7TwJ5mlN+MI7kOAbpD5e6gZ
	s+guRg+yIh6g8AqyqMSxuYI=
X-Google-Smtp-Source: ABdhPJwdVZoA5ouGEbyROkIvvbte29z+xcau+1/b5+PsdR4KAbe/oMsZtJAn3bbRySrgnUZHlLAWNg==
X-Received: by 2002:aca:4257:: with SMTP id p84mr79420oia.176.1603990226655;
        Thu, 29 Oct 2020 09:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls882479otk.3.gmail; Thu, 29 Oct
 2020 09:50:25 -0700 (PDT)
X-Received: by 2002:a9d:6a0a:: with SMTP id g10mr4088481otn.44.1603990225724;
        Thu, 29 Oct 2020 09:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603990225; cv=none;
        d=google.com; s=arc-20160816;
        b=eOkN5lmjvSUKpwBSgoZ4U5ppr3iXgTNnjD4YUO4RbfDOQe7WjeWCjtBXFu7JTzCqn6
         pZg/6j4CNc/ZKugvGEjvYqQsGWP4G+wCz9LXCW3CO+jsH3wfcfdwxgv92B8FTinl1PaC
         qLUQh26xPjnWxq4uLvu9RGlfe4LV4i567YVuAC/7gmgk3XrpK/DAKdODx2oPNKM1gu7d
         3jZBDcq49fh7Naoe8NwnErVBKZ8tpmHJKfjixFfe+aEfr8SM8pwrpQYRVtJrqNcdtjyO
         o0iD0G0EfSc+1YiPsKGkspGITYgGWlp/DCJQhMygotFDje5rbVMHJ608NcL+/hHpH1V5
         7Ezg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cv4+7kQkXt9yP5NUmOCSvou0pMNFr/3DXVTAN8b/WEM=;
        b=YNRqcnIGUKeBaFtssPyaLL3Pt4GOaylFSkqG0bBpbdfY1w5uoqq5jhwgiw9ZefMZ9Q
         3xesNqrm/3Hi9IQ59KliqJXqWKWLzzMX6isCbLsx7idvmOoVZXVZsccDIPbWV+W81J0+
         ro5ekSbtB+SdLL2Q/2AfxrYjbndX2Ik5XVGfPVOOuz/O8KOT38oOpsSvmkbg6wQg8dhA
         4AOB2T5sLOmwbsbXtA4P9L+mvs4AE+1VSZki9em4Z2v3PCu0qNR7UAXMNHyUw7aZm/OV
         +usduX3dNB+sqx1XYv1qwWms6ODc0x0StHynQDGZ1U/9LhjgVqu/UeYRmwfiKosPowx/
         kcUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qc8xa9Jh;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id d22si323601ooj.1.2020.10.29.09.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 09:50:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r186so2847713pgr.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 09:50:25 -0700 (PDT)
X-Received: by 2002:a62:7695:0:b029:152:3ddd:24a3 with SMTP id
 r143-20020a6276950000b02901523ddd24a3mr4914942pfc.2.1603990224897; Thu, 29
 Oct 2020 09:50:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com> <94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl@google.com>
 <CACT4Y+YhWM0MhS8wVsAmFmpBf4A8yDTLuV-JXtFYr79FJ9GGrQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YhWM0MhS8wVsAmFmpBf4A8yDTLuV-JXtFYr79FJ9GGrQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 17:50:13 +0100
Message-ID: <CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com>
Subject: Re: [PATCH v5 02/40] arm64: mte: Add in-kernel MTE helpers
To: Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qc8xa9Jh;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 28, 2020 at 12:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>

[...]

> > +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> > +{
> > +       void *ptr = addr;
> > +
> > +       if ((!system_supports_mte()) || (size == 0))
> > +               return addr;
> > +
> > +       /* Make sure that size is MTE granule aligned. */
> > +       WARN_ON(size & (MTE_GRANULE_SIZE - 1));
> > +
> > +       /* Make sure that the address is MTE granule aligned. */
> > +       WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
> > +
> > +       tag = 0xF0 | tag;
> > +       ptr = (void *)__tag_set(ptr, tag);
> > +
> > +       mte_assign_mem_tag_range(ptr, size);
>
> This function will be called on production hot paths. I think it makes
> sense to shave off some overheads here.
>
> The additional debug checks may be useful, so maybe we need an
> additional debug mode (debug of MTE/KASAN itself)?
>
> Do we ever call this when !system_supports_mte()? I think we wanted to
> have static_if's higher up the stack. Having additional checks
> scattered across lower-level functions is overhead for every
> malloc/free.
>
> Looking at how this is called from KASAN code.
> KASAN code already ensures addr/size are properly aligned. I think we
> should either remove the duplicate alignment checks, or do them only
> in the additional debugging mode.
> Does KASAN also ensure proper tag value (0xF0 mask)?
>
> KASAN wrapper is inlined in this patch:
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3699
> but here we still have 2 non-inlined calls. The
> mte_assign_mem_tag_range is kinda inherent since it's in .S. But then
> I think this wrapper should be inlinable.
>
> Also, can we move mte_assign_mem_tag_range into inline asm in the
> header? This would avoid register spills around the call in
> malloc/free.
>
> The asm code seems to do the rounding of the size up at no additional
> cost (checks remaining size > 0, right?). I think it makes sense to
> document that as the contract and remove the additional round_up(size,
> KASAN_GRANULE_SIZE) in KASAN code.

These are all valid concerns. It would be great to have inline asm
mte_assign_mem_tag_range() implementation. We can also call it
directly from KASAN code without all these additional checks.

Perhaps it makes sense to include this change into the other series
that adds the production mode. And then squash if we decide to put
both changes into a single one.

Vincenzo, could you write a patch that adds inline asm
mte_assign_mem_tag_range() implementation?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwCO%2BJ7D1_T89DG%2BjJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q%40mail.gmail.com.

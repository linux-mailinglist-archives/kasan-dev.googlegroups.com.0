Return-Path: <kasan-dev+bncBDA65OGK5ABRBGU2WGUQMGQEMXPIDDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EE8E7C9B89
	for <lists+kasan-dev@lfdr.de>; Sun, 15 Oct 2023 22:35:40 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-66acad63d74sf48730526d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Oct 2023 13:35:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697402139; cv=pass;
        d=google.com; s=arc-20160816;
        b=RUq8n8cHjF4y6rblayT/FVDP38vbfE6XWvej3mSknIlSXtvjzagnqdcp8Vy4xIeaAs
         zzvtywiSlhNYPuuycbO9xYY9lXycTeNHHVFnqOo2fUcFrgJmxtzL8HbrBv6zBLqcNpk1
         NjXVYO6gIlnIS6s6QmEA6o5f9Tx6FhHhfGqGWRyzie8dyHAqOH9PoPcOgoc63q8czuPH
         XVTifE4k2JGNsAwUL4TCN6tqJip3GpjaHAXbhahZ/9wIxYcYo6ccaTgx1tlRowdEoCHy
         +xUmgVNE5lwMeFvse645Bymw1RPI538Zg6DQdo82Ih+dRZvUu3fWk7Qg1WhR98MzT68w
         gvKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FmkT+/lMnxDG8i/dTAyEQjLHljOPFMY3J8E94Bh4/4U=;
        fh=dzDjLnSBpiWteN3VeVwQViw99DTJGyKI7iTcYcsotVc=;
        b=JD/F27KRLSdUcVP3gV+ZrLNRfdErapktOGsBtGEjynD37mLo5In/NYlTxKCh7FCgwZ
         U/BsWDtvQud3KYafe58yIaP8RBM8yBsLbFnI+WPzi1kqInEozPiU6zOQHeypa94XpzEG
         mrmePT3WTgm3S+bREgwk41wKYbTTDkJB+xtEN8aOmNZn0w01YkiXDgj6VnBjns2Jd/Ic
         kzbcXmex0sbTPgYrGh3n+XmS9QuSEy0aUATP5ChlCLnvYt0HAUKKPomFGdWi8J3ebIB+
         L+3p6UvcNawlCAfc7OurEtK6N0lUB6zGA4wmPyBibvEsKhpMDJ3BwY0g4vLeGYd6V8Xi
         6h9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BRREXwUK;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697402139; x=1698006939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FmkT+/lMnxDG8i/dTAyEQjLHljOPFMY3J8E94Bh4/4U=;
        b=xqNmGgrAdIcGQElqbpakH6IKSbHmH6EWEa3CbosmKv8tI0XobbRJVbnEGXgeRNXnY+
         IS3ZDi46xrBMZphsvIuWnpPJ/hVdXb9xBUUpkpy3kDVjOO+w6cIzXl07Hr7zzO3iBxq5
         EvdU3a0DnaX9XG4aecmIBbZJGbCXNODcrXyaajTTvqfn4pul21S0RtjeqhVo9nTrO2Mz
         ihjqsZ5aqGzFPr6sDL1HQb8jy4Vh2xub7DiVSTX9qhRPwqJvQv+rZqONGviWEx6m5UNZ
         lsD3Y96LCLFKRK+fUi1c/MU+Fmda2W/KZl5LwMKIy7wTYaMI07qqzZ0npYFg9XAVl3QR
         yYjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697402139; x=1698006939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FmkT+/lMnxDG8i/dTAyEQjLHljOPFMY3J8E94Bh4/4U=;
        b=WhJ3PTSN5ebi7BLaYBAP8d55z1jIM+QACEmh/UqiYKUCWZhmKClLs78P6IPjw9MnSg
         ZnG+SKcNzHybBYJVaaRR6R8Fhm9Oov1B8QBJpLcztDbyWk1N/vHH4bM8dkhEyyRpnp5l
         u/6IwS20LpvcDWJbeoJZCEaPS8erlEuAtRzR0kQbAP2lKZnjrf81DfI+nfgGpWixPI9K
         +x8/T6HMkGkci6XUcslOntj3Z2xHil82yi++kzwUhtz7DU9Sbznt5VJ/+DUwXGIzLEgd
         LUhscXNdcwFWlRrlnyVu93GrLZIyBo3YDaBcNLZ1gyhXpNXQC4RhvyYS8L/VW5D6zji0
         kdXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697402139; x=1698006939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FmkT+/lMnxDG8i/dTAyEQjLHljOPFMY3J8E94Bh4/4U=;
        b=kEu53Ymg2ZcAOJ8IkOFAj7B1wL46gGTCGxKSJ3P0xvATG09FKM9Gsxuhn7pPg6GuMD
         XchxnfpOs1WNgnehL2n/AkWyImoIFQFktycdZAmdiJof7DLWmXkqiy3Oq00Zm1NXpCz3
         SY9Kqc/pCuROQia5vXrai6nAAA+Ygkp3UMCeXRhNYziigu2SpCqIAhZhkfu20Qp0ykcF
         eSe2ddA700qvP4ObCDWWMmdG9lV7sUacXAiWoVS0t4BhxS6HdzRD3xdbq/oPYnKiqVtd
         Payx63tKhFQ+MMn4toB5gswY9a5tJedKZ7fKZfiao94Quo1QWD4LWO/4j9HXDDQrZlhr
         MmZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw215p4pX//eDiig7OHGXJvE0RH/lMbjt7csKMZsayAR7OKtFb/
	DTwMd1UcusRxkoEbG5AaEYg=
X-Google-Smtp-Source: AGHT+IGNBYqsEvsws9Q+UtKTUs9u5BM4wqoclGyDOsxsFto/RT/+k30UVU3wD9WYvlkMTQkxu7vsKg==
X-Received: by 2002:a05:6214:21a1:b0:66d:3f56:ec3f with SMTP id t1-20020a05621421a100b0066d3f56ec3fmr5013524qvc.13.1697402138716;
        Sun, 15 Oct 2023 13:35:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1774:b0:65d:592:a279 with SMTP id
 et20-20020a056214177400b0065d0592a279ls1886732qvb.0.-pod-prod-04-us; Sun, 15
 Oct 2023 13:35:37 -0700 (PDT)
X-Received: by 2002:a05:620a:1708:b0:775:7c53:c023 with SMTP id az8-20020a05620a170800b007757c53c023mr39348998qkb.18.1697402137794;
        Sun, 15 Oct 2023 13:35:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697402137; cv=none;
        d=google.com; s=arc-20160816;
        b=MmYCzRLlU6x4iQTOJa/9vAs1KhICNZC+VVZVM9PQg9iCyarFoh6sU9/EfaNHSD3Yzw
         1SLhmbUKTGw18r8EtTevhPRtF4s2wag5vt1pUIoJcClCEJIZncYLJkTuYSPMnC+zR7Dx
         GA+tZJ5I61dS+XwzKbGdzazZuT0MlJ4mMRSUS2kRmq/Myod48riHmyfeLnrF6Mt9XvGo
         vE6HQv9q4f2tptJJ1kSlVjDRd2hEAlutM6z2OVpgJRO1Xl+Bp5nzdyF5yuhZ+6ONnUsL
         rbrtAxAeFDE46QRvP/V9bcLF5Zn+LUQCWkNXaN0dIPJe8mrwxYq7j3wgUrgzW9aGA7iL
         N4xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KUi6hE5CuO5LVhmusvTHYPNNPWcnkaNQ7utVUkV5A98=;
        fh=dzDjLnSBpiWteN3VeVwQViw99DTJGyKI7iTcYcsotVc=;
        b=fPlmdOTDiYsqZTfTeYGHj4i85Q2xjrOW5KTKNt/rmok8zwHm9j7KFbsV21ZcdnbEeR
         fXnTKP8OgXvss9NUSO1srZ20BenMAOil49xa8dGItAOwA5S1l8W1xnR97AaEowN+ctCd
         CTAePwIE0jXqPqzMMNAhR6MZiZjsmBSQgbeber6DhgaLYFyjtvq6/lalLxSJ5tbhZRjE
         bSu10dFHr4J4X9EYeV0tEQ3gsrJvY8qRp3DlJqAz51/COG7Ao2mMjabH5dhGfwjQXV8O
         tQzlDkrkHAjBqmuy9bllFMjiwNrk2hDCYh+ZfQ25uVjHbkh3bv2gW8FyCm8RfyN4jx/m
         vXmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BRREXwUK;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id dv22-20020a05620a1b9600b0077576de1665si384190qkb.3.2023.10.15.13.35.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 15 Oct 2023 13:35:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id 71dfb90a1353d-49e15724283so1228428e0c.1
        for <kasan-dev@googlegroups.com>; Sun, 15 Oct 2023 13:35:37 -0700 (PDT)
X-Received: by 2002:a67:e006:0:b0:457:c57c:ef13 with SMTP id
 c6-20020a67e006000000b00457c57cef13mr4889967vsl.31.1697402137240; Sun, 15 Oct
 2023 13:35:37 -0700 (PDT)
MIME-Version: 1.0
References: <20231015202650.85777-1-pedro.falcato@gmail.com>
In-Reply-To: <20231015202650.85777-1-pedro.falcato@gmail.com>
From: Pedro Falcato <pedro.falcato@gmail.com>
Date: Sun, 15 Oct 2023 21:35:26 +0100
Message-ID: <CAKbZUD01au=HoDe=yXSLtxJgYdivZccqqBfpmnmQ04R1Y1orvg@mail.gmail.com>
Subject: Re: [PATCH] mm: kmsan: Panic on failure to allocate early boot metadata
To: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pedro.falcato@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BRREXwUK;       spf=pass
 (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::a29
 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Oct 15, 2023 at 9:26=E2=80=AFPM Pedro Falcato <pedro.falcato@gmail.=
com> wrote:
>
> Given large enough allocations and a machine with low enough memory (i.e
> a default QEMU VM), it's entirely possible that
> kmsan_init_alloc_meta_for_range's shadow+origin allocation fails.

Ugh, forgot to run checkpatch.pl until it was too late :/

> Instead of eating a NULL deref kernel oops, check explicitly for memblock=
_alloc()

If there's no need for a v2, please wrap the above line and...

> failure and panic with a nice error message.
>
> Signed-off-by: Pedro Falcato <pedro.falcato@gmail.com>
> ---
>  mm/kmsan/shadow.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> index 87318f9170f..3dae3d9c0b3 100644
> --- a/mm/kmsan/shadow.c
> +++ b/mm/kmsan/shadow.c
> @@ -285,12 +285,18 @@ void __init kmsan_init_alloc_meta_for_range(void *s=
tart, void *end)
>         size =3D PAGE_ALIGN((u64)end - (u64)start);
>         shadow =3D memblock_alloc(size, PAGE_SIZE);
>         origin =3D memblock_alloc(size, PAGE_SIZE);
> +
> +       if (!shadow || !origin)
> +               panic("%s: Failed to allocate metadata memory for early b=
oot range "
> +                     "of size %llu",

unwrap this string like this:
    "%s: Failed to allocate metadata memory for early boot range of size %l=
lu",

Silly mistake...

--=20
Pedro

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKbZUD01au%3DHoDe%3DyXSLtxJgYdivZccqqBfpmnmQ04R1Y1orvg%40mail.gm=
ail.com.

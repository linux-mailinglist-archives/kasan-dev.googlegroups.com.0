Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU7BUOGQMGQEJI5QK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1544667B0
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 17:14:13 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id ce19-20020a17090aff1300b001a6f72e2dbdsf95678pjb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 08:14:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638461652; cv=pass;
        d=google.com; s=arc-20160816;
        b=hoh1j0cc+ZYNwO4iN4Xh17KM4+yCGPNvFN6bVULKNtkZDKM42VxJN4VumLruIe5rCR
         ZgOnkXn5cmzWzYjdYyFAR4Z+5yHeayPFts/5nb38E4/hNp5acLNO7241ywdL5fYfde6K
         bM1816nSdDFJ5hA4CZvmrzSRIaCg3ZflwaBGoHH9AkF/ofi8/+6gpBcHkOt9a1SriDTP
         FAjCHDrPA9yyDGo/90HhxAJ9njtzg5scPM4yjFgbyr6wgPl6Js5+SD1eyXVq46/fBRLj
         Ra4F9yYLAszQJxobDE7dOcyAvli1tQBndPK7IR2kla324+HUO3wR65SE+bu7133jpJRE
         Oqrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eSmAGKCmyTznSB+omJ9f0C6Du1u/CyT4kY8Klim7VVE=;
        b=eumw3olvua/vd9f6N9bODot2gWA7jOEp1iMdxNMT/NTUSQTbxl7VYYyo/CslzMAN4k
         KKqX0NLJ+vBnSF1E8jcUDsFmPF+DqPGnK/y/antwkrbmNjHXd6LKRSYobmSF8R+mEcO8
         GwfGGT1RWNKeNaYeh0aC1a8AZQzLkodalav5VepwGQ9dR6EGtnNTjNR/oaoa6jP7uFcl
         oSBiex/Bdl+hK8Rc7OG4Ov0lOACc3sFyoemP87mFWROhX2g/EIRsPF/KlDUZe1zIw8Au
         wBPVkw6nexA9yecuvGSDT+9Sc+AfOHu9S9SssX0wTsfuYYgOi143mJfJnTSpAP+H7bCu
         N5pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Crx2IVA+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eSmAGKCmyTznSB+omJ9f0C6Du1u/CyT4kY8Klim7VVE=;
        b=o87dtHdsTYH7YHqKU9GfbjCi+mWT2T7RDZpn6of6s1yy9rVsRFOUdZEaQKiEK2va3x
         M5RiuCoqBUgtEdW/PlATOZy1oOlUoorgTIDR2XGlHKA7aEbSV1On6716XXxCkLbi7Jm2
         QK+xoNHo7tM5LXN2AuDNDtsUSotTctFIksxB1evnb6/ZZHqBfUMT9yIRN9nOGJ8qeIdO
         o5trdrmAiEtWEcC7RSBth1dSjuWN9WEM4wuiiUWNp6Un8jP57BN8kpeffGaQQJVV/b8b
         b+4R7aO8gQY9pQHjxSHbZuunrFOMyM+y/v2spL6XgreBPdertyJ5s7cyuZdcvMMlmbC5
         o6bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eSmAGKCmyTznSB+omJ9f0C6Du1u/CyT4kY8Klim7VVE=;
        b=eytcRH22P66iKYuGnDXkXqzNrgDYD6Pgrn/FBwCiKH7M6dIHYmGsNqi5/CbqujwcEQ
         S1SwzscieZMelSNF+CYPNHWCFao8XohLkVnbXx7CNOUPUs7ptSD09HgI9Ausc+OkQvFi
         OF/seF9l+GYuxk84xlfUrkZBI3nbzjdD7WhvLdr2Qaf7VUElRxV1YlNPZWylKMKvVsbu
         MVi/4Huue3ZK5nhv9GjdNz34UfOVId/dSxvAa4yQdm7WN0BsRC+GXZPXHD0TnzkGRGJ5
         OUp6bB5+uOs0GwDjzax6OF3YqoPvJtcN3VyOu6nHfKksT6kpsd9QQQWc1+VVA28/dVsv
         M1MA==
X-Gm-Message-State: AOAM5321xtJVz5k0G+Y15utWRf7xQ4k1QR4vjvlvCxtKwFI6ZFJ4s000
	pN1hL5qqZKGFB4MuyZATPek=
X-Google-Smtp-Source: ABdhPJz+s9bSJhl0Z/Lamg1OZ6voJEJgkTwOFF8kEDcnjT0UzJ9+9Dc6v73ZvHk6toWskex2dZlxpA==
X-Received: by 2002:a63:10a:: with SMTP id 10mr131677pgb.172.1638461651977;
        Thu, 02 Dec 2021 08:14:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:80f:: with SMTP id m15ls2540606pfk.0.gmail; Thu, 02
 Dec 2021 08:14:11 -0800 (PST)
X-Received: by 2002:a63:914c:: with SMTP id l73mr118030pge.384.1638461651377;
        Thu, 02 Dec 2021 08:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638461651; cv=none;
        d=google.com; s=arc-20160816;
        b=fBHPiV3TxhFNf5JEKBms1T+f3PUZbcCl9EgVXuqvhwMXRhSXXb0Ah7Uetssis/fMe0
         TclvNjw3jXFc3K6YEnYSxCsbZnjbm23wmzExrQE8BZ5iVhHqYQy5Te1/I39SMys22LEJ
         02MY9sW+81/7mm/sN7zJJhdhR9R7k2+9v2MKR+h1tzaZtNRxTfAZWTMCw0BMOZRXDfEN
         MAQypY+84m/PY/PRP63sRMKuJPgnUEjBDIfDACcqH/8yp5bavay30kXrol7NYZkgzvlh
         mthpKA9D5OIje6/3GwHF5W6vx/t4mzob4YuTvfH1FSMHmX2ysuyyUyvtObG5ewxVW2jT
         XTOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ufkuMHJENZAKBVIrvseO49pb4ZFToj5htqXCloJEnks=;
        b=PR4QzN8cycsyOwOPF/o1K8K3bFkKx3lEbcauOjXMUn1oUGvJF3irTUnmYDL+4wc32+
         ZVe0AR63Cw9jwCy9BfvoPDrlBFW34HfVCacOvwdhi8dqOAZclQOEarFwvBJAUZ6iMmED
         5fJoyVPtIcHIZkh2hU3K9Ak5bPXhpAjcw87px8LAgNC6mlU/Ig67Qb2Jvt6Z7/SabAg5
         ckn1wQ/4gQOEPK5cwjGA30HX/naJWCYonCy3FKY3uGZEvuDx7A3jtz8Lwuz4gC8Zp0Kq
         ggJ3Oh6YGDv+7WGQ8m35/rHETYXgkb3UHY7QYdxNIj9IjEJ2Bgd2WReRJyltYadNfpaT
         ZNjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Crx2IVA+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id z21si33371pfc.4.2021.12.02.08.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 08:14:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id g9so23496354qvd.2
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 08:14:11 -0800 (PST)
X-Received: by 2002:a0c:8031:: with SMTP id 46mr14089905qva.126.1638461650530;
 Thu, 02 Dec 2021 08:14:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl@google.com>
In-Reply-To: <984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 17:13:34 +0100
Message-ID: <CAG_fn=U71Yn-qCGMBR=_uOt0QCEu9skGzhgRBJjpkQCjZ=dKiA@mail.gmail.com>
Subject: Re: [PATCH 08/31] kasan, page_alloc: refactor init checks in post_alloc_hook
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Crx2IVA+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
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

On Tue, Nov 30, 2021 at 10:41 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> This patch separates code for zeroing memory from the code clearing tags
> in post_alloc_hook().
>
> This patch is not useful by itself but makes the simplifications in
> the following patches easier to follow.
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/page_alloc.c | 18 ++++++++++--------
>  1 file changed, 10 insertions(+), 8 deletions(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 2ada09a58e4b..0561cdafce36 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2406,19 +2406,21 @@ inline void post_alloc_hook(struct page *page, un=
signed int order,
>                 kasan_alloc_pages(page, order, gfp_flags);
>         } else {
>                 bool init =3D !want_init_on_free() && want_init_on_alloc(=
gfp_flags);
> +               bool init_tags =3D init && (gfp_flags & __GFP_ZEROTAGS);
>
>                 kasan_unpoison_pages(page, order, init);
>
> -               if (init) {
> -                       if (gfp_flags & __GFP_ZEROTAGS) {
> -                               int i;
> +               if (init_tags) {
> +                       int i;
>
> -                               for (i =3D 0; i < 1 << order; i++)
> -                                       tag_clear_highpage(page + i);
> -                       } else {
> -                               kernel_init_free_pages(page, 1 << order);
> -                       }
> +                       for (i =3D 0; i < 1 << order; i++)
> +                               tag_clear_highpage(page + i);
> +
> +                       init =3D false;

I find this a bit twisted and prone to breakages.
Maybe just check for (init && !init_tags) below?
>                 }
> +
> +               if (init)
> +                       kernel_init_free_pages(page, 1 << order);
>         }
>
>         set_page_owner(page, order, gfp_flags);
> --
> 2.25.1
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
kasan-dev/CAG_fn%3DU71Yn-qCGMBR%3D_uOt0QCEu9skGzhgRBJjpkQCjZ%3DdKiA%40mail.=
gmail.com.

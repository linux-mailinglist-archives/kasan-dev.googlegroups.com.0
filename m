Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCWSUOGQMGQEPBLCNFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id B711F4666DF
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 16:41:00 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id a12-20020a056602148c00b005e7052734adsf32816120iow.20
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 07:41:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638459658; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGyMkn1ZJRv3LpOZsJal2a3yQUJUSMikdORL4aCh2rGTphgPL1YErieAwwjdryzH/q
         8pEGwF4Sbrm4WogsP1moTNq2Mx8kx4yTX8XVUbFTMI5UkU8pOanZ7dE/yf3SMnnAVwX4
         J2wlILljrqrj1U7GZcEVvcPxHtw3lkqcNP/lnTULok6SUw1GTxA6YOZFIsclDHE6BVxi
         /2X7ycKrxKC22j3j4UjuAL4ZcqRZA7eq3EVz+SXqQzJSIN0Tdhp+IFuMEodky4U7KD74
         hIbtBVy37uLvOfYMqZRn41Fx91WxLLEUYZ5pddB/WSgpTk50vHIsklUJf9zPas2LVGNT
         CM1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Zt8hsd/rjM6toNxga63ChNrs1o7OyWewUJLVYn9YwTc=;
        b=lYi97XnhmCnUmv+b3/D+5DkApdfqnWhbKsesbdmEGFBDIj8m5liszMnwxBD2vx1X8k
         GR2xJRM8MNJ2zwFNUmfB4MawiWcsMDsWAHxt2Xka9jhlMmwySsHKlh2oYtOqsbesErLS
         IT1WVPTZCmuNFLKgSGX7zNQIxowuW0f1gpvWO19l6SOkCsX5GBDEPzSHkjzY8NE9SFnc
         yf7S5CVrSbLUHZXQw6iNE7YsLR7+EMmbshKWcQUQZEp4SXNz7haUHv/hVWqzNAiStTag
         gPjtdT2EAanQvbih+A1arEpex7u3QFP8pxpKYy3Tlx8h62NTzirQhbkcKoZ2Dhpgi0dz
         /eCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pa2nCnfc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Zt8hsd/rjM6toNxga63ChNrs1o7OyWewUJLVYn9YwTc=;
        b=rUKHKJ/fKl7AiKf437cSsJtTMAtklSCRqtS/a8exz2+Axu44gppeQhCSmdeNaqwkjR
         EXZ47gT7rSlZVeSe8Mt3rQ5BTkF6ZfEGmVlUhyGlxgzi5jcjCYodg41KIq1kt+3yZHVu
         yWIEwU+8CRKQaJ1tizOWaCT24vlcR5CDEVyJMhD2csECOyIsPr5XXrYhIxF9sg0Sqcw1
         53z/70MRxAH9knrqOIe5wCx60d4oMhPvRov/4ydQQdMkS9aC7erxivNSoJKKAJkwH+0r
         ENZEXYgWtOWr7A17LZHMeEhE28hmP7wRnGyNbT5Wxv8Qz3nqt6EzoU7ztSoX0O16gMbK
         P+BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zt8hsd/rjM6toNxga63ChNrs1o7OyWewUJLVYn9YwTc=;
        b=dAsFM4YL/k6784uD/dcjWyDtH2emPUY9OwlTaU8cc/vxXV7kzXXzmhWnwBubsUtnVQ
         e0+6tAxR8GYAR9MhyMusvLMsa+Qv5WTyaXxoy1iIVdNaf+8ZbSM8R/qsbjiHk9zUXPI2
         TW66SUiDD115elupFjSC3CTkXBR3oSjyHDBRaz1Mt5WzWK/dNJPPxgl5qFUeG2iNT3zK
         3Z/LSfWhdOSyOYJUrM5erdW0TXzQS3uXU7940iUYM46vkNoJ/f9RqY8MaaNsmMgpV4DZ
         IY1n9MbyOuHnNur6HJxK7S0EWvQHjOVm7WydXBn4ToSpkL4YjP2v/CXTUA435aA7+GT+
         Pa5A==
X-Gm-Message-State: AOAM5314ySsXRBUhefq9/v9J4f2J4gg5T8M5W7Hmr+fucOLQu1NluDh6
	+9nzPsBseAXL0m0iusKqNxA=
X-Google-Smtp-Source: ABdhPJwwwBM8ztVwgBlDlSQHvrkGf8Mxv+RxNfcJ8cDlGuje507xylOhzIrL5sMWtzeBl4S5LJ0rGw==
X-Received: by 2002:a05:6602:140d:: with SMTP id t13mr16890775iov.120.1638459658403;
        Thu, 02 Dec 2021 07:40:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2165:: with SMTP id s5ls1115349ilv.7.gmail; Thu, 02
 Dec 2021 07:40:58 -0800 (PST)
X-Received: by 2002:a05:6e02:20ca:: with SMTP id 10mr16118026ilq.246.1638459658068;
        Thu, 02 Dec 2021 07:40:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638459658; cv=none;
        d=google.com; s=arc-20160816;
        b=qTTvh1813wUqEQev2vGSTKWonTqbG4XXwYok+xnWwREcSkGk59ldql4NYiScz0M7kZ
         oc9IcdaS0/cNMyJKo8/JyyhomnA/89bGwy2OqBVeTyEHvd8UuYbWou57EZ03Df7hg0wB
         MF8NtLs7mHPbzPyXBbsyd4lXuYASWEL+qPuT9IVCs8wn3R2ZdDnJVqK1PsavbTQ10Ypv
         S+lWXIIKjtcSSgYsLvvtT/VojnmR0zt9/8IOAlcAFFptZ3Oa/PAT3YuuI9F5Tqo54bpR
         kYuxtqyYgpbNB/CC2y80sC51Z3plwpMPbCqex5vI3rcgB7sThEDMs0cWImOI83OXVbJV
         TLVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ze4OYA4kCMJmMvK5z2d/7YkRmJBRmguQKYCL2ja2UL4=;
        b=tpS4qIM52nGFlMs2FOphdC2XpolhILju31SatN8Q/Nz7aWphCYcJZJwT2BXRCDpqTV
         zKBJMZDTj1HHjCimF/SnMv3Pamx3KVyVrqZ/JIUlFamHlYcmKJdnnzYD3aQADsZ7l3vq
         PwDqOYIwOCBxWJwFs+bIrhe6U9sgkCskPGB1BqWtxcZj1gdtOHdQd6QYdo2TZjdRUbnp
         7Th5p90NjCfxyb+eBQE/s4pDOWzxUxlcmpUdSNNJlooprmTluWesPXAG/vhlCL0yjK6t
         jfald/RNPA+j/4nZS/tjIuYZe55++FWAPZV4r8uHbYfABZixdtFBhth1PtwUJoYU2AxW
         FNQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pa2nCnfc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id s4si3507iov.0.2021.12.02.07.40.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 07:40:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id m192so302023qke.2
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 07:40:58 -0800 (PST)
X-Received: by 2002:a05:620a:d84:: with SMTP id q4mr13046469qkl.610.1638459657279;
 Thu, 02 Dec 2021 07:40:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <938a827f9927ee2112d98e2053ad7764aae9d8f8.1638308023.git.andreyknvl@google.com>
In-Reply-To: <938a827f9927ee2112d98e2053ad7764aae9d8f8.1638308023.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 16:40:21 +0100
Message-ID: <CAG_fn=WRKRUskUrN1wb20gv2nLF-DOPBF5aDAg+q+sFKczDw1Q@mail.gmail.com>
Subject: Re: [PATCH 07/31] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
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
 header.i=@google.com header.s=20210112 header.b=pa2nCnfc;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as
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
> __GFP_ZEROTAGS should only be effective if memory is being zeroed.
> Currently, hardware tag-based KASAN violates this requirement.
>
> Fix by including an initialization check along with checking for
> __GFP_ZEROTAGS.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/hw_tags.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 0b8225add2e4..c643740b8599 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned =
int order, gfp_t flags)
>          * page_alloc.c.
>          */
>         bool init =3D !want_init_on_free() && want_init_on_alloc(flags);
> +       bool init_tags =3D init && (flags & __GFP_ZEROTAGS);
>
>         if (flags & __GFP_SKIP_KASAN_POISON)
>                 SetPageSkipKASanPoison(page);
>
> -       if (flags & __GFP_ZEROTAGS) {
> +       if (init_tags) {
>                 int i;
>
>                 for (i =3D 0; i !=3D 1 << order; ++i)
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
kasan-dev/CAG_fn%3DWRKRUskUrN1wb20gv2nLF-DOPBF5aDAg%2Bq%2BsFKczDw1Q%40mail.=
gmail.com.

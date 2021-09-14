Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYFDQKFAMGQESO7XMTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0732B40AD36
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 14:13:22 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id f64-20020a2538430000b0290593bfc4b046sf17088003yba.9
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 05:13:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631621601; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGe2U1NGXuxQagybpsfm0zCAhRmCWBs38Ioa6K+0k1rdBIIsAf6ZlcRFlL7Sx/gYKK
         5twUOzp7WWIuA2dRvPda6+Wd4CjnDpn3f0Yl2obp9WyyWNsfu67ciUII0GRok+fvs4qu
         uhcy16aN/aI2ODbCfyfYghPDjKGD6nPq6NeNQKIG8WZQAea0ByjN1p4+jQmaMuaNmdYY
         2N5a4dnP3TrVlTGv4KpmEacbv/MuEt9RDlh010jM/WDvQxOXaOIEdTJppjiPYycbQlHY
         edwuve4TVodN5h/N7KDS53g4TgyDhvYJ7aLNnH018B6h15G+SH5X7Zm+b9Vxe0OdbGcc
         RC4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pnX+PvhnTVVtsFBlfgmQnmmSEfZ0AWmvJIJiZZt/iWg=;
        b=KD+t0N21WDtoAEzsnJbIcE0dOsfY8DsDDIcZy60HNxvk0nofzfGXkizEt4UjL2QC8m
         yMGLbFmM36RP3wyhYUnabx3ZlkPNWLCH7N3Gz0zkKGnwL3uBEWqVKTTU6+3hIybGv3Ts
         S2B5fKRpgcZ2mZ0YoyeoJ1BPFLK3uEu6aEVMYIeSYkfnCDlyqmHx4usOoo44FhGyvxAq
         nNKEZDkJrD6Y9M1k+CYUF1IIsqjGXEt6wi+Wfv0wturd6SD/5tXrTi5oiAazWfdKUfqi
         DXn8fUKGhchA3Xg0L4s/gkLwzbEHFWzp8bIo7rbTn6yFv82TEGfpvsqEav6jHLs6kPPV
         +OWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZT9oblhQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pnX+PvhnTVVtsFBlfgmQnmmSEfZ0AWmvJIJiZZt/iWg=;
        b=tsPc+yLz+LzCAp8iT4H+JlEwwwX/75NVNHukwlCRWjcGfBJMudAV8gUX3SO09rBPuS
         AiGLrmgmxsGE1jyH7orIGYYfxhR6qjX3OfM55aGb5DMY296QM6RH3NkJVkzljsKe2zZb
         1G8M8N1xSW5vJixu8lfL0zMHxVMbPEOIJWnj4wEQzUae76nLKUDbW8/neBEE1iPTCU9r
         JGDvOB+JYaHHrulRKsza4kBbUTjwWPXPIbnr7DIEEoLglLqLH8AZmLOcKYraPzEoyjuv
         1r1ZLNd+Yjz/GoY5E/OCKWo4n9LTibroygXtTorc5nHlxJB7dSSH/prpgqsi8dXU8/t6
         5yVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pnX+PvhnTVVtsFBlfgmQnmmSEfZ0AWmvJIJiZZt/iWg=;
        b=5lGNv1pH7eITaV5NwtIQNESTY0luE/tksF2RJbE13hAYz0oqNc42ZZoND5qFRjqSzM
         11KPUF6PjMvCkgD/fuQQ79KDJ6JI39ilBvT6vKK/iimDsZwp6HQN6DkKKIvc2Isq7d2q
         Y++tXdodQuK7W7h8Z2l4OuwvCdwt7WuHdCmhpkzSVOvaBysTwgN37dUFd7iHExwjJNgO
         s1rWW4ZQ719BDYY/0CchDX8LWvxWR1Vldu1m/C9Y/vTBC1QTl6VN+IfnDxOMDAOkqkdq
         OeJp8EHtyUK7fI/HKxjJmP2WKsrsdxLJJYjdp0lvGNE+8KyOJm4X5KcD4AKj/+5s6tAE
         BrOQ==
X-Gm-Message-State: AOAM530nQEC4MF184bh7rbEwJKc8h7js+cZiiXrhE0LusAKrdj6kkUYC
	ILvxGnKR6HRlEiBmO+i2Pg8=
X-Google-Smtp-Source: ABdhPJyCcUrUKMrUYmb+o8YB5thyBv2GUGmGo5XeKjqjkQmdLZz0l1h1bIV3IJ6tAnZtSxOBp7N7xQ==
X-Received: by 2002:a25:2f42:: with SMTP id v63mr22194071ybv.388.1631621600870;
        Tue, 14 Sep 2021 05:13:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e04:: with SMTP id j4ls4438406ybc.7.gmail; Tue, 14 Sep
 2021 05:13:20 -0700 (PDT)
X-Received: by 2002:a25:1d86:: with SMTP id d128mr22375943ybd.406.1631621600392;
        Tue, 14 Sep 2021 05:13:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631621600; cv=none;
        d=google.com; s=arc-20160816;
        b=obPViPmHJw/C4DTQ183EGEtL9peEIQ2OVQ0kV2Z4and1mNFY/KS4Cu4rCc7Gv9aPiJ
         0nSxlyuiQZBYoCxabPFen2TRQdHU3Q1e5BtZzZ2SByIELkGTaLTWuPyMsaxKjcgrhyJx
         57DTrbPUelElvZ+EaCR+ehngsRELraS+eOt+w4abF2dl6WxJIkINLRdfM8X3WzITrhNw
         4Pe3UTGF6IFjwKzrm/+452kv3pgsNMxVff3Oc/PBpzh8YWTR3qwGz124r30SCMJLeiv6
         58yr4O5byDbqMQjeV5dEOSHRY6G0XPU9Rs4mkjq2UMqjGoVXP1dAcGMAhQEG1OGMrNy5
         6MkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pJ0yW4/1Jn6ZEeGlxOvvBqEA1VuZRtIwgqtBes2tjIY=;
        b=Q94vpvo+VchrlfXh1nbunTwzgqposmbjRUd0/zotI02yVvnI6Wl9/3vNCCDwiY+EYF
         mspo+dkd3blF289ctEYbwmqvVrKPZAavpYzFGrwfjtlvvb5uyhntP1d5DqjEUIJ8F82g
         xbpcWUNegZOSIsAiH13ALHdI9FetT/GniHvth2ub1OCEytoryTEKcBaFMnvUygkag+fW
         tJzTFV25vIEoPGhAK4clCoPDvSqaDhfIi1UTfOjaEuLCWkdO0uqeOEu81/e/GIK4Ysoh
         pTKJkAXidIKQJf2cLdlOZMz9iInuy7a+JbhXSnH+FB8RAliePbcoSrd9hwfGyUU+CCeL
         cvLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZT9oblhQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id w6si722628ybt.0.2021.09.14.05.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Sep 2021 05:13:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id t190so14439208qke.7
        for <kasan-dev@googlegroups.com>; Tue, 14 Sep 2021 05:13:20 -0700 (PDT)
X-Received: by 2002:a05:620a:191d:: with SMTP id bj29mr4500655qkb.362.1631621599977;
 Tue, 14 Sep 2021 05:13:19 -0700 (PDT)
MIME-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com> <20210907141307.1437816-3-elver@google.com>
In-Reply-To: <20210907141307.1437816-3-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Sep 2021 14:12:43 +0200
Message-ID: <CAG_fn=XGa=UK6cduTNAd2AREA6jxUaGFJqTWT1cNTXCK4-6k0Q@mail.gmail.com>
Subject: Re: [PATCH 2/6] lib/stackdepot: remove unused function argument
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZT9oblhQ;       spf=pass
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

On Tue, Sep 7, 2021 at 4:14 PM Marco Elver <elver@google.com> wrote:
>
> alloc_flags in depot_alloc_stack() is no longer used; remove it.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  lib/stackdepot.c | 9 ++++-----
>  1 file changed, 4 insertions(+), 5 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 0a2e417f83cb..c80a9f734253 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -102,8 +102,8 @@ static bool init_stack_slab(void **prealloc)
>  }
>
>  /* Allocation of a new stack in raw storage */
> -static struct stack_record *depot_alloc_stack(unsigned long *entries, in=
t size,
> -               u32 hash, void **prealloc, gfp_t alloc_flags)
> +static struct stack_record *
> +depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **pre=
alloc)
>  {
>         struct stack_record *stack;
>         size_t required_size =3D struct_size(stack, entries, size);
> @@ -309,9 +309,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *=
entries,
>
>         found =3D find_stack(*bucket, entries, nr_entries, hash);
>         if (!found) {
> -               struct stack_record *new =3D
> -                       depot_alloc_stack(entries, nr_entries,
> -                                         hash, &prealloc, alloc_flags);
> +               struct stack_record *new =3D depot_alloc_stack(entries, n=
r_entries, hash, &prealloc);
> +
>                 if (new) {
>                         new->next =3D *bucket;
>                         /*
> --
> 2.33.0.153.gba50c8fa24-goog
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
kasan-dev/CAG_fn%3DXGa%3DUK6cduTNAd2AREA6jxUaGFJqTWT1cNTXCK4-6k0Q%40mail.gm=
ail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJE552GQMGQEI2NXNAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 36A57477C31
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 20:08:22 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id n13-20020a9d6f0d000000b00579e30aaa02sf47486otq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 11:08:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639681700; cv=pass;
        d=google.com; s=arc-20160816;
        b=P/Yi1m+RWPYijczjHJLJ4M/yPKdiIHBspjLYLzhR67ypn4KSz6M1KODQvQwQklcDH7
         bCqh0yY+4HmKO2UH7H15/qtr9tiOfbzkrEoKvlwP9ReVe0cWAxqH1Bm7wHzb1+8QLIon
         bq9t6q7E7oHmnP7dzrtNz0e78nJtCO1RAJ4VtXg707eHIApRSLjt40NP3aHLLddZdoU6
         wkZSPnQejmcaM8E/PiVcOhZaaKvqiUXuGGoI9kLplgvvxlc86/l0r13wSf/QCOnjfjn3
         cv7UFipt1Wq2p+HrNz30rHP6tOHAU3jusMCA7WtpO59ucegzQkjuf02dJn+7izMk3PKK
         Gl+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CZapfM8D6twE7G8P1T8LDKwU4qQeYGrBkA3P5a4LDFk=;
        b=Ev15nGHpLrrF/TsV3KO8NOOlVeEEeaulQZvsIOktiHkhvERLbd2NoEmhuSS6LI+KcO
         Je0VAmtiHhBvTL81Qk3N5GzG8nUGJz3iEB1wrjjpoiyBuqqrYkQ0jn4Jlp9nkU7ZUqS/
         C9gBo5KrXrdIggudqFpuLw+p8j6LULnbi4/fBesiyT/RGYVdgwtcgS0LWSGw4ZlAbuNv
         0MedQEJuStVjZ+zBjJd4XA7uoND2Z7i7vFVJ6G5OPNpYwNbhg4m1yfNBOmDuKBl1+9i7
         gQk7p2g5LDo5QF9yuhcBYu8rvBXffmPu5mYA3vNNH56u6GJkdwGsMFOGrTM2u5+9D0oy
         88mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L8dy+Tim;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CZapfM8D6twE7G8P1T8LDKwU4qQeYGrBkA3P5a4LDFk=;
        b=I1+nFNu7NhYQLZmpRD62d3JgoUcY2dSZUdniu7mN27f7uRBjYkuz1l8fKGhjXXrLea
         Il2mamaiRqL/tnfu9tESpyvBYlZES5prswD6BZjzDVDv1kVSrd/5RwxpsJ0wyjP0w+ar
         X9GUsTMbkR5TIE+H9ShZT061pJoDRCzISp0DpC483cFQ8kJpAzmFn6N6k7ayo7aPYJbT
         SOSnMnIaCOHsCwYRIMrAXjnyxHPA8YdbesyLp7rZQDtGL/uJhb/kLVIPaSn8q7g7Rm39
         Pt6icplyBO+erhgTN5lsPvtVScxA2o9EFoiwDhQt6dJVBznMBq9XtjPGvSHltGw271K+
         vmLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CZapfM8D6twE7G8P1T8LDKwU4qQeYGrBkA3P5a4LDFk=;
        b=mfZNHh1pvRWb6+OhJhWX8RylDuPerVGphqWp2S+qdQ64uuupMTrOsNYdoQOgZ483Y4
         toPF5tUM9MrSgIeUniFMZJvyOZTCycFm+fLCMPGK1khJzGDhnQyM5hLzW/KXq+itbUS7
         XdMqXRTwYiDptoTKaQw/313VAdyZhLV2eFsESeu1cu2pt8ajWc6V6IAhvSKTF5h6WclH
         S+o5ZFhC3FuP1ebxhPt82+yFlxOvQA4vU1A/uXjBBmddnTxm65PJXUn0HaJsR0eFO7yX
         JwzXKsFoelzAf8HE5r++8IKTtadAfNE1ZH7MoLB/PdA5LhlBFVcB2EldZKATWYjL5P+F
         TcUg==
X-Gm-Message-State: AOAM533U4SDOfomJfNofOTRs4T/0zIoLs/f5W7lYgQ8yNWLk+Nmks6cL
	3FTZXC+ry0RvvAOkBfbqAi0=
X-Google-Smtp-Source: ABdhPJxe4BP3Xeu3SxflsFniCtzyZgnirWNEbhH6ZrqXDfS07mkx7Rjuy2PQXudIzjdUxail42AvUw==
X-Received: by 2002:a05:6808:1311:: with SMTP id y17mr5270622oiv.32.1639681700704;
        Thu, 16 Dec 2021 11:08:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4492:: with SMTP id r18ls1540064otv.9.gmail; Thu,
 16 Dec 2021 11:08:20 -0800 (PST)
X-Received: by 2002:a9d:4c90:: with SMTP id m16mr13676761otf.129.1639681700332;
        Thu, 16 Dec 2021 11:08:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639681700; cv=none;
        d=google.com; s=arc-20160816;
        b=oDcR1UtbY5gc/pygbTUE8J8dJScLx+2wuNCH8ore+ZJ/9MITDQxlRalCk3l17cpBMZ
         Yb8HueWQpFwUv5zHDS+jIFnc/eovmNv+n91LyqW8g3wGANgxfyUpgSRpnpTxSiykOe4V
         FmP9A36K8xmFPWpRyhI+WY1swDx0VxwQpDih/jZ6AUjG8kvkEYMfOSB0FYiU61YZHy5e
         kMjHwMWJM0lqutDCuvPXjvr7dyf7lh5QqMwsrROei3yINv6g4vHKwgunNc+04ryQYxKJ
         oH51Bvli/3Exu9EKuPrwT/4nN9NtXR1dAYJObJq7nXgqRFeCgWQUe9hZY0Wcrje54Bzw
         cF8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LTFLzci/snq8/xtVRONsMSy0mihEg+vOqMAB8csECsE=;
        b=tQKEBomnpe/UCgcT07unr8hZ9E7UV3yjekzBeeEwZIJnZiA9FwRZbMTnhzoFoGITUV
         muat+6hQZ7bprh7qGbP9xvIdHJ/iq+4ijTQgOxho5tQwNrs3mv10YUAfJgmmmqc8roaQ
         2yW7MCZtBfptvt/+2/3v19yvQjWnccTabUwnLlmKEvVvrjJ5Ij/T5UdHWDsF/qaAko4F
         duDPZ4WjC2bBtesPx9tZIEQA9gjMCJS0IbiN8khVx6Rton179x6Lziny4TZ5hAXEumy6
         3+YdnupK9KQVmlH4SxOgKWkLfhYW95+V8CvhVq9A/Cg7PlmNcXiAI1DHLbN2E6GsnPYz
         UVQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L8dy+Tim;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id d17si409046oiw.0.2021.12.16.11.08.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 11:08:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id l8so221870qtk.6
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 11:08:20 -0800 (PST)
X-Received: by 2002:ac8:7fc5:: with SMTP id b5mr18754527qtk.492.1639681699782;
 Thu, 16 Dec 2021 11:08:19 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyknvl@google.com>
In-Reply-To: <1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 20:07:43 +0100
Message-ID: <CAG_fn=UWe_wo+E1P-1RyTPRAaSqXcCbhEwLaU=SJ+7ueGSysEg@mail.gmail.com>
Subject: Re: [PATCH mm v3 26/38] kasan, vmalloc: don't unpoison VM_ALLOC pages
 before mapping
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=L8dy+Tim;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

On Mon, Dec 13, 2021 at 10:54 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Make KASAN unpoison vmalloc mappings after that have been mapped in
> when it's possible: for vmalloc() (indentified via VM_ALLOC) and
> vm_map_ram().

The subject says "don't unpoison VM_ALLOC pages", whereas the
description says "unpoison VM_ALLOC pages", or am I missing something?

> The reasons for this are:
>
> - For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
>   mapping them fails.
> - For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
>   kasan_unpoison_vmalloc().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v2->v3:
> - Update patch description.
> ---
>  mm/vmalloc.c | 26 ++++++++++++++++++++++----
>  1 file changed, 22 insertions(+), 4 deletions(-)
>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 58bd2f7f86d7..9a6862e274df 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2208,14 +2208,15 @@ void *vm_map_ram(struct page **pages, unsigned in=
t count, int node)
>                 mem =3D (void *)addr;
>         }
>
> -       mem =3D kasan_unpoison_vmalloc(mem, size);
> -
>         if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
>                                 pages, PAGE_SHIFT) < 0) {
>                 vm_unmap_ram(mem, count);
>                 return NULL;
>         }
>
> +       /* Mark the pages as accessible after they were mapped in. */
> +       mem =3D kasan_unpoison_vmalloc(mem, size);
> +
>         return mem;
>  }
>  EXPORT_SYMBOL(vm_map_ram);
> @@ -2443,7 +2444,14 @@ static struct vm_struct *__get_vm_area_node(unsign=
ed long size,
>
>         setup_vmalloc_vm(area, va, flags, caller);
>
> -       area->addr =3D kasan_unpoison_vmalloc(area->addr, requested_size)=
;
> +       /*
> +        * For VM_ALLOC mappings, __vmalloc_node_range() mark the pages a=
s
> +        * accessible after they are mapped in.
> +        * Otherwise, as the pages can be mapped outside of vmalloc code,
> +        * mark them now as a best-effort approach.
> +        */
> +       if (!(flags & VM_ALLOC))
> +               area->addr =3D kasan_unpoison_vmalloc(area->addr, request=
ed_size);
>
>         return area;
>  }
> @@ -3104,6 +3112,12 @@ void *__vmalloc_node_range(unsigned long size, uns=
igned long align,
>         if (!addr)
>                 goto fail;
>
> +       /*
> +        * Mark the pages for VM_ALLOC mappings as accessible after they =
were
> +        * mapped in.
> +        */
> +       addr =3D kasan_unpoison_vmalloc(addr, real_size);
> +
>         /*
>          * In this function, newly allocated vm_struct has VM_UNINITIALIZ=
ED
>          * flag. It means that vm_struct is not fully initialized.
> @@ -3799,7 +3813,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigne=
d long *offsets,
>         }
>         spin_unlock(&vmap_area_lock);
>
> -       /* mark allocated areas as accessible */
> +       /*
> +        * Mark allocated areas as accessible.
> +        * As the pages are mapped outside of vmalloc code,
> +        * mark them now as a best-effort approach.
> +        */
>         for (area =3D 0; area < nr_vms; area++)
>                 vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->add=
r,
>                                                          vms[area]->size)=
;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyk=
nvl%40google.com.



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
kasan-dev/CAG_fn%3DUWe_wo%2BE1P-1RyTPRAaSqXcCbhEwLaU%3DSJ%2B7ueGSysEg%40mai=
l.gmail.com.

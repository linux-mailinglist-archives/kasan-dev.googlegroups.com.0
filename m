Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHEHU6FAMGQE6BCK6MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 658764132A9
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 13:35:57 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id c7-20020ab02607000000b002baed713ac3sf14776084uao.7
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 04:35:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632224156; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBGHrrH7Rt8IoadGZtzqvgDxKkGDip4gqdlOg6GIKQGUy/kKzX83bHT/JZtuyffPtM
         tyvoM9rOAzCZ21gSDcf/hW0v9CtJvHMsS45MEQnI1nrximdmtumSgDYDIaIe97y/MhOY
         ryqPVQRk/zfiR0e47ghFaZJraBv080vSQVDRN1XXqfyBsvioUSmipRS3d2JTQrt6NZB4
         zGAHUTulMnlOnAxDu54+4YrrV62uQdRkezRuuROC4EdHINgI72tG6Ju2tdPIGiuO4OFL
         pf6EiFDslcyIoEKHdjEMr4WwZb444CFCkA4g+BgNAXZCU24dI6urXl8BLnqJULQdnY/F
         cbUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iOiydLdHzRpQo64gtgomliVBZuNk/PtA5QOKshNKCUY=;
        b=pcXCxe5fO8nxhMKNMbEvSgGglWgpGDSyWplVf7ROYW6OCv6J6INW3FOf6Fq7Qb9pS/
         tA8UQfvO40E5e0Wa9uZIS/9cZ54Ybd1Pq7nEo31pL2pLgmjc2tpJyT+ou9B81b5apdGb
         3B4UdZxDESSIiUZ9GqZ+Ao0bHLF6DkYajyyy6J26aSgT2ETTpEPffs4Emyd0eRpGZc6K
         MiubKg9nhAr16dCjaS4KYfpWtYuu8ChoM91TSlcvFpgJG4k5It9fxXxdPGJCEd4/yRKh
         OXBALY49iGYzwxsV8s6j9r6XJ9XZ2GRLy2K/rgVb6fijkdZX4tQbfBgNFruDE2hesVnf
         6p7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RcIeDxNz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOiydLdHzRpQo64gtgomliVBZuNk/PtA5QOKshNKCUY=;
        b=bkZnsf5RKGrDs+87z3hH9N1TSfrwCXAKESfxQ8RmVThnITOmhiat07gWqH1vv6fuFW
         VtWph8N3GZXME766GZfEsdKquMw0RVuvZWxym9aefQVxoBPyrMf6zrXv2rkOrpfAQGIk
         qIbH4fMEzM4JB2sBrJl8anjWygWshOW/oEkuva65wf61My6Hf4+B05MFsaqCld9oo5Zl
         6wONr8zVqKjxkJ5sqa8GgsvG31gt9CnaoiVgRxx7oQoNEwqBa0Aw0CrrThL8CdMng90b
         5czY/tpUOkO8ofG4ZgOtIoyRB1ySbrVu78iFxj69tklVtYHeo5+fPqRl4EUpC8pbZKcc
         UzWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOiydLdHzRpQo64gtgomliVBZuNk/PtA5QOKshNKCUY=;
        b=vxgVZDnhI6ZW9qkXHPDNaycbS6/qKw3rsL6BEsUUhGpnhRt7hsFnw8i5QOit8lHhZR
         uytut+71mNMhd+6Lpt8yKgQAkYFp2477Na9I29/+c3PO/hurLteZg622vCrD6gIdI4rY
         qrhj0I/rLfxa3b4Ze3t1kIs3O+jLL1f3gxc1K6lz1YMNzk4t0fn8Ap3nAgnZeDe78Wnc
         0I24XQOgYvOwhe8aR2Q2Mi2Pe2+MwsU7jdTKLYOWQZL5sgxuZGtymuGRBQqxiLXOuOIt
         JxlGBbk7/vkMkLvl0rz1NaQ1dczCg2KUoU0H++9yJw0Rrg52Sqe9YfW3CGRqVH1gn5RQ
         FESA==
X-Gm-Message-State: AOAM530ukD9w/4rW1bpgbyglfOYo64MO9rtsDVHnfKMVYdVA0wIB2mpq
	L+rw0DNYArwXNzD2oa3+Xfo=
X-Google-Smtp-Source: ABdhPJwfRzaCWNc7wr8TdjYyR4+X8DUB+QK8iQoXZPlkpjIhSHR3cB3y0tNmBuoMhIzrtAlvma8ISg==
X-Received: by 2002:a05:6102:ac6:: with SMTP id m6mr19831116vsh.55.1632224156224;
        Tue, 21 Sep 2021 04:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2469:: with SMTP id 96ls2236337uaq.4.gmail; Tue, 21 Sep
 2021 04:35:55 -0700 (PDT)
X-Received: by 2002:ab0:5ad2:: with SMTP id x18mr6403046uae.125.1632224155516;
        Tue, 21 Sep 2021 04:35:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632224155; cv=none;
        d=google.com; s=arc-20160816;
        b=rQ5RWBTzu0C2mTp7gOuRa3OBM/7U9oFkWt8FoLpN9UnQTR0PNVTvs66I72PR/68YXF
         Im+P30GqTnm1/eyWv5xQ8P9x5KqpUFMopmpEOx86N34XB0dXrDNTnyRvGftpgR0xVqUj
         jk713RxcLTHrwAiZLqGaCaN57XKwG/OKSwa6zLiadNYjSuRcEIqEGeyGIoFHuMrfjYK7
         PJn68UAZvDNKy3jvb9jvSY5rSmHu/o5EnX37b9aDHCApSicOjW2e73PN3kEbMX7teehv
         11zMKjy1zOVY866Kk/5QtJTIhFHnOEPJMwbWjl8pq72TRzQZCnj+kDnA16eKos+VduBJ
         BBOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y/NtL1eqdessLJJ7QAgmdSlgwRQ9C8fMojdqN92nFPU=;
        b=jvnfKJC4mtvJl3tv7Ny/1qPFDxi56jCezpAO9EEpxMGFYBgzTsYIyxxD4ow4tWEvRB
         ltqEFMyyu6ZRkSryoXk0LtsP6DQJysV4ADWSn8Uhx0ke1/7AkaU1Ja6UFReTa8xbIQV5
         eMTYsbzqw11LwkaDjiZLaji10H9pn/INgfZtmr0LgHUmjgAuuAGL3WwZB2ABuXPs5MuC
         CEIENPL3rcgUzldGxIAm0Ih6GzPfKOczREzJCv4f0+xjaKLguDDxOVtMMXSrX0M5wuKz
         mKDbddQaHfUhdITtjJ88/tQNbaKuTN2gVYPtNpk1C88n18n1UuVGvVzJqWjAsVF1YzWg
         u2Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RcIeDxNz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id u64si261490vku.4.2021.09.21.04.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 04:35:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id u22so20988715oie.5
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 04:35:55 -0700 (PDT)
X-Received: by 2002:aca:4344:: with SMTP id q65mr3351129oia.70.1632224154781;
 Tue, 21 Sep 2021 04:35:54 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com> <20210921101014.1938382-4-elver@google.com>
 <CACT4Y+Z6Rss3+oiN5bcKHYeQgG=nZ9VDqwrhOS4VUZ=_a5NoBw@mail.gmail.com>
In-Reply-To: <CACT4Y+Z6Rss3+oiN5bcKHYeQgG=nZ9VDqwrhOS4VUZ=_a5NoBw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 13:35:42 +0200
Message-ID: <CANpmjNPuW47hwmLm=RXr6sXSzvAmz0_vo3m9UGgUbT_CQ=oSgg@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RcIeDxNz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 21 Sept 2021 at 13:05, Dmitry Vyukov <dvyukov@google.com> wrote:
[...]
> > +/*
> > + * Adds (or subtracts) count @val for allocation stack trace hash
> > + * @alloc_stack_hash from Counting Bloom filter.
> > + */
> > +static void alloc_covered_add(u32 alloc_stack_hash, int val)
> > +{
> > +       int i;
> > +
> > +       if (!alloc_stack_hash)
> > +               return;
>
> Nice!
> I like the hash seed, non-evicting cache and that threshold become a
> command line parameter.
>
> This check is the only place I don't understand. What's special about
> alloc_stack_hash == 0? I see that even double-free's won't call this
> with 0.

Indeed, it's no longer required (I think it was in a previous version
I played with). At this point, it should only be true if jhash()
returns 0 for something, and in that case might not even want the
check.

I can also remove the unnecessary "meta->alloc_stack_hash = 0;" in
kfence_guarded_free().

Unless I hear otherwise, I'll remove the unneeded code (and send a v3
of this series in a few days).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPuW47hwmLm%3DRXr6sXSzvAmz0_vo3m9UGgUbT_CQ%3DoSgg%40mail.gmail.com.

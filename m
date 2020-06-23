Return-Path: <kasan-dev+bncBCMIZB7QWENRBA6KY33QKGQEQTWMBVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id CD298204A1C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 08:45:24 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id b11sf14330141ioh.22
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 23:45:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592894724; cv=pass;
        d=google.com; s=arc-20160816;
        b=PuGQLYLVRXLlmwmLI1xzxD67f3Htc+ihBsoDE9EqnpnpP22fN5AZbwVvLQD9+IMJWm
         X3AYo7e9zBFB+TFTc8GUVjJQFoo+7yTdiGlH0vJhYFKHk9zQ+uhVszXkIxp2a98jThnM
         MghKzsOobH9Tqtb6YZmEA8iuAmeWssa3+oWyc1rjkd/zcSs0WCbTxXSDo2O8DrNYu/b6
         TJNhmBNvpnRffOLjuNCQPR5EmFweqSs5KjkWeWEvxgW9u7eU5F2EXliLmSBZDMJ9Qu6B
         yxXE3SiHhMg09XGFcbidob8W6Kc4RLO2DWzXdrZ7puhyk+/d4XLsfamtNvlGxCqS0vbU
         pkmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nqZlxIUzVX4IVhCP5gYL1L+EpYls2moZ0KOdsqzxHg0=;
        b=AoaIlJCeU8v6zFFA9asZBQ7B0L+P8v3CmEsqhd7NVqYFcxjuEuETNRKUDw5LSGF9bI
         egqWK5mcGxTZQPp8xvBT5pNlxgzJIIe8XjmFfie7b3MolcGFdpDSBGnd49OL30YVjL+v
         DzDuGbWFVRKjm7dCbDEhkcFkH4PEJZtW0fVW8V5UZxRwc7ZTgG+bKZZ4bLtQganhtfhj
         0Cl70iP3rmr1u/8IBPdQyZkyWKZfFpnk0u22ZAssw7gapABE1Hi4ekwIxdjFmgxl/uVv
         xn3TofQaPIAMCVo9/cADK1fcuyGN8EKRQp75r3XM825W7d31SmWP4rGXwlgaa9ckuKUU
         y31Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6U0Skvb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nqZlxIUzVX4IVhCP5gYL1L+EpYls2moZ0KOdsqzxHg0=;
        b=SLlhmBhvjTOooRuCHYYaXXy7Q3PL+VtyXlBnlKN29vcGP2F0/lYFe116686+zr/heI
         Zcg9/mPW+7HFAU++XuXblOfIUkPeqns9eW6cXp3hRn9DPUJT6YFBKKuH7MegEpCceZuf
         0R7qVeS3lkH+IrhIOTuxZYM6NQMjkiXWkzwMa889ij0l1WkaN5+FZlig2LZqZwQh9ek4
         6r4pBp+NqtQ+GQRie1Ok2yxoF9cHsW5dhtrRk1iy0LW28zCGE36D7EogcONmANnzErNH
         eASynz7IiQl9PIKieeJ/e4mE0a+RQfB6px9vmrDIbbzEHIIgcQuxFBt8vMf94P3ClmFd
         wbjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nqZlxIUzVX4IVhCP5gYL1L+EpYls2moZ0KOdsqzxHg0=;
        b=gDc6W9N3PfoURxDxqhUfyAXKmYO0CT2Hj/l2iND6PcwQlseUYRtDoj+Z+XYVSn00wi
         7U9fkjWVh4PgHsuiDUgA+nwHh5uZgregTxYXjKQP/UnT5V0UpJYGtugHTZSnY3DrCreO
         fjPLtMz74aXaYUvBSWEHRbe+CViFwAMCdV2U0asOhEAEo4vT7cuoxD7YKWkoBmaezLSe
         4IpvHdppLT+AilsGv8w0IGTm517on3XAgQ39PyIS8eTW0XzHpf5fhJMTWd5xS8jLVBvC
         VTwkQNP9QdCbD7jQQZC1DI9GbmSnIGmpkOilfSxf4bNm2/dYOYt0fFMsNrhqurLETALc
         G74w==
X-Gm-Message-State: AOAM533LzySkfa33SAofxu0rfO3lnpEX73sxCb3JPvujDMOQmGEgCTpv
	MUgmX4jV++KSbBsk4h2Pfbw=
X-Google-Smtp-Source: ABdhPJwsjHqNyqKPqLK98mYR5JqswAEciY1yIfb+K7GX1EaI16dA36LNcOLx2RumESXzodNx/KBMrg==
X-Received: by 2002:a02:7605:: with SMTP id z5mr1504919jab.90.1592894723785;
        Mon, 22 Jun 2020 23:45:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c80c:: with SMTP id p12ls2542595jao.7.gmail; Mon, 22 Jun
 2020 23:45:23 -0700 (PDT)
X-Received: by 2002:a02:7108:: with SMTP id n8mr21771949jac.38.1592894723221;
        Mon, 22 Jun 2020 23:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592894723; cv=none;
        d=google.com; s=arc-20160816;
        b=nFRyX/z9xsNXcqJZg1bjvys39I7Ozd4GiXI/Vbg2ymGFj2ZpUR17ESrsxpWd9uAOxi
         THJf4xF+kfY52lUCbEaSzJBUoq8ZQ5vuaW/7wE+6VIO5HITfCCySGjOpoMiS0gg+jHyk
         GyEcny+HfM3ICtjPpKtLgQmA+WpOsphLgbcCcFJiy/pr4R/lshMnv9T4n1TDHcThZP7U
         vSTmQ8DqPL6pNcU5LXYHGi6pEYHLPkYVIXYAdZ/m9mhlrMGIurQdMkcoUT4nFDtE8sqt
         39Z5tYtlrnIYwSetuMsyd/n9iCOTzAf2sKUwOpHAxD2xhX2y3ZZ8EV53F5x6Dg0K7Iw3
         ybtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kqrm6H9MAMConNZ8UsM9qxabxTYbRgGIA2rshZa0MPA=;
        b=fiwd0wQfFWJirGqdAknGcYbXyGif23Kaag4cOAZ/p933Jbl7lQyk+wE+DRPg5PbLxa
         CPJC2BaQU+cqmnVvfDn+GDMt6zVXb1cRsmX6N1sowSd/fRdhfeWrQpTGYwlPLDf+Dg8D
         IjrUGgPqUMVOvtpnjAwLMs2o3vIx1jWhxOQqKVs6jiurVEy9ZsG52ZIpZbBb+GxEya5V
         IkWOI9MrZcbo/9yg9WnA7zES9XoSgCzy/pzyXPVCnmRKZMsa99Lm6Qy01y52mVM+5Vby
         enk9v2bzSi6LniQJH/YjdiYWMMacIwea2Tnv/1hbyna59fbIVRtSytYaEYt/+RqUYcZQ
         806A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m6U0Skvb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id b1si956532ilq.4.2020.06.22.23.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jun 2020 23:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id t7so337900qvl.8
        for <kasan-dev@googlegroups.com>; Mon, 22 Jun 2020 23:45:23 -0700 (PDT)
X-Received: by 2002:ad4:4868:: with SMTP id u8mr25497586qvy.34.1592894722434;
 Mon, 22 Jun 2020 23:45:22 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
In-Reply-To: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 08:45:11 +0200
Message-ID: <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Jann Horn <jannh@google.com>
Cc: Kernel Hardening <kernel-hardening@lists.openwall.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=m6U0Skvb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrote:
>
> Hi!
>
> Here's a project idea for the kernel-hardening folks:
>
> The slab allocator interface has two features that are problematic for
> security testing and/or hardening:
>
>  - constructor slabs: These things come with an object constructor
> that doesn't run when an object is allocated, but instead when the
> slab allocator grabs a new page from the page allocator. This is
> problematic for use-after-free detection mechanisms such as HWASAN and
> Memory Tagging, which can only do their job properly if the address of
> an object is allowed to change every time the object is
> freed/reallocated. (You can't change the address of an object without
> reinitializing the entire object because e.g. an empty list_head
> points to itself.)
>
>  - RCU slabs: These things basically permit use-after-frees by design,
> and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work on
> them.
>
>
> It would be nice to have a config flag or so that changes the SLUB
> allocator's behavior such that these slabs can be instrumented
> properly. Something like:
>
>  - Let calculate_sizes() reserve space for an rcu_head on each object
> in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> call_rcu() for these slabs, and remove most of the other
> special-casing, so that KASAN can instrument these slabs.
>  - For all constructor slabs, let slab_post_alloc_hook() call the
> ->ctor() function on each allocated object, so that Memory Tagging and
> HWASAN will work on them.

Hi Jann,

Both things sound good to me. I think we considered doing the ctor's
change with KASAN, but we did not get anywhere. The only argument
against it I remember now was "performance", but it's not that
important if this mode is enabled only with KASAN and other debugging
tools. Performance is definitely not as important as missing bugs. The
additional code complexity for ctors change should be minimal.
The rcu change would also be useful, but I would assume it will be larger.
Please add them to [1], that's KASAN laundry list.

+Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/rcu
affect KFENCE? Will we need any special handling for KFENCE?
I assume it will also be useful for KMSAN b/c we can re-mark objects
as uninitialized only after they have been reallocated.

[1] https://bugzilla.kernel.org/buglist.cgi?bug_status=__open__&component=Sanitizers&list_id=1063981&product=Memory%20Management
[2] https://github.com/google/kasan/commits/kfence

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BacW32ng%2B%2BGOfjkX%3D8Fe73u%2BDMhN%3DE0ffs13bHxa%2B_B5w%40mail.gmail.com.

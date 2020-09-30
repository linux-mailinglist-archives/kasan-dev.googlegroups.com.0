Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQH62H5QKGQEHGNG2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9141627E8EF
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 14:51:13 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id l15sf570425wro.10
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 05:51:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601470273; cv=pass;
        d=google.com; s=arc-20160816;
        b=MB84KieFXCmhpGOUC6+IQ9VVOlXCOXNMJzXxfUfNjdSkmyFPcPKkdN1GENBji2DFj3
         W77M57QscdjZhX8gvzIpOSB/tk8ZvpnAwTN9CqGzjyGvQRdOYk0l0KOUuHFc0A9HsVUs
         GomCmMbUvKvfCR/NMKzF0QPIy2e4s/jBestwg2FvtpD1xZK5gSATjf3Qwef+FIUnLCtZ
         1ZWymVG9EE4cuPz/X+8VF+LlpS29zOaEibX1SqzGXAVAxQcf81pvee8QCM6EJcfe2XvB
         QtY1HSGQglvrEH1O4/UF1Ecu7Kp5PuBvu4BCbTSBw/7k+wXDZAstJehEjXd6y62JN358
         1K8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WySpF6F+fg01WE39Jk2f5/UbC+kXwe9Uw2JMYArbjOM=;
        b=O230+S+PrmqK8gTopu7yGvA9JJqqBziedte9t19i3hwRIn30qcx93UsAGukMU5hnzV
         ncIgScCOdizvYwM1Gs6UkyYtKev5dsee576wxCySRtxMTpu2ybsduncNBzrvS71+emzv
         /XC+xSyS963Lz4pHWRyNCdgJJdtpJqR6hkpbtv0Nizq5Vy1dahoVrjVa0efYz6ZnBDHk
         2DyiLdiwTd2v4OLvh9D/UqE3/6KFZndsq8qcdGNVLH1KOoZlESawvWKaEQM44wJlCNmB
         BwfiICydP/I2u0GbTkSu/s59QL38d+L+hsBCOD42HD5Zok6zJr308DsWP63YxRIr0jNP
         Rdkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L7X6TOpx;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=WySpF6F+fg01WE39Jk2f5/UbC+kXwe9Uw2JMYArbjOM=;
        b=c8XxO+ZnJOB3pC4W/xa1uh7iOgZ8VzNX8aeKo+CiOC5Lfw/OIDb8ctYEz/Tn05Effj
         UeyCby/ZW4RG6gjkZgkE0coV+5Kr1+NuPv18TrJcHNCK3EsKQek8FS8dW2vZtkkkoc48
         io3SymmjP6UKU0FJSrEz+w+zqZY12NWzQ2sA75jBfr67FECRnr7pxhc33jfN27JM5Tby
         MgwY9Gi9LBDM3SHrXxYeHndjO1PJsPePioJeQBpM9xJxjN0e/vnkHAxJ+twhae73PS9q
         y9o7sdzhk9Sb1NaHhUKdXqJZFekgNLaPQKNqyUJSaa81fguUqDF2r7xB743N0h1Rk5sk
         xWzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WySpF6F+fg01WE39Jk2f5/UbC+kXwe9Uw2JMYArbjOM=;
        b=KyzGvetvcLNqNhQyiYxCndfU9fIwFmByVCdKn6JtSMFm/gFm1QvaAiHECmIarFzHE+
         R42ueuVLjruQraPZWtGkQORDYM4aTzRx2dYTj5WW94/OBgri0FfX3tSaoxN65KSunVKE
         ukkeAof3Z6ZsS/RtkdEPmjEa3flv/SuIr3e6ykkq3wU9WOimGfvQhyvHkvZVWd6Ai4GS
         1N2/88isPxOpDF1IY4q4h0Vi+j7KMkou+7kF/L6Slj2MCFwoUQ0nIm7i43bUhb0rEBFB
         spbntuprl353Qutkpb9Er4DJ2BQAFaZ1c/hbsmgBAclqTCD/ha93loDOExn7ZtFppzk0
         JVfA==
X-Gm-Message-State: AOAM533xbk3kUjGrsnbF3nxwGzhY0N4ttlbTBM23TvMPX2qhrBy8axGx
	x0gpCwwWMHRvNbOt/K62kRQ=
X-Google-Smtp-Source: ABdhPJzvuxovCCzNzdSrdlIbGrTA4seMfZ1m+o/hEbAgTiRpL0vjiNVnKCez3OAsWEEASR5S5tVyXA==
X-Received: by 2002:a05:600c:214e:: with SMTP id v14mr3045907wml.118.1601470272326;
        Wed, 30 Sep 2020 05:51:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2e58:: with SMTP id u85ls1025928wmu.2.gmail; Wed, 30 Sep
 2020 05:51:11 -0700 (PDT)
X-Received: by 2002:a1c:9d43:: with SMTP id g64mr3196309wme.16.1601470271443;
        Wed, 30 Sep 2020 05:51:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601470271; cv=none;
        d=google.com; s=arc-20160816;
        b=SoJbVU6MFJ2q/s2xuyaZpPDeYir10kMud2QmUUN/SRegjdfY7AEK+mGneRS7Dk7Y+T
         v3XUsYOZUCeFWAHs2U/QiUy3k2b80sPcZ/WpnOu+ZCRz7FFhC58CWYLCfjq2nEIXsAao
         8iWyn2jjyVt/P3eGJrknk/NkCQ+nL+PfJWpAw+GMYyxpp7clbGnbp3BDPJcOJjLT1a2j
         +ZoH6zkf5i1jFniDPdOynxnvAEk55wDQgMBKcPmQQZF7piB2KNYqfLyBJtVJ2OwpJRpK
         1AHSVXAmGDKLQ+aKzTnjlANpdoVZyjljp3PbD8tngJnU/h/mLnN+M7LoCCGP0xZ6mOiT
         56tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=061+j+6egSPgQBxcQTsTW5phFlVIKpu1EERfRNYFm3I=;
        b=lJk2WSdnSMX8hY3BZfxOUwTMxyLjGIJbqoDLdz/cO6xJOesQmXgyvCfUgcZARv3sUa
         j6bmjBC21IUEg8fRwM4I70c+WA9zXlL4aR81ZoktaaLsF8G9d5JNtcyBp3iivFYQvcOi
         UFaqpkCGhiQplFwtUrLFmc4p2VWd9i4OvcCtYwEJcs81+BRwDvK33oKt5UJYq9xKD3Ig
         GfC2rOaRm0OkFfpO/swDBWN971mH4bPuu2JDE2pLkSkwuNI6lOj7GioUIsqz+LSYWI1b
         BmNN08LA46/+ZUcMDwTgc974UYPZ6JNMs+snMknXtaEyC9jSXU24rNHbOFF0REBy2cWF
         8Z/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L7X6TOpx;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id d19si39012wmd.0.2020.09.30.05.51.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Sep 2020 05:51:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id e17so1575526wme.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Sep 2020 05:51:11 -0700 (PDT)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr2785473wmj.112.1601470270876;
 Wed, 30 Sep 2020 05:51:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <20200929183513.380760-3-alex.popov@linux.com>
In-Reply-To: <20200929183513.380760-3-alex.popov@linux.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Sep 2020 14:50:59 +0200
Message-ID: <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
To: Alexander Popov <alex.popov@linux.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>, 
	Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthew Wilcox <willy@infradead.org>, 
	Pavel Machek <pavel@denx.de>, Valentin Schneider <valentin.schneider@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=L7X6TOpx;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
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

On Tue, Sep 29, 2020 at 8:35 PM Alexander Popov <alex.popov@linux.com> wrot=
e:
>
> Currently in CONFIG_SLAB init_on_free happens too late, and heap
> objects go to the heap quarantine being dirty. Lets move memory
> clearing before calling kasan_slab_free() to fix that.
>
> Signed-off-by: Alexander Popov <alex.popov@linux.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/slab.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/slab.c b/mm/slab.c
> index 3160dff6fd76..5140203c5b76 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3414,6 +3414,9 @@ static void cache_flusharray(struct kmem_cache *cac=
hep, struct array_cache *ac)
>  static __always_inline void __cache_free(struct kmem_cache *cachep, void=
 *objp,
>                                          unsigned long caller)
>  {
> +       if (unlikely(slab_want_init_on_free(cachep)))
> +               memset(objp, 0, cachep->object_size);
> +
>         /* Put the object into the quarantine, don't touch it for now. */
>         if (kasan_slab_free(cachep, objp, _RET_IP_))
>                 return;
> @@ -3432,8 +3435,6 @@ void ___cache_free(struct kmem_cache *cachep, void =
*objp,
>         struct array_cache *ac =3D cpu_cache_get(cachep);
>
>         check_irq_off();
> -       if (unlikely(slab_want_init_on_free(cachep)))
> -               memset(objp, 0, cachep->object_size);
>         kmemleak_free_recursive(objp, cachep->flags);
>         objp =3D cache_free_debugcheck(cachep, objp, caller);
>         memcg_slab_free_hook(cachep, virt_to_head_page(objp), objp);
> --
> 2.26.2
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
kasan-dev/CAG_fn%3DWY9OFKuy6utMHOgyr%2B1DYNsuzVruGCGHMDnEnaLY6s9g%40mail.gm=
ail.com.

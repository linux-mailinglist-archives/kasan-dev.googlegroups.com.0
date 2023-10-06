Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKPFQCUQMGQEACK5WTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 42A2F7BBC85
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 18:15:39 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6c65a8aaa0dsf2667581a34.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 09:15:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696608938; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxAJCxk0WSUSunXERxLeWw0n5K0rq4tdbM06IclYsvGgxPg5j2N1LgvFBrwBIrAE2i
         Wufq1CZDYYaF7ig18fDO89lIVIJTPfzeM7yyLuUal37ggUIPhstu/8F7D1lNXpEnSj+t
         26tiwohiluJdVNL9ehTce3ftG9E9e46laI89Qjo2u/qcBWO/bXfWXmV89vHq6nXQwIQY
         MsBVu113tiXdGvAcUwmwXlyZgLbFjKotx3nIZ4sTpPmgBKdxX7cwJNhTlrNRBx0RGLDR
         InpyNf75EiVKiFYwRm7vAxP8KtUFc26wm0QJK/M3DFzRn25Hj6wO6r3zj9q8CJEdtWYl
         zfRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KbsOzv9lJRoObBrFrmmzKJ7a4tKP0mGvJ1pf+NWl/Oc=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=YbDTQQ7+KjGyGLGfZY/O2eN5NjUVKYxFqs0BMXFhy+Wcgs1MFNyAug+lRmOwB51JG3
         H+x2wnhz2zoUSBQkurWmNl7I/uQx5IKf81fucV9eDCF6mVKP/LbIvNirInaEnZcblZQK
         Yq5BqPebVJrf3r3PLvpJa6qealNU8vmgiliFk61m1x4p1NhMq7U0caK65swaxpH5DbMd
         BJCt5Ao4Vo0edl8kkbksP1DPmTlpyVfbnaZhO3dTFvN8irwIRMOM9FESJ9FySinZWgVg
         90bmzZUC5hgeNxfmsDaIGqTBZfdGBpLl5b5cTrqbH6vHtY00+sqb7R+EFO18PMmThcwm
         D8+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tl7jjoaZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696608938; x=1697213738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KbsOzv9lJRoObBrFrmmzKJ7a4tKP0mGvJ1pf+NWl/Oc=;
        b=Aq79u7lH5iwLnkVBasvdjPG0fYuIFuBnVpdS6dAGv9J3PpAYurnjYBADl5Ic1fidvh
         8O1yEkNbHf4rbghhR1A2fEOek5B391JdUN/8LnV2m1NjvpiO5XziN7Uh5B1x93WHhMga
         oXw0WJO0cJnoOodr6qZ9kJLZj+QfLGM0gB7ZYJxYT2MXWJeX3OD+IrKHbXEi10rDZRKb
         l5Uz0RFSvF3Z9Mmzh2rZlXyH8QYWC0nibIJprMe8AhJnOFPvCxXAPWk+dZ3tX2prZeV+
         tXNizrSG9DCQDsPXHqhyDzYav2eTEUwuaRAPfNgSVu2jMgT+EYDurMhLqOySqbcBlDxa
         lXkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696608938; x=1697213738;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KbsOzv9lJRoObBrFrmmzKJ7a4tKP0mGvJ1pf+NWl/Oc=;
        b=A1JnZthFTKzuVGij9rz6MAWPXPpEbCTdQNgeZP67Ir1rMA+jbG0rSEGNpikYSeHdzZ
         1D+SiYz4sseV9ZfGIXvhzHUy4w1qvH7vnUgMm6m4aWn3I3y6V0pkQli0K+NbHRZpxXT4
         I50IM8DrIYL6so8GkuNaMzuAlN1EhZrMCKbb4O6jSDGTitaS9uOp+bUVZNRXt3L8tI2u
         jr34avgq3KcdRJZIglihpgfkzdBY3Dogo4+VtEt/rpmeScIEDW04KzgbsBqnUIE907DA
         5hduuHHiyO/CROCR3DwtbRIK/b0Htn0UR9dSFhbtkQ63l4exi+8jdN6XDei1Ba9TVeZD
         EyUQ==
X-Gm-Message-State: AOJu0Yw0R+HDk+AlffaCtft3hPNjtNQL9Dnf7+8z3crqLlhCUtj/5/XO
	gkE5RGs7GuisRdgVYgeF4tk=
X-Google-Smtp-Source: AGHT+IGdP+5kJXA0DDlL6GXG9sQ7HMvo3k38RAO/j7U9Dtx2HOr7zRmMze2jOP2IFwlFz9z+oGW3bw==
X-Received: by 2002:a9d:4f0e:0:b0:6bf:1444:966d with SMTP id d14-20020a9d4f0e000000b006bf1444966dmr8396090otl.1.1696608937800;
        Fri, 06 Oct 2023 09:15:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5101:0:b0:57b:7aef:9d1b with SMTP id s1-20020a4a5101000000b0057b7aef9d1bls2655717ooa.0.-pod-prod-07-us;
 Fri, 06 Oct 2023 09:15:37 -0700 (PDT)
X-Received: by 2002:a05:6830:1486:b0:6bc:e8dd:9f4d with SMTP id s6-20020a056830148600b006bce8dd9f4dmr9358247otq.11.1696608937111;
        Fri, 06 Oct 2023 09:15:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696608937; cv=none;
        d=google.com; s=arc-20160816;
        b=DEpKmdPf2qbtwdlPgSG4SD3N0LYPKf7zUKQV/eEaDfYjwYtlbZcEV3pClx71W+nMMM
         3Sr5BaIzQM8I79G7n/UlcJ/Zm48ZnRj95+PPYAe+2h6QjeGOC7ILVI0HPk63cljWqDGm
         6WxpazPxNppyrpamCS9ypfSKftIPTg8jUo6pbXV/Qix3qUIYEotZ7ABJYl8W6KrBAOOe
         LAmzq2Xx8MfNZlYQJO77IZ8xrUWuMEXri7rDIXkdN+zZgsuMzbsVPQfRTMS/s+Y1j1uB
         xLy/NkBQXddlt50ORkm9rLL0VsexldpdIeBHAqRUEKI5pm0/dhxEWXNQBjUR0bH1BleE
         7Gyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ai1VUkXPsadETq6pOE6a32ZLkIYlGlq9aDxrp9PEvE4=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=hCTa66H/cPr1J/P05FQt5Pv1sLvMp2mWn3OVZJ/mFc2sKWdBHYscJ3mwvgEcPqezey
         rskDRxfLp3wD5Dh54UX5jICSv3Cd+M4HLoyAvRDD50FksNRt0cPD3apkrzcNe+e5hlcH
         TIYOfaCWEI44v2L92X4n0IhJLrCw/S/g75iySM84vV7KDNXfYggI+7kiJ+PXdk4iMNaH
         lYUcOHSVlvavg2oezzPW1dOhkV1rcmjO1aGQ7VF0Q/l8eZa69c9CZczL8x2YGttzDMK6
         fRvi1DmYMd6Y+jcX5qL/CpF7ysy9CZkl84UqRe3E4ZC/wDPaOw6ce0qLDLRRe0NBOq04
         vRIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tl7jjoaZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id c2-20020a056830314200b006c64ecd75f8si449649ots.5.2023.10.06.09.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Oct 2023 09:15:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-664bd97692dso13172056d6.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Oct 2023 09:15:37 -0700 (PDT)
X-Received: by 2002:a05:6214:4285:b0:658:708c:4d56 with SMTP id
 og5-20020a056214428500b00658708c4d56mr8723713qvb.17.1696608936423; Fri, 06
 Oct 2023 09:15:36 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl@google.com>
In-Reply-To: <e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Oct 2023 18:14:56 +0200
Message-ID: <CAG_fn=UAF2aYD1mFbakNhcYk5yZR6tFeP8R-Yyq0p_7hy9owXA@mail.gmail.com>
Subject: Re: [PATCH v2 06/19] lib/stackdepot: fix and clean-up atomic annotations
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tl7jjoaZ;       spf=pass
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

On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Simplify comments accompanying the use of atomic accesses in the
> stack depot code.
>
> Also drop smp_load_acquire from next_pool_required in depot_init_pool,
> as both depot_init_pool and the all smp_store_release's to this variable
> are executed under the stack depot lock.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(but see below)


>                  * Move on to the next pool.
>                  * WRITE_ONCE pairs with potential concurrent read in
> -                * stack_depot_fetch().
> +                * stack_depot_fetch.

Why are you removing the parentheses here? kernel-doc uses them to
tell functions from non-functions, and having them in non-doc comments
sounds consistent.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUAF2aYD1mFbakNhcYk5yZR6tFeP8R-Yyq0p_7hy9owXA%40mail.gmai=
l.com.

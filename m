Return-Path: <kasan-dev+bncBCT4XGV33UIBBWFWUPDAMGQEPX4OAGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 16519B58C6A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 05:36:59 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-32deaafeb5bsf6554786a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 20:36:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757993817; cv=pass;
        d=google.com; s=arc-20240605;
        b=FbIqHPgh2WL98sXT11YqBcT+cxvF+8ncIJF1wjJ3g96RnobDNpn0vNQxeRlQMWgXUU
         QE6QGoMTSVuL15pKKB4DucHlw+sErHZ+aJcUkGPmimo0loGYY+2J8gthMygcocyeifFk
         iTNk79KkptWmCHirxTrO2GEcV6HE55bbHN/iSEr054VdL73a44Fs63MYy/HomjJYplNr
         h+HhIS3gLAI1B3vfMqJnhaOvS5sk1GsU9ilhN4f0u8DoLPYaKXhWC2UtCvp33OCkIFmr
         g7W7iHbVT+fbfzG228j5qSNBYt+c4G0hceb1LZf+DK+kJ4SZYXjdLAvhLfYRkOBBJy9e
         0mvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=i5oqsic/jClY+meQRTwZ0HiXk2YJbl9KnID5CzRmqHc=;
        fh=o1M20VEE4ElF8PFvPS/kTj7uGE7xcGqaTmEj3A1OxRE=;
        b=d14DeWLCf5aW9VuJrBf24X4bSd1dnQ6ZEguUgZNagcvHH6ejFMJ/jJGePu/ujbCL8E
         JRmi5EQoIy3aE+ZVi6k0QmkdvtS5rkpTSSx2RKjO94NJZhBoblLuBLTWQo3RbFmD+cye
         xsfJM5f4t11a4xT3D9ssyOQOI94MY/QnTw7kkJC2u8dsPgKZ8xVgM/MWfoIV5oC4U+TL
         9wqm3kWNde7sqKxyLhuTTUNZHmJ0qnLTlARaEIjUYT4mCpjCLgvLzLqeBPzIAdvm0aUy
         WX+Vr4wVScm3avWTTnB5sNbHtu+BYU30yDKFvjm+GjqL7DPfGudlKIqT0HMf63cdhHdE
         Ewxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CNf7AHxN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757993817; x=1758598617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i5oqsic/jClY+meQRTwZ0HiXk2YJbl9KnID5CzRmqHc=;
        b=ofH9QdrWZDteqvS5qRfvYZ5oqwCPPjqG33ToKXrna/KxIGy7IKDqIeDtgUw2ECb+9f
         E5vFVqAjCNJYPKxDsCNKa9wD9P+8zE+vzkNYHbj2gcoL2KdkHIhoNgfzs3wLIf4iHPqW
         21dI4Y0s1k1/JMfTyYwknDzA+u3lvFaDKHMmC83YzxYXZ6zLsUWyjw8Bh7Hu8a5Tw4gJ
         IPcCeTfkj4esQ5IgYQglviMIfdnECplEVhGZmMb1JZqruq9oh9U7JlYT174Rj/h/TAJF
         oCD2dMG4I9XUZk55EPQXANhhBvScWCjq7Cp9iPEgfGuAETIBEMdaadIYGzIn8BfEjKbO
         HOqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757993817; x=1758598617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=i5oqsic/jClY+meQRTwZ0HiXk2YJbl9KnID5CzRmqHc=;
        b=rAIJlmNn/ETP9mRBSbMtxWLt10/+3EzUsJYxiG4LHEsYyKak5yeO0Z877N0NE8Lfvt
         rk+xIhq1Yx/B01qiS4VizvjGfVEXUbVmbE5z8I/KglJ8Q2Gju8mNcaysMXuYwR4An7px
         TWQCAqBLYccPxLlMzWwR+mak8V6Yds5S2Zk6HPzaG0RQpD0h+ANYV1IXrUZ+qqxvxfa4
         9SIoN1jZBJZgcDX4D1qswqah2uyoXPT0W/WplG4zJeMlaRodUFkB73oUaJUAxBKjftJ6
         dJDIIRmD2e9rDS3PD1pPazP4grgs5/oNpBCgtJBwNbc9LI5tip9769h1gdTM40JV5QsO
         Hrmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVu7tNjHwzyd0Ex10vtpQyUgI9bPF8W307XCYCimOuuQ7FeSv92LDIeg6mKSa41Vdf/Z8SlwQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHbEftWmoHuEjjwou9LBw4zzP/zim8QyylshWIHe3EhCytHMr9
	9OvAhx4WKYvOiX5CMZ+DObNS34WiGC/M3o6Onc11JF4xJHbrCJHHvfdt
X-Google-Smtp-Source: AGHT+IEQVmHXgueXSj92fPz7CSGUG3Jq1IrU78O8FDlyIJZ19LgA5G6mYU95A5IK7Qzca8+9/78ACg==
X-Received: by 2002:a17:90b:4b06:b0:32e:a41f:382e with SMTP id 98e67ed59e1d1-32ea41f3c21mr1570811a91.28.1757993816824;
        Mon, 15 Sep 2025 20:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7M0iDY+zeF7+9PHq4FuQNmILCDjOML+MBD7rMaMMAw0Q==
Received: by 2002:a17:90b:3d8c:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-32df96cffa5ls2789934a91.1.-pod-prod-03-us; Mon, 15 Sep 2025
 20:36:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdXo1F6ofqGi2y3+i6+OLkGBFfIqyigOMhzLA+w/GuLThdOk7eHwbXCPberd1KcLcojzmDTiag3iU=@googlegroups.com
X-Received: by 2002:a17:90a:d44d:b0:32e:7ea2:6a08 with SMTP id 98e67ed59e1d1-32e7ea27411mr4768599a91.31.1757993815080;
        Mon, 15 Sep 2025 20:36:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757993815; cv=none;
        d=google.com; s=arc-20240605;
        b=BAAAOQH1P4G4fpXkCHDtraGMNYO+RhzcjUVd9vM45B/rYT3MVi+bJHp4wjphMKSQTs
         JN79/nuSxdaVZj9yP2vosBPQwlfqlZxOSFSnZO+SWgu8BDFKXzxhmME0CCiMdZ8ASa8X
         cdYwumlofo5uUoPPscFkG3Zi8LwDv2fYqyN17rKbE6S8qZ//Ti1IL8QSDs2XIzX8hJDq
         l/9wG/Cm1lT4jJDJn9oltgSG7fiYGlbfhbfFEQAAjmM3fGEwDQRMe/5xbMkWXaDE89bm
         fonxNbSDTwXrZhasvZgxFRhYM39sWRPkGaUnF6Us3iuA517CQU6qcYt8oYcftCoOgYir
         VvLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AoUtYaSqpxJxvLloy7nshr4G6vpZl850tw+AAmUwDdk=;
        fh=J47oZQpZYurB68RbY8B68GTo0iNcNF437tzwHG2LTkc=;
        b=EdlPt/F/RUkTlSC/hbgND90+2fxK+mPwy+h/Oy1vqV73AfKHSQ+Q2rWULeRMhnz6y8
         y0TZ0CJckIgjiI1RUV6b5Lv8cnNWqzmQtLPpTQNQeEyLEfBBTzRfOWVZb1XwNk38Jpxz
         clBI+QnqMo4Pd9z4VdKE9pXQomfjePwhqQc3uQ797uVF8JPDy1G2n/cdgPwYor8ZH93f
         XDJY8v6gYAmN+xuWPs4fSV9e3IqMiWv+PbEolg56kvbiPcxAOYyFdX5s5u/OouSuXIai
         v+GB21xuWiI+wZ4nZYmdRDnjQyvP9KhF1JwOqHKiTQChbTVu5a+AzP64bI398Z40ehNz
         QI+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CNf7AHxN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ea0859ad4si68972a91.0.2025.09.15.20.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 20:36:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C7F3040716;
	Tue, 16 Sep 2025 03:36:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F04DAC4CEEB;
	Tue, 16 Sep 2025 03:36:53 +0000 (UTC)
Date: Mon, 15 Sep 2025 20:36:53 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, ryabinin.a.a@gmail.com,
 christophe.leroy@csgroup.eu, bhe@redhat.com, hca@linux.ibm.com,
 zhangqing@loongson.cn, chenhuacai@loongson.cn, davidgow@google.com,
 glider@google.com, dvyukov@google.com, alexghiti@rivosinc.com,
 alex@ghiti.fr, agordeev@linux.ibm.com, vincenzo.frascino@arm.com,
 elver@google.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify
 static key across modes
Message-Id: <20250915203653.c17d501a5f4b68936a0e3ea9@linux-foundation.org>
In-Reply-To: <CACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6+nG-+bTA@mail.gmail.com>
References: <20250810125746.1105476-1-snovitoll@gmail.com>
	<20250810125746.1105476-2-snovitoll@gmail.com>
	<CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com>
	<CACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6+nG-+bTA@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=CNf7AHxN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 15 Sep 2025 09:30:03 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.co=
m> wrote:

> On Wed, Sep 3, 2025 at 6:01=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>

[400+ lines removed - people, please have mercy]

>
> > > @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem=
_cache *cache, void *object,
> > >  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> > >                                 unsigned long ip)
> > >  {
> > > -       if (!kasan_arch_is_ready() || is_kfence_address(object))
> > > +       if (is_kfence_address(object))
> > >                 return false;
> >
> > Why is the check removed here and in some other places below? This
> > need to be explained in the commit message.
>=20
> kasan_arch_is_ready which was unified with kasan_enabled, was removed
> here because
> __kasan_slab_pre_free is called from include/linux/kasan.h [1] where
> there's already kasan_enabled() check.
>=20
> [1] https://elixir.bootlin.com/linux/v6.16.7/source/include/linux/kasan.h=
#L198
>=20
> Please let me know if v7 is required with the change in the git commit
> message only.

Neither works - please send along the appropriate paragraph and I'll
paste it in, can't get easier than that.

> >
>
> [another ~250 lines snipped]
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250915203653.c17d501a5f4b68936a0e3ea9%40linux-foundation.org.

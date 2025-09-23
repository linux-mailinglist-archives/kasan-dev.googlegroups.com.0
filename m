Return-Path: <kasan-dev+bncBDW2JDUY5AORBRF3ZPDAMGQEWZHVL4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D8258B971B0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:57 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-36b57abe6d0sf12545451fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649797; cv=pass;
        d=google.com; s=arc-20240605;
        b=d8PZftWQI+t6+Al4qgcO7gX82IiepcLMdarE5pvkXuyAPzYlDfcFwDFJuQ/L/pHslg
         CdBI6cw/xY9vrdzNyW2PFflQHlAtPzkTRj6ji0HWS97lqR4dWa8ZBATN+Ekbn8iwRXd3
         0KcAI6j9ixJCifMCSjWbba+MR0RZs1mVIwvpQ79r4+WoRubikE2fmn6QNdfZrXRkWP2M
         jik+qYa0nBAgV2QHdnvagXg73YhoMxMMIF4cA9QXNSayXJab1Fz9VzIIsh0S6/jj2Owx
         io48kORJAkhkKD3zUB17DfaJUewYRSFRXHNNQ+BMA/tnFvpKH2gV+C+5KTh3D6VYC4Ll
         JXtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JrgjIvePzpKv0uIFbf62y5UM/Jj+9awxBwYWSK4GZSY=;
        fh=7lAa+cm1fFra3cYDEd0bJaUChE78L5tS/JZV6CVsdto=;
        b=eR75FT5D6tbKilaxWfG6PtomDd5p7dX7MfF6+yPEV7KxJslBJvN793S0HEr0p1LwGc
         m0UkBOkDpbR1s9ntW7EvrqG2YKz9aUCuJAm1bk6J5ktq+ATsP11Mrpyl1BmliWVpQTuO
         XhIo+MnjckkF84c8S90+s0cBEaV22qPYiresh89HD9ROyx9shjUYp6Lp/Q3Ab3SQDJE/
         SBvpNisXQd8NJEyXzCZJI88fLyiY7sTWFSRoedKixxCPoEaqGKu2aTTjGOI9XOCR8zJx
         ytqAPVP5FRh7jr2NY89Ep/QZ8Yt5xb/RvxrCJCZAO09W8qZ0kic7GHhufaSv0GGbpRp8
         Cmdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cq3xI5k4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649797; x=1759254597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JrgjIvePzpKv0uIFbf62y5UM/Jj+9awxBwYWSK4GZSY=;
        b=iHor3OlEjTEoR3ZRISTeHeh4k/1Jvq7/vA+adQ7u+wrGTqDGR7DUuQrU6fQXtmDZLl
         PaYIkCBzvhYL1UuXUX1t5OMgstNuJLRAkGt3IfSyoPTVf+ZzSluCn8v6G+fmKtbtSCsx
         a9oiLWIE80elBre1HcgyfPpI/03rzawXRhlHMLrdSWUV0Hs3orAQJdUlRSGVuRyT1q3S
         ONMzwXWNwQzaj+nytRmjG4ecNHiQB4MnMheGk03pmrsAIchSxFI0Av5i1qsk+LRWBQJP
         VHyeaJKzFC37WVUHaZLvigmMzcRnChaPessjYDfXc+ZIZhHZCI/edLu1w6kIJXEprs28
         E3sA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758649797; x=1759254597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JrgjIvePzpKv0uIFbf62y5UM/Jj+9awxBwYWSK4GZSY=;
        b=CApY4mp0t01uMERGwRB0XbXGfHWVELuB2KE8pKOFnPP0+1+wA9XmZVyKoNkiuSLCGM
         LWbq7FZWTeYS9NdkXCeNiEuturyN4XeBBpVWh9XSQb2B+LR2J1GZ/Ekm07zCqf6WJUju
         qSQ8Ijr/6ByZU761pfsMlOVQnYBshBn+mZkBgqQVAgwjQV/14Q+oiyNiH9afRoA+Jxk1
         /+oIaUE37amEsuc9T/xBfQndQhg8esabUX8rssamkZwo+QSLySJNqnh/UrwZPYQrnbpe
         mwSzh6NVHg3WoCHb9sykMDmMmBjE00kb+7oL4ZkOLWtuAoMCdrO412VIuo7T0/zThV9D
         aK3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649797; x=1759254597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JrgjIvePzpKv0uIFbf62y5UM/Jj+9awxBwYWSK4GZSY=;
        b=SM7hCJeNkgIgi1vBdniarkxv5wLGQBSBypZkksm0rFrJY0+Uo94k5XQn6WjBgGsr5P
         czoU8Lg33rYXhLhb2ILdt+TzXNbBT/xPLww75iRrMf1CRxH/dL+gop5TglmjIxbN61+S
         Q/F7z8h1tCObZwe9Gv31kU7Us7uIdT8g08ByGZ6u5kFLWXFK0WoNkHM2ohiAyuzY6FET
         U3DmBd4Vcfvm7PH4UpjTkAlc8iqSSocSLYnCxBrnrUR/cFJG+npIcpt+bXB1Vqw5bXgP
         Hn6KQi1UIY2SYy9389vPFW2XzejKcEh6Y9riCulAvGpLjFlclynN6FtP4mNqJo+yomgt
         jgPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU39Vggb8gUWOMlG/4yFj9uTrWBZqsEFitL/1WWf4Kxd962K4QLUVwrZnOeGcf4xgDKwhH/MQ==@lfdr.de
X-Gm-Message-State: AOJu0YykE0OapQB+QV+QMtp6yf9zYbyWLLrk9eKEVnlV7RvoD+qlAsVm
	xe38eiiZSbhtnRyAQ8mdZlXnj0CmrfMWHNt+YDVcd1kpKNk35zMaPPnX
X-Google-Smtp-Source: AGHT+IEeGkv84t/E7Ge7/kVG0NzT9KVKB7zQP30fWUG83ntr8I++WOQDJmNrdMmWTMVdyO7orZjUFw==
X-Received: by 2002:a05:6512:6396:b0:579:f0fc:429f with SMTP id 2adb3069b0e04-580730f0895mr1097131e87.49.1758649796853;
        Tue, 23 Sep 2025 10:49:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7OZcmwneD0UIC4IankU+ou0QSWyLwINtlkAsyXuY4b8A==
Received: by 2002:a05:6512:1051:b0:55f:457c:89b2 with SMTP id
 2adb3069b0e04-578ca7e37f2ls2024266e87.2.-pod-prod-02-eu; Tue, 23 Sep 2025
 10:49:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXULyX65rTxCxwuEdenh1rYLq+g/1BgKqdCkKZgxIPNIrFiHvmclOe22X6QJrLlE84630Ix5YCcFsw=@googlegroups.com
X-Received: by 2002:a05:6512:638e:b0:55f:5685:b5e9 with SMTP id 2adb3069b0e04-580702346c5mr864116e87.8.1758649793965;
        Tue, 23 Sep 2025 10:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649793; cv=none;
        d=google.com; s=arc-20240605;
        b=cxiZyUrkTP99zJkswMopmyqAZI6WMVf33pAnG1HfcqyD+gMaf6BwfELY0HPb85PADD
         mlWPoGfTQCp1EtV35KZPpkgFeBnZGvM1g69F/Ej7LxHaRx/ePChbtF7DMV9hcRIQMmQ1
         Uzz5DAJ32RHHBca38eUYXmWakNXmmfvOx+SPFsklXVs+bhlqnUXg8iuig6vJdsk3dBN+
         C6R79rSRR5aspxEMLEzYZQaNA0uSEyd4tJWvxeQp3wSbeg9oGs3hqwajyhv9+332uZg1
         D3/j9fOrrm1QW1RcNrQypv5YYhlGVJbT+nEKFyOwt63TNi/mjDz+ZwhBrnHgbhgTJoMO
         HBGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=O0kx1rTugh76QptF0xZZo2hW1gYb0dlnX+yVu1KHk1w=;
        fh=DwW34Ilm99F4b6NeDlJ8eUKkQVkeo6zLEHlOK0g8RZQ=;
        b=Qp0Tt6Jv1/x3W03H9fLfTCRyQfyppcG3uvV/77Ma6F8+p915kc9i6Kiab6w5WS3KIj
         MUY9hOY7YMpxPwpZ0ukaMSRic7pMX/9dFF7oLT/RTUFCIbOH61b6L5HBqrYVR/HkBko0
         lZ9OmXTbJjUIDeGqtU6sdOBoiWQ5on3CnBMs7UyDB1EfxkihocCyEMXv5IXCQfJty2wc
         9rP1s5nTZsMDSs2J9IvI7EOLpRsK9fWqhbMI/1B1Dp8cEp128SVF7axZVLXnlSkHmSAp
         FpjmUl74TCOuXftCAZJ3ks3myiR8hIg+LzaRZm3r6xWbuVxbxRnSH7x8vtbywC3bJqCa
         U1xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cq3xI5k4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-57aa85bd5d3si291025e87.4.2025.09.23.10.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 10:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-46cbdf513d7so27861105e9.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Sep 2025 10:49:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaNeFuv9EkJCkq30mFNCmM0bmAaBb+WNhz0Ty46McaTWUGjV3ZfC9eQXwsaEm6q0VF/CkmXpz6hEA=@googlegroups.com
X-Gm-Gg: ASbGnculwMOD1Ko9XvQs3NszRn/GLyqcfCZrfOfy3oP9x9Lm9SJKNpdhJp1uedvhb4G
	2lWI0e+C2hP33IUBYyt8TOCC40tfCXvyapCudTo3bvIdawkOlGS3b7MGNecvNKPlQyPFzPmQ+M5
	DLOQ4THNWxPTHy8GQRRGGhH/Ylk612pVijxrAGTQCwkqtbTT0FjxNFQwvsz8yFRyDaW0w/me0WJ
	wd/ZQ+DtQ==
X-Received: by 2002:a05:6000:200e:b0:3ec:7583:3b76 with SMTP id
 ffacd0b85a97d-405c6847528mr2568370f8f.22.1758649792481; Tue, 23 Sep 2025
 10:49:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com> <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
In-Reply-To: <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 23 Sep 2025 19:49:40 +0200
X-Gm-Features: AS18NWAnwGHtT4NaZMiBj4LqaLnQFy6R4R90e3R6j2xRpw7zcnqFbVZB-WdaVnM
Message-ID: <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, snovitoll@gmail.com, glider@google.com, 
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Cq3xI5k4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 15, 2025 at 11:05=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> > If you feel strongly that the ~1/8th RAM overhead (coming from the
> > physmap shadow and the slab redzones) is still unacceptable for your
> > use case (noting that the performance overhead (and the constant
> > silent detection of false-positive bugs) would still be there), I
> > think you can proceed with your series (unless someone else is
> > against).
>
> Yeah, that would be great if we can also avoid any not needed memory
> consumption for kdump.

Ack. Let's add support for kasan=3Doff then.

But please describe it in detail in the KASAN documentation.

[...]

> When I made patch and posted, I didn't see Sabyrzhan's patches because I
> usually don't go through mm mailing list. If I saw his patch earlier, I
> would have suggested him to solve this at the same time.
>
> About Sabyrzhan's patch sereis, I have picked up part of his patches and
> credit the author to Sabyrzhan in below patchset.
>
> [PATCH 0/4] mm/kasan: remove kasan_arch_is_ready()
> https://lore.kernel.org/all/20250812130933.71593-1-bhe@redhat.com/T/#u
>
> About reposting of this series, do you think which one is preferred:
>
> 1) Firstly merge Sabyrzhan's patch series, I reverted them and apply for
>    my patchset.
>
> 2) Credit the author of patch 1,2,3 of this patch series to Sabyrzhan
>    too as below, because Sabyrzhan do the unification of the static keys
>    usage and the KASAN initialization calls earlier:

Since the Sabyrzhan's patches are already in mm-stable (and I assume
will be merged during the next merge window), just rebase your changes
on top.

But also note that Sabyrzhan is planning to move out the
kasan_enabled() checks into include/linux/kasan.h (which is a clean-up
I would have also asked you to do with the kasan=3Doff patches), so
maybe you should sync up with him wrt these changes.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcWEuBerMeS4RCXQtged06MJhY%3D55KsYeJEOJn3K0psXQ%40mail.gmail.com.

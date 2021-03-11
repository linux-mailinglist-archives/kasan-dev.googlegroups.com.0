Return-Path: <kasan-dev+bncBDEKVJM7XAHRB3NPU6BAMGQE3OUDKJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6BC7336E08
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 09:42:21 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id n2sf3739765wmi.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 00:42:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615452141; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5VRiifMiaemxZQyQTwoFUPR0ITDgRKWSR4XQodpI0PyDIMA5aKeMSbmI9ZZfHTaB3
         nANCGb5UZtHYusXM5T+ciJE+VyON5UwYVJpkLa2ylHcsZnLJvhOpUPQp6gNd0ZieJJ5F
         SaBVLoS/o0QiGVR7T7qWhYCxMChlWA23PSTKRmvm4wz+vGhkD2HAKAmAb6qsfvBkNJ5I
         6t61J7Q6b7me06j7g9eSjSQmtTHD/Fm70VM/QHGsovFai7Zn88e75ylae6iGBsWAiEqa
         G7dIgpE9udaqwj5qENKijkqjeQ1lrDveekzkMLVPF/cXM2GZ5B8FDvtOlaWEPAEUE8XY
         07vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=gb2IHkEnaFC2dx0wPuQhc12i4pw/zA7X0sN68x2xCUs=;
        b=TPtOFLu1kM8k0s8rH1xQsKVkRZTL0+4x4zsbNFHD1cs2iK+FupCpnaJ4h5RAeeQxd5
         N7JMr76wb9FtfOkq68EPCLGq14OBRVPjsSK6PcXo9hgs2ccC7mfBk/3c6hpDFhSje82L
         jRS/F5rfbjihX68uO0EQRxiWNC4Gfo+rn5hqWfEMm8xmxlohhmMGQn+J8t14pO9NHRy/
         73QWfW29bwOjCXLLcpqPqrHJh1/FMTziEEK6sOL/ZfZeSz8uYgHgz7aX1ChNnPNr8/KN
         O5JCIQgEh/Mjbp0izqzc8CCGM6td/ONlni0pQV2gTLB2OYiKLwfLe0/7L7PuzrgES2oR
         9LiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gb2IHkEnaFC2dx0wPuQhc12i4pw/zA7X0sN68x2xCUs=;
        b=AE/cfrpPtTX98BZ8MtKQLaqo9yHns8GMLRhvZ8Z6SUwxHw0/Xntvk6qQjBmM3kzTNS
         6CP+QD5nPZSzWVex9tMgLmgIWQrGCwhVWbm0UCxLc4Vx5G+2sCR5NcvmuEUJ7u1ECeyn
         E5xPMk9039QEJzcaNduJpi+3lUn//aCc5WAOkGBcmO8Q3RnKjxqmB5VBzypQ3t2wp9tx
         lKlBGRSxMMa5ZLzXXG+VmqQUuUAty2qS1OHgKt2mbBWc/1u+5dH4SXaM5E0sY0OCqEH0
         HlN3D/MC4GhJFlV8KygZVKFkMd4cjbZdNuXBHQFAB92Zr0JkyDyp+qqJVbW4KQUPZwpj
         6K+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gb2IHkEnaFC2dx0wPuQhc12i4pw/zA7X0sN68x2xCUs=;
        b=g25PcLIGP1Zx3bO6laU5dGQyjr7GTiECUMNAoXwDoSiZvBre0vetZLSVbVzldcfJwf
         FtCNCJR2pkWHdkBz1Jv9KJ30MB0+RvfYqUMNu54hVmmVZnfbV/1T0OCZHKWRNlLG33ow
         /z9BfImP3ZpxbgQiUY7nOo+MHwb5g8CwG/mtq9i8x36vrFcToEwychL5Vcz438tvOaaX
         JRr4dr8ge/txKgA/3V5gm7d4rwVArbM8yUecaUOXxFOOHptlojcwC1PLSH5YS7FbxAxs
         TXX5otxPs6GRyo4Zmz/BXt31eQfAMksjp99mr2ZGk8tjuPX/CBtWL1vV9moDp7j+ASmm
         /VRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ay/CsL1Rwnu8NMyZJXxz/Imzc1ClraqXCEx7pQzQ69cSiGGTu
	ga8KkESRAUwjiOBmvyDa2ME=
X-Google-Smtp-Source: ABdhPJyKjPCBOIvWxAWsiksa/VV1gkbOtntmosLnfPyQhiuwO8Ec2HRTFtSQUMxTppOFh2I6VxTqeQ==
X-Received: by 2002:adf:d20b:: with SMTP id j11mr7424885wrh.397.1615452141521;
        Thu, 11 Mar 2021 00:42:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1546:: with SMTP id f6ls2417126wmg.3.canary-gmail;
 Thu, 11 Mar 2021 00:42:20 -0800 (PST)
X-Received: by 2002:a7b:c418:: with SMTP id k24mr7120047wmi.169.1615452140720;
        Thu, 11 Mar 2021 00:42:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615452140; cv=none;
        d=google.com; s=arc-20160816;
        b=Bs7XH9wgHj5fIkfTVf5MPWgerYhJ3sNrC78SOSAzj79MBXWKvXMeu5MbCIr04ExOh5
         0Dq7y0GHOHIZn5M0HyCz+ItOAxH92Js4ZuCQ3hQNpr22549s4mfoAP5pVhPg6mA0eDRf
         E5tdRzc5IjiU/Gp9Mw0l/57yHbo3m2tnIsmLAy6dVm1BATZ1rojjGcyoQE157xEwXh18
         aKMwFe4l8v4/Sl2d8rmKzjPYI6rDEID4DFYuz0Oy2chwZbXARW2Aa0exCozqZrKDtXnp
         FINw5LCzxLyo5Fytt+7Mf5NSl87aCfxoDXGyNEZJ1Jq3J7UWlCOa47ZvlVJY93Wn1+1m
         BBrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=YASGYb+hhQZ5tO1JyDx7r2mDtyfXwHX0lf6yNe4ROUI=;
        b=M5Q2nAUJihljx+pikgpvGeLAaF2/V4rtBnHgLXzYZOwbvheUIkUh/CJOjfrXwjF7t0
         5h7CS7vT+ofAp93mebaqo1In0gK8HBKFKJwkY8amb8qh+YHAVVHXpJWUVxcd2HzdIqo2
         Lt0KvAj50MefFdWSzJdG9HXHDqsOJ3I2oSTUND3CeymLJFfqlzh5FtP39dRyKxbtAsA2
         2eD3+6zCeF7vKZ7AKixniqHY0kCZpOgPTOfa2ufZSwOrd77Z+VN29FRSSDG8FKoGmJpJ
         0YVrs44RuvvaYU63j6objzEd/Dmciy5jvsHhG/JpZKAtlAxHnqF8JD5qwt6oj29ZIbnQ
         3qFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.130])
        by gmr-mx.google.com with ESMTPS id b6si349337wmc.2.2021.03.11.00.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Mar 2021 00:42:20 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.130;
Received: from mail-oi1-f171.google.com ([209.85.167.171]) by
 mrelayeu.kundenserver.de (mreue009 [213.165.67.97]) with ESMTPSA (Nemesis) id
 1M42fA-1lKGtg0VZA-00021h for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021
 09:42:20 +0100
Received: by mail-oi1-f171.google.com with SMTP id u6so14994396oic.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 00:42:19 -0800 (PST)
X-Received: by 2002:a05:6808:3d9:: with SMTP id o25mr5663752oie.4.1615452138884;
 Thu, 11 Mar 2021 00:42:18 -0800 (PST)
MIME-Version: 1.0
References: <20210225080453.1314-1-alex@ghiti.fr> <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com> <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
 <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com> <236a9788-8093-9876-a024-b0ad0d672c72@ghiti.fr>
In-Reply-To: <236a9788-8093-9876-a024-b0ad0d672c72@ghiti.fr>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 11 Mar 2021 09:42:01 +0100
X-Gmail-Original-Message-ID: <CAK8P3a1+vSoEBqHPzj9S07B7h-Xuwvccpsh1pnn+1xJmS3UdbA@mail.gmail.com>
Message-ID: <CAK8P3a1+vSoEBqHPzj9S07B7h-Xuwvccpsh1pnn+1xJmS3UdbA@mail.gmail.com>
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linus Walleij <linus.walleij@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:1FX7bpbNnHtoyk8FC3Cmc34LLKoAosZMKuRmiIB56LGZr628xFZ
 j+JrSfK6iwadu0wUiMTmD6Ggc24MyL6g4gU41vKxItij77d/mn6PxC5wQIWG22AAbHr04Q3
 bBuGle+YUfqbrRR0nBtTL9dY4pzNdMl2AdXgILGP5wrR3Lw6VL5k/EgoYZiK7eUGKvmrQdQ
 j/GMhT0U7fmblk1sz2htw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:sKVqXq7Rx28=:aF4pwwwQ5/qwg51PxpYrLj
 3zfmgEIHxfPObmH0vhRNyBrB+1hwl1xH/j/c+jUL8ccmnWbWlOVobm9x7ejPInZbpJmo/n4B5
 rMuJ+SL5zc4HocSdwQt1WEqQL/nZubQraRHPnWRUN83q02Htrm2oE4M+5kslVFW53aI9DJxgd
 OdASOSNydQSWFWKNbFOnjgZpDhHXlk4tVVAwS4sINn1zOsdg5VBkOJreJiLTzwIaBAucFvKWh
 M0ZGXHwq7iD7voPSKV4IEJVGWN+znSg/WncSLT4cmvGrhmy3pE2Gir2nmV7mSkWaJEZ3Fk84s
 5nKQKDtP/sFi4TrsQThcGIe/A9GfNdiNxfwAlFCojUerZO53Xf33CzTznNOV53wMQXY5l50FA
 LON7yOFJLAh7hXvWj1ShV3PLKyE9s/oZ18QHvwhFqPsTlO01tzjmF2dRt41mkNwk8bdO/lIoe
 2ShmMTOiyoZ5A6J2wtS/HXJRWPc6P7uNrHYBroQXgQwaWTQxz9NER4UaugwGmIS68yH3fVcoH
 qXo3BfTrXkwXOCsIyNR0J7rC9rcvIQhJ42rKf0gJr9V
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.130 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, Mar 10, 2021 at 8:12 PM Alex Ghiti <alex@ghiti.fr> wrote:
> Le 3/10/21 =C3=A0 6:42 AM, Arnd Bergmann a =C3=A9crit :
> > On Thu, Feb 25, 2021 at 12:56 PM Alex Ghiti <alex@ghiti.fr> wrote:
> >>
> >> Le 2/25/21 =C3=A0 5:34 AM, David Hildenbrand a =C3=A9crit :
> >>>                    |            |                  |         |> +
> >>> ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
> >>>> +   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fix=
map
> >>>> +   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI=
 io
> >>>> +   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vme=
mmap
> >>>> +   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB |
> >>>> vmalloc/ioremap space
> >>>> +   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB |
> >>>> direct mapping of all physical memory
> >>>
> >>> ^ So you could never ever have more than 126 GB, correct?
> >>>
> >>> I assume that's nothing new.
> >>>
> >>
> >> Before this patch, the limit was 128GB, so in my sense, there is nothi=
ng
> >> new. If ever we want to increase that limit, we'll just have to lower
> >> PAGE_OFFSET, there is still some unused virtual addresses after kasan
> >> for example.
> >
> > Linus Walleij is looking into changing the arm32 code to have the kerne=
l
> > direct map inside of the vmalloc area, which would be another place
> > that you could use here. It would be nice to not have too many differen=
t
> > ways of doing this, but I'm not sure how hard it would be to rework you=
r
> > code, or if there are any downsides of doing this.
>
> This was what my previous version did: https://lkml.org/lkml/2020/6/7/28.
>
> This approach was not welcomed very well and it fixed only the problem
> of the implementation of relocatable kernel. The second issue I'm trying
> to resolve here is to support both 3 and 4 level page tables using the
> same kernel without being relocatable (which would introduce performance
> penalty). I can't do it when the kernel mapping is in the vmalloc region
> since vmalloc region relies on PAGE_OFFSET which is different on both 3
> and 4 level page table and that would then require the kernel to be
> relocatable.

Ok, I see.

I suppose it might work if you moved the direct-map to the lowest
address and the vmalloc area (incorporating the kernel mapping,
modules, pio, and fixmap at fixed addresses) to the very top of the
address space, but you probably already considered and rejected
that for other reasons.

         Arnd

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK8P3a1%2BvSoEBqHPzj9S07B7h-Xuwvccpsh1pnn%2B1xJmS3UdbA%40mail.gm=
ail.com.

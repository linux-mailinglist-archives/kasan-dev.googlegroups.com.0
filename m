Return-Path: <kasan-dev+bncBDW2JDUY5AORBP5JYHEQMGQEQU5SBCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF29C9F68F
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 16:18:25 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6417b2fae83sf7439989a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 07:18:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764775105; cv=pass;
        d=google.com; s=arc-20240605;
        b=C9AJiBzKx7F+pP/joee1xSupeL2IsKK8VKEgVw6ktaZ8VFul/SB6bLqU+9nOyb6Kjf
         EGPJHN+2kQ0eU2HIlE+9c4NRtWhwkJMSMmJ7rEGqQWa4PZXCG4ivl72HksRcCykFVz+X
         Wl/3QskU74JfNEzYF+Sb1iStPP5B7WijBEMO63C/2Ac7BiKJ/9htu5ae29N4Yq0tSwU7
         r80D5oLrQo3XekOSzg8HnvZ5ult71JXoEy18VOXDvpdLGTbzWeei5TwvgTFOYuolZHE/
         Q/RugDPJF46pCltao4p3wjIR9aWGY9tQT/hnRTSjydvIummTzWTT7m3P+hMVW9KlRN7m
         v5UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MM7oPT/GvyOYvkYYl5MbXVrUvYBXpuvtH4QmbXo/hE4=;
        fh=QOlcoDQsuMnDW0IFYMSBhuVQLXy/u00IQ7zR8xJHqLo=;
        b=gkOsOytrQNmBQ4up6kU19y6v9al5EVYvJcKKyl2nzRABWBrH+hn5IWEsD9Qzc0AU3A
         bAYhv5S3gVhKG3EaP7MYqXKTmw7lVdCpRW+NwKLq/zd8NIgiA+4ASmcnmQHS46CYj53C
         IeWyUTjuijNpfQt6f7HgZ3i7tMQDVc+GM4kQ/Yr5SX+n+wEvxr26aowzd+l4rGTBBLCb
         DOPc9fDFYmN3lS3bs5h7lReuY/D94HFsbu0WM5bpEIBkbK1XuiysHXkgbWTnl86nI0Mk
         Dg2fmMLL5K2rMRSal8us9tai/QAI6NKmMahjzuPuEnXHPVzfmAoYKdeIGC9ryCWBPOpc
         5aOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XNv8DRih;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764775105; x=1765379905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MM7oPT/GvyOYvkYYl5MbXVrUvYBXpuvtH4QmbXo/hE4=;
        b=h3cnVThC91Dco4W/XbpNCmCdiH/xN85qUD1rxEcRFmomTfFNtLyJ3lNY8Cc/KO2OsB
         ickD4ShdFWVRzA+nSqTSOWHn3XS9J9Ly64wRcm21oxy3P2bRratzEvGeW+L3VHiERNFg
         mdoqnrpA5pqloaLZiw++gj91axrFqd6tk+iL+mqf7KWCzwMK6VdliojY1kIXt+NBafaH
         y4T4QDAf2CqM1AVZomhsTCK/Won62gbEdBfZDKEO77sjTfSApUKsZQe9DgFYHd7zQSuC
         SkH8wQKFrDfO/b4EgxD2YFpSxvpOCvh6Yz9dqfSCClBkpKfUxeR/bgBN4UWzRyrZYIRs
         v+nw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764775105; x=1765379905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MM7oPT/GvyOYvkYYl5MbXVrUvYBXpuvtH4QmbXo/hE4=;
        b=O+KYSkfO2mxO3oLlVBK3971WI/lDSrN92CDFdeRayI3fCR+cKvKfrEtDZ/Y1YCukY8
         30Uqhn1azrXQ/94mlpwlZsviaC0DVJvlPxr4N8vBdW/V/NleZXCTBa5i0ATNPW1wCEgE
         hi84SCEvqTshADIYLpRMyGmBHtRuJ/iXfE0mKSK22URjdYyuVk1z/MSwzYSibsSJ/Rzm
         QT6K1VB5HeWY9usoZZpeR98JztIazMUNqRTzslOIx0iNOxI3ePxpr2FHF1OA2Rkz8WdD
         yS7A4Hfye1WAYW+bW17YQtbmF4UaOKuc9hhp5gtNTdU6S9AFx/inOUBxoT9sglKBl/kU
         /7Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764775105; x=1765379905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MM7oPT/GvyOYvkYYl5MbXVrUvYBXpuvtH4QmbXo/hE4=;
        b=Ovo1HfNxp7FOpk1FJB5Y5MJLB0ca4mmezzSKJbJeZb4cbg1H/SRiezF2SegI7xpZRl
         X8D53vl8kxM7niB9GTTnJ8pJaGKtYf498BVzFuY6gT0To+ZZRJ0TLYS2c1XDm+ekCXl1
         6XV8l/IAj0a81C7FalGYMJJl0tgz9GjN3yfji5K9e9ggFKsyKXQLDWrOhKW3l2qa4l23
         0Xlm4AJiDSSOZ/byyGsxC4fj/AnCzZ5FNOIhE9kwHZq9vNh6LqSuWXaQFfw9hUKjUUhq
         aBaB6iqoRe5urd6hskdaHXD6qdAov5VpgpNuSM+2qORp0OXOxXDVee0iRlHZZXcLsQok
         zzWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW88IUE/PeaJtF1huenyVQT1ZxFSjOeRMJ2sQghxVZaVA4jhUJ2bLez/eyUULp618ufdFCvUQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywt3Q/W7CoPBEODt9EF7Pq8ZOsSDs7kNDBLL28VWev4E0pwnrUN
	MXrAZxmcYxYzXZlU/OjnOw4y6EVbfOhHssFenFcGFKBgu9UPoEx9/AzE
X-Google-Smtp-Source: AGHT+IHBMDGEPN1QQVC5cv1oxiquzPKC6iasxtr99uA5MB+YSJoSqZxpasOnIq06aNkmoAm1UjqbGA==
X-Received: by 2002:a05:6402:40d1:b0:634:ab36:3c74 with SMTP id 4fb4d7f45d1cf-6479c495107mr1977645a12.9.1764775104442;
        Wed, 03 Dec 2025 07:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aDo6kwWFMpTzMIB7z4S/3F3JsjjVECLZeQjSd1N2xUmA=="
Received: by 2002:a50:fa8c:0:b0:641:6168:4680 with SMTP id 4fb4d7f45d1cf-64741977331ls6104866a12.0.-pod-prod-02-eu;
 Wed, 03 Dec 2025 07:18:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWRpmI6KBFRILhAZ0TXJKz3gWPV50ciJxTD9WpkhdseatALialzNiiJk7oQd3OTbvVirAZUgSKqzVI=@googlegroups.com
X-Received: by 2002:a17:907:96a6:b0:b6c:38d9:6935 with SMTP id a640c23a62f3a-b79dbe96ac2mr278387866b.24.1764775101446;
        Wed, 03 Dec 2025 07:18:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764775101; cv=none;
        d=google.com; s=arc-20240605;
        b=Fo2Q0w2k1s9MqzgcGj1TpDpPr+tf1tvHmQVDPbn36aYQPa1enULxgig6VdLtS0JAcN
         vZ8oD/ZdzeveKmNRKdUexblAHYyetBFO+0o4j80RhUika4NGpYil2/aFKU7YmsU7rAuD
         0KNsXTb4upT0MfzkyKfSuhycAtz5VXid7wgv1ftouIh9BNoGaNaisNBb7+ip4rKRrRw1
         XUGxMOviN2jV8c3jM+hUNbUgB4kd0SsacLOfN90Ugvek1kW6xeS9WBXY10cS1XYtZXoO
         eIG1qzgq079nvxccnh/w6KS+/9m+PYgDxIR6UwGknfeUC26jC5asjjdI2N+LPlheVB4u
         6dyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fHkKMPEnQ9YySxWfhJQb2dUyJQ3XmA+wblB+0uzx3ww=;
        fh=QFMyXU7dpA1gtx1fTK/eTdYHpAIdWfrSwHBPOdN94P8=;
        b=NuHLPTlqmkoaBU4T1vkStgswlHMqYqQy1DYkW2ReXi9hDXGcbSTD80g7ucjRJQqVtU
         kz7AHsDDlD6Dg4OAK/tnREjUqHLsuLcMNIQMMVv3Q1D9ALxzQ5fEqbe+bvMsED7Bk/9h
         qtGXRUR2t8aymxaX56TsMaYUD7WNscBWPY/jjJCmi7bCpnSNKNuD1NQS3W7b7KJEkpSN
         /grWBiz+MjmqFhZBhgzG2XO9TfGj4J9WwLWT7mxXiSLIKjzHxFOpcXMmQ9bSjOkVc7iR
         u5j26uHNiUmlYVOkubFPNZ6/v66KmfQlNBz/AyzA7yd3Zqkp6oNGYyGsrdRHOXvqGpPc
         rRuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XNv8DRih;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6475102acb4si292275a12.6.2025.12.03.07.18.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Dec 2025 07:18:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-42b3c5defb2so4675032f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Dec 2025 07:18:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVDIRkHq2HMtYMJ5YpqzL44mbqfgyiPpS/UdQEYILlxZ1T0xvnUDM/M9FaDCAWxVFLvH8O+M9iike0=@googlegroups.com
X-Gm-Gg: ASbGncvKbvqL+g1z4z5n8g99BJbhQMuPrWC1w8XaBneo0hDDmb1EcwxTmileCaUzQxN
	0w/aCazD8wykY9EY3QSMk4jtYvcR4lorRywfxdWoWI4tuwo95GIpBFWcaFonLOtZGmPfBr8IFFe
	gr5r/ZXkHUHcKoVr5m9hGlhpXKMU4WgkFxTc8kaYLv1Q04ZysFLLFKJLdC4weDDZhkJAJC5RuLK
	25oWm92uC/g8Qef4yWi0y9N2a+LzdUfMLhRqmZlwtitjWVADes4wjsLPBXx8SVWypHrc6wu9JbB
	qTN0mqUbD9oxuiO+i9CHAGDT5CACXn++2SWpkO3yp+os
X-Received: by 2002:a5d:64c5:0:b0:429:d6dc:ae30 with SMTP id
 ffacd0b85a97d-42f731c2b6cmr2934585f8f.46.1764775100859; Wed, 03 Dec 2025
 07:18:20 -0800 (PST)
MIME-Version: 1.0
References: <20251128185523.B995CC4CEFB@smtp.kernel.org>
In-Reply-To: <20251128185523.B995CC4CEFB@smtp.kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Dec 2025 16:18:10 +0100
X-Gm-Features: AWmQ_bkUSZqwRcjEKOHC2jF7jJ05Jhr7oMctTnmr-36-DTvY88P7pB7sfUaL8pw
Message-ID: <CA+fCnZeKm4uZuv2hhnSE0RrBvjw26eZFNXC6S+SPDMD0O1vvvA@mail.gmail.com>
Subject: Re: + mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
 added to mm-hotfixes-unstable branch
To: jiayuan.chen@linux.dev, Kees Cook <kees@kernel.org>
Cc: mm-commits@vger.kernel.org, vincenzo.frascino@arm.com, urezki@gmail.com, 
	stable@vger.kernel.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, dakr@kernel.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XNv8DRih;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
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

On Fri, Nov 28, 2025 at 7:55=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
>
> The patch titled
>      Subject: mm/kasan: fix incorrect unpoisoning in vrealloc for KASAN
> has been added to the -mm mm-hotfixes-unstable branch.  Its filename is
>      mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
>
> This patch will shortly appear at
>      https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree=
/patches/mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
>
> This patch will later appear in the mm-hotfixes-unstable branch at
>     git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
>
> Before you just go and hit "reply", please:
>    a) Consider who else should be cc'ed
>    b) Prefer to cc a suitable mailing list as well
>    c) Ideally: find the original patch on the mailing list and do a
>       reply-to-all to that, adding suitable additional cc's
>
> *** Remember to use Documentation/process/submit-checklist.rst when testi=
ng your code ***
>
> The -mm tree is included into linux-next via the mm-everything
> branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
> and is updated there every 2-3 working days
>
> ------------------------------------------------------
> From: Jiayuan Chen <jiayuan.chen@linux.dev>
> Subject: mm/kasan: fix incorrect unpoisoning in vrealloc for KASAN
> Date: Fri, 28 Nov 2025 19:15:14 +0800

Hi Jiayuan,

Please CC kasan-dev@googlegroups.com when sending KASAN patches.

>
> Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
> issues:
>
> 1. In vrealloc, we were missing the KASAN_VMALLOC_VM_ALLOC flag when
>    unpoisoning the extended region. This flag is required to correctly
>    associate the allocation with KASAN's vmalloc tracking.
>
>    Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitl=
y
>    sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it=
.
>    vrealloc must behave consistently =E2=80=94 especially when reusing ex=
isting
>    vmalloc regions =E2=80=94 to ensure KASAN can track allocations correc=
tly.
>
> 2. When vrealloc reuses an existing vmalloc region (without allocating ne=
w
>    pages), KASAN previously generated a new tag, which broke tag-based
>    memory access tracking. We now add a 'reuse_tag' parameter to
>    __kasan_unpoison_vmalloc() to preserve the original tag in such cases.

I think we actually could assign a new tag to detect accesses through
the old pointer. Just gotta retag the whole region with this tag. But
this is a separate thing; filed
https://bugzilla.kernel.org/show_bug.cgi?id=3D220829 for this.

>
> A new helper kasan_unpoison_vralloc() is introduced to handle this reuse
> scenario, ensuring consistent tag behavior during reallocation.
>
>
> Link: https://lkml.kernel.org/r/20251128111516.244497-1-jiayuan.chen@linu=
x.dev
> Link: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36 [1]
> Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() sizin=
g")
> Signed-off-by: Jiayuan Chen <jiayuan.chen@linux.dev>
> Reported-by: syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/68e243a2.050a0220.1696c6.007d.GAE@goo=
gle.com/T/
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Danilo Krummrich <dakr@kernel.org>
> Cc: Dmitriy Vyukov <dvyukov@google.com>
> Cc: Kees Cook <kees@kernel.org>
> Cc: "Uladzislau Rezki (Sony)" <urezki@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
> ---
>
>  include/linux/kasan.h |   21 +++++++++++++++++++--
>  mm/kasan/hw_tags.c    |    4 ++--
>  mm/kasan/shadow.c     |    6 ++++--
>  mm/vmalloc.c          |    4 ++--
>  4 files changed, 27 insertions(+), 8 deletions(-)
>
> --- a/include/linux/kasan.h~mm-kasan-fix-incorrect-unpoisoning-in-vreallo=
c-for-kasan
> +++ a/include/linux/kasan.h
> @@ -596,13 +596,23 @@ static inline void kasan_release_vmalloc
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                              kasan_vmalloc_flags_t flags);
> +                              kasan_vmalloc_flags_t flags, bool reuse_ta=
g);
> +
> +static __always_inline void *kasan_unpoison_vrealloc(const void *start,
> +                                                    unsigned long size,
> +                                                    kasan_vmalloc_flags_=
t flags)
> +{
> +       if (kasan_enabled())
> +               return __kasan_unpoison_vmalloc(start, size, flags, true)=
;
> +       return (void *)start;
> +}
> +
>  static __always_inline void *kasan_unpoison_vmalloc(const void *start,
>                                                 unsigned long size,
>                                                 kasan_vmalloc_flags_t fla=
gs)
>  {
>         if (kasan_enabled())
> -               return __kasan_unpoison_vmalloc(start, size, flags);
> +               return __kasan_unpoison_vmalloc(start, size, flags, false=
);
>         return (void *)start;
>  }
>
> @@ -629,6 +639,13 @@ static inline void kasan_release_vmalloc
>                                          unsigned long free_region_end,
>                                          unsigned long flags) { }
>
> +static inline void *kasan_unpoison_vrealloc(const void *start,
> +                                           unsigned long size,
> +                                           kasan_vmalloc_flags_t flags)
> +{
> +       return (void *)start;
> +}
> +
>  static inline void *kasan_unpoison_vmalloc(const void *start,
>                                            unsigned long size,
>                                            kasan_vmalloc_flags_t flags)
> --- a/mm/kasan/hw_tags.c~mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-f=
or-kasan
> +++ a/mm/kasan/hw_tags.c
> @@ -317,7 +317,7 @@ static void init_vmalloc_pages(const voi
>  }
>
>  void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                               kasan_vmalloc_flags_t flags)
> +                               kasan_vmalloc_flags_t flags, bool reuse_t=
ag)
>  {
>         u8 tag;
>         unsigned long redzone_start, redzone_size;
> @@ -361,7 +361,7 @@ void *__kasan_unpoison_vmalloc(const voi
>                 return (void *)start;
>         }
>
> -       tag =3D kasan_random_tag();
> +       tag =3D reuse_tag ? get_tag(start) : kasan_random_tag();
>         start =3D set_tag(start, tag);
>
>         /* Unpoison and initialize memory up to size. */
> --- a/mm/kasan/shadow.c~mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-fo=
r-kasan
> +++ a/mm/kasan/shadow.c
> @@ -625,7 +625,7 @@ void kasan_release_vmalloc(unsigned long
>  }
>
>  void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                              kasan_vmalloc_flags_t flags)
> +                              kasan_vmalloc_flags_t flags, bool reuse_ta=
g)

Since we already have kasan_vmalloc_flags_t, I think it makes sense to
add reuse_tag as another flag.

>  {
>         /*
>          * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
> @@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const voi
>             !(flags & KASAN_VMALLOC_PROT_NORMAL))
>                 return (void *)start;
>
> -       start =3D set_tag(start, kasan_random_tag());
> +       if (!reuse_tag)
> +               start =3D set_tag(start, kasan_random_tag());

The HW_TAGS mode should also need this fix. Please build it (the build
should be failing with your patch as is), boot it, and run the KASAN
tests. And do the same for the other modes.

Would be good to have tests for vrealloc too. Filed
https://bugzilla.kernel.org/show_bug.cgi?id=3D220830 for this.

> +
>         kasan_unpoison(start, size, false);
>         return (void *)start;
>  }
> --- a/mm/vmalloc.c~mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kas=
an
> +++ a/mm/vmalloc.c
> @@ -4175,8 +4175,8 @@ void *vrealloc_node_align_noprof(const v
>          * We already have the bytes available in the allocation; use the=
m.
>          */
>         if (size <=3D alloced_size) {
> -               kasan_unpoison_vmalloc(p + old_size, size - old_size,
> -                                      KASAN_VMALLOC_PROT_NORMAL);
> +               kasan_unpoison_vrealloc(p, size,
> +                                       KASAN_VMALLOC_PROT_NORMAL | KASAN=
_VMALLOC_VM_ALLOC);

Orthogonal to this series, but is it allowed to call vrealloc on
executable mappings? If so, we need to only set
KASAN_VMALLOC_PROT_NORMAL for non-executable mappings. And
kasan_poison_vmalloc should not be called for them as well (so we
likely need to pass a protection flag to it to avoid exposing this
logic).

Kees, I see you worked on vrealloc annotations, do you happen to know?


>                 /*
>                  * No need to zero memory here, as unused memory will hav=
e
>                  * already been zeroed at initial allocation time or duri=
ng
> _
>
> Patches currently in -mm which might be from jiayuan.chen@linux.dev are
>
> mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
> mm-vmscan-skip-increasing-kswapd_failures-when-reclaim-was-boosted.patch
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeKm4uZuv2hhnSE0RrBvjw26eZFNXC6S%2BSPDMD0O1vvvA%40mail.gmail.com.

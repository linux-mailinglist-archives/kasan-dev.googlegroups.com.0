Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH7HZ7DAMGQEUO6H54I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD27B9A0C7
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 15:35:28 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-4247d389921sf14859605ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 06:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758720927; cv=pass;
        d=google.com; s=arc-20240605;
        b=J7ODgogwKYxPiM+jbsqlI0ne1m+QIBca5DGUkaBdSUlXxLHhdP60PaCTxx1QnbYG9x
         lARvc9ubjPl939AOjh105MKN4FnLSOUC58ALUYzmRS+TXX1ayI/gc8Ykxg7uGGZTjQ5N
         /uUdp+0U7dA0QWsn731DJG8OAvJ5XpLuEIYhQtC+/R8agFi8zTW40OzqtI3eeN1A+WyV
         dVT9OsVsE+4KjDM30AL1q1P85GzWgTbjhtaUP1bAJhDkD5Pc9D4Q0Fdutf3NC/mc3MYf
         bGkm0+Te/pdyqRtaFel08NL4CXtUkz46/7ZpjG0Vy1KsLDpYV1JfNVx0z0h5sCPiNWUl
         4/UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/z1sNNgmradHfqIsDEszBmWy69va9QNEf191AzhPTd0=;
        fh=zo383qvIyuCAKuAYXXVEPu7Sj5MvrGwU/R18DjM4ufU=;
        b=lOnCwq38wUa7I1lsI0PU4v4hzY/6Ng4F5q1DrORkEjJXITjDRhaO97Y/sOwA7QYp/o
         3ij4KlLVtd2brOwweiY2GLGwq2jo+Ao1LsCbUOtHEiUnM4E1e8G962Vujhd4EMVsaL4u
         rfqtDGUDrqlBXL2fBCmXozGgTK9cNSXbu5av+eBmCF4wqDPxswUcG0tUa9X4koRdOTPR
         P7G8WQ/ILbIJPezRzTnKsDIAURpJb8Mucb8nEsLu3kml7xI49lZQBLZ1lNkGXOsuxnCU
         SWEe3s3vLINv7SUVtgyqesElE4jwMwIBWPL4LmQ0aAapb/vtabxeNhk/krNvRDSTUO4q
         BHFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VRNV2iOC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758720927; x=1759325727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/z1sNNgmradHfqIsDEszBmWy69va9QNEf191AzhPTd0=;
        b=T6EWPL5gPdGkuAI4kJ1k+xayoyIAmkFdOKUo+vUcE4gvoFR781312HMf1nBLvyV9j1
         tuABCMkfTCX0byVWg2Pd/0+LO8rB5lnPt1APRiAsoZakZde53xYzY4n8TwKtctSC/SZb
         R5I/exzmiX4uEHHavyh521GmvSNNe9uPZxbNuKPxKPOOANLn6EtgZw8FemNk3MZlPP7O
         mU0q6lDEys5lQe3g7W4qyBcHDYzpoW/UWKPcnga0MKYBI5qOvrmdP0pbwpee6bYoIafb
         /W/VvsyKO//HIZpuXFVIXLYR34c0VAuJMU7A7pE4X9ceLxdBjmzsXuDXtxbwDS7g1H2e
         ijGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758720927; x=1759325727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/z1sNNgmradHfqIsDEszBmWy69va9QNEf191AzhPTd0=;
        b=h395jDuxWRbbBT3b8nNC9dwzaMa5R0yWVxq4amjsjlJmKA3zuIxbau5Egc1tadiJDT
         GFpsRXNTQxpOnTODjuADMB2iLUYKwYphUrkLcp1PImoeH3EkdEcK/8JMghu0BTLSaDPE
         x0Zm93s2vJ2FRQD6CMyj2KHCjjNk9jTaB+QNIHlZQ+TUM7EWi7Ta+eIHiCwEHiE9OmLh
         zPipiWZ8gQ0CwCA7ITdJt824xyfcKettvrWy/ZnTk2Bkj8HIOGT9JneFIZUauX4rjyK3
         kvwGr1PdcSGxsot9DZbhyAi1Wq9cBdXZeooevUKjoT9ZXTD4AYIMifuOzSetABxSwro9
         /VHA==
X-Forwarded-Encrypted: i=2; AJvYcCVQN84tJnixDLoezM1mkZA0IrYQF59NzfQ2f3FTTX3oqBtAOcvMlgYmpmbBWOOHeiUCvk25Aw==@lfdr.de
X-Gm-Message-State: AOJu0Yw45odSsDl/kXu28nfzUvOBlJ849OIdSwftInWj5fGkH7txUZhR
	tb5np2gY5/t/BQY3jPWPYFBX3+9kkero4HKbP7StdkfhOIXvQhqjeSo4
X-Google-Smtp-Source: AGHT+IGAT6CpJCpwv0Z5nQ61QVNlR7vtXQee5ysNl22XVELnZqf2Hq2m9N8E0zBlSDStlJsx2HuDLQ==
X-Received: by 2002:a05:6e02:1609:b0:425:70ad:799e with SMTP id e9e14a558f8ab-4258d8a5eaemr37495545ab.10.1758720927345;
        Wed, 24 Sep 2025 06:35:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6VVjE8N4mBfCjCXo6hF5K96wEzJekvCpDk8J6Z+GerCQ=="
Received: by 2002:a05:6e02:4610:b0:3ee:60af:4e5c with SMTP id
 e9e14a558f8ab-4258b473647ls3853485ab.1.-pod-prod-00-us-canary; Wed, 24 Sep
 2025 06:35:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCk4v6AHNfI5M7QU5Ix8i4pwdcSkK67xnBYQXDt7lOrsk/BULCfLSpnHeywQK0CbmRG/pZB3cg7ms=@googlegroups.com
X-Received: by 2002:a05:6e02:3386:b0:424:817a:5b84 with SMTP id e9e14a558f8ab-4258d8817bcmr36244185ab.5.1758720926156;
        Wed, 24 Sep 2025 06:35:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758720926; cv=none;
        d=google.com; s=arc-20240605;
        b=TzekSi6TgYlAJkeFnMNiz+cK3wp0mig0EfPrifD7S1s+nQ9UcXh2HVani4LUQCML3f
         KyKdB4Em7Zpe3d0gf0LiSTodhuo7tk/3yYdFStPWUIATgsMIzaVTZ4KwAsGQqJLlixeE
         CYQx32MjNtlnHEMPeUOnx+M/RB4Maaj9JdQdRINkjefwkCjX1L+uxTkzJmFfuM7Yw7bE
         pJ9mV/oRa534cSmTrOvbpvutmXKf5ekInZnmpngf5vGARgxP/8NiZLutnZgKae2a3vUi
         yiieNWE3rB+MLTjdsvDIzWSN1G4P2fZO3H8RnvwmQKeE07/CI/EUmuATZBNsSOFn0yCQ
         ohig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Pe50O/RrUQLZAFgmjB7HU4D9kzr+KcVI1Eg33NkTII8=;
        fh=YnxWGMkOZ1o619yuD5lhPB199kxY9mP8LnzTd1BRKgc=;
        b=kZaaHwOHnEUFkPypQxytCSvAikCQ09fqsRoWnK7xYjHrkTmPHGmKaag9g0kNFLdK0+
         mRBvt6geTXfItj+eQHfI+fc/inV/3DizIpP89vUWeUE4zW/YrSZH9uYbtESFHN/873Hz
         m5v3lVhxJZYkjXAa98HDSzCwi+VmTo3tytPXe1XVWqyQcohfHr5/oz2LYQ+Hk0FaL5Qd
         YHsnaYHz7zrcJNDR0DWPovhgaBTh6qRXAI/gDUPm3drywxrnTyDWdQcxEVNGK+ozlJoY
         pUXJl2BV16i60NxJIGSpBIJC3Ox8n/gGQOSZ3oV7hY7oMVEhegFkHsiNB1BxKBzw9Emg
         V9XA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VRNV2iOC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-55217205bb9si471475173.7.2025.09.24.06.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 06:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b4c29d2ea05so844138a12.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 06:35:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVACTq/21HG175kPp+e0o2BTHktbGgrvu9xpnvSOinKgPrzOoQ4izEegm4s7eyszgle8GL/JIvFfK8=@googlegroups.com
X-Gm-Gg: ASbGncuDx3QtlXj69537kJX4h5nDhnnXP0F8a40dOBhouLCcpCR9zoocBgSxbaQNY3i
	o0qQQy1W05JJ60r8ucWPZh5NMdMYjtzQWtL7aolB3cLWS9uV9sih5N/XYYmqJHff2cWvhyAHani
	g1wYZKaAwOE4N+6NuWWgY/LCUaaTd7Adg9rpnDvXm48oujq54zNMt2pMwUnDe3xQi6kB+bMs8Ic
	2dVfgoqmlO4UtPJmCoSlQ0rfishRAdS+w3qdqlQowUq
X-Received: by 2002:a17:902:f64f:b0:274:823c:8642 with SMTP id
 d9443c01a7336-27ec1199cbbmr30080495ad.10.1758720925041; Wed, 24 Sep 2025
 06:35:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250924100301.1558645-1-glider@google.com> <8f0366c8-f05e-4687-817f-90a5b47922c9@web.de>
In-Reply-To: <8f0366c8-f05e-4687-817f-90a5b47922c9@web.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Sep 2025 15:34:48 +0200
X-Gm-Features: AS18NWAZTmBr2I7oYM4SLQ_DoH6Vcj7XLTdfUyItYT_CFFhymyeJQEwdn2xWFgc
Message-ID: <CANpmjNO8J_cN-mCepSsqkG+az3QKbxZvD1zSKi29oi4prW9v5g@mail.gmail.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with KMSAN
To: Markus Elfring <Markus.Elfring@web.de>
Cc: Alexander Potapenko <glider@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Mike Rapoport <rppt@kernel.org>, Vlastimil Babka <vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VRNV2iOC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 24 Sept 2025 at 15:23, Markus Elfring <Markus.Elfring@web.de> wrote=
:
>
> =E2=80=A6
> > +++ b/mm/mm_init.c
> > @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char=
 *tablename,
> =E2=80=A6
> > +unsigned long __init memblock_free_pages(struct page *page, unsigned l=
ong pfn,
> > +                                      unsigned int order)
> >  {
> =E2=80=A6
> >       if (!kmsan_memblock_free_pages(page, order)) {
> >               /* KMSAN will take care of these pages. */
> > -             return;
> > +             return 0;
> >       }
> =E2=80=A6
>
> How do you think about to omit curly brackets for this if statement?
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/D=
ocumentation/process/coding-style.rst?h=3Dv6.17-rc7#n197

No - with the /* .. */ comment there are 2 lines in this block.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNO8J_cN-mCepSsqkG%2Baz3QKbxZvD1zSKi29oi4prW9v5g%40mail.gmail.com.

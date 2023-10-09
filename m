Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEETR6UQMGQEYQO5ILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DBA07BD735
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 11:36:19 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-58d54f322c6sf1457177a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 02:36:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696844177; cv=pass;
        d=google.com; s=arc-20160816;
        b=drz3C72/UN+fUb6tbUKRwZHwf+MEMKPTDH8OAOCGIJoWSuUMx0fwujG4rGYmgjqMyJ
         qaMRD3ukFLYDxD14zg3h9JghhyZ/zE0qUdvTBtCKALyHanYy0zClQlClvRa5HmHwVIcx
         Ksb3yAcJRnxrZpfUDpTJhlDt3oOkOUCs6Kk4vj4g3mlFVLNwMJheIawYj3sE6KyA2Uq2
         B8ImGxkDWE1d9qi0PA3v50pMN4gyaolD37vlv6RuN8fh+BaulD13yXtfIEDYh2Gvtql6
         f6wuvUAlhPTXsaG5bjpjn/PdoqaIolBfGrC1pvCL5Heuv/D01w3ZKjH6FN/+b3yFXLSb
         M5Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=swbk78Wh/gB6oZmjRc90rCwjo/0NRmcTZ78270Q0WiM=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=mVUd3rfMEE/Hr0xA5u/RUG24m7dTQPjC7nxdeEDX7zh+cWWNh4eWgafHLrDYMKFSvs
         uWZqu/KVKB5KpPoDMniNZtjPciKxcvzxZOaDIAnfdTET87vpTr31vn2/p/sNNXJH03Hl
         kkTuU5GXuHELtOKBOrhRgb0oSlU1hhvWXs7LVOJZsbvEL/HPS4BTo3hgXSq5+MIhYAsf
         5oMISeCfhUPmHSbEFrPE3qY3On2M63xAjK8Gd0Lb3QNTeM8yr1DVlcVQZAsGduoyslVg
         4ejC75H3dMuLjEf5nGnTQX4RFrh/SUn+XRcdglD0wLqgVN1IUA2ub5R2We5kjYcXZ9In
         AAxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vifeYajk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696844177; x=1697448977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=swbk78Wh/gB6oZmjRc90rCwjo/0NRmcTZ78270Q0WiM=;
        b=O2JsM9vw8i0n0TYFzRMKSwN1gOa82+oEgOFLged/z2Y7UtugdRgH7/THlc9iaEb/Hq
         AnFGlpebSr4VT2TMj2ZSlhLDHY0fGTmYiUA3P67Q+j3/u0dIfcaidqLQlYQIuZr32RP2
         l/eDB81diw3n4Rzv+Qh5EKn5ypt3cN9x34fDaBpyAKzyRZESBWKl4QCDa+LdKvfmW0cM
         kGVS4iiUWha3fAz+lXnTfJLw0xeUkUwbPo/zX9+ip6pbAj7TN8qHQVTnadZE4P1Uqlwz
         tuxYZEu0/N5Qmzv8j+e5+oEkZMaZ1xje55U5zFtyJuRx9j46US+PFjD4pz5hGyUSrflM
         9FVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696844177; x=1697448977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=swbk78Wh/gB6oZmjRc90rCwjo/0NRmcTZ78270Q0WiM=;
        b=AFNNC5lmMEXdSRGm1VwTgrdm7xE8+R5mkPA/hBo473+6dsf28eFazUI9jdDKJGFToE
         LfCJ8Z2nvTXkLc2qmxA+ygW0IkQKz4QDPC0fYcO7JMcF6WeQMlEaNSL/gtz9Zd+URUdo
         XHR8eQbGvizBcgh+QwpC7IVJQRA31rB4QujSKPV2CcE5ER2hoRlsMnlSwEXmQpOpHJ31
         65uPCUVWYIf5/cGfry0IyskH4yshw0Zz1S9K98haNo9fJwkpURbEPpntchpOtF1G6NTG
         mx0osgHiavz8oCa+NJ5ckGUap99vqumLzZ1gppv47My4HQ89MAELLFmxmrFcvs8t9O55
         rjng==
X-Gm-Message-State: AOJu0YwEbC9XALjpQMN1P6vgl0O+qS9V2Brk7xGHJS+7roaT9W2I5HlO
	Mk7JpEVFl6yB1rdOn5D2B5c=
X-Google-Smtp-Source: AGHT+IGHHvnioqt5ywD75RES0/Q2u9y0om8CcoJVdFh2n+mktrZZ3LdA1kSsxTgCME8LiVpg7eohQw==
X-Received: by 2002:a05:6a21:181:b0:135:7975:f55 with SMTP id le1-20020a056a21018100b0013579750f55mr18495317pzb.47.1696844176646;
        Mon, 09 Oct 2023 02:36:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8bd6:0:b0:68c:8bcb:634f with SMTP id s22-20020aa78bd6000000b0068c8bcb634fls3158631pfd.1.-pod-prod-03-us;
 Mon, 09 Oct 2023 02:36:15 -0700 (PDT)
X-Received: by 2002:a05:6a20:2447:b0:154:3f13:1bb7 with SMTP id t7-20020a056a20244700b001543f131bb7mr16564122pzc.49.1696844175663;
        Mon, 09 Oct 2023 02:36:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696844175; cv=none;
        d=google.com; s=arc-20160816;
        b=J9nOYePLjxqn0gnlmTjaZe7vBOt0N+u++XlSIQR2GLY5mm2+CCU1/G/UiKOFShbUSt
         GzO67WX/Lr0IN//N8uFkTYgW5A9LAXkGvNeItBKoAyzvIzvwe1psL4eAZ+XNBiNJw96H
         LOFLmvPbuqm+sh2SOUPFR9OKDk9BcUUCMXv3sBStHorWK+e1ENGu/xCwUc8I0E4IYhaM
         3zhaVi1540D4GFyUsVJbfQo1jAYp73srXJftFTFfyzT1mp0lijTV+ag2AmlP/dsrvAy7
         TYL32ormNAzSJwPUn+fPMvbdXQIe6VthNnz87pbInns1Nd/ScJlm8ZCi/AGacHGtfB26
         SWDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NbPQn5PYDTYWmHehcflWH6rr2b2zYJNRYM1EffH3dP8=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=P7msS/2Qu58CE1OMUNPDqvM4JwAwiWxGNraKkEfslk3ARq1HEegDbEYvOBe5/Hdp/a
         p7DcX0DTB6zxREOg14hROnopOhYd0NEJT700SMSBXz9jgu8oJu5mO5zVXbiW+f69rObS
         7VsiojhwiOrnB8dKfMTxx0bKYEdzPXLNSdGMaQcwSXvh7O32UAM7b6RBWmO+5CGwt22x
         wLbN7W9Gd1z6COSqoQ3V/H8TOrAuzaO4+wmRMGUbCiMTe8HBaYQKGc5sJj2mEIPSYodx
         9K0/om6seq88x2P9AOAdHOYQyZoeDRaIwAKT5x8zEeuaIbWJMYGhu0Lvpg03F9Ialg+e
         7k5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vifeYajk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id u34-20020a056a0009a200b00690fb1968c4si592295pfg.2.2023.10.09.02.36.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 02:36:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-7741c5bac51so246883985a.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 02:36:15 -0700 (PDT)
X-Received: by 2002:ad4:5d6a:0:b0:65a:f5e9:8ecf with SMTP id
 fn10-20020ad45d6a000000b0065af5e98ecfmr19993574qvb.60.1696844174006; Mon, 09
 Oct 2023 02:36:14 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl@google.com>
 <CAG_fn=VspORKG5+xdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ@mail.gmail.com>
In-Reply-To: <CAG_fn=VspORKG5+xdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 11:35:38 +0200
Message-ID: <CAG_fn=VSSQuR2VLEv-t+ByG7AbfDxjeR=oPvpaPkMOq4ZoEs4A@mail.gmail.com>
Subject: Re: [PATCH v2 07/19] lib/stackdepot: rework helpers for depot_alloc_stack
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
 header.i=@google.com header.s=20230601 header.b=vifeYajk;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
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

On Mon, Oct 9, 2023 at 10:59=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Split code in depot_alloc_stack and depot_init_pool into 3 functions:
> >
> > 1. depot_keep_next_pool that keeps preallocated memory for the next poo=
l
> >    if required.
> >
> > 2. depot_update_pools that moves on to the next pool if there's no spac=
e
> >    left in the current pool, uses preallocated memory for the new curre=
nt
> >    pool if required, and calls depot_keep_next_pool otherwise.
> >
> > 3. depot_alloc_stack that calls depot_update_pools and then allocates
> >    a stack record as before.
> >
> > This makes it somewhat easier to follow the logic of depot_alloc_stack
> > and also serves as a preparation for implementing the eviction of stack
> > records from the stack depot.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
>
> > +static void depot_keep_next_pool(void **prealloc)
> >  {
> >         /*
> > -        * If the next pool is already initialized or the maximum numbe=
r of
> > +        * If the next pool is already saved or the maximum number of
> >          * pools is reached, do not use the preallocated memory.
> >          */
> >         if (!next_pool_required)
> It's not mentioned at the top of the file that next_pool_required is
> protected by pool_lock, but it is, correct?
> Can you please update the comment to reflect that?

You're adding lockdep annotations in patch 11, which are pretty
self-descriptive.
Feel free to ignore my comment above.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVSSQuR2VLEv-t%2BByG7AbfDxjeR%3DoPvpaPkMOq4ZoEs4A%40mail.=
gmail.com.

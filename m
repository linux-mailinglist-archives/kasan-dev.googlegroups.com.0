Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVNRGWQMGQEZ64UJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0987782CAC8
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 10:24:17 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-598b4d37248sf2754340eaf.1
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 01:24:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705137850; cv=pass;
        d=google.com; s=arc-20160816;
        b=xPomvTuI05iE2JenH5AGa26U9FoqlRLBXfn6LSL9lwuDJH0nw0ctXoata7ueMF4LjJ
         8te4C9rHOVbNAIR9BkhvrYpavIvoX0ra7HZiMdl96t1hRGSoO89HS0DdPGICAj2nW5eW
         Aqr3LH+DMnz1oC59aVeGifqnNjPsjSlc8kV8aqNgLKtlIhhonzZqrLp+mK8clAKjE0ib
         BBf9/5Fv73IO6nk7WwrKRuPCHJ7DWEBqe8vTBvtnSsK83nD2jg24xaVrkyvXYGSbSZ3m
         30c+sG6NZA0Ur+IrbfxJumBlpl9EsZkxAb6tA5ikVkd874sSOST0gzZxD38hhRjgerHA
         cAxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lYOqsELTXtC9YpUG/6v6nk5dxfTMZkXJCubFOfkeqK8=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=xTtySD2gypENyrsR6kS+QMUPNERMsAOWGKVlBkWzKfKTTa9ArK85ip0Vdc0t2658Ib
         2K6t/9oWnJ3dqAEtQKc1MrlzHjv5HOus9gg9pZLfupyLYSM6BDar4bq2O+NjCp4DzflP
         ZXcJOEmiWNbxWAUJCvKtV765gxcg7SMcx5a1qp71kLOv9vKDe+gnLrsULSgFlwdYuKVY
         j+14VxdsyHY4RUlpxCdqd9hmT8WignMWK6th05nY7hVRd51mQaOXzkh7309qQHULgjmz
         XzMd3zvaHmJo2sakf2bMvUxMaIlJIwhYqOmX48d4Bo04g97+sPGB1iDogYSb+xSX4y9/
         TWfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G66HbfZ4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705137850; x=1705742650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lYOqsELTXtC9YpUG/6v6nk5dxfTMZkXJCubFOfkeqK8=;
        b=N+0kLx9s+Uxlz9ZW+bANv0s/w1bVxh/U9iDEn+guM7DKJ1VHJ1i/E/3LT19L9tFbqV
         iZEgu7fgggkftaKpy9PQEe3Y/4aq/GtlelwrXf2zKewy+FJ1VwT4ojGDDKtyz4d7admR
         F9h5rRD4Zp5BiAvMvIraATF1CS2gZIfXk6hvKVtGpE73KmZ2McvkbcHgJXg/zCv2vt+Y
         Yx0gBJZ5csRE0vEjQ657uUQodYK2JCY4u3hM4lJZ0L9TVzaVlRkZezmUFqcFdDb+hfu1
         UE/sGYhTOr3iBQqsSKas/E7Rk55mRda+/gL1YY2+rUbfjaf4EmcCeEU/71jGZPqN7P2e
         IkmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705137850; x=1705742650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lYOqsELTXtC9YpUG/6v6nk5dxfTMZkXJCubFOfkeqK8=;
        b=hbouJ083BJMEBsmI3QP3jS7nFof1nAwCjXdMi6+yMaPGQCUf7EGXY4R1dnDDwuFjO3
         xyvAL3uT2itjpf46ci/QB/YlL1a3bZjL4MdFlQ39E7kI0hfPCxhIk7dplW2eECZ7r1yk
         ozUqF0Km08tptcWjGUZX30RaBYC+fwGRYv40KuZujiU3pkxWuXunF+vdPgSPQ1o7iJnN
         2E3AA4vmpktfL/69zfxXScWM1PCEqKqIbnTbn+ywnGVzf2em/r43v2q6QHPA4FDeyv0j
         hWyLinj7yuvP/h7472bsUJpaIdXr0Kv34GvGKSrix6trZv+zPvtC3rJZgcIV8mMBteNN
         +IYg==
X-Gm-Message-State: AOJu0YzrGjd2wRKe8o+33MABtQKZZV9QJreoei9pA+2i4CrYjUmKulGW
	IbK5D5WGr69dFUJVNVWjx18=
X-Google-Smtp-Source: AGHT+IG3Y188TbP97TjtcX//Pk55U1n8HK+LdR69+APWNPAKi61aUTy8N0zPB0cJW8q3Z4kol1/1mA==
X-Received: by 2002:a05:6808:20a8:b0:3bd:631e:5589 with SMTP id s40-20020a05680820a800b003bd631e5589mr2380677oiw.6.1705137850708;
        Sat, 13 Jan 2024 01:24:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:330b:b0:206:e548:e34b with SMTP id
 nf11-20020a056871330b00b00206e548e34bls455740oac.1.-pod-prod-08-us; Sat, 13
 Jan 2024 01:24:10 -0800 (PST)
X-Received: by 2002:a05:6808:1b0b:b0:3bd:6862:438b with SMTP id bx11-20020a0568081b0b00b003bd6862438bmr1339421oib.118.1705137850146;
        Sat, 13 Jan 2024 01:24:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705137850; cv=none;
        d=google.com; s=arc-20160816;
        b=uuHoswa1Ja3uumhXMtgCz9K0FMqrQILbGjuHiQ8eU6aCnYYXkVqF3WWDOkBk2qap/D
         4cENGMfEPveHskV5Ex8rc4x6l47Y6OJ/kBh5iyaluhFj8jQjb/KU+B7IHwy7e4Aa8eCh
         W9Smypi+thqdlxkHYj8XshL1VmML0y49tZ3FJxzk6tjTu8aSBo09EN/iUEGlZbhxFUk/
         yDak/zXbKSjCvaIEnz9Yi4vvrerDbHaHefEo35AUkmX3mRoV61xUlDe5rEZNThys8afv
         /40PvcS15HgZbPa/WsPorCiLllFxVX8FB76zORP/xlg7CmnjFP7lyb6+IoModGtNkQ7P
         U+gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mG8ngPgKidpc6DG7VcOonL9w+Hnp78zOGjk/tfdl9Tw=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=Tp0S7gGkadkymXNKRXtzfJuGbB832MQzpDLH6AXi6uTgUxwogC21+T2pTjN2tVwkOC
         QtcBjIMDg2roZZU/UmhbV6v8HPxFwpzSdEnFZ5kByE2fQ7ODVA5Y6S7A1CHUWIFoHwGP
         8Hsq/aJztqYbBzx2ZuZWuHsL6Sc+wqCjrJ1zDRwKXnI18+N2qxAdAnj0QvT/cpYjI15+
         +UO7cR917nLTARZ1I2tcixO9YIfEbJGlmEOePvmpNaStAvUP3aiCVoZkSVlFqJpfu34B
         Z5K/0D3QjDuHppI3Ot9M+VpcjqYFsqY+oVUQsKJsErG5DpSZadSMCImJOShr6Xw0DKSk
         WnwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G66HbfZ4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id gr9-20020a0568083a0900b003b2e5af8604si610987oib.3.2024.01.13.01.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jan 2024 01:24:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a1e0cc1a2514c-7cc970f8156so1812472241.2
        for <kasan-dev@googlegroups.com>; Sat, 13 Jan 2024 01:24:10 -0800 (PST)
X-Received: by 2002:a05:6122:4308:b0:4b6:f1e0:956 with SMTP id
 cp8-20020a056122430800b004b6f1e00956mr1346224vkb.17.1705137849491; Sat, 13
 Jan 2024 01:24:09 -0800 (PST)
MIME-Version: 1.0
References: <ZZUlgs69iTTlG8Lh@localhost.localdomain> <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo> <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com> <ZaHmQU5DouedI9kS@tassilo>
 <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com> <ZaJVqF-_fJ_O3pJK@tassilo>
In-Reply-To: <ZaJVqF-_fJ_O3pJK@tassilo>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Jan 2024 10:23:31 +0100
Message-ID: <CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym=DRa9gHLFkaNHLmVw@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Andi Kleen <ak@linux.intel.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=G66HbfZ4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as
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

On Sat, 13 Jan 2024 at 10:19, Andi Kleen <ak@linux.intel.com> wrote:
>
> On Sat, Jan 13, 2024 at 10:12:21AM +0100, Marco Elver wrote:
> > On Sat, 13 Jan 2024 at 02:24, Andi Kleen <ak@linux.intel.com> wrote:
> > >
> > > On Fri, Jan 12, 2024 at 11:15:05PM +0100, Marco Elver wrote:
> > > > +             /*
> > > > +              * Stack traces of size 0 are never saved, and we can simply use
> > > > +              * the size field as an indicator if this is a new unused stack
> > > > +              * record in the freelist.
> > > > +              */
> > > > +             stack->size = 0;
> > >
> > > I would use WRITE_ONCE here too, at least for TSan.
> >
> > This is written with the pool_lock held.
>
> ...which doesn't help because the readers don't take it?

This function is only refilling the freelist. Readers don't see it yet
because it's in none of the hash table buckets. The freelist is only
ever accessed under the lock.

Once an entry is allocated from the freelist, its size is overwritten
with something non-zero (since it then contains a stack trace). Those
updates are released into the right hash table bucket with
list_add_rcu() (which implies a release).

Am I missing something else?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym%3DDRa9gHLFkaNHLmVw%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWGQ3CTQMGQER5GPPGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E659D791D70
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:56:25 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4eff0851bf8sf25036e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853785; cv=pass;
        d=google.com; s=arc-20160816;
        b=wFBxdPihMzDVVMvc/3sH4WfzT2LlHOvBFffU5nsXefIxBL+cG1qRw2AysNPGzD3Eck
         PlRMw++qR9t2CWVGnJ4N5kUar2OJEW7MIdvte+Nis7ST7BkAomLULiLCapZz+FG/c4gR
         OLPb4cESqFKjGmc8WpRQC8Vpe3bBtXDb1uikP7zin9t8YJsR9h02ySuC+PS650XjSOqZ
         TjZklaDfGnREY84NQ21NbiU2d17+SDI9aRSPxEPU+f5WY9GEbqXRvET8qjnhyG7/7q33
         2LzH1IsI3B2T0p0jBPgRNGuzs9v3/81X9ihZ6xur/8OxYmJayiDVLJjyPtqI5+ODpNhj
         artQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uj06yjSJhq69CH9gn0A84rEVXi8klhTsgT7lwMfjX2o=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=vliSei9n/Bw8snd3+LLOQtm9m0KhLZXJI1zueJn3ijYxguWvQjwehICdlrxozU1lnf
         sxFSH2Tdck6sZCrIj79VGVFKQBvBLt2tzLJsJipnMjNdbjRJ6Afx11Ubsc9WPkxg6Eat
         dfSM8zM8zGtfNaaq3w4aIpHoxHBZpJ2jV5z25jQ96CgWzERUAlNVfakuSNkaQQEb3DJW
         7Bw+AKHuMosFK5gRhpIkcF/awUAWcR4h5Z5OiE2zT6SAQw0sqVJvE7jXMQOKlN7pEr8w
         1esbU10C0/B9SxMxzqapsmRcAYBvOy151XBjIqCgpBfPnkinASBwHdUsYVS/zrbjre55
         o1nA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="WMNKJ/uY";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853785; x=1694458585; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Uj06yjSJhq69CH9gn0A84rEVXi8klhTsgT7lwMfjX2o=;
        b=PNaTsPmiPyH6gaoNwMNgvNiqXv02mPg9qxXfPax8O81JjLt1hcVMrj9F3KlKyH9J7I
         RQ74x8vwZACbcayNKdeleUC/VtIKke713uOxr+XU4bh852mqVZwjeRFRCTkwupNHqMrX
         N3z/RF54QKq5wbGZ9Z56wJrbBeyjam93UACNp5ye8NJRh14DPF321/XCHSSIYvF0Q9/0
         dvpzuwSEqm3G3CguUlKeQke07YhYdbF+UW6WCzPyG/6XNW5q7HN2Fb6HdaFq3Eh5NLFn
         2wLpv4H93l2ACwPvKUkcEV24tC/ebP1x91TFqWbUt3fNu9dSB+R1RKxXRhWcg62Tcgtw
         Wq5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853785; x=1694458585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Uj06yjSJhq69CH9gn0A84rEVXi8klhTsgT7lwMfjX2o=;
        b=Z3cN2dJ62+Ayxpx/vh50ojzzRm9QFgQ9TUiccdH3VwmlaJnVDi4AasrKeMxhUMCPA7
         Vk2xv3JQoaWWIYruOzzOVGyHk/v80wEkHTkaeJYYK2013wwwF5w+ZOpdTJ6Z9PDsGM24
         T5czwVfHh5aLAebCcoUWjdanUBfOkx5BjcNBPEQC80dvxsUPZ44DsjXJsH5a9251gG96
         3LsfHOcL7ONzOHd06c2R9INwZ8SDN1KhPtB0NnY5pVopfQmN6YtP+H7bwCTAdafP+Woi
         EA0j3wBh1I2Jlj6e+UNLv4Kj8v4XBXTRztFlOogiod5EOcAn0Q1FOy4BVZNi0Mnq9NP9
         eYVA==
X-Gm-Message-State: AOJu0Ywu54PBR/Tfn5ffuY9qJ7xa8Y1fCmjwRV2kQg85MAznu40EPYvX
	73xBc0cVBPmnX3CbvCMxxXk=
X-Google-Smtp-Source: AGHT+IHNkxUBLAeIy+S/i0v0UnwsP/Ky7c/IQ3P4INdNDkMzMtm7zaTMTdJFnj1zt6gOvucCgGlyhw==
X-Received: by 2002:ac2:4aca:0:b0:4ff:d0c0:5d75 with SMTP id m10-20020ac24aca000000b004ffd0c05d75mr122116lfp.0.1693853784545;
        Mon, 04 Sep 2023 11:56:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:464c:0:b0:4ff:8ac4:6bb8 with SMTP id s12-20020ac2464c000000b004ff8ac46bb8ls1585393lfo.1.-pod-prod-03-eu;
 Mon, 04 Sep 2023 11:56:22 -0700 (PDT)
X-Received: by 2002:a2e:9051:0:b0:2bd:124a:23d5 with SMTP id n17-20020a2e9051000000b002bd124a23d5mr7112623ljg.11.1693853782428;
        Mon, 04 Sep 2023 11:56:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853782; cv=none;
        d=google.com; s=arc-20160816;
        b=dac3/djqK+ok9JIitjDgofDR9FDZsb92826hjPMdlLMBtFT8Sz8PvRgdwh9b+peLYn
         LS6BTgy8HB4/T/DXvUySM+SbF7aKVjq4XbrNYSo3DB2TUVG0mAoA8Il1bEqe6KjCdL5K
         eaypIx99G3znvVv7YFzz1DfJ2tyQi6/18QVmwAMmjX7CTqT0EaYkNjS/8j8npy9Dz4OT
         CxfcSMnhZOtqaV9Ay+0AnzY8dO7VmjNveERALuaSr36NEG39cY346v+77YPqThDRny58
         uxfZxg8qMbOW2MaLTBZMV/1fSUR9iT298HQf5/jTFgmHO63ImX0RRsYQQ9sbfRlyWPr6
         8Bag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G4qsjVHBpGU5sO+OGh4AT0ORwR6myZD1vH3gXnj6fKc=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=VWOmoGhmsXMnQENbyuENOj4qXtTYDQeQhV9VVhu6VW8dL5GV4XXH6OALRrDGkC8RLN
         JBcQ2djEzkoTTn1HOHnsa9nFRUjDGkdXE+iM+tXjG2Tr8/mIZ3eNPqk/C/iC11ODou6b
         bgOUcyjOzSONzDWmmivpw6n1rhUBLQ8Q8CH/5wFANC8OWs/U03LpD4UnUG0vdiVrryle
         R3g53pHLWX/h4d0EYOMuBr7lNy3AuQvpvgQI0UGmnAyowPkmR5T48m8RWKCSApGxrJMw
         j5aMAwypMTbMeufOWKRyJ86Ttb8ISWVLbvDbgiKQndTuk/6zEhENXFrAk2GztuK3pYlS
         CwlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="WMNKJ/uY";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id bx7-20020a05651c198700b002b98ad21968si576478ljb.5.2023.09.04.11.56.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:56:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-401f503b529so17532495e9.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:56:22 -0700 (PDT)
X-Received: by 2002:a05:600c:2218:b0:401:b53e:6c3b with SMTP id
 z24-20020a05600c221800b00401b53e6c3bmr7443728wml.6.1693853781573; Mon, 04 Sep
 2023 11:56:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
 <ZO8MxUqcL1dnykcl@elver.google.com> <CA+fCnZe2ZRQe+xt9A7suXrYW8Sb7WGD+oJJVWz6Co-KGYghZLw@mail.gmail.com>
In-Reply-To: <CA+fCnZe2ZRQe+xt9A7suXrYW8Sb7WGD+oJJVWz6Co-KGYghZLw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Sep 2023 20:55:42 +0200
Message-ID: <CANpmjNPYNTTfBAay4J96hm=3tb4kUBH2OwpaCfJxL7rP=aibJA@mail.gmail.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="WMNKJ/uY";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as
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

On Mon, 4 Sept 2023 at 20:46, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Wed, Aug 30, 2023 at 11:33=E2=80=AFAM Marco Elver <elver@google.com> w=
rote:
> >
> > If someone doesn't use stack_depot_evict(), and the refcount eventually
> > overflows, it'll do a WARN (per refcount_warn_saturate()).
> >
> > I think the interface needs to be different:
> >
> >         stack_depot_get(): increments refcount (could be inline if just
> >         wrapper around refcount_inc())
> >
> >         stack_depot_put(): what stack_depot_evict() currently does
> >
> > Then it's clear that if someone uses either stack_depot_get() or _put()
> > that these need to be balanced. Not using either will result in the old
> > behaviour of never evicting an entry.
>
> So you mean the exported interface needs to be different? And the
> users will need to call both stack_depot_save+stack_depot_get for
> saving? Hm, this seems odd.
>
> WDYT about adding a new flavor of stack_depot_save called
> stack_depot_save_get that would increment the refcount? And renaming
> stack_depot_evict to stack_depot_put.

If there are no other uses of stack_depot_get(), which seems likely,
just stack_depot_save_get() seems ok.

> I'm not sure though if the overflow is actually an issue. Hitting that
> would require calling stack_depot_save INT_MAX times.

With a long-running kernel it's possible.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPYNTTfBAay4J96hm%3D3tb4kUBH2OwpaCfJxL7rP%3DaibJA%40mail.gm=
ail.com.

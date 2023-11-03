Return-Path: <kasan-dev+bncBDW2JDUY5AORBDNUSWVAMGQEJVW46GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id AEF277E0A66
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Nov 2023 21:37:34 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-41cdce61dcbsf26405161cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Nov 2023 13:37:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1699043853; cv=pass;
        d=google.com; s=arc-20160816;
        b=SU4KP6fsm9tECqC5/g8Te+FwHymzOXScuZevn2CIikdZCGxaOOx22pF7kieWhobG4F
         O+vLI9zFgZDsVEXlebxUjbECv5HksfGDcPztX9k/y456oUtoBzj2GGkHmc2inAn/k+1r
         TwVwIY/QpKjAPB71hsZhpGA3wHVmIN0p6KIOIjJmGJcHIYX6vQ6DJfjRMxXnJ9/1laHp
         nsWxwKn0DvsFqzrIX8eRXExpVyQlaVnQToUER3mCWW7OFDbEKpyLZA5KsT/DutMOVrC0
         QzyJLN8t0RcKsLxsD4+3J56yUzrN+VaVSNWou0Jth2WBJUKb+f/lPbVfKtVwY4/HryJf
         pxjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=SKbrls17lEMixmqrelqZ1jsqaqzgs0rkZTRwfudttwY=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=D2DNowj1V8MugR45UqKq7y4batxbobLHS1JZ1ygZYgk2xyrYbqq6ZakZnaOcf13S0+
         ptH5gEVHhS74ojrE/WVhhpN36cg8DBQBQ6DzTJkF+jqCfWdu9i+8c1fcc2DWt/II7y6r
         5ir7ytmOL+0Rg6DD02+0M4V7oIf7QUylw3nkI/ZRPtc51sa2fpqtdNhPb+Sns5vkC19x
         SY98QlekrFcLECN0V34BVS51ut2BPqBCxd8J1GJEi1U5n7aJKEvGtOnJwjuxd4HJMab1
         X13pkSyGgC+GsCD1xHfkWLH5x/pR+7GCXHk3UNQqD0q1UdeOSLE5ZgNNXftfM3tI/bUY
         YUkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aiFSoxT8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699043853; x=1699648653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SKbrls17lEMixmqrelqZ1jsqaqzgs0rkZTRwfudttwY=;
        b=HSg5LA2LqyvsFkTZlstXaxswAA0uB5h1Bl+26PS66Ed/Lej0UCJpwIQS6OTzGXETzt
         F7fLISBwXNivfdL1gahy6N6kjT39S5YsAD/0k91zjHW37MZbh7oRJuHj198ILrWe1nYh
         C1zYS+UOc2kSFDIDXa5GJ26QvWuo4u0+h14DIqVv2VUpdf/2xZo+MOhDz0sZ6ZDXGtV0
         7n3KoJTnipGsh9BJl3cE1723lUnElqiip7qRvsWPG6f1OQe9n2NAZZmPNPItMIJyBeUi
         lXcpMnrfm1H7RqZ7snXrjnbMrFt5nE0WXO4iDGSjeDGvKot0qVKrTEoKkUlhaWO/u1N1
         Nd7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1699043853; x=1699648653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SKbrls17lEMixmqrelqZ1jsqaqzgs0rkZTRwfudttwY=;
        b=IvhrYNWgWIvEMxqgerl5yb+OpkTDWZdp9Rg/L5AvFH0u11DQ50eV4Y3KjBb4FYXQG3
         wsgN4gQogou1exNyNahHLnu4bMgNpKdTJ2eYAH8P2jHQRFaf5fJOuFz0NRhY31oYjWIG
         yhx+Y9CvmZnjgL0vGK+U9ZJvEG2rz1kqdyukEHBh9i5O/fAcG3EBiw3dFZfJA8QWLgB1
         DywUO8q1KT9IppiXzNGzd4uS0IBMFCQb/74ZIsVrtx4bu8hHSzXqWMIiwxdDaIDlvFWN
         URsyjD+F8FxqbKqtF41SYB2TL0kX7z9Zk2e9NOJfj+MfizbsFILEL6V6JD549YmTUNnr
         DMYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699043853; x=1699648653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SKbrls17lEMixmqrelqZ1jsqaqzgs0rkZTRwfudttwY=;
        b=BukzcrtOoMZAlR32s+DnBF7E3dnXj4cb0Ul76L7aJlGGxOOF+Qe7y6wyQ/rDmv3aKc
         9zI/GQBIEBQPrEsXew9hD2ymqj5KmRiUJD73k2g9X4T4gNdRhL5Ckk4MuUzR/w6gfrFh
         SIFZgGUG0zg2mMhZpz51IT6sY7WGO3nNX3NdQJInwlmu4fiRr5dvHtUqQdHJaGLzGsjW
         6JllKmQaJ2TRuo3TBFQxttGI3cEWmaHmWkNUhC3x/91PlU+EV79NkjYMl0jAkjHBEMdz
         v6Edb6mjdJJPR29Ob7jm1sOliC4i7OGJ1/nNMaADNvn3mFpnY0gZfFaoBzYQM7bP+7Qs
         uKfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzq3UbDhhMzIDYhSNrzfNv6IRD7Y56gYmHRdN+0HHSNLgQFG/hF
	Q/pBj20m7GzJdWms8P0QXqE=
X-Google-Smtp-Source: AGHT+IFDLZOBmYx1N6gG8O17EmNMGVlpWqxu53BWWreX2TvWWFWVNn8oJUX3M2Y0OrsM5CUjBONBow==
X-Received: by 2002:ad4:5ba4:0:b0:66d:a301:e512 with SMTP id 4-20020ad45ba4000000b0066da301e512mr26076244qvq.27.1699043853263;
        Fri, 03 Nov 2023 13:37:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:108b:b0:670:afd5:657f with SMTP id
 o11-20020a056214108b00b00670afd5657fls357849qvr.0.-pod-prod-07-us; Fri, 03
 Nov 2023 13:37:32 -0700 (PDT)
X-Received: by 2002:a05:6214:404:b0:66d:130c:bb9d with SMTP id z4-20020a056214040400b0066d130cbb9dmr29642636qvx.13.1699043852429;
        Fri, 03 Nov 2023 13:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1699043852; cv=none;
        d=google.com; s=arc-20160816;
        b=MXTq0S0wh+J66hufc49wGbxVdPGq+XQwDGjJbzJXC36s4DeEiynGmpTYP2zy+Icn1u
         CfilMIjtOfNLmb6ToSTWZRllfCnOvjmd9C0DbpNUyNm4OF3JRACtrAqFscDuy4tm0knS
         CdF46yDBHRQoyqKdVFC0n715NbsaRy2mbNTalwrzhY7yq9KyqjRRDJYXHMsUQjaQLp2G
         YOgQj3d8PwEx33p8OO7QnThqzai0AZrf/5PNawqaswIYAiEf7SYRLmEh0CapCgMS2hkk
         GCgEDK9sB82Ywq7+KavUqBjYvvrhNsGVXVDAklRM3jG8k4NXdCCpZ6gPVNRM2seVYm2w
         Ix4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qzjEyUYLHZleIDTS6RTLkKtGAiXZ2AH99d7iJ1I6V2Q=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=kG9aute/MXiKB7orLppwMg1OQmOF/ME5Lr23J0NGu0UNfSATc58/qqybg72qkvL5GH
         yOt/jW+8ges4auDUlUiYHYgIepKDpNmdc9JwBSB+zcgnuVDw16nhQAx+fFFyjDM0Safg
         SEpS/Q0po/IhwAcnrUwjThpXLQaa6Vo/GJ8pQKsDJd5+564/S6Ki25OjvdsIftZ/+b7B
         ZC/qtnTVbZm4+/qw/bgVtpDN4TAeAdLagvFhpLOGU4TPe6RnCPCjkd/BGMAn74wVO//l
         N2u/8LueyubAsjrd6HC1Y1jYFLDKCINtARHEuKGuHAs+okmHJwpfdRqqdfeExSBBRC6X
         +QAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aiFSoxT8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id f5-20020a0cf7c5000000b0065afd3576a7si180223qvo.3.2023.11.03.13.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Nov 2023 13:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-280cc5f3fdcso2993425a91.1
        for <kasan-dev@googlegroups.com>; Fri, 03 Nov 2023 13:37:32 -0700 (PDT)
X-Received: by 2002:a17:90b:f92:b0:280:bb7:9fa0 with SMTP id
 ft18-20020a17090b0f9200b002800bb79fa0mr18749245pjb.43.1699043851766; Fri, 03
 Nov 2023 13:37:31 -0700 (PDT)
MIME-Version: 1.0
References: <e237a31ef7ca6213c46f87e4609bd7d3eb48fedf.1698351974.git.andreyknvl@google.com>
 <CANpmjNOrKpkV3aEPsTZSuL6Nb7R5NyiBh84xkbxM-802nzDtBg@mail.gmail.com>
In-Reply-To: <CANpmjNOrKpkV3aEPsTZSuL6Nb7R5NyiBh84xkbxM-802nzDtBg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 3 Nov 2023 21:37:20 +0100
Message-ID: <CA+fCnZeBzs+PQP8SQGorSsOe2e_NzDnqP_KksjfLwkUu+aVTZQ@mail.gmail.com>
Subject: Re: [PATCH 1/1] lib/stackdepot: print disabled message only if truly disabled
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aiFSoxT8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Oct 27, 2023 at 2:54=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> stack_bucket_number_order seems like a redundant variable, that should
> at least be __ro_after_init. All code that does "if
> (stack_bucket_number_order) ..." could just do "if (kasan_enabled())
> ..." and use STACK_BUCKET_NUMBER_ORDER_MAX constant directly instead.
>
> The code here could be simplified if it was removed. No idea why it
> was introduced in the first place. I think f9987921cb541 introduced it
> and there it said "complemented with a boot-time kernel parameter",
> but that never happened.
>
> So I'd be in favor of removing that variable, which will also simplify
> this code.

On the first thought, this seems reasonable with the current code.

On the second though, I think I will soon add a command-line parameter
to allow controlling how much memory is used for the stack depot hash
table.

I propose we keep the code as is for now, but I've taken a note to
either drop this variable or mark it as __ro_after_init when
implementing memory bounding controls for stack depot.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeBzs%2BPQP8SQGorSsOe2e_NzDnqP_KksjfLwkUu%2BaVTZQ%40mail.=
gmail.com.

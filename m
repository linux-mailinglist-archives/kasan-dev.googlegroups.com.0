Return-Path: <kasan-dev+bncBCT4VV5O2QKBBXGSY3EQMGQET7HXM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10210CA4437
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:31:42 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-647a3af31fbsf1252646a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:31:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862301; cv=pass;
        d=google.com; s=arc-20240605;
        b=EEyRIwnDhr8B9YPmpYtp4mxBcwgPSg1Bb1LLrSj5O1fzAxU8dAlBD8qgAHyFPmR8BC
         wb79Z65icaen7aMuMaN8NYbiHdrnJMzhGvUljO0efZ5Km1hABD/6tfTHrtQ5idTyFckR
         9rezuv3WKjKrVhNjiI++fBAhCNSLPP0OwGwZIrlNphM4ayFCkE6ue36JTVXo+hXBy4zA
         ontSQOEI7P3OXKPHfzuzAJdqTkcVnWLsBrUlJI5GDhBFExhTw9xr9myuDVdzggMFdLcp
         NHcqm1cmeDq35a6vAmtE989aKzzddATmh1yr5zv5syNHsulITcucmKc++TiPVlkAorLm
         yepQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=s1Q/51tammLz73hgiDfVnCJcKrQZnB+4Z8mHX+4va7M=;
        fh=c9Rpy3H5nmQK0dKbT3hkdCXiAiz+/pNm0O1Rr5J2eDg=;
        b=bvCaJAu72u2bza4blNcy2uzXQc7nCqWvo2bXz+pn3mY0GCbrOR+D+0SNLqi8sqe06W
         Jt1v6iQYTxsPkz75rc2g47u78JR5Xcsv7I/OlSW5z5WoB22SVhtbHFOOLUAnhFjDRoS2
         BK/GtVsCF++VRk9gXMXKa3RixjxcecWkBh6oEDh98vdFkOiugAbNNe6ETx9ZpKUknTrp
         VuRW21Ft/laMCptDwjA+XY0LkD0RtbujoFtyIGAgc1UNACkVfyQo09s0Zi9K4E5GWj58
         qj4zUXB254CH9fBTFnAfd9ixt08P1OT5GGuShdOFdW7sQnJCqL9RwqXLG3COqQtELmRy
         rrzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TIyP4IPV;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862301; x=1765467101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=s1Q/51tammLz73hgiDfVnCJcKrQZnB+4Z8mHX+4va7M=;
        b=jTEG/aeLt7Q4GpkoNlFT9AxT5v+F37Zoesj1jAj4wV7hKioX7/WeRK1aJn451zN8MZ
         5jrzjZ7uN5y5+v94bsy4Mm7vkOVwtGc1yxSMf7vNVYyOU4WfYAsGmh0J3i7ZsW3MDzbr
         WVp6EfCSNkkp+eYjcZ+cCZ/RjZC65nqtAKX25v+kKNzG9UtjraGaO2I1Fb+DT/bwIuob
         5rMTawvD8HTMfhhPeOeM5PRfJJsdQFd3Z3ZUcqdFAvauisdtSIJl2gpwnw+HxCM/Uxzi
         Mc7N10oI3yGnLZ5nLrtFBJ5tFf9D6m2iY2hBSkLega6k4LytaJjq/4Enpl1UhPyNISTH
         Bosg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764862301; x=1765467101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s1Q/51tammLz73hgiDfVnCJcKrQZnB+4Z8mHX+4va7M=;
        b=X49lSvCl6A8jG1ldGIvpm4EHsWlxiyG8kSfZFPT1yxsluxVuUN5zpBZ+kzZAKcYhcO
         QdtCCu4eKGOYOX5PB8a1xJmA1Ae6CsbsPmd7Ew7NeINM3yri7vhhbYcC1maGTo51N17i
         V2XMedi7IJ6ZQ+O/ElaYrpSeGXcpDFSZ0DAh5chzJuvlDPIPFKhRAXTPFw3uGzkaz/EO
         a+Lh6BFlh8wnMv2f508UWc16lR3BNxQnq4SD1xqsKHtDdn9DVo+qWmAwU9rcYjh85u2W
         Bwy6LLQimwlxmEt2IDUsV++Wd0XmpWb5WckRa0cI9u6mltr+Rq8PLr+rjLLESpXGuW+T
         FNGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862301; x=1765467101;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s1Q/51tammLz73hgiDfVnCJcKrQZnB+4Z8mHX+4va7M=;
        b=wSH725JeiJqcci0pYpioLyqnQhZ23XBUnEw5J/6UTvLhEdoaTc2R530yFBdDSbpWX1
         TY3qf2K9YI0V6d7QdQFHOS/wkDiUr+pmZyFEi0xY3Aqi4u02kfkdHn2C7vGrbA6qdryc
         4Gfde1dGYciEjS1fP4YRPXcgYVs29xUWhs2lmum96kA1stmcUKmMTTFqSykkAn2wS9PQ
         GeqXHqs2Zf0WkvkGftfo1J1p4WgYAlhwCWHGqh1N34/oAaFe5EfDLJSv7OG3riadcsqq
         wCB8AKfnWJIMizxd+X9lPs8vzwL0anD3dwDd8rnbLR9yvDCmypqd2WQJJWVVoDlZr1cp
         3BNg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZK3VRKSz5CgeCmXlpwFcpYpf5CecsNAx/gCR6HuVqs5r7ZcW8/zv9hgN+CdUr8WhCXfd4nA==@lfdr.de
X-Gm-Message-State: AOJu0YxmN2b9Z+AE+CG/Awbtkate7bEoE2qfZz2L7+FB22GdCYnvSWfi
	Z+8+eqpo+6j48EJ+mrTOpl2BF0qVpdppFgo9W4JpJXCVqZ1BCHoDBvDI
X-Google-Smtp-Source: AGHT+IHu6zQEetj2Z1Z1wxWmFmbgLbwVNScD09DnUL9dA3Vg0o1qcNh/ElSi3H4nkvjZ1M9Th7juHw==
X-Received: by 2002:a05:6402:51d2:b0:640:a26e:3d76 with SMTP id 4fb4d7f45d1cf-6479c4ad440mr5198625a12.27.1764862301200;
        Thu, 04 Dec 2025 07:31:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a9kx48+fE3q9qd/Y0sYSX0l483OnkVDegsUFflPUnfZw=="
Received: by 2002:a50:ee07:0:b0:647:9380:724 with SMTP id 4fb4d7f45d1cf-647ad2f5589ls910273a12.0.-pod-prod-05-eu;
 Thu, 04 Dec 2025 07:31:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYMoelsSNm3xfp02rNa6Z7K8E92efkR4yRLudXN2zzHiVDyXCYgsK/dMDY0bhdFVCVCOOMOIYsRKg=@googlegroups.com
X-Received: by 2002:a17:907:3d87:b0:b76:45bf:ce38 with SMTP id a640c23a62f3a-b79dbea4522mr583051466b.19.1764862298171;
        Thu, 04 Dec 2025 07:31:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862298; cv=none;
        d=google.com; s=arc-20240605;
        b=CT4odmwMpHs3QVfU8UFB+U9vlpudFhYe5uerOxSjif3M10b33DW0suQwqOL3BmriPB
         eJuWyhdF/9ku4FoeacQeIngSJR+Jy9ssGAAPwmF0g6sou7Bq/10yR4gUdEQRBNoEggKj
         dy9XoHxCEYYhXhlLyC2qwUHNjVLTOld/sLj8BavUbwXAuIaRjCd8ZO10WhqXxV4Q34vd
         s+XAPz4un0YGDqRG83M1BABnBdV2LslkkJLuYOnwr+oJyyLUqAy62KD2+JxYkZgvxOA8
         taZ29RmbIvZUfthiM0TtqYJsVW/vOXZvDBJN1zfDlZiXpPP6o8yXmGi9PjLN53nY+2iQ
         UIVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=POTlX6ISPXXEWpjlfGwt41tj3VGCl5g++BEcuBlKXmw=;
        fh=RBC3nARJdh6OzE1l6Nd7v5elk/A7KZNMusZ1Jn8DAhg=;
        b=QXRd+NmrSLo4ibuzg+aEEyCP28qFY8No16x41+Nih33C3Fgfzi5CJHpQB1Ev66I6E6
         nRZHwGnNxULT9Alilbim3Kf5ItV4vzAL9YqMuN9tDWoU29PEk1qSze/Jr6MImBjEAiRI
         r7t7KwKtiDc2X+K4Chx/E94q0Hpfg+/EONe6fW4LoSEBPb31cRtqNXqZeZw9JjTjVWvb
         9PtSaGz43xICFy2prn35SwNBO5Melhzsh5OlaUZRPb1OM+X7tPvqCBtjJE4nIjrfvORz
         NT1qW1ptOnytDZXv8EaqMupRPNkS1wkx67qS8qxbVrKJRktCtNYSG/vOzEkEeLh0Piu7
         LrRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TIyP4IPV;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62e.google.com (mail-ej1-x62e.google.com. [2a00:1450:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b79fa7eb3fbsi2360466b.0.2025.12.04.07.31.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:31:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) client-ip=2a00:1450:4864:20::62e;
Received: by mail-ej1-x62e.google.com with SMTP id a640c23a62f3a-b79d0a0537bso125753266b.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:31:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtxCO8ktoBikFEA2JDuKfzWi/Od+I9yij9h9P1cugP5SlyFtIKqCfqPDrwtNiOUO6byGm7yycfEQ4=@googlegroups.com
X-Gm-Gg: ASbGncsFoZF8j8GLL+AabjP2IrcuGih0JKmoBaif87llL9qbbwiPB84NxVcImh8tEs9
	BY9Ow/BlZ+qj8B45sthKpaFD5eO/XxIV1YhmwwNw3L6iSodF8sZo5A9WdR+MSRohwK10DW8rHV4
	IszSJf5AQ7jG3otomcoG/WBLwj3FsZQ7BdGe4B781/HuKpuTSA3KdegpSpBOb4+o0Lq/sxnyO9j
	avZFb/HNB0276L26uRRqOQz6vJdgzCfKDACb1uchPvbmuUUdslqaNAB/qeApfbTZTJUvYoVx9iQ
	j3/L80LBqLEIfcQK7aFHMayM7+lHszezt5N6P4BqyPe2Lq0+A8Nb0q5sjUGsBbZ0NukDmnc=
X-Received: by 2002:a17:906:d54d:b0:b74:9833:306c with SMTP id
 a640c23a62f3a-b79dc777cb2mr731791366b.47.1764862297473; Thu, 04 Dec 2025
 07:31:37 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-2-ethan.w.s.graham@gmail.com> <CA+fCnZcvuXR3R-mG1EfztGx5Qvs1U92kuyYEypRJ4tnF=oG04A@mail.gmail.com>
In-Reply-To: <CA+fCnZcvuXR3R-mG1EfztGx5Qvs1U92kuyYEypRJ4tnF=oG04A@mail.gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 4 Dec 2025 17:31:01 +0200
X-Gm-Features: AWmQ_bkuYb6owVWFxIAiek-YuFB5R-dRF0smhrRgpbJbH_xsE9jvhcY-L55PbKY
Message-ID: <CAHp75VeARk=pm_R10K1bEoCuV+32HgV3ZvQCNVs4D2_2W3B_Tw@mail.gmail.com>
Subject: Re: [PATCH 01/10] mm/kasan: implement kasan_poison_range
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, shuah@kernel.org, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TIyP4IPV;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Dec 4, 2025 at 5:17=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
> On Thu, Dec 4, 2025 at 3:13=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gma=
il.com> wrote:

> > Introduce a new helper function, kasan_poison_range(), to encapsulate
> > the logic for poisoning an arbitrary memory range of a given size, and
> > expose it publically in <include/linux/kasan.h>.

publicly

> > This is a preparatory change for the upcoming KFuzzTest patches, which
> > requires the ability to poison the inter-region padding in its input
> > buffers.
> >
> > No functional change to any other subsystem is intended by this commit.

...

> > +/**
> > + * kasan_poison_range - poison the memory range [@addr, @addr + @size)
> > + *
> > + * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE,=
 defined
> > + * in <mm/kasan/kasan.h>: if @start is unaligned, the initial partial =
granule
> > + * at the beginning of the range is only poisoned if CONFIG_KASAN_GENE=
RIC=3Dy.
>
> You can also mention that @addr + @size must be aligned.
>
> > + */
> > +int kasan_poison_range(const void *addr, size_t size);

And also run a kernel-doc with all warnings enabled and fix the
descriptions respectively.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VeARk%3Dpm_R10K1bEoCuV%2B32HgV3ZvQCNVs4D2_2W3B_Tw%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNFH4XCQMGQEHN2KWPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E4525B43651
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 10:54:13 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3ecbbe7dc63sf9690395ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 01:54:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756976052; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZYSScLrcgK4uuFjcVWvqO0i/A3Qg+uWZSWEJbbyNVKgQ3GJNnEp38X88Zll06xTuF9
         Mr/yZuXamnQs0FeA9KSCE8viQLdVh2BpH7qMdswBg2pi9ojGATCdKHDNZLmu/dn+1YYM
         K6s9NeTJ9WmtFzCu50nXX6GQmok77sJPpAzaQw5aU2xY/sZy7HMVa/E0mQCzDBbNGlWT
         wIiXQcYZh9ULO4BkWKXf9HaIpaBwbGQV1QkhkCRB5nV+gzFkXyDUqHLQg+AZ0tDQ/lRu
         WKLsupbbTuV0ry9MqxFCVlpaaJwJxwA4IUomua3daoMzl+9XXkTFbY+jv9ZJUTEyDBa9
         K5tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XOG2xVzhvvxO/w30TNM6RUI0h0QWOlaOWM8pAK+6mvw=;
        fh=BcxaMOy82QPj5ejw/tJQS2uEH0MqAckDY6IvYmVZD0Y=;
        b=FDahm0Wel8GotaZ8Lj4DrrSeTnJRKZ0k1VCKp9mSPFaisgGT7D2t/xKUwludYaaPWk
         OPXu3MTguQfDK1MTT+WK7F5amfruCGBjlfxrmTjOD21Wi8Gjv0AphnSBUO8BwGMYrmFa
         8M4mAdqMyCa1gE93IWqlG8z7dR0fEbkb0poZ92XsCtsh2A/f7WE2g89QGehL6VXYYrHd
         hX5Ar6T71sHYFwShE/XiNdQjTjYHYZg3ezmmXsua0mUwO/rfqu93qWj9if0b7FQvwkwc
         bVMbJXKOFuPIopr2k0NMI2iXOsLBaN2BNxd2su8vU9tECTYNsglZyusFIpBheoHwOkGN
         Ypig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cSZRGba;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756976052; x=1757580852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XOG2xVzhvvxO/w30TNM6RUI0h0QWOlaOWM8pAK+6mvw=;
        b=bgkK743pupavC0+5rqgIqZQuIl2BnNXURJ+XGy6FnPeyeAlT+89pRY45RPaceNMx9d
         LW/F8ecgzcWihbVeqT6nnD9fwpayRz44yfxG+lieRP/x82b7FscWOd3Uyu5wf6fwr19s
         b+hiNHAnZuphgTEHBiK4/KxfPsJECYg0oZYOYykIAuQUT5WmYf4/5CorCzOJyMviS1ZX
         JaG166RaMjHDl107ltPVGD1Hj66xImCxsYNRS1YsN6MnhOUvxcNkIefSunIl7H/pILHq
         4Iw5uLfOcJfbvHoCgw3Co+GSuDONS3GDP4E+1DKGiM6SrBJWmTyBkZ6W1u/AFI4KWVEX
         T0OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756976052; x=1757580852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XOG2xVzhvvxO/w30TNM6RUI0h0QWOlaOWM8pAK+6mvw=;
        b=FfSq5MnCVxbzp/K8kNw5p0o9j4uleTNORitriRvoEVBqJBVrmE3YcEQ+3XGEfuKeDo
         mCoODN9rDCwlJ28ypPwYW6spLj4Uabouj7eJzil1PhIR5Bt04HrMu9rb9tdigffx8kqV
         1cc13sietAVZdxCHYWkaNWfljUCHD1HT5GL01WqLMWaU5dHVmzwHFmtBY1mp18y76+Gt
         X6DB6udQ3myBR7a8lZABzLbXjOSDsoKYoyZ8hHq6nzBntpPzvnxVuOsEM0f9M40k0bxp
         Bqi32MlucxXLQ1CjQAfh6Z0f7x4LF9uIww7U0ILiyOOaaqatBtM2ASiJ1gn+5Ccy4lgX
         5MlQ==
X-Forwarded-Encrypted: i=2; AJvYcCUyC8zx+ZwPJGDyUzaRjL5KKKRszoxeffaPjfn7UkfahFsDr6FW5TbesGNhiyGguTTzM6Fapg==@lfdr.de
X-Gm-Message-State: AOJu0Yxq/IFYi0WBolwyhIhLnpvQwbJ64mMe5zVaT/p5BWeOzLdS+EVI
	npv9o1dCV0f2/b6ddvlQloMgfNa5uVMIaJQunSQE18HM5ZI/ap/wBBkk
X-Google-Smtp-Source: AGHT+IHeq0D10h7lnS3RDY1a55BE5XiHSbC2lsQzEl0FbxoLo+hzBjfyPjguyUbH4zmxHXoh2FM+BQ==
X-Received: by 2002:a05:6e02:1d99:b0:3f6:5f7f:5050 with SMTP id e9e14a558f8ab-3f65f7f506dmr85636865ab.15.1756976052348;
        Thu, 04 Sep 2025 01:54:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcU3qPi4Oaf00coInlxzXDcWCR8a5+nZsj4wFWMjyPbbw==
Received: by 2002:a05:6e02:198d:b0:3f1:219f:f51e with SMTP id
 e9e14a558f8ab-3f136fb421bls52524805ab.0.-pod-prod-07-us; Thu, 04 Sep 2025
 01:54:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+yIeWkbOsYxiHMEe8Say8tM1tLc2+npB9LRHE04koeyXm3RvM1NgVLkAGjQYfG8FVvRCEySIZz/8=@googlegroups.com
X-Received: by 2002:a05:6e02:168f:b0:3eb:9359:d88e with SMTP id e9e14a558f8ab-3f401fcf90cmr256511295ab.21.1756976051481;
        Thu, 04 Sep 2025 01:54:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756976051; cv=none;
        d=google.com; s=arc-20240605;
        b=a70gPSF3RcKfkZM2FLxjljywNCTDFIR0LzXrIk6nAtwaml1vBADX+79un3d5MgUPpa
         c6/S1j/Bao+7c9l3dRoUusKHBBfGRMzL3/0KihiAsXpBE5fCYMgodLvilGSoO0Q51Kzi
         vnBoHMnjCHnIZMLUgt29/jxHZs7Piwr8uK+4/awQjueOonVjXRAg16ObW2EYPyrIihRg
         xYSkrTsozuSQADIWvhkJ4+TcPHLiNDB776VWAKLYzS9mb6DdFLwQ1pOBczxSGCWcQY+O
         IkF2zq7CuHDhj4/RxXVSjOXv+cLZV2DgTmhAu8LLz+2ML9CUvYuyPLXq0Y5ctjXmamca
         20ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9VicjXT4pdNAgXdUSH6UsBDRLh+o/JYSTnI74S8PEYQ=;
        fh=kj1tGHi4jjA/W6gTSWzpLFfNNg6Wv69v1ARTw0hDCCQ=;
        b=O5tzHsA4lbQnyNv+VNe7yoKBvPWybKQVP1P+8UJG0V2RiGYciqh/ABZnDYO3DRep0/
         TqXznhAdfTBkj2M8eerFlxc5l+jaUJySPOLr6EdqZh31mAAVqxSGyt5xjZHF4Y2aSOn5
         zbY3LtcJgL0C2KQzH7U+NUbLD1XIL/DLBT0U9Ve9bdR1RYm4/qicHP8cVLF3OtegORU3
         QuhVPz+EjmbUGzVJ2QPyGPtUwTzfhhDJ9DC1G1yX1o+8ytd8joKBcQV1eSOiwx6wwfe7
         /2xdNdB/acz1LTIQFz7k2WVjEpk3e0IC8TejAVabOXnb3BWZ5G+bPaKUyw9sFMx07EV0
         HEaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cSZRGba;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8f054ff5si654243173.1.2025.09.04.01.54.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 01:54:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-72816012c5cso6172946d6.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Sep 2025 01:54:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcJGkZ0DbHwvUTcLFxeTkEygLUDUnFji37z2Q82dGPjOn2ol8PNVYr1+SixwJbt2sSaJoCzdR4yT0=@googlegroups.com
X-Gm-Gg: ASbGncta4xQj68PZ7GeCAtBTrGKHfLjwfzzoGdTpokNNTexoC7apAtwQchreurjVqE+
	fru64p7F3P7oSK2QbsK1PPbXST579mHS3FmwFZKmmK+1Q1YUZbYi/Di537fFKKXI+up72ejYfD5
	dPepq5VY3i+AF3M4X04ajI9y1GWOZHlS9FNviI0tSVR3xrrD+FiTroZRgS7yc57N86ngjCwJrhi
	4ApXOgcVqFh1yQtyBSivTc+TSyOGz3tBIyHzPglvuY=
X-Received: by 2002:a05:6214:19eb:b0:723:255a:9168 with SMTP id
 6a1803df08f44-7232569d525mr82498246d6.4.1756976050489; Thu, 04 Sep 2025
 01:54:10 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-6-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-6-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Sep 2025 10:53:32 +0200
X-Gm-Features: Ac12FXzGXGcfd1LWU7AL2P0uHHVI9Cjfbatglasugt3XjpaIrqiLrO1UVJEntQs
Message-ID: <CAG_fn=VBbSqb07-pbbEw7F=SP5_t74Re7ki0+ZS=mBm2S9BehA@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 5/7] kfuzztest: add ReST documentation
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4cSZRGba;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 1, 2025 at 6:43=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add Documentation/dev-tools/kfuzztest.rst and reference it in the
> dev-tools index.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

Some nits below.

> +Macros ``FUZZ_TEST``, `KFUZZTEST_EXPECT_*`` and ``KFUZZTEST_ANNOTATE_*``=
 embed

Nit: missing second backtick before KFUZZTEST_EXPECT_


> +Input Format
> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +
> +KFuzzTest targets receive their inputs from userspace via a write to a d=
edicated
> +debugfs ``/sys/kernel/debug/kfuzztest/<test-name>/input``.

Nit: "debugfs file"?

> +- Padding and Poisoning: The space between the end of one region's data =
and the
> +  beginning of the next must be sufficient for padding. In KASAN builds,
> +  KFuzzTest poisons this unused padding, allowing for precise detection =
of
> +  out-of-bounds memory accesses between adjacent buffers. This padding s=
hould
> +  be at least ``KFUZZTEST_POISON_SIZE`` bytes as defined in
> +  `include/linux/kfuzztest.h``.

Nit: missing leading backtick.

> +
> +KFuzzTest Bridge Tool
> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +
> +The kfuzztest-bridge program is a userspace utility that encodes a rando=
m byte

Nit: do we need backticks around kfuzztest-bridge?

> +This tool is intended to be simple, both in usage and implementation. It=
s
> +structure and DSL are sufficient for simpler use-cases. For more advance=
d
> +coverage-guided fuzzing it is recommended to use syzkaller which impleme=
nts
> +deeper support for KFuzzTest targets.

Nit: please add a link to syzkaller.

> +
> +The textual format is a human-readable representation of the region-base=
d binary
> +format used by KFuzzTest. It is described by the following grammar:
> +
> +.. code-block:: text
> +
> +       schema     ::=3D region ( ";" region )* [";"]
> +       region     ::=3D identifier "{" type+ "}"

Don't types need to be separated with spaces?

> +       type       ::=3D primitive | pointer | array | length | string
> +       primitive  ::=3D "u8" | "u16" | "u32" | "u64"
> +       pointer    ::=3D "ptr" "[" identifier "]"
> +       array      ::=3D "arr" "[" primitive "," integer "]"
> +       length     ::=3D "len" "[" identifier "," primitive "]"
> +       string     ::=3D "str" "[" integer "]"
> +       identifier ::=3D [a-zA-Z_][a-zA-Z1-9_]*
> +       integer    ::=3D [0-9]+
> +
> +Pointers must reference a named region. To fuzz a raw buffer, the buffer=
 must be

Maybe insert a paragraph break between these two sentences?

> +.. code-block:: text
> +
> +       my_struct { ptr[buf] len[buf, u64] }; buf { arr[u8, n] };
> +
> +Where ``n`` is some integer value defining the size of the byte array in=
side of

s/Where/, where/ ?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVBbSqb07-pbbEw7F%3DSP5_t74Re7ki0%2BZS%3DmBm2S9BehA%40mail.gmail.com=
.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZXJUTDAMGQEYBPO7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C0F7B592CC
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:59:04 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-25d7c72e163sf80777655ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758016743; cv=pass;
        d=google.com; s=arc-20240605;
        b=UfY72BDHX8puji3l+u/wq7xFohMUjJw0iGamQ3Yd70ExviZQ8r49TpiwcuY6bV0pVM
         +uWGzShZfihb328Spd5yzyfTHgTXjCnWoeVR8nHKk/GtR3tKZhOMqBghFxNFVKXaikH3
         Rf7pFMEG2aPasphemL5GAoebX7KN6IZSUcB8qDYjzwLxd7ZrYGL4p/CsTDhI02FK4mRa
         bB4rqQxhW5OvnX/k5r5U4fYUgezpwTWvpCrj0j7qu0GSNseTtLvBE1/Isqo/YFL7TamK
         ry+YptsZgYuEWkzjI9E5rlleyit5XafR5dztBks3X4Yiq5gKUAeN1qL4k3mDIXgulrk4
         LPXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Bz7RmzYYZCEyHsaMv4gyG1MS8W6aaY/cjQ7jBlufPVE=;
        fh=3XZcuSxcRKhiEjLTIv4U8MKzvWCGttEr0RRp+cn7Iac=;
        b=PxPuonGuRXP5ySSy/zdJf+TPg1fEyNELjki/yqe9/fJtXO51weWAz8RZcuL7K9XpmD
         x4VF6mMf2fq0ETvMOcY9NkeShxzKNKwvhNSuRl3/fsSKX5JBe+GDFvY8kd9/3ooRVfMs
         wSUwVdlkqM4XAqPx6AQG369sta4DUCxNNGy9zTcqqqrtAOTowLrlgeCxsutmb8grmm33
         OfB5xqdZb3vb3jFxtmK60qYPa+nQOdg1youHoxciaok2bO+IUDlkCMrOUz7gqNP8G4nu
         TpOwyplhqQLqKWiAFaqGMH3tHwSo5k/I20UWPSTceJzr2MToEz3PdJuBrEYT+P2X2/0o
         l8JA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VJQpmtbD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758016743; x=1758621543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Bz7RmzYYZCEyHsaMv4gyG1MS8W6aaY/cjQ7jBlufPVE=;
        b=aq8cvTYlN87V8nFqgh42X88ghfhwrp2Wpom0UNsN0BI0Ttr+WTLpqL0wWjyrTzpKQT
         7JgA/uLbKcLqD54+k8O5jy0pg1+5HUW0pt97yYdQxmnAYmLc3wXA5/+bGNaXb3BQKWkF
         oYTIyE3lkKp75iRWJ9j4A/ciuQUA1f6+lt6Rr+/7w0pSZJ1zJAwapOTksmKW6wdgbSvX
         R4U98qpJWCEVniZq653xUOvfbJFx5rn48bMobQq21IrF63GHLSE3tRdF/K2QCGFkvL0u
         ewjUd7MOujEhYaixRh6yXCdWbkoGwd++JpltYAyo5hNRQ3LZy67XtpBDaUJXew6ho9Yt
         SR9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758016743; x=1758621543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bz7RmzYYZCEyHsaMv4gyG1MS8W6aaY/cjQ7jBlufPVE=;
        b=bw2s6jY6PsUZ1QkoCUTtH/Vk2qGw0bLVXhZ/CKmY7DdNtkvlTaHCAKq0SCi2suVimn
         80tZIVeF9meAwsMThNx9yx7waHYMhmrWbKp+rRNTgZlR3gQ16YJFKz48E+3ONfFYBMF0
         MCcH9Obf7wPoQdMXJQLPpwsaF+6192xCLMasusPNdiK1bqoPxXVPZ71uAqVYH/or+B3H
         YeJ8EyQpdiIN9ycBcAD0OFUMYrrwjhZZl0wRdBOnJQVlRmwwu+vS0CzTvjVt/oex3EP+
         od3kp+8AkvJKfGIElJruy5Q0Nx8JjSQhK49poIRFkXNxkPl0nClbznUYHx3vXUJ3Z0a0
         8t4w==
X-Forwarded-Encrypted: i=2; AJvYcCXfFLVU5fg2NV2iKJl7KKsr1g29agP4eDIhmHiLYI6Og4Gud/Y7xzWdaXlNQF2FF/XmjURVDg==@lfdr.de
X-Gm-Message-State: AOJu0Yzv/fOtQnAhJwvETs5yqPEiFTgedMu0+1iACrPt2uq11bsu+0dr
	n0J3cKNRpDAiCPSvsJaNLrsX0kZVWiNIUwiCOkWwwZm07QE+/vNvMYvY
X-Google-Smtp-Source: AGHT+IF/KxAGctplh7wrxtgIZD7FRJjdFj5jEM3UZfZF5CX24soBP2DMJe9WhtFFRUOD0w7R6sFDSw==
X-Received: by 2002:a17:902:d2c2:b0:248:96af:51e with SMTP id d9443c01a7336-25d27d20531mr219020845ad.45.1758016742925;
        Tue, 16 Sep 2025 02:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7B8Io2ZYBJZCglkbWf/SbuBn3htxFKiCo/M1WrbZisrQ==
Received: by 2002:a17:90b:3652:b0:32e:b78c:bd7d with SMTP id
 98e67ed59e1d1-32eb78cbef4ls206208a91.2.-pod-prod-08-us; Tue, 16 Sep 2025
 02:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6l36b0uj8V7jn2muRoM5vEPMn1j+iWC8Zt3IAvhU7XNl2DiM9XV09ZptxDFZe0wy6ET2WwND94EM=@googlegroups.com
X-Received: by 2002:a17:90b:4c4d:b0:32e:32e4:9785 with SMTP id 98e67ed59e1d1-32e32e49ff9mr11250763a91.6.1758016741606;
        Tue, 16 Sep 2025 02:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758016741; cv=none;
        d=google.com; s=arc-20240605;
        b=ISGu4+lERuh9K3NE5mkZURgM4n74Rf7XQQ5RHDwvQjlreYBLUj8Ko1nvHZPKnZX2u7
         LAKN+7gjl0jozjdfB0sK52VSLO1R4+p1WelFrXOfmCE10crvAmJgAq2FmVzo2rRuueuS
         ZFOOW7HczSQzhsB+OXVuapMwzrThkmCb5F4YtR8jg6xs+aRG9bSHrBXaiGw4+WHCCp7A
         8GkfQVlSUKdQmTRsxZZHT3kMEeRUO9GYdSzRLKNAtTmlKj/Sw43Sa+buBPHOm5CEVNjW
         oX05WIgdsQlva5E0DZbw7IidfYtZ1Aqv9OGChPV3lsTgJAaH1euz6AeVYTRsXyOVJxs3
         XkZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ihmf+x196EH8nuZxldOMUKvsTYF5JZyh/dMEPXLM1AA=;
        fh=C9oONs8+blvGXL1DUKOONDIyNid1dDiyoGWzbIiEIi4=;
        b=lhpEuwUUrBygjfwwAVj8BBcR00JcOpJ+1gaao5ySp6inCnaJSjnYRKe/MJ5/2rdSOU
         PDBTjaz8DyHlS59XO5MUDRTyx/HW07nRFHaqiguG68DIfj2++Qkf+9URBTmGFt3Tvd4a
         SNrQ6sL6AfktCd2AADIh7P2RgLohM3ynCu2nupu8xCI44XKYjDTAgcjbn+t0/KLLfpY9
         zeTWLCrDshcrXAg94JSD1wlqhXcWvsIQ5dqJXRQUJZioHHVb318reCB2j47aQukfvvuU
         P4RJ3rexGUcc0/XSA1ZgOqZz4LPA6ktemjNQoLyVP8HrtUrCg17osPsN/Tw0tzshrXK0
         HMTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VJQpmtbD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd98b9073si80695a91.3.2025.09.16.02.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-78de32583fbso702676d6.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnJBVemfcl0IGDALJsdgE8iFZnxlgTx3F97j2wOEsNCiuHQ+VhVOCAxwe/KrnveN44nKUx8+zBjCQ=@googlegroups.com
X-Gm-Gg: ASbGncvVrSi1OBZIGfdQX/i62lGv6WMlSqFd6M/hx1thPUj32M6EUZwk/6i82YDXWnB
	D7O6tU3URrR68d5nhCJQLgEdcDjP3M6wcuQpubjzsxoUcJ8zSggIRaQwOIQ8cvfKfrGTBFq/9cW
	r26hBBnztwQeHy6mCI5Gqtb2raU6dN7tyt6iYF7+ma+REm8R9MM0E72Z0aiv0oZe4DioeduIzcI
	6a0+kSMFXmalyB/dGi9uoPyuDxtT/YSsSmwiMRlaAMp
X-Received: by 2002:ad4:5e8e:0:b0:723:e1c6:8d7 with SMTP id
 6a1803df08f44-767c5aebad5mr178831206d6.64.1758016740321; Tue, 16 Sep 2025
 02:59:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 11:58:23 +0200
X-Gm-Features: AS18NWDFgZtzDhBG5IKRN3iWsXFMSPZcawD_BvUUYRoHSVWInp6fN2JP63m3d4s
Message-ID: <CAG_fn=U8Y=WNTNnP35uwQqxmFOnOV7ptdG0i1VjsaYUe3wfRuw@mail.gmail.com>
Subject: Re: [PATCH v1 02/10] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VJQpmtbD;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
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

> +
> +/**
> + * struct reloc_entry - a single pointer to be patched in an input
> + *
> + * @region_id: The index of the region in the `reloc_region_array` that
> + *     contains the pointer.
> + * @region_offset: The start offset of the pointer inside of the region.
> + * @value: contains the index of the pointee region, or KFUZZTEST_REGIONID_NULL
> + *     if the pointer is NULL.
> + */
> +struct reloc_entry {
> +       uint32_t region_id;
> +       uint32_t region_offset;
> +       uint32_t value;
> +};
> +
> +/**
> + * struct reloc_entry - array of relocations required by an input

Should be `struct reloc_table`.

> + *
> + * @num_entries: the number of pointer relocations.
> + * @padding_size: the number of padded bytes between the last relocation in
> + *     entries, and the start of the payload data. This should be at least
> + *     8 bytes, as it is used for poisoning.
> + * @entries: array of relocations.
> + */
> +struct reloc_table {
> +       uint32_t num_entries;
> +       uint32_t padding_size;
> +       struct reloc_entry entries[];
> +};

> +
> +/**
> + * KFUZZTEST_EXPECT_EQ - constrain a field to be equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable
> + * @val: a value of the same type as @arg_type.@field
> + */
> +#define KFUZZTEST_EXPECT_EQ(arg_type, field, val)      \
> +       __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_EQ, arg->field == val);

Nit: you don't need a semicolon here (also in similar cases below).


> +/**
> + * KFUZZTEST_EXPECT_GE - constrain a field to be greater than or equal to a value
> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.
> + */
> +#define KFUZZTEST_EXPECT_GE(arg_type, field, val)      \
> +       __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GE, arg->field >= val);
> +
> +/**
> + * KFUZZTEST_EXPECT_GE - constrain a pointer field to be non-NULL

This should be KFUZZTEST_EXPECT_NOT_NULL.

> + *
> + * @arg_type: name of the input structure, without the leading "struct ".
> + * @field: some field that is comparable.
> + * @val: a value of the same type as @arg_type.@field.

Make sure to fix the parameters as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU8Y%3DWNTNnP35uwQqxmFOnOV7ptdG0i1VjsaYUe3wfRuw%40mail.gmail.com.

Return-Path: <kasan-dev+bncBAABBXM7ZLEQMGQETU3GAZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 25D54CA68CE
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 08:55:11 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-37bbe387942sf10847541fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 23:55:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764921310; cv=pass;
        d=google.com; s=arc-20240605;
        b=BAzlk3Wok3SPAaXju3qwRVpS3EW+YoJiIC7o646QntnsO4FsJ7epdWId79qtxT8PHd
         WEmN9z6YcF23yIRhba2qRMIPlubY8ZGtmUPNO2kZdBdvCIpL5HPIU6nSw1wms6xqQ4G3
         0a7h8QLByXhfH37/LAR1kQaOD6cJjyIVUdjmPaZuf4bqIH090Owk13Wx+PhYvnxMYYh/
         ++4YNZ3m0AtLKGR7p/RE5x2nYrPtAvtPDG0jBEhiC5s0+9m7gSVWZHp44+eXsFRUsPm5
         sajNbGTAO563SwJQpJcmaBGt9e8ItNU5/2U4FeS7EB/WBbrPZQ7i8iPCzdPh54mWWNis
         hDcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=jlM4NWMJYYCarolKWx+ADzL1hCvyYBM95KXTsymp83U=;
        fh=rFEsDMHUMn0fo+kMrn7la7dVBs3Eqqt6qLPAoiuvDKs=;
        b=gTZ01ZfWddlF0OAHoiO/0V2AXGHHPYhPeKMY4yuBzKzx/WPnrIyGAfjc5TAvCno5zp
         86qLg57BvO0Ci+4oamsHN1TXV63BkprjWYLEaQC81AZ20/W6T527sO2WQi+z0Z8urvmd
         uSnETSvOOqcR0/YO7HLQZVWCOxWAORTxgzCt82AxLbibgnDNA5BXKblZu8GJ/AIbEovd
         ke2EDWOxLqMuwgCif228UVXRn2hoDzoXYbD/wqOM+4qT/tqnxyk5uzY59VjktApkDlum
         S3U8iAzaHIjiBmwO+2z7pIM4jie8ZrSLbGUjIl72InHqvNKdhilL3gu7UtUCfe6WO0o2
         reDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="kvFx/xmZ";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764921310; x=1765526110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=jlM4NWMJYYCarolKWx+ADzL1hCvyYBM95KXTsymp83U=;
        b=EDj3iDSREG1BYOREqHAjAkXOzXZ8QM09TZSD4p/ucujUCLOlfvJBu6ehD1afX37cH9
         6cqq03pIKoNrKDfs4Tm1IGOrCjvx0kdfNRzWifAk0DnMj1jy2HcX/Lr9T/G/7235Xa/M
         6Vjpn9jR0cGLpH19V+W/jJPYO9IGZbDnk4orDO5POrjRevhTUcCvqmxOnzuG2mpFLJaE
         dMU/2KjjxBrf4g7OssO7QTBf9JlAdNw5yZSeKyZ8AoM1dt1jFoAxqxWSx83+WC1S1TuT
         qvieJjCEX/misNHats5iTQElOjpXsllyEOLDhneIwQhLGcM6xHKFj6DA7YXHNELircfr
         8hUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764921310; x=1765526110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jlM4NWMJYYCarolKWx+ADzL1hCvyYBM95KXTsymp83U=;
        b=wVKAxzLRoO3Kfb+Ca5WzKvhClE74l0fjZ694uzMn4tEGaS6SkDrgyQVda6pbgLUiQD
         rrrS8zXFgIerR7HDAiUN4bbySfLZU3K3NiHbhcf0moQeOa8v0Z5ON0eqtHdkWsQH+gKQ
         bbiiAYw820bR/zUtD1U3jJuUoE3TVg8cK/P/bJyQlhDhhUpePZkYqpXPrDoPJ1MX1wYf
         70Zp5NRYH1rrhx5usU9ZOLJ+0KNE7pkh2np0B/DxsH4S0L414h5R1MXV94kZ/2Ak1YGE
         JxplhkmNii0f92Wv5RoHMImnMU6sMuODTnyDQX9iypwBgHfnKpfdkfECqQdHqhDq+N8d
         oB4A==
X-Forwarded-Encrypted: i=2; AJvYcCXNYFj7lRdo+22j6X2jPqthmb95KBEB5DQH8bK5IJ4d2NSyRDou+6ZDjMLWumjcHEbZ/mo3jw==@lfdr.de
X-Gm-Message-State: AOJu0Yw6JqjF8iWkbTXoQ4K7Vv2djx5bMLqyUZ3k4mOtf0kZGX2h5bz1
	4tfePKiloiRGjlEvEiWwwtgJrQxFFPYTaa2UUCSi8s73nzYDwGEQev5X
X-Google-Smtp-Source: AGHT+IF1Q1T3q8PhHn03GDW7JByyf6ShlJJlcEXW2zWMEF/B067UkPvoKnNEa1POiKzkitPS2KWZaw==
X-Received: by 2002:a05:651c:31d8:b0:351:62e3:95d6 with SMTP id 38308e7fff4ca-37e6395abd2mr31943981fa.28.1764921310162;
        Thu, 04 Dec 2025 23:55:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZwuKbxOBJa2h8aGy63jG8JtMHS2BPay1Q8+HYYoUy/ng=="
Received: by 2002:a2e:7a04:0:b0:37a:4d6c:471e with SMTP id 38308e7fff4ca-37e6ebc802els5311891fa.2.-pod-prod-01-eu;
 Thu, 04 Dec 2025 23:55:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWAAXGSNkbRnOq5RvEfgfg9rkwRicVrSA8Pbz1znNlLgzvk/XAxOv4SpZNUs6dXMHqI9pNy9ZinD7k=@googlegroups.com
X-Received: by 2002:a05:651c:1241:b0:37b:90fb:9caf with SMTP id 38308e7fff4ca-37e639f22bemr19131211fa.41.1764921307741;
        Thu, 04 Dec 2025 23:55:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764921307; cv=none;
        d=google.com; s=arc-20240605;
        b=KrVVP/NoafnlRFzetNIYu7Musv5o81J3m2mM06YjhsL71KaRdJp7n1dtU6J+NOlh/f
         /FG88f0q3IeLvrxvzPkBNq4VRhmNpS2JMW9aae90Ma2mIoJTk5So+mi2kftVIQyZP6kN
         fMYA5bNOIzPRALj76x3q5KSxqDRK4hUo9J/XM2acWbcnkjujBiwxrczNp35NSH48scSL
         mNgW7ar+qBPEDB20qO8Kpf3SZTukf39TGS47ThWtD2tTjZqMjCf/WKk09BmeBZjSTCcI
         jmlJy/10eTKTwtQ+NHF5DHawajHtWkWeZYCRFlyghSQnQu+jOzl7b4s5htU/22R6XgWh
         nWjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=eiqow6AcLnuWm1OdBsmeLZ5HYj8tUdXBpN9mWfYflcc=;
        fh=N9jLoZIR30MHUxIyuZUisf6k1oEQ+eX7ezk7jzvdNzM=;
        b=fXlVt/zEE1jYNLJ0ucj6eEhbCZhtCMyHj5Z0nGYnTAMKPftBdVtBdp81p+1vThoD3v
         fsPWEJsp3A0sO3eQSqwwAS3MTXgzd9a1vnIYA7j3pJ7yqkDCsdmCFA7Z3OKF9WT8P4Q4
         8MSSk2r6JwhD2e0ZF56DP9zBptlX4acnnUuDU2l2RVwjFr5B2MP82Xrx63j0I4uEoqlf
         xMrlcdPDwy0YOMDphNHFlK9OtW0IbtGYa2EaZNcAMCO1wgI9mrYHYo1Hcvubn1J89yfX
         KsMPZd9j9M42/xj6/stjcbPtZKHrR1IMtjG1Mr8ikSdzzYubbFmb82P+uQQtWBOmMaaN
         UmgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="kvFx/xmZ";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e700c1e69si616981fa.6.2025.12.04.23.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 23:55:07 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Fri, 05 Dec 2025 07:55:02 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <qg2tmzw5me43idoal3egqtr5i6rdizhxsaybtsesahec3lrrus@3ccq3qtarfyj>
In-Reply-To: <CA+fCnZfBqNKAkwKmdu7YAPWjPDWY=wRkUiWuYjEzK4_tNhSGFA@mail.gmail.com>
References: <cover.1764874575.git.m.wieczorretman@pm.me> <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me> <CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com> <20251204192237.0d7a07c9961843503c08ebab@linux-foundation.org> <CA+fCnZfBqNKAkwKmdu7YAPWjPDWY=wRkUiWuYjEzK4_tNhSGFA@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0439dadbcca67de10a77ca7cb46b286e26d6834d
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="kvFx/xmZ";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

Thanks for checking the patches out, do you want me to send v4 with this
correction or is it redundant now that Andrew already wrote it?

Kind regards
Maciej Wiecz=C3=B3r-Retman

On 2025-12-05 at 04:38:27 +0100, Andrey Konovalov wrote:
>On Fri, Dec 5, 2025 at 4:22=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>>
>> On Fri, 5 Dec 2025 02:09:06 +0100 Andrey Konovalov <andreyknvl@gmail.com=
> wrote:
>>
>> > > --- a/mm/kasan/common.c
>> > > +++ b/mm/kasan/common.c
>> > > @@ -591,11 +591,28 @@ void __kasan_unpoison_vmap_areas(struct vm_str=
uct **vms, int nr_vms,
>> > >         unsigned long size;
>> > >         void *addr;
>> > >         int area;
>> > > +       u8 tag;
>> > > +
>> > > +       /*
>> > > +        * If KASAN_VMALLOC_KEEP_TAG was set at this point, all vms[=
] pointers
>> > > +        * would be unpoisoned with the KASAN_TAG_KERNEL which would=
 disable
>> > > +        * KASAN checks down the line.
>> > > +        */
>> > > +       if (flags & KASAN_VMALLOC_KEEP_TAG) {
>> >
>> > I think we can do a WARN_ON() here: passing KASAN_VMALLOC_KEEP_TAG to
>> > this function would be a bug in KASAN annotations and thus a kernel
>> > bug. Therefore, printing a WARNING seems justified.
>>
>> This?
>>
>> --- a/mm/kasan/common.c~kasan-unpoison-vms-addresses-with-a-common-tag-f=
ix
>> +++ a/mm/kasan/common.c
>> @@ -598,7 +598,7 @@ void __kasan_unpoison_vmap_areas(struct
>>          * would be unpoisoned with the KASAN_TAG_KERNEL which would dis=
able
>>          * KASAN checks down the line.
>>          */
>> -       if (flags & KASAN_VMALLOC_KEEP_TAG) {
>> +       if (WARN_ON_ONCE(flags & KASAN_VMALLOC_KEEP_TAG)) {
>>                 pr_warn("KASAN_VMALLOC_KEEP_TAG flag shouldn't be alread=
y set!\n");
>>                 return;
>>         }
>> _
>>
>
>Can also drop pr_warn(), but this is fine too. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/q=
g2tmzw5me43idoal3egqtr5i6rdizhxsaybtsesahec3lrrus%403ccq3qtarfyj.

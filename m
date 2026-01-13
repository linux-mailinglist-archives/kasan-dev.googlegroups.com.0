Return-Path: <kasan-dev+bncBAABBWG5THFQMGQERC4DGDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 67C5AD1A1D6
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 17:12:10 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-477a11d9e67sf51665435e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 08:12:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768320730; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y5BGcbvWlX1hdul9Lx2qIVbHhkUWE/EOjXzYQrSUDW58aLcmiq2rP6rZ3MtZbCzUdK
         iNZ7sxTe9S4foGCStnALpy/NSKuaJIH42uHRVjboVNms7wn7vcTW2I9cQ7m8oRfrHL2q
         3jm6n73yx9WY5uBjVRjOQxjAX6ZB7YekVtUqvpGpyNPYg/o3KPqKTF/ZfxaDjTSuYfvu
         AEEWTVxvj5ULkDZUv3K5pqVwoysV3R3QTDdZIeh6g7QIucqRNLYIPn2jGPpvGmNYfN9i
         QUKfT3z+GS2ORRtztTtjt+hJGGKLEywHKAMpGl82BRgbNEBNtlUJBRsahiAzImcGSZ9/
         0ajg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=C4tKJnTazwlZ8HAdj7g5JhCL6usF2Dg5ZBGE/x8+7HI=;
        fh=Szic/54TW3FVKJqxCSAuDcOXXTlggzitxPGbkqMwXgk=;
        b=GB56Ju8fNx5A2NVTbrTEpo+P5c0+j37G9938etdFOS6DU+2078Hq1SCn4Us+B2MUPg
         O6A3wIuEbjTJknv48sPSPtJlId6wFvGI9DHbIfOjnoOf5c/x5IpyML4UUUnOdnQOV5b0
         GH2MTjEwEHAkTsvRHByks5p7QZ8aP0QnkmUKZ6p+TfWwm1J7lwokvnsxdlDG/21utOBr
         +ukaFaGrxggm6OI0wVCYJRLD1OHPcvEuTMCe2CDfcep/KB8z2i73H9V6f261V0XlJv5m
         XpIui/zJ96uqpr4oJOiSDrUZCLuFCQwo5cZ0GQaqn6wV2FBN9MH9uZY8BOfLZU6qB9a1
         EeJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PCz8aVv4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768320729; x=1768925529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=C4tKJnTazwlZ8HAdj7g5JhCL6usF2Dg5ZBGE/x8+7HI=;
        b=mY6+oODFvNnlGKB3RjJ9hJcYZlGZNXPmuYqIy306QoJBo9Qmc+QJBqHHs8fBO/cXbh
         ktKIDkeB+eiNbI1BQpOj4X8GGWULpaO2coXGDXHGgb66665rVXKTl/h0zi56yq62jG6F
         kPIUWyGhZH4fLWMcfebZaBg0bwRvUXh9X+qoam0JthhBz2p4LKniFm9tefW3zwhV9NCA
         YO5pcrZIFN+lrqHYDXpVbW3guq5YiHMt8kxcoFbZoL+4wlO4H9SstUDi/fVXP0im7v66
         O2MSluUUM+zj5o49AvOybD1tgkjhUv0B8kAJM5stR2SseCAwGZXl3wtG0enqtxYrdqNf
         DJ8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768320729; x=1768925529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=C4tKJnTazwlZ8HAdj7g5JhCL6usF2Dg5ZBGE/x8+7HI=;
        b=RDGQistHPmkd3Yi4LOymVMuQioBrVjlwos9neUXpkB779twm9Ws2Ajk9crLNq0YQAf
         7OQYjFy25FGKcySOkxYxF0TfLx1biPOdj3wJGZe1GPa1kTRMm5Tz3IQVIV59UYGpXJ8+
         f1AfF1BFIPuRag349jcqJWZM9UWUIIxKNhxa+YEPounr1CZglvLCSfUUyZFnmdq0AON4
         oIoKG3Hm1Yn/n9bRFSBElQg3bw9wtteqhDDTk/2CzOmjwqaYcjL/wU+coeEQ1xZfI60F
         ACYTEx1/wz6radiNycxgApHLYRM/KKdTM2GYuHdSkvdQn4xomJSMTdcJLoAIZ/XUd8Z9
         cebA==
X-Forwarded-Encrypted: i=2; AJvYcCWwkon30/W6V4G9NbaoVy/fNqALGStWxv55l+rxSVlrgPtZwG66+oxNmF5aeuZoVeFzsqDEoA==@lfdr.de
X-Gm-Message-State: AOJu0YxAUt72CkwMQQ8yeexBUcyQtxAiCcYzaCjVzjHXgGorqg0AdUV6
	HJV+7bsucozFd/sltLD+ks5D//4Yad5OPXf77hsGbZnMy+FGgvkALZOF
X-Google-Smtp-Source: AGHT+IFAGho61BxYRqxK7IPU8Uh0E1XvjdVPDSrAzMSmTg9nVR/XNcHPe1PGl7Nm2cSqi9WMoQUR/Q==
X-Received: by 2002:a05:600c:3152:b0:45d:dc85:c009 with SMTP id 5b1f17b1804b1-47d84b1a04amr275333725e9.10.1768320729334;
        Tue, 13 Jan 2026 08:12:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HVnbcRYbXLmAxPvqyjNQh14QQ9OQy5EMept1FPHJyhLA=="
Received: by 2002:a05:600c:4703:b0:477:980b:bafe with SMTP id
 5b1f17b1804b1-47d7eb13f6dls60126395e9.1.-pod-prod-04-eu; Tue, 13 Jan 2026
 08:12:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUxokUCZQ3G71illrUSWREyYySGk8nG+SfTzftRhAzImrWL0KScJTUM2G7gsQ02sQmfrSVLOJQmtow=@googlegroups.com
X-Received: by 2002:a05:600c:3152:b0:45d:dc85:c009 with SMTP id 5b1f17b1804b1-47d84b1a04amr275332625e9.10.1768320727672;
        Tue, 13 Jan 2026 08:12:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768320727; cv=none;
        d=google.com; s=arc-20240605;
        b=Az40KhlX7UF4Lwhoq2XYqbO9Vk5lzT9pZsxH7yivJECUeH0YHuUPet6iyYXV+bZ7c9
         onx/ALvKL0JaA01/mDq1I5zQSzYD+Doe01EhRLsC0o4aDjcUalEirYiYAq5HMH0VSiWP
         afbf6Ff/jFpdmY6QJ6EZZdG0QZl5ofakDA9h8LOhck3kV2jrOZCu9n8+znzq9/CtlcSF
         Bwc30etIdEDYZ8ZhlOxk/BY9OTzLILYMOHvz7P46E1cCv3FR0H77TBhM94vZ78kh3Rh1
         IEvaG5ls8bvAIWzPgdqhSTFXypZg4quuEr3mZFZudzhAa1p/u9u3ENru534UtR4yWilF
         W8bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=/IM1IJGDRiUpTxho6UE3GiNOiCAJhVQawQ+QVWUuJNc=;
        fh=/NSPTZzypKgXOgoeDahHsH97e0JAOnqgmRUFZRBw7nA=;
        b=ab11ToCm+jE1UJwq4z7+Xq1S8vJ91ZpKyC8wpCX6uTMMytqdLXopO7JYNzFKvO0eNT
         hA+WXHwjzl5nueOC9do8+4qAFBKRZVsSIHpuklqyYJQ9vvRRmXdwHGWRDGkwlad5AVx7
         6iJLMXmk7+OVb8PAIsGL/3JSoE2e8Exzd7PBa/wxzudnWQ3qKA+eh5KsP90Niaw6C5u9
         lrPvrnFMPhGf9qciQ/akvAXhLThgi2MRpcRbBe4BmHSGJTINtNW/ADnTNFmCO1SyjZ55
         J9xLI/gJxyAnCRmMBYsboN3NrU6ieWaBdYrmBjTbNYdXY8ciUYCsWz59r4JJhhubpDv6
         qirw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PCz8aVv4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee0b488e1si48135e9.0.2026.01.13.08.12.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 08:12:07 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Tue, 13 Jan 2026 16:12:01 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, Wei Xu <weixugc@google.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v8 04/14] x86/kasan: Add arch specific kasan functions
Message-ID: <aWZups-lK-J3NwgS@wieczorr-mobl1.localdomain>
In-Reply-To: <CA+fCnZdTDzruwLA2MdE=+5KQC5VKMEjm49Z5ez-dDO27y4GORw@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZdTDzruwLA2MdE=+5KQC5VKMEjm49Z5ez-dDO27y4GORw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5dbf393033876631cef8bd13fe0e2530c3676625
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=PCz8aVv4;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-13 at 02:21:15 +0100, Andrey Konovalov wrote:
>On Mon, Jan 12, 2026 at 6:27=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
>> index ad5c11950233..e4f26bec3673 100644
>> --- a/include/linux/kasan-tags.h
>> +++ b/include/linux/kasan-tags.h
>> @@ -10,6 +10,8 @@
>>  #define KASAN_TAG_WIDTH                0
>>  #endif
>>
>> +#define KASAN_TAG_BYTE_MASK    ((1UL << KASAN_TAG_WIDTH) - 1)
>
>How about KASAN_TAG_BITS_MASK?
>
>When KASAN_TAG_WIDTH =3D=3D 4, the mask does not cover a whole byte.

Yes, I suppose that name makes more sense :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WZups-lK-J3NwgS%40wieczorr-mobl1.localdomain.

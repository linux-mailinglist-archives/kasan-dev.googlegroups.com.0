Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGP4XOTQMGQEHPHU4AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 782CD78D41B
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 10:30:19 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-56e9cb3fc9dsf5674661eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 01:30:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693384218; cv=pass;
        d=google.com; s=arc-20160816;
        b=dDBRSKe8a85TxcVEKC/YIcz0ibZ9LSA27Pj2BRv6c4pAzRUWRod0xVW+8glGHehjjD
         NNuzVo7tpGtnaxu84T3RsMndV9VNCM6jhghnnxxfyt+8jqyqXYFGhTO14nTph9Nd/iX6
         RD3Ly0nJnYNgEWR4UbW2aAKYs0a06A8dzBoCCgmvIRedwmktVi75SOZdiz3eFTXtw6Hk
         dz+Ss9qt3IY2lL3Xt6XyI6Ds9HRC0VMqtYu6Y2cCHInFzaaUwkTO/skWhzhYwYa1sAgj
         GE+y0k55PFII6opyFpGPiBaneB7wKMoEgLU8T2wqGDUX3mA6Vm7wNzvDjxjAm0Fb7eI0
         yeaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sswhf8AwWd4Kc0d+tcr8g5pHSJDeG9hbYtj8osXE7l8=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=qaYTcesj06OL6P6kikG+kvVvbwsacl58cHmSYU0cIzW0RzlQfSkVUM3HNTCj8U1xYn
         LOszEIbzDcwyUq8Lq9wkWhoEkBEZXRUcnUzdrvDZKKMmLOrGsNUi0q/LuvYTwcwd8IE2
         k59qry3mWFQ3lfBPCuo0uw5xZsqR9Y/y6nNZ2KIjRqLfckuc7mXKrwj56ae/S2Uu+pDO
         nsVqG9GIcMFiag/ulPf/w/JWjjSoz6uHp9seSQFY8pwi86XRp8vSOeSytzrMrirVZGXW
         QQiHHiSz694YU+aV3m4n3Y7S0NY4k9VKsYDgc6y9/VnIwB/c2ZueObAtUTp32ktQfoSj
         Sf6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=d4ztlABn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693384218; x=1693989018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sswhf8AwWd4Kc0d+tcr8g5pHSJDeG9hbYtj8osXE7l8=;
        b=PsRlmXoTFFUiFn9l+3Ntho7S9NQq/rhjFElJVIrc7Ww2AikDSWOOdhgt837yck7+4/
         5lAECaOenhrnvDXBezLB9Sd//M31kbgkOaJXbVyCKmQiyYXx7XH7hpyG2fKRlwc+20Wa
         2ePaCqJ8SyeYHoIQ5TsZI/4xRaSRAWLa6ZIDIRIVpXiuI6ZbHvBVd7RQQ4bo0nAInfKQ
         rua/xjSl7MFCMTQZqkoQt125JRo+X3RqNPM+V1hl8XSaFnxlAFl8hGAwFJ0kx57Xs8xV
         JVv9iEjQMoR1kyjmlaGbX2HNN5tHN/LLOtyv9DIVzaTjVH0JfofwVu9OrwYI0QUpekHB
         D6uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693384218; x=1693989018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sswhf8AwWd4Kc0d+tcr8g5pHSJDeG9hbYtj8osXE7l8=;
        b=eQHLBBKwh8NicqNE9qbPmCojlr7vk65Hi7KHYPtfWxjtb7dL99E1DHlWBBsPUrNBoq
         sMfjtYhWTApDQFIPlp7K9bAO06lU5RdfV8Rsrai7WTzKaMhW2w9i5nAco3smm/KKcNm8
         Ly2ExIPXQLX7gqD6XzTTy0n97ujEyRwrnNqu20rIOx2jZa9F61oDAd9DU2HwEMKdh72w
         E1qkQNxm1Cj3kvE36DOUMHnUu1qgfHOxClJdSX17QppyBVBl7kZNNy9lL3hmYuxECelC
         SS00pjBoXFssyQsZnlvd9Ku9QKji0lMYCbSuoW3RJ+0UBhd3c1zqDN7QHuamy+1g55sE
         aQcA==
X-Gm-Message-State: AOJu0YzzTEUya6JmjmYUK7FIXBru5KgxGlNAPm/flJhpUrQ9wPghvCRT
	vCm2TII6gFhMG0+X+5pqjyY=
X-Google-Smtp-Source: AGHT+IH1eDMyatFs6YFtJ3WJ12TQ2Ii2nB/ZgO+x72elG5SV+WlqNLIhbnZJSJjBEz8jw8gMiH9DNw==
X-Received: by 2002:a4a:3954:0:b0:571:24b4:15b7 with SMTP id x20-20020a4a3954000000b0057124b415b7mr1523775oog.1.1693384218057;
        Wed, 30 Aug 2023 01:30:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a98f:0:b0:571:2459:9a05 with SMTP id w15-20020a4aa98f000000b0057124599a05ls4736950oom.1.-pod-prod-01-us;
 Wed, 30 Aug 2023 01:30:17 -0700 (PDT)
X-Received: by 2002:a54:4d06:0:b0:3a9:c2fe:335c with SMTP id v6-20020a544d06000000b003a9c2fe335cmr1450847oix.52.1693384217203;
        Wed, 30 Aug 2023 01:30:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693384217; cv=none;
        d=google.com; s=arc-20160816;
        b=GfE2QCCt16R2z+IdASNUvoPAzozjJTiqnfyFgJ25zUTfItcJeA1iG4TetjZogUKgQH
         DqJzwkmuHPA/jmQnZ2sQNY72IeJJWSNylwjz2m0k5UjnYYc5iGvgaTuG9147tzLNwfC9
         yDUWYFNJUFI0QGgrLtrL6WHoyZPFf8KIDcLM03Dse7OkVQHP1zdyl2/0ve6EixGEi8ON
         5Q2ZjghSOu54MU5G7PxCZOccG7s8y8B3y1c8gjeQIDdkz3L5QvyE15ZCMRvKJbtBtGet
         z6UnjAGDwRrc40sakTHBsC9RvyIfbjiKkIiSX7kbaSwXflHC0CG3o+yvXWf3Ytnm18mH
         +Csw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aMR1GV6sFpYJsS0folCTsjLW+vWGeZBsW541aS1m7cU=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=p1lhGrKaF+wtjNGnnGQJwS5BirBKpAXtOn69FmTNgnq+Mg+szYVhZonlWRwbFpgbJ6
         ZdiSe/0tXsbM7VUzT1chnmfDvDW3EZn84OKLHwcWR4lYzDYiZGfaovauFWg4wSFbdoEB
         cExtc3gs/+pCeB+M5BwJK/yzOAV/U77tdLGKGx4Gn+pdVV1nJ7Pmr4viQV/3QjsfYpgb
         bPv/l71gjFxZ30GY80pdZ+YWz8h7O6/1IFgvvmEyrMZLBoivWzbrUO+VO6Yo9gSBi+MF
         AtdzATx2r8Doy7oPanrsZuItlI7JnLg1uHsPT5lNjfrkBdVNy30NEzs/Ml+2HaT6r7ou
         lKxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=d4ztlABn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id s2-20020a056808208200b003a85352ac61si1666236oiw.0.2023.08.30.01.30.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 01:30:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id ca18e2360f4ac-7927f36120cso171585139f.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 01:30:17 -0700 (PDT)
X-Received: by 2002:a5e:cb02:0:b0:790:f397:4321 with SMTP id
 p2-20020a5ecb02000000b00790f3974321mr1771037iom.1.1693384216737; Wed, 30 Aug
 2023 01:30:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <f5dad29285c8aa7b4a1a3f809e554e7d28a87b6c.1693328501.git.andreyknvl@google.com>
In-Reply-To: <f5dad29285c8aa7b4a1a3f809e554e7d28a87b6c.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 10:29:40 +0200
Message-ID: <CAG_fn=UYA3bwO+_K60UydVa+9NRayQpH6qHwXukG9Dfc2YaCDA@mail.gmail.com>
Subject: Re: [PATCH 08/15] stackdepot: rename next_pool_required to new_pool_required
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=d4ztlABn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as
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

On Tue, Aug 29, 2023 at 7:12=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Rename next_pool_required to new_pool_required.
>
> This a purely code readability change: the following patch will change
> stack depot to store the pointer to the new pool in a separate variable,
> and "new" seems like a more logical name.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUYA3bwO%2B_K60UydVa%2B9NRayQpH6qHwXukG9Dfc2YaCDA%40mail.=
gmail.com.

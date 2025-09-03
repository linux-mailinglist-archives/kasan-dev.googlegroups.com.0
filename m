Return-Path: <kasan-dev+bncBDW2JDUY5AORBRHY4DCQMGQEW7AQQ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF98AB42036
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 15:02:10 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-338000873c0sf5951851fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 06:02:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756904517; cv=pass;
        d=google.com; s=arc-20240605;
        b=DbxYf1QvQ0+jkUOoG9nGGawE4lvHEHcT0vqtWszc6mGLIt6mL/IKYwAwg9yFJ20kV7
         cMGUtz5gXVtEALOix7R6M3IbOpnvNKBD8k5I1Z8c2FMAsBpxFOgy+klkCdargpi/Qgkx
         l7bdm6ODoaPxdSrNiG/fjynnXQFJVlSTyEfbqJQQkRbD1c5/aDOw3C8F8tGArwI0+wk2
         YjFacgCYvimzkC6ixx1iPDRoXj1Eg98ZMe1ua2wIQlr3nf+iWWbTKgYeOfsc/Xwe0fg1
         hiErliVI1cn8lwgGsaLOaIVyTDi1HDFWPmpCqJP6Pw8749O0JZAhRGHHZrChYloNSF/t
         gksw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=oR8A50Ste/RLoUoo06Pa9MhrIZjIcKXnf5PJnG3jdsk=;
        fh=w4D8eloZlC+aqLlY7bUAcy8gD847TulnwUNa382Mp5Q=;
        b=je2WQ1JHjS2yXIUnvM5/o3VBRD+oXcRXJ6UemLhLiivAehPfJg5j2VPUxFXFSwC0BV
         tOMmZQIbe97FoooNjVLwS4YwgNK8unjcVtPB5e6S6H01xM0wxiep7HOvrocyUz/Xh+zG
         6gm/piJjzSlzLS7ArNkLFZy0/QEp1ZoZgerGRPJxC8gcJ7Uz3wssC4plFJvsatWSrfF3
         fe5AuFv57DkWIhk5bXYk3WcEAK5UtLX0ywWzkVqDTKeJ09WlmV8nICpyaOT+erIGz/sI
         z5FyHMKPsdJDuRUo1AdDam0JLW3ZTAznPwRYPrvbUSYpHRzRWuyUjkp58G+b+fN38qPv
         2oaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="N/o47PaA";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756904517; x=1757509317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oR8A50Ste/RLoUoo06Pa9MhrIZjIcKXnf5PJnG3jdsk=;
        b=JPr4Mr5gGU0hdslvmy0ORXYydwvptwOWX9MXguK1WX5VcZg2iGDzHhSTdl0HSdz3es
         xUrYN5TTuP/trzJb+fzA12AUZF3vGM1bjCWTVxM8kKADLjSVLCL+VlIifLvsj8H4p9aE
         hN2d5vwE4R2DtAB9JeTpiRyudsL1Ro3lUbOxlAK1VBdyn3xJO0tCdcWjW9Kpzejx6FN2
         qQZ8vlCYK0D8qw9AL5+IDorKYKfU0ZGeU+hWKG8KbZZNkmLcDuagYWqK0RYuC/kT7ERt
         ho3fe86cKI2Uq8fYpWp6Pv2S0RBaFNV93HSLkiXQHPDPh19CYE/FBnMDiOcZK2owfS/H
         SQHA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756904517; x=1757509317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oR8A50Ste/RLoUoo06Pa9MhrIZjIcKXnf5PJnG3jdsk=;
        b=jh2Lfor4eUALc0nePo2r+pJ5QYCUEsSkBLjDpgt35DGVMRFDLnvy1PEHOpODi050WK
         kIdNe/2W2m7ZvdQuzF/ys7oOMsk6tb+irmjIbcR/oiiCqANXfCL/6X005XH9Ho+BlTh3
         ATjNrQYFyXGnsxnT0xsbAB93MaHueRNdxFpiIQGaqAPGSmYSc/5yBHIrFx6jCtnyJ4kG
         fnWZ+W4rVnfdZDzgYGJVXjjdmJk1PZq83Az3NWaBTGz8uQWAcjdBeldUG9jM4MoN24bj
         0yZhWXJXmmyj4EtWOxZDqsH8LZx1PxvZq7/JJ8LjmBVhNsG5/XHVaTvI9K/VltTU1V1Z
         C2HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756904517; x=1757509317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oR8A50Ste/RLoUoo06Pa9MhrIZjIcKXnf5PJnG3jdsk=;
        b=X6YEhlUOeG+207M+LU0ZMCzonZfz7oORZBigiMK2ZMHCKYUmgb1cZwWGqsHly+xWNc
         NwIpQGKfnBP7o4t0zHVjb4qEB07NiccjuLDeST+B8jC8dpTtM+Wsyj3b8wek0NE1cvx0
         LfgZqCuHjHdcxOMGCbxK0B4we1d9yUe4UWZMQVL/5UJTOWVndjSu/ZX0IBITD8cpH2uW
         6UkYDA+Dd1/XLSY5k086zYQoDbB97SY5S9ybJVsV3twqqdgAG4kKtJTUj3Yi3V50VNSg
         BGJte0AaIDVyCvuc16+GEdTEMrnV0G5aETviBAegZc2pgkwOISZlVxlMJgFimQt50hia
         yjYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7ZmKe3q4uomza/85jnZx7r4f4jFItfGp+cA0dBZp8TbVNSfo0JFPZ/GPYb8IVKMqGpTHfTg==@lfdr.de
X-Gm-Message-State: AOJu0Yz9WFfuCtypWuHQStwd7gFyuPhPIkgie57HNXXDgp++tGCo00pF
	oaDFJdaghH9yx++u6hQxWF0exy/J6WL1AXH2d7TZGx23uqKAvDmNelXP
X-Google-Smtp-Source: AGHT+IGU7ZreF29JiZdRGUv8ZlEAQjHAx/vDm90QDCZcTCCO0SWifNUcZeUnJk7+TJdMfd5h3dtX0Q==
X-Received: by 2002:a05:6512:b24:b0:55f:4ac2:a5a8 with SMTP id 2adb3069b0e04-55f708bce0bmr3470895e87.13.1756904516754;
        Wed, 03 Sep 2025 06:01:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdhnjifpiZTK/hRp66XDuna4X1NRabi5hGAGw/eorAIhA==
Received: by 2002:a05:6512:6399:10b0:55f:4059:1cc6 with SMTP id
 2adb3069b0e04-55f5c7cba2cls776059e87.0.-pod-prod-02-eu; Wed, 03 Sep 2025
 06:01:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXA11N2DkwKH8/uuVLRKFr5aw7VQyEkk/OBXY2ekW6Me1jdZSKgj+0XQfC528f8MmzLMBTQm7RgXE8=@googlegroups.com
X-Received: by 2002:a05:6512:ea3:b0:55f:4bf6:efeb with SMTP id 2adb3069b0e04-55f709ba073mr4850187e87.43.1756904513281;
        Wed, 03 Sep 2025 06:01:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756904513; cv=none;
        d=google.com; s=arc-20240605;
        b=kk8HJSpfCkJEHS6oV2gTiEx1e2Hs9pB6TUOqzSG6F6sFDuYbIwBabe5BjOlTCgvgeN
         bIFXeGYyqCMooa5xGWRFqi4bpD/x5jpgahDsYZaDMm6Ip643ZG6HJa+PDFX8FRi3e7eg
         iVlG+6ZPGLJPuorDKELimwDLStrztRliBQdT6Y8ZiNvBows/0YrrdOJ+Nfgauac06hcZ
         NR6DEw+ZBqhFeoX9fvALkeLkD2AurcH+SxcgWTMlTiAwfWNqU0bX/wYN8hXF2C3npEGM
         S+7d6f6u6v0m+S9gvoKDCHFeKpUT1hYUvjkKkNAwaP1y36JF06ga8PBl3lSceJ3VB/NG
         8wNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rxOgjN7WdDoAv2rvG3Wc6cb+dOveWBvcqA5WgB2sqzo=;
        fh=N/e1m4UwbP++E0JXlAhsov3KK7q2IAQqDNwkkRTtScg=;
        b=kuRap5cbNu/t4h5EsWFhQDM7wLusuC/3Y43rcoy8kMxFV0skFAseu1wKRXNN6af2R6
         Ao2ADoU8jqTzWnL49bvHYRUponsMcbto9mzj/08mYOpqFqDOFvfB31sdsBLY15tmr5xC
         LR0Vpvj06mmM8Iep6r/7aMCktiZEwaJi0RWhdWW7aMJW0MfIQ43ID2ym7q66915yUzSu
         RbImolT6A/2n+iDKjDXhPWZPirv8CmjI6o7siRaW41OQ0TxLv/64ovZu5kJVPuKulYNZ
         90t66fj1BRfupVqAK+PD/9LVVDv8FNbExNZuf9LcZPbV/+XKzsfDttJ87EpsxUXDhYH5
         iReQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="N/o47PaA";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608aa35090si49323e87.0.2025.09.03.06.01.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 06:01:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-45b84367affso38164095e9.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 06:01:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVXGTW3JnQ7cT3OvfkgrzuxodVPI3/wLo97vn6xw0ttbb4zpIQihv4jEr+V7UVwXmOG6kY+cfO02Qk=@googlegroups.com
X-Gm-Gg: ASbGncvf8UNdu9zdVla0eiqXz/CP4HI2q7O2eGBOXTiP8Hm+nZKAi21ocUfXYvaT6l0
	SdFULOGr287atUVp2n4ND8iH4R6r+b3+f0GJfV1pybO/7ee/AMvJVe2MvXrStaB+KlRL8fvi0gV
	6NCvXIhu7PvG6lggT+iJhNXAiO04vUs06zJuN56/OO6I55tQuI9E8WySwpJiAOBjUNHBALQY7uV
	HVtHw9p
X-Received: by 2002:a5d:5d0a:0:b0:3dc:3b91:6231 with SMTP id
 ffacd0b85a97d-3dc3b916271mr3074458f8f.12.1756904512228; Wed, 03 Sep 2025
 06:01:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250810125746.1105476-1-snovitoll@gmail.com> <20250810125746.1105476-2-snovitoll@gmail.com>
 <CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com>
In-Reply-To: <CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Sep 2025 15:01:40 +0200
X-Gm-Features: Ac12FXxqG38KSSLGvfY5HirQQyjqsvLS5blUVLw1nroWjuASE3O6kwm-RqaVNbQ
Message-ID: <CA+fCnZdkHATBYG4RJ8rR8MciKmeV4QGwVwoQjkhc-O_igpUBTQ@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, christophe.leroy@csgroup.eu, bhe@redhat.com, 
	hca@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, davidgow@google.com, glider@google.com, 
	dvyukov@google.com, alexghiti@rivosinc.com, alex@ghiti.fr, 
	agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="N/o47PaA";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Sep 3, 2025 at 3:00=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object);
> > +static inline void kasan_save_free_info(struct kmem_cache *cache, void=
 *object)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_save_free_info(cache, object);
> > +}
>
> What I meant with these __wrappers was that we should add them for the
> KASAN hooks that are called from non-KASAN code (i.e. for the hooks
> defined in include/linux/kasan.h). And then move all the
> kasan_enabled() checks from mm/kasan/* to where the wrappers are
> defined in include/linux/kasan.h (see kasan_unpoison_range() as an
> example).
>
> kasan_save_free_info is a KASAN internal function that should need
> such a wrapper.

... should _not_ need ...

>
> For now, to make these patches simpler, you can keep kasan_enabled()
> checks in mm/kasan/*, where they are now. Later we can move them to
> include/linux/kasan.h with a separate patch.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdkHATBYG4RJ8rR8MciKmeV4QGwVwoQjkhc-O_igpUBTQ%40mail.gmail.com.

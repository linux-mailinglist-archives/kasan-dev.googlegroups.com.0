Return-Path: <kasan-dev+bncBDW2JDUY5AORBHV3ZPDAMGQE5QOTIEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id CCEC7B9717B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:24 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-36d99707249sf3384601fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649759; cv=pass;
        d=google.com; s=arc-20240605;
        b=SiN3Ov0qiBOjUImULTKTTusWg9em+VJ6nCs9kiETdVDZDIYf79ie0iVWXnc32YNXeN
         z4Ky8/vXyLYGoVCoep9vA36QIb3KjRFl1tbDGuT2yAmpodtJhAPg9iQdOP24+wqW55n2
         Q12onP3FdeGwiXgi8d+MV1JNvLVK4v+ZJwn6YmMKeCwkZeA6UyvVj1fULw8mH2O2djPF
         cOWRPEpIA+fycxgoZpgjdZpEmru74+traFLrolO8md/I2IoDH/qC7NMX72E/JFz2uf/S
         2EZIDoUCSvxjllVar/kX1XoPHCwccfExK58YwtpGq5MVOmiIYkt2ISxjVUETgVv/clNt
         Gk2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pZLmyq9ZgF3V8s9RSeBVbZ9vi15C1Rj5/bLfL6xU4bE=;
        fh=QDkwABnLZH0V+pW/CufMtoIIfTDo2r6Ah1GcfbIM1gE=;
        b=I4jzHNIl/fJArEGDbyZsr2v1h7aslbAbO+Z96L5jSuJUN0X7zuI40gJ0jBMWZlsEcS
         pPDP2eOcecF439qpDw4qXzNQMeGA3ayJYdtpSFXWHpyYeIXEF7tPVLXAd9BC15qjzTQk
         kmddy874KUY0cm3UB17qkH4in7ACn1DYDVPh/qz8Zx9JVeBBZqxzU2Nm6+d1ZDOp4U+y
         eWatYoQturYzQOctTvlJ3v5HbcAy20Bx5lGChFXGkp2pbKpWd/yGRYd4LpJeYe4q+6C1
         CNsl1L5t8A0t7CPGcjeahVcHOZAMdknoaAyBPHY0B+J+skA+Zd7VJ7SdydjWzQjR2fVT
         KThQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NfjSc7s7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649759; x=1759254559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pZLmyq9ZgF3V8s9RSeBVbZ9vi15C1Rj5/bLfL6xU4bE=;
        b=jIEuUtPllJ1CD0m/R5Mvg4Ap0TuMmlwcduzzQDGpU4tJVZHsHv6tVBHQGWvVuCfjvJ
         pA2XiyYcxLwD16dkPC+M6KnUJ+G1axfBQXqybqi5GkK7gKe39A1xKXmfXagvkAmvzWzX
         2lPPG9KxGcS1W2v6NHMrG0oKICiVhIDsiT9Frjqd+dm11Bkqrbq0VBCnpUjIrW5poDvV
         jHACp95kTmRvkcvscO23JWX9+q+JGkzxMxR4/qan0GsLli3oo1XyD46LoGmP7U3G9ssj
         EoG0rtmKBJh0rA9bEa5woernc8DyN19X2/Xz1oUUEKgl1/Kw++v2TgwrouE7kISkgxcm
         rUIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758649759; x=1759254559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pZLmyq9ZgF3V8s9RSeBVbZ9vi15C1Rj5/bLfL6xU4bE=;
        b=DwuTVZZ/21lkZsBjv+0JlwCGEz4l2MuFQMOxWVmJchUBfK32Y1835p1KWnGeX9h5O4
         Du9XDkvD/fPbvoVsabbVEQFYIe4OHdk/lvWNifYg9CLV1+YgUDHWIxtkW9PjunC48GJL
         HXAOCiwbKc2Blcb1AlBcDRGbTJhnU9wvFpVw8/LlUXUoG8sm3erlrAaz+f+qbWAnmDRQ
         YAZg+DEoNRhsZmag6aRxgukA5ogAsPINJjlwF8KaSLWcqc6+r8i/nwj8U951ckJcOT2s
         C2pgQOX/d0+7khkr17bJ44FowBqZZ1ykJ8np5nqQ+O0T5+ZLi9S7DMN46Clkg4fsT8c+
         NwNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649759; x=1759254559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pZLmyq9ZgF3V8s9RSeBVbZ9vi15C1Rj5/bLfL6xU4bE=;
        b=LhTldIoR5y8z+TG9M8vVpHT9ou7eUp9KLEKTON/abPTMNQIOOAL9dr6iv8uBor+WJK
         BgHyJalsnkBFxg6PfROVyeJTCmiaNbDuTu7Gi0nZ/HLQGR906bdT6rIqa5PcrtZCCuuh
         oDvWlKVgAoHgCw5jSLSSBedjNj+meAjXCqcrv86PChzkQi6AeuHOqndFL8SlMJ8FzRuR
         RpoFX61FhMkxgYJjeX92tGCSrX4mgq/nSpELmqOb77RX+Ne7sopAECKsRY4g2u/svNDr
         Bbu3/7LWcwipRydNvH5woQGaCAR09Zr4FiTv7jX97yqO7ELxjiyLYwwAfwCr05N4L8ay
         HNBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVCqVi5YMK43EcfI6pjsqXz7GULzud+TylwN2gzF3DP/gaLV/Q/SfbmjqIMkKKBInQtf4Q9g==@lfdr.de
X-Gm-Message-State: AOJu0YwZ1bakxLpS8fwyJtxn7qoxgTPL9hIXXeaG3Uma68PgxGCaUoVM
	BJ0wtxQQyNB4yXLbFPCry7C871znofKbTAeOjlcfqVFxbXKrGzdD18HA
X-Google-Smtp-Source: AGHT+IH9yj2fH3C3TkQKe4y1VoiMWFh6ayaio20xWWLMX6I+w2HSkjRZIxh7j5PX763jP2/G46yzpg==
X-Received: by 2002:a05:651c:19a6:b0:338:beb:88c8 with SMTP id 38308e7fff4ca-36d15b5c68fmr10234881fa.19.1758649758813;
        Tue, 23 Sep 2025 10:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7IRKbfA/ohDslURGwx2yUv+bUFZBYeGqZftFI0oHG9kA==
Received: by 2002:a2e:a37b:0:b0:335:7e09:e3da with SMTP id 38308e7fff4ca-361ca3d87bfls13814791fa.2.-pod-prod-04-eu;
 Tue, 23 Sep 2025 10:49:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJXLEZ2h+W20ARReGwylzOYD9gG4OsC+9zPvrtCQEUa5aeOSTB2V2lVZIpJoUFPYuYvza5GUbo+Js=@googlegroups.com
X-Received: by 2002:a2e:a00e:0:10b0:36a:6072:f8f0 with SMTP id 38308e7fff4ca-36d175dd870mr8402521fa.34.1758649755793;
        Tue, 23 Sep 2025 10:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649755; cv=none;
        d=google.com; s=arc-20240605;
        b=gAxLP5D14ChRyOu8lVqb0ZDpUD+jEAoU1IRzS7B9tvHHNHR7YExo5XDxGYgF5GbSkc
         l28KH7xKYzjVXTPQIQwwMT4YV1oJSBCcuuaLTtdJAv5C4zAHrh+NB2/6RbuGFg+JtyWf
         NDCHn4VQr5w8u5CnlbtSt/W/GKAWEN5duh+ln5MUMKMW7xJd0LGGrzeGkfGAQTqTe94/
         hBbA0/21PNeuVMODve+nuhudSVUA2a7LfBXTqazlGFY6L8y8x+MoPnSYkqoOrV7yE+Nn
         xTAQClQxAQsPNA7Im13rtIIec4Sg4fNaIfOSGRhwGF18zc5XYtT0gIEvh8xL0MG5Od8O
         W9mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ak83w47Un+0YVkw6h4ejJTiciQnGZqbDFJcToiU+0xQ=;
        fh=YgxhH1iANALYTcbtBhaP44URofoFqJyEtkF+x0GBWB4=;
        b=eSScUov7nvYaV/T1Ci53nct4JP5d6iRvVHxWUqj0h4RxQ+oC3C8UiX7+jNdK2EnNPS
         BfX2tzrwiYFizeb2/QozS6VguTJGZB4/syCKqeJ/cn2N7HuxQmZo9MWC6Z5jCY5gXuVH
         Br5utwOzs7gOlQyXnHmdr3mWYBPk+Ykj8PCq4SuRHrnKcQAoVpy+bp6809gZ9VimTwdL
         65ZTXHP0l+Ujj+vDtGJmVp1D7qHCxY0NCHLlcqrB2Yzzpt1nQEWheZYW/H/mhK/Oo9Ig
         zzF1Vg1A0L0lu4zN9r7uG1XFDtBS6pKxobMf9G4rsTIFfvA99G1cE7yN40AK/QpUNnDq
         76RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NfjSc7s7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-36e3876bbe4si20691fa.7.2025.09.23.10.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 10:49:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3ee12a63af1so2621278f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Sep 2025 10:49:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWIaEoAUHdWMY1hnPgVCHtbgnki9pqaCoRPpGSt6gvWpWXtUkOxmoL8kcNH9SzMrGrlpAUVgCZB6Ro=@googlegroups.com
X-Gm-Gg: ASbGnctwSAnNW5fmkO+haIY+G5ZCDBABSuIkLD3z75dF0Ks6k4pWipMLI66psGG6TwB
	y7/qUJmQV+h1LccGpuUfiEZfHkBIBBUr+7DYIJrgnnxhYwS/2NIOlMcXPkZgwvoCZSZ7QWL/qXG
	oifcUygXSuydY19kePyHRGTLywamCM2BgbLuKc/XrZwPiisoh6LrVv+0pV0ot7YM3VUDH513h8l
	TxjQPwpEA==
X-Received: by 2002:a05:6000:2585:b0:3ea:c7ea:13da with SMTP id
 ffacd0b85a97d-405c4a9734bmr2645479f8f.9.1758649754815; Tue, 23 Sep 2025
 10:49:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250810125746.1105476-1-snovitoll@gmail.com> <20250810125746.1105476-2-snovitoll@gmail.com>
 <CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com> <CACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6+nG-+bTA@mail.gmail.com>
In-Reply-To: <CACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6+nG-+bTA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 23 Sep 2025 19:49:03 +0200
X-Gm-Features: AS18NWAo7UnIsKkvCh16EnxIlUsef04XXrIh6VHPmyIq2HZ6eh0cMjqVLlDuPQw
Message-ID: <CA+fCnZce3AR+pUesbDkKMtMJ+iR8eDrcjFTbVpAcwjBoZ=gJnQ@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=NfjSc7s7;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Mon, Sep 15, 2025 at 6:30=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> > Why is the check removed here and in some other places below? This
> > need to be explained in the commit message.
>
> kasan_arch_is_ready which was unified with kasan_enabled, was removed
> here because
> __kasan_slab_pre_free is called from include/linux/kasan.h [1] where
> there's already kasan_enabled() check.
>
> [1] https://elixir.bootlin.com/linux/v6.16.7/source/include/linux/kasan.h=
#L198
>
> Please let me know if v7 is required with the change in the git commit
> message only.

No need, but next time please add such info into the commit message.

> > What I meant with these __wrappers was that we should add them for the
> > KASAN hooks that are called from non-KASAN code (i.e. for the hooks
> > defined in include/linux/kasan.h). And then move all the
> > kasan_enabled() checks from mm/kasan/* to where the wrappers are
> > defined in include/linux/kasan.h (see kasan_unpoison_range() as an
> > example).
> >
> > kasan_save_free_info is a KASAN internal function that should need
> > such a wrapper.
> >
> > For now, to make these patches simpler, you can keep kasan_enabled()
> > checks in mm/kasan/*, where they are now. Later we can move them to
> > include/linux/kasan.h with a separate patch.
>
> Yes, I'd like to revisit this in the next separate patch series.

Great!

But for now, please send a fix-up patch that removes the
__kasan_save_free_info() wrapper (or a v8? But I see that your series
is now in mm-stable, so I guess a separate fix-up patch is preferred).

I don't think you need a kasan_enabled() check in
kasan_save_free_info() at all. Both the higher level paths
(kasan_slab_free and kasan_mempool_poison_object) already contain this
check.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZce3AR%2BpUesbDkKMtMJ%2BiR8eDrcjFTbVpAcwjBoZ%3DgJnQ%40mail.gmail.com=
.

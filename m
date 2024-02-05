Return-Path: <kasan-dev+bncBDW2JDUY5AORBE4ZQWXAMGQEAJ5KYXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 626AB84A681
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 22:01:08 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-40ef88ff82asf11384685e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 13:01:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707166868; cv=pass;
        d=google.com; s=arc-20160816;
        b=eOkrzPtLywPR/4U9hhTSn+Iun9kGFFVo+wBQkefbvEzz4xfPgYlnylbiZ5h2cW/3AY
         vO/nxN+DxdyEhDQ3eQXp1MINNBIXpywif5Z7fCagrWsiE9qYHHfVe4vzcsYIKDF9dRXj
         yTzIF51uDsT2xyoDmPIGjXuBGGcE4RSBYThWXqBC4yeERMoMHSdF5eCX9XE9zbaXlduV
         mmwXVrgdPTrFBWoIipCtVXnwyl9Te5mpcmCkaDhbFmjH0eUt94KFrWZWw/Bq1xmmzbyZ
         FQaReVZsg8XkpwkLZdIuISj9eN7N7K+HfDlDslS1Nt9qKkv2tFCdnbFSc0waiXEj6Jds
         l2eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=G9LgNAGH0T2CiRuiYuqnwLPzShS1A8SeZMk4ozrBrBI=;
        fh=ghNVcSXI8KI7/nKr6VFmBw4oGvNzvZoozkujPOXW0B4=;
        b=CoPULV9tbasR9zN3lrcs8clhxM+5pkl5b2G4C/rf39nGz8oVneh11s4iDZjKvfh+iV
         veIClYynt1jvL22l5LjwL8M5d1jQLnQBqvHC20hAssIgE5Sil6COKcLu1zYxXKXNinXQ
         ENTYcHyqBC5zjeX53HsezmXx/h/35EIALWGeLJSVkdHivFxTy0rUv0mFkjLGkU9KH4DB
         eSiGaOMJRAgWsGFxpdH8iEtxJ/BXZF4PRk6//jfsPQFBYUC5MModoVUHMDjTujl5GXbd
         5XrJL495KXx8qfAOwTgI7tWJSQUKjlhJ3nKK4meVHnUt8dkf0sJbW9EUM9/Q/aUCXEfV
         d1QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EdZBAiig;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707166868; x=1707771668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G9LgNAGH0T2CiRuiYuqnwLPzShS1A8SeZMk4ozrBrBI=;
        b=XNlSlydIC2jrSJpDcmekH2ZsLKvIZoqw7/9D7V2iLHfpKAv4Z0BKIxXPtaCL0yjUEV
         jrRt9XojdCB6VlUEJImbd6RAKtN2wiPzr3wB2T/FMLq7knFGc4DUoXIqwwfpRya7Xbmm
         fmuKijJyLZWvSm+3sfIeC/R3K35BfCYcMPhcQl3eEE3+usW81YBloGuLB/q9RYvNYbHo
         jpBiogYTBfFYhwxZ5hiVMhfwcKkHsFUc6BlFHiVrUau3O54pJBbeb0u1fCg42n/JxLd+
         UDzVxNyZXD2G62WYHUm2NqMxokh47gtg0MovPN6dqu6+xDHGOnJ/Lk8OEIwn1sDEE9IA
         FJVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707166868; x=1707771668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G9LgNAGH0T2CiRuiYuqnwLPzShS1A8SeZMk4ozrBrBI=;
        b=llBQj/6bo2jlwDZ0P3G9TF+CCKjtOQIj51wNtZlv0V4Wq/1QWAJ8qb28imT5rbMYg3
         A11nprLQb+jW5MT8eh0q8QRsnJKj0HkOGMlknokowb8JLzBnyCI08zcGWrxYZ26iK23D
         ETJzu+cT+cRFx36+jEJ9IoZR5NofOC8lJ6WcCm/3vlifhqWqZYUAIJlVk31BFGZMcaa4
         /uzGoRoPtTcagSCFG4sRVJFsLFudeCEcviYYE+QYUQfYbHrEgUPL2/LCfhfak//r5btr
         ek6N5h0s6BFcFbzqiEtGDvcRU5mW+FjNS9bLUlZHPGYe6ma+7EWZwwQRwG8Wc6qcNnRq
         kJMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707166868; x=1707771668;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G9LgNAGH0T2CiRuiYuqnwLPzShS1A8SeZMk4ozrBrBI=;
        b=DLyYxNH3RT49mrGRw8ZP/OQEArc3pIVvEvcgXmFQPKANh4tYpsHDicyBv5QVYsA2FT
         mIsX6M52VEEom2i+r8G0mKse/ld7GB1mCFaFhLwgzSgeigi2Q3eX2w3Vc7iPg3M8CSU/
         0PwcbwuLLNmZG4yaCHV+w3JJp7TPfKgqk8JpUtrEc1YbCADtA7Pid7zqC/9gzg+wkpGW
         nLzzcJu3IFWzbSQJK3goSCHAfJyr426cLVS2GPcOXMFFtzj/9gmu7mD1imboB0rczhN9
         bdxdeTp7EK8uK0QMCsIsSk3u07SZX49XAQDeBruKxqoINhOjhpdhS7w72ZRnovETE+Zd
         0+rg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1cGuW3J0zyfL76vaiWm/FAD5+q8WXgKS1m1RMtBMqFOwpGrW997ZuvfhKoL2DM+8zp2TWJUMbeBspP0UK5HETF/gVUzWaFQ==
X-Gm-Message-State: AOJu0Yw6FKRrqnHBmSfEgxkVMWjfwZ0PVrmCrJLTiU88BYfmHujGtgfd
	GepAM0DIg52+Zyz+6go+J0dDF7wl1pQxI2GmpfCTP6Yba+pAgwbJ
X-Google-Smtp-Source: AGHT+IEsbXFueP7n6EFQN+2SRiRAF9nsXg2f7Rq8TQ3iqKnRkwVyAgtaqnjMe68OXVJXxl7b71I0Gg==
X-Received: by 2002:a5d:5642:0:b0:337:9a1e:1d03 with SMTP id j2-20020a5d5642000000b003379a1e1d03mr463911wrw.5.1707166867564;
        Mon, 05 Feb 2024 13:01:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:460a:0:b0:33a:e4f3:830c with SMTP id t10-20020a5d460a000000b0033ae4f3830cls155937wrq.2.-pod-prod-06-eu;
 Mon, 05 Feb 2024 13:01:06 -0800 (PST)
X-Received: by 2002:a5d:5f4d:0:b0:337:b315:5643 with SMTP id cm13-20020a5d5f4d000000b00337b3155643mr612799wrb.6.1707166865630;
        Mon, 05 Feb 2024 13:01:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707166865; cv=none;
        d=google.com; s=arc-20160816;
        b=Lev9GBglzdAXRs4pUh4MVIveERzeWRh0BWM92wWYnARHff4raV0fQI5PDJ7kby6UYj
         Mf2s4mrQm7BZ4bDUFVd/aCdB2Am3SRDxV6XXC90/V8NEYyBUvMGNm8T7r5tAFasGH0dN
         ndFayaGCb4kr9rn213D85dUTRS9r6nzLwzpcRhUj61pxNZZHvmVYsS3A420jekZVN21K
         RDQxMSvuXq+T9x8/T7csozBu+V2bLGNbG4xsA789U7Q7GhPawyX6jhGGrDJXWuCBnBUr
         TRjqTg8R0jTF2o1N0i9tKngv/Tpo+I2iUXs7EKuyL9U5rob9Mg8V8/f67qJcVrHtkO9c
         bcAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=X2K15Hg3yhqnl2UBe8X+/YSPQqkoXC0ybPHCaX0Zh/g=;
        fh=tTvP8edHSXUWtbIhEeFs7o4adVlCdZKrAoowsttWHW0=;
        b=qjyLtT/NEqSITs85FiSDQdacUBffAdHq8OdVQ+8u7ZHB4Hht9OcIe9yg0FNApTVS65
         nD77QnGuL2oD5+Qy4BF53nmsQILfTvK9x+oKxor8YQM/ioG+1FCAurJzqqhNqBc7bWkA
         SyJHFnaD7s8DE87q9YzYb0fCYQu/52q5LrRK1FQOpvT61gxbWMu0ZQ4sQgeytir49lQn
         HvKLBKgCGV4DUJGazkT4Hl2/tmc/40pvbLjw47UjkN9jS7wR+CyOJoM2NSqCadrb3I62
         4NHL8ONTIxRrMVNPOgHBz87cP/KZdnhCPLiayxGPIxuIxP+mqCsBloL1KgBdTjFlJ4Ix
         /yXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EdZBAiig;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCW5b+IJ44vkcMT6/zi5cQMf3X63v9BOGXokSz3JIhm2X9s9gTLGBg49a2vYILm16z7+7dxBw4k8Wjo9Jb/fTL1xxf+VQ3NqgpdVCw==
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id n11-20020a5d67cb000000b0033ade294ea7si29547wrw.3.2024.02.05.13.01.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 13:01:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-33b409fc4aeso775461f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 13:01:05 -0800 (PST)
X-Received: by 2002:a5d:4b4e:0:b0:33b:1a43:578 with SMTP id
 w14-20020a5d4b4e000000b0033b1a430578mr484273wrs.25.1707166864881; Mon, 05 Feb
 2024 13:01:04 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
 <20240202113259.3045705-1-paul.heidekrueger@tum.de>
In-Reply-To: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Feb 2024 22:00:53 +0100
Message-ID: <CA+fCnZdDxot_wms3XmZonBCo7=qkCSj72inhSX+zHNF9gkMv2A@mail.gmail.com>
Subject: Re: [PATCH] kasan: add atomic tests
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: elver@google.com, akpm@linux-foundation.org, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EdZBAiig;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Fri, Feb 2, 2024 at 12:33=E2=80=AFPM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> Test that KASan can detect some unsafe atomic accesses.
>
> As discussed in the linked thread below, these tests attempt to cover
> the most common uses of atomics and, therefore, aren't exhaustive.
>
> CC: Marco Elver <elver@google.com>
> CC: Andrey Konovalov <andreyknvl@gmail.com>
> Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueg=
er@tum.de/T/#u
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> ---
> Changes PATCH RFC v2 -> PATCH v1:
> * Remove casts to void*
> * Remove i_safe variable
> * Add atomic_long_* test cases
> * Carry over comment from kasan_bitops_tags()
>
> Changes PATCH RFC v1 -> PATCH RFC v2:
> * Adjust size of allocations to make kasan_atomics() work with all KASan =
modes
> * Remove comments and move tests closer to the bitops tests
> * For functions taking two addresses as an input, test each address in a =
separate function call.
> * Rename variables for clarity
> * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_sto=
re_release()
>
>  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 79 insertions(+)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..4ef2280c322c 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
>         kfree(bits);
>  }
>
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
> +{
> +       int *i_unsafe =3D (int *)unsafe;
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42)=
);
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, saf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsaf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, =
42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe)=
);
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +       void *a1, *a2;
> +
> +       /*
> +        * Just as with kasan_bitops_tags(), we allocate 48 bytes of memo=
ry such
> +        * that the following 16 bytes will make up the redzone.
> +        */
> +       a1 =3D kzalloc(48, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +       a2 =3D kzalloc(sizeof(int), GFP_KERNEL);

I think this should be sizeof(atomic_long_t) or sizeof(long),
otherwise a2 will not work as the safe argument for
atomic_long_try_cmpxchg on 64-bit architectures.

> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +
> +       /* Use atomics to access the redzone. */
> +       kasan_atomics_helper(test, a1 + 48, a2);
> +
> +       kfree(a1);
> +       kfree(a2);
> +}
> +
>  static void kmalloc_double_kzfree(struct kunit *test)
>  {
>         char *ptr;
> @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kasan_strings),
>         KUNIT_CASE(kasan_bitops_generic),
>         KUNIT_CASE(kasan_bitops_tags),
> +       KUNIT_CASE(kasan_atomics),
>         KUNIT_CASE(kmalloc_double_kzfree),
>         KUNIT_CASE(rcu_uaf),
>         KUNIT_CASE(workqueue_uaf),
> --
> 2.40.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdDxot_wms3XmZonBCo7%3DqkCSj72inhSX%2BzHNF9gkMv2A%40mail.=
gmail.com.

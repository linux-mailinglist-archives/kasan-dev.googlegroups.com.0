Return-Path: <kasan-dev+bncBDW2JDUY5AORBRW7RG6AMGQEXXJYW7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 06898A0A3D0
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 14:19:05 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-3061554bce0sf910691fa.0
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 05:19:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736601544; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9r9umuuk5hkc3dIhPwTZw8vblLaHGTX3wufC3WA67oe3YPhlsbpt5FRUG9aOy+8IZ
         qdSC54vNlNRWfUGbtVsmoOkq1IfLzJr7PqcERBpMX8weuqGpClm+uZsPLMRayWXILt2F
         f3upVgFJ1Nf3OWUj7UlxxgA4BNFhcSlCNyKDIZ2QCG6hwf/fSgQ9Vtcp+20d+Yfio+rt
         Y/rnnWXMAced8tV7Ew6EjrO5VhFm0kzXu0KIYDRJ71MJe/GkJbpaska2WqArBm5mcCNN
         U5dnXctG01MNV2K8JusfdB1/RCFX90EqQrMJHNMKWngNcrmotjfPyNuFeFXLKzuk8OmG
         18jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=yRk/JTlUfXITowVOcRonC+2LhlG8fAgb++a62XxyQa0=;
        fh=8YB/B2Ka99Db1bOTpC81QYlKhLyhguA0BjIZ2XPIwxs=;
        b=L7nBhIzXKe+zNVNS32tPiN94+2xYtDoucL90zUF+eA9oDHj7ZvU7Wa4WDLUfGPQ1c2
         WAUGEUvOrjZ6K9NZdioL445C54LKnaat1s5ha8vVkqWGroifVzCQl1STwxOqo9NaaLZS
         x7GA3A90gOKrw5XwrRgmDks2bwe8Ow7OtZ3gEwIsjlTMe/BQVqnQWJcp2/0McPArbwo6
         bvp72JcFcfbbWzOjPDlno7oWUQvSp9KXVaYqcbyPTMcKylrGn7pf0ul+5zJG52DG8BLy
         mgyvD7pHBWz/tlaUKqwuE/pyKe3KSB4KaeJrqajZc4AxORxfD/KnfT8xM1QY//+mpzZ8
         KOmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WT/VwXV6";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736601544; x=1737206344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yRk/JTlUfXITowVOcRonC+2LhlG8fAgb++a62XxyQa0=;
        b=m4CeIuoyLRT/47yWEfIZpZ9556q22LUUIjBTmLUdNuJePnvf2sO+mFruXJLVgcLCmq
         1+XljezdVLmkCAzKjBo3xQlKyPBB4JUmSLq6ukv9yMgWMR2ypEmIZjlAi08aIgjZV3Gh
         VMxKLtzWnwUSAUTNULXw88vcewwMqymyS10TPQJLB4sY2v0MMQkPbJQeKdnQJhMmoY6y
         RYk+hGjE4CcUJRlgJ8Q4IxxYiNFhY2yT3D+NQMkvWX5BZo+J4MAfJOktw7paiU8nI2xS
         r3q201DTB+PWKkRWNryNzYBPejLOlRpcgkL2At0WVia48Dynii1L0QK/VwCXQ8EKxgxV
         bK4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1736601544; x=1737206344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yRk/JTlUfXITowVOcRonC+2LhlG8fAgb++a62XxyQa0=;
        b=J2UAMz2sJhhovsei7nEVy1TPM4mKN0RDcIxs6OFKxtLUHLYRhD5ZgWLUEQaIzvNByi
         rSO1cQ78IptZYlQfXxeXaBm5pLbrjILzEDNxz9b9HXmZHjh+BoSWoFCfNxZjuKUC3mDM
         nsuNUpPiugAec5HrVd7O7GfdNwnuxBfLYvLeSf1uIVL7z308f3ARzGWy3pR5jbZsbw2E
         WvXoB7+4X5/fp1iS2S31vfdhJWl50upV3ntt4k23kELBFpvevXp/IDU2DKk4aTZdy7Bs
         fzNEAV19jOAjkvQgSLzUFRBGuztwAsRlvPRCmuLEirh/TiOAD4EX2DA3yFfjeM8gIM0y
         fluw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736601544; x=1737206344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yRk/JTlUfXITowVOcRonC+2LhlG8fAgb++a62XxyQa0=;
        b=AbC/TixO0yPW/gFSZ6WTLIpkoezGAvV8Tn1hlQtMSB8rZV8H9nb9Asy9yHyG1jFlTU
         zgllnPtw1z8m1NqIi7W1WB1YGBKttLMxiTkVGJgCKgmQKYWZLlvm/SiGCzGgbEUmK7Qn
         ROWy2vU3LkDUkYDvpzZHbSAR2ybIOFVoQOkFizfHgtccsrm8wbsYfCuMEtHTIa3NlW7A
         XSgQoHOv8PqpVJEZk2Rpsa/PhRjX/hDzNVAroUWKocIyub3MknVVocD67DlC9i5X73ci
         FMp5WrPxqHLGWUSwnzEL/XcimSpl3QBc4c4ZRtr3MDaNQOC5y/c2/7YI3qffGC2J5m3T
         b5Xg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0Gx3jtFzJMVzotLgKDRkXZNGCexvOztsBXyqqUtBY/mHxFIx12+XwGtUG71sGoWiK7Dd4aA==@lfdr.de
X-Gm-Message-State: AOJu0YxOstWP/3BdJ8EWRybtHpiBsh0XIFro16Tpmi3+eoORcRsc54bY
	FGLzXwqLGZH56ExMmDj7xe2jAvADidSaPyocxBSdShfnFQVlqsJ1
X-Google-Smtp-Source: AGHT+IFkzc5PVwjNFGOSqW+JGckiTz43XD8aZjIkit4TSx1iI5uDeoMvcpIRQSqbo6rzY4fOCM3w+w==
X-Received: by 2002:a2e:a544:0:b0:302:3356:7ce2 with SMTP id 38308e7fff4ca-305f454052emr45451631fa.11.1736601543119;
        Sat, 11 Jan 2025 05:19:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:894d:0:b0:301:2daf:3ea with SMTP id 38308e7fff4ca-305fce2db80ls10401fa.2.-pod-prod-09-eu;
 Sat, 11 Jan 2025 05:19:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUG3/I4MGlQgsLk9Ad1qaJQxok/I855Qimj3ZTkxzUev3btZHtKnXEXi3PJ3zB4DIxKkz+qx0ig1Ac=@googlegroups.com
X-Received: by 2002:a05:651c:2222:b0:300:38ff:f8e2 with SMTP id 38308e7fff4ca-305f453f9d5mr44845241fa.10.1736601540264;
        Sat, 11 Jan 2025 05:19:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736601540; cv=none;
        d=google.com; s=arc-20240605;
        b=Hg2cynaZh8fIpg1G4FexG4gsYtCxcFtpG/D4T+c2lhF9DopmN4xqquWPp66MqERybL
         c9HB5/3B/dqYxfG/h5b0f66G1UbF4sXdQPBMNWyXjEauKyyK0AkRVC3tCcOYSdNCRwLY
         0MS+1jNB+3fZmVUi+9nn3zGxGnJIiqvDAUKCvNpkOCPZq5FJdxZvyMrTZ0XEgERF49mq
         6OvqgMtcAHQ8uNv57//ZPR9ChYivcHsf2U4clYaA6XOlfXfuw7KU27KBMBhvb95j9nGZ
         y6geV4NClGhxMpkzca8oe2/o50WUJSjGGvXU3zQmmK7j/yZ3BiZySoNjnDqI6nGqkd7x
         NRTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NQ950WLlj0TBvIMK61SXRto978+YceITtIyuftoObTc=;
        fh=oJ+RbW8NrPTpMU8hFXjBj1jLNxxXGrm+K1H3Y3E86Ms=;
        b=cTgy2LCPHlOohuq43YiDdsPakS7CjiGsgEOmCS19b1nKFnjel5A+muKznB4oWd8Xu8
         aqq2+nglZ8LvgX2I2xUd78xRvPpBme2d/ateCOn+zHJnBjOWFAOIiUWbaTu2Bd9UD4E+
         yhV9U0IlrBaUALRuvcaHu4G9yHnmtDuC9k5pYB08jysUXbcJxRI/rEN4ViBuBZmJaJul
         r9Adwh6AGj2/5ph6ge12ngIUPH+/yhAaLyd9gNltZtYKpR48vL0txB/XChfSWK/mOgsR
         93o+TBKz4W4fGZc3vWQ235wuKAdxFAeafdyyiFo3bsAYjJ8hFvea4EpEzFbsCap7QII/
         tvcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WT/VwXV6";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-305ff17fd21si1086681fa.4.2025.01.11.05.19.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Jan 2025 05:19:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-385deda28b3so1734336f8f.0
        for <kasan-dev@googlegroups.com>; Sat, 11 Jan 2025 05:19:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUKSeiYov6LYclyWD7wc42VchvKnzFL2yEoL+FAVqAwdSxHsGQy9oOPmRscJMyOsHkPssIl87ySs0A=@googlegroups.com
X-Gm-Gg: ASbGncs9itc5fRDrPLOO/5ZFiD+gg+XZ+z5/5SYOCysqBUw9o37RX4MX523lnlt+5ot
	r1KbQdv9x2To4/weN3iIOk3DV2qPXr9I4+aA7QOVD
X-Received: by 2002:a05:6000:712:b0:386:459f:67e0 with SMTP id
 ffacd0b85a97d-38a87304a47mr14921574f8f.21.1736601539309; Sat, 11 Jan 2025
 05:18:59 -0800 (PST)
MIME-Version: 1.0
References: <20250111063249.910975-1-rdunlap@infradead.org>
In-Reply-To: <20250111063249.910975-1-rdunlap@infradead.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Jan 2025 14:18:48 +0100
X-Gm-Features: AbW1kvZV4f2eoVrTO-A_9JWr9GI6zUELEgGiQ3ZEOk5kb1EAhJPWvtc96tf99bM
Message-ID: <CA+fCnZeTQQ6dCY8Fu6PwDwaj1DrGR3CJVQO+Xi_xMbTf-xta_A@mail.gmail.com>
Subject: Re: [PATCH] kasan: use correct kernel-doc format
To: Randy Dunlap <rdunlap@infradead.org>
Cc: linux-mm@kvack.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="WT/VwXV6";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
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

On Sat, Jan 11, 2025 at 7:32=E2=80=AFAM Randy Dunlap <rdunlap@infradead.org=
> wrote:
>
> Use the correct kernel-doc character following function parameters
> or struct members (':' instead of '-') to eliminate kernel-doc
> warnings.
>
> kasan.h:509: warning: Function parameter or struct member 'addr' not desc=
ribed in 'kasan_poison'
> kasan.h:509: warning: Function parameter or struct member 'size' not desc=
ribed in 'kasan_poison'
> kasan.h:509: warning: Function parameter or struct member 'value' not des=
cribed in 'kasan_poison'
> kasan.h:509: warning: Function parameter or struct member 'init' not desc=
ribed in 'kasan_poison'
> kasan.h:522: warning: Function parameter or struct member 'addr' not desc=
ribed in 'kasan_unpoison'
> kasan.h:522: warning: Function parameter or struct member 'size' not desc=
ribed in 'kasan_unpoison'
> kasan.h:522: warning: Function parameter or struct member 'init' not desc=
ribed in 'kasan_unpoison'
> kasan.h:539: warning: Function parameter or struct member 'address' not d=
escribed in 'kasan_poison_last_granule'
> kasan.h:539: warning: Function parameter or struct member 'size' not desc=
ribed in 'kasan_poison_last_granule'
>
> Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> ---
>  mm/kasan/kasan.h |   18 +++++++++---------
>  1 file changed, 9 insertions(+), 9 deletions(-)
>
> --- linux-next-20250108.orig/mm/kasan/kasan.h
> +++ linux-next-20250108/mm/kasan/kasan.h
> @@ -501,18 +501,18 @@ static inline bool kasan_byte_accessible
>
>  /**
>   * kasan_poison - mark the memory range as inaccessible
> - * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size, must be aligned to KASAN_GRANULE_SIZE
> - * @value - value that's written to metadata for the range
> - * @init - whether to initialize the memory range (only for hardware tag=
-based)
> + * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size: range size, must be aligned to KASAN_GRANULE_SIZE
> + * @value: value that's written to metadata for the range
> + * @init: whether to initialize the memory range (only for hardware tag-=
based)
>   */
>  void kasan_poison(const void *addr, size_t size, u8 value, bool init);
>
>  /**
>   * kasan_unpoison - mark the memory range as accessible
> - * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size, can be unaligned
> - * @init - whether to initialize the memory range (only for hardware tag=
-based)
> + * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size: range size, can be unaligned
> + * @init: whether to initialize the memory range (only for hardware tag-=
based)
>   *
>   * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE=
 before
>   * marking the range.
> @@ -530,8 +530,8 @@ bool kasan_byte_accessible(const void *a
>  /**
>   * kasan_poison_last_granule - mark the last granule of the memory range=
 as
>   * inaccessible
> - * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size
> + * @address: range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size: range size
>   *
>   * This function is only available for the generic mode, as it's the onl=
y mode
>   * that has partially poisoned memory granules.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeTQQ6dCY8Fu6PwDwaj1DrGR3CJVQO%2BXi_xMbTf-xta_A%40mail.gmail.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4HRVOAAMGQED5DAA7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B212300847
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 17:10:26 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id m9sf3364953plt.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 08:10:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331825; cv=pass;
        d=google.com; s=arc-20160816;
        b=J4bOHgwlH5HzLtdQIjp+SFbHIvnnHP04R7nndLgaSKm6NSNkHONQ8JX0HrXATSDTIX
         kj5NazM0LErXSK1whzmLsnEkMF7bv3oI/qMFIynNYJqdqAn+4JfGTrq5ddilvD2QzQCq
         6st5tlM4cc51X3qLuL/cXS+oqcuKdMcd/pRd755uE/Occ1cWKDtH6yrf8gKRNVec2KV+
         +PT028FpU2bvf7BjIKKXb0p82d4MJlnQYXDojG5aPBDxsuSXNRX7sA5arbPn4Y3+clYH
         Xh2wEFQ5w/Wr5/SLt2qPhqpJAsfbtEySGjRcwr5/KPms0Ve0ZS+B11rG0MVdFrZVMX1x
         gESQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XKf7kLguSEGpCIbLGRWJxlIoe3NSHZiBHsDYgno6Bzc=;
        b=LKocaiTRFhsIe1oSD6XfuthImj4LzyVUCcxIO4GeTpbrRJMf2525//PpFVKnQUbpOA
         FNgUoZ4Ftcs2nZZoQduq0+wrczUwMC1hIQxxKc6mdSxjIZ+jyG5HoOvYVnpyP6Df6iKI
         NVfDBO/avdZ+0+GyoCGqQWW6YERycr9QLnuTPjlybukhElg1J2/7V4vcCmRAyORsCs6G
         zJEUBTVdombx3es6aCDu804I1B2l/6RHglKOsUMpHlmJOgUc68uomSoruUP24L6j6+wZ
         8Iv1URgnRhU8/qUTiZXFckz9kehrNY1S02EmuG887wKK9+j+Y0ZyMsa4bMi0fWCjdf1M
         EYbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O8DuFrQj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XKf7kLguSEGpCIbLGRWJxlIoe3NSHZiBHsDYgno6Bzc=;
        b=DeUTQHKyfYzEBy2JCPro7/YjkgV7fDY2RfuylUwn4H1cMFRY92W1XOQmWvBNc0225n
         tzY4E7AZYgSbN4r/Xj7nqo5p6xk9+SVh7T+ZkDD0SeRZo3HbpKFvaohBAwthjlxFucVi
         QQgJEUVrklCXX9nlxaMq4DDQqMo/DEYrkE6urBjkOug7yciv99jHVQRPBBSYMez8LQUX
         htDxIXWS/ERklZzGi/XIgsLNVD/2lbrfiljTbJHEm88sBbSgAugp0qZVHeI8z0SYesNf
         1GhgzAyGyS/ppwbeCLN6jgHxqR3fQ6mFybci4XlV6cJOu0EZIkAo5p4rfdQXvqbxwHdy
         2Isg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XKf7kLguSEGpCIbLGRWJxlIoe3NSHZiBHsDYgno6Bzc=;
        b=hXzzPg0KW6wvEUaIXMT6jm0PPR/tR5pZ98+LwtBdd+/WVKqjo8H2d6hmykfAb5MtAV
         oTUj2Js418JTRqWOffCu58oMWOyZ5jcu9N9HZmACD7ojgS5q3Vl2J/1ZL2EPoX/CKVBJ
         Jq5LYsOvReqRPRljaC5JimmWM+Aum1UW1YvzYnVeb/sO0/7Vzas4w/aTE30OExk996Oj
         Rsj3fFDc6OPG3NarOr4UxDdpNeP2mMdxsWUQeQ2mDM9MMu32YgdyjIhs3TsmxfKdUIP2
         eEj3chW2sn34QEA8dbAjQVh9AtRpfN7m3FoKyNcvcbyshtJpL3vx3NGtr7R72R+TpGRe
         A8CQ==
X-Gm-Message-State: AOAM532Nz3ydCa1tiLuFgTBpF7iNTq0lVlmA1/RUWV/5//6fX0HWkHfQ
	i6iT2fQj5bwGOZ8dji97PAU=
X-Google-Smtp-Source: ABdhPJw67epJpdRIMJFesDUtLQ6pkzXX9tckUA03DneA8sDZc91qwy5os5C1ex/r1VAlcdvwpTYGFg==
X-Received: by 2002:a63:ca10:: with SMTP id n16mr5162155pgi.105.1611331825051;
        Fri, 22 Jan 2021 08:10:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9309:: with SMTP id 9ls2324363pfj.0.gmail; Fri, 22 Jan
 2021 08:10:24 -0800 (PST)
X-Received: by 2002:a65:644b:: with SMTP id s11mr5377972pgv.4.1611331824457;
        Fri, 22 Jan 2021 08:10:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331824; cv=none;
        d=google.com; s=arc-20160816;
        b=ZHjxSE1ZTxXZcLuqkHCw4I2tRRSXBrRemn+po49bsbLdL/cRdB04Vet/kpmpciRurL
         hFmaEetZkIobvve2/KMCeuTniGMNWavJXMjBHnYJx0/dR4ZxV3OXcnB6aM2HrxeaD0qD
         PEjxRn6ZM0R+0862eMjehft08YfnTs9hRe0kPy/o31WqMYco3DKFI5+2RQK0bp5uC39n
         D95rYnASZGoI8fyR6wIjsDVYuSyIAgca7leOHQcP02WDU7+ligJoU3aIY9Iy/4iYfCEN
         tGeLwoaeWny1dSD4Hm+kAiPvTQjn8OVzQ+Dy2M+MCN71PWcTDddp/RsL35yI4NkguMSL
         qSkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dJPr/tLBjltEO+N+N4HLyjzEYnzxewBiyXdbKYJ2UPU=;
        b=u4z/bKAwojhOk8Za0HDGtmAoY9ERB7kS/5FFCBxCyG6l1Ldg/RsXSTb4PyWE/ZSOTH
         YJwIrA3U2Q0js2NZXbzJ7j7BTe/iBEslvlkEIZS6rGWO1B10dYF/TEQhC0qEyX0Y0mTg
         NYvsFBf+lb9JxUJKsArp7hTj94m9k2J148YLQybgMe2t/oc0F0NLafYwaLiQr+fGttc0
         RY0WRq7Tk+qbf/UlD6Won/deDdPdCZG8ZccxWZ79+cqxa/g8FhePIdrTb/YVM6Y5AtBM
         +r4riTrd95yTo0O3qNPxil7sdbBuQzJQsbER8YQJfq5L6La7T51ZDfxcICwWQKgYOTQr
         XmYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O8DuFrQj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id d2si605407pfr.4.2021.01.22.08.10.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 08:10:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id kx7so4004459pjb.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 08:10:24 -0800 (PST)
X-Received: by 2002:a17:902:9009:b029:dc:52a6:575 with SMTP id
 a9-20020a1709029009b02900dc52a60575mr5072205plp.57.1611331824008; Fri, 22 Jan
 2021 08:10:24 -0800 (PST)
MIME-Version: 1.0
References: <20210122155642.23187-1-vincenzo.frascino@arm.com> <20210122155642.23187-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210122155642.23187-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 17:10:13 +0100
Message-ID: <CAAeHK+yc2c1x2cENQ03xcDpYNPCHgXDP1Sez85b+ohyz1CW6gA@mail.gmail.com>
Subject: Re: [PATCH v4 2/3] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O8DuFrQj;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 22, 2021 at 4:57 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> With the introduction of KASAN_HW_TAGS, kasan_report() accesses the
> metadata only when addr_has_metadata() succeeds.
>
> Add a comment to make sure that the preconditions to the function are
> explicitly clarified.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Leon Romanovsky <leonro@mellanox.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h | 7 +++++++
>  1 file changed, 7 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index fe1ae73ff8b5..0aea9e2a2a01 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
>         return (void *)arch_kasan_reset_tag(addr);
>  }
>
> +/**
> + * kasan_report - print a report about a bad memory access detected by KASAN
> + * @addr: address of the bad access
> + * @size: size of the bad access
> + * @is_write: whether the bad access is a write or a read
> + * @ip: instruction pointer for the accessibility check or the bad access itself
> + */
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> --
> 2.30.0

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byc2c1x2cENQ03xcDpYNPCHgXDP1Sez85b%2Bohyz1CW6gA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBDW2JDUY5AORBOEIZO4AMGQEXWUOGIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DD229A47DF
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 22:25:30 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4315afcae6csf13426925e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 13:25:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729283129; cv=pass;
        d=google.com; s=arc-20240605;
        b=lt16/1Sp9jgg1P0O8WIbsfJ6WDrv79fCqDhxD1dPp0Oo9Q7410d/jnIKqxiSfebm4x
         2e+gMy1V2WeAPSAu8+Pn4st6Yqa1c8Nb8iaT+ST35qFOB5AZEXmdQRIseZGfBjZi8aMe
         DJBGHP6EZOnn44bA2/eGngIZRP24NF2q1NPLB7c+7Fcm1+UcKvjcknyLsRGnXwQFjBgC
         OTc750x+TouN0fSS+nki9ahWYTGIjHCbbMgVPSjnR0RMdpL7i1qitlgkmSyAffEUFsNU
         IsTnmqZGMQqYsEC+gXTMsXIySJsNEkKvi/hD9DWkPcXjc/0exMEDlDAd9UjKXmufQQ/z
         4ZOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ILPb9PO+vwsgiHJ4e/QY1yF90xbtb3IkhmQ/+B1PKuA=;
        fh=KnSWNu7vsyFG3TU9kBbB5eFxET4tDJ1B39vw/wUXHu8=;
        b=S2v82jcaMIVzUGG0JUygyUIIiZjrUt38+OZTytNjykGqP2VYtN7JJMjWqZBlE9ad0a
         sKP+iElDB64yPtm9JU7nhDfpHX5Ziwkt9bpsbXJSirBxpn9QceTQK2pPKTA4CKM2H+XR
         Dz+jDSNeWnjAjAPKttu1rx6ngLVXRl/kglN2PDcWvidFSJlbFJGqDwwKQAXc2ZYxS291
         GslvRYKIf/M3wxhKILwOBTbttKO35bSYm3qpGTdy8wLHwsE0LIC9qb7JqmmjyIOY3N/h
         dJJRmb83hf1U7HA99LzpPjiygrTtFu66iU9JjQFvdn/eDGympgO0QcCup5znmhbM4Mc/
         Jn9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="XTy/CGre";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729283129; x=1729887929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ILPb9PO+vwsgiHJ4e/QY1yF90xbtb3IkhmQ/+B1PKuA=;
        b=lKWo0S5nZ9ADq+OHIXYEPjYhUv+CFzNSUlPKvVbUiMY5O8Pj9cBcBJUytyzCYab9gJ
         /x2sbI9gtglrUthHIF5Q7QJvNNXeVYFkdfTCVnfrj99dbU8pWy3PgBNkeZBTuIoG7DFs
         TXcrUj0LRvEQQwjYVjmlIac6s4qHBu3PaYSZymmwM20DF2/W3MKCqnESIsExMulyLlaA
         k4V1J3MNRg/ToEus5cMHy54EyddG+Z+GGQ32SBSYAW9tVSAMBC4WRU2hqM8Ar3Ndy7iM
         jKC0DAQGQR3IkaZH0hnjRGD8dyIWh7FC6jTdAU9zuUopU+sdrCCsiU2XphIc240k5ONH
         5kmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729283129; x=1729887929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ILPb9PO+vwsgiHJ4e/QY1yF90xbtb3IkhmQ/+B1PKuA=;
        b=NnGrioRF04raeke9lMJ7rLP/Hoa8Wq9obmx2yd47jok4F58/DhczaofP48uDThP89d
         653LYeQJvgEUYqzpu7m8Ji784tx0FkDOgdin+aYQRrJkmRdTsTKej49R8r1xRgIBVjez
         /msXM5C3v0oVuWSgNvEISVM516t9w/Pg1jID06susRyAvO9Q+SBafcWvcUH1ewijH/MD
         bewjs7qc9HxoRkKigpLynpDTzVtXf9ETDn8AW8Jbx/C+6lYUv8ZeI1sAJyqizQei7+vZ
         5mBP7dAPpjLxs5VkDFAvSh2PaFu+5yzLset+Oma0WG15n4Bdpgid3UZzTZEXuUb2klHG
         1oaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729283129; x=1729887929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ILPb9PO+vwsgiHJ4e/QY1yF90xbtb3IkhmQ/+B1PKuA=;
        b=KP5bOYJdPvODuKSXKhjTgUgupgETDtucWGVq6e7mdx9gcOUdxstw1CkkW8AUECBuN9
         QkIh6E660Y3f2JNGWm7Nve+4LCJHI+uvGohJaQYNeRVoTnH3oVvAX9l3QSO1aIZ4qkI+
         a4NsHAF9DwWy1wBhJy1Ie9kxO4SjQMT/QrZmYaOPSbJLx8MAINcV6al+fYlVesrmt9gb
         E5dZG4zoDkwEK/Oc0PyqLCrp4mjtAA1hT4Ra6iHfqZbHFseZmZbWetFAbLov916Ohphi
         n5WiNL1WWUp2QyYbTwLh/+A7rjJgAwzSxuYkb1TnCnrP6CUK6P0qj4Qo30Cs1iXuY1i/
         3D5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCRzTVayv6VyunJL2cVPLJuH8NWaDhTbXK+DoWr7IHyxufpCF3OmpiSi2cX0GHmjhexAGi0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx2Cfs4QTq9Nj8ZEtI3NBuxGvhTJ27tnp4kuR3xCMSGksy6YRjf
	J4ErT+tl0DV1S9evZG1lMevaWYcZfuCPBg0afAUFIFFxWqqOJ8LD
X-Google-Smtp-Source: AGHT+IHjq3g/xvEgg4HZqDbhTOCjQTbRf7GBMkf7xX7L/APCbUsCH591+jtGFVBYWv6c6MCeUjDghg==
X-Received: by 2002:a05:600c:5110:b0:431:52da:9d89 with SMTP id 5b1f17b1804b1-4316161df7bmr24261925e9.1.1729283128831;
        Fri, 18 Oct 2024 13:25:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:450d:b0:42c:b22e:fc4f with SMTP id
 5b1f17b1804b1-431588280f7ls6371045e9.2.-pod-prod-00-eu; Fri, 18 Oct 2024
 13:25:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUk+Atg6W0vAiP12rmo0c5+Y5tqo+nKHoj6001kaIjJgtuOShpAqQDZQWSBLQ3Ra6IpIh0O8odXZoU=@googlegroups.com
X-Received: by 2002:a05:600c:3546:b0:42c:b54c:a6d7 with SMTP id 5b1f17b1804b1-43158756e2emr55347635e9.14.1729283126962;
        Fri, 18 Oct 2024 13:25:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729283126; cv=none;
        d=google.com; s=arc-20240605;
        b=QvluxSyJZ8NlspKX5ekBPGAhTPYlJoAxXDf/plG1+2zJfhcrb+H+INknGcTbJ0BJ1O
         TEUsY8WaOGKMUy5Jt0BFrAFwEX4hBOqOduwGRG/1IV404brc2AS0Z9Q5hYUY8SacNBXZ
         AK4hrXg5G1eEiSRxjOQf4N6UBQoYuUt0ww2N89lGE8+8Kql1NPsWozqCImgM/DVpD1ma
         0KeTT3E/Zww58okVoO1wHDRJPGAKDJAQvisL6A3IT2ufDapAYgsoMVV2Ox3/Y9q5+ndD
         3/58cAZA/1AdTtLRN2XsTS/9fN3CAab4g6Bl5Z4mh8FeArCqcRtTx395OnDYg+K7GyGy
         IwKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QAHVI39XorAJ2sHNdw9fdsNt3NLLkABuKEzRhxqlTh0=;
        fh=OAgW7LMDJZ6f2y52cxi8i2/innnNcMjBimtnKBiqAVA=;
        b=UJ+nLbmWSV+iP1MWLst7DCNRrLQXnEwMFJvXKhyQ+xaVIkP4/hArdMf+0ZH+g9bIx1
         UvGFCOX5IadniAdk201SVmxiWpEbIEg8CpmgDLin5y0gbC8uLDkqt+yk1uivhU81E0M8
         9d3rgblftMm4GJYTDnJUw2Vv3Mix5YeL8BjUl9+bHx6Fvfpp9iCaPsTv4rtacqwpdGKU
         Y4Pe9eCPdf/zx0uEghIMpZ7X0kXfuIJgCpHwdQGXcYDpV6zMK/PPBELOvZc6kTqy2vcS
         abStGWc3zK0OtlaPTfn2V99v14cL1XFTJkY/6Id2IA4NKvnr2UH5cA+o8XvPZzGyELKM
         aIXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="XTy/CGre";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43160d3f348si502365e9.0.2024.10.18.13.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 13:25:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-37d3ecad390so2614709f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 13:25:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhr2MM+NeAKufodKrY8HW59HJDIvOfYwP5XOCchh8YlVHrQN9v2TDvBy8UMWhLFko1GOm4Zk3AGcc=@googlegroups.com
X-Received: by 2002:a05:6000:144:b0:374:cd3c:db6d with SMTP id
 ffacd0b85a97d-37d93d43e12mr5419328f8f.6.1729283126217; Fri, 18 Oct 2024
 13:25:26 -0700 (PDT)
MIME-Version: 1.0
References: <20241014161100.18034-1-will@kernel.org> <172898869113.658437.16326042568646594201.b4-ty@kernel.org>
 <ZxIeVabQQS2aISe5@elver.google.com>
In-Reply-To: <ZxIeVabQQS2aISe5@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 18 Oct 2024 22:25:15 +0200
Message-ID: <CA+fCnZc4iNa_bxo8mj52Dm8RCKAW=DQ_KUSKK2+OzjmF3T+tRw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	catalin.marinas@arm.com, kernel-team@android.com, 
	linux-kernel@vger.kernel.org, ryabinin.a.a@gmail.com, glider@google.com, 
	kasan-dev@googlegroups.com, Mark Rutland <mark.rutland@arm.com>, 
	syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="XTy/CGre";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Fri, Oct 18, 2024 at 10:37=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > Applied to arm64 (for-next/fixes), thanks!
> >
> > [1/1] kasan: Disable Software Tag-Based KASAN with GCC
> >       https://git.kernel.org/arm64/c/7aed6a2c51ff
>
> I do not think this is the right fix. Please see alternative below.
> Please do double-check that the observed splat above is fixed with that.
>
> Thanks,
> -- Marco
>
> ------ >8 ------
>
> From 23bd83dbff5a9778f34831ed292d5e52b4b0ee18 Mon Sep 17 00:00:00 2001
> From: Marco Elver <elver@google.com>
> Date: Fri, 18 Oct 2024 10:18:24 +0200
> Subject: [PATCH] kasan: Fix Software Tag-Based KASAN with GCC
>
> Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not disabl=
e
> instrumentation in functions with __attribute__((no_sanitize_address)).
>
> However, __attribute__((no_sanitize("hwaddress"))) does correctly
> disable instrumentation. Use it instead.
>
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> Cc: Andrew Pinski <pinskia@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/compiler-gcc.h | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index f805adaa316e..cd6f9aae311f 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -80,7 +80,11 @@
>  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
>  #endif
>
> +#ifdef __SANITIZE_HWADDRESS__
> +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddress"=
)))
> +#else
>  #define __no_sanitize_address __attribute__((__no_sanitize_address__))
> +#endif
>
>  #if defined(__SANITIZE_THREAD__)
>  #define __no_sanitize_thread __attribute__((__no_sanitize_thread__))
> --
> 2.47.0.rc1.288.g06298d1525-goog

Tested the change, it does fix the boot-time issue #1 from [1], but #2
and #3 still exist.

However, perhaps, just fixing #1 is already good enough to do a revert
of the Will's patch - at least the kernel will boot without
false-positive reports.

But I would keep a note that SW_TAGS doesn't work well with GCC until
[1] is fully resolved.

Thanks!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D218854

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc4iNa_bxo8mj52Dm8RCKAW%3DDQ_KUSKK2%2BOzjmF3T%2BtRw%40mai=
l.gmail.com.

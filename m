Return-Path: <kasan-dev+bncBDAOJ6534YNBBPWFX63QMGQEVAU4DZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E8E6A97E0B4
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 11:26:23 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42cbadcbb6esf26457015e9.2
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 02:26:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726997183; cv=pass;
        d=google.com; s=arc-20240605;
        b=KQAsynRKWu3ZtUjjti2+wn5TzL6JwZbfdu4D5nboAspQuK8PiyvRDsB4OacnZLKF2w
         Gmob1oMW/4UrvD/XhBRanB9PpAwAyqkFqOjwFstgXz3V73xV62QVZCDRH1OTSrWjHHoX
         ODmMoDID+anhP5MTSTDdB5eXXcJ9IKTIevQmf+8636OwXlNua8fgzy5xnDgEVH/MjjT1
         EsTXSHixhOdgMlFHNLTKOb1wHsTjbd6nXrRR1RNtSd7OU7lzKpaxkORy+CZmQ54/MKem
         9tQ8NBTD1mA8Fv9Ou+fBvRorFaVd51Jrbbwum19FE+iw5hqIHXJHRwsdg2BzaaYK9jAx
         PLHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=U9zoQC7gvimP02qEIUL3oXIJHhg77ay15PX7s40I0Gg=;
        fh=ZlfbCXN4HspGJ16PH7uUWnSB0H9liOiQu0kun2aTMNU=;
        b=kTf7VuTqFW/1Qc25DKbYvjj09Ud/NiQ8500fE/Wxx2ZEMMoDv2KTS+xWX90cZFAzS7
         zV083myjCJXFHnepK3OOw2r3vpGeHcErS6xm3hSgEJ1ouO7p2L0nUXepy1DxCLwufeef
         WiSxkAoL3nLjZiTQYhuhkqfjMLs4Hclp8q9JvQgJrYbxWl4+pq1vdWYWG8zjKQ9+3zev
         N+HxdlfeRFNCdoOMsrnyRAuyYArZd2A06IwUqdskRXhHIxxBur7sUYoKeXCopzvqlBJ6
         Ra57wgTf4mUvEFr6op1VQ83xoVHJGvpJ1FZQxBwejLYVLV/0L4EVyQ4Q/gFBOWDoBuh3
         TKow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y8bsdsRW;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726997183; x=1727601983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=U9zoQC7gvimP02qEIUL3oXIJHhg77ay15PX7s40I0Gg=;
        b=vsID+ErRw00/nitFE1ftfKCJZjajVPSvFDA//igQe8W+M4eMIXaIMdNTM727H3BNYb
         IB+S9jCES4xWREgYZDy7MwMSbyeHvK44BfZPLu/j7Qq3RtxJii1IBqWy6kAiPur1hffR
         6nNO5OAvpg887oQRr4s3t5w3sSD+ldbXTBxeu/FNUdmMPaidl6VrLMyrTYaidEuyjjUL
         RFghwYfd50qWGFYm9RNOgvk84FqciFa2e7yoFvvg7PCMWlVTqGimG37AhfKJEnS46xhz
         iNWrjYouRWH5ZalODDufHyo5YrtqwJClk8H9ILaVsFFkvTT2djqBiVd4mBIz3WMmeHLS
         baxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726997183; x=1727601983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U9zoQC7gvimP02qEIUL3oXIJHhg77ay15PX7s40I0Gg=;
        b=cQP7pz9AOzIt4vdXMHrgwnJifK4TaeIvk5rciU8E229dMWtN/HLbXjJGR0siGlfi5n
         jDbiKcqAdhEfKqF8ac/af2l3Elvxj2YsIigu0i1i4BcafyowFVS/P62G8YnZdRLHGbNs
         Xreea9uqAA0EzLxE0AlbmfiEvsAj2rs4HSjmda63rLH9xg+ly6U6ebwFHRGmoqERq1QE
         Yxk7FOL6jD97R1YAELz8ljxWUlu2OOZvHdWF5c0ICsNEftRd22RUFZUZBPYamCU2wi+X
         7wRjPZbOdfxPXXfrHj5Y4gHGzYwedQbY88S+Xuub/vr6M1tDf/sG7Ivmew3Ignfx8qhn
         6Tfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726997183; x=1727601983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=U9zoQC7gvimP02qEIUL3oXIJHhg77ay15PX7s40I0Gg=;
        b=BklR49g9QQwKbfI+iAwhTZP5mSW9egU59LKUlFh6sJJE0bxgg4T9Qg6nCcITYT8Ehl
         cLH1NJ4rjAPLPzQ0DEDGWyU2jvErYau74i0SOG5BKrpZjtZ8kvroX8pzFhTpeHpNvFe8
         fvaEkFMrcigQdGOI46IAwP5eOPUSz53/27KkCG/OA3ZZ1Zk9FK9kVv5jshI6BOArdK3w
         TDqf0c9CaeuNQrndDP2fO7/LQjcxeWLMxeeyfWu1nQHDx8FsPbj/1U8J+8LTNPhV8FJj
         5+K5iY19U9uQjps4XvTgi1RszTv51pO0KO9UdkYBzX0wjLprPKShehm5mhYZenUnlWRQ
         QoKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVA7qjPied+GQ4LSY1B695+YzHRbl+nbrjF6N05zVCnJ9Rbnqtjz88JYARRszA8qtQTKSrFXA==@lfdr.de
X-Gm-Message-State: AOJu0YyXSjfyETN7Emeplh5PbTlvcNl/I1VB1BJ8Tc6PyTnNcEnq38Vg
	THB7jFqVBOSW7LE0cmdIO+K3VebKwB7VtnEZKt2CS+lv3nT1yksm
X-Google-Smtp-Source: AGHT+IFFl9yBCRpJLEzuwQ2WH42liP2cxzcRZzPVs6X4s7eIKPBGJXs/b36KYsfAcfw6gxxIYNvgSw==
X-Received: by 2002:a05:600c:5025:b0:42c:bd27:4be4 with SMTP id 5b1f17b1804b1-42e7abf43d0mr66057205e9.8.1726997182453;
        Sun, 22 Sep 2024 02:26:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:46c5:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-42e7474bf28ls15294525e9.2.-pod-prod-02-eu; Sun, 22 Sep 2024
 02:26:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIiPsx+TN/9HLv3D/dU2RWAFzUs457YqciTGxwf1Mqn8uE9BkCqvFF2uQlWNdc11PYznfQcFVUu10=@googlegroups.com
X-Received: by 2002:a05:600c:1c04:b0:42c:bb41:a077 with SMTP id 5b1f17b1804b1-42e7ada4c7cmr55028225e9.23.1726997180578;
        Sun, 22 Sep 2024 02:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726997180; cv=none;
        d=google.com; s=arc-20240605;
        b=g9FZZr/qBt8eqhUYB2X8LBGe902ZUoQQD42w+0/dXbgLkxgMbtyY1WfTYTeztSefcJ
         3HJiRigs8DcZ3cpNEk/j9a3dw/jsZNgeGIvZzWSSSPGkgtkadCHAwSPJ9Fw0B1qAXfA3
         GbbKkhIFBthO4AhqsU9BuGVnnI2EDVi+EpmyZaioHoAljLnf+tsFg3lH5e9p0ha2yYjj
         nW2ByGW35Y5l564ldckfmXaTvc9SlgOSaQ5wvBnwLbCLVNbh1AYseUpEcbpiDzxf4Y5Q
         AepQwwaH2UZSRZ2ji8rpsrYs98Vh8ybhzBprWvzxAPXT/rvkLeGdu66zQU4LqPTXLhmi
         r1BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=v26B5rb0HebxXVZ1o6iq7edGSSdE/AhTSaSIaBxYmhw=;
        fh=ni60SmkJSKFQITrfOQEVyKejNLd8lBAow4ZkswvHCWc=;
        b=Xg9T2XJh0j7lhMqTRpwPxMFJ3DqViRLgLbpFTjpf6mPYC+QqIea2VnIpOtiXy7QdSn
         RYe0QDemOrtxVn3uvi2gtoyC1RhXSjr6jz0BIic8uTXckKc4fNAP1dLJqwftVzdvc5HC
         dVqVy9KfRBsgmMMJB7XLQ6a6RY5JbgpBiCVd8x34QdCBoBDOdzB4I6K+Ef71xklSKklr
         oxsy+N2tP7xudqCLQbu7gC0RoiWGS0L3gRM3tICriSUhxM9LhCJlXVvZ7tvA8ejIwS8M
         pA+SqGkyBMV+PAVGEac6zyIXoVb/aYusihzQKs1E65cNM+dMYxbSkMys1DqJmAqiotiT
         fOUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y8bsdsRW;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6c718f09si3302745e9.1.2024.09.22.02.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 02:26:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5c5bc122315so529033a12.3
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 02:26:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUg99iIfPFWvNWsR0Sm9+g5wxMXfZJS/SoqV8/lAg3iswF8H+srfpt7/LQFQf9cgGUcOaWeIBY948A=@googlegroups.com
X-Received: by 2002:a05:6402:520b:b0:5be:e01c:6b5f with SMTP id
 4fb4d7f45d1cf-5c464a7f4f4mr6878449a12.33.1726997179864; Sun, 22 Sep 2024
 02:26:19 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
 <20240921071005.909660-1-snovitoll@gmail.com> <CA+fCnZfQT3j=GpomTZU3pa-OiQXMOGX1tOpGdmdpMWy4a7XVEw@mail.gmail.com>
In-Reply-To: <CA+fCnZfQT3j=GpomTZU3pa-OiQXMOGX1tOpGdmdpMWy4a7XVEw@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Sun, 22 Sep 2024 14:26:54 +0500
Message-ID: <CACzwLxjZ33r2aCKromHP++2sLjWAQ9evF5kZQCx2poty=+N_3Q@mail.gmail.com>
Subject: Re: [PATCH v4] mm: x86: instrument __get/__put_kernel_nofault
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y8bsdsRW;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::532
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Sun, Sep 22, 2024 at 1:49=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> I tried running the tests with this patch applied, but unfortunately
> the added test fails on arm64, most likely due to missing annotations
> in arm64 asm code.

Thanks for testing it on arm64. I've checked other arch and found out
that only s390, x86 are using <linux/instrumented.h> header with
KASAN and friends in annotations. <linux/kasan-checks.h> is in arm64 and x8=
6.

While the current [PATCH v4] has x86 only instrumentations for
__get/put_kernel_nofault, I think, we can take as an example copy_from_user
solution here:

https://elixir.bootlin.com/linux/v6.11-rc7/source/include/linux/uaccess.h#L=
162-L164

, which should be a generic instrumentation of __get/put_kernel_nofault
for all arch. I can try to make a separate PATCH with this solution.

> We need to either mark the added test as x86-only via
> KASAN_TEST_NEEDS_CONFIG_ON or add annotations for arm64.
>
> With annotations for arm64, the test might still fail for other
> architectures, but I think that's fine: hopefully relevant people will
> add annotations in time. But I consider both x86 and arm64 important,
> so we should keep the tests working there.
>
> If you decide to add annotations for arm64, please also test both
> KASAN_SW_TAGS and KASAN_HW_TAGS modes.

Please suggest if the solution above to make a generic instrumentation of
__get/put_kernel_nofault is suitable.

Otherwise, for this patch as you've suggested, we can add
KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_X86);
to make sure that kunit test is for x86 only and I can add arm64 kasan-chec=
ks
with SW, HW tags in separate "mm, arm64" PATCH.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxjZ33r2aCKromHP%2B%2B2sLjWAQ9evF5kZQCx2poty%3D%2BN_3Q%40mai=
l.gmail.com.

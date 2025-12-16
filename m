Return-Path: <kasan-dev+bncBDA5JVXUX4ERBPGSQTFAMGQE6S7BX7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 83A88CC1D64
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 10:41:18 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5944d65a8f5sf2636482e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 01:41:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765878078; cv=pass;
        d=google.com; s=arc-20240605;
        b=XE2Tg90N5DhI5JNia+Lccbldlx4X+ID31PuOsYjXb9aAoTSwqvPlTnSOUhLkMgzKsm
         s5ni9oVn/+FYfwYwzuc6vk1Sa6kOcOmdC3J3CqZm7WGVGmBFxCn8TUoUm8FJakE0JnAp
         YD0XX9nn0KHI3LEr8xgPNL6sQXssks/M/2Y66ONTtleSDnS54TklifyFr7lqAbV4gvJr
         7/cU0x+pzoIwNrnQbBoSXUrLkVN0P9L+ZHJbfq0hfD31Va2bcr0HO71LBlqMTkNeeGx+
         sgqqAqYgbqAQQ5bs3j8T+SK6YWxTHLPvnQNRodPWfX+ydfgFmtipG6HxBEnmS942swV3
         R1DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XVAcbqhAzMMxnAv6vbg1mfRJK7DEIc4+ACst4Kr1meo=;
        fh=8Ge1zjfR+xiTf5hC0bZgWE681M9RjGS0rxi+k6qZGMk=;
        b=ehpzBSs1Ncn+iNL/q2xY5lURah/EipLw58LfxEu8wg8dc3eotB3MPwSgMZtiOVE0AD
         R5x70wUgVYN+S61Ql+DpyyvkaXvkf9DVlVz/9NfZkbxPSDV0bwYA8MPtd63FpkdnCe5K
         hBJuzMf/x6J4+uhP27jzM/gWxOwg43KUvObxhQu7d3QF/R0hE5e4Ttcng9oXcSe3dTq2
         ymAo56XDS1R2USjZs9mlcjdnfYEYI2W1YH4OADRpfnAltiK8hhIs+XmKvIrZYt8Ulei3
         QQM0AiQMfYnI5miFBgmN4+8vwnnAXqgHyAL1Ei7PHdzjcaFS48mmg7RsQajeB9MIHv8M
         5jZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eunuD2rH;
       spf=pass (google.com: domain of 3oslbaqgkcealcemocpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OSlBaQgKCeALCEMOCPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765878078; x=1766482878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XVAcbqhAzMMxnAv6vbg1mfRJK7DEIc4+ACst4Kr1meo=;
        b=lVtOj1j9JpZxjYmp6TpKvP++MTRutE7xbMUmsaQf0+PbsLU5OJywkZ9oMBLrvmPwe3
         AegOk5o28ffUBDArq0gNsJ4+t+FR7XbBJQl2Qz3x8oF3/nVxNudB8UyavWLGPe2hp88q
         nZb+RTj5pYIg+5d+oVFzy5gDTsbJL6Yql7nxzVUPuEKwC1PiR6Jr/9PWyJAQpMusUVqt
         S9/FTDBXSjnEbXGCOr68euIvwJTLS5y1tlpsYwiSj6ldWe4HSlFDuS0RU+IxOeC7/K5J
         WUvtvbW3k4tQCv0Vl6YaSjJfsvCXBcv14pDuXaWrYCZ9oTruW7fGl6LGP6bhv6EfJEZ+
         dxgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765878078; x=1766482878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XVAcbqhAzMMxnAv6vbg1mfRJK7DEIc4+ACst4Kr1meo=;
        b=qwlsjdFOw3ycu872QlNOng5bzL1YR3s2TG/3WyDYT62TpXIiwP8XG6oFAse2uWWAAI
         r0yC1gXD2nWiLROtOTYvpHorjYIyYmEpfdBPG3qF+zv7omDFKC97E5NypiQbnNg4Dm78
         NIavsm9/j7hOD22pLCo153a4he3z6Gj7bxcdIseOIm+zWPGcRaGDFr0mGgm2sltLExHQ
         f+q8TB7Al22HZhwl5VPJ5PAytz+ypSBsBNVG77gKOB8y2zwxTGMKK7Q3/WzfKMj9AM3T
         fR49T5XYrJ9orBtTEwIcnFMEOG5Hd2GCahy/Smg4fQW7+VZNw6QHRSGXMxIzU8KMdjvy
         VFhg==
X-Forwarded-Encrypted: i=2; AJvYcCUoFN22e67GFTb9D1KyWYNeVG3mL9fNfK3AhkzhtvvVEkT3ghdrjhrjI7Nk1amSr//i4TqqFg==@lfdr.de
X-Gm-Message-State: AOJu0YwX942ZZGCDkYH5qjjV4HMHIElf5MkJMNYwby3KeMnARMu7iulG
	6gqgg+3n5DoYyg8tQJ6Tp2BA3932G13u2wdbc1xShDR4lQojpYuLrQBx
X-Google-Smtp-Source: AGHT+IEmO/BWZRoPg6BhlvX4lNnhJXBPT8RtdB8diGlFCJJjmERBO5PC2Vflho1oMlOGBYCUwPxdww==
X-Received: by 2002:a05:6512:2351:b0:594:347e:e679 with SMTP id 2adb3069b0e04-598faa904d8mr4432470e87.43.1765878077442;
        Tue, 16 Dec 2025 01:41:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb4JMvQz6EtGkRbRwCzqGlwPt/xAk/ZwCQXgG0v9URhdw=="
Received: by 2002:a05:6512:b12:b0:598:f8cf:633a with SMTP id
 2adb3069b0e04-598fa413205ls1385722e87.2.-pod-prod-09-eu; Tue, 16 Dec 2025
 01:41:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrbH/xlqAP2NKMF4MIl2UNQxVi7D3Piksc4eT/VnZyXvenRzSMW1k1YBaXwEEjMsh4NU3YoKpWpys=@googlegroups.com
X-Received: by 2002:a05:6512:3b0a:b0:597:d6f0:8816 with SMTP id 2adb3069b0e04-598faa25568mr4505885e87.7.1765878074623;
        Tue, 16 Dec 2025 01:41:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765878074; cv=none;
        d=google.com; s=arc-20240605;
        b=LBFKoXUscG4d4Go96j4AO/dA8f00/eICBIz4221XYccJJlXkproow8u0YaR0/zKlC3
         TcDHnx/5W/Dugx0eNUAdz89w25z9njLANYBeqi2IbxcghjkHLOmo8AfEDNLamEIMG76+
         jUXz33nh+TY921kRvMGM4wnQSwrXAj9KjyKWy7nV/dWLyel3y0vMsqwP6GJpotNRHmlb
         S/Excb566RZO+2dyhKHWWHP7356wcwTX5jREUkHuyBeLqJ8aTgrYFt4SPD+X2+6P68Wm
         H8rvAXtsQNQtcprAgci1l/W0yePbSlbZe+n5Z0/yNW4Qsa9/6TohnkdzScD0Ut8lBz3y
         +sCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kzxpi320fuDlWVEdLz2y5J46WN58k2cyto0/t27GRCA=;
        fh=upq0mMeIUgfV7TZJAzmuo6QIKq7AI4WGF/xIQNGVcsU=;
        b=FowSFmF0oDqcensmTomDTvypz2mGVgsIoq68sUityrNX90T9fc7Pdyv0Q3fHmZ5TvW
         m2jSbse1UAqrQAfeYNuPTOwm923SSDvtjFbP4GTs5HaSy7LLtljsLf5VJ1297YNQmTOx
         N1fyMfSwLbr0TeclTaPZ/HEHo/SKBXuz3FvYMsMHBvaUQbN8GJTm/siP7959rljLWxVm
         afR+T/cSt+0F81KBYW4B14/wnXDNPYxu0/p3rh07iG8yMWT0SaXOx5jERxy1IU3QUyCi
         Y6gcv8pUsIGTtgF2/vtjGy51aoW6T8rcBl1XT4sZnLtfPz2/nXB6hn52fOsagKHS24Nt
         itkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eunuD2rH;
       spf=pass (google.com: domain of 3oslbaqgkcealcemocpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OSlBaQgKCeALCEMOCPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59911b09084si13777e87.7.2025.12.16.01.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 01:41:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oslbaqgkcealcemocpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4788112ec09so31775145e9.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 01:41:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWumth4FkUhQICKLsXyBuGBWAzs03OZ12400jJzXzKysSFedMl5gQRlgRbkT9FIcBD+UixVQjSLZRc=@googlegroups.com
X-Received: from wmpu6.prod.google.com ([2002:a05:600c:4d06:b0:47a:814a:e0cf])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:1c88:b0:477:8a29:582c with SMTP id 5b1f17b1804b1-47a8f917533mr151251585e9.34.1765878073998;
 Tue, 16 Dec 2025 01:41:13 -0800 (PST)
Date: Tue, 16 Dec 2025 09:41:13 +0000
In-Reply-To: <CANpmjNP=_g4Ecfyk7h-Z1bSWho3MXNU3CO_a77zs+phhUZu76Q@mail.gmail.com>
Mime-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
 <20251215-gcov-inline-noinstr-v2-2-6f100b94fa99@google.com> <CANpmjNP=_g4Ecfyk7h-Z1bSWho3MXNU3CO_a77zs+phhUZu76Q@mail.gmail.com>
X-Mailer: aerc 0.21.0
Message-ID: <DEZJJ7PS876Q.2T6OVVJH0ZGZD@google.com>
Subject: Re: [PATCH v2 2/3] kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eunuD2rH;       spf=pass
 (google.com: domain of 3oslbaqgkcealcemocpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OSlBaQgKCeALCEMOCPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

On Mon Dec 15, 2025 at 12:11 PM UTC, Marco Elver wrote:
> On Mon, 15 Dec 2025 at 11:12, Brendan Jackman <jackmanb@google.com> wrote:
>>
>> The x86 instrumented bitops in
>> include/asm-generic/bitops/instrumented-non-atomic.h are
>> KCSAN-instrumented via explicit calls to instrument_* functions from
>> include/linux/instrumented.h.
>>
>> This bitops are used from noinstr code in __sev_es_nmi_complete(). This
>> code avoids noinstr violations by disabling __SANITIZE_THREAD__ etc for
>> the compilation unit.
>>
>> However, when GCOV is enabled, there can still be violations caused by
>> the stub versions of these functions, since coverage instrumentation is
>> injected that causes them to be out-of-lined.
>>
>> Fix this by just applying __always_inline.
>>
>> Signed-off-by: Brendan Jackman <jackmanb@google.com>
>> ---
>>  include/linux/kcsan-checks.h | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
>> index 92f3843d9ebb8177432bb4eccc151ea66d3dcbb7..cabb2ae46bdc0963bd89533777cab586ab4d5a1b 100644
>> --- a/include/linux/kcsan-checks.h
>> +++ b/include/linux/kcsan-checks.h
>> @@ -226,7 +226,7 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
>>  #define __kcsan_disable_current kcsan_disable_current
>>  #define __kcsan_enable_current kcsan_enable_current_nowarn
>>  #else /* __SANITIZE_THREAD__ */
>> -static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>> +static __always_inline void kcsan_check_access(const volatile void *ptr, size_t size,
>>                                       int type) { }
>>  static inline void __kcsan_enable_current(void)  { }
>>  static inline void __kcsan_disable_current(void) { }
>
> It wouldn't be wrong to apply __always_inline to these 2 stub
> functions as well, but I think it's fair if you just limit this to the
> ones used from <linux/instrumented.h>. Either way, please
> double-check.

I was thinking here that it's a bug to call these from noinstr code,
regardless of your ambient instrumentation settings.

But yeah, on second thoughts... says who? I don't think that _has_ to be
a bug, we could totally mark them __always_inline.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DEZJJ7PS876Q.2T6OVVJH0ZGZD%40google.com.

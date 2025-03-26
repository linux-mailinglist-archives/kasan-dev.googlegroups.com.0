Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBW4SSK7QMGQEZ2KO4EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 383C9A726E4
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Mar 2025 00:10:21 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43bd0586a73sf3383225e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 16:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743030621; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kf6oDc0JIRw1xcQwoI6nRer+D5GUC2iJOeEDvafXRcq4q7zfQppEPvx9lvWirBHplL
         kFh0DaUdIJ+RHVXommlRKGiDFy1kZ25TTm3KoUlIJDZBhEh0Xmd40xhcMYvw9r/Vbt9c
         RxCpH3LN+1FrTFZrOPRZEadoJgGGFbYSQCipWTnsayJgKMZyPXtFfuFjRUMdVGP/LO9H
         h7Gm+sGWN4R8tHvJlByrhbY30LbIv3iJ491PuDD76h8e/6U+gcOlLQqff12ZF0e8oBR/
         L9tyXCJXE924zWOWmFWyK21H4OlyyCnwl9QZnB0k+RWcJmWmIK/0dyB1OGa5GnWzYKTL
         kmFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=aJ15ewnXWvFwypelDj8nCt4VngKWjBp+9X9HfCcAHdU=;
        fh=A5WWMDBKXrucErO6CdAPo7gIgWmmP6TLd8vDfA3FiuI=;
        b=ER5IWodGO+7Tg90Poe1HaG4KVCN9Vy6H/0uf9vaKrx6d3Cr7IHE1xaHRIMcrr0GCDG
         f1hup7MfYpYjsC5Tj2dGg5VSyjckWdvAiNfW/SIxuIIiI0W4uxUUQ+UBwvIOgmApcCSC
         JGGAE03czOGkXPMLgUMBsI4x2aQagb8dy9yYOBAKvZJOhvRbFRVWinSnG3q8YUBDp77o
         L64ub4+pEXW2KqKxSypMs/qgCIXpl6lX+aywx3TAhSixy1oiv795FfZIdChBJuKnCwYl
         CT66o9Dn6zT9bJIACyCzVVuPMw3HnImnreQhEqbor97TxH7ws2/9ZrL2xPegoFyDLGrW
         Wtgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C0NUTCuS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743030621; x=1743635421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aJ15ewnXWvFwypelDj8nCt4VngKWjBp+9X9HfCcAHdU=;
        b=l6M22Bw4WA+jDaUCeF+82WC7i/EVGI/UdXTtMvG3ZVJAAr5Wfl7V2rfdt9k8sUrPjI
         xyn1LmsROCV3apthFAsUFE2aEfvm+4/r/mQWMncj/c9AqzBNgCjvuw1hZZLv9UWwuys2
         3NN4M8s/l0ACW3X736NBcdMGpVJqLOCFTr4Nu0KD6cF1lhZ2G9pTaoayIW/EoJ9i/gzw
         OrWQRax+m0AiStiD8JH8gF8uvphCw1Oue7qaoILu/ahQFYt4b0B9YZSfeiSuFyY8qOO0
         Sfv5yeWJQMr/v4l1Csn+pk10rPdiNBYvW9HzydIGR1OaB2+2GE5xYsbq0brs+uk/Nnef
         r/KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743030621; x=1743635421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aJ15ewnXWvFwypelDj8nCt4VngKWjBp+9X9HfCcAHdU=;
        b=WjJMa9Ht6t1FuGbXbQZKGCPSk1IvkKMBC1nRYjpPXcZgIC+l0p1lSdWcfeAGV0lmMX
         3I9veF9GZ3ebZBDr3ug4tcLC3JNij67yP7qIf7lN24+430c4xAlPByNVJs+XMSfgttAm
         p7VeerPs5asothpsJTQQNlhV3yPY26+rlmGuWf1lSejBD8z6IVJ+TEocOoe6b2EP/ygb
         zvywAHlIexH6+szOfDEyXCN8VeAp7KPgjhy8squ6ZhkRsZqAGwnNFppMHyAl8bosKYFv
         ObUCiH/fg/1xRURflgVGy/6g/jqLdD9qWZ0k62dyf6ve7Xk0+ckd51G2V/Z2GXbvFLf0
         ukXA==
X-Forwarded-Encrypted: i=2; AJvYcCV2PprlTZY3Bx8rpIN0bSFWdD/oBj6cNa9FEqnVqJak51YNpspoh/WdmcoV9kRaqAe3FmNI8g==@lfdr.de
X-Gm-Message-State: AOJu0YyxPUmuZbyXZKC6X71pDeS/EuKOCx3uAVOdimIa5O++nSO4UOz9
	c7LLsylKkiwywLXxsD5HTAlAXmaXbFNRsiHJ6nZb2vKtsNAU2ilc
X-Google-Smtp-Source: AGHT+IEp1c/3o4+BGiHwma1vko6gfvRg8WDiOQqV0I/BALpoggJznd1jXHOIUShyTEVi3AYY/8kZvQ==
X-Received: by 2002:a05:600c:154d:b0:43c:fc00:f94f with SMTP id 5b1f17b1804b1-43d850655f2mr10653375e9.23.1743030619899;
        Wed, 26 Mar 2025 16:10:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK6jfdBA8I5k/1C16GPlj0q7QlUjhj178O8VjNXbMyKUQ==
Received: by 2002:a05:600c:1e28:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-43d84ec3dfbls1947855e9.1.-pod-prod-05-eu; Wed, 26 Mar 2025
 16:10:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXf9pPf+8K8aBWQoP2O+7XZiBHWlnE6O2otVS5igjhCvY1afqsNPlza4zUjZC0CbSpHolUwdDXEbwI=@googlegroups.com
X-Received: by 2002:a05:600c:358c:b0:43c:e7ae:4bc9 with SMTP id 5b1f17b1804b1-43d84f5b711mr9307005e9.1.1743030616950;
        Wed, 26 Mar 2025 16:10:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743030616; cv=none;
        d=google.com; s=arc-20240605;
        b=D8nODq1rEAAZgWjAkTCTX0wSDwnXLIGKtlDHjkJ0wV9bR9HcWE7dLl9Y/d+MMICXqA
         Qntyee24cbSpt52qqU5Xe18bPon41LTixcGMNJ0SUwo3e5kWrAvypvHwXIrG50ia5RKe
         yPjPyI266AmxIRqpkZ0+k3NKgh4ipMw34xOeZxh7gAIt17FwsXQIV18cmPL4vyXbHaKx
         w5W1IpJK0qNkAHXTGnDFfXR0aJrMkg2znB9oc9rQ3qMFIeMMG6jmX4UAwHJHp3UA+oNX
         vCu0iw9Chsc2C4BW9pYWKaDvmYcMbWK4DUp+omgs0zgOnFBMrSnZRz+YBPTFDeU3q3q/
         iXUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=wc3YVGgFFPukQsTfiZoZotgv1qZ6Vpg2i6m4XEs2Ox0=;
        fh=T4egolUtPUGB/Ps6R7u8dUnDI+rVGlAqEmKcAbMZVMo=;
        b=XOzJr8LGb7kz359jHi4vNg+rQpVLgGdASMzgorzYdS+pbpRPhwWaDFV8/KrbiYu4my
         mH+dYnEuQkr+19ZpQPKlohEQ+se7Xllo/VCit/jbXkn8uP+lUqDtRPwBH49q91jcWQ0h
         q6EaVUsOv4kmgJrkls8krNYN5RUcE7Mxc/d5rqgQzfGGVKNjl/MK8gCx25E5sWFw0vt6
         e/GB/49WhdBvx2r5vOw6wMeXRclGKtOPz7766f5jIqj6mmkH7R0Q7qLudGsMDAPPI2Lc
         Ask+NJfXV+2LtHQUTDJEBNNjCKEtQARaKBQCjB3mu3featDFGM3SuCfUUK+o4CuJ5KFo
         fjAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C0NUTCuS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d7bfd1725si1376495e9.1.2025.03.26.16.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Mar 2025 16:10:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5e50bae0f5bso4315a12.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Mar 2025 16:10:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVM4WyIj2D+mCWffEUdtuAcEMe8h7suybV30LGeNesM91NxhKSgCbcUf0+2oO1osTXDGNFPtlBT/v0=@googlegroups.com
X-Gm-Gg: ASbGncsP1LINfLyLwxbPRIgB6f46Tm6V1tao6lmUKDWMhp9CjUKvJmThb1V3FvReL98
	MZKgwr1AuAzoAzrTsR7LFFMdKYreoClvM+KSfqDBWWhLLYvagC6aWQu42e2nTae1Vrh/28PDGDy
	DUwkQWE0JTPsXZiF84K+lvD5bpQjog5K7THNd7Jz0BfuNprZkgCpsWzHauitIIhbNNLg==
X-Received: by 2002:aa7:c954:0:b0:5dc:ccb4:cb11 with SMTP id
 4fb4d7f45d1cf-5edaae205aamr22369a12.4.1743030616016; Wed, 26 Mar 2025
 16:10:16 -0700 (PDT)
MIME-Version: 1.0
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Mar 2025 00:09:40 +0100
X-Gm-Features: AQ5f1JqVjr6tTcBF7w0LwsC86zQrBaocMPZS2--LfQfER88FYjnvupdq9_ZCZqQ
Message-ID: <CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ=A@mail.gmail.com>
Subject: does software KASAN not instrument READ_ONCE() on arm64 with LTO?
To: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kernel list <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=C0NUTCuS;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

I just realized - arm64 redefines __READ_ONCE() to use inline assembly
instead of a volatile load, and ASAN is designed to not instrument asm
statement operands (not even memory operands).
(I think I may have a years-old LLVM patch somewhere that changes
that, but I vaguely recall being told once that that's an intentional
design decision. I might be misremembering that though...)

So because __READ_ONCE() does not call anything like
instrument_read(), I think instrumentation-based KASAN in LTO arm64
builds probably doesn't cover READ_ONCE() accesses?

A quick test seems to confirm this: https://godbolt.org/z/8oYfaExYf

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ%3DA%40mail.gmail.com.

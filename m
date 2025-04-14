Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBROS6W7QMGQER665X3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B64B2A88C8E
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 22:00:07 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43d4d15058dsf36825105e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 13:00:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744660807; cv=pass;
        d=google.com; s=arc-20240605;
        b=j/lmkMKSzN/PWlKaU+w+buAzZ6HJjzm1H1KbxW+81pMCy2sT4NoQSgZVQxJkV9Xc+E
         /ZcZxr+vR5aiPZjEHBx+gxY0X8tlYVCzUL4cPMQObNshBVTQJ+eMAKatBXk3XrKFWB50
         NNgwQCNVfb85Sy5u8ZmEEHBywKyaGrclyTFvtZjUhr840EdqfRlX33H9+2VUXyQAtnci
         4xUR5MDCtQiaFlEqlfzbmQ4AcAcoQxnsf0eZNQBV1JX36s85HP5QvNbSDCZ2Q/Qmi6Af
         MRGTSfaef0kmgPq+D1JD/7Ri99su6+1A4yWZxocVjXZi8JPv2I7TsbouBHxZVFAmZU6t
         PdxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=cOot2zdGmZo+W7iK1BUJY/K615RZruoDE5NWh3NbDv8=;
        fh=7uBzwIGUf83hnuTspxCoIJIB7vdZh/HbYRtQNO8JI7c=;
        b=jUt3bRkGTdunsP86Cr90Q/kW0f++yDuymeTUAV9qnch2gcYD1wzw9UXqAGNpJIZhXq
         5PtvGSFzAuCY3RZ8pvQHVFgjnDK4JzosmJSq2nwVGxFOnP9inyjuIPVtIGu8QIHFzIo/
         tPmv8rsBwKvGxoCD4PkgpLGfjpEM9rmVFIBh6R8e4IsIvSgTceLZQ+aQXg9QJrwsffrm
         cvoxO9AM23gYanV8+CU7N7TdX/73qQFr06yjIolY98QMxPECyDdkLV/qC/QGd3h7ptuP
         IOwarY3B1Jn8ETPqJJQHh3dMrpF4mLXikFMmtc2h+zSTeQ51G6v7dWJjub734dubkmfX
         fdMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=JeZTPuF9;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744660807; x=1745265607; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cOot2zdGmZo+W7iK1BUJY/K615RZruoDE5NWh3NbDv8=;
        b=VpmGKs9ke7/ViA6cQWoHmv2El8czNwW6rWu4ojzhW9WR6b8tGkOjGakYQf0KFfMKdc
         kC4bwA82z5F6g+xHOyKlbf7eGW+KiUv/neorSw15m0rwAca4S8ZKD1UJUVOYVVVQXysw
         k8cy2WhjiCAqzJKreCZoNf9VkwmwAX6B+RoBiZHlJ0wZDl2Veh5a0Qj+UcFEKMRz/RCc
         kgHkovzlHl26sMX58OyUeM0sY9ZdOEc0e0HEnPiMH6NS8ymhqOWVtNe80gcjE0bWks7D
         WhUuDo3ZUaTrM1/UJKrPJyDE2H/hNB24BIZ91nzR9Ii1xWhmgqNfk4D0+ea3pRyWGhMZ
         eBtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744660807; x=1745265607;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cOot2zdGmZo+W7iK1BUJY/K615RZruoDE5NWh3NbDv8=;
        b=RNdUi4PAKQE7+pn4rZhOr0ByQ7krJWF5T1//FCfOikQoNNFN/yVw9QAmmdPfebXp87
         PWE1CuGnadEMHKO++y9mI8+X4BDr4G+KxySBN+780t6LWHxE4IbQObq3lHvLTO4pEf6f
         /I0nNuuOFVoPnh+vK1fplxC0driJ0OWZL08aPvvGICZorhtjHAEEuVil4pSQOvG5J3VD
         sDQ5PA7HcpU4MlesH0uQyy3J0Zf8Bwtmxru3+AgLNeHhKQKE1A5X/cOVfkcZMYxGx7Rf
         WbYVU4XF82zvZmyvnQum9miGh/l9/kGH4ZVO2GNPUTCqmjfOH217tAMzwHmy9pFBtxoi
         6zsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUWKteNwZSFMGIMMc7JWU92A6wgz7MNOYHSPyOgL+204q9xroS3Mj39cPN8ILW5Ewwn5EeD4A==@lfdr.de
X-Gm-Message-State: AOJu0Yz/g1EhV8q+tca9KoTXW9IO1GnmKrJxovWObAOkfHBgC7CY29Zq
	qYdk35rAqvZzZ7bPGCgiG8cg6lr2dOEVFVcBk2APHWZYj8pExf6K
X-Google-Smtp-Source: AGHT+IFI2WYQ/G6zPrwI7lbCqmw/ri0M2527LEWZFF+QcA2Ncr+1JiEjVYZBqErl2E6B+h0D55appw==
X-Received: by 2002:a05:6000:4387:b0:391:45e9:face with SMTP id ffacd0b85a97d-39eaaedcd05mr10773475f8f.54.1744660806110;
        Mon, 14 Apr 2025 13:00:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJrOCY4fXOK1sBECeInzKPHizkfLzoEh7v6V2+H46ag5A==
Received: by 2002:a05:600c:1913:b0:43e:ad2b:6916 with SMTP id
 5b1f17b1804b1-43f2c24edf0ls20813845e9.0.-pod-prod-07-eu; Mon, 14 Apr 2025
 13:00:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9AIvznYaTewhtMVSfoaGnJlaZgpMkQ2tLYFHBO47C45FB4+R9PL+SPDMGK3i6LmhlU7WM2g0M3IQ=@googlegroups.com
X-Received: by 2002:a05:600c:354f:b0:43d:2230:300f with SMTP id 5b1f17b1804b1-43f3a7db98bmr114905675e9.0.1744660803215;
        Mon, 14 Apr 2025 13:00:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744660803; cv=none;
        d=google.com; s=arc-20240605;
        b=SYG6y83sdjC8XR2m9lP+Bncc0vD6oGA8OXb/AFqQqJ+woOKJlq41lXUf9vVcb3o5AS
         ZRUKTy7vaYOCfw6EGwpOvYs8cRYngDumVX/s9eiMJfx87lhCrfvMd84wQpvEHfvZu3Jo
         +kVQKRwHToAVHKVIONXgg95J81MhxsZLHgAl1AjpMuzvaFzUHENpn7/MJJfd8BeZmvbZ
         7AECg7f96wDTeT2tbb4x8y8R38YQddJoj0hqiHkL5BlxZL+gvtUfrv+0XFRmBrQ26br+
         sZsW3pENzUnVqAoJokyBM9L+jRJNo5vXm6bvhyUyKq0IsYfOHZGQxBlmURQ1XQNlHxKN
         6TcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GuKnl7vKvuhivlDBXfVU770x/Uehh0Z/3wv2E0YnWyo=;
        fh=KYg83i3ZAsue+5dS8at4XKbpi9sX2Gw0NDgEN4EHpJY=;
        b=K9hYXRkBNrwiF8I+TIrCtDAybb7FeP8IdY8/a/kIBPyirhwt/VKmcBEevO7lcGh07I
         RaSPtc+ndML8UAVgCFCSCkKXgnG8tBavbW++5HeNwI7t7uDtzpNaVkmF+lXkYl3l71d8
         XRZUjklkjiBnR9axP86cQM9lPHe1TMtX+u2+gD7HgLaHGnC9GizguULPwrpSiiBLMJEP
         e6BD8OkqztPkp83ZNyxYrWyUyIk57JdAaUr3hahzpj1ID6dNsZFB8WWAyoTPqpYJnBbK
         NWVelhzx7Mybm9+jCbw4QRQ7UYIY1zgmKxrGQcQNKjqaL49IXidEcBDae3kMHAlX0uwO
         N6Kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=JeZTPuF9;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43f20a7ec88si5688945e9.1.2025.04.14.13.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 13:00:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-ac25520a289so814511266b.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 13:00:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcZIPyH0ygATQ9JSYtQqMamCKxoJBdCx/OX3u66nBWVvWU0vdMq/+7i2VVVYnjf/48qPtnOEXvuqQ=@googlegroups.com
X-Gm-Gg: ASbGncv8/ejl5r8SygiNcZzEe0dEzmxxvz8VEb2x8pU+yElDH+n8JKmzjfC2dXNUlEY
	v0JYjGCRSfLJmhDc8Lf3WQidrwSZbdi4n0nUeKbrwT+ttqna8T2tJkl6kznHThZ0yTR7IFUBIOB
	c2qSHEBcmiVT1zrSlswUmVvBElv551Tx4BXT4H27UTQLReWPvi1HFRv7rGUHWe3vmhaKrQG4JRp
	x9ZZWwpNm3VKDgnDALvn3oNJC1wFg+qH36MajEeDgncym/z6WFqZes2Ts5DtCfpDvqCzNhl1B3y
	j6Tu0pa58zaBbdNSOWonnxSkJM5xVjzkqqRh/r19I2Vx6HKCKoAp94CHTz3raAU1qmjw7sB6kfI
	V50/ylOorDNkNSJk=
X-Received: by 2002:a17:907:720f:b0:aca:cac7:28e2 with SMTP id a640c23a62f3a-acad3595065mr1292637366b.40.1744660802478;
        Mon, 14 Apr 2025 13:00:02 -0700 (PDT)
Received: from mail-ed1-f46.google.com (mail-ed1-f46.google.com. [209.85.208.46])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-acaa1bb2e15sm980618666b.17.2025.04.14.13.00.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 13:00:01 -0700 (PDT)
Received: by mail-ed1-f46.google.com with SMTP id 4fb4d7f45d1cf-5e677f59438so6942810a12.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 13:00:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSBk3yq1CAO2bgVA6bqauo39Ya/6slXYU9DHrcVtKVCsYlPnwI4s09um4bhS0/g5qDRjr1RYZFqHM=@googlegroups.com
X-Received: by 2002:a17:907:d9f:b0:aca:a687:a409 with SMTP id
 a640c23a62f3a-acad3493c39mr1317258666b.17.1744660800790; Mon, 14 Apr 2025
 13:00:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250414011345.2602656-1-linux@roeck-us.net>
In-Reply-To: <20250414011345.2602656-1-linux@roeck-us.net>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 14 Apr 2025 12:59:44 -0700
X-Gmail-Original-Message-ID: <CAHk-=wir+NJgwwrmRzj_giQYBuXBh=NRhhnPEqMmOM-phANVNg@mail.gmail.com>
X-Gm-Features: ATxdqUHeq_tz9wbsN5mKAeuATH-Menst-DTjon-gy2q5nMRbAO1idwPR8rk3CJQ
Message-ID: <CAHk-=wir+NJgwwrmRzj_giQYBuXBh=NRhhnPEqMmOM-phANVNg@mail.gmail.com>
Subject: Re: [RFC PATCH] x86/Kconfig: Fix allyesconfig
To: Guenter Roeck <linux@roeck-us.net>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=JeZTPuF9;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Sun, 13 Apr 2025 at 18:13, Guenter Roeck <linux@roeck-us.net> wrote:
>
> Solve the test build problem by selectively disabling CONFIG_KASAN for
> 'allyesconfig' build tests of 64-bit X86 builds.

I think we might as well just disable KASAN for COMPILE_TEST entirely
- not artificially limit it to just x86-64.

Apparently it was effectively disabled anyway due to that SLUB_TINY
interaction, so while it would be nice to have bigger build coverage,
clearly we haven't had it before, and it causes problems.

            Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwir%2BNJgwwrmRzj_giQYBuXBh%3DNRhhnPEqMmOM-phANVNg%40mail.gmail.com.

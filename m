Return-Path: <kasan-dev+bncBDW2JDUY5AORB6FLQ67QMGQER5QOIAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 45A1CA6E609
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 23:00:26 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-30c4fd96a7bsf23532551fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 15:00:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742853625; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vj51um2pic3az6KMD0pCH0nlDwA7ymfgA6zk7Cgok41ZadTDhLfeou6Xp5bzuR9c0a
         7HzmZZmvt9uv2R27YFcbl301Xe0gUUZQ6WKfVKiiKVLBLoL6XaOHFcjOaoKtIWGwu+x8
         Z3wKOItJAtrGD84Wu3o5QKOqBO1NB4LvvyHImAda+ZATl79Nn0mmAzjT+w9Uzqi9FZOJ
         9xzmV1vrPxWi7luFUvzM9umeqg3+LO4wbDCraJTOiLncbpWShOZ598ywdtQ52U8eWRUb
         3k5KXB+DBp72RFiIkvPlWsdhgQyi8MuALTca055dcBEsbjCsMPs8ZP2LhGAXqrVm/5Ju
         h++A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WcyktT8S22wDXF6gaF6ECbW0yVYUpOe2A+KpVLAb21w=;
        fh=jguTDScESsyuBGfzukoJu1ZfsKD2Tm5YqDk1k21cQ5c=;
        b=BfkBGrrYgxL+F/YfrBOOXomUsok1GMDdbI6pvlNrJ+2ByfVqljMCtFk/QcU/1Oysb4
         PG7PmdW8Oyy2kF5IhMrvr/6+spJDoh0hwNgW0GaZAvnlquGQ1xzWiDjlNaBNNopHxA/K
         HSDZC04b0YZ6uxGHigN0ujCqqPu6f3oZzcUBsFH/6skaGsxmz2x/uZ/dO7IJnU6t8jr7
         4N5y7PxkjLprkdd7TnxRSZNjUAdVZ5DjgUjSgiZn7TjJHntXEyIUempUZJ5OCYje7win
         NSkmsRaQBStS6c+wplgjwVeDEVtBHUFYrLlbxkfYOXG90lIc5P4V+mWYxzxzyQD7Ld5d
         i2rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RDIn4enX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742853625; x=1743458425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WcyktT8S22wDXF6gaF6ECbW0yVYUpOe2A+KpVLAb21w=;
        b=QYpnpywqkifXl7XB4RfTLfVyqP/7Lz1TiJAnnuIr6Vt7ryqKIjL7fwUSNpQgnMOq16
         F6JpgArOWU/OI1nDtBw0cysuDQhMgjvTnXtPY4Z+tFHLt+fjks4gEslW1YBrsoea9yWS
         a2SX3B5zqWPlefObGabV/K4oy2EsAgjVBLwBUv7abhYr2IG8Ur91wq3SpTx+uaCtbIrf
         nm42tciNgnUnloMBtQtpC0dyERQL2C64KLFR2JqrlnisLYGdHf1NU4nbOhlMc/5fGXvd
         W7Br4U+idNlh8rbnS1a/qbL3pGddly8xK7aLqqej1q850aK9rJpDYZcZOs9sLKLkc5vY
         MSMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742853625; x=1743458425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WcyktT8S22wDXF6gaF6ECbW0yVYUpOe2A+KpVLAb21w=;
        b=VPKgQ56rGt54XHbWJdVqFYZNX9ERxY6G0GrDLoAlMo7xI/2P/G1HWNdTkq/yCQnceC
         zu29wn6I9rJ3KOpK6Opo740ptIbEgcrb37HzWAhQvDHKsqunGiWTbDFsZrDdb0uuCDnk
         S3LIYf80dSEHZhS1z4bqfDv7z4dXfFNqKyjhYDgmEJa/V6WurYOtcgYD/gzhCy+fenIC
         s1qa5bWpSN/NI1BgrOJs9KqMquwYSKHv0TZUlF5TMnGHve37JM98hs3gbvOwe3D+oVbC
         qOrZkQ9pr+HLgjuWo0fPi8lyMM1NJnzK/qsgTCZHbW/72eYT1GBXCI+4Kf23X+QRmkPn
         mbXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742853625; x=1743458425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WcyktT8S22wDXF6gaF6ECbW0yVYUpOe2A+KpVLAb21w=;
        b=T1Wx6e/gD8L26OC3RjwuBZbiXPPSrJCom7rPDl3V9RYDoc8bIKjsWK3ba79yQ1bPLR
         Uk3FVKo3Q9Hen8QEwNUNn4Gtv6Wo6FlxqiQOCom+xcE7yREdfr26i6m8Z/WtuS4tnyYD
         4ZpbBuPGNk1mf6jPZgzCHIFW7EPMzcXk16tfzm0O9x9nlT6G59jLLwB1upeZp8OoWXoC
         dNCraUom/IsIvbBzHJZYOgyQhM6NrVbn2gaO47RqIDSX7yQfwAepvMJ4FSbXILcdzO5M
         +KW0ZLurLVNH/KIH9CaqYvW2Egj2xY3ouu0AvE3jNiSZ6tmZOkDGRQZ60XPQAShLo/8v
         8dkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGc6hwTk0WZTktdfCpfcMQptQTe/ec1TT2zxAA+Tf5B5tfflUtdFYBo/mzhHjwTxrXm3O4Cg==@lfdr.de
X-Gm-Message-State: AOJu0YwrD8wThi2mNFgx2X/U37MVirfBKrb2mTE34OqAb3zpC5QunNaK
	LW+O8tqy812ZoZcjikmrJ+bwobgvfaf/3XkrnJRCpN0S0DUETzjC
X-Google-Smtp-Source: AGHT+IEQoMiOyuanbqK8T8N5DohlecVcFGJ3gOdR7/CW3jXlMK8O/k82iRSwf0MQLV77ztWGUWtc+w==
X-Received: by 2002:a05:651c:19a4:b0:30b:a187:7a77 with SMTP id 38308e7fff4ca-30d7e204869mr63078091fa.4.1742853624722;
        Mon, 24 Mar 2025 15:00:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALkuU8G4Xne2/jzb0ucm2c+VJWqiVclvJTKCeMqOCMLCA==
Received: by 2002:a2e:7010:0:b0:30b:f8d2:606b with SMTP id 38308e7fff4ca-30d72dd04d3ls1708471fa.1.-pod-prod-04-eu;
 Mon, 24 Mar 2025 15:00:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3FGaPJ9CrZuzr8SLJiGzYUYe1zb/FwXP9aDnpArzJ379zlqDU6m+oMXswsrfewhIfb1wfTsUB/D4=@googlegroups.com
X-Received: by 2002:a2e:be25:0:b0:30b:b908:ce1e with SMTP id 38308e7fff4ca-30d7e2a76e7mr38871681fa.29.1742853622016;
        Mon, 24 Mar 2025 15:00:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742853622; cv=none;
        d=google.com; s=arc-20240605;
        b=YaS/+PiBNFdoBacqm8gXc/fkJEtdJUX8RSG5dOurQbO1iasZVKzoie46YS2c789PRU
         /ztvHav+dEjC1YRoKFoxuqDsDJH9jVHWxpl0JT82J/6oiEQg5ym6jgoGCF2KjqBkl6pZ
         VZOTG+1Qsxq1bH7gahtwR/gI3lImulwlUXx4zjCWq7rxLAjMYFS3IbRmJWvDMqj8EZTt
         G4nlb2Xoq/DplK9QWSLuDH13j8kWU6dLCa3i7yfJczClStZuQSt+0DSbhkN9O7f8uuCp
         MB2K+iXPfhoPugapitnG7CkujCip8omvY8H776k2tAOP55VVFP4fZpuemqilApVkUPBq
         8uVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B2YpdWGkegazNf2klfKbGc0M99P0XIEZmajFVkaDbgM=;
        fh=RPv0gnhRfy1frQhY+WDUo9ogZLdnW2fj2FqWVsE5ltA=;
        b=KkdvfsnNy2qsl5KxvqwrihF8ZAJ4i07Sb4wfzYkrICd2ahc69UYWFHeMly0J3hnh2u
         w6l59LzzrUaSzRUSgxqh8hgWYYAeaq0fg8xIOdTtyq3qBKEqGHlpTk+M1FVx95idmS8u
         Sl7lAnga2bSHAzT5wT0yNLUApukuaNDXwlu/RdHjdGuMgs8gvsjyn5/zUUDunscwk7NW
         iDqRRr8idsHJS+1xrhGlvn9SCgEAhi7p1E7+FpLj1KWqYLdac4mBLPxI+25Jsy+2I49M
         uwMsEIyI7qIhn8PMkv6slSfb2v4yztfM3JhFPe3QdlV/dikN1qlLgpBufIXNRqlLMECv
         B9Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RDIn4enX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30d7d8575a4si1785351fa.6.2025.03.24.15.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Mar 2025 15:00:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-43d0618746bso33263935e9.2
        for <kasan-dev@googlegroups.com>; Mon, 24 Mar 2025 15:00:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLktSERmdfbrvZeOPui2nlsac81jU0EMa6AgBY/5vfnMY5U7tgg7I4eQqKlhkvbepBoUwfIyAIqfk=@googlegroups.com
X-Gm-Gg: ASbGncuVqPh4n24uuJbZSnRpDBtg1fR0Aia9cTkcey8g9ojkQNWPMYBppdUfwtluRIa
	f2/8/QPv7HwDxeyO53UoNdckLSBLKIxDP4zm9FVQdwA70MBFpcOqSKRQJrpXALgNgttPIDcD9w/
	pw/doCJNOAu4cS39NtoHCLpXIQe7M=
X-Received: by 2002:a05:600c:1553:b0:43c:e7a7:1e76 with SMTP id
 5b1f17b1804b1-43d509e373fmr117579115e9.1.1742853620933; Mon, 24 Mar 2025
 15:00:20 -0700 (PDT)
MIME-Version: 1.0
References: <20250324173242.1501003-1-arnd@kernel.org> <20250324173242.1501003-9-arnd@kernel.org>
In-Reply-To: <20250324173242.1501003-9-arnd@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Mar 2025 23:00:08 +0100
X-Gm-Features: AQ5f1Jr0LTV0sn7xM4IaIDNraogN3q0NXArhmlOA0HByopDTVxKTYXLP7U_x9R8
Message-ID: <CA+fCnZd6uLYoKZwwHfBo72C0QLV=pv1feEmB2mMaqP9HKKeo9A@mail.gmail.com>
Subject: Re: [PATCH 09/10] mm/kasan: add module decription
To: Arnd Bergmann <arnd@kernel.org>
Cc: Jeff Johnson <jeff.johnson@oss.qualcomm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	linux-next@vger.kernel.org, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Sabyrzhan Tasbolatov <snovitoll@gmail.com>, 
	Marco Elver <elver@google.com>, Nihar Chaithanya <niharchaithanya@gmail.com>, 
	Jann Horn <jannh@google.com>, Peter Zijlstra <peterz@infradead.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RDIn4enX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Mon, Mar 24, 2025 at 6:34=E2=80=AFPM 'Arnd Bergmann' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> Modules without a description now cause a warning:
>
> WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kasan/kasan_test.o
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kasan/kasan_test_c.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 59d673400085..710684ffe302 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -2130,4 +2130,5 @@ static struct kunit_suite kasan_kunit_test_suite =
=3D {
>
>  kunit_test_suite(kasan_kunit_test_suite);
>
> +MODULE_DESCRIPTION("kunit test case for kasan");
>  MODULE_LICENSE("GPL");
> --
> 2.39.5

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

But just in case you end up sending a v2, let's change the text to
"KUnit tests for checking KASAN bug-detection capabilities".

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd6uLYoKZwwHfBo72C0QLV%3Dpv1feEmB2mMaqP9HKKeo9A%40mail.gmail.com.

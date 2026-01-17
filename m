Return-Path: <kasan-dev+bncBDW2JDUY5AORBBOGVPFQMGQE44SISAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E84F6D38B13
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 02:16:54 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-382fbcb5077sf13736391fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 17:16:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768612614; cv=pass;
        d=google.com; s=arc-20240605;
        b=LT4Mem6S7XEJ6A2Cn+zFnQaQ/lkkR+myFAeQWzEHl+wkT2wMg8j6MmhucUBChaCVDb
         M0F3HwOaQyBTojylPOaBdFfHDfQPcHtEFPdSmG6gqPIQnnlF2ZRlfTBaKLeoKDaGKk4h
         0sPZuZbD4DmV/SnixA4RmoZxMy+bfC2YFTYh/aV7nMdjUovoqXglo2OOFXQ1KiiXWPh4
         xkVuJKg3U6uC+8Us0lISALSip5x1+3LIlwessab+2P11+3d4blNATM8A3eDSJ8WYA2bh
         beuL7bRZdexjODkuomk25PdJMS+dFCiFx/cAovSgKMAf3HeEveTO0XWa8iPGcn/qKO2n
         dw5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/Ux7m9EpBnc0snPDNQV2yXjDldaZk0lxzgCaMNAsB9o=;
        fh=9xXFVhOQcV/OnfbbNxb8pJPlIWAiD3o+EyzoKQfFXQo=;
        b=Y/wd4Xt/v8j3zghjm3+dRqBQ74+nLItzdWX61sdmBSz60XWGPw6p5O1AUKjxJxR/sN
         inMDh+j3abV1syR4doWxyRDcdFiG5+xXHBJacx/4VIhEVYh7mE3dVbiMT5WG37QkGUh4
         bSQ38g73JA6q4knOKL75vF+4TeslnRNbp9UgGPm1qWDXRYV14EN6OBsgvPazBP9km6Yq
         T5uESyBCKRXIZogKR3AyYKLQn3Qthm6WWG2e2k9Xd08pSc+it2erf81VdtRdCMq4YhIZ
         4mJ9MTXApKGa+UWw7kYNbL9skJkR5VQR8EW+3uppN7ieu49nKIRssuYHZwfwhshcX9zo
         etaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R5iT04zJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768612614; x=1769217414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/Ux7m9EpBnc0snPDNQV2yXjDldaZk0lxzgCaMNAsB9o=;
        b=IPiRTHsggo9pF/euvjGCMBqDTdwDNyScYZzegGoy9i/A6BTJ1H+Zt88TaDccyMRrJf
         0ALM7yaASUAb+48OBayIRggJFu6Z/eNhgiTgaAUC7WYNVdsFUf1uiRf8WMS3eaY793Hq
         tYEQ77D3nqWJVYKXaV/FE2yEMYS+opxKGS8JpVgvP+FCFQbQ1yrrT7M0w2Mpyhh7MZVC
         woONxSRK+2C6RXgsH4pZRZ3fpEEiS26XOSIiXGvxinmNWPxpgYM1A9Fo6kBaUqqqy1iA
         eZUKycpy/KHhhEdL2N4UB84ASR9JLKYOwyHSCRgtUBjYwM97U05xkm7ua7SlmjRFkCKz
         cNSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768612614; x=1769217414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/Ux7m9EpBnc0snPDNQV2yXjDldaZk0lxzgCaMNAsB9o=;
        b=ShPkp6+am+fNe0bkhv6V3W4Md0ea5eJVqrIP5qr/LkfZBkLVd8EpExdhNOWXLY0eax
         MCJ5ODtFPS/ueX8bDiyt1LFgy3WFarXFGswCJM0zlx+T3JxLSdoC3NkrhdfHWmhrDPUp
         ygYhdy62Wf+iY11PK8XTnBKozKHIRz2jJWzDmdGzmyWgImQE3Rr/N5xOuuNFztRLR67E
         /fuHmD1uxLi0ad6DpmKq+lOuePHZn9+rf4U58pIrJbYYczk05D0HCbvRVGYwKmScjz+z
         E/veGTbn0MItGB2z9/Q2M11I/ZgRAT/kk5h6kWUsAtWziHG40TLGxKSRpZZiIIuaA27H
         eWyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768612614; x=1769217414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Ux7m9EpBnc0snPDNQV2yXjDldaZk0lxzgCaMNAsB9o=;
        b=UpjqxQOR3AM/EKbWUq+HNMV2AV3AaMj6M9Q2KgamPHj7vwQAMF4HtAxcq8G/eudJ4Q
         3imJJrjanU2QVCcLaAq+I/YbHWTig2Cthjp73fNRi4O/nOiHvjN4MSP1HJ+lP5qPWl9C
         aeVohOR6m1lzUFE9p8SnECYQ99sZ/D+Fm00pmG8Puw+3fZTQ1T+uM/Cx0UADxMmYtRA+
         s3vHzMLuPnp8JlZW+iwJSw1clnUJ9LGnMlQWAXkmKJvUEy67TfbDZPo2/+70r3W5aFbk
         prD1SVd7jkvTQX1iEsMw2BEGRLvVYadlxXKvTXsX0jpxuLHGwFkRk7duF22qVy3/mHq5
         beQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkpD/7kaXL28aBeaZrPL0M4EovnL5joZhU39/P19B/1MEJiwAzsclQGwjl3bmHjZ4AblgXkg==@lfdr.de
X-Gm-Message-State: AOJu0YzmNfvON9nyfKErxt9U4RZHU4CMim/5kvuPk3D737M3SM51/eEI
	b6YEFpAvwxxJJBtjNWd47aCTUkYIx4x0Hdz69wo/N/AtUTppE4GdIJL8
X-Received: by 2002:a05:6512:b9b:b0:59b:79f7:63 with SMTP id 2adb3069b0e04-59baef0f5dfmr1455261e87.51.1768612613629;
        Fri, 16 Jan 2026 17:16:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eh6GuIgVTYn1IyDXO0pgGDmuKa7IqCQVvxe+XS6vYUHg=="
Received: by 2002:a05:6512:31d2:b0:59b:6d6e:9887 with SMTP id
 2adb3069b0e04-59ba6e4edcels911334e87.0.-pod-prod-02-eu; Fri, 16 Jan 2026
 17:16:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoQ9j0u+jw6hJhs3R/2ZpqDDjjmHrIQgRxTQqGTJ/cI14h1+UhOgAlWyEleV3L9bQ9sruJu3L/G9o=@googlegroups.com
X-Received: by 2002:a05:6512:aca:b0:59b:7d3a:2a26 with SMTP id 2adb3069b0e04-59baef00dfdmr1556571e87.44.1768612610752;
        Fri, 16 Jan 2026 17:16:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768612610; cv=none;
        d=google.com; s=arc-20240605;
        b=aZT7lVmd+2+r46q0nU8xf+32z/u+2vmsnLQquFoA5Ze1qISN70xeePpJ9SQbJfjW3Z
         m/1Wyojawi+TJt7SZdeP6eJqxBzZWPkrTPf1E9OFXlpHJZjaFc/DoqYgAyMHnEhFYFNJ
         TPiKB2x6qn8zy4EMrgZavgwYbmywvX69MaZy+XD36NQgQWPsXrmglYlvvW8SIUjT7W+j
         VSrnO7HbGZrSNGZaKfFfq+TdPxVrrUchBMv+jx0SM49TMehIo+snPW2iFEIbs1TB6LCW
         vRFaSu7UqRqPNlN8GCUO9ax5ziG6y2D2zACVJz2YEer57gqwCP52ZUNjFoNd/CGY4j8J
         Q0Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gp8dpIv/Dfc5cO3s+321RGbSFnooMWYq+2UyEKL6k2M=;
        fh=dPPH33dV98tlfJE8Xhm2Q44pkEn6TSqeAKcz126seEQ=;
        b=jly8DkRmwgA+QIQPev2bj0kvPsfGHvHSBbXIsR8UfXolzXauN44i4Zksz5QWZZx5D8
         gjB4NpviOluMbSejtdwuVvhcO7PdhfvrPfeJwTXW449/8Jcsj4Ery/wgB8AWqkdD6CXw
         A4s8+252Dc07WyOT1lHx57rtu2dHxZaQRST/KRlnjWWO75ZcTJh6o39M7EwbqsC3UMRM
         My/n5zBGWFoCGLkldWNUsnywEUlRtagYZdJn1VNY7pif2AeK4ni9hQIT/+vASD569zHu
         9+3klaEbeB5KGy9jDry66jBpKue9PnBDNC33lSHq4nRnqC1QP0PHS1RtgIsVBMK722zs
         fCXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R5iT04zJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e285a2si893361fa.5.2026.01.16.17.16.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 17:16:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-42fbad1fa90so2330358f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 17:16:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUS+NA9WFAU0cYXEB/Znz/zPH2WqMZiVFIuQw4ury/4IwnxKCO6JqqVrP8taLPG1O5oxNFCrcmgaec=@googlegroups.com
X-Gm-Gg: AY/fxX5dexhuT/IDt1u+AhNAczEnmbYi+7ubIrVmTEmtJ2fwckI+XYyEnVVGd2j4dS9
	36AJ0m9++GjfJtuPqBCPNpj7K1ZeYHqu5JJViEl0UXNeehePm52Rc1B4rGN8hya2gp51B5yUbqt
	odigEKKKQokXT2x98155euCJ/s+fFz6AnHZXvI3pg1mV/urtt1OXxpOC14z4jVVdWcGsi2YONpQ
	2/dVLeDUyRnvvKOXJrWkCvg50NxTwusUuY7yDX8/PH64usPEeatCZt99y9/0UaDD0pyc7tEtnyP
	dgVzFR4pBtwVcAnMhAG3rMELUQw22bZjkjjY/lU=
X-Received: by 2002:a5d:5f94:0:b0:430:f879:a0ee with SMTP id
 ffacd0b85a97d-4356997f1c7mr6293652f8f.5.1768612609986; Fri, 16 Jan 2026
 17:16:49 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZeHdUiQ-k=Cy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw@mail.gmail.com>
 <20260116132822.22227-1-ryabinin.a.a@gmail.com>
In-Reply-To: <20260116132822.22227-1-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 17 Jan 2026 02:16:39 +0100
X-Gm-Features: AZwV_QiTZME4zVfDXinUP87CAfZ4TJxGgME07itg4LO7utgz1XQ8x_7oq7n1Sw0
Message-ID: <CA+fCnZed4zuPgoacXgEKYjPJ-r5JkZTFcgFFysFLngMLkrhfKQ@mail.gmail.com>
Subject: Re: [PATCH] mm-kasan-kunit-extend-vmalloc-oob-tests-to-cover-vrealloc-fix
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=R5iT04zJ;       spf=pass
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

On Fri, Jan 16, 2026 at 2:29=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> Adjust vrealloc() size to verify full-granule poisoning/unpoisoning
> in tag-based modes.
>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  mm/kasan/kasan_test_c.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index cc8fc479e13a..b4d157962121 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1881,7 +1881,7 @@ static void vmalloc_oob(struct kunit *test)
>
>         vmalloc_oob_helper(test, v_ptr, size);
>
> -       size--;
> +       size -=3D KASAN_GRANULE_SIZE + 1;
>         v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>
> @@ -1889,7 +1889,7 @@ static void vmalloc_oob(struct kunit *test)
>
>         vmalloc_oob_helper(test, v_ptr, size);
>
> -       size +=3D 2;
> +       size +=3D 2 * KASAN_GRANULE_SIZE + 2;
>         v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>
> --
> 2.52.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZed4zuPgoacXgEKYjPJ-r5JkZTFcgFFysFLngMLkrhfKQ%40mail.gmail.com.

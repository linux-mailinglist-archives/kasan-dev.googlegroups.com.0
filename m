Return-Path: <kasan-dev+bncBDW2JDUY5AORBFO5VO3QMGQEDXEYB2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 850B797BE77
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 17:15:35 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2f750ea1a1esf53936361fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 08:15:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726672535; cv=pass;
        d=google.com; s=arc-20240605;
        b=J1TkHLXVTH4quIu2FwkR79zQNkd5VVCjbqnXvvfztj5ZjbUtjYDrMC4BXqnNnt/B3I
         Xl3n8qLdG43+t4B1qbmRbDU2kHkqi5PGiOI7Nq/zI3IKRczxXb4Q9BupCJ6WE3k4241z
         uGB53fMppuZ8AhSvGK+CqdIvMZ2yg8cWK8j0fOEiJLjCu0v9zGjuRYACkxtiXwZNJGan
         4UJ30BUbQOmpli6R7iXulWY1Elt2hGkqjwkNzL9pBEQslUJVCFIPkiJWtfZCyCBGNDpQ
         DbZopGbMW3/g1wbcTO/7dxXOd5Q1Woro9LO1DuWUH2xVNK/zEXxGzWfnb8kVDW0QtnHv
         zmVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=sqG/58fVSUivN52YghUXqjD3ltTNFsRtGFa9Frz2oE8=;
        fh=yVraPJtdpl6S+m7dFzQ3gxcISgumoZbgsg2nychV41Y=;
        b=Ff9JIYKpXtFx/GolDjNLM3moSy6uKTynLHkSj53fnUWH89zN4Ql7BdmQnfS2SNeWih
         bLKH605r8PHvAynf/qiYkck6y8l3w6Muc/yQV4c4lGuC/T8fW4sqF36Mr6lqn7upq8tT
         pv8T05r8fEZdV0IISPYlGLJG0ZvwM0ExRV99Zqduw85f267KxW297V3Uy6KFootd8kj9
         hIyO38NOPsHw3J/4RDLUH9yAJ5SLX6nbfSluaIEYtubDZTDRgMjKHmi3h/7bGyvxWEYE
         fGBNAFdznR0JFhadnRxKNyxzTkSWRNfAizw0XOP8AfGgXnysUJ2NHMxhbULiNXodyxJy
         /OmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QmaWFcb4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726672535; x=1727277335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sqG/58fVSUivN52YghUXqjD3ltTNFsRtGFa9Frz2oE8=;
        b=imjSf4LgM+n/XREW2X8q12O4pw3RoV5Q9fdxcf1ve3d3w9OfTsagpZt5I45orbbINB
         dshKO65/kZmQ33y/OjmCC8YipYkji07A7E09fFG/dUyd/js2g5ECYuW1nUyzECV0vRkZ
         ZD0jjwiPRVr5KxzRK8gjanfWtKS6cvuNjGefNWZzcycvp4QybhkDd4gTINhWcLKBFVOa
         gVVUaMkvCpFv2X7xLRNtc/bjGMvHts6wqhEwEic621VC+vki4DABXB/UEdY60AuwoEeR
         86MvcD9oBoHQEC3Fa+/GKtME8M5xaKC+sVlTkXoiDsvqDKLUk6P4MXjIDm2yESrZMnFn
         r9hQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726672535; x=1727277335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sqG/58fVSUivN52YghUXqjD3ltTNFsRtGFa9Frz2oE8=;
        b=cA2r27DwtoaCjPwzWvaG9/K7kQREEJ0e2EOqgGs/ZQw1Ue8yShCR6lwsYMbqOvKuty
         tSOudGEe8L23qrqcJKk0ToWz8QVkX/lvv97gZY69XrEbww1uKBvhSVL+gypBSNQk+ZEn
         f4rkc63fNOZnar56LJvn5jtZsQLOVTjkTw7GV24iXcwKd7BHbS5so4mI15zFajQ44zNE
         pwaC7WgGXWB4KdIteyxchxUpcZiuD1loLxVPO/a0SdCYXPP7JeauaMm3q9eXGnaLjYDb
         XPDaCGizZQe7iayt4NXNnbgQMFgOKMLipDsFD7uIs0m8HH6Ok7Z8IrpUrS5DyDT+4+NW
         DJkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726672535; x=1727277335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sqG/58fVSUivN52YghUXqjD3ltTNFsRtGFa9Frz2oE8=;
        b=PbNrYd+dS9sUFMnfzRd5hQrqjMdiORBze/2CAI1Z4eSAvQfYMxc/ibCMfLBLBn+2R3
         AGOTfJmr1y5xmB8unWQH6Sk/EAKpR0GbPrUSABqESWQBTl4EOHRmguXIyi1qwPMYiBIj
         lnOSfbRBoju8Kt5E1+C4V8ZR0HxB2d9F+z7x6uxRXDeEbFJWzsXg0g6as6Sh+rJuweg3
         8Ob5BKKXLPouBHSl0ef0jHqpTSoHTFNLGYV4cW0/yAGxQXGEK0g1maHVtnS8OLJYIuLg
         Z1jgw/UoHGeljAESG+xkHuUXkWmm5qJGJWk1W7qIHou4NiB9JzPTedc7FrvkPndXiuWr
         kNIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyDT123xvTWFcRIpSh2UdBMFmpauxBkRtcjZv8OszS9O204oDFRtJQJPc6jg/iry+dMVbTSA==@lfdr.de
X-Gm-Message-State: AOJu0YyU2GceRqmpiIbmLjXQIQ0DTNJ7K9P1NwjZOtQaCTDJCYF1g993
	bcrx4VsQjUwYkEVi0HwPt3vxVGG9qRql+4qOZVDxq2q96q1/0H1w
X-Google-Smtp-Source: AGHT+IHbr9alwr0dvCzwuM+sfhWzHX6ZhI+GIdAK5xCMSUqQGMpHFXReX1Pe4BJFt5E2P87TgfVXbQ==
X-Received: by 2002:a2e:602:0:b0:2f3:f2b6:6ccb with SMTP id 38308e7fff4ca-2f787f00aafmr86917661fa.26.1726672533897;
        Wed, 18 Sep 2024 08:15:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2201:0:b0:2f0:1cb8:9ec5 with SMTP id 38308e7fff4ca-2f786f54092ls19007471fa.0.-pod-prod-09-eu;
 Wed, 18 Sep 2024 08:15:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGZvLXZ9x+Os3nkFPxBpfHzfnRfZ89obu5Dm1VnzncPUQ7FfrIJ7iuT1EXHc84NijqvZQLlsHz2G8=@googlegroups.com
X-Received: by 2002:a05:651c:1549:b0:2f7:631a:6e0d with SMTP id 38308e7fff4ca-2f787dc3b59mr127828311fa.12.1726672531843;
        Wed, 18 Sep 2024 08:15:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726672531; cv=none;
        d=google.com; s=arc-20240605;
        b=GiIzyysTW9CotvpLR3HU153pOBVWg0YYA5WZdH4vrgGL1n2vtSmon9/1i7q+HL+N0h
         e2yJxBNhNujPlSi43dzOyHtSH8IZMF6VJg9syTenLR2dGZcUOm+9wirWUEuHAFDsAUOt
         NrBlEj+Y27gpFZnflJA1U+zx6F3cJ32Zt6ISvmWaGu3NQILCiBNPird9nf5VvPeyXr4X
         hGFuLD6qec7KyTJpU8c2VyvU6Rgbx2AulQg/8g37ig7nH3tYyA/IeX8AXAT1k+ROoun/
         pt930EwwMNv7/KwRXbc6/I+btHoLMi1PdYHuCCO3MuXtoXTQxhULTMxB+RC2hj5yfCKd
         6pYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0e7U1XrXIdEL6SVlFY7nb/dZRU8i4CDxNhm+to+Gq/Q=;
        fh=t3ifcw/Gc+GjUu8QDMJrXmKkNO88tZUkjRDw+u9gXa8=;
        b=EQo54symUFQeC2QwhF3/rYOnIuZ/2rt/7xUQcQ0+5XHUIMLe93sL9lyDw3Ug7MjFhJ
         toX8V3/AlZCU0yRUwhEF7lSiLMNkC5oGworFL0rCr6wEyY3AqyKa94RgEYlZRKF63ehK
         otkh2iyJAnvWr0JiQ7KdDBOV16RKyy6eimA8TBM10VLmF6wpqosp7ToM4wMKErIDWNWC
         5GF4Gi2B889eIth7cm5Y/XeleUZDtkuRTx6jBp7kxRBWy+pT6SBkRZkqK2eJICi13XR0
         Udc9tlgJhQ7inpehpMM4xwphA1r6OMnjDdcnDwfgXbWIPgEnQW0djBVwuDM1KVr/6Zmq
         E3DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QmaWFcb4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f79d37d155si2323641fa.6.2024.09.18.08.15.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 08:15:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3787e067230so4806644f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 08:15:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUWM5TyflUUTTEsvU86RRBAmRRYFx3viqpOjUSeF4XsZIfK/gPcXDwag73DjEudNAILWS7PHY2C42E=@googlegroups.com
X-Received: by 2002:a5d:440f:0:b0:371:8ea0:e63b with SMTP id
 ffacd0b85a97d-378c2d7275dmr13798552f8f.52.1726672530778; Wed, 18 Sep 2024
 08:15:30 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeorA7ptz6YY6=KEmJ+Bvo=9MQmUeBvzYNobtNmBM4L-A@mail.gmail.com>
 <20240918105641.704070-1-snovitoll@gmail.com>
In-Reply-To: <20240918105641.704070-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 18 Sep 2024 17:15:18 +0200
Message-ID: <CA+fCnZfg2E7Hk2Sc-=Z4XnENm9KUtmAZ6378YgeJg6xriMQXpA@mail.gmail.com>
Subject: Re: [PATCH v2] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QmaWFcb4;       spf=pass
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

On Wed, Sep 18, 2024 at 12:57=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..9a3c4ad91d59 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1899,6 +1899,26 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +static void copy_from_to_kernel_nofault(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[KASAN_GRANULE_SIZE];
> +       size_t size =3D sizeof(buf);
> +
> +       ptr =3D kmalloc(size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       kfree(ptr);
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_from_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_from_kernel_nofault(ptr, &buf[0], size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));
> +}

You still have the same problem here.

What I meant is:

char *ptr;
char buf[128 - KASAN_GRANULE_SIZE];
size_t size =3D sizeof(buf);

ptr =3D kmalloc(size, GFP_KERNEL);
KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);

KUNIT_EXPECT_KASAN_FAIL(...);
...

kfree(ptr);

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfg2E7Hk2Sc-%3DZ4XnENm9KUtmAZ6378YgeJg6xriMQXpA%40mail.gm=
ail.com.

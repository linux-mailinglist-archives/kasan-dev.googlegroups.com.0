Return-Path: <kasan-dev+bncBCSL7B6LWYHBBWMX326AMGQE4Q6XGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1817DA1D6F1
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 14:36:29 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5d9f21e17cfsf3870482a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 05:36:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737984987; cv=pass;
        d=google.com; s=arc-20240605;
        b=RVO6VLYZfCrzmlgQbBH5XR34BKZAbRXVjMZLlp3xk23Izx3hgtFZqCWvp/QRRsYWBD
         PnN66g7zpuYOk2MJ+eX3gDolLkKAxie1oJjpkaxsjc3r/ZTjuaCR69busYcBq8pmy5K8
         w9Tc2nM9p11+EKyhHD7YklfYK/pZZcDZrppPEOAHrihSKobMJ+NDZtznhZpTmh9gu9x7
         GD1LMeyV6vFtUEjNNj2V8wIl2S9PAm9rGI/iTRIqp5WJpufuyM+mYkpNTeMfbInyTjZq
         El2JK5x+FQwxCQs3Qr7M/yRZFtyrzN+JcVdWEfaOtxTkr8Mp36agWMsW8k3E2w2xTCz6
         if2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DYB0NJP1qF0PBmxe+Byq7wrlhiZaiySzkuH/cyLNkO0=;
        fh=pcf8fP8I0deZHEMRd6LMj06hUSLLP54zj/BLd2zEyCQ=;
        b=MG7tQSuOrfCm8L2ms65nUl+iO08PLqSoay3cnVD0Uv7k80Ehc1UFWSSL8PoOtQPuZV
         Rhy92H2zJ3hMBNtSZk7Rb9qG+GbwUqyronC5sbN7VR1KTHEw7FC+1kPlnB/Vrz4xQuNF
         qyO9Vr+4HiYKZA5U/ZrdKkYwi8qqCe6e1dpDBlot9B74UeEOsaRI7pPfJML86mIKSHv2
         OCd3tw1bMWAR5fE9id1IzS+wsMVxSvW9Jf+sLl5BUbVt5NTT/sE84Ljj6gK+x3cJ/tM2
         2OD7950QKC4LYDS4L6tK/gbWcmMaO+DINjRi/VPdvZdRLX2DnMYxWjxUDehMe0dusCX6
         ZEGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RezRIyIj;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737984987; x=1738589787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DYB0NJP1qF0PBmxe+Byq7wrlhiZaiySzkuH/cyLNkO0=;
        b=oq6YKPW9ab4HDOjlCQSVKjXjPwKf/G80SvYyCFHmuEd5KtKMyN1CIIFVS8XIpcMIeh
         aaKBj0m58x93tTuKxw91dBMGZPkwIUnFVS9CJi+AEiKjLiZmwoqlBzakoNcSGrKPZoQo
         UmesrrT7ZWD0I4IP0WJPKRShvf+JFvk0FmCITsAndrQvEzG0Zej4lPK+151DZcjP6Lj3
         jBQUFimwPhOD9YMtG3ToEBV3V5JEBijd1z3/56HE3s7nCkFTT07kANoQ5F+MRdwfzM16
         9v3NeVv3Y0ESmw/0aLk+8rTfp9crquCaiFfAgHY5tLEjAIIqN6i9oKj6G1SpZDIEDSXp
         VyWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737984987; x=1738589787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DYB0NJP1qF0PBmxe+Byq7wrlhiZaiySzkuH/cyLNkO0=;
        b=DCoIhxAjgLU0vWUUox9/BfSItFNNZpXwo2VCBvkFOwAb4xNhKYFc9pG2nG08mL8/2X
         gwnWqQeDpkchWPG9gjt+OcJG83nOao5JTJoQjf9x9foHZfzNADihZk7jE5P+UeHlSW6w
         N+u2EP4PcRLrdRyVy8JhVaAztYVu5GGBRFOfrX4yRn+he4XImHcPF+z8HCRlzNPLl4ws
         V5cLsDAljWykBQuzegmTsvKjlNhT8YlzgaVhlSF6uqQ9qxL89MGrE3FU//WNSTPdRs0g
         SBhmK5RovN+P9Ktlnoy+EMg0NSTQDRRw+IDAMpreUsqusw5E+ZsKB/kU/I+ZaQ+AkUFN
         kHVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737984987; x=1738589787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DYB0NJP1qF0PBmxe+Byq7wrlhiZaiySzkuH/cyLNkO0=;
        b=NnGZeC4ASgys5IqewPWcDGlCHkRydxoQsGUu3QFCP9+X2ZHEopI9xEpttkOoAJ5q0A
         pRuse7750qzJnLMs28AK5bGeUB+Z0w8hID+8vDYf9OlxlgQDkD97bvibdH5G0X4WlgVP
         cLwSAOYCiBIINvKb8xgI5QxE2qNjlN7CttxDGgDdCUBA0Il4/LMogCd5cFYf4wGH5RJ2
         Py65ZSYoJ9tFF4bwSUY1fc2kIInRgaBNYooIWCnpHQsW3V0QzVHKGIFP6E3/BQ22Szzx
         PVLbpoTWJOjG8/8yaZBoly/3HNnbNtoW2ycyBVC0ZOpZdI5We+e/y2CffqzMoO3E7Tx4
         47/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRbHtuy1MK77l3+Np2hkSTzFcTqxxb8RlQfwq+d8YaC3s4p1T5y6nm0fiA/FDSPEmDphChfg==@lfdr.de
X-Gm-Message-State: AOJu0Ywjb87NBaw8Y+ELJPt9GISC24oWOGpe05Rf0BFf+fxZB4SNRjQ1
	vOnLkpiNpP1+NSvcm0iev4YSiQmOfEwTEx6kbtZFtm32faeTyjjP
X-Google-Smtp-Source: AGHT+IEYNy8CPz4kqixggPvZzwEXwO6xLgZlFBCE3S7Od4iWzXyrhuC9CTehpAes2bvo5SKNYJ66ag==
X-Received: by 2002:a05:6402:51c9:b0:5d3:bc1d:e56d with SMTP id 4fb4d7f45d1cf-5db7db2dbe4mr36043641a12.31.1737984986009;
        Mon, 27 Jan 2025 05:36:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c850:0:b0:5d3:cf02:d209 with SMTP id 4fb4d7f45d1cf-5dc459e3e2als67337a12.1.-pod-prod-09-eu;
 Mon, 27 Jan 2025 05:36:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeLh3Z5JKrn/Q2bKmlWOeQ05c9qgwlD6XLG/Sy7HvPMQZe8TY7aKuyrE8MJctCErVt6heI6yv44+s=@googlegroups.com
X-Received: by 2002:a17:907:7eaa:b0:ab3:398c:c989 with SMTP id a640c23a62f3a-ab38ada1546mr4369589866b.0.1737984983438;
        Mon, 27 Jan 2025 05:36:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737984983; cv=none;
        d=google.com; s=arc-20240605;
        b=K3AeoZRSwn3hmdj5CZhVVLxwnRrALEzyi27oKpQYhSv3/080uWcFuwPigC+ePbLfnP
         nWoyR0qtIqBwnnRfM923qx9PfV4/vqF5F4IiKO6h3bBRKkuKkaubc7UiXiAKmiVh8zVJ
         eYOCw9wuS6yn2sHdeRbpbR00wYivFKUKV99oiDuVK3QqmT+KXSkfg2kgMKXUsKwqPg70
         7Q+SZrY5eG4g5XifLMcj0toplkgqW5+m7tzDKkpF6eyM3bP/8tlexMLURenV6XKHHP7F
         28ppbMWk5FH0XD1PgMhUBdnwJ6NVUqplvan4hZkugqfk844hn9Us9obxo8GO5rrew5rt
         DizQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CHlG6AWWEnigDewIm8jICn9LKhM+kgmczZJmbvtFgt4=;
        fh=ph2jxtMkTbqQ5aQToJZsK02k4pQzQE1nseJKXvclVTA=;
        b=gRkLKyhdQ+GQBQl0GbU4spNFHaLNj8O3l2RE6i1mcntL2WvzISROmWHf8r7n9Uz7wl
         +LBW1ej3fPJyv9YctjYx54wiIsDkUN+ly2I8X/cX5HcQ3Zn6D0w3H+eOcsDqVGeXVe6B
         E9l35Vy5Qvprknyw6ovq9cBhxTIy4q2zHTxm9fOStPJRcctnNHe+3NAvaE9Bc8KLjHmE
         mqMgyThNAyG8hZEWyye2XkE40tjyxA+KmRh/xFPD0zU2hiQ0AkcJYfW926X+ZTshHI1h
         FJhJgnf7odPI22KGCRIwmYOSo/XamX+2jdsuZyHvXGhADRRwlxsqJSIFkmW/J9Ab8K3k
         mT2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RezRIyIj;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dc186abbcdsi148038a12.5.2025.01.27.05.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2025 05:36:23 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-38636875da4so674054f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2025 05:36:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV10dxt2SfKRmTXjM9845AGmxmF7cjECui8PKEdX3v0prdiYfCWu8jI6Zgj2qcbw0u3sXOPrM5mZtw=@googlegroups.com
X-Gm-Gg: ASbGncu5FzIzK7wodtogkwZZu52z0X7sWtvDYNi5+iIyk3fULuNY47Uh8e8gYwouSV1
	hBxB0wDd3p3RZWXQuWlQkMhvU2/fMYtMS8eA52szz4JR5Li8S+uLqtCfeVyFl0pynmK4kP1KhM/
	+ggzv5a9307STuLLXx
X-Received: by 2002:a05:6000:4022:b0:385:ef39:6ce3 with SMTP id
 ffacd0b85a97d-38c1a7d087cmr7134980f8f.0.1737984982791; Mon, 27 Jan 2025
 05:36:22 -0800 (PST)
MIME-Version: 1.0
References: <CAPAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ@mail.gmail.com>
 <20250122160645.28926-1-ryabinin.a.a@gmail.com> <CA+fCnZdU2GdAw4eUk9b3Ox8_nLXv-s4isxdoTXePU2J6x5pcGw@mail.gmail.com>
In-Reply-To: <CA+fCnZdU2GdAw4eUk9b3Ox8_nLXv-s4isxdoTXePU2J6x5pcGw@mail.gmail.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Mon, 27 Jan 2025 14:35:03 +0100
X-Gm-Features: AWEUYZlL-o4Q2NjgFkTgV84l7QgdO4LRWJbYKyDVa5jE4weNS1kRLZqv5Yt4eEU
Message-ID: <CAPAsAGy8HBMFpeV900thoXUr8QC6V5sCzRh65+NNbYGpJpYgHg@mail.gmail.com>
Subject: Re: [PATCH] kasan, mempool: don't store free stacktrace in
 io_alloc_cache objects.
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-mm@kvack.org, netdev@vger.kernel.org, 
	linux-kernel@vger.kernel.org, juntong.deng@outlook.com, lizetao1@huawei.com, 
	stable@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Jens Axboe <axboe@kernel.dk>, Pavel Begunkov <asml.silence@gmail.com>, 
	"David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RezRIyIj;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::434
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Sat, Jan 25, 2025 at 1:03=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Wed, Jan 22, 2025 at 5:07=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:

> > @@ -261,7 +262,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, vo=
id *object, bool init,
> >         if (!kasan_arch_is_ready() || is_kfence_address(object))
> >                 return false;
> >
> > -       poison_slab_object(cache, object, init, still_accessible);
> > +       poison_slab_object(cache, object, init, still_accessible, true)=
;
>
> Should notrack be false here?
>

Yep.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGy8HBMFpeV900thoXUr8QC6V5sCzRh65%2BNNbYGpJpYgHg%40mail.gmail.com.

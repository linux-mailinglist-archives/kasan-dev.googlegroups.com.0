Return-Path: <kasan-dev+bncBDW2JDUY5AORBJ4OZ26QMGQEANPBUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AAFC4A38BC8
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 19:59:53 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-30931bfee74sf12511291fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 10:59:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739818793; cv=pass;
        d=google.com; s=arc-20240605;
        b=IpU4eYv9fj8D4h+j+/cU5Lxvj535cFHGcthvnqCxYhIYHGI+PyMi2GrkjnnR7Z/wFV
         5szTu1GIoHaZ8VwCzMUDpvAOj1/XH4iEz7bkXvrs//uFSZhbtbUpCavp7cW/lOFel8bs
         5JcEWmxbzwmozUQT+95Og+zT30riIj8uCWMy2RI/V0awqAwIw2Qlvq7BfzCN2fOuCGB4
         qiPsvYWyo8A1KzekvvwhUCyCIcBtObTaGP5zp6yVJTwLlK2Tz2UYVHSSSpkOJTm8JxJ+
         gp67K+4q3lao1xAj/klFWwj5ZASsT6M7yHVHnXjBPhHWAnLcARCMuG8+DIMCHyu7JD+m
         ctLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pHyQL8ClR8B+QJ6UMSInUIJFBgJL5D8Gcxh0DXTJszA=;
        fh=771tRM0kgycZeZX7x01m/fy5CIhnQJPtW/m2krGpVsw=;
        b=UfFaXAdddtPS/Jl0cvPeEUdGVIYZhMN/MPvxsRjLuVwxSvaOGujfBdj+QfTP6+qZ/3
         ooQSnnuDBWC9jdiJ0FbtUzbKqKa9RrG6IVRrE3YsewdaIXqif4fHefwocuvJNoNsvUcb
         F8eLX2bThbY29TFOp6NVk2mMjlTRjllfwqvMOy8mnP3vwSD/n9vXXZ4Xi1ubNzJLRyfY
         SsIsprC/kL9j73wPLVGJ66XIcEBEb9wXjnESe5U9dHaaAatYjzlurUr958AunzvM8bxz
         nwqXom8LUsYVz0ixvsqu0UmDm5NgPn4huViSCa5uZAxyJPXigA01U64TGV/Pa1w9sZzR
         FElw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h0aFHP+O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739818793; x=1740423593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pHyQL8ClR8B+QJ6UMSInUIJFBgJL5D8Gcxh0DXTJszA=;
        b=a0GqCzBX1xznGcOVVAz9HWnrCSjgLuqsUppWTvrGsdgFqwSI+BmsND8dPjc+Bl9AJ8
         1JhlmIOx+NqXeNGUMizSC6XnPwUasYL1ow8t5frExQUqdIzG3D5KV+dnvUZXD+5WEBUf
         aoLa3ZJ4fZenSlkzLggZh0uUxJuc2wUiHh+L+v0y25HJnmHruGgBx2btoFJOufpWPZ96
         WL+LFhkNAgKTrWlP38Vmvhf1hfl+Arkxs02xCtQtFwFOFUOy803ZP74ngqxD0DiJYCX3
         QnALY/Bka3QFDbBK9PNAXF4H/dsdSOkPLq3g0y6aJPR8mLyNkCfFF4bNHhMY/aKz1A+k
         vgPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739818793; x=1740423593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pHyQL8ClR8B+QJ6UMSInUIJFBgJL5D8Gcxh0DXTJszA=;
        b=Sdh+jMU5cANJwLlJ8hv0XMrC9S6mX+vyoxDZxTjDC5bOv6tZLl2Sz1O2Od0/DVNy/M
         BDbTyf1ufXCOtKUmLVxEmBPUy/gxm3LikHpKru7M6JV3UcuBmS/bcwd0Y0DFD2i/6Ip4
         mxOpRrzGzuRn0jn9jhAnHRJygqDcWsWaRZ64aN5mGMsJt5H+sTzA8lkQCE+zjQkuwNnw
         vxZfiTrkTkrwuab7v6PjV40aoYaporOgZH/HSz+GtXNVx3XD2qYaB03CZaedQhubyeNJ
         JJPdj6qyPMxcrvEon4GdI+wrxy7hYQgxnxoCYOmklsFgKPCfE7EmiiGWjZgNdzoUf5TM
         w84w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739818793; x=1740423593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pHyQL8ClR8B+QJ6UMSInUIJFBgJL5D8Gcxh0DXTJszA=;
        b=tP9HqAE0wwTB18LnI97FD1ADB7kkkajge9OGnIABs5SI+LEr4NXCjalLROgHEVitnA
         HRzFovgOugRa/K67sdYWJfGXslvh0Z1TUErxrOPIO7NYyzQvRmMt0oPAzbBpYSFXmO4o
         +XLksxW0lo0eNgaFzH4l+zO5u8+/lBh2NUoz8bY2KAA1u7gN9Z/Pcsd3DtPFsqolaRCl
         3A+BXP0e8k+Tg32ovCkIet3AMz+M1bj64q/iY+cETI7XxM7oXCjYfYIgeY1HoFq9OXmD
         EjaP0h7Et7FiAXjghhNZnGbHRtDRc+MNl4ZRH5L8FN1f2ZmRcxQUYi7xXth652KNUUf6
         8nkA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/2gjjtbYIdmhD7d1TEr7HZ72Mj4hSrmY9qfmZLcY0iTEjFvl0pI3A8iKWlkPT3jNb7PyR/w==@lfdr.de
X-Gm-Message-State: AOJu0Yzx2yNxMh4LRfN6TJo4RKSUx/H4XCkg595QEP4HM792qrm+qc0l
	v4qGf5U91/mMOG5YfP/nMzFBSZ+Wovr5s3yrev6yAbtrlfpmfgPv
X-Google-Smtp-Source: AGHT+IEKH1yxWluxFXaY9YtayVcDvIZCvHmcLdbp1fHVUO6ekSSjXlPPTvlWa9vhSsPw+GDlIRiuvA==
X-Received: by 2002:a05:6512:3b99:b0:545:5de:f46e with SMTP id 2adb3069b0e04-5452fe86de8mr3607857e87.39.1739818791933;
        Mon, 17 Feb 2025 10:59:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF37iCgV6lEJa/LIra7G5MwpAJGwq6RTNu44epxKVVeUQ==
Received: by 2002:a05:651c:505:b0:309:25ea:d681 with SMTP id
 38308e7fff4ca-30925eada3cls694361fa.0.-pod-prod-05-eu; Mon, 17 Feb 2025
 10:59:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHsXTedZpahV9SeLtj5a69MRKi2RNp1sgOBHgZye2Yiv19+Hj/7LcyLEJVhwFREhknL/f0og7ZAx8=@googlegroups.com
X-Received: by 2002:a2e:8e8f:0:b0:308:e54d:61b1 with SMTP id 38308e7fff4ca-30927b197a4mr33050891fa.34.1739818788166;
        Mon, 17 Feb 2025 10:59:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739818788; cv=none;
        d=google.com; s=arc-20240605;
        b=ivBbPD5Ytpc2STbpfosW0HeQBVg5KCUSpj1IYMVHmMgbXlzU6P5Oy6UGPZGD2N3qPs
         lZ5OzjviBfEw9DjxA2AMJYHrlr30lGFBrYn/5WD2LV9eYPX7K3cSJYfDHScBYd1k1tUm
         eM4qccUqCIoGEaNrBxYIhaKhjodp6Fox7KH2tR6RCSl9LtnN/C5Suyr7J67dyLE54VLx
         zNgIsPs1nIJ9hw/NiIX0WFdaUrLGf3QlP4j4Eouh8jdFt7RnKHl4b8VDoXlMp2U4AeJz
         NB8CbWXtKadXPl9xTaisoeQW7ZKQ6JntkoGdzC+/MhzzJR2a33kR7T/bbxp7r6yr8CpL
         FDbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sK1f+sf0+Cg2T6VQTOIDYxT0Z22QiqhTwWz3Vtwgu4E=;
        fh=vnztm1cbPl2/rwoNfivsk7oP03QR4tnCcUQB27CO0hw=;
        b=fxAwpZCdYyH2A9U/J7sx4tffAEqbs/fGGizIbyDYbgwpq+S1RkhOdtWqnc5eOcrljD
         UEMLkR7bIX64dzXJgL3BPwyAAFR3MaQBbnlu5RU8TOhfcI2dgTvqjDc6I/N1ymrMwUJt
         VKtDS/5BPDz03HOAPuvv/vZcbD0//NpzDsJ7hdzA3EMbBcA0yi85x7yexIaFNA8gigj7
         EfWnaJC2WVgN0MyE/a/BnJojWRWjTmOiX56PhGZyq6QusiR3SiJF0KdqIHlbHOi7jjk/
         EU4RSOq020ecte2W9SLisNm3Rn2D0Elc3KNE1/YFt3wruqMw6AcNWqpkl12fxh9J26Hh
         pgHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h0aFHP+O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30924cb0b76si1474511fa.7.2025.02.17.10.59.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 10:59:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38f378498c9so2022234f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 10:59:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWKs/jcdjXICVBgFTXmDtRvoaSau83AJKTkesnKrLzesKKC5gobr5mSbpHAlDv593GLloOWDogZmZo=@googlegroups.com
X-Gm-Gg: ASbGncshL3H20x4dBGpj3wcycd2QWJobMhEQd9YtgZ/tTn6oq6WaAUFutGicVxaRYU/
	PC9Rd6jKsBMnPU8nVXdTQoTDLM6vPzaGW9BnJ2bRLOP6HcqHNv7iOMDGeVd7BY+TznRNbGieUlQ
	Q=
X-Received: by 2002:a5d:47a7:0:b0:38f:4f62:7e29 with SMTP id
 ffacd0b85a97d-38f4f627e84mr1592906f8f.26.1739818787231; Mon, 17 Feb 2025
 10:59:47 -0800 (PST)
MIME-Version: 1.0
References: <20250217042108.185932-1-longman@redhat.com> <CA+fCnZcaLBUUEEUNr8uZqW1dJ8fsHcOGCy3mJttfFDKq=A_9OQ@mail.gmail.com>
 <d9c96532-9598-426e-a469-dafd17d47a70@redhat.com>
In-Reply-To: <d9c96532-9598-426e-a469-dafd17d47a70@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 19:59:36 +0100
X-Gm-Features: AWEUYZmoRBvkdpI9_aKr68h3AIVmSuRz0ygJyNHx-ItVSg0Df3xpQx3Z3q7nhsA
Message-ID: <CA+fCnZeBuWMUk4n01z0tWf65dvyBvLghqohJYKA0WkQ5pMjdEw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <llong@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams <clrkwllms@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=h0aFHP+O;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
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

On Mon, Feb 17, 2025 at 6:56=E2=80=AFPM Waiman Long <llong@redhat.com> wrot=
e:
>
> >> + */
> >> +static inline void print_vmalloc_info_set_page(void *addr, struct pag=
e **ppage)
> >> +{
> >> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
> >> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_S=
LEEP);
> >> +               struct vm_struct *va;
> >> +
> >> +               lock_map_acquire_try(&vmalloc_map);
> >> +               va =3D find_vm_area(addr);
> >> +               if (va) {
> >> +                       pr_err("The buggy address belongs to the virtu=
al mapping at\n"
> >> +                              " [%px, %px) created by:\n"
> >> +                              " %pS\n",
> >> +                              va->addr, va->addr + va->size, va->call=
er);
> >> +                       pr_err("\n");
> >> +
> >> +                       *ppage =3D vmalloc_to_page(addr);
> > Looking at the code again, I actually like the Andrey Ryabinin's
> > suggestion from the v1 thread: add a separate function that contains
> > an annotated call of find_vm_area(). And keep vmalloc_to_page()
> > outside of it, just as done in the upstream version now.
>
> I can make the change if it is what you want.

Yes, please, I think splitting out the call that requires an
annotation into a separate function makes sense.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeBuWMUk4n01z0tWf65dvyBvLghqohJYKA0WkQ5pMjdEw%40mail.gmail.com.

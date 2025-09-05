Return-Path: <kasan-dev+bncBDW2JDUY5AORBYES5XCQMGQENDO5WFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 68EF7B4649C
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 22:34:42 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-337ec9ab203sf12768731fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 13:34:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757104482; cv=pass;
        d=google.com; s=arc-20240605;
        b=RQy+MVWKKCikgovC57jvt6YcDcO9U4K/vLvirknGWCm1oPoUnb2jcus+JD2NaVXPEH
         9WLvONQF/rT04vpzzbWDxWyziGYhqJw167sOYjflg5aA8SlA2osInGsgLOrMqPpqR6p0
         9OYJjOUrpnX6rEDjW/IvehafrK8rF83fqi8k21D1bvN7EW3136oSznuKDPgez92lBm1z
         bD/DM7DKEdF1heN/iZBiIT9/Y8SdbseUZpceyLQu+QJPfUqEdMRZIKmOXeEbkdOYQOqL
         EmNPyJc4vbZs3dbtfCaeXDG2uM+KZoKTJ0H/Vv8fZkQBjBqlubN9a12FOVYX8DHrrSjM
         wYOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Pd+HCU+zO//cJqKJgzs2MDHM82s65B920b/mZSL+76g=;
        fh=qoxsj/CFhpxef0p8xTnopodTT4CnBKYvCHp7BkGjpl8=;
        b=jaLyv3WJ/tUbnx7rzlqsG3ImOvhG/rjizmtgU7KCmQh70d4VqqQHcFb7Q7UKPhHXVF
         +DP76+GmOus0RhFnmbJJK6Ja6+2ZX5TpcRMNOxnU6qc0A76XU0M5I8XkN2jEUWL2ajps
         oTLwNm6fiGfceELrgIk07USOvIh3EpcKd8WHud4v3zp/soObhXInhEsioXFKNuEbYckp
         +3nTOHY1Z8LjzxdfKK/4v7W9brE5bytWPWFsNdSJ5oyEe0BFQCGeOPh9VV4WUI1pRQrj
         fIaA8pGizqz9lZuonLk0CGsjToDuJgHPypbMfBtLEJmS/7gf+T+3m6s8R//wKdAOQ24R
         KH8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=doYH4Dzx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757104481; x=1757709281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Pd+HCU+zO//cJqKJgzs2MDHM82s65B920b/mZSL+76g=;
        b=RSAH8+hEGGG5r/2Q4nwqc5NrU9CkRQbrNFXK+4GioXjhOA2ZCFdiSuxsAGmsKU+1Us
         z5EAP05r7cIKaqEIKe4y7AtywSIzkVkRzXCmIsmjscSqmJ9HgClyq8l9pkGprKAoyN/K
         ltvDrirUnm34jmGIZNWzaGtBfQyNEdMna28RHqfeSFV9KCfH9Cj81rL+aJqU6Ti7M+S8
         MOGSpT4JihVSW9EYkkrsvxlbFH5UTN1sE3ck4kqqzCXd/+LC7CsrGIH+7itPek5HW3+B
         Dhmv1ZMleCtG6SJkbVZQ6kQm1coMy6c73G0C2oDxQnDa8Gq1CWlAb6KT2hEJurwLPCSW
         Ow2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757104482; x=1757709282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Pd+HCU+zO//cJqKJgzs2MDHM82s65B920b/mZSL+76g=;
        b=gcKamY+WLbCgPUSgrl+u2IN3xUUWCHjgts+tZkLaDXqOERNswykt3Ffa6OzOFbWX0r
         6avMZOHWEC1GEv15JVmwxmM5xIAC95brMMwzloq3vV8sor0zIdr6LPaNQJkil16h3sk3
         GYP/+w6tIbBpaP8OdZGg9SHjcM7N6gpniQy+GTrq1fU+B05g3CaLgQ+DsNTBjtY4u/FW
         uerRDVMgmSdU73/gDhZbqBratrkLC6etRmXxQfepby9HlYLXEEc6zxEegsSzG9YlZ4qk
         GE2LP0/wZXR/+CJVTKpd9LFM5EJLwBaWlE98hYrPn4N/VpsIm//NxrtBU98UCZVvHJ1/
         E5qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757104482; x=1757709282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Pd+HCU+zO//cJqKJgzs2MDHM82s65B920b/mZSL+76g=;
        b=OCoq9uLqtm6X7e8/lviyYMqTQ1mDpZ9Gi2fTgk4QC+J+ts+w8eF5nUAePC++foz+WY
         dXqNnsPS6ZD8QaCYeArh60wXety9kCszvRqbbCz3GzM9xDgOhva/rvQqk3zAwJJoN68+
         sKiQx8Twcrjg9kLiezFAqUSlYXXP/xT7OsCcnJjXSv9FEh9inWxtXb+xx/neWbs4bPbH
         MEg7b8b55dAJP9sac62fazvWmS3vdEHI2MebyXbCW/2KAvHdWyBEEegclg4x9eYUokZ1
         UP6Z9izgmjYNcnWwcuJCEPf6CdeH2DmT32OizeeX1DNfwNZcqlMQrnf41omWNsYydoap
         8w9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzZyO6H7i/OxAKSEa88KF48l3zRMvE6iXOOAFKU3WkgD0WwXaBO1XZDTY6c5deVeYqryaxew==@lfdr.de
X-Gm-Message-State: AOJu0YyHT9UXid85RX+rDJ0b21MvRZGlW3107Go9o0eBpH+IygdlOkPL
	QnCG+GANonyybEUv7J5g2+s2iiS55B9DLBcSzzA5RSIMoQiyTTv8fjjs
X-Google-Smtp-Source: AGHT+IH3VThIpMXC3kF8QdLRtdxZOE1WLSEfl5tfA2hYN8Vv8CnzrQLRq5dO82NJdhx3emXlZdw/4w==
X-Received: by 2002:ac2:51c3:0:b0:55f:48d6:1cfc with SMTP id 2adb3069b0e04-5625f5362e2mr81432e87.3.1757104481350;
        Fri, 05 Sep 2025 13:34:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfjAXlmspf6itlxv/YVCsxPYCvXFD/AdQf4a6VyJGbnIA==
Received: by 2002:a05:6512:3ae:b0:55f:8255:d96a with SMTP id
 2adb3069b0e04-5615babf325ls398903e87.1.-pod-prod-02-eu; Fri, 05 Sep 2025
 13:34:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKaO71iW+qtCErknE5kcM7K2cVFn9XCfwPjhDTx4R88C03PJ5X9tR4O/koNMkjkhbOSpY5V7/HOyw=@googlegroups.com
X-Received: by 2002:a05:6512:23a2:b0:55f:4746:61ec with SMTP id 2adb3069b0e04-562619d8302mr62786e87.37.1757104478068;
        Fri, 05 Sep 2025 13:34:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757104478; cv=none;
        d=google.com; s=arc-20240605;
        b=XtLQwZtV87coEiGshB2V8J0xURpHWTOPLl+O8M/6wZyd/ZTkLxcSy4JoS/4/5kxzId
         gqKOjjXh/BaKRJDJAG//AMOo1gyOPbMD6y9Y9Fsf/z4fS9nEBo6vFTp9CPkIUcXhfftD
         xkoGLNXZqfryQnjMQZGpdUFWmf+Zyojal+Dzvi8ShUFqkpR0E1RO1WVVJeL9PwOoNELl
         pH9XXEwxJeij1EgAEQCqxADhRXO7nddvN6icJ61xsMA3O/Y1Tgn27n5Wcqxjjnpx5LRo
         mwLTWS9+3dU2YE5TfHwYjtDRuTsml/TXot3Rg+TZTuoIIuSVT0Dfq/s4f8Xa1LjGzdFs
         k1Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BfAilJ2gxaTlTEXjw4cUYBqev2DLfb4NtdyYplV2cLk=;
        fh=rsjnqn5H73n2jqtybUf5pPp1caMQzRDHf43Sqe5Ft5s=;
        b=ENycwGvKqdeaihnrcpnVlf/jBwFMox/lPPv5WlHKE/mB2awAHTvWpJttExDGUUtRGD
         FBaO78anNNAJ+JvG4M2y7n/V3LOplkZ66b8fid4PDMYz3gU5dw1iBE7r+MLMsjNYYi14
         RxqKy+N0mnqBn/zuwZP6qhWkWY1leuOjPg/F3AiZJ20HJrJbX6/1akprZRrLrsNXZHws
         gc3zjoHrpT54mkGbiToUKdxAsQatUaHBdI/v0d93CDnKinT0lMgHmB2BVz/WEUszpoX1
         s7erEsSeQgGtza5JYCMCp1e780m/nP8ULeoufC19fWfSwzrbJKpd4w4cp91XWfByPpAG
         Mriw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=doYH4Dzx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608acdff78si166210e87.8.2025.09.05.13.34.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 13:34:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-45b9853e630so23770405e9.0
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 13:34:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUyHYK071bS5vZXger4rEQys4Rxxqcmxguvfu9Hd17iQiLxVTe/soCze3bFL9FmLqnoKhkz+7Q3Uz8=@googlegroups.com
X-Gm-Gg: ASbGncvuTSZyTmDePYmYEQp/uWxKL+poX5D2C3NwU6f8Wz4Rx1w/yx/ZuO7W09L7YxR
	ZPeB6lQHiflrBqajW03rKTkbW5oyyZQCX3HGrsDLydiZ12+P0y+pcCwRLH7Y6iZIkbnteAVHkVG
	P6bDCP5spg29Mqqg4F6kSkSps7tpCiwqcNpbjzQdz+RmxOrEDLlKASbrwqpDBnYuyR06Ej1V2BM
	HF/e28=
X-Received: by 2002:a05:600c:1991:b0:45d:d6fc:24ec with SMTP id
 5b1f17b1804b1-45ddde8a579mr1347145e9.1.1757104477218; Fri, 05 Sep 2025
 13:34:37 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
In-Reply-To: <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Sep 2025 22:34:26 +0200
X-Gm-Features: Ac12FXx365TCqrnAMDPozsjaxIlbZS7cS1EckX64FuOxYCiii9Ap4uOCa5qcCQw
Message-ID: <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Baoquan He <bhe@redhat.com>, snovitoll@gmail.com
Cc: glider@google.com, dvyukov@google.com, elver@google.com, 
	linux-mm@kvack.org, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=doYH4Dzx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d
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

On Fri, Sep 5, 2025 at 7:12=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail.=
com> wrote:
>
> > But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
> > CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect this
> > should causes crashes, as the early shadow is mapped as read-only and
> > the inline stack instrumentation will try writing into it (or do the
> > writes into the early shadow somehow get ignored?..).
>
> It's not read-only, otherwise we would crash very early before full shado=
w
> setup and won't be able to boot at all. So writes still happen, and shado=
w
> checked, but reports are disabled.
>
> So the patchset should work, but it's a little bit odd feature. With kasa=
n=3Doff we still
> pay x2-x3 performance penalty of compiler instrumentation and get nothing=
 in return.
> So the usecase for this is if you don't want to compile and manage additi=
onal kernel binary
> (with CONFIG_KASAN=3Dn) and don't care about performance at all.

Ack. So kasan=3Doff would work but it's only benefit would be to avoid
the RAM overhead.

Baoquan, I'd be in favor of implementing kasan.vmalloc=3Doff instead of
kasan=3Doff. This seems to both (almost) solve the RAM overhead problem
you're having (AFAIU) and also seems like a useful feature on its own
(similar to CONFIG_KASAN_VMALLOC=3Dn but via command-line). The patches
to support kasan.vmalloc=3Doff should also be orthogonal to the
Sabyrzhan's series.

If you feel strongly that the ~1/8th RAM overhead (coming from the
physmap shadow and the slab redzones) is still unacceptable for your
use case (noting that the performance overhead (and the constant
silent detection of false-positive bugs) would still be there), I
think you can proceed with your series (unless someone else is
against).

I also now get what you meant that with your patches for the kasan=3Doff
support, Sabyrzhan's CONFIG_ARCH_DEFER_KASAN would not be required
anymore: as every architecture would need a kasan_enabled() check,
every architecture would effectively need the CONFIG_ARCH_DEFER_KASAN
functionality (i.e. the static key to switch off KASAN).

Nevertheless, I still like the unification of the static keys usage
and the KASAN initialization calls that the Sabyrzhan's series
introduces, so I would propose to rebase your patches on top of his
(even though you would remove CONFIG_ARCH_DEFER_KASAN, but that seems
like a simple change) or pick out the related parts from his patches
(but this might not be the best approach in case someone discovers a
reason why kasan=3Doff is a bad idea and we need to abandon the
kasan=3Doff series).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8%2BhngQ%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOUCR67QMGQE3DQYW2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C7DA71327
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 09:56:28 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-476623ba226sf110632201cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 01:56:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742979387; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVj1HBSDm0y7rM3GtWmnZZlU+OXci30P/Y70HFEgPh4hUsC0lNCa/PurWcBsCfF1QM
         JvJHnQafcjmftdVRS1IUfan0clocEBZSrVj/592Kp/RgMOkC1Ce/oyBS1FBnLmH7LTOG
         UHNqxl1U9hvebqPZNfPeXf2fPaieEvKHXxr7F80lhpcv48mfZq5x3f14ZynqfN4/3wWJ
         9D2IGvICN1U0DIKTbxtNjgxHIOtmRLzkP9ZuiG87y1QsWYV5yB4KV7Qewzx62yjqKy3f
         4HQe/8PZsF5M7pCt3cP3PMFNdoulvRnRccZ/1+oqWxhbRbUaFefLfnYldeVlWYznDJAN
         UwsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gzHr+0EU7hsBjPkn/q8aLP3KtIVZAirHS5V72G2xDBs=;
        fh=75am3q2HGPVnoJv+he/P8gFpuEiobHIu8QD19bo5HAM=;
        b=Ag6VQVDNQA1Ac1P5BOuCY60476m0AMQOJC6uWa0K4WVFQyVU49CfgjDpQrxH87qxGF
         GZfKZnKvE65N37cbqcL0vtaotwj8+CI7ksJ91OcxunyeaahxTsCz7sL3dt7KUHk1BJDa
         WXuBM8eAPQAl8LEHmIXR4cS094GQFOekXmJlmVhsSSrvSEAuA6EjP2ck/8Lyh4TQ4VVt
         GN9PtoVQNz+cWUnoUDdstNkytPRR5iQoILM/aFqH/fAhfi7LcoEYwI/ZSqN874xnU6EO
         RNNHA8vxnctk5FNB64XfApVO7wSPCdFIU6SnWBbpHIQGxRUyFVJU9/hqXx/39J4/Ggaw
         wYZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BN5007bc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742979387; x=1743584187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gzHr+0EU7hsBjPkn/q8aLP3KtIVZAirHS5V72G2xDBs=;
        b=Mcvbm2ORstqj3qAK9xU6tHNUVdM7poCHk10ig9VLmKM/w/JnNkf4sjdT7MDVeANNDp
         IpA83c+rKyeXTlgV2y5kQ7sOnvePVyYDGu6H/EwDYT0UWjDGdHUnZ0feNs6+6iDUVwPj
         3yWclmM1NhYzNsttjdgBS59LDxHRTkXoOSpY4pr3PAYkPV+piD2nAn0kGQQuG762CmRh
         jB0tmoT9GEcWZ2+LGgCJzy07XB887nGHOgKO+xlEbzHCK29yBi5FenHaBRHEKfy9DP14
         c7Yh2hnEr79/2RWgkYoiEyejsCvi5UzucFxPKwCKTagbXyKEh5QriY1/BYwJgvahFcZC
         3YjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742979387; x=1743584187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gzHr+0EU7hsBjPkn/q8aLP3KtIVZAirHS5V72G2xDBs=;
        b=qnyXmZwv3ipJgLntK64cxfedMyrFXAVHb/QTi3nQL+7s3z/8nmjXsJq25qoHOsqcl6
         r3Zv1gWpRbW1gCcjgnmPrYs4XdTURo2nzq7a2Vl9pB1iF3EPzOLkwL69QapFW/IQfTeR
         nySfZuI2vqQpbm2MQLkZOKMW1jaZN/oTOlbfkTe4fhjZpTdfjc8xSLOSonmzGDuCd7NO
         ErXxMA8K4QSju/4G7CgNJo6VUxlte3H1iZnQPfcGKs3RmVP58jHKHorCjPZ6UnL98Bor
         b9wHZvnO4P0Ns8wmhAZsILF3bS/oHIo9Qu6Ey//kNN+f6F7xaAYEa1bQ+QC3Hx5ZDThg
         DlYA==
X-Forwarded-Encrypted: i=2; AJvYcCVZxsgp76TiSe5EzpVUnfIMAhVWIMmL5l2tt8sMCW/VeJJOOeZbXjT4hS7OhSKQRzMzr6/kqQ==@lfdr.de
X-Gm-Message-State: AOJu0YyRvUNNjMjIJiWbqqqdE75xzYt6/ealCu0drvynY9yzCVI2s1uF
	Ls+lHSSSU4i+HNaOQ1vVRozylpi74JBLDnIRHpvEyRJZZNWcV5L+
X-Google-Smtp-Source: AGHT+IGp/iCM7QeXiTRA4sbhoiRyezwYUA90/pen68QbiITO7EOyKAPtVO5FKwLI5HdU4pYKJ6dbww==
X-Received: by 2002:ad4:596f:0:b0:6ed:15ce:e33e with SMTP id 6a1803df08f44-6ed15cee919mr52344806d6.27.1742979386871;
        Wed, 26 Mar 2025 01:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIXMrtTwrSqTytZQdo0xuPF7PUBMsRx3pZ/f9K1O6sEmw==
Received: by 2002:ad4:5382:0:b0:6e8:efc0:7a3f with SMTP id 6a1803df08f44-6eb34b2e10dls65762716d6.2.-pod-prod-03-us;
 Wed, 26 Mar 2025 01:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvQtoXknsm8bURIlUSOkfkF9nlNAdFYxLSgcm5f3N3qCn5NEYr7Z0cizs9crnGovwWNHmrrA+eM48=@googlegroups.com
X-Received: by 2002:a05:6122:8c05:b0:50d:a31c:678c with SMTP id 71dfb90a1353d-525a82dc9ffmr16533913e0c.2.1742979385665;
        Wed, 26 Mar 2025 01:56:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742979385; cv=none;
        d=google.com; s=arc-20240605;
        b=azhe9ZdS7ihCnuCIdT6YKmCWzyGG6MgWUyuBpL3mcuLtoOzbH6qb+abzfXIXmA5I8V
         xEP10vzyVYOwd/DrY5zpwMa13xRfIJdl+T9qhGlR/myufDzyVUOodp6zauxG5s7uIPl9
         XPYp/8e3D3CkQdHZPpA7P4mSxANIBrEpoaTYy9eF569B+5oFTqDu8U68Yb9qDNZI9TTN
         8g65EdYB9YLId70MKTyIKuShFSHciPowYKypfumX8KvjNeyNsPfAyNyicYDV4rwPi4Zt
         lFrx5lhUrLKIkt4aIIzA0LmmiZGqZR4MGDRuZ94EgqNe7o2YIEFi4xN7yLKkTV3rjXFN
         KWDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LUtMG1viScXqSNg0mC+JJDbGX6A+bo4La10N7sXD1PE=;
        fh=cEGsPynAem1mwWTt7rWoDjKLjE+DKrC1R9LmzLAUSHc=;
        b=f8Uc0qMDxpeztlESDvAn7BfgCnwO9hxu1B3TasN7oJHr9bRf2Aqikr3/dGx62VVfoV
         kkwe4dYSOGPLxf41azosP0AcJeOqEroBHHXkO3PswYAwsGKI3HUcUzC/8ECX+woCxiic
         +F2yXxBuTHc2gD38/DTLFyWyYx3dkLuxyMoW+JeUcOrVsvDzLNX+xgN3ktY+qPKXBAeH
         zzRikkyXLJcOrNpf4HGMBQ0OabPlsuGZ3nhkcNUyjtFnZTqwCPU1/yW1dXa03vLe0WIn
         IKPr6kU6gXSoF9inGJLLs5e03ioxX9K6mS8aJHOQw8o8GBJaPVX4FDGgrbNvnwYLzdHy
         Arzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BN5007bc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-525a71bed82si565436e0c.0.2025.03.26.01.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Mar 2025 01:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6e8ec399427so51796316d6.2
        for <kasan-dev@googlegroups.com>; Wed, 26 Mar 2025 01:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX35pDv5YOKgbBKUTnoZyfLT55JPI8d6YvvfqGXu8cN/tcdeJAQUDm7aiA/HD2pYkwvtqt4K3ijB1w=@googlegroups.com
X-Gm-Gg: ASbGncsDQxD7wuV2z0dfHFnmFYu7A8xC7GsjSBtBaCAQ5DaelhYRXYBlAv37njfTeyi
	zuFkSnMLttCkhdcxsYWvgMIDcdksJeg8YUMi3uOCoHBdQQlbnH+jgn9RR06q5uZ/+TrVR2MKTzC
	cyvBMg/3nsLewKay9RPXyE5c5187ieSciUa32kGGfoWB6JytI/UcX1/tbfRcKv/5JBCA==
X-Received: by 2002:a05:6214:948:b0:6ec:f0aa:83b4 with SMTP id
 6a1803df08f44-6ecf0aa86c0mr155919526d6.8.1742979385032; Wed, 26 Mar 2025
 01:56:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250321151918.3521362-1-kent.overstreet@linux.dev>
In-Reply-To: <20250321151918.3521362-1-kent.overstreet@linux.dev>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Mar 2025 09:55:47 +0100
X-Gm-Features: AQ5f1JpjU62368jKA64ScilFeokxJ4pHQ2EdGX2X2HRcHFEdCtoyyiq4Hk2zahk
Message-ID: <CAG_fn=U41nUt-kvSGS3kN9EKO8Ga515icnW3enPNuZmS+8A6fQ@mail.gmail.com>
Subject: Re: [PATCH] kmsan: kmsan_check_bar()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BN5007bc;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Mar 21, 2025 at 4:19=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> handy dandy convenience helper for debugging

Nit: s/bar/var in the subject.

>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU41nUt-kvSGS3kN9EKO8Ga515icnW3enPNuZmS%2B8A6fQ%40mail.gmail.com.

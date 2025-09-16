Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ66UTDAMGQEZ2BXZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 03A5CB59252
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:35:38 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-26076dd11d1sf35066575ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:35:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758015336; cv=pass;
        d=google.com; s=arc-20240605;
        b=QDPbqXI2afVWmuRIn678nOVRK+CJwWjPDDQQ9xY0wkDr2OoxTzdy9cnqftq4tseD8h
         aNeGP5uxIFwxFn1AK4Cn5YfVqvAXwRxtuM0JMuIyKqkjW+huwH3n1mqiXaOfOgMfv2ns
         +Xcx6AsE7cAlCnWVObIHLVz1yWDvjPeG+TN7f5KFEJxClIW6r+51HWEbo6n6mUmRkwD3
         gNtryAmwYF5j2lo5zJZIbr1vLPTMzux9eJTX5JrUP7+syHahMFUVYLSURFrLRnQHmXuI
         tYLb/73KTgdnLpPwNzrDmJVRS1eozKGDllEaded9WSOu376Y7yMJpf/TGtWuX1SWGWZm
         ymIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AjE+cK6OomiVWSTFYwjGYcNX964CnpninB91DmU7xkQ=;
        fh=M9/hJqpJJUQs2qmuBg6qJ0rbYV5Hed0zgJt0jMEahaM=;
        b=bTvHKZ+iwxUMtL1v6aClcq7njDKssKUG1VZZNCwdb37hGWeETK5/ZN0qugawgSXVJ+
         ZkpLpRXFXV3u4U3AmylXcLfMM35gyNl4QgGeRuUXQPI8yR9hUYPGczMyTpvBTi/YzNNV
         EqQbfXbYnK3kOnfWk2JVOkXc7N8+azNQih0tybOyVO9sbnh7zGZOGTtW2Aj7H8sZ9HaI
         XRasLpw82UL1w9fX3ZozP+TvoLWuxhIVImnZZrt9XNaG34yR7X6Onn+ZBQIORfKysC+w
         1tZI7/T3BoEFNQ2I6+lYM1zOidhovemfPluLOUU4hUnlrp0z2ENAMsY9lTD9M9GJJLfn
         P9uA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K9J5IZUv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758015336; x=1758620136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AjE+cK6OomiVWSTFYwjGYcNX964CnpninB91DmU7xkQ=;
        b=DovAHcoOcKZt1DT9i3/66d7ueBc+5lIoeG3ZHSNgDfoIBTxS7SVotZi7B9RhIJviMw
         sLoyhrCbcVtiYovu6+Z+/rzX4nOiaPVtHrkbonBwDcYRFm9hkK0i7iLirVWhjo4/oDNV
         lf0y/XtR3ZCvZNSFzuQvpqveEEfKXjSOAANq9N1a+eiukSkvAns5IIMIDAqt0HqPAd8l
         Q+gfvIBqyceeiEdx2KNTyl+LCRx3syeBxj9eU89yVCib50wgNlH+l3t1SescZhr+XDo/
         A7EoTTXNz9e8Lb1XpuUsXyJmE2N4J6eIsoP4fKJpYDtNIYgbcyRtOMA0tuom1DpHZt6R
         5zJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758015336; x=1758620136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AjE+cK6OomiVWSTFYwjGYcNX964CnpninB91DmU7xkQ=;
        b=EedhZmBvlJMP9Q1PWI8x9FuGo2JYEJ3PcvScEXB2H1nMK5J/nAr7rY+KaqgHAN/sAU
         Y4OPNx1TYbA9fQ9X3vAmNyxmiYIy/TOM3XxGjfuag5COxLiKMu+tOJh5pQYSBlfqjaKv
         AO1DyI51otw/sDVyEZRpGxBRfySBUczwCMwh+LqsX9Yuyq9GJWnaJdTjmeQZQLLzQpr+
         61U31Szu3w+dWauVC3IyyHCAS44X6Iw/yf3jB3mOUOQ94sIpWqi2jFctkTJWA4tBRfem
         Ri0ofd/FPjCqL9lMtgK7yhXFkDS/L4iKBiC2L/hAAugzXEafmfBgj0gs8BFapZV2xZzX
         EU/w==
X-Forwarded-Encrypted: i=2; AJvYcCWK58r/fSW4us7sJftxcaSRzWq6xlwWpTfyO+IwfDqs5XCbE5G/2h6ib7bKryvJkLWyb9AbCg==@lfdr.de
X-Gm-Message-State: AOJu0YwKhk5WThGkeIIdsILd1ckQelB5xjhHnvMQth5sI6kNiKHqLysc
	AZQ7lhEBMyfBgEefd32R+NlnLxVGwrM1t71pOmmyqRzRp6vGHCdePCwC
X-Google-Smtp-Source: AGHT+IEqSil6vZciioZWKeZUk8ADKykvzmFKuEqN8S+pR6aF+pNvDU91lYLAjdhgBMKQT1YcTE7wEw==
X-Received: by 2002:a17:903:37cd:b0:25b:f1f3:815f with SMTP id d9443c01a7336-25d2782cda6mr233497335ad.58.1758015336115;
        Tue, 16 Sep 2025 02:35:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7gLwsCLIkagwClGmamFWJwppvXhcbFa1DnaH1uSqhKWQ==
Received: by 2002:a17:903:40cf:b0:24c:c1b8:a9b5 with SMTP id
 d9443c01a7336-25beac2c351ls47367175ad.0.-pod-prod-07-us; Tue, 16 Sep 2025
 02:35:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjUyE5n+j6oXq1c27nQEOql4I42W3dRZI3c/VGOXeCegp3lMUuYsWspGxZWW7U2gbBZMKPcpcWUMQ=@googlegroups.com
X-Received: by 2002:a17:903:37cd:b0:25b:f1f3:815f with SMTP id d9443c01a7336-25d2782cda6mr233496515ad.58.1758015334800;
        Tue, 16 Sep 2025 02:35:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758015334; cv=none;
        d=google.com; s=arc-20240605;
        b=KPJcNgvHbrnOCwsZ0/EoYPSXavj0nin6hyWJLNhcP+bb9W77oTsqhdCdYyT701PBTQ
         Zx3jREsObAdx/XIP4pJyNx+YhR9uL9SmhTBz1hie1tmaaNDrfY6qy4POwsqtID5stMZQ
         eJwGD9cmrI7Vf/CwDVR2K/Q2Ip9423UU3FyAU5ZoTQ0fdbuAKbC83G4vfyO/bDhVyK0r
         UCSn675B3KBXri/HkYUS19gUNLO3+6gb+YnqeDZ5zC1ZBXyT7BWd71IO9LbEWSf8XFLF
         aYNUN8LqXfgHpOgUDCZDhUOxKVtHqjoXpIoKR8XNl7lXIxASwTpyet46corXJt6AWt8f
         RVXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ItFEEUKNnd6JDkvIGqIsrhAmf5lSlmXXN6ieayVKa88=;
        fh=ZFxtO1bU+w0TsWK3jmGTPHdFR2VEPoCBuKZd+1pq9qk=;
        b=KvqeE3H2d6lpfvoKNYxIqFVjZqJFfOIiMTtHKCSXGrEKNwYMIO0rfAB3+PrSdDarVK
         v3JAaepEBMWUzAthkxskfb6ssDKmuKbL4ReEo8tIH3pk6inXMWq9pxyB4x9W6y+t75BZ
         CGAq9N2bZrEl3alUD7tggis3HTCvu0IZhoCWEWrzoYK0BZyr2eI4IL6pGe35ujE9sRLx
         Q143Y2kg993CiRVI55KxtTE+zSVUlDVNGB59Oq/iIQ3riWSJIjz9hrJrKnGqEVG5JHzP
         U6LJ0gqJSZMVoTu1Wl8pYGd3tSgZmSr88lUy2W71oyg/Ir1TIfjaLs4MSCP0toPX8hXe
         bSMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K9J5IZUv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-262cd8cc2e4si2663055ad.7.2025.09.16.02.35.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:35:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id d75a77b69052e-4b7a8ceaad3so17666591cf.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:35:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURo3dhOhd8kn3qyCXofgpcARSTSq/IucvjIwLtq+q2Ivm40FChSQspCnMp0up5YyVKYXl1QuZWnCU=@googlegroups.com
X-Gm-Gg: ASbGncslLUglDoIYeIhdQYuICY9TgLvXoOyhIMNv40iHq01fxKZhkYY0puLI1PygezA
	CCZJ5cWhbUutJeeAsAdzb4UxaYDL0RQ53mCSjhkowSLT+01RdfIbueHHpfG/pe826JqjqiQHqKS
	oUZuFpY17KWsZk+O8FYo0hD1i7lZ2/AkjMJThX2veB0ypDjAT2mqtbxCbWTnXrMGVRnqUTFNTDN
	pZ0V+ZYI+aPmu0bcAVh2AUOCRI1Y2UIZe8URujDKFUHR8110zS3fUY=
X-Received: by 2002:a05:622a:17ce:b0:4b7:9438:c362 with SMTP id
 d75a77b69052e-4b79438e5dcmr151588411cf.33.1758015333543; Tue, 16 Sep 2025
 02:35:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-2-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-2-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 11:34:56 +0200
X-Gm-Features: AS18NWAeZ0I8Ql6T2VXhNmbi0_zOyyX9JImpZH4pIDJbyS4OHq46p0yv6zBf1BI
Message-ID: <CAG_fn=U-SH5u4Lv3CcqKVHnK1ewrF46AF3JU1eiAh-JYxj86sg@mail.gmail.com>
Subject: Re: [PATCH v1 01/10] mm/kasan: implement kasan_poison_range
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=K9J5IZUv;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

On Tue, Sep 16, 2025 at 11:01=E2=80=AFAM Ethan Graham
<ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Introduce a new helper function, kasan_poison_range(), to encapsulate
> the logic for poisoning an arbitrary memory range of a given size, and
> expose it publically in <include/linux/kasan.h>.
>
> This is a preparatory change for the upcoming KFuzzTest patches, which
> requires the ability to poison the inter-region padding in its input
> buffers.
>
> No functional change to any other subsystem is intended by this commit.
>
> ---
> v3:
> - Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
>   kasan_poison_range(), and return -EINVAL when this isn't respected.
> ---
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU-SH5u4Lv3CcqKVHnK1ewrF46AF3JU1eiAh-JYxj86sg%40mail.gmail.com.

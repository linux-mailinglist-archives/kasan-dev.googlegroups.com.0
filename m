Return-Path: <kasan-dev+bncBDRZHGH43YJRBEUN4DCQMGQEKRO562Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D053DB419A9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 11:12:51 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-74381fe311dsf5208515a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 02:12:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756890770; cv=pass;
        d=google.com; s=arc-20240605;
        b=QrBXNn7eP7LyrLZzqHI32kCVHfpokPOL+1YwkN5UqcfUjUEq/igKg+HqHuFNaMGScU
         O7vuxXNzdczUefx+E2HN58hBSAFT0Xnd/vNhL9GM5JP6UBKpnkmsu3paxRfH8JSzZncK
         TiKUbgqBn0GEwUzv3qhNFMZIYVQTCAimb5lDvqZRrtcT5IU6D+ERrFrHofsEX7yKSPYA
         52CVuzPjgGhkxpzOmOoPEsruImstCPtvkSLVI4gjvAK+celXyeZgPO7UI4qEhK/LMEcA
         lEd2K8gEhOTha0ON2bJIMndfb/Pto2SXjohflBqAYufa+4PSMCuJloiEh0OTRfAHkJNb
         gAyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JYF3fXHL+mm0Yf5DjQ6kAfoy8Tt633Kb6YRqL/ezfkw=;
        fh=TBZxpukeqsCKeL6iFNmvMZwSZwJM/J1k47vlBvVGAVI=;
        b=Mdr3+SD3AnJX7ZOGn/F9z7M/wsZQdgKh+1gDCV4BttEsUhvWthpSmJfxntwJt3lbvJ
         sdQLF3fRNqhp4z/Aa4caMKFyB3bgP6XuzJSEohmA4UJioSn/PBRA7tHDhT7scFMy0urM
         SQwhqpX8574PJoVCmTE9g41tgq63oIAQqSqi1Va/0M0Y0KhWwq8/W6ZofFjPSbjImI3C
         31Opzx7xGgjMXCJwym2spVYLdWySWdpxU9JdBC5w8Z8L795WLfBjjcnLg7c82ssvpEOL
         wbcGMi8fi3h0jZhQY//XCEypLMEa/+eOocRi2aSD8MredE/O1yVVkF1ZvOoVmEQZqn3E
         P/jQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LmopG++o;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756890770; x=1757495570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JYF3fXHL+mm0Yf5DjQ6kAfoy8Tt633Kb6YRqL/ezfkw=;
        b=bgezusrNqLe3kBsY64kYHzvStB26h4Nu881dAgFm7mPrZ52jK5dhUhZsFQn2ewF7Lb
         FS9h1Hu2OobSvvnd7BGIPTNpVcwTBgdTbyDHsdFXEHXAuLjHRRY6orZfPIFrVooZO3XB
         QoYbnQrZzqSOYKE3GgA+lojAABJCTz3x1h/fzlE15x39qB6N7sOZ/LexBMHx2YVyIgnD
         hBVzpDsfOZZb9CCqKaypZoUCfvzn6cdINReBbLiwM8MnT6PQuu4qcKFmqN6bDU3lSOeC
         sxVOlApA+uAQyvfHI/m5PnATs3X08C6nyrCMOzCyBObNY2YE38fxj4fvaVdiUqGW9607
         TdRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756890770; x=1757495570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JYF3fXHL+mm0Yf5DjQ6kAfoy8Tt633Kb6YRqL/ezfkw=;
        b=kQ0S8hkpgWwdTL3Q19gr8/LSCMvJFYWnLdGPz36o7mz2jl4elFnzx+foDYjWuUKqoN
         O3HFMGCbjyZcQaEf4aD9XFvoAPdQQqxc48RmV3bhSVlJmrTHJxPHT3S8ggVHFA3raiZB
         QxIW86NBO8PbzOQwwdduul3rG26Oy07ce07AzHjSkOxFzmBYuEXurS39UcUDv6/qvswB
         2zUp1SYQ5MI8pinvR0slBfdJoA6yunytMbEAvacipL2MpmrbdXQsmIrMM1sGNhGbcliW
         cJy2ATiBnh3xGQx+niovS8Vr51iM5HNErGid7adwx9CyWn037Q0QAlNRjldKfYNOdKNX
         0NFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756890770; x=1757495570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JYF3fXHL+mm0Yf5DjQ6kAfoy8Tt633Kb6YRqL/ezfkw=;
        b=DqYSpf3LWETNneiq3Lb3QzOoW6Mop9Dwmpu0Wc1BOYmj2E1tPPqbVD2WgmrzWLinEo
         jBk+7eUdsB+2ibGmbwZjg1lTqIVIh8xihaDRlmxeTDqS4Myq3nkGN3Tm7psnXe7mqQXi
         P4Nf8K3o9c2vIuX3MGictfb9KYdw0YrWEPxRPZ8o9zMRMvdVkS44wsv7BezzOyc/iZyw
         FFX6sffQq3XYyx+LCNRnYMPf4zT+fQUbPuFLNHYJIj3uyzN84i05rhFJ4HGK5SG0jWxZ
         54QyVxDTOVpaYthvBaQtkiokM42PdimzoL6d48oz9KzflAvCN1/OW5vjsDPPhV8Jtpru
         XWuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXknKP0U4PDZAKLLYVj8NSHH4TzUcEQ3XJU+siWLpxfn33h3EyS9sJbVPJRTa2qLc9Oq3OcfQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy6NROXRaEQ/3Wg3u9NYwmWbfTC0/WgPrwFV04QYvHnStuR6NSX
	uBYW8A+l9f43Z/+Rfv8NaTztNuWLmiQ1VqbzYEH621meIcbpchxCEyQD
X-Google-Smtp-Source: AGHT+IGQj/ux7HTkowegDbowcntyW2SMufNIU0PtXdkY9eE8tjvpaED8b6ZzM2g8/1yGevnqXRsdGg==
X-Received: by 2002:a05:6830:63cb:b0:73e:643f:5b29 with SMTP id 46e09a7af769-74569d78fb5mr10221512a34.3.1756890770370;
        Wed, 03 Sep 2025 02:12:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7IxV4NpzSndVyaWxx7vIKCil8he9sIrp4jvEbBMApLA==
Received: by 2002:a05:6820:704e:b0:61d:f8d4:b321 with SMTP id
 006d021491bc7-61e126e9ca1ls1877359eaf.1.-pod-prod-01-us; Wed, 03 Sep 2025
 02:12:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFluJp6Ejiw9PJ9A0/fnNq0iCO3My8CcfJblINT1N8yv5xZe+kXYW93WqnjuxrkDTw7pYdCELyt0Q=@googlegroups.com
X-Received: by 2002:a05:6830:3489:b0:745:98a8:47a1 with SMTP id 46e09a7af769-74598a84abamr1112269a34.16.1756890769382;
        Wed, 03 Sep 2025 02:12:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756890769; cv=none;
        d=google.com; s=arc-20240605;
        b=gi9i+TpiD5vX3jAPJ4MrVBlI5GmhX0NCZBFDOfEcf+K81BVvAFjAGr4Abl9R9ifSEa
         KqDdnU1ncEAwM2STB1ihGkJRDhat/KJhW/rtVMIFfzPlVwvQ9JAEBY3fFMiAx3DgZmMk
         29qs85n215m4bgT7EFzAUT8CCsV57v1vtdv9qeB/xHNH0JmnLY4dxMh6D/i0X4eOuaaG
         UAi24U1eEOE+JQ/c19FarSQ/ekjetAPRmbS0rArGXkP8LLbLXUCWIleuuhG79449VnPA
         V6U97w999sIN6Zj2XiG6BBnaAU372oEcGE0Xz4/dI8bms7iMHhz5Uys/WdQKPUJql9/Y
         rl4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=u1dUo+ncWnByrkiVnzOKVZT2Xjkh2cB3EGgl85trqm8=;
        fh=D8LK58oA6ohHJri0X0aQhEBkPl1TaVxnFHyHEUuxwNM=;
        b=LKWpXtEz0a/2rE9TV3iysndkcWj9mJC+fDkEg2sfUHPTEz7qTrJIwo5/5qmZ1MkPCE
         l9NIRCcqog3OCNwY9Bsqpb3zA5lAwt2jJrC9tFwHKVBL7aNUj1NTWmWyGr+0TbkZUGQ1
         qvQnADCKmBNJi7n/XL/bGvlUAMrVhZbB2mMiFJ7PRGjdiqzGMmnFe9fY4fp4S0rsJjOj
         LbHIhpESMPjfb1tJkVR0Uno4TunXu6YDTAhIOfh93vRMrH3fbBjBBuVfAXz2oZZBP4s9
         ePaDtTUwbLgDGi8jlmi7DJnNNlLKqv914ONlqpWVUmzoqnO1fjyqnp/SYRySNOR/cKJu
         8apA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LmopG++o;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e351e5bb7si377700eaf.2.2025.09.03.02.12.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 02:12:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-24b1331cb98so2930705ad.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 02:12:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWifeC+Fp4I256bacLLlBkZRUSOLB+uncu+enuGrsi3ZfWZ7OSVTRZP6wJ/UEJGTNwl2yAL+C6J4pU=@googlegroups.com
X-Gm-Gg: ASbGncsV13krSTZr7aMbBONP2YVu4gtvKPUKGIMo3Hi95fnNBqfK4XKopdIdP42+8N0
	UYHsvvwqB+jtVRL5QPpLg3waptoTHPEQO9ZiUaZyXn3T8OpEtYVv5PJChkCwwU4SvdTZkiVijGH
	zsE/rFtjFoVHM9d63dr6TXwlAW5USt6EsB36hW4DDOX4KdX9NWIyKn+xSNzFMctWdaG1EgEEZLH
	yzJuclliED8UNMsXZjQvZvtTjbCZBktgvoHCCoLzudlIL6ojkGG2Q8R+8jJRZr0dB1fdFkQ4vHS
	Ahfiv7lqDNnJ2uUeRLmdE5/qpr+nWV9sE2BF
X-Received: by 2002:a17:903:41cf:b0:248:b43a:3ff with SMTP id
 d9443c01a7336-2491f246be0mr103559945ad.8.1756890768748; Wed, 03 Sep 2025
 02:12:48 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org> <20250901-shrimp-define-9d99cc2a012a@spud>
In-Reply-To: <20250901-shrimp-define-9d99cc2a012a@spud>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 3 Sep 2025 11:12:35 +0200
X-Gm-Features: Ac12FXzVStDccJZt9jg6LxgcDhbP5A9e31eO3h_DSesybX7nfJW90L6qE4tU3Nw
Message-ID: <CANiq72=hD3No2R8-8znrOsL+AEs3rCVjNn3sn-d7qKSKZaGWvg@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Conor Dooley <conor@kernel.org>
Cc: Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LmopG++o;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
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

On Mon, Sep 1, 2025 at 7:46=E2=80=AFPM Conor Dooley <conor@kernel.org> wrot=
e:
>
> I'm not really sure what your target.json suggestion below is, so just
> reporting so that someone that understands the alternative solutions can
> fix this.

If you mean the last paragraph of the commit, then what I meant is
that we could do the filter conditionally, so that `rustc-option`
would work to test flags that require the `target.json` for those
architectures that already do not use `target.json`.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72%3DhD3No2R8-8znrOsL%2BAEs3rCVjNn3sn-d7qKSKZaGWvg%40mail.gmail.com.

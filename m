Return-Path: <kasan-dev+bncBCT4VV5O2QKBBWMPXLDAMGQECQ2NX7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 75E2BB8C619
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 12:54:19 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-45e05ff0b36sf248395e9.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 03:54:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758365659; cv=pass;
        d=google.com; s=arc-20240605;
        b=X7nXFH4bfQU2Mh+jL8zfQkH9RFHFpaa42ka78zirqX81Shsl8stO76NxVKVat/4e7L
         pg1CrIn4/p33nTcJj46VV22ooO/fC0qammPl80F+Hg7SR9GmIPbM3UKGNBHhxOR+8kaf
         kuetEgWBC3anPzQ7q5VlyQ42xF2/kefP61Vlilgpcpo++ML74vKFSQCUzAYEADurrC58
         Ba8gp5kcY6lfj681VZV7s1baQ0Xdeg3qJ6eg/kl1shWr1z8LXofuLLiPxgKailOxx4IL
         O+FT1/HjAWZQdvpxY/Z3XM936fdLzkJbeSFx5m+ysvywEKuWS0DsztzFNcIzPlcv+4ge
         LXZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1YeNuJ1g16EA95fB6pD0fzyYcSIhYq0kZultA4mgR0M=;
        fh=Cfum/yuDTT5VLRy0qEy9uv7C/MRKlmbUrx3/9jloQ3U=;
        b=KMmJoc2JQFpLgF/wZ1MVt6ZurLnuRVw7b4IqdpV2++nLZ3VQfAsLprHleQUAniot+p
         7sKqZWIyhVp8A4Z8MpFCHoeKTdBeWobf4kjJWNyf8OcBimkiNrwXPt017v6ftkWrRXRp
         moU2r8dv821Ec5w70x2dUkPzgtAy1342I/joQUM+4I+udL/Trutdn1bU0ZEXaJrwpSRf
         YvzRSug0q8aBISgJAKv6eI9DSAStavNQpdLOIeEgJVN/IldPXWBoe8yFwTZyC6Jx3oth
         GXZqHOX7wBHXmoJXWk/jjnLKu3828rCJ7KQONEoR3nWTdr2c4nbuGDuT0A3rxNuWgEjh
         0mlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CZhsU5Tr;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758365659; x=1758970459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1YeNuJ1g16EA95fB6pD0fzyYcSIhYq0kZultA4mgR0M=;
        b=aTWM12wsgpOWhFS1HKCDWCdTFuW//SFLS9R70qUNNIp1ofXHtuVTaK2XwZ+5pruaIu
         JsyDP42IvVtqMUPviJ46f5XAmBu29dyW8kGXRx7ixYkKLcM45bHJILHwaY/GhFOfjBUp
         wEAbBz9gC5HssjbUVbfougVbJrBu2vkaG3MFWYukJmIE1UoCS7x0MZIeMLt8mILHXIBg
         eKs//jOZMCtcvFj89HUxbxMXGBBjRn0Ue9WButKHAoIAjJxlTV00ThaIrSAR4JcEWPSy
         kD35BtFyFvFcpqBIVEJ1gJQbuu7yjCYygt48rM6K4LUdLIX3vEZxh5LLfneQ6WSL0tN3
         RKpQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758365659; x=1758970459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1YeNuJ1g16EA95fB6pD0fzyYcSIhYq0kZultA4mgR0M=;
        b=brr0IrwVViJaiwaWy3kSnNS2hrM0Ba/muMEZtanKVNz+EW4/VwvR/s6lI2Gy/wCcyT
         q/z1wDKD94yDouTn3bJBGwNPlpoYgRtXpA4pOTHbIO9uwuvHTi/hzh8EFKa9cW9JCBm0
         oyNfy43xA5STzld+uhJoaW4nAaHxziFyDrAZ95CUCQezTt1/6FiIkOO5SsH9zj73Fpef
         dN52EL9WF4IjZ++W3U2vUoEQXaACrnzDF1AM8EOT8Po7/LUFXoR1c0St6dPSfr7saQxb
         v8BB0iOC2AjkO/yAQOnsZDnMHuZweq3uGmfi4LzSOFoPk4nmJas6Xx7FeqxwSS7C3DFj
         k/FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758365659; x=1758970459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1YeNuJ1g16EA95fB6pD0fzyYcSIhYq0kZultA4mgR0M=;
        b=u8266MmXy0PDpbj+hPtvFThnS9sY3A+r751UJkgHwOQb9rNkRTn4OI4prq0U8MlYUM
         +gETBz3RX6QiYCTlVmoqeVd/+YXmqzGuAFzMM6N0rj3ceqhRKk2msY1KY37stwb60z0d
         somQ85jkKUlTCZXNB5EZ94n9JGuIudrFH7IZdSuKyOPQN2FxCXjnI7BLMj1U6eTkhZV9
         n9xviHPhURsN8u/mesDThBeIyQjPuhAcVUi6K28dDPSw3i8QsYp7j6kitDzRmaSBefrZ
         RMIwZ66uTX9Vd7wR2ugvJEcxjdaueCIrf7EbEGrYdW7n32to1YFAZMY2MiaO8zfK9Rhp
         YOAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfSlnIEQVREg0yJetw1igXP8kFh8/eTWDwPO+ZcFIls8ee5Lq11Rxw6KkwuKzQmjh0xDb5sQ==@lfdr.de
X-Gm-Message-State: AOJu0YyV3VVT7+u3uzCf1HBWLLIc+mGJS+mjOAeXKn7dbA51cuwkr4Kp
	ykumOc4wLgfBuEsjkhxPP9NXZje8X+g4xbZs5lqt+knxivnV95jTs2Zi
X-Google-Smtp-Source: AGHT+IGC/9bsCymXF1wKDx8edSTrl4BsGoCSXNUrxu+30aji+DFDikdHq85I9FNTVKZ4qSkLqf7Lig==
X-Received: by 2002:a05:6000:2f87:b0:3d0:e221:892e with SMTP id ffacd0b85a97d-3ee1dbb6b17mr6300393f8f.27.1758365658572;
        Sat, 20 Sep 2025 03:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6hT4JXfY3XEOWY42PqxfCMemWYTXtevy9Dd6nrd+dzUg==
Received: by 2002:a5d:64e8:0:b0:3ec:83ee:175a with SMTP id ffacd0b85a97d-3ee103008d2ls904566f8f.0.-pod-prod-00-eu;
 Sat, 20 Sep 2025 03:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmAyd26me9JtyMrrZ0J8TmWvcnlRbrQd/QPJ3MSCesQg5HTfJqzlURT5ViSToj97wGDLVpnp5jUXM=@googlegroups.com
X-Received: by 2002:a05:6000:2083:b0:3b9:14f2:7edf with SMTP id ffacd0b85a97d-3edd43ac9demr5986897f8f.1.1758365655463;
        Sat, 20 Sep 2025 03:54:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758365655; cv=none;
        d=google.com; s=arc-20240605;
        b=DaYp2fYVJG/zSuIHsy5PTHGBAI1nQK2e9WPbtQ5bbowMp34i97T3YPb3nkfbZBqB57
         vDRFtLKffawn2pVmPqLpMThJ/XVdjuuELJkWxqd7PejU1klXsms1MKzj/70pqLiD1vzP
         0mgkO23I0oaKJTlDD8xdz7z9aNo4x+diu09JXSLkXEoLta+4pAPHA+Osy0OE2o2i5orb
         RO216qf6g959tKwrBg1RieNcfAaXZgwiV4SFEUmV4kGjXSYEadZuNw3kSUAaG9Zb84WI
         7/q19qiwYdQpE3pMaQlknnYAQkgcj2KkyzJnG5fqaZLOkGsmnYr3OlXvoYWSEEZWiiDh
         CGVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SHE/5/T0iACb/l6eEELV1mJgr9I92jnyUNEPbB0q1ns=;
        fh=KOSSOR6UG71GnQF8VdwDvs38cATYZSMCEL/yfkCuKKg=;
        b=IwhXMIlQJ1ykRicCdaRIjTeuZiHAZYS20oY/DQk3vxq6dlBXjKoIRD+gS924ijbtJN
         cE1U+vNhHwxjQ2+xy86WtAzo5Ml1x1y4uAvdsw6JRpaVJkV0o7YHyq2hoGQk0SkOwgqJ
         KfiibvWUTjql9JpWxEwNEomo8d7h25n2PHe2RiO3gz5UUVVmZWpLCJrTEmQVRUWkSVgA
         KbkzHr/XCHSNDsKtNdvWvb01iQ/Om/yodeOf4B2vWDNwMQLMSMCUPvp90o4Uy1ZVWOKr
         fu2P3I4pUFfZTRicGxE5XnSIU2O5y7t8cF7YQateikqrR2XS1jxoiHzVZg7TOYMAE+cA
         DXoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CZhsU5Tr;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee073f5527si167968f8f.2.2025.09.20.03.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Sep 2025 03:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-62f0702ef0dso7506739a12.1
        for <kasan-dev@googlegroups.com>; Sat, 20 Sep 2025 03:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhlTGCYvHKd9SxvjRHZxPoe7mGMLmTf8A0id6hi1hks3Bk/D55wFQKikxcqSMDYMYE/MChKfT8kNQ=@googlegroups.com
X-Gm-Gg: ASbGnctgvhAb2OLcsx3M8JR8dOEKysdsSrJJi7yeDfbO1YN2TnsZDYYryUuFoCnaHb4
	T0+dn4piLvV0gB3jP8ekwG04oLh8+EVnI+ZNUvCmTX53o1pBcqVypDwo93kEu0IxUja03CQhKse
	7wmwWd+sc6r6rdEnCM+NRFXAY+q1tWdOhESnUztGfMxF1W1KYpWqLBt6L+RrWJqM6pkZ83BpVsz
	v0jhZY=
X-Received: by 2002:a17:906:fe49:b0:b04:5888:7a7d with SMTP id
 a640c23a62f3a-b1fac7bfd56mr1024511066b.22.1758365654928; Sat, 20 Sep 2025
 03:54:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Sat, 20 Sep 2025 13:53:38 +0300
X-Gm-Features: AS18NWDpSLAbdVwTREnAeu_jIcCkH8hhst__Nu2pxxOR47JsAXWXDyIhGWC1eV8
Message-ID: <CAHp75VdyZudJkskL0E9DEzYXgFeUwCBEwXEVUMuKSx0R9NUxmQ@mail.gmail.com>
Subject: Re: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, elver@google.com, herbert@gondor.apana.org.au, 
	ignat@cloudflare.com, jack@suse.cz, jannh@google.com, 
	johannes@sipsolutions.net, kasan-dev@googlegroups.com, kees@kernel.org, 
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	rmoar@google.com, shuah@kernel.org, sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CZhsU5Tr;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Fri, Sep 19, 2025 at 5:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
> file under /drivers/auxdisplay/tests.
>
> To validate the correctness and effectiveness of this KFuzzTest target,
> a bug was injected into parse_xy() like so:
>
> drivers/auxdisplay/charlcd.c:179
> - s =3D p;
> + s =3D p + 1;
>
> Although a simple off-by-one bug, it requires a specific input sequence
> in order to trigger it, thus demonstrating the power of pairing
> KFuzzTest with a coverage-guided fuzzer like syzkaller.

...

> --- a/drivers/auxdisplay/charlcd.c
> +++ b/drivers/auxdisplay/charlcd.c
> @@ -682,3 +682,11 @@ EXPORT_SYMBOL_GPL(charlcd_unregister);
>
>  MODULE_DESCRIPTION("Character LCD core support");
>  MODULE_LICENSE("GPL");
> +
> +/*
> + * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to en=
sure
> + * that KFuzzTest targets are built.
> + */
> +#ifdef CONFIG_KFUZZTEST
> +#include "tests/charlcd_kfuzz.c"
> +#endif /* CONFIG_KFUZZTEST */

No, NAK. We don't want to see these in each and every module. Please,
make sure that nothing, except maybe Kconfig, is modified in this
folder (yet, you may add a _separate_ test module, as you already have
done in this patch).

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VdyZudJkskL0E9DEzYXgFeUwCBEwXEVUMuKSx0R9NUxmQ%40mail.gmail.com.

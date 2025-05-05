Return-Path: <kasan-dev+bncBCMIZB7QWENRBQ5H4HAAMGQEU66TAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 22B84AA8BE5
	for <lists+kasan-dev@lfdr.de>; Mon,  5 May 2025 07:59:41 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-30bf647866asf19145961fa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 04 May 2025 22:59:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746424773; cv=pass;
        d=google.com; s=arc-20240605;
        b=E+bHqQglG+04Ay3I7suIcZlK/pE4v+WGPRblIpn3ocXGOiJbBaXPh0SItCEoukE+2t
         j5n1w56IVhh4b8qx1/gKEivHzx08HFqBlhL6myvrv0VysD4XME2szdr3S4JUKoWNfvwH
         HOuOQRBDd7sAuzh7OBENftWmpUf5Jw8rSelTHRwN0rqQOJVkjHCVsymQEiy6Yq2HIRWZ
         5vEPW6KkHLVrrb4pbckRumlK/Jxdmmnic6dswElPiEEmqmWIRMueIMmUJOLhQkhQTccY
         ZXGBYtgAPBEG23ouMmLVjOdauPFOCsDYvp7UoFF5Qtnu1SfExv7c3G805X6EO6tqeza1
         4vcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RthfoVtvJS8wKl4xTPZ9gu8dph9t/9OBoEBqbQmvwEo=;
        fh=rkvXu0IAPCGur4fjQ5u81fvBl+RPDK2QvNvNaTaPctM=;
        b=QHIvBeMAT5qAa2L2TJ/R2jyhzC1wKKso+I4nllZv27Yjm0Cysifs9xXOdWhJ5OzxV6
         JixpshKn2G+5IaG1pTDh8dOhbxmFA+rzTV2s9Sz9u40grON5i3pM+3ctW4ONCEhfm4vC
         zDO7u8vVWQnqlBSGZBXzHX9NRJEzo5ymvanMJvo3VQoal36AZQPun+HYoBO8j7qivclu
         T0ZV1ytUb27QXscKv4Nltii2a3nbq0j+sOzxPUo4LQ7SVTMXBfB3hu5m6EEQO99LaOHj
         C/40msxGh7YpoyzykJ3xhj4plVXmMAKk4PdtPrglCb4bBpnQDMz680wRxZyHG7FaiHlN
         Jzvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="tXkhy7/y";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746424773; x=1747029573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RthfoVtvJS8wKl4xTPZ9gu8dph9t/9OBoEBqbQmvwEo=;
        b=hvtkkG75zfNONla+Dwi3askSFDowS5CqIRy41nmr6x8qeyVAhbkMh1D/MZmEcbAdGv
         iQHHOee4cjSR7LZkTfwtWKJhLn1rymEj4wAxvgWrUWO4E0y7u51Dyyq8pbqF03AjnMoH
         0BAE4JXgRAcvELqiNyLIy2bmrUwxHEYB69EV3tfIAQ3vVyTbtntRAntPgJwwkn9cKv1H
         i/inzAULOoYtuCCLgvnZXoiaQmhPalCOoAqtdPQRI9erWWrSJTwng5T91ubL9Fd0fr39
         HPamy6u5Tc8NIyZoCkcrdIZS+2eMQwOv16h5lnhysC5W/wV1/9vKIVD6vhj1XQNAv5m/
         J2ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746424773; x=1747029573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RthfoVtvJS8wKl4xTPZ9gu8dph9t/9OBoEBqbQmvwEo=;
        b=EkdwfCdbjwJok5WRyGqt5DslBr9e8IiAPAv7aTCv9f2a8J2O0wGaCHbu2rFGoIzTGS
         JzjGW1Tkp5HxIpDKWXd11oizHsnlrN0pb9xQOAwe4unHvf7DVmr9rWnOby6YxY8EaY1u
         0cXLTpi5qhZpLslWKZ0o+2X8cMEjBKb18XXejwsSPo+WetMhToyFM4ouod9F/3gG/m/K
         pFWfFvh7r0hONLWK+Umdsk+Pkh+hzgM4EYCjCa8BdZ58mrSULOQOsmYOy/G3EgBbrI2l
         qA4dFlxFOCIReJU4LmVGgNfOTdeWHsQUtpKPWith/mmh6X2/1yVjMI1XMpnKQb+3jyis
         PRJQ==
X-Forwarded-Encrypted: i=2; AJvYcCXAjfoc2HtZuu7nytbUBB0knfRk7KuZ2UQyKoL3YvbYzSnvPkGGv2+sHksc5QlCMWSK+VYQew==@lfdr.de
X-Gm-Message-State: AOJu0YyzuZ6F56lZgA+B5Q6JF92ViorYS8ylzDteDH4zkOdE7URg4eD0
	tPO2UBkDGxYaWYY4caquleXyrifmnbAlvcH1kA3gj8tPfvIbqBJ7
X-Google-Smtp-Source: AGHT+IGPOQl+C1cXR5O0QUHojlg+RnKF2By8N0IT7v+DBPiY7utj+ByQKoZr/k98uMK4HXl2dr96bQ==
X-Received: by 2002:a05:651c:543:b0:30d:62c1:3bdd with SMTP id 38308e7fff4ca-32349059a79mr16102401fa.23.1746424771996;
        Sun, 04 May 2025 22:59:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHbsftCIUeCmcqdF0DJt/oqAzot+Dt73vLK5JaXbpBa6g==
Received: by 2002:a2e:954b:0:b0:30b:fc7a:25c2 with SMTP id 38308e7fff4ca-31f7a39a97bls2272181fa.2.-pod-prod-05-eu;
 Sun, 04 May 2025 22:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0NGu4/Eu33C/Yt1YcXSkX75fmNNTAna5jA1X02vOQE3E8VY197Lq44Rzl32y+LQGjI7LKxfddY/E=@googlegroups.com
X-Received: by 2002:a2e:bd11:0:b0:30d:895d:2fa5 with SMTP id 38308e7fff4ca-32348b4e280mr12449621fa.14.1746424769186;
        Sun, 04 May 2025 22:59:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746424769; cv=none;
        d=google.com; s=arc-20240605;
        b=Nnw1zeN1Txvo30TEWTCz3bB0n6q9r0oxDryH+ipQ4heY/qtWq/9ZCrUTqvabC6rbHy
         1njRUKiYGaiQkGIU8TYxx9VoDzwC/Vp2rl5sJSee3Rk97ECqdZACz16g9hMYPiGi2sW3
         BSRJ/xlFbM2uSIzO30RI2LIDRJG5PXLWWsfJV6mBCeTUnNZDd5zXyBdLrZQ3ZepZr0Qw
         C6MT5yZz4Oz9gzkiIVuFnIISWQwV4744xy/DZUc9DK7E9ntV831zblxpV0TGmoq2SA3W
         zi5oPqBH6K/DbbIETxPYcCJdlNM+frHB5u7DhD+bo8ewZiM+TyIiijcOktOqCw29tRhh
         SRQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dKbHiB4RZA41z9Ie8R/mefcD/M19yRwwyT/XOpBK3WM=;
        fh=Axmb8lgNRx0L9fRv+fbGsiIcqgDuemEQwnUfGaPnHO0=;
        b=PyPUQCyFJOJSdbK79McsxftX+2UP+TMm0qSfV+Vr3v/u4ElLpOZ3CIAjQbNTjDJaU/
         udaChGfEwrP+PcPRq/wiqcH/QNiYeZ0bcJ3wpobQ1nbTlBto4IhJXbKseV+CR1Q6DtBK
         KdS2oYztmt70q7U4x+nVTfTpkQXl3AKwo/7vnEaIIVf6Ma6SCNSvpm3xa3f5hsDeDbRE
         bCkjctU+CWrF3TgONOac8lheh3PCCFId7TTe7KeH0Jyc7k1yA46t8J+3CMO+Zq8/5iWw
         EUwu+AHEBP8GuBnRdoWRVSmyPVX3PuEd7Z0Svh/0jucv9+xzv2RXEI4CC7k6arzvoKDn
         QRqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="tXkhy7/y";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32028b36c3bsi1167651fa.1.2025.05.04.22.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 04 May 2025 22:59:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-30bfc8faef9so33502901fa.1
        for <kasan-dev@googlegroups.com>; Sun, 04 May 2025 22:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkD99un5kc+kpb3fYzq5wmUNqT/XA54g8/r0jNGx84WeV3EOp5kU6Selp6U2iKPSww6zrrtIuETAg=@googlegroups.com
X-Gm-Gg: ASbGncuhd+Zq2Gh3lCwJ/wB/A2S8aPWFGyLIgGucmNnjNixOueEKtbqbs/xncr4VnHL
	AkHjsTZ9zLlhLiaJ0VN5Rd3t/2LD7nN2pcd6fN8aZG8vbk1JED6Hf3nsOkHllwZvReDrDUwowRM
	PwS1A4kW6TMqvwrxY+kDOhsQFF/pI6wf/dl+1mlg2BPqWX0yLx7ZFDKg==
X-Received: by 2002:a2e:a585:0:b0:30c:12b8:fb8a with SMTP id
 38308e7fff4ca-3233ebe48fdmr15610161fa.0.1746424768540; Sun, 04 May 2025
 22:59:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
 <CANp29Y41LKZg-kSP+j5hjUKMNeWnPsVd8VvDnOpN8+4WHHjEgQ@mail.gmail.com> <CANiq72m7GAZ4gfgiU5bXSb86R3-UMG2vsvi5J1Ua1EpVV5EdAQ@mail.gmail.com>
In-Reply-To: <CANiq72m7GAZ4gfgiU5bXSb86R3-UMG2vsvi5J1Ua1EpVV5EdAQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 May 2025 07:59:17 +0200
X-Gm-Features: ATxdqUE_jDd0HC0IONKRAtQ24jV76OHs3LwnQnbNgHzz6cgeJxyFcYPBg_mcEL4
Message-ID: <CACT4Y+Yavh4GkocO01GSP+0hWXZNVBEaD4-9W2V452Z5+C+kZA@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: rust: add flags for KCOV with Rust
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, Alice Ryhl <aliceryhl@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="tXkhy7/y";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 2 May 2025 at 15:47, Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> On Fri, May 2, 2025 at 2:36=E2=80=AFPM Aleksandr Nogikh <nogikh@google.co=
m> wrote:
> >
> > Thanks for incorporating the core.o change!
> > I've tested the v2 patch on my local setup and it works well.
> >
> > Tested-by: Aleksandr Nogikh <nogikh@google.com>
>
> Thanks for testing, very much appreciated.
>
> Dmitry/Andrey: I guess you may want this to go through your tree
> (although I don't see a `M:` there), but if not, please let me know:

KCOV does not have its own tree, it's merged via MM tree with MM
maintainers effectively serving as final accepting maintainers.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACT4Y%2BYavh4GkocO01GSP%2B0hWXZNVBEaD4-9W2V452Z5%2BC%2BkZA%40mail.gmail.com=
.

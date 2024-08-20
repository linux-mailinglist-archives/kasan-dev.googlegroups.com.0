Return-Path: <kasan-dev+bncBDRZHGH43YJRBAEDSS3AMGQEKXB4ZYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A01958F54
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 22:50:10 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2f3f3b25223sf6182241fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 13:50:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724187009; cv=pass;
        d=google.com; s=arc-20240605;
        b=FaZ1Z7cCSFNmgB39fvnmNHfo0IghmUZR6pfCosaKcuCHZLfZ/2vE60o2MuRUt52ARp
         psIJFvtupnb+6eJUkN+C7oRZttATKXcGjzcWLQZ0YrSjvs93Uh67jmoJOmItvHO9tQHi
         O5au/TkAkWMLE6uuFOiPEeYV5/na34MotqtGmwHBC/Z4lAbEzyVfCwWs+1Rqr7vH0ESj
         Qg5257hUk5Bjmb7DtM2c5zOWD0JnGV+tc21AzvSH+fUGkwNj2mlGDeqtZ+5sMgBTVWMV
         n2SJT+X5hxiQ1uR4dY/WacikCk7NA/Lb7gU6W64lgZC18hn6px/uA3utQSp++LrQZYDr
         eOEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=V0sEtjcOe59mWxl9fc3ETezDqbsGCqwVu9gEdrAawnU=;
        fh=wfcwCZ/JOr/JiGgD061PSS6GLH4nK2PUG6phOae+UrU=;
        b=jnuGdsOL6GkLkU+3D47/lRDsvwavDaCQfI+Yr987rf9gGNn5ctY0kqAIA0C4Y3k4a6
         daMS62/jE2vjZPtUYvRcyQR6ZrGLYWVS8Hx7BZ5BHuEgmqUtodEjXtkrZwjYll3J/rA7
         3TJRlG1soluX7LAQKUhANAoiKIQoopGq0W+BoAXwXiRysU0f/K+kXpQHrzpt0mzi5pq8
         m/GbahArf5x6C48EZcy6kDI6URROhb723qf7eYRcjyqnZwbm4DhD0szS4xSTObt1UPph
         eVBKGR8jck4OURYJOjjui11eEAbwpqGcOmJs+liPkmmdGsVqgf+nt9izCc45/lgVcJSX
         r/2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lZvczX7G;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724187009; x=1724791809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=V0sEtjcOe59mWxl9fc3ETezDqbsGCqwVu9gEdrAawnU=;
        b=VipAzcc/a9ULYjgR+eqECBgTtyxTa1ZfvoX2HqR9jyZoc9VU0/jtSKsvlHVAPQSA2C
         Rn3xGt8bO+k22AmyL81nVnlFI8Vbeu5VFtJotGjP5tYgRXh4LmIXzpYY104m9HvvXDaP
         86/l3ONz0vLFFLYrPNxBmcOhoiAmAfTsYflvq/w4VU13jyAoLLcjszCWtuMv+xuF/hpT
         MEj+qr2udr7/KN6sW0QXtIyhQhoKJNFH2S4nRAWW2Fy1iD467z/VqghIjxVNPSZAVDGE
         LeC200RLyD+84TJ+T5L6SdFFls03vw+446GeZFOV6ycYKMGddnFv5+mWQhXcUO/Lptsw
         Xs7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724187009; x=1724791809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V0sEtjcOe59mWxl9fc3ETezDqbsGCqwVu9gEdrAawnU=;
        b=AJfX193qayhN3zNqUpqjZjhfcUhXSJcRQCLhalDd/hXqNn7UecNdQoXaxiePOJ5Sdf
         l5TIWTDruh+YPkyOHNGMzhcpWjGnIHp7IgCSUcddxKjAfruNshbsdja8GclKnJwqbNcO
         lbOWkF7DFeRLP5qj4EFyKvMi93UlF/dka7wiGVndBP1V13Z/+qHuhduPbzlBTuB+7hO2
         2vCrpnQe+ev8AldUjgBq8mTH5xoFM0Vg+Kan9lTSWaFpQHIg0Jy4lLYwtDr8GLJ7cYgp
         U4zTBkD4kjFXaT+OuI2PjhH6sAj12PSK0ekTzO3FBt3wE2QiB5NS8KMe77xUVONmePWD
         zk1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724187009; x=1724791809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=V0sEtjcOe59mWxl9fc3ETezDqbsGCqwVu9gEdrAawnU=;
        b=ss0PcSZtT7+S++N0GWSuCn+/w90PSIkcz3i1CfRElAGDnOjpYsUPyKqSFjf9VyV7FO
         IUR98rjbg+yzy3cqWLslqXTdLxx47fqhY2MBnu0gpzkQ88vUAPwf29RfC4h4Wzy6LYDp
         mNPYaH/1u7bR+CWvq9HM0qoi0spP90ZH74CFlhG0MVJDi6qrTwnSYyIvrFeCQslzRf1C
         E+30fy+OqnNvG9CBNRUtJndbpVq4dGka46aRMO/7yZFmouV917cjTAhQ4KQJ96LmvQUF
         UHW1O/2HtaDlwkYA+iZxvlbFtFPA7ZjJDg0Bh/Lp04fzZtImyFxtISKUU9y0HSyBpxTP
         gfDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSt0pIeiYkgQAqMn+D/ExP7gIz6SmqNL3Oh7XV4u8SCtB6V9PKlENTPlQl4lsSj/ObkUUs5w==@lfdr.de
X-Gm-Message-State: AOJu0YyzDXk6YmDpJ8lKUhV0V0hjgbF24lFBtr5aH2/uo9Kiv7dRCeW+
	gZTF9Rl+GVibaqVpCGbGgg/Khy/wezlW7lLyhuVbwL9ONdMUGVkT
X-Google-Smtp-Source: AGHT+IH6f79xTlZZoBb8N3WDvjy1EMbKjr0VS7KHU15ZXX4Ik+3QlzK88SPwNNG3Vc5qwrx83rozdw==
X-Received: by 2002:a2e:bc06:0:b0:2f1:a4a0:86a1 with SMTP id 38308e7fff4ca-2f3f88c444emr1158071fa.20.1724187008695;
        Tue, 20 Aug 2024 13:50:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a05:0:b0:2f3:f220:27fc with SMTP id 38308e7fff4ca-2f3f2202940ls1345541fa.1.-pod-prod-02-eu;
 Tue, 20 Aug 2024 13:50:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUAtpbjldOk5NQJS3a8VzFoEP8LrdG1AVNIfhdnbqn3tK6QZCELO32Wrc0oXl3YTSG9gGc0ch1oTU=@googlegroups.com
X-Received: by 2002:a05:6512:2812:b0:52e:faf0:40c with SMTP id 2adb3069b0e04-5334857e29bmr15532e87.3.1724187006158;
        Tue, 20 Aug 2024 13:50:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724187006; cv=none;
        d=google.com; s=arc-20160816;
        b=CWymY6tg6mUum78tA66VCSsh9VinvkTv8x5YZyr0VRir9wT19ynp8/bFupoXduq7hG
         KJjZuur18idoB5GDBoMDtQPCIVsrC0qJ60YBEgub1T+OyzWPrm9P02HzbKPrS7KGHBvF
         nHri0Pw7s8MtPqiJQyhgJYwnfpzHf3ZH0GUf7W4ysWQ1WTim/Xl+SmZ5EgollRFnyVr/
         Er3eg7mfx8mAtQ8tcIw1hs/sE9Zo5Wr8cP/5SCqKcOiUGMZCu7fNh4+mtjrRKwMq+doy
         AS/cfc5wlC87hRGLpeNZC+N/WkASqGL1mzqSoxZGHL0ppgb8547hP0AWL5e0agjXOAZM
         JrzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VzJFd4bvLYVyrRq91pLVKMp6cHYmymXxbjKHf0cCDsY=;
        fh=BA2NiGxWD/IhTjU+oFsqkHq3C2Mf7Q5+sgUjS70xsys=;
        b=0rcFD6JF9/ccUs/xzN7Xl1nVRf5fWYibDYKLc8IJ79/G1zMYOzIA4BlrXVZVVZ24R0
         EgcDqGKRJo4KhyQJlejQ88v6iSZ3VRq/xzNUmwt+HV0Fy50NwKmjcHuaVjjfGIzWQZgl
         Pq1yLVbfKjERpA9wyOMqyXLm1UY6XiyDLkFdJ6YY7djXRzzUrp+AvRSQior4OnTjOBon
         PcSLzRYyp2QnXZx9ntZDz0IC+oMHo9FZLxjZuwDLQXtJ8fGUGlZyF6UTAGJcoSSq+vuJ
         /AzZXJSGpQxsUB5QJB5GmXpMOKw+tie1A+8ftKUnaYwqRFf5HB7dLhoHtfDuQhUkVBMD
         FZQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lZvczX7G;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53344b76f88si35924e87.9.2024.08.20.13.50.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 13:50:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-53331ba49c8so10900e87.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 13:50:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnHnC0v6h6q+KgVGhzwARAXMnEBjBblqg6kR5Equg6h44cr7TCFWXKAYHRAU3Qhl7QMJtee0KGvJA=@googlegroups.com
X-Received: by 2002:a05:6512:b99:b0:52f:c337:4c1f with SMTP id
 2adb3069b0e04-533484ee187mr12476e87.0.1724187005190; Tue, 20 Aug 2024
 13:50:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-2-mmaurer@google.com>
 <CANiq72k8UVa5py5Cg=1+NuVjV6DRqvN7Y-TNRkkzohAA=AdxmA@mail.gmail.com> <CAGSQo03GVik5_yXFmCUnNUnPUwuwk-YFA0kqBd640PUjFOXcGA@mail.gmail.com>
In-Reply-To: <CAGSQo03GVik5_yXFmCUnNUnPUwuwk-YFA0kqBd640PUjFOXcGA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Tue, 20 Aug 2024 22:49:51 +0200
Message-ID: <CANiq72kgw8YA_1yFrCbo-=okFC8Y5R1rc+QGhE0e7pVJ0bV=2Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] kbuild: rust: Define probing macros for rustc
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Masahiro Yamada <masahiroy@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lZvczX7G;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Tue, Aug 20, 2024 at 7:22=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Sorry, I did miss that in the refresh. To respond to a few points
> before I send up a replacement for this patch:

No problem at all -- thanks!

> I expect this to be potentially used for whether you're *allowed* to
> set `RUST=3Dy` - for example, if a particular sanitizer is enabled, you
> may need to probe whether Rust+LLVM supports that sanitizer before
> allowing RUST to be set to y.

Yeah, makes sense if we do the dependency that way.

> I don't think so - I can't think of a case where we'd want to error on
> a warning from an empty crate (though that may be a failure of
> imagination.) Do you have an example of a warning we might trip that
> we'd want to make the build reject an option's availability?

IIRC back then I was thinking about something like the "unknown target
feature forwarded to backend" one, i.e. to identify whether a target
feature was supported or not. However, that is not a warning even
under `-Dwarning`s (https://github.com/rust-lang/rust/issues/91262)
unless something recently changed.

We can add it if/when we need it.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72kgw8YA_1yFrCbo-%3DokFC8Y5R1rc%2BQGhE0e7pVJ0bV%3D2Q%40mail.=
gmail.com.

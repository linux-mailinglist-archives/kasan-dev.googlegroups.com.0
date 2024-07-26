Return-Path: <kasan-dev+bncBDRZHGH43YJRBW5QR22QMGQEGV6XNUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FD4993D315
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 14:36:45 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3db143904efsf946799b6e.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 05:36:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721997404; cv=pass;
        d=google.com; s=arc-20160816;
        b=riXM6nUb/Neg3I1xcu/APgUBtv8JSRrtgxYBnawF9jtWYZ9wc93p1kmKXJEiCp3Oco
         rMyzy9NpWzWhQq+z+zG8ySjyayi5ri8oFqxst+xXBllV8XaYNWw8sPpcyFyfCiYvfQun
         FdP0+KJz5WszT0sFFYj4ZojkEdoji1MlAhiTeC7npCXSE2fISfrillqZLRjl0hMOOx+W
         OOtShZsR/msxOEe7ebc5jd3Xdzh/3D8ZF7UES/HfadEbub53KbDdWI1qvFsESflGvAU5
         ky2lhPpWD//RNEFhqGokDJW7LySfscxT4F8HKNv79KUYH2a68obmNkxpen03EUtoIn8F
         xasw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=A3rqsW46w/q/218DCMu7jgOxi3dhTPUmX9INg9bcuus=;
        fh=XinIrE12tWwfqvN+zazm1gQjHYhyIwV0sgTPr7008Ls=;
        b=YI3XU9INdM/CLRJ+bj7O2YCI69g3Z/iniISzE8rG2mjmo0eY9G52aY7EOt4WXactku
         5hs2P9a9Q5B+mmm91Rzmy7Mgo9A/93haIn82aU9eMZJ9W34qGFzdKkJL3Zv0eSxHmjXh
         kuLU5fUbaj0PxJVMZEJdePK3mjzEj2EUShqMCK544kiQvfeIUgQTDQ1wDoQrsob2/unZ
         hGMIfEkrbTxDEuGcRdOPtUIAvZxzRE7kSxs0z+w1IhNJYMvRJ6kRRDuBngCVcLHdn8no
         irJVz+2qPCTpqpwnT3qL4ph9bsK3yjEUmuZ35cTF2ltQ9da3WVWmq4wjSHzqw1lp20WJ
         1ScA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XY3SB+p3;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721997404; x=1722602204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A3rqsW46w/q/218DCMu7jgOxi3dhTPUmX9INg9bcuus=;
        b=UAHLW2UdjGda4P7G9xJMqEmEbf2emYDspRMdClEPUh+vx7MduBH+DaX/t92buZPsLE
         7XzaEXP3E+oqqsAsdUxBCLyGMYsaCOQYQQPuRn4253M0TVkEXFFjXrXM4/P2NlMzmO8B
         aXgaOxyPL6jKXBC46cnFtQqKt0GRjE+okT5Q/GlntgrDx5njwyBXpkZquN5anbikYQLH
         tk2E0tzSSxZ/aFtccRwjEBbsNQAmnAibF2i1r3aJys2w8AYB04OKZ1oPJUF8ccOFdFtI
         CNkQfqTgDLJ4v5g7xkrZemOg0kLu2yOg2zmVrVFhr2PFpHm2oPOdMGeYsTcfO2r8xFkC
         aKlg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721997404; x=1722602204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A3rqsW46w/q/218DCMu7jgOxi3dhTPUmX9INg9bcuus=;
        b=RyV9WBpxofKgZi9jSIj3ah4XH8QyITUpZW8qirBP7Fww4bchvrxOGclaDv2u/LaHI6
         A+iEyg7ubv8764Ox21Rxuuuf9spB/P60GfFuokLwQCsulS9UY3eimoC4p7fybPC8yu6h
         nXqIFYcPhH4QecZeadbbwbYRnlrjI6T6RfuCjZHE7tuES3tXwE6pUFOOm06ECjQHs2Kb
         hIcbwov5On8Si74UYCG01rxcqGQwX7QMK9v7KQ3j17fy1hzhTEdgwaXaHgE2P8JkCQ0H
         uDD9XTQakJsdXhe+ws91XWL+xLiN9d76q+uBDAC20NV/4vnZeBSdxfOHZS4jexkLMDrz
         +OjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721997404; x=1722602204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A3rqsW46w/q/218DCMu7jgOxi3dhTPUmX9INg9bcuus=;
        b=JzfNq0CuJxqaIxp+DrbcNkHHfrhjctbYQJ+0M1phw3k+Bos4eWRgqE4vUJxukk2EIX
         Q7qIF23eTzZUE1tZdE3JPxPwG5pe0MT5jJo/40fFUT4qY2HEZXgA3h4DPJwG3lVWfFZW
         ffzDzW+JZ4AdTmsDYfoLcXtsAPXoBEv9yKWXR/jaMz1EpLEY0a6xFiuUJUPI30l4cPjF
         XhFvFLkqdSAZH9qivoXc3nefSWaEYv0qHD02tc1OUHAUSrsLpSf/xMbt2TmN7DZqALtF
         SkEIZlLsAp1z+leCeO4qTU8PZHx94Q2ReoxQjWLFvo1E/fOPbZte3dKnsjcoepVqDsx5
         TQjg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCymOAIv96qHQqch/h2iJUaABSGLiS7P5Umz9THL1jC/oEnLPr63F5vRXy6VZgf2E9au2OFABvhVjusaA1k8Ds4F55FDgnsA==
X-Gm-Message-State: AOJu0YzgG78+newPRTjeuaXMUqakdjQrzvpdpZ4Yn4kvtJUOSYYvToxv
	zqTzYPFxpNUS5/bGljFlFr/PmCKnDP6lwdRGe94Q/q5GnSOvw1RY
X-Google-Smtp-Source: AGHT+IEGODTLB6n2VeZpdY9focksTINsHQ4S2lHd9LRtq1JJJvwed4ICnnPQVpMqK4HeOFEGfMqliw==
X-Received: by 2002:a05:6808:19aa:b0:3d9:243a:7ae8 with SMTP id 5614622812f47-3db141b3a98mr7085212b6e.39.1721997404007;
        Fri, 26 Jul 2024 05:36:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d96:b0:708:887:40c9 with SMTP id
 d2e1a72fcca58-70ea9df61b2ls1350295b3a.1.-pod-prod-09-us; Fri, 26 Jul 2024
 05:36:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJisquzJC2ZCCRUd8IjM2+Heq2N315CZk1nBQw5UfuE4VVXdgsi5EM5DGGhtSZjtG13/zMKuV3qAgGfZwGrBCv1QcBShohmUo4hg==
X-Received: by 2002:a05:6a20:2e99:b0:1c2:92a1:9324 with SMTP id adf61e73a8af0-1c47b1b74f8mr4404915637.13.1721997402681;
        Fri, 26 Jul 2024 05:36:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721997402; cv=none;
        d=google.com; s=arc-20160816;
        b=a0Au6T43GPLmDQX5vHDeYAlifhRDr+y07foK3bDMxcDIYDCqgwM/CW3hqMoLNq9FMh
         flS415OCUSwyAk23+J0sym8/19WeVW48UZpFLrv6OIY+P71FTN2tmSZHo0rhHbcT2jQQ
         MQtFPUbVwZ/xI5i9yBUJEWQ8Kx9VvgU1GCMo0Ct69EOYQ87YfDdwmb0LnApVcoABCKHd
         M0irESoluMwg2qTGWM9ONjCZFXg7YVmhZVVQVLQ+SRgYGJF3CqTWk/MyMC53/eiF9YJO
         t9ZNcyBmkhWSUkTx9BxglNKolxlylOSUWZCs3mXHXdW226RpbpMLZ8xb//MRRmmG09S3
         u/cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1zWDRWp+paDjK/r/9N7qgoFAesuhA/2QMW3EwgwYqcg=;
        fh=ILgrGdg8JLuW7kegnH7J/o19AOoWm21F90vzcAIvxNQ=;
        b=kepLxNumOHD46OooE5YgV6OwbOlfOBNnFGTpV0fpuU7KLhcFy7FSgEis12py9R4DCq
         6NwZSJJvqGm1XJPQhBIr6VeexYD3fGbLS2eE+lItuCwXAte668buGwz9IjrvEqQpnOi3
         lurFDV0pC1NjlaPK5WR6uFg1CsNJ5NFWwMeLVg3BLb9whb3mO8RxDDjP2ET8khQmSDo8
         m6KGG5iPJeov/vWI1p9N9ULPfD9RnEeI8IdYfdwRVmgM2GIl7b1f+x3qBs3hgahZPh9v
         5OptRhCcM8fbibEh4l9WuS4HPbmypSrR0H0EFvFiQb5l/0aLn7rTS4mtRhMhlAmoNdyl
         gobw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XY3SB+p3;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cf608d50f8si77344a91.0.2024.07.26.05.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 05:36:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-75a6c290528so689038a12.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 05:36:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWI6H/uoDdvKymF7xVnXCrECNvKUKD0VimeYmIVeRnM1TcM7fWAnwZuXANPb5F9fce8jSWijG6vvkeiWIc5pmhmvytl8E3/YESOJw==
X-Received: by 2002:a17:90a:1fc8:b0:2c9:57a4:a8c4 with SMTP id
 98e67ed59e1d1-2cf2ebb9251mr5312268a91.42.1721997402182; Fri, 26 Jul 2024
 05:36:42 -0700 (PDT)
MIME-Version: 1.0
References: <20240725232126.1996981-1-mmaurer@google.com> <20240725232126.1996981-3-mmaurer@google.com>
 <CA+fCnZdwRcdOig0u-D0vnFz937hRufTQOpCqGiMeo5B+-1iRVA@mail.gmail.com> <CACT4Y+Y+XmdNervhF5WAEyVwprJ32m7Pd8FF2fKy3K9FiTpJtQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Y+XmdNervhF5WAEyVwprJ32m7Pd8FF2fKy3K9FiTpJtQ@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 26 Jul 2024 14:36:30 +0200
Message-ID: <CANiq72kb0df5k-8njjNgfFFVj7Cfx-uiTSEtMt5Cbb8f3DkjWg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kbuild: rust: Enable KASAN support
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Matthew Maurer <mmaurer@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Alice Ryhl <aliceryhl@google.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XY3SB+p3;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Fri, Jul 26, 2024 at 12:23=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
>
> This is great, thanks, Matthew!
>
> Does Rust support KUnit tests?
> It would be good to add at least a simple positive test similar to the
> existing ones so that the support does not get rotten soon.
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/m=
m/kasan/kasan_test.c

Yeah, we have Rust doctests converted into KUnit tests, as well as
upcoming `#[test]`s support (also handled as KUnit tests). For this, I
assume the latter would make more sense, but we have to merge it.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72kb0df5k-8njjNgfFFVj7Cfx-uiTSEtMt5Cbb8f3DkjWg%40mail.gmail.=
com.

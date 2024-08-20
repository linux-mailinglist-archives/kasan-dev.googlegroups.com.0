Return-Path: <kasan-dev+bncBDRZHGH43YJRBKOMSK3AMGQEKA75DWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 307559588EB
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 16:20:27 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-27015be8d14sf4925570fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 07:20:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724163626; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRm/VbwXbXT/0gsG7eBR0Vtv723dskHNJf1N9x+K4mvwBDb+OSQkndqXviS1WOuyd0
         F377/VQsiSIqadlcRS4EU8qWkuj3m0MNtdUVIDuuBhgBgcMM2tJzuX6nYC25Pn2TI9O8
         gehcLbE3PUg0cPNc8oUOgoWY2IRob6pvMo4KbbXz3p4lDGZacq94ftEMTGxbEs8cj7fU
         +01kJlLR6LlxOwu1WUeoDSIQMQxu+YPcSK4PGufIvj5fJVZ9pYURIF1gF4Ysw4thL+ar
         4USGAmnIFc+kXA4wrJG6b44zu2T6q0ZNkY5ty4dMrbHNDRW+ndB9VuGoNOrBYFkz5Pku
         yqHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Qlgyu+OqnKV44qTtfFW0aHvEKXwfwCW+toebF9GeChk=;
        fh=58tN6Z2WrKiD2mZJ/L+euhOhMa/KH2KuxB2Tcw1KJvs=;
        b=VDb/qdr1UGqkDULXcA3kJiqI8EnZ0UXlSmrx8dsx1oOL7SbWaMrxphGUvRZDOYtOod
         MbD/m4tmIjlwO167lusXvM7/ihEyiOAAU1/gVnIZMXI7YWDuHs1Tl8dGVRIHcz4KYUMe
         6MFAtaTwjZ6DZ82JiXYI+pG4HtIMgWgyV2S7XV4WFwKGN+Xw8OiMi0JbW5Tj78PCPpnf
         6xjSQVvMdI0PRi8vTrj41RIpvd79CoDymX0xlIScKzZd+Lwhuzw2NpX/yka2KQxcqP+k
         CCG+krOFrUB9c/aEp4g1Ru4SoVhrYcq6+RAf4L8sGajwCWdyO1GXV9Pj7ob5T5OT/ljr
         euew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ex4M1NU+;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724163626; x=1724768426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Qlgyu+OqnKV44qTtfFW0aHvEKXwfwCW+toebF9GeChk=;
        b=oXIdB+7Nq2ohdcP+Bg72kbEipdQdD49ZmbLz1enUrC763ndQld2ZE130BSs6Ifs7QZ
         jAPYL299+bmt82slLUHRY1vCWheQ/QwtZnnwP93tCWl+88asOi8D7X8y0Bd4QLnEBzkT
         S7jSjA++VJkAhXTTncqicRgZen92pZzEEMFYoQ5CIc27CvGO7uGEKgEdPTdtbYnDFHZ2
         96GPv7F/R4DD5Zvk1/2BsXgSZOb5csLlq1sBENWGsN2puxm1YHteoFCZhl/yYuQKH8zM
         uImp8FXGJFtHrEgU0SjLxR4a/Hpt5sB5wOmofUezxPXtcfkZJSGotKLJtnnl8cIiFaWl
         b5lA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724163626; x=1724768426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Qlgyu+OqnKV44qTtfFW0aHvEKXwfwCW+toebF9GeChk=;
        b=VSPV3wjByCnuLI1MFccxKz9DQCd1J/0tCLkWik5UEmKLd91Vl3njONnNeb+/Hn9Gzk
         mzQv1MVC16twpRfgIgTdQDICEESa9CgjjEeMozCmimW6aNe1/GU5TnckPmR/pST1GQw+
         eZEhVQ+QZ7UpyfpOxev0QvdM98KWwY5p+GYVON56Bw5FoYHDPCGYAs8yNAdmSq9xHpJK
         q6dcJ3a1FuGdmlQEP7+bwYSh+FiwN7tFm9jI6I2+bN4mBUlr0Neoxh9Hq8PMTgXIiCj8
         XIHtdjYhoqnFgjURIUsgHv4+oSc+ekNO7sCU2OQPVTfnd2TVe15aJAW70X9jFk/6tQzK
         4qLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724163626; x=1724768426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Qlgyu+OqnKV44qTtfFW0aHvEKXwfwCW+toebF9GeChk=;
        b=dMFNDuXx6KXmxTq9bTIje3tLb6wTOA1Vog1WluRUuzKXW2tyMCsTNg2Ro9Zr9Cih8V
         fxYqKIgq7/xnycN+F+MIrKojolOY5pZ5VQ2KZcP1oepxMnBwk5cHusHA7qFuwEo3IfqT
         AJeb/dIj2QOyUcxvNwiobKnm3Z0XbgvdcqMGwjPPaoXW1xVzYbFnz2NnYEkCJzELaxfS
         Umh6BYpAnE+2whDUvtjhu7nX7hTmeclJHPEOiuQGDc5G7/IHI5n3qNWt+8bANWcnXd52
         6YPUO7fUZ9z9wiil4C3RspfpfmqvRQpQY5v+BtKp2cW0dsxNC3kRWs2ZKVjZhzisJaTS
         kGeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWX/xPHHadrikrpELuua8LzDV5TYe+xYgjcNIlu5MZ+iQII/Rtt4bYhIHfAY7lZ0/gpjnFPza538oOPtzO20st2Mu75sGH4eQ==
X-Gm-Message-State: AOJu0YwWMNWewn+IX5wuAH7No/2YlmNsxX+BtWoxqjmZzo0lBNe/CT3E
	EVqIGlJEPIf7Ayjozfk38hBMMA+BT+ZJPFsOWcqts0nYmyRNmJWt
X-Google-Smtp-Source: AGHT+IEwEAKgVJl49qAW/Nmj/iOEC/1O4jT0KrsWYBGXGt25Rti20SuC0SmVdYyKWVYcIn6R+mGgqQ==
X-Received: by 2002:a05:6870:96ab:b0:26f:f1ea:6a4f with SMTP id 586e51a60fabf-2701c343e78mr16591785fac.1.1724163625965;
        Tue, 20 Aug 2024 07:20:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1f0f:b0:259:f021:752d with SMTP id
 586e51a60fabf-26ffeecb2f4ls1593696fac.0.-pod-prod-07-us; Tue, 20 Aug 2024
 07:20:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6czqBV/rl47lTnaDx9yWmncpKj+GyKKN0KTWHzgWIQz7svHq8cqX3O/psfnS18q3tonXdDHgECKZBLpjVRdgaDk+Wc9tq3LjDsw==
X-Received: by 2002:a05:6808:3195:b0:3d9:22df:8e0d with SMTP id 5614622812f47-3dd3ad2d612mr17749872b6e.18.1724163625167;
        Tue, 20 Aug 2024 07:20:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724163625; cv=none;
        d=google.com; s=arc-20160816;
        b=bS2MAzGH3aGCt9sRY7hYa+a8erkNlBwQS9dL449Y5zAsUTY8Ln3qrfAHzK/Pa+cF0L
         IDRnYp27+JxcLF4lHh0+2Y37FsF1I345QQLBHN/9ullfrSg56DIKVKhUIZVu8imgC7Ig
         6AxITunvouH6n+ZIcSv8vW9YGygGSYeuDN1/svrZoWXehPVjAc/arPNOdWiVOhLThhzc
         Ba8S1YXcCZGERvOwIAhw+EqOkmwXq8QxLiHpE2J+AJGRMrSi1e5sl8Q8ef+DQU6wgyxL
         WRVkxPnCb+w4Pnr1xNa3/esVNZlgMf2NhoDIUb3fQWEeu4tiAHCkZ8BaFVG9ArbrjKkj
         SAhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wswv5PurLM6P5IjETHMLu6CnN+eBPmZTsMYIqJvimvQ=;
        fh=bY+2kwAjHt6o5f6uqUnwLrzqHZp3UnibwYFbX9dM7c0=;
        b=DJZJL7XkZ9AVfjOUp3JbkJkVZKJCuay+ygEB/0rUkyZetgLcifgkbw4Y36iseU1p5/
         /7vRera+hQPQ/jJByn0bpE6S0+bzlDdkKjmNO4Dc7XlUWeuqqcJs3SRRPdZ5g6+zHqtF
         1nzQYklKiM3+RtQFuIwXaS2cEem7NcPVgTOEtrKtiTrVzkWg9jd/uGfPEo2gp73U127w
         a3dF8Qc8apo5uadtsajs7fI0N4x9wjPxpSYsRRQ4pFbzaiTFhPszjbnd7dBb9hYdIjWM
         NWODIIS25D0ossj5xQ4YhJ+2pWCYQT+UvKbPcuin6SgE0fpPsdlWpZc0R2AxOJjJYbfZ
         CVEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ex4M1NU+;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3dd3cd8dec2si383925b6e.3.2024.08.20.07.20.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 07:20:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-2d3f39e7155so708044a91.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 07:20:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVnJEPoZgWjkaG25QQpR/x28+LRPNOjKUEFgSW1kKxRtR5M1TBchEWPif5otf+9DW8CL68TL4yZ7AImi9dJ9JbRiFFkyl1PezcF4g==
X-Received: by 2002:a17:90b:3d7:b0:2d3:c2a3:2383 with SMTP id
 98e67ed59e1d1-2d3e1733fe9mr9282006a91.0.1724163624163; Tue, 20 Aug 2024
 07:20:24 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-2-mmaurer@google.com>
In-Reply-To: <20240819213534.4080408-2-mmaurer@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Tue, 20 Aug 2024 16:20:11 +0200
Message-ID: <CANiq72k8UVa5py5Cg=1+NuVjV6DRqvN7Y-TNRkkzohAA=AdxmA@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=ex4M1NU+;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

Hi Matthew,

On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com=
> wrote:
>
> Creates flag probe macro variants for `rustc`. These are helpful
> because:
>
> 1. `rustc` support will soon be a minimum rather than a pinned version.
> 2. We already support multiple LLVMs linked into `rustc`, and these are
>    needed to probe what LLVM parameters `rustc` will accept.
>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>

I had some feedback on v2 -- was it missed?

    https://lore.kernel.org/rust-for-linux/CANiq72khUrha-a+59KYZgc63w-3P9=
=3DDp_fs=3D+sgmV_A17q+PTA@mail.gmail.com/

Thanks!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72k8UVa5py5Cg%3D1%2BNuVjV6DRqvN7Y-TNRkkzohAA%3DAdxmA%40mail.=
gmail.com.

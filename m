Return-Path: <kasan-dev+bncBDRZHGH43YJRBFWMSK3AMGQEY447OMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id BE9AE9588E8
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 16:20:07 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4502562fc7esf3541081cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 07:20:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724163606; cv=pass;
        d=google.com; s=arc-20240605;
        b=YSFoXdTdbfsHrwEJDYVaHr0fG4Lkqas0MwT/yfKsM+yehNXAaIglcvbIh/PnhnuMBr
         zxBG7CAyeZgmFhey6DHKRBsiILX7QfwWY/fnH5zGbfEOvkzqymY4gTSEKJv+a1Q/dVTU
         N8Sox40vG6DCoUEmnHW7o4tS3BV0a7gCE0D6dxrVT2iiAyeLo8GNlrFGwX3cEqalZaTu
         Pu2pG0n9ycTadcjasD0EnSOBh3PEAND57lhybspNOWwMBSiW94gsLUgD5nvxgrumA/WB
         RKstrLxPwZtA0jt7Pv8XxZCf1lhcJY9eyrxlM8j3Cy9/HU14gO8KXe20PWu1kDG5rIOZ
         /xKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=4RyRmwLwUJwC/4biig52avlbDA362oWxb2r1rONGCoM=;
        fh=tpcmWFpbadNHf5gPDzuqDAcjpYrQ1B4Y66GsjlnYLy0=;
        b=JcvlP4wtyFXdQ28C/1MiMoN9U/UvYxj8moZTK8uX+Mq8n9RdfnYm5tPKLrNvSnH5bG
         DNzh9EfpS61lwgTxLwD0noNSJAMg2euvBwbaPmE0dsUcAdCs5Lfm0RTWUVIvyth4+OOh
         HM3gxxU+jMDS8jruvKPQs/Nav8KufQp+olqC0dw70/6PiVIPsn4c7RsvoPiDs4KtMqSu
         u8YjG7EytzSOgkpHSRfzwpNBa2lWOf/NqJpgD9PkjZSNXLFOC2Sxhq4/OxCKNuFV3UmG
         BYXoTWmmKznq0x59awxa2K5Q+qbEHArG3wE66AULp/cw+fjJoVVy+sJwTWsNupQ3vaxJ
         z7Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JbNvyNti;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724163606; x=1724768406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4RyRmwLwUJwC/4biig52avlbDA362oWxb2r1rONGCoM=;
        b=SjB43i3yhN/CFbuZBpyJfTW+OpSGgWbZ1Z3x5FUEdmZ54Uq4i1Jyp83uxhk17YFJ5c
         DeBuwfgd4RG3/+b5esflFFsMdnm+8zp7NQYJb/SWfn2KQG4sBjbik5t81kpKog2LojSp
         oy0OR1ulXjphW3Ha69LHZMCDINf6JEqdLyMWSWpUFXFi3KtKpWmuCsTKw5GsiNk2UdYk
         D0th0XQ5MiT76KeF34eBVO/JvYRL1PqlNHADuRxPOh7z4seFM3ZWzP8CilLlqRiw9v6s
         o24Tw77tHjwpBLQGmvQvpvkBBI2MqN8aEqVYOA38ok6RNX5exKmmWPgJV/VfusG0tvKJ
         aYnw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724163606; x=1724768406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4RyRmwLwUJwC/4biig52avlbDA362oWxb2r1rONGCoM=;
        b=C846I8PFwohFcsJ9gfULJWzSk+GkQlA85wv/lUFW/JtyMqTyHcYj3SZ54BY6Tv+57S
         3f08JVijqJZPwE+m+khczfjADBZOtV02W1i0N1KX4vldf5/Iu05+DB5BTb8jSQPprcJD
         eO5rsvM23IQl2If52YNhHzhXnP9tBf6ET3tyc8U2gcaNZxG5/6+9EM0rQk4i+NhH7Lix
         VJcIWDP8/wG6pDbgUNT10L3EcvENk8T7U8s7o0mE8YqJ5ENvF/EUNif15iL8P+Y4pT79
         6eYsz24dKSV1bvf3+cKwNyX644jMFeK30iopg38TDLQklfS6NdCVOVP5DlontOJtC/LD
         4C8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724163606; x=1724768406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4RyRmwLwUJwC/4biig52avlbDA362oWxb2r1rONGCoM=;
        b=gzEPFc6Dzv91itgaXfAhl+eh02I2EGB0OOFX0kzsPzjgznZ7MQBLM1rM9SpCislzkZ
         Dv8/HMLTLCPgMp3oinwxKV9RyJiqGQhUhZrEP9aOmgfr4Xb76pHEDtYR28pBUZAfUYt3
         ALwiLRVd2k6T8bxPlg5rpP70Ld3398+M6r/gbjJQCpts9RNuPcNLQeYBft2ZZKBsuu6v
         kYicrZjXECDMoJFdur2zpdvVdMWbVkR5yt69t5MLa4KpiB6FzU4HTLY1Q66GZdtTpCfl
         fKbUWh8BttbFMw3CJ1Hjlyi32uiC74tqZaJ1VF9KWNcgVG8JyUg4gJgie19b4zwDLFau
         WnRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtPeDp69whANV/HdYlRyzsA7O5ifiqNYYtfnHMq48WXt/T3OQV0I2CW/YwKwVOHSonaEKahAAR9Wff/61FRlu2DfB1Qw8SmQ==
X-Gm-Message-State: AOJu0YzSBSw/lCv3d4RY1Lk9b/meTXRRHKMwx0VaXp0VUrBDxBS5BCjg
	sPCG1zZNkM6AhmgVa/lcHsw8qvxzjKA77eQugc7PRh4QyOewojUu
X-Google-Smtp-Source: AGHT+IGW0dDwFSwma2b4nt/qLaHu6W7ohuNX430WI417w1Evg3fhzTGjK3GQPrIVXNUk+GlWV2Yarg==
X-Received: by 2002:a05:622a:14cc:b0:44e:d016:ef7 with SMTP id d75a77b69052e-45374296dd5mr102357511cf.7.1724163606352;
        Tue, 20 Aug 2024 07:20:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5708:0:b0:447:f1f3:5341 with SMTP id d75a77b69052e-45367462b3dls3059591cf.1.-pod-prod-03-us;
 Tue, 20 Aug 2024 07:20:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX04n7THQHxRWI1zwcKILyu5c47bZT8FoB/0ggOfStY/TkxkqnzqQSWh+xr3TSnytdvU7yg1685HMaNlVRyNvgOdCHIq2ig9tXylQ==
X-Received: by 2002:a05:622a:400b:b0:453:140c:ac60 with SMTP id d75a77b69052e-45374333420mr203975921cf.50.1724163605619;
        Tue, 20 Aug 2024 07:20:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724163605; cv=none;
        d=google.com; s=arc-20160816;
        b=rDvCHWzE6OoQQjo5GpRoXqMCm55VnHkto2ko9wxBhVDdw7U16yn78d+JLY8agJLD6I
         HfKucWp6uITiscVwtWZ8kGZIgK76rjob8k9DhC8Zx5CVv3zLzVeOkpSWU+xd0KxjxJK3
         9hh+1sAwkbpJgmhwM//gdFwpgSJwFo4+bAJ34tYXWgTrKfJFxkNM5deFjyrvTkNO8Lmy
         gkqn+iVegNsy9fR5fCq9unqKQbqxBidNcM9v8Slc0Yud+rVwtw8MM6XK+PRMOSwXTvh2
         bzCJpATqNoYqMAwL2iBdBnT4LpXQeweQwuysSMqy3DAX62spmcsCETDQDX5ppRUctLJl
         nyNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DxvtxL+Ke8K6Pv8l2dm3nQAgwg0QSGFXf5KSkc+OWOI=;
        fh=3+LSJ8u9ti4QRJohES7flEKMxf8D/8rm5H3quUaiT0Y=;
        b=oSGbU0ovAXdqBNm8ui9f/oGF0nx9wBxfxLxT7Wy9Y06ZsGfrAMm+nbj163IqkUb0tB
         4hvZERQTAUkC+RMhQy3bk9BGrNy3Xd9V6zW3OTPi6AQhMb+DgZp1wyKccaSc5T52wiJt
         Hz2Nz/3R+kEeA+XbH3CgOskCS4mLjY9v2xJitTNtDg36aeACI0qXdkSt5pB49k8a3Kpt
         4NPAtTri9frkZC8RhRSveiza8HATNSOTlWj/6g8fkya/cGROe4Oi+DWlPHDAKvo+K17z
         seOj+MZ2eJrPqWyhfiDdE7APNSI8/8WoBnnElVScnxUXavzzzquH0z67ak3XbhrltjAr
         gv9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JbNvyNti;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4536a01f60csi5658151cf.2.2024.08.20.07.20.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 07:20:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2d445c87788so387760a91.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 07:20:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWS+BAQgWJfRK8w3APTOWR3LTSu2z3HFFzd76pXoldDZu/vtrS+hsD0GJqOxtMR3bxmY92Ua+EsuhrHpvcJQYEWqMD0xc/6PcLhrA==
X-Received: by 2002:a17:90a:9a9:b0:2c4:cd15:3e4b with SMTP id
 98e67ed59e1d1-2d3e086417amr9595929a91.4.1724163604537; Tue, 20 Aug 2024
 07:20:04 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com>
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Tue, 20 Aug 2024 16:19:51 +0200
Message-ID: <CANiq72=jxS-LtTMPdtFCmO0T2ajNZO+XLywqeevE4FyNhtyNBA@mail.gmail.com>
Subject: Re: [PATCH v3 0/4] Rust KASAN Support
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JbNvyNti;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com=
> wrote:
>
> This patch series requires the target.json array support patch [1] as
> the x86_64 target.json file currently produced does not mark itself as KA=
SAN
> capable, and is rebased on top of the KASAN Makefile rewrite [2].
>
> Differences from v2 [3]:
> 1. Rebased on top of the maintainer's cleanup of the Makefile.

Andrey/KASAN: whenever you are happy with this series, assuming it
happens for this cycle, do you have a preference/constraint where to
land this through? I am asking since we will likely need the
target.json patch for another series that may land this cycle too
(Rust KCFI). I asked Masahiro as well what he preferred to do, e.g. if
he wants to take everything (KCFI, KASAN, SCS) through Kbuild, that is
great too.

Thanks!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72%3DjxS-LtTMPdtFCmO0T2ajNZO%2BXLywqeevE4FyNhtyNBA%40mail.gm=
ail.com.

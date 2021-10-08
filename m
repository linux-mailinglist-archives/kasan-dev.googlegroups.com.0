Return-Path: <kasan-dev+bncBC5ZPGPA7QKRBCFB72FAMGQEBRUISUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BE79D42614A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 02:27:53 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id b7-20020a0568301de700b0054e351e751asf2946933otj.11
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 17:27:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633652872; cv=pass;
        d=google.com; s=arc-20160816;
        b=CcPfu66IlR5K4o7naBhIZpwKziPUQAfM0giCgPHhtBE9NqpjK5x05gVbxPJOY3Wr9F
         z5oKFz+rIAj6Q899dU7+/xnGwVHA/GRNdZE4GkFjHXfR1GeE6TMvBX1xWsMc+/zcphVI
         QNml5+JrD5LXHuttDUrzx4bpDV61CiyklpwnwaN9FPnVIJI0MVCZwLcLCvR3Y3gr45bv
         vr7XXNhwNFPzc3NBDr5QDEBKXbyEToxwejFn0G6Od/UOLU/tQZFdJ3LL30KPjVHHjBJG
         eGPmGBdbr0+tzec72y4z98Ks0Ku18+Mxo7gU6ajj0QOzE3D/I6zgBGx6wi7Rw7c/xlV3
         /Pkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=NBxXZXJ4t4TWleSkUO6PYghm3v4XTD25bzT8HvdD8rA=;
        b=x7uCRziHPUCllT6k1OfvE3qPbO8pfNc5nl6fyKJYBIb+3a85ooB64ErjR7LUNjG1ZE
         lN4x/RmJMbDw1zCTgq3kwf28g/qCk91UQmOY/5PHAG0xzz+GGlXP7adXSOMonNcrmjQa
         Av1E4cv/uMiEkjtnF746TF4wSH0BNsOdN+L95Bt9MniPNakehyig7ASRBNsz9Yl4tqBn
         vD5w4MnD5kGIbKruYRto9v++vo1mMtIAwjH0nv7zS2E8luMOnTyzcBoym1pElPsGWmLr
         I/5qzX5JWrxBwGTZUlZRnCI4IFG1f5aLj98ICs+2PNJSXlfBMPfa6ac767pby7gFsh7h
         OrjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fSUzY63J;
       spf=pass (google.com: domain of comexk@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=comexk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NBxXZXJ4t4TWleSkUO6PYghm3v4XTD25bzT8HvdD8rA=;
        b=jAmZGT3L9uFHnRu9blaCoOib5zZAGt3uMwLbRnlifwx0f2jf39xArNdxPyB0aKvH33
         WFMYzI/X7ym55lnnbGweZH78VOuFvXQ1QjmfHlAI8nEK2WYPXV4SPM3OZmmHlaYOENPL
         Sa5xv/ZHLjiDiIYfe/1oEaeYGRZ+Jmo3O4xy5j+7Fwf0lSCQovt4Nsj0dDKZBqNUQIu2
         RdILVAlcr47hSl69RsHIJf9qnBuAmpc+ys5ld7Kyjm5fc24+kJSQR4EwUEfKYOIe6f/J
         xde3DS9FRDRBt2dCV3phd4NXGDTJnHjmPB8+vieouegK1JSp6Xa6tbh7lNLwRbGIUT82
         l0aw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NBxXZXJ4t4TWleSkUO6PYghm3v4XTD25bzT8HvdD8rA=;
        b=XWTok4Mhx54+iDCBgATHRL53xEVaYBtqqaV2Hx0o35M3lf7X0GRcyQJ1Pl46833qeQ
         OtuYnVic1wB96BXrifdyz3O221wyimJuYYoWK1RxQ5ZDOiu5vm9uN3iqe1Mp+ifkKADg
         C7yofvdOjSAdw4RbGWeo9VY70ZtQbOQVT/6LIX9TRsvUZasptp/ln1OwhRfRyHjNH9Ib
         HeAE6u/kEEid6KQaQXUEP1xkOTGjbVu6ibhOAikJHHfyHitymZE4JVoFACooBoW770ms
         TzE0QjMb0fLYwtE2Okr3oMexZKxM6eIaHkcy2C0BZ7n5Rhb+tYDGwIRCkIhPOrTEHBcz
         LlLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NBxXZXJ4t4TWleSkUO6PYghm3v4XTD25bzT8HvdD8rA=;
        b=MSohVntxIwfr02RdOay9HNgYmWXHBh+rNthoRKYHcRfy1XyVloEamOlsVEgoegFB5Q
         SqC0XUoY3xZSLSublTKcZJj3rDIAwABbSjMoF96GsI4sgG2OiYc4x0LL6sFD63sgoKDw
         eI9nM4x7V8jxr0S3OXFlYyU2SiOYyCVpLWcKlX+/+nyizzf7d7vSdW7dree5IkvvmPQF
         DabafxGhCaNjrLz/nij3LQJXh7OrZIq7wXCjy0/3+Tetma5blRDAe4aDcCaT4pfQXpz4
         oLBWlETySrdfbN6FKzO3nbTNuc7tRsKhUtMZLVki0wBihYvFCZiU5m41X0b0c+ayRi+6
         F+pQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306Td/ZEG5TgTZaVjpeF96pSvg87bTvX0p1hfFcyy1hvTLYlc7A
	4qAWYcegulPmBmGRz4UiB0k=
X-Google-Smtp-Source: ABdhPJzf5gF0i//90sy3Cz87a9jRVk/1jz9tA/uWKgDYl50+eYFYQdxff4DL2txphJc5XNNmJSobbg==
X-Received: by 2002:a05:6808:1187:: with SMTP id j7mr5702601oil.135.1633652872544;
        Thu, 07 Oct 2021 17:27:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d902:: with SMTP id q2ls482315oig.5.gmail; Thu, 07 Oct
 2021 17:27:52 -0700 (PDT)
X-Received: by 2002:a54:4807:: with SMTP id j7mr14026109oij.140.1633652872252;
        Thu, 07 Oct 2021 17:27:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633652872; cv=none;
        d=google.com; s=arc-20160816;
        b=ELSrl0QuF/emkgrmh6rEZtN22StWgfm2hgpxQuOpHQEgDu7rEoPwwDvziOnmF3FNz5
         JUztqk5vOoOI0Hhw1xzfwDfDmtcC9rMbH0/8nI34AO7ZYkvXvmAZgBK+NtdZqEG4Rt8N
         Iu0my2hSI/7jHeVk/ql3fHZFPIMLaif/0RfEdh2dT5DuPLIvd73lJwUqErux1j6Uyv+B
         aA/RUjWE+DFAz3kKK4kLpEd8YHDQHKSlIDV6GrftOWhhmrvxcybgNzEe4JE4oHtiHUk7
         YGtrUl5DkGULdMAxKVPqu/cb0GAU/bxXr8//dojyPDy7vjly6eXgVXHqAluEso6TFGIw
         iFYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=iUTP4HSmp3xOxpRb2/2WXV/LFPy9RUoNRuoCStV1//0=;
        b=OcM6UvAKCkvi2IU0VkcNAS1XNvBGq6xSOfDW4FH+td9zi0EMc6ut/i3qbUmuxaIdNk
         U+axIEP7lTA3gkoeoO0dKqZFVpR9+Z68CVb1rXgj1y+EUtXc+Ui4evO0NfWWty04W1z7
         ClqN9wZdovg9WahnR6G7jGO8OwzeRCEw6wFQl9RAdWyGcKtA1HMwOdyFlDz0g71lCWMX
         yAucDeBkBb2igu+N30OYbEW9RpuqaYXnu+fEesYw+4yEwF/zKDSbwPrShmCXZnbjiKYn
         jp2F7LxVJ6SG7QiRfcqSBqP8QGr6d8HveFSn6AEjMeEqGfn395SfaHM3YmKdH7fMVEAi
         aYgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fSUzY63J;
       spf=pass (google.com: domain of comexk@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=comexk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id bg28si174599oib.0.2021.10.07.17.27.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 17:27:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of comexk@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 133so1459821pgb.1
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 17:27:52 -0700 (PDT)
X-Received: by 2002:a05:6a00:1693:b0:44c:64a3:d318 with SMTP id k19-20020a056a00169300b0044c64a3d318mr7089306pfc.81.1633652871605;
        Thu, 07 Oct 2021 17:27:51 -0700 (PDT)
Received: from smtpclient.apple ([2601:647:5000:47cf:692c:444f:b010:8bc4])
        by smtp.gmail.com with ESMTPSA id k1sm349838pjj.54.2021.10.07.17.27.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 17:27:50 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 14.0 \(3654.120.0.1.13\))
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
From: comex <comexk@gmail.com>
In-Reply-To: <20211008005958.0000125d@garyguo.net>
Date: Thu, 7 Oct 2021 17:27:49 -0700
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
 Marco Elver <elver@google.com>,
 Boqun Feng <boqun.feng@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Transfer-Encoding: quoted-printable
Message-Id: <F4A43CA9-29C2-44B7-803D-FAED9A75909D@gmail.com>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
To: Gary Guo <gary@garyguo.net>
X-Mailer: Apple Mail (2.3654.120.0.1.13)
X-Original-Sender: comexk@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=fSUzY63J;       spf=pass
 (google.com: domain of comexk@gmail.com designates 2607:f8b0:4864:20::534 as
 permitted sender) smtp.mailfrom=comexk@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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



> On Oct 7, 2021, at 4:59 PM, Gary Guo <gary@garyguo.net> wrote:
>=20
>=20
> I should probably say that doing LTO or not wouldn't make a UB-free
> program exhibit UB (assuming LLVM doesn't introduce any during LTO).

Yes, but LTO makes certain types of UB =E2=80=93 the types that exist mainl=
y to enable compiler optimizations =E2=80=93 more likely to cause actual mi=
sbehavior.  But that=E2=80=99s no different from C.  Though, Rust code does=
 tend to make more aggressive use of inlining than C code, and then there=
=E2=80=99s the whole saga with noalias=E2=80=A6

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/F4A43CA9-29C2-44B7-803D-FAED9A75909D%40gmail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5P4SO7QMGQEZLIPQCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D00C1A72A95
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Mar 2025 08:29:58 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6eb1e240eddsf9975036d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Mar 2025 00:29:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743060597; cv=pass;
        d=google.com; s=arc-20240605;
        b=Na74VJDHvmKhwf+QT8Qu3QDSuHoWMPdhZz2kUT4JyamvMfYKuLTyqbZ1zVBNfvO8Yb
         tZrBJjk73XvylR3Ie8dkCLvP9rlXpT/KAMUE5bBjsL6br7L7tYxo0s1iJHrHdCkoSRWU
         /7EcLd52FG7G8VilEbNvLE1Y+LqARpKws0rfYqnlqVRj8fmIP4zZda5AMSPVjTs0D35v
         P8wo5UXepaLp014JAbbwqOkzNTLqShOoYnk4mD0DMjVGWxAHD25+8+ACuY6JiTGEa2R6
         yzhIYA0mYhcY99X/4ivDZ3OmjLZVlcbc3Fr6jneY5S6uCHQp2MNZZeb8koSpBSKzzRHz
         6LLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I3NG6PVDeqEQtCw8aQWAdqcW+atvS2Ph8oHLoqv9U7c=;
        fh=JU18Ypk6cxZEv4DZsKvM2d+f5AjJBmvmAB5+cJi8D9M=;
        b=d1yxR94Mko/EpJB+mPhjAtt5C4HjHQU5mmLXGcJ47yA57msz/kL/ZNpQqP+Vji4Hab
         NHxfrzcOL8X1we/D320HVyBRG3U3UkVsDj0H/bHN5KlTHeDHWICmA0hZiAJx7H/xXW9T
         PaZ0A7JnsGXZ6eYutGV9ZihkYfpEKPYBfK9ktZSKh5SeqFjANujlezBQXfmlxDLHpv75
         AXr8gqYtLU8wLLcpd4RgVyYRUckZG0d5PGY0I/fldnYFQW3Srvk66NXJ5uuNAj+XcqcU
         wjpm8bJ6u2dqlXKcmIi0oVN4MeE9BF4JQ1z5SvmcaMBq2sfrSwjSQoHEORuIe1SvbPyw
         F9mQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="J2C/hILA";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743060597; x=1743665397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I3NG6PVDeqEQtCw8aQWAdqcW+atvS2Ph8oHLoqv9U7c=;
        b=GxvItVLpMLlZKR2i3hGXsDj8NNUopIdHvzbHK0+pjPL5d5umoAnjYx6K/0OaAipQ80
         d55RVs9gMm6gvgrIa+E6L4s/Z3yoB8of+p9vzCmIPtEj/UwN0qXt3Sv+Cq9UAegSROlo
         8TSZfH9vbvaN2O7uchoga8rI3lYyvod2k0BSsItgO+hZd7CCV2XNSwxwhJY2c3S9JSU1
         Jg1wCr5tHINPPIXOviROXVMt9DERXUx2GSmbBCzIlsrygDledineH+9UB4dDsWg/wTK7
         RC9CndMhf3PK/AEti2sMPfJ2SKmmJwuLSnYRwBorOT6jfWUJvR9nRlJWLtUD8TULGBtI
         ByOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743060597; x=1743665397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I3NG6PVDeqEQtCw8aQWAdqcW+atvS2Ph8oHLoqv9U7c=;
        b=p+icZwm8br3tXfxbftY4snwJvbLd8pIAeX5ifVMh+nauwfHXydgCeWgDfGmwmt46Sz
         nkGHORyB0ocMnDAif0gj1md3q8+jvNUAnXEaXW9cflCC5PUFMPKAmY6BbAYZhGVdcB2n
         lS2w8yeZispdYcP2c3qs8ioHUW3r+MzX06vFd0Dr5E06fHayc07EjXsS5ShGRH+IlVc6
         XUJMTzztQudHPyh8YB1mOefnTjlAHKCNCMBqqQseNu/7juTC4YGsroAFzrjKADTmfAmH
         aNj4gKZHgyMgk6KQUw1Tgwme+vVI2B0S9j+yhcV/ctJgCNedBU4hjFQMcjFzkah53YRk
         iJRA==
X-Forwarded-Encrypted: i=2; AJvYcCUcGr0JlUmFCBWWdA9A5xhaJ+Jy/XFMrcDq7mZ/SrO50/V5eN7QNV0Z73ra56sFU63LgIF/Ng==@lfdr.de
X-Gm-Message-State: AOJu0Yw8PMSv0Qo1B51i+TMIidsf/f+1T35HVtKrgDIX1Kg6MYe7VLIX
	jbCBf21OE3ss56CqyHr0Cw9KrQy8cmSYRQN5yfpmWCf7o1GD5Fy4
X-Google-Smtp-Source: AGHT+IH7EpsUVdXH7ZO8Eg4KjepBOnKYfwY1gZkPwXLcbrcx1RPcNHolUtKDGuvwyW7yUAzT8gnoAg==
X-Received: by 2002:a05:6214:1d02:b0:6e8:f4e2:26ef with SMTP id 6a1803df08f44-6ed23904822mr38226676d6.31.1743060597266;
        Thu, 27 Mar 2025 00:29:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK/9h7pfQJw+akLPFEfw0tzKVxTg+jSmAI7ESNmxg4vxQ==
Received: by 2002:a0c:ea2d:0:b0:6e8:93c9:3e7 with SMTP id 6a1803df08f44-6ed23281610ls9367366d6.2.-pod-prod-05-us;
 Thu, 27 Mar 2025 00:29:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVD+BhOURgl3Xswxd5PU3FA6cEpZcF1SMuUBTo01PBIzH3n5tbRHwm+xD3GO5cBT+msontWwPNBTl8=@googlegroups.com
X-Received: by 2002:a05:6122:17aa:b0:516:18cd:c1fc with SMTP id 71dfb90a1353d-52600a9eb6bmr1624457e0c.8.1743060596059;
        Thu, 27 Mar 2025 00:29:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743060596; cv=none;
        d=google.com; s=arc-20240605;
        b=K+WV90bXK5B/WEpQ+xCatkwUF0HmsIGJhGNnTsft4cvLfEBNzi5ACU5c0EruImbY5O
         FCswQp2g19hh9gzQ6Lp/0v7ZJY68f/r2qmSY9yPSRXdzRmP8cwy+IhPlZQB+NN465T9k
         1P5KuQEvUoa18P7QvPobtL7jLNDpFOy88LoD3R4A2wEg5XNiL49QJragDSVeYhRwhGvY
         0NvIpRwIKZ7MFEfLzyEpCzuf4rQRTCJbGTJCENegGPe8LXHWFsK+MVWTUsi838TxRjmF
         zwyLN6y1300E/edyDdlQgXVNt1epWCD6YfysDqKcLtmZHizV+0qIXu43Es4VjF7eBb6Q
         ydUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UVSK2OcQIxu7GqCdEZXROoD138DGI826o2h6Os0Wvbs=;
        fh=TY1gDLyJchS8skq79rhs8KmfVieBBXPryg1juObSHVw=;
        b=hsrVjdFA/3l+uakxKhbJS5+gtPcL8nAFvCNn+jq0jdj+QpEBxfy+p7UxCU3Sb3pVa2
         wX+L0kJkrJt9kRA2YMvTU4hdMLROuP0Hx3YxUGyAsJBdDYF9N/A4P8dxKJnLa+QzVU0W
         lgJYmJiGvThmLi1SKiJvOCQAw17DsZm2vUGxbyNZgHzbnOXHtc4iMX4YSV45RWKasxEF
         mY+lscGwKnsjjmj11fy4tpw3p6IQYi54a4zBbXeI0vgVx5VnNjQN3y33OlRE4Y0DRUI/
         jmyX/vaCKyHawsM0fB8cQLKkTwJ4y/np8TuR+ziT+r7vJ9HkmA4+NSlI6sPz8T0h6OBY
         /ZTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="J2C/hILA";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-525a74b86d7si672118e0c.3.2025.03.27.00.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Mar 2025 00:29:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-6ecfa716ec1so6192756d6.2
        for <kasan-dev@googlegroups.com>; Thu, 27 Mar 2025 00:29:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVcydi1/dxbp4crb38i8Q16amKswdBDg8DwkM02QPzfChLnRWC/2uWRdSsQrTWbrTDdU2MWml4vEY=@googlegroups.com
X-Gm-Gg: ASbGncvB4j0oeiHOPPJ5uP4wS1+CW61p2g+n/XpoEWT6lN04xeD3iFn+p9yK0nbnT20
	d/wpLh9clc2RDWymSWhiKcTmU35pvZQDFa8/bcJnQ5O0YhSkJk3W4VfG7ytRYH+PNZ5y64FR15l
	jm4zNktLvbxEKWWnw7tLno3EEEvyIgVFcUURFsOtn8OtL1ajW13LIEShYl
X-Received: by 2002:a05:6214:1311:b0:6ed:1da2:afac with SMTP id
 6a1803df08f44-6ed2390449emr39214346d6.32.1743060595360; Thu, 27 Mar 2025
 00:29:55 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ=A@mail.gmail.com>
In-Reply-To: <CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ=A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Mar 2025 08:29:18 +0100
X-Gm-Features: AQ5f1JpUvz_D0Czd4hU24LmSodys4uaFqOZY_Yq3Ndxmm6C9Z-cmzAlUlTUQiTA
Message-ID: <CAG_fn=UF1JmwMmPJd_CJQSzQAfA_z5fQ1MKaKXDv3N5+s3f6qg@mail.gmail.com>
Subject: Re: does software KASAN not instrument READ_ONCE() on arm64 with LTO?
To: Jann Horn <jannh@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kernel list <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="J2C/hILA";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
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

On Thu, Mar 27, 2025 at 12:10=E2=80=AFAM Jann Horn <jannh@google.com> wrote=
:
>
> Hi!
>
> I just realized - arm64 redefines __READ_ONCE() to use inline assembly
> instead of a volatile load, and ASAN is designed to not instrument asm
> statement operands (not even memory operands).

Nice catch!

> (I think I may have a years-old LLVM patch somewhere that changes
> that, but I vaguely recall being told once that that's an intentional
> design decision. I might be misremembering that though...)

We have some best-effort asm instrumentation in KMSAN (see
https://llvm.org/doxygen/MemorySanitizer_8cpp_source.html#l04968) and
could potentially do something similar for KASAN, but if I remember
correctly there were some corner cases with unknown argument sizes and
with percpu instrumentation (at least on x86 percpu accesses receive
an offset of the variable in .data..percpu, not the actual address).

> So because __READ_ONCE() does not call anything like
> instrument_read(), I think instrumentation-based KASAN in LTO arm64
> builds probably doesn't cover READ_ONCE() accesses?
>
> A quick test seems to confirm this: https://godbolt.org/z/8oYfaExYf

So should it be enough to call instrument_read()?


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUF1JmwMmPJd_CJQSzQAfA_z5fQ1MKaKXDv3N5%2Bs3f6qg%40mail.gmail.com.

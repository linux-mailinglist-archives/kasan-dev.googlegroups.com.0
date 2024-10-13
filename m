Return-Path: <kasan-dev+bncBDW2JDUY5AORBYW6V64AMGQERMXFDYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3298099BA42
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 18:03:49 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-539e5f9df25sf908900e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 09:03:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728835428; cv=pass;
        d=google.com; s=arc-20240605;
        b=MVUiYCtkw4rqOcUfCSUHytRS6Jhxzcizc0Y7Djf5e0q5nmm/oQh8Ra00dcAqgX2f7f
         EOn34mGz2RNlqm0jDiXLQEsqXvC8joyRDpO6DSMs6unASR8K+wmZwlXywmkllIVEiVbb
         nXm534/AdI5DEX0G+kkKnen+u+A0TDjYrxA8+n75bCHjsArE4bRQANOsl7o5g6oT3+YC
         bgEAEcpDlfmhtm6AoSH/wbEFU/brSEmUzmFVHWSjARAgo7ofLQJm5XSXPpWphtMc6wxn
         K8vvyFEi8J6/137jB6wvCNyRJDwzQiBhnmBdjYFSOdlEBCiuOzzPTr0WYUMXr99Rnj0l
         XxjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jE++k78LI52rCiM0cNyo+yvJRUc0SFZFx2yW0gyVj6M=;
        fh=FSpg393tzUmc6GgpPZiiFvoRXXuvvFWjyUUHPDxj1uk=;
        b=KIVm1eniR7jZ788qTuJ89Fw7lPHWm7rSUZHjRwlHIEGe+M0EGB9ogaKHDCUH8XOhJK
         N2ZiwrPseg3D6it+hTjf9fIRpHeKMWOALOalxuk1pP5R/qivvgXUZQ4mAXQnBlsfR4Wi
         7WZnTajBYiwMOeYs7mfCnRSEEHU6+wtB6/t3VxF4Yx3eO2jfcuosF3m6ATvIqF11m2nI
         DfGV+4ZKmNx1KtWKBTdpO1Qxl2m45i24SpRbo5cQMEXIs+I3sMUpo34fPyRwTH0+2tDd
         k1BgHtsPuXMw9aYBtn2jStvD+AY2BZbM0V855WR+Pyzv9kJ3hQ0nRwqy03StoUqmwF+s
         WuXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="kFn/uyMe";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728835428; x=1729440228; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jE++k78LI52rCiM0cNyo+yvJRUc0SFZFx2yW0gyVj6M=;
        b=WLO50Y9CmJjHO2iRFP97ibEZFopZr1c6HPHwWzxVrsCtzTN+935wE47H32iIdF0BOP
         nBtYW8odk0pbNL0Xggj4djVn9Ta13B9gOGs5866+8FHM2EYM4RBUKicANnJlbN294ei3
         uEtBND0qlJaLgPen3yWKy8DSQBU3OPenR/qUW7sAdo3EZgNdR610/LLJAOtaFkwYqD1W
         izU/KW294ATHgzhroOeAxruvpeiOvGWItvnvteERrLbAwW2wyD+LQQlb7Dmtx8sfFhyB
         k3Pg7obd11JMsOkJpGshAvbtCrza8DCXHS/i2TaqsiV0zdxKkXpCxtIZvuqLHTvFzBO4
         twSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728835428; x=1729440228; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=jE++k78LI52rCiM0cNyo+yvJRUc0SFZFx2yW0gyVj6M=;
        b=PoKNeCpqn3pps+xY8HSeOXNcXyzRxvNmsFCA6kVuzm4EoGvAOpmjHJBI0avrDFZZj6
         VGn4lsb+mcaZCkQBWMUGbCtS/EU+HLIyV6BaYPj9J1QrNpfHlnV5F50jja7kCkxXWB3R
         OEUvVKvmmgBMURFUbPl/+5nTweABsyof2psDqDozMIwAhniNZQjCTosA5GkJdUNO8Z2R
         FJCyKvljI9md1JTj6euJXRqcBV1/HssLmCbb3ZKvXmYsEZyQ6btyBujDlg2mI8EU0+Ma
         DYnm+GdsSA57hBshJNmov0Y7gQjWOisRnJDm8H3OXsJJkGd3qfjLnvsceg8TCvlCvUGX
         jKXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728835428; x=1729440228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jE++k78LI52rCiM0cNyo+yvJRUc0SFZFx2yW0gyVj6M=;
        b=V1AehGjrUMrcCm8EolQ3q5CaNVddZ085Ii1URsMtx8wT8fjgWgs+M17Zx0bGCiWjNS
         RtWq4ZFpUhdSxkFDmva0JEVCVoop8Vc5MdSXFOEpyclln+eH+HVGMgUOfTABp8m1Rk67
         I4VlwsXNv4NuvVJREZlXtaQI1lz7lj2jHw9i2W/orRLqHngrJR4XFoZE4cUm7tjFL7fh
         cLyh1wB2W84oRSzWvVfrdD7aHXPybvIc/Odqgu5nIY/n8Kavla03z3csEgaWr87YuS/i
         tZ2HRiFj+kYEfI8Dv65FmyN+Jz3GUF6IC+5qSLEOTYERIU8/afitXqxQA4893+jlBwHg
         h7sQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXswFvz4it36A1WypFpE6IFL05hIDlFstHu0NUPpfNf4nFb01Z4nZzRVSNp1fkt24pIV6m55g==@lfdr.de
X-Gm-Message-State: AOJu0YzzFrlgG9JKqod1uD7TaM0AA0IkqtSU8odB7Z9kE1g1AmpgX0mU
	SxKqXzbsG1w1kevl2oCQ+weedxPu+U/stS4J7sjvc/QJt5WaQH/4
X-Google-Smtp-Source: AGHT+IF6YLlUo3mTxxL+E1XozTMpz8MKNDlzJ9N6s29esr6bSciSWxcBomWOZql9WCayX07hmgUYOw==
X-Received: by 2002:a05:651c:210a:b0:2fb:4b0d:9092 with SMTP id 38308e7fff4ca-2fb4b0d9376mr6359911fa.1.1728835427265;
        Sun, 13 Oct 2024 09:03:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:22c2:0:b0:2fb:4dc3:c8fe with SMTP id 38308e7fff4ca-2fb4dc3c968ls498841fa.2.-pod-prod-08-eu;
 Sun, 13 Oct 2024 09:03:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPWI9i30QQGjkPaMKIcy9NBeQ1JZ37Lz+wuIIJpGueAzxawlu8AnqNCT9t+agTzYF1o54rm1aBLJU=@googlegroups.com
X-Received: by 2002:a05:651c:548:b0:2fa:d345:18b9 with SMTP id 38308e7fff4ca-2fb329b2a01mr38992741fa.38.1728835424941;
        Sun, 13 Oct 2024 09:03:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728835424; cv=none;
        d=google.com; s=arc-20240605;
        b=aiTHrzXDs82hpcLy2J5qtX5BpGSzFXihlPG/EdA48suefmClxiqRQsiNJE9bYn6KEv
         Ci4JxZI6hyecoHTmQ0VIUvZL8oXZrvJS7VbDgqd8PDCe0bw2p2Y5hmIyb31ktvNn85Jt
         vgqB7ZGZUf8MjRKUtJsxriX9do/MrZFDPrqAytDrkwYSG1fbo/lBiSWSaMaHLe4oly3Q
         28HP+ShBhsqzKcNshjL1hdPuz5yFIiOEcQLe+Vr4ENZizeCCWm2VzP9BFfb5VfWGw3/4
         of5dKVJlxVp7ir1vdX0gH9u2SzqSWowSOdddOSepyHPeFtSR+hc+5o1VNQhmMcVXcZB/
         s+Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=clhS6jCen8r1o4VJuWKC3QPAogIxNmTpT2RR7+NeInQ=;
        fh=jnHLWOW8AG26JBX6595p750Ym3du77xxBFTqhN0FAj4=;
        b=jH01/066l/YOWflLtJci50LpRSzufwKAB6cHFae2O+rLFJuR0f6YiIaN/D6Up8f+iH
         EjSkeP5DB1WMF73pU7QNmivKa8dR9YcD6Fe5aY//yu+9Mi2AjBnT8b7sLVoa/Vvor0Ei
         MGwa6zpaB78bYbLDn4KVUsp8b0dCmvJLPrbum3Ar8or81RAi3c3TOAdGT6pL7MrVLKKa
         ++NaLO707I/UXUhAXTQMGHXCGXGJQwHKq2Ut/kl3n5yGfDIANwUlZtIXgf2bQqNTjv1a
         L82Jg2wp6gwPj2X7HOanJ5uFaMJe/hB0m9gAnZbjlGt2yymWnuPOrFWqpblhpjjgISok
         jClQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="kFn/uyMe";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb4d7ecd5dsi176211fa.2.2024.10.13.09.03.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 09:03:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-37cea34cb57so2224479f8f.0
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 09:03:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWuXpKBztUG/JXcQnjt8mNW95sZ0ilBEFUaNAiToxS1XzLR/MoPgV60kslNIWSh8N3AbKPSlOGP+Bg=@googlegroups.com
X-Received: by 2002:a5d:4750:0:b0:374:c56e:1d44 with SMTP id
 ffacd0b85a97d-37d5531a55amr5620451f8f.48.1728835424046; Sun, 13 Oct 2024
 09:03:44 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com> <20241013130211.3067196-4-snovitoll@gmail.com>
In-Reply-To: <20241013130211.3067196-4-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 18:03:33 +0200
Message-ID: <CA+fCnZdakHrmky_-4weoP=_rHb4cQ9Z=1RkZnmZcumL9AXeo1Q@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kasan: delete CONFIG_KASAN_MODULE_TEST
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, elver@google.com, 
	corbet@lwn.net, alexs@kernel.org, siyanteng@loongson.cn, 
	2023002089@link.tyut.edu.cn, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org
Content-Type: multipart/mixed; boundary="00000000000053d77606245ddd32"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="kFn/uyMe";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--00000000000053d77606245ddd32
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Sun, Oct 13, 2024 at 3:02=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index d7de44f5339..52fdd6b5ef6 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -511,17 +511,12 @@ Tests
>  ~~~~~
>
>  There are KASAN tests that allow verifying that KASAN works and can dete=
ct
> -certain types of memory corruptions. The tests consist of two parts:
> +certain types of memory corruptions.
>
> -1. Tests that are integrated with the KUnit Test Framework. Enabled with
> +Tests that are integrated with the KUnit Test Framework. Enabled with
>  ``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verifi=
ed
>  automatically in a few different ways; see the instructions below.
>
> -2. Tests that are currently incompatible with KUnit. Enabled with
> -``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These test=
s can
> -only be verified manually by loading the kernel module and inspecting th=
e
> -kernel log for KASAN reports.
> -
>  Each KUnit-compatible KASAN test prints one of multiple KASAN reports if=
 an
>  error is detected. Then the test prints its number and status.

Let's reword these parts even more, please see the attached file.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdakHrmky_-4weoP%3D_rHb4cQ9Z%3D1RkZnmZcumL9AXeo1Q%40mail.=
gmail.com.

--00000000000053d77606245ddd32
Content-Type: application/x-patch; name="kasan-doc.patch"
Content-Disposition: attachment; filename="kasan-doc.patch"
Content-Transfer-Encoding: base64
Content-ID: <f_m27rwwlv0>
X-Attachment-Id: f_m27rwwlv0

ZGlmZiAtLWdpdCBhL0RvY3VtZW50YXRpb24vZGV2LXRvb2xzL2thc2FuLnJzdCBiL0RvY3VtZW50
YXRpb24vZGV2LXRvb2xzL2thc2FuLnJzdAppbmRleCBkN2RlNDRmNTMzOWQ0Li44M2M3NzdiYzk2
ODgxIDEwMDY0NAotLS0gYS9Eb2N1bWVudGF0aW9uL2Rldi10b29scy9rYXNhbi5yc3QKKysrIGIv
RG9jdW1lbnRhdGlvbi9kZXYtdG9vbHMva2FzYW4ucnN0CkBAIC01MTEsMTkgKzUxMSwxNCBAQCBU
ZXN0cwogfn5+fn4KIAogVGhlcmUgYXJlIEtBU0FOIHRlc3RzIHRoYXQgYWxsb3cgdmVyaWZ5aW5n
IHRoYXQgS0FTQU4gd29ya3MgYW5kIGNhbiBkZXRlY3QKLWNlcnRhaW4gdHlwZXMgb2YgbWVtb3J5
IGNvcnJ1cHRpb25zLiBUaGUgdGVzdHMgY29uc2lzdCBvZiB0d28gcGFydHM6CitjZXJ0YWluIHR5
cGVzIG9mIG1lbW9yeSBjb3JydXB0aW9ucy4KIAotMS4gVGVzdHMgdGhhdCBhcmUgaW50ZWdyYXRl
ZCB3aXRoIHRoZSBLVW5pdCBUZXN0IEZyYW1ld29yay4gRW5hYmxlZCB3aXRoCi1gYENPTkZJR19L
QVNBTl9LVU5JVF9URVNUYGAuIFRoZXNlIHRlc3RzIGNhbiBiZSBydW4gYW5kIHBhcnRpYWxseSB2
ZXJpZmllZAorQWxsIEtBU0FOIHRlc3RzIGFyZSBpbnRlZ3JhdGVkIHdpdGggdGhlIEtVbml0IFRl
c3QgRnJhbWV3b3JrIGFuZCBjYW4gYmUgZW5hYmxlZAordmlhIGBgQ09ORklHX0tBU0FOX0tVTklU
X1RFU1RgYC4gVGhlIHRlc3RzIGNhbiBiZSBydW4gYW5kIHBhcnRpYWxseSB2ZXJpZmllZAogYXV0
b21hdGljYWxseSBpbiBhIGZldyBkaWZmZXJlbnQgd2F5czsgc2VlIHRoZSBpbnN0cnVjdGlvbnMg
YmVsb3cuCiAKLTIuIFRlc3RzIHRoYXQgYXJlIGN1cnJlbnRseSBpbmNvbXBhdGlibGUgd2l0aCBL
VW5pdC4gRW5hYmxlZCB3aXRoCi1gYENPTkZJR19LQVNBTl9NT0RVTEVfVEVTVGBgIGFuZCBjYW4g
b25seSBiZSBydW4gYXMgYSBtb2R1bGUuIFRoZXNlIHRlc3RzIGNhbgotb25seSBiZSB2ZXJpZmll
ZCBtYW51YWxseSBieSBsb2FkaW5nIHRoZSBrZXJuZWwgbW9kdWxlIGFuZCBpbnNwZWN0aW5nIHRo
ZQota2VybmVsIGxvZyBmb3IgS0FTQU4gcmVwb3J0cy4KLQotRWFjaCBLVW5pdC1jb21wYXRpYmxl
IEtBU0FOIHRlc3QgcHJpbnRzIG9uZSBvZiBtdWx0aXBsZSBLQVNBTiByZXBvcnRzIGlmIGFuCi1l
cnJvciBpcyBkZXRlY3RlZC4gVGhlbiB0aGUgdGVzdCBwcmludHMgaXRzIG51bWJlciBhbmQgc3Rh
dHVzLgorRWFjaCBLQVNBTiB0ZXN0IHByaW50cyBvbmUgb2YgbXVsdGlwbGUgS0FTQU4gcmVwb3J0
cyBpZiBhbiBlcnJvciBpcyBkZXRlY3RlZC4KK1RoZW4gdGhlIHRlc3QgcHJpbnRzIGl0cyBudW1i
ZXIgYW5kIHN0YXR1cy4KIAogV2hlbiBhIHRlc3QgcGFzc2VzOjoKIApAQCAtNTQxLDcgKzUzNiw2
IEBAIFdoZW4gYSB0ZXN0IGZhaWxzIGR1ZSB0byBhIG1pc3NpbmcgS0FTQU4gcmVwb3J0OjoKICAg
ICAgICAgS0FTQU4gZmFpbHVyZSBleHBlY3RlZCBpbiAia2ZyZWVfc2Vuc2l0aXZlKHB0cikiLCBi
dXQgbm9uZSBvY2N1cnJlZAogICAgICAgICBub3Qgb2sgMjggLSBrbWFsbG9jX2RvdWJsZV9remZy
ZWUKIAotCiBBdCB0aGUgZW5kIHRoZSBjdW11bGF0aXZlIHN0YXR1cyBvZiBhbGwgS0FTQU4gdGVz
dHMgaXMgcHJpbnRlZC4gT24gc3VjY2Vzczo6CiAKICAgICAgICAgb2sgMSAtIGthc2FuCkBAIC01
NTAsMTYgKzU0NCwxNiBAQCBPciwgaWYgb25lIG9mIHRoZSB0ZXN0cyBmYWlsZWQ6OgogCiAgICAg
ICAgIG5vdCBvayAxIC0ga2FzYW4KIAotVGhlcmUgYXJlIGEgZmV3IHdheXMgdG8gcnVuIEtVbml0
LWNvbXBhdGlibGUgS0FTQU4gdGVzdHMuCitUaGVyZSBhcmUgYSBmZXcgd2F5cyB0byBydW4gdGhl
IEtBU0FOIHRlc3RzLgogCiAxLiBMb2FkYWJsZSBtb2R1bGUKIAotICAgV2l0aCBgYENPTkZJR19L
VU5JVGBgIGVuYWJsZWQsIEtBU0FOLUtVbml0IHRlc3RzIGNhbiBiZSBidWlsdCBhcyBhIGxvYWRh
YmxlCi0gICBtb2R1bGUgYW5kIHJ1biBieSBsb2FkaW5nIGBga2FzYW5fdGVzdC5rb2BgIHdpdGgg
YGBpbnNtb2RgYCBvciBgYG1vZHByb2JlYGAuCisgICBXaXRoIGBgQ09ORklHX0tVTklUYGAgZW5h
YmxlZCwgdGhlIHRlc3RzIGNhbiBiZSBidWlsdCBhcyBhIGxvYWRhYmxlIG1vZHVsZQorICAgYW5k
IHJ1biBieSBsb2FkaW5nIGBga2FzYW5fdGVzdC5rb2BgIHdpdGggYGBpbnNtb2RgYCBvciBgYG1v
ZHByb2JlYGAuCiAKIDIuIEJ1aWx0LUluCiAKLSAgIFdpdGggYGBDT05GSUdfS1VOSVRgYCBidWls
dC1pbiwgS0FTQU4tS1VuaXQgdGVzdHMgY2FuIGJlIGJ1aWx0LWluIGFzIHdlbGwuCisgICBXaXRo
IGBgQ09ORklHX0tVTklUYGAgYnVpbHQtaW4sIHRoZSB0ZXN0cyBjYW4gYmUgYnVpbHQtaW4gYXMg
d2VsbC4KICAgIEluIHRoaXMgY2FzZSwgdGhlIHRlc3RzIHdpbGwgcnVuIGF0IGJvb3QgYXMgYSBs
YXRlLWluaXQgY2FsbC4KIAogMy4gVXNpbmcga3VuaXRfdG9vbAo=
--00000000000053d77606245ddd32--

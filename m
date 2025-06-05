Return-Path: <kasan-dev+bncBDW2JDUY5AORB7OHQ7BAMGQEZ4HL5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44CDDACF71C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jun 2025 20:37:51 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-450d9f96f61sf9387355e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jun 2025 11:37:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1749148671; cv=pass;
        d=google.com; s=arc-20240605;
        b=T4RsEv5T9LyNUTOlz2olgFgdOnfmaimKHDocXPOZ3/V685Hl6fvDMiw2BH/W+Xur+C
         1TZZAsUAKa+I7Yn8BRbo/WXvvwHr098EZg9S8d/jRo84UWQOZDkStC3u3u3Z1DzUhQHS
         d4CfO6Dht9JzxptEw3zBe/hZ37ZHe4Q615NWtSs7B3QgvwzkxWX3eJ+oW96B39+cVKxX
         1ZcVbXOnICdTCOQ+pzJHlCXZNHovRssncIZ4VIle9w+/XYKSzq+cGVVM7hehdq8W9uK/
         gnW7BjG5mLUqqGQ7qYBB0d3UbwBScrY1MtfkbCdQhvLNpLlfmb7wOzTx6I4b5aMImz4l
         iANw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DS5LUIfEpAxoXcBXqxEsaPI5+Gv4Kv0QNXDoD7k3eZE=;
        fh=SBP8gm9M9x0YHaMfKc9vneguz+GzIzeKnGYJT9Hnt9o=;
        b=XUL0eaE2iUDcCzQJx6fgkAnovIZaHTwGW1wkIpZkPndD30u+Xcf9zIIMfxWpSIRiOD
         qQXMM36IA19Xo9mPj9DJi7yue4J6JjIjMOAEbUxYifsbDCjuMlQGBUM7SYESPwO3+0tn
         xPilerYZirQHgnlalXKrrmbKPrlD/F6k1SwikzHCLBr5hj+AZcQ0sMe+Sl//ewcQb7GF
         ZVzcr7gQdUvAvo/csN1btYKn9bzCCydRThbu8MX//bxjn90iXzwrwgmpeJmZBLJXwqUH
         q8FQxpW9cWd8/5BeTHghrQ2Nz45S+sfl6nYMpsZGEb0iilZUA9B/bIUyrjecmuu5Qei2
         J6LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JwBIRDlo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749148671; x=1749753471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DS5LUIfEpAxoXcBXqxEsaPI5+Gv4Kv0QNXDoD7k3eZE=;
        b=bElce95WowXKedfQsXcZVSPAU40Tq2gSu+3PWkueIgHXm8wl5GY/s/L5M/2B2iakkz
         wvASZChwVX+Po/rApAUDFLEXLnYscxNLwqAeJfrvU0jHfzedBf69WWirwrerHDjjd6B6
         3dichmUtS6HfyQubTDzTq2K+UCn4xvrq4fzusTqlbRhTQ2V+HbQHVyRvaP5jzdv6LRyq
         V8ZTt+C2P5PTkdbnrRp2q5dNTabas3zP3/OWVRESQj927U1FqJhpZWiPcmpu/HkPFaPB
         YQyxXUuoKOgQhLI8mds4DGA4BWXUJXdzjKLjVUkq/1KezrLcleG9S3wyjlm9s3n+hXVN
         dTOg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1749148671; x=1749753471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DS5LUIfEpAxoXcBXqxEsaPI5+Gv4Kv0QNXDoD7k3eZE=;
        b=XrIFKou+gOck28bK0XvaOJbbR4NAYAvu+dShmsw1PVARxbTfllH4ZuMRJRC6Ffr5kj
         o6gio+SUMUruETKv22Ptz5LS2rZM/0Ybbllz+by4V1l4i9pvoj2sUVUdRYJvdOqRCanC
         2YackY2UvDRbWiLmGFRuhjfPb1OMpD9t1syA74a5LUKKunZmls9zCW9HNVNDswZasUVC
         pTlrKuT90uM+u3THW7SLjOoQ4yh9OLX+8vbmTECdHinmd4mi2ubprXSHTDF2l6lU1XSc
         KqJklIVqArbcscVYuSTW+VLnBbiHmpLH9zDIm9Jl5uOGXFLRjYoZUmU7+Udpp6cy+K/t
         Jfbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749148671; x=1749753471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DS5LUIfEpAxoXcBXqxEsaPI5+Gv4Kv0QNXDoD7k3eZE=;
        b=F3Nkeygxdo0QqyOCun6PKOywU3jt/HrVl/zoHTQ25TxtBFFOxukM6crKi/Y8hnKsUy
         M6ErHuXZP5o6lO9Nem8d0ubSREsIgOI+CmgCdcPhYiV558lPgiw8oGL+sX9C538GD6i1
         rnQbcxDG4ZzP3gIBRnCyVuEaaNmWChS5gqptL68FlnRv6sU51roIukE1SwpoQj+0Yncc
         CWaTEFu9BsQ7WI3sT/gW8qWdR3LqPUyb61Gr/WySICUYDQmggzrH3/F9n+6V/XUL9N2u
         7Fo9/Tdd6SoGrejYmRQuueOcYbayC1q69q0gTba0ywTusduJ/dBvKY/03kfv2+bYgZyF
         V49w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9rxJ1rC5y/RJwLpmi1B6tw6hqbh1yvZY3Ge/LbBxCTVOML0toJ3ONFOIQN6FWgKSsycpuNA==@lfdr.de
X-Gm-Message-State: AOJu0Yxn9TXBn+BbQy7h294sV9CveBInVDYE9cvOS0FxphxU1BoXrGwx
	727GNg+e3MzLwSm/wUIBsbxfyUUgydOc4/BCeDBYeOxK2wGZwgUm/lcy
X-Google-Smtp-Source: AGHT+IHBmtKW/Ly6OKXe35iyYB29KvLWPGap/v4hnTMslRtAVW82nTIFmuQbYFjO0cAZJnTD/LlQ+A==
X-Received: by 2002:a05:600c:4ed0:b0:442:f97f:8174 with SMTP id 5b1f17b1804b1-452013b0417mr5216335e9.18.1749148670311;
        Thu, 05 Jun 2025 11:37:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7hgILFlyCMCGPOOX7AVBdBgF8LF0dP6R2jvuxDPQvpg==
Received: by 2002:a05:600c:3645:b0:43c:e3ef:1646 with SMTP id
 5b1f17b1804b1-451f88dadd6ls5724065e9.0.-pod-prod-02-eu; Thu, 05 Jun 2025
 11:37:48 -0700 (PDT)
X-Received: by 2002:a05:600c:4ed0:b0:442:f97f:8174 with SMTP id 5b1f17b1804b1-452013b0417mr5214685e9.18.1749148667695;
        Thu, 05 Jun 2025 11:37:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1749148667; cv=none;
        d=google.com; s=arc-20240605;
        b=VTeaZePQVMAWP5ssyZ9oPOR0+y3DSeDkcIxCfg7U85l30v3JFHPdJ/+JxCcWAJxSvW
         dTxrlGa/Tsys1MX8S28EkEVvnmZDOD28RHFj5EIzIrjBGJdIoL2XeleRRTQu3BP00Lv0
         eTQXvE6bKBLki3kkATU94SqKfPPfDbKcV2ugStquO2gdH/dHx6jXStToivMMDQXGXdzs
         R7jOn5g/bX3SAkelciGAhiM/WZdWoXM3XQ+3DLxxNuHXc/u9j2NTbR8JDNblfYXskuQ0
         D+7D38qcfygr+P9fXdEZjPNyia3JestyykyUmPLHXi/OQ5YBBBDXyq0hzs3c+4vl/zdY
         dRVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2/3kb+A00vP7gPuy8nioz1x3iMOxx8RCT3twKi4k9/M=;
        fh=2lsUIz+BICPKGoruVn5PQ6eMV1TqeJjGPhknO964m/Q=;
        b=B6VmsleBwhQaLv5rkP+moJI+/0yHyLe6OwN/8hKJ/VkeX3wwSvv/ce1kW41T7OAHWb
         eHldZ+iA/qPulKERRbknpoomY2nP41u5O2rfuOKm+RP/B2TVj41EXv+Mrd8Qb27bJtBR
         4jveiOx2HMDB0LnqIFLkR0hqKxlIo+0D85bnU7l+l2h27GKvWrSfK2v8uDJO51OuOMmx
         OFTN64f4cLRQ9a49bD2ci0XbtrVxCmci3jUYeNbt93sSelGtbEDnDTfrR1SuWKBUOufD
         KxAhd24GGQpX/Z7A3+Bv8Xr7VC2Bv4VWhfeINIo8ZZ2pG/OIb0GqwLBUjIFZlwmErrrr
         9YpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JwBIRDlo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-452013ded78si52125e9.0.2025.06.05.11.37.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Jun 2025 11:37:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-3a50956e5d3so1116813f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Jun 2025 11:37:47 -0700 (PDT)
X-Gm-Gg: ASbGnct5xGW90DCat5kwXgc4AEj+6h25apL3wzGBBsINihkA+1gUe1bX+4LsFPWS8gc
	vLaSEj8+sCCJQjNo8OoFHoyGehH/NOl7zNH7Y7RSCfcj6ni4WXLa3pnA4k3/mt2Df5qehImHg4D
	FgCgmeNFsE8+d0V8NGVo0llnkAyfVyHmGMJCo=
X-Received: by 2002:a05:6000:310e:b0:3a5:1222:ac64 with SMTP id
 ffacd0b85a97d-3a531caf8b1mr163860f8f.38.1749148666968; Thu, 05 Jun 2025
 11:37:46 -0700 (PDT)
MIME-Version: 1.0
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
In-Reply-To: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 5 Jun 2025 20:37:34 +0200
X-Gm-Features: AX0GCFshe6pCWAx2a1xBLf-rwvBNss6UkKL_rTWRnqWNqU9rRmkYBLxCHVieS2Q
Message-ID: <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
Subject: Re: KASAN stack and inline
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JwBIRDlo;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
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

On Tue, Jun 3, 2025 at 10:05=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Hi,
> I'm still digging around in the x86 tag-based KASAN series and I'm somewh=
at
> stuck fighting with llvm and KASAN_STACK / INLINE.
>
> Is KASAN_STACK supposed to work with LLVM? Are there any requirements (ve=
rsion,
> other configs) etc?
>
> I have odd issues with it, such as load_idt(&idt_descr) (which is just th=
e LIDT
> instruction) inside idt_setup_early_handler() freezes the kernel. But whe=
n I try
> to disassemble vmlinux with the llvm objdump there is no difference betwe=
en
> assemblies with enabled/disabled KASAN_STACK.
>
> Also is KASAN_INLINE required for KASAN_STACK? I saw some remarks about
> KASAN_STACK doing inline things but I couldn't find many reading material=
 on
> KASAN_STACK on mailing archives or the internet.

+kasan-dev

Hi Maciej,

Yes, KASAN + KASAN_STACK should work with Clang/LLVM. At least for
Generic mode and SW_TAGS mode on arm64.

For example, syzbot enables both options and, AFAICS, uses Clang:

https://syzkaller.appspot.com/text?tag=3DKernelConfig&x=3D73696606574e3967

And I believe KASAN_STACK should work regardless of KASAN_INLINE.

The only Clang-related issue in KASAN that I recall is this:

https://bugzilla.kernel.org/show_bug.cgi?id=3D211139

You can try disabling the instrumentation of the function that causes
the issue via the __no_sanitize_address annotation if see if that
helps, and then debug based on that.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX%2Bb3L3WmV4tyMg%40mail.gmail.com.

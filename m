Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLH43ORQMGQEYGTDZHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57B3F717944
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 09:58:37 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-3f6045853c1sf21568285e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 00:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685519917; cv=pass;
        d=google.com; s=arc-20160816;
        b=RwNjbpPUFmQQimxfprsDYfb+Wq8TgOIb4rtFqpJQ2nMhEdsNkOVQQWomJXD7IlWDvk
         0gAeQtaP7YaAhbdZjA6/jZY6PTl3reLwniT4Qd4EqXbPBaw867vrIyB6yhfvZT2ruKrI
         dmyq+KdLcnSFCYRCqMUyJJ44JjynWiDf2y09s4IMDBhBzie74XPtWmTuNFi6YHIBgigY
         Pcek79hZsvP4zYo5qQ96mKtqsIsZ359t2AvztjmkI8sCpt52yiU9RkaseKJT/ypWHlki
         Yd6s4wsY/NzPd93kRReCGNIZgaMTn8OvSimLMI0JrwLTxDjQq0Ba+py8xgwUR3y4yJ2Z
         x73w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5dbcE1x+qABzhJ/vNk1EloqFX+hNngjBLa6MfQgj9MU=;
        b=DdV8erAoh7wM8oHIcBxMpgXnAJ3VvtV7T5ZVc7TvHYdc10bb6GEy1PRxnk0rg6H/2n
         JKpdPCwxmz/z33cJBvXM0VOB2wN/F7vdnEPxau4JDYJLlaHL1i9jAzgPGykgnT3x8sQV
         yCP61NtTYwIFZaPbLqhd/40UxysmUpoCWpUY5eQKh2fBxXWiFkVMGA4KYQcqJB07q4w/
         1H3eH1MAJWVMTkIW6jmqrT1aC4Ny7++Wi0rwN7/tuWbDZZWDaXtLojBOK8Oj9GBxxYRl
         H/JWB8LwikHyPZUDMu0EBpZOgXZCawtNuR3Y8v+mH2sEjgWax+Hw1+EC5MSec3NEu74y
         qBQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=rAWvgvyn;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685519917; x=1688111917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5dbcE1x+qABzhJ/vNk1EloqFX+hNngjBLa6MfQgj9MU=;
        b=bU1cuw3reSHlwgNefDD/yC4uoY2mUP90SIdl0qGCyfwPivB7Eq/iyWpLlrGzJ3OC7V
         rBSOi9/lQg/e52UkI2WZjnVa1JpeJ3lLgaBERuwnajCWybIoCwMBCjDsOCerrT3X/qrD
         p/DW56y+blmCaQZBpAZzjBUmTbIPn+KbBqvEQk2Mz2j3BJ7DjEn/dQBlc3IEii/v95jv
         cUb58BM7cgkb2KjWE4b8vHaEdvRZfi1zG0mSifns6qN39tMhGZz0ZrwggT0K+kYlvf+X
         fZ5D0JWOJq6tQfLs/Wwnn1+zIKyYvnuQT1wyguHvvWfgO5+p2aB116rNcsIadiBcRSKu
         LqMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685519917; x=1688111917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5dbcE1x+qABzhJ/vNk1EloqFX+hNngjBLa6MfQgj9MU=;
        b=PRJOU+CpH4u2bojJiRtd/uz9RrGgI5S7VMZTghwXuHTMmpz6H2j/NUq7zRIQteHyDK
         n61U6wBvW/yWIqU4CwKjIhZpToiZHXa6Kd4yx3VS3pS/gW4w9i52+Z+HvOFz56lPMO70
         +sSc+kW7dXM64T1slQdz6UvDU32xPxHLjeeSXYPnLCyEDNw+B/tX4EmIXRcDYxiZ9seN
         Y21Be4iTfNV5lxeitlvzDCokgE9RhB1JlaZs1vKOMwmF1XltaCCnIttCftCPBdW6YjHL
         OAs232jvCfZzeC9dbHWyeu9FG9Hu11N9Ja8Cn5GwBVPVrlc9m0j6vS3M8TIVDIObyjD+
         g+VQ==
X-Gm-Message-State: AC+VfDyhu0vsOZZpJ998zaGNULt0m7MmxbQ8GaCupqfq1+wGSJWHq9QQ
	MU7/wm82myn4J7Tokw5DbZU=
X-Google-Smtp-Source: ACHHUZ7nb/3THcKQD2Zx8OeVozMrqnZ1xaOgOYcNfiwaouDToHOkCSOw9Uus6LOWuoj5Vnb0rGSIkg==
X-Received: by 2002:a5d:6ac1:0:b0:30a:d86b:de6 with SMTP id u1-20020a5d6ac1000000b0030ad86b0de6mr713720wrw.11.1685519916301;
        Wed, 31 May 2023 00:58:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b27:b0:3f6:cb7d:f6b with SMTP id
 m39-20020a05600c3b2700b003f6cb7d0f6bls4566663wms.1.-pod-prod-02-eu; Wed, 31
 May 2023 00:58:35 -0700 (PDT)
X-Received: by 2002:a7b:c3d4:0:b0:3f6:89e:2716 with SMTP id t20-20020a7bc3d4000000b003f6089e2716mr4287494wmj.33.1685519915043;
        Wed, 31 May 2023 00:58:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685519915; cv=none;
        d=google.com; s=arc-20160816;
        b=xQev5Ub8sYFZybgv2vEN5358OWooA8jinW5WwtSGHQ/PjbN2/Ud5ovEDznx3rSvcs4
         x+00aPVscZ1VFvJUmlrUt4hJNGDmj+kR8TF6RYTjOo/ywvSO5q3XlFjTpMsAeQBYLrnb
         iMYSAGab6943dqWvDmjBV5RLIL5maMI+DCvtUGDLBU1xnFqT1w0ojS/SRKHncAB6OUVY
         KOvNgw3NWYrJD//FcivlhIxRZTSdzF5S91Y2RTofrjPJmnFGgo+TUqKknwvQvhTx3bad
         Baw3D3ZjxbaZM+7bgbXtyzOwF00PaBLR9uNyhVT5XbOef0Kpte3fkI9xPqCSR18z70Iw
         X/HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nHMZgb7ql614fjK+awMwSPS6BsriEA2nG/M+3wX+ebo=;
        b=MDKJvx4HyYH/tuKnxvYmYuixqh+zblMcvoQWOyG+eeh1GXxeFlJYntWCokp3YtWFP5
         7uHJhw/3Ru54DjG+eeBd3jPdaDdDwpssvpo9HDCUNwYQscYDzwf40Fh2r9TKBh021bw/
         NqosLDEniGgwmpvXlH2VMSFCKJwEBJVCvoOz3ERBjcNUzG2ISOeNV6RVqWQ+tKbim2yx
         a1rh6GXMTQ7kEACo0M5fwfDibaNDjTSCQ1Pdl0XNSbmZPbc1VZdXECWUOjnch8xLPhvc
         DQhx2S5iG+GydkvD1rUUhlwY/sF5c2DtW3qJxxCLhA66OPWaNqyPxwmzQ0+Ru/bLDdk5
         NrAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=rAWvgvyn;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id e1-20020a05600c4e4100b003f6069b86d0si1388308wmq.2.2023.05.31.00.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 May 2023 00:58:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-4f3b4ed6fdeso5895674e87.3
        for <kasan-dev@googlegroups.com>; Wed, 31 May 2023 00:58:35 -0700 (PDT)
X-Received: by 2002:ac2:51a2:0:b0:4f4:d41b:f416 with SMTP id
 f2-20020ac251a2000000b004f4d41bf416mr2067501lfk.4.1685519914228; Wed, 31 May
 2023 00:58:34 -0700 (PDT)
MIME-Version: 1.0
References: <20230530083911.1104336-1-glider@google.com> <168548824525.1351231.6995242566921339574.b4-ty@chromium.org>
In-Reply-To: <168548824525.1351231.6995242566921339574.b4-ty@chromium.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 May 2023 09:57:57 +0200
Message-ID: <CAG_fn=VOsPw=EqN=P3zPfDyD=ZKYtzUVZ=y42HcqrY2hznx6Ug@mail.gmail.com>
Subject: Re: [PATCH v2] string: use __builtin_memcpy() in strlcpy/strlcat
To: Kees Cook <keescook@chromium.org>
Cc: andy@kernel.org, Andrew Morton <akpm@linux-foundation.org>, nathan@kernel.org, 
	dvyukov@google.com, elver@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, ndesaulniers@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=rAWvgvyn;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::134 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, May 31, 2023 at 1:10=E2=80=AFAM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Tue, 30 May 2023 10:39:11 +0200, Alexander Potapenko wrote:
> > lib/string.c is built with -ffreestanding, which prevents the compiler
> > from replacing certain functions with calls to their library versions.
> >
> > On the other hand, this also prevents Clang and GCC from instrumenting
> > calls to memcpy() when building with KASAN, KCSAN or KMSAN:
> >  - KASAN normally replaces memcpy() with __asan_memcpy() with the
> >    additional cc-param,asan-kernel-mem-intrinsic-prefix=3D1;
> >  - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
> >    __msan_memcpy() by default.
> >
> > [...]
>
> Applied to for-next/hardening, thanks!
>
> [1/1] string: use __builtin_memcpy() in strlcpy/strlcat
>       https://git.kernel.org/kees/c/cfe93c8c9a7a

Note that Andrew also picked it to mm-unstable

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVOsPw%3DEqN%3DP3zPfDyD%3DZKYtzUVZ%3Dy42HcqrY2hznx6Ug%40m=
ail.gmail.com.

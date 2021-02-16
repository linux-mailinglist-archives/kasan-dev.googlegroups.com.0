Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUNRV6AQMGQEUXILS4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ABE031CC1B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 15:38:11 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id d8sf13890829ybs.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 06:38:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613486290; cv=pass;
        d=google.com; s=arc-20160816;
        b=HuCZxSHwdlEhiktSWCje8aM3j0IsrT1i2KrLT5+YEJhB2y65wrvYa6t68PSqCHlZHz
         +pK40N20fgR+WNLXdp7SG8fERcFqJSbHTqEliUmfCmmvMwTERrinfQayTEKdnckoIJ6a
         qmECr4bY63p6ww3r6qGQRtbe0hw8mf2uS6HZh1xXpb/Ki+OBtkHxuR5bp/CYL70JP+hZ
         Tx6p3gSw2h2gcHlF7BmjsDO5Ogz7bi051v4lumr9VLWPm1PLoV0BCsz9If7jbVraDPTN
         qy5AIRZew5UwPX5/E2FrynvtnPNHs8M+jvuPdqONf2I8RLvwgVvxH+3oKn9cLsfFyfB2
         uSLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OPU/1FkKEDSsODOMzKs6PNUMffT0W1Sb/R69ZwDf8hY=;
        b=j8Mcv7gYzd0/tF75HA+mY9MmF2On1r6qHSLTkb3xti00mwo8DiEBbDKtgakuk22GL9
         7J2VqR0M8E6dLSvVUhOngMOwPYXg0xWpEZt9GE/kf2K+kluN2mL5y8Sv+4fnl1XUxQBm
         y69ZbbYw+1WKiB9dkhb+hVLgzltDxEEZcfYa/RSYATfrqMol3sRGMAC3fI7PEA/92eA/
         CuY9IQd5VTt7bWO8cQxTW8ChXE8oWVQJ5B+Wg3NCDtW4XS85GQz1Nu2rTjmI3VLnsJ+m
         +mUVBBt1xJILenc9csv2izIMoFuS8Put0y9LmrfCt+vaMXxoDeAw95xRt0slI2EcHv+R
         wMzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XFK2W6U4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OPU/1FkKEDSsODOMzKs6PNUMffT0W1Sb/R69ZwDf8hY=;
        b=TQdrok5S4xNLWWnjic5MNijdh8dIxf9xOPWG4YOJaD6S82IdhV8lzP2RPRUdhsG2iu
         oHi0hOjBKm24SX6PLzLDCyJHH0PpuV4ex284jdTvcXcR+aOTSPkSYb+tMoo9ttEJ0I2H
         McLzqewz1mT6ll34o09L/z0lqTCk4EoOafmufk8sJ4AYxZ90kbeWp1xx5oT85HVG+lEy
         QiwbmicC2ufjrTAu9YPrLyjBedoBmhyNdxuSXeSdHajvCfnBqTvbRbhyyn4oF5foPY2P
         VMMk+M5qBZX+ogf4qCNrGm4g3GGQRGk+Z8okdc5G2U8WtCnVEWVSzgBd4bcB9GbL9cZD
         0rEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OPU/1FkKEDSsODOMzKs6PNUMffT0W1Sb/R69ZwDf8hY=;
        b=db4CtMpmTDfl7f9MWmdRzSZlgjV030ZC1wwxKqdCqszi8ScP9YBhWF1CtHHSg5Y+1P
         sEc8fXcm004fk3+GPx4Qz0tvKWRWCtPCtAqpf33r61OOsODRZF1/amotzs5R3kVwd5TD
         PQ4bG1Qupw1DvrUNdAthuPrt0LN1Lwbv8az+eYxqOX6tPgCNvrG2J0AxJPceAugaleUU
         eJA8ApunHQIl3Z/AxdT9x0Vc8nRfK5sUB0iHMjVgiYuMHACgKjJW86WoZu/aSIV4Iwgt
         BDyE4YZ9YsjVYN9sJicFUQrQA8+T4oN1n7r+7f1GbbENB6Oo/cgfSsmVdCmoEVRN/JGO
         IIOg==
X-Gm-Message-State: AOAM530Sd3EZvjn0PiSF+6ApfM1BJmVMBX3SPbvyMdHt2hpn3BhMVkUI
	W3oqvuktDdHwvNeb4SfKslA=
X-Google-Smtp-Source: ABdhPJwxg8DZCZ+HRBxs+Dq5Uoe0kb5oSYjxHc+o9jy/moHlBlN9QQpVlzVvTrQxF/Zxr+m5m/NTmQ==
X-Received: by 2002:a25:1457:: with SMTP id 84mr30349154ybu.74.1613486290010;
        Tue, 16 Feb 2021 06:38:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3d03:: with SMTP id k3ls9235769yba.6.gmail; Tue, 16 Feb
 2021 06:38:09 -0800 (PST)
X-Received: by 2002:a25:6110:: with SMTP id v16mr29376267ybb.435.1613486289627;
        Tue, 16 Feb 2021 06:38:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613486289; cv=none;
        d=google.com; s=arc-20160816;
        b=cN8xHl1OzOocGP2QpF1h1Kj6BJupOah4iRCa6pPSvmo070mpkQ5oILiagLK51yuLGu
         g/V3YlZD1vpc7Jg3E5mEuCUOd/fMTsWdm7C48Q6BwpaEsHzJVwVnfdeNYyySmq0/p4fe
         3mkvdJdHqd90cwXiknbVQyW5Y1z0AWcr6cMF7ER6QWlLALt2RMhsOwXxmncTDNjzWsKP
         g5Vo9GIMdWU/1D2kqwMvmG68tQ4ynRQus/RPoVacVSeDfgWaMh1Z7B/+/sl9sagMXARw
         r5BfYr3wLjNaIm/yUmVo8dOf8UwqgYmd2JRZrzm6GtUMlgiNd9iZnksvKvqLCyz3Br7M
         2pEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tFvrda35dMbRxlcYLXUSE/8d3zZXv7a6nUnMUpXrkjI=;
        b=Kef44aIisuEjZasgzj29WWbNS9T+jP7Um1gSkPTJDAIPr6PQH0Vs7W8bN1KYX34Yrs
         PcniBMvRKhuMVqKr4b2kTpcvorbtKw0RRawu54QtqdTIHZF59gkJDHsE6zYIVEGimVNl
         Rai+ZNEuCj4cr+BxsQErrmCy6N+PypkuQxC5t6bhoIqDeHHstHxTzGQD7Xb0NWM5VWcU
         Pebk5d1c74TRNViNlxj7lQacoE6apbJru8zyBANAqdPi5uPKSK1kX3x/Nl632PZspT/P
         p/cAgiBGQqRnzL2NaXKHjkSlv+g6qD7d2OrSwV70PlV0nGl6c6OjJcPHkLtQbF67EaNK
         7UoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XFK2W6U4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id i194si1376727yba.2.2021.02.16.06.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Feb 2021 06:38:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id n10so6318457pgl.10
        for <kasan-dev@googlegroups.com>; Tue, 16 Feb 2021 06:38:09 -0800 (PST)
X-Received: by 2002:a62:8cd7:0:b029:1d9:447c:e21a with SMTP id
 m206-20020a628cd70000b02901d9447ce21amr20259077pfd.2.1613486289127; Tue, 16
 Feb 2021 06:38:09 -0800 (PST)
MIME-Version: 1.0
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
In-Reply-To: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Feb 2021 15:37:58 +0100
Message-ID: <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
Subject: Re: __asan_register_globals with out-of-tree modules
To: Shahbaz Ali <shbaz.ali@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XFK2W6U4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Feb 16, 2021 at 1:40 PM Shahbaz Ali <shbaz.ali@gmail.com> wrote:
>
> Hi,
>
> I am having issues getting kasan working with out-of-tree modules.
> Always seem to fail during the asan_register_globals step.
>
> I have seen and tried suggestions mentioning ABI versions; e.g.
> https://groups.google.com/g/kasan-dev/c/NkcefkYk3hs/m/74avihf1AwAJ
>
> As per suggestions I have tried ABI versions 3/4/5 with no success:
>
> Version 5 (default) produces below stacktrace when loading first out of tree module.
> Version 4 crashes near start of kernel loading with similar trace.
> Version 3 produces lots of kernel errors.
>
> I am on arm aarch64; gcc 6.2
> Kernel is at patch 4.9.252

Hi Shabhaz,

4.9 is 4+ years old, there's been hundreds of KASAN changes since
then. Please try a newer kernel. Preferably, mainline. If it works,
you can bisect to find a commit that fixes this issue.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz1k3Y3qQWwYWa5ZuZdYtR%2BsqF9CSauoeLfGqR%3DqcdyDw%40mail.gmail.com.

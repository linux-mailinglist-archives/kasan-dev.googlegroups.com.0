Return-Path: <kasan-dev+bncBCH2XPOBSAERB57PXG4AMGQEINEG3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B8FCD99EEE6
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 16:11:06 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2887dd3c2fdsf2368908fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 07:11:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729001464; cv=pass;
        d=google.com; s=arc-20240605;
        b=I78/Lp8B9rtpW/3Lp/j1EAt0zz+C1O5ymgNZhj2LrBgB0gOYwYUzMkoP1LIMV5/mel
         5J9sxyC2IU51v4MT9ve5jnYljmPSjZTTAUsReJaVTj6ZqaGnSu/JK4UAhPrzwDbinnFJ
         mWKZDg+24FBdPqk2NQ0bFklKgAOzY5P6JKCak91DcBqBD/pOYEzxCAWvjbPcEBl/LUu6
         1FEo8Aj1wOtUpc5JYLJcGbkSkH+Suv8M0r4QbcrI6jwHrJ8Qh6PORKQIpfDwxyZunCTp
         quFCzJiFDmvhUKiZw4W4AEtkg+wjnL/8koT2DYjnu3rfjZLQHZ4IczJueoNS2FYhbYS9
         uRGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=QA6TFqPgNO3wFHV7joDeX5QbSAt+ihLzVXz2kDVtSgs=;
        fh=9A8GyHWJT60Nh/nCMmaTS8lz75rJqegKp6ZdqM+QLhs=;
        b=illwp3n9EHVnxqmTU+o5x9fGy7J4U0bs7NKnYjKi+bxwODar/3UfHjhUtM+Axn+n2K
         mhNO+O/pIDll32/3l6RMZn3qSbKmSZGqLjPHntkTIkb9k+v8D913T+rqNiYph7FuGyTA
         0VV7qG1bY5w67CPnxV91sxpa6jpr5c03VYQgbd1MVkA35vFlRpsYHO6MO/CuFhieFwzY
         Wt0UuwAVFi7CNST4xITP6PublpndxVLCYlIEqGbfANlG2JLqHk15cWeoix87xAixrCLS
         DuICJ3QCUevlPN4sWlbhplxs4q/PFmVc1vEPKNrpo4I5I+DKmAgGMMmkdwnKPdrdlEdX
         Qnwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jc2md3Uv;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729001464; x=1729606264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QA6TFqPgNO3wFHV7joDeX5QbSAt+ihLzVXz2kDVtSgs=;
        b=UmNb79NYoFhkaCdSZqT6cQnX+4itwIL4tBJYJXgDddraZ4+u1BPXEoTWKECtDNMUIA
         +FY8g6rTk8IiyA5qiZWVoQzzbhSqsqd5tMyh52yQJ6ePI0MncPi2TGCbz9srVo2egJbJ
         8HYoG6IVf4Q8m0kP0RABFNNAyx1WrfdZAIEzoA8fSL5jT2nbJcbHQY/vBVM44tBbOn/9
         WoZCcY9Gz9ZgzhKMU91U+lT+mUQHUFwNWwoRtsA5a7qpt2Wr7BQoRPCzLA5Y8zgLlhea
         QTvGnFmeS4EJpNBkZQ5gNCneoLe1oOA8cVk+3iVk5sMaUUyzr0iLBVWakcc+LFdeYp9O
         GF7w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729001464; x=1729606264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QA6TFqPgNO3wFHV7joDeX5QbSAt+ihLzVXz2kDVtSgs=;
        b=WrJIk79n6CpdVwX/7qQkGcKSoF7vS0p79Yuxrnveul5rVZXaXX2dL1Jp0Z91p02pd7
         AJmmP2uUYYhiK57GzGEX4f2XCgcGeNpTcx1IT0xwXTEHAk68UaGtM9i5K5lz3Zw6G5/F
         NYquD1KCSsQPhavWtLrvZ3vb/q3oIpyVtuivCd2nOXqpaiJWwtgcOawQNr7Q3hnR+4ZJ
         U8kEMQjZtP4K0r6/B6XULvTgxAy055qoLSiYTvAPo2ASAsAi6qtRlKK55Y24/XCzNJvQ
         +TUhKfowxX/66PE24dflbi0WnwYiSMy/33i4rf/9qCprhZI8hzsv2meVBOJgO4dOLENf
         LzNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729001464; x=1729606264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QA6TFqPgNO3wFHV7joDeX5QbSAt+ihLzVXz2kDVtSgs=;
        b=S8XLX6Qo4OEvyhSzhvr5FbWr9eI9T79QG3TDJk16ntFvvPkUWkrAqS7XQZunbInXoe
         /fOzw28eNHKTj0hjrh6er5fQEB0YBOe3KV8O18uu0FfnHnYy3Bcpb/qc8wcSm06utZWd
         QXjJw9Qhph5eFk4KaqqaQgLaFaOdiLzbhozkEater6sYQ7fh61z1wESFNwZe2YDSWlkS
         UgXEexp7FS704ghCjndGtxZZJSYahi5f8I42f7xSyV3SIvOmKC4rnRIbfB94311JZL2t
         62VlZiVZNPrHG7LGGP5nLbbnpb1aYTBTMounrvq7wG5QAvtCS4olvJ8anM2dY5UDMTZs
         kBOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXxaWxJJG7Dg3ToZXOY1tQlpg0/RuOsYXuQBE4cYNMHAQabKIxSs3i4DWgrg6M7G7uywy6+GA==@lfdr.de
X-Gm-Message-State: AOJu0YwBdUfiyjypcqSb8SHfMsdkE2XdCRiDU8O+ovQ+7JF5bAq7sxnu
	g7o7SyAQCaEae2g/16cUTvMAtzohwmqXQZ4nR6jYJSpAdVTeCSjD
X-Google-Smtp-Source: AGHT+IG3/LL34WQWd7iC8x3xzK/tc0GZPcKhUjRzDVHtZCxKF6/kFPWbCmo++TRj3Eke6gFnYTBYGQ==
X-Received: by 2002:a05:6870:7196:b0:27c:52a1:f2fd with SMTP id 586e51a60fabf-2886df73decmr10651355fac.37.1729001463816;
        Tue, 15 Oct 2024 07:11:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:7516:b0:287:bd77:a787 with SMTP id
 586e51a60fabf-2884d46816fls1276917fac.0.-pod-prod-02-us; Tue, 15 Oct 2024
 07:11:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN4WgGzPLxBl1WKntiDnuTgULapg+Pcfl64r6vNLJct1mcUb3Vq8UI5VRxrxHmO8MSIIl6SFOYhUU=@googlegroups.com
X-Received: by 2002:a05:6870:37cb:b0:287:f1d3:67e5 with SMTP id 586e51a60fabf-2886dfffde3mr10665036fac.43.1729001462766;
        Tue, 15 Oct 2024 07:11:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729001462; cv=none;
        d=google.com; s=arc-20240605;
        b=VC1VZ0W+3a2MYdrKo+hI6jAMmiaCgDNrTMlszInNr7/z+e5wZkSuBxnIed22va9fHu
         OPKEqelTNjpzPEfbahghZjzOEDggdMqSrBLuh2UTnUP7ltHyT6eV/kRKhsLdK6dU9GC3
         ZLKmFcI4CiJm6Pq0kgtcBaARKwrXiIBu6p8/sUluP7vgRP9zGtvi7ONIDMGpxmavTH18
         12nifwnKpp9alHfqPex528+AHIcvboe3pNKzybcA5QY9alNvhvVfeG1vsSuz00FouzrE
         gbo+uZbm2LcVIubtioqqBvXxf7RwWjc734bC+j5f7nY3NxQcSN0gDFiHBU3zImhn47ZB
         PqXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yU7SIHnP46WmT+FWC/zVEM9bHxNRFsvDbjjWknoaYZI=;
        fh=8umlRgLUxUj6CVd0G8z/v+U0IS7LPX2ioGMRz/hFpzU=;
        b=lDsAWDvaViPnRSJw/+EId/i47V9HaGj75fllGQ22oxtiLXbRFC3KxLT3YmhgSjmnE9
         1DU/EwFKbMC7Z5oRHl5qidDgm4t9L4uXE0QPDJ61AAXU+Kxn/6KRzNnfdofh8Ph0z2Qj
         3YaXrSzRA2+HvAa6zmDOSwMvn+SlaAJ9HVb6bMgvFgngBHQQeyyo5ltoxKCD1/DVSuEa
         WqL4KtXZjC4zOlPo2Mu/PfliWUV2oOwm8kHNht4UWmh+zuuMAgAH18S4TZJCOBFSrDeo
         a6AmyKTUfs+RVXjLSkUTDz9DCrSyPmrCo0SakWWShk6RK8TGFHwHo67y+usF9vwTBn3X
         4tmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jc2md3Uv;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-288dae46071si60001fac.3.2024.10.15.07.11.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 07:11:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 006d021491bc7-5eb276b0009so1169070eaf.3;
        Tue, 15 Oct 2024 07:11:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0fO8bQ4vUqDJZ8mTZf7rJ6Fw3DTcd+VySziG2CxJav82dVhf2S48CCoxXzJpjJpz5qcjwOijBJsnK@googlegroups.com, AJvYcCVDrYa4sx1zTxr9FkP2yLexwsCNW9i3A0af2DP5+zFu96AqIYvNYO6nz/ERiEMFSV8A3Yune4IxsFqCHxPq/T5kSdv9wu/Z@googlegroups.com
X-Received: by 2002:a05:6870:ac87:b0:288:666b:9c5e with SMTP id
 586e51a60fabf-2886dd70e90mr10741729fac.17.1729001462320; Tue, 15 Oct 2024
 07:11:02 -0700 (PDT)
MIME-Version: 1.0
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
In-Reply-To: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
From: Dongliang Mu <mudongliangabcd@gmail.com>
Date: Tue, 15 Oct 2024 22:10:35 +0800
Message-ID: <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
Subject: Re: [PATCH] docs/dev-tools: fix a typo
To: Haoyang Liu <tttturtleruss@hust.edu.cn>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Jc2md3Uv;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
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

On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@hust.ed=
u.cn> wrote:
>
> fix a typo in dev-tools/kmsan.rst
>
> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> ---
>  Documentation/dev-tools/kmsan.rst | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/=
kmsan.rst
> index 6a48d96c5c85..0dc668b183f6 100644
> --- a/Documentation/dev-tools/kmsan.rst
> +++ b/Documentation/dev-tools/kmsan.rst
> @@ -133,7 +133,7 @@ KMSAN shadow memory
>  -------------------
>
>  KMSAN associates a metadata byte (also called shadow byte) with every by=
te of
> -kernel memory. A bit in the shadow byte is set iff the corresponding bit=
 of the
> +kernel memory. A bit in the shadow byte is set if the corresponding bit =
of the

This is not a typo. iff is if and only if

Dongliang Mu

>  kernel memory byte is uninitialized. Marking the memory uninitialized (i=
.e.
>  setting its shadow bytes to ``0xff``) is called poisoning, marking it
>  initialized (setting the shadow bytes to ``0x00``) is called unpoisoning=
.
> --
> 2.25.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QWdqPaZSh%3DXi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ%40mail.gmai=
l.com.

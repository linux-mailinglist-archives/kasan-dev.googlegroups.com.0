Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE4EQLCAMGQED53X5SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 63B5CB0EAAE
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 08:32:53 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-60f428458c5sf2378300eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 23:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753252372; cv=pass;
        d=google.com; s=arc-20240605;
        b=N0UUmM9XoE9mIISx521gNQgGUFqcSWMhHN8ihd1uNeXSv+7mjI0ziKoimdlLYYwZC3
         GbNA6hd5bmMZ/8VH8dcZs6El5L8Ny+IYoUoaD8iNpUd77gN+33eL/BnQquuxd0r7ZxjQ
         LYOwedJoMLu2Hio3m4qNizfcENvx26eL2Tuh0c+9DlZY1bOgAdWSEz3Mnc3wIcESUYNI
         nUD1E7SA6DwfzxkTnFbGKW4LP7A6SD80JsWMK+7O2ZE07zTic3aLoRKeAmE2jC9z/xhU
         dQDmjkeSBuiHY53VHDo4z5UK8WmhFgjzyY5T+WeNsQ35sf+dxi/Av7Na/mNrTdKvqaqB
         XNtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gVhT7EIfUVw/tmOKPtavh3fI5ZsdxFNagMT8lzis8qM=;
        fh=HKi2/4g+4BqtphRWAxk/itp6Qi2HH0Ae/SKdB2Nduuc=;
        b=KRPwVrW9ZXKQ3FJ+IkpICRPuparFX5C5m/gm5JnJDlXEc+a8kgWR3FVBOBFhzG4KEh
         s4DI2+JGR7uiXtKQBhIzvljeRRolXfPWX2j3FoV3gPvcSOJ9JaoLEAwx984UHhEJBlFK
         JAhHS5PbfHyY0qq3e70toRFyObltIdCBP20J/iqMamnNRyhfygTDkpnwHw9tmddJRCkx
         0WqovkSw9K8pYrcIb+HYJnj5EIV/GYaNwe6C+9hy4mfb8308HSO2JFLcEwtpuoMZV5JQ
         7vuf2nD9IkIbxplRgWItBFN9tCe2X/ItBR+N1HwuyYW345vgMGTUDK/7GZhPEv3YCDf9
         NVjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oddFdHxW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753252372; x=1753857172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gVhT7EIfUVw/tmOKPtavh3fI5ZsdxFNagMT8lzis8qM=;
        b=I2dCkC366TrP55JXyz8wY8RVMI2PxrVuQbo9mnRjutCeFzV35408FVgwkjtzTP4EaY
         zy+1ONpQIxHJxm8NtwA1hHAyr54zIHyzp9HNLk0BAAjXsU6/hODg5YJnpQMX2YwKO7KC
         glwJvZNYbte/7Z8UvbhTmb0q8tcV94STT0S+9SLS/1qZJSam7/VOGKrP3VX7mbQWGLaq
         fwZqjsJJNz8LhkRGPzRvoIxeOLOvNeOd636DXLDp3/AwBHrfC4YUC0/jJ9kN2iC/p2ZO
         RujKmX3W1sUHdMdXEEvbl0Ho9bZPgKLhxIEGm5RnGLTqc+q+Ov1FrgAYsNV14VFOmOMu
         06jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753252372; x=1753857172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gVhT7EIfUVw/tmOKPtavh3fI5ZsdxFNagMT8lzis8qM=;
        b=EDGupx9T23ZzETyMRtmWJf33bPPsg6XJBOxs+rIhEfBhsM+KpNsyweFQae+sRqVd0z
         I1AO19ViCa+Ys63GmVP68p7NVbGiYN6qI0OjwcbxLYexdIlYcDmD8w6FHBmbLnQ8oAxO
         TFoANZiOgyvg0kEY0JpgOjA7onn9V+CQQnTvOxwug4Zu2Oo/4I3DAtt3DQ1TUi5FXlM5
         WwFqELHjri+VrwhjUux2fkoMkJpiVEnGOWLsxbl5VY8NpTSkWJQ+R09sLb2HGdG+e5I+
         EcIsCCKyImNqz/9ZXA5qXeIYRN5NllOHfY1ITcZLw5HtNbRvXmBu2CcIlPUw8pDoUKw5
         dpKw==
X-Forwarded-Encrypted: i=2; AJvYcCW8C7yhFHudF7UOdcrKA8UKKEV+RMODg3auwIm4HEfn2vEGqIBEWJ7WZ4f4EzReECVDpKypIg==@lfdr.de
X-Gm-Message-State: AOJu0YwzgXcNP2jvDJb0xc7Ri4FSHpnvdc4311qCwu13Rqkheb8dCtho
	oO0+qAEJ6ltjKn94UZiWNQ1I4tLA4GzvhDtrPrW6ZB24I3e6xC+YGf/p
X-Google-Smtp-Source: AGHT+IFeRW1pfNQJnXFMeUfvDEMmDqtkYlEBqQ0sCtazaCCSQhYqEpTMgLg0kiIvUPSL99HxMQhGsQ==
X-Received: by 2002:a05:6820:208e:b0:615:83d3:7269 with SMTP id 006d021491bc7-6187d8c30d2mr1179712eaf.8.1753252371717;
        Tue, 22 Jul 2025 23:32:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd5TFVfyOK3HLMiU5bXoQ2ybO+Bw4iA00dgqmUv1xIpLQ==
Received: by 2002:a05:6820:6786:b0:611:8f05:9296 with SMTP id
 006d021491bc7-615ac710e5fls2028888eaf.2.-pod-prod-03-us; Tue, 22 Jul 2025
 23:32:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeWEUDvJaGd3Bc4iayhaYf9vxlAdMDnx2wX0rZrs3Svknglay1Xb2Zdt7wlIb2w+6PCWD8xDwj8LY=@googlegroups.com
X-Received: by 2002:a05:6830:43a4:b0:73e:9ee1:3d49 with SMTP id 46e09a7af769-74088987328mr1261527a34.19.1753252370934;
        Tue, 22 Jul 2025 23:32:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753252370; cv=none;
        d=google.com; s=arc-20240605;
        b=BhHnC+6v7PQ+MBYOgWw2plArxXTh+kVnKgdeZejh9DHbZL80UvkRJBoQOV4EDBGZNx
         25537Gwln18eB7BaDkvDGcfj7TrCXmtiB12KXjVWAWyesO/5AhMn0RHdyzOOidDJYJqI
         SMePfJulFF6xEslAcV9cgIdoj9CJln5FmOAaIFaxLVevwbd80mLOnp1Vi6ah2aGdUA+X
         0RZZs6GtGXSwff31fi7pY0+met3pA3qCbLyFQ/WYmmKQnqucOnj3rQD23yDfYL8BnOuM
         /njQZwvZBhxXDWGnrEfoNgS3ZVPno4Tjy01Ts/HRofA7tiK+s1fLs/+lVRvId429KlQq
         nb8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wF+NlFQlfE9P//LH37cgymDuX2rWkQJvOt5FtUPktlY=;
        fh=Q/7XzEIiWXMLSwtasVwLMKP4PNs+RGlGnOziqwq55ps=;
        b=efMI663mSeJDRUqnp4pff12uLA0E73y4WwZ/erfh4QlaC4HPrH6AQGZPXpU6KtHLQ2
         8KiysEeURsBCM3mLFK6ROOueNEZ/X9MCXV5L/ex7OZtZ26swFfaKqM4FVYoEjHWR4RKB
         3XCKETPL4AHv+RuaRHZdtXnHHixePofGdCEHBpHRMqdlZzIKJtUI9MHR90v1k1TbKpI2
         5hn73R+6/ejVtRdcRwNi944yBkroAswBxufhvEwYPbVLkJm72/XGp211RIg/hbFSFFjQ
         GML53WLjOExoP4+epDkllMmJngK1kQZXUyF1P/3qtOGRTLk/38LVUS1sihzW7Z8K2VwJ
         wgDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oddFdHxW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73e8355706csi692239a34.1.2025.07.22.23.32.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jul 2025 23:32:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-70707651960so731426d6.3
        for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 23:32:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVX0S4JJMm2oifyHDRfmkqY5P6LPlqSsEb8o5UHMmaa2DeIvIotjuM1efGGugil0XLzsMyKiFa0r9Q=@googlegroups.com
X-Gm-Gg: ASbGncvVjDaRJ6nwggOC3SKdEDKHkupfhTSMtilDqj85bjG1TmGAnvmYDzAJBqTnWtD
	GA84fDnK3xmttqXdrC0nJfOTChCb+IhUaQTdT8j1R415gS7ejpVr0QrOxTWx8l2AFW701sZj9CG
	JjSwcFQJL9B1BhpAqFqDXEP7rSU0+GzLElJo8zUas0gf29vbo+B5v1V7BPZQaDDjXFN3oCXuA9g
	loh4Ix6QBZ00C117qCHewYs2qaQpy1JCtED1A==
X-Received: by 2002:a05:6214:f6f:b0:6ff:b41b:b5bb with SMTP id
 6a1803df08f44-707006ca3aemr26052026d6.26.1753252369878; Tue, 22 Jul 2025
 23:32:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250722183839.151809-1-elver@google.com>
In-Reply-To: <20250722183839.151809-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Jul 2025 08:32:13 +0200
X-Gm-Features: Ac12FXyBlr57qCpyR0lUbajVEyB390gj3dwP42_EXhGqHDRidQO7_1t2ga4NKco
Message-ID: <CAG_fn=V7K2fSOD951uNuk0sAExUxrHRg6hOnpt1Eg=sb8Jo--Q@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: Initialize dummy variable
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oddFdHxW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
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

On Tue, Jul 22, 2025 at 8:39=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> Newer compiler versions rightfully point out:
>
>  kernel/kcsan/kcsan_test.c:591:41: error: variable 'dummy' is
>  uninitialized when passed as a const pointer argument here
>  [-Werror,-Wuninitialized-const-pointer]
>    591 |         KCSAN_EXPECT_READ_BARRIER(atomic_read(&dummy), false);
>        |                                                ^~~~~
>  1 error generated.
>
> Although this particular test does not care about the value stored in
> the dummy atomic variable, let's silence the warning.
>
> Link: https://lkml.kernel.org/r/CA+G9fYu8JY=3Dk-r0hnBRSkQQrFJ1Bz+ShdXNwC1=
TNeMt0eXaxeA@mail.gmail.com
> Fixes: 8bc32b348178 ("kcsan: test: Add test cases for memory barrier inst=
rumentation")
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DV7K2fSOD951uNuk0sAExUxrHRg6hOnpt1Eg%3Dsb8Jo--Q%40mail.gmail.com.

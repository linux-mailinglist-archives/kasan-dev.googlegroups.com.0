Return-Path: <kasan-dev+bncBCCZL45QXABBBPG3YC4AMGQETBTJBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E9CE9A14B0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 23:18:54 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-6e36cfed818sf5788877b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 14:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729113533; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZE9PjGuM3/3lPr+bxda777n38JxLPd8vLK36LAtImFKwHr6MNkoeAudx/q1xUYnC6a
         Fxbfk8RXSYTxKMDiQN9t0Nv4s6p6Pkvey8IWCFyPW5qMdon7D1/eprRIP/zKdO3CrHtx
         GVn1oJezPpPAgrK9h0lymn/AcKumQWp4Y8/8X/i2uS3HqkUmAA6ojnlCLotwHDln6/VC
         eq8qJqz6VsCnSU1uAGFRlsez8kW6e/Q3eb1HFbmen9aucX28c4byoOwP6ucHgqlEdqa9
         DAz4RR9cgcoF0szpW66/qGtOWtPRvFnwUhv2BJ5DyFBrUAkvnWHYcagHNw61swTKQWHA
         481g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=wAp/NlnIxM1fXzo1P/ld+dpEfwLqbFpKTInzl/1cTjQ=;
        fh=wMRl9tivbxJjmjctrWHiHTVtRzAaQufh1uBOb0DVwkM=;
        b=aVeQdaYqc6HQj0ySF0eLaNyxDR0JzuTVR6ZIrsGw+HqM0ArVDb6Hr5dZ7yhK63kOFX
         pBoztRg4DkykKAxR7vUppqv/DciPsg1MUOR8f6AwU9dW+UQOCdoW2rE2DMifVL27LU4z
         FDJOeVHbP8hLA44b4MSzWYaaQumLPnpRGkgCnNp/OAZ2KMRorhcB3ZUdQQDH0+eIANE8
         ZfQciRbGCGj1ydlbmB8IKlE1AmnG9wKQy3a7T74cSTIgtuA7ftV3f/dmwVYkHiXjy2yi
         9Wxfm6j7voEE3CG048lR2Xh3xmcEIHvu93cECOiTvAxVMwse+Hv7hTWA5HiKsVP69g4g
         7u2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=ch89uXXr;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729113533; x=1729718333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wAp/NlnIxM1fXzo1P/ld+dpEfwLqbFpKTInzl/1cTjQ=;
        b=Sk+AJ06ciXZPT9Fs67Sj8Co/0UB7/lUA1iYKhMdDEstReEwWuDnC3IP5c59Dt/Edch
         d3PFt+yZyP5jc/YZWEq00iYAWRtIEm1H9MtEUDmdBMvQHSfu18Ay0dSU3C8uWqntGl56
         TrsI4A49dnsubWha5kGGlJJ1gFRuYqfWwlDkhF+dO50V4xQ3r0GYDsjFtmoP8Yi0+GCr
         3u+BBrQDJB/rEojHfMzWagQbYBC+r1ldC6cbFAFRMq61rnQI9F8i3hbrJ+dba2Mvlad1
         QTfBeh87Jue60gNv4+dUucy0IocZ5kmqumqAboeyhnVSgmrgW++54uxATPXHrYO0JKND
         vULg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729113533; x=1729718333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wAp/NlnIxM1fXzo1P/ld+dpEfwLqbFpKTInzl/1cTjQ=;
        b=syM/wl321sSyn5R9+fTM0V5uwyUa4pwc3zueIlGpYKqz0oNiAhr3D3UtQ08JzKjAfG
         BVJdYSgw9R0NckzOZNTM67RTGS+Xs0VdvSiLo7HFMxFkCeu/+VEhfva79BWjFCw/YQkq
         F6WXIYZXbgyLwqh7YSzHDeNsqyZVsKagR+xQI7jyYtMVVq5v94LVbOnCguy+Uz/iWRsx
         8EZVA/q3IDVFZRHfaJ5mQZaz63fX8mVd85iJ/6sjR3g4oFD5s7jdDV1uOTOM05vqx8oN
         qBjRS3yfqcapGlccTt7TCGnJgE3Cw5DnciWTG9Ntbn4ryf/Gk5dvolRh4QLcnxmr+pIy
         s6Pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVI9buYKarxTGBed1Jm/5csrhZ57MEwEGMO7Rca8M/WWBb2wics876GGtQ/WJqir/8wltwdjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxCycT/TavFH2UcegozHvtiJcdngYLInVH4mx5s3CafIMmCuY22
	H6r2lINoqYsacP3tu5oPE7KoQRZrfhZds2rYS47xKuHheZpu7dfB
X-Google-Smtp-Source: AGHT+IEmCuJl6W5sKji57TIfQVw0xvX11RnZ0tBWgGm0DPfjZNauVGB9rv7Pej4FN1u/BarHT1DeNw==
X-Received: by 2002:a05:6902:1688:b0:e29:93c:5188 with SMTP id 3f1490d57ef6-e2931b1554emr12788562276.4.1729113532938;
        Wed, 16 Oct 2024 14:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:120b:b0:e29:19d5:b575 with SMTP id
 3f1490d57ef6-e2b9cdf6d92ls349535276.1.-pod-prod-06-us; Wed, 16 Oct 2024
 14:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwzEOor0NgYtHtL3c/hy0NNJq05Qz5GvsdTlruIDdCH1lQebKKM2/FHicbumz01+8jG29+GutjrtA=@googlegroups.com
X-Received: by 2002:a05:6902:2e0d:b0:e28:f2b3:1a3d with SMTP id 3f1490d57ef6-e2931b15419mr12985591276.6.1729113532217;
        Wed, 16 Oct 2024 14:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729113532; cv=none;
        d=google.com; s=arc-20240605;
        b=Ccu/6AuaCERGG2mIs+VPtKcCBuMJI7BoQ9PU9Dr/G+DSbA4459+MpjEYMOGSBFDi7D
         dw+LgT1aTKCDOzvdBQbhjPe5Tzc/2KVeezPKLFZivji4WJNyUOPWRftt9cpdgZ04DlrN
         X9R8CK6oGkbfg1oNy/dAcm8r2nJAB3Y7R4C8Q8QVNqFBSXCyRM4w29IyYKO0vfkfjXoo
         jTDanv5PcKchTPgJKzm6gXAh/w2HP6wGdoqxHVMuDs7gnav+BqE5iP4mMV15TcBaB4L7
         7j6z+0WmH8qB6HjHnZjCtYXyZmyhiG8uScluv4+t4jeFwtwRXjAA7n8gd2j95TfUmXYK
         QT5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7LQRC3L4VImH7cjZINRKtu/5qiGqUUYdnzfIGcfIZ6Y=;
        fh=JOVPEQPKqBfTpf9DJNa09HTOq2swOIPVBwB33u3oNjk=;
        b=X8K75r40WNuKuC1dfFw5DyrQMm/8UTyD5BhcXDhMRAMdM3IgcSuRGIffngJOvGfsFw
         aW0/3mi+P2+mD+NIKbHVQaTvTOXJyXpaHeUHEJx67n0d9oXOy31JWhhlccYwBUUi/WAP
         MqmdK5JgnWKj8ksZZS6QDWb77/SAuI1lfsd11KDGU8mfjHETFzat44+ueMxydyftMbgo
         laZRqu+kVlLI8cYCoecsBGNYJPtAcbcjgBfxgPVdCg9g/wfwrcCJVPMRhsxkxwO+mjj9
         wX+X5yk9XBg8by7+FwkecUfNkBGf+Cqkms1TH6ZoCLPWf5nmjyEwnUT5FGnlW3ATA4Hl
         OX4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=ch89uXXr;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e296d0744ffsi266100276.2.2024.10.16.14.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 14:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id e9e14a558f8ab-3a394418442so1260435ab.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 14:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW37lD2Zw882+RsQZNEv91Nira487jAnd+tNY0imhzRjScBUC/7V6hPFPgObXOn2j20XWJRHDsSvpk=@googlegroups.com
X-Received: by 2002:a05:6e02:1caa:b0:3a0:bc39:2d8c with SMTP id e9e14a558f8ab-3a3bce0fc22mr139127825ab.25.1729113531546;
        Wed, 16 Oct 2024 14:18:51 -0700 (PDT)
Received: from [192.168.1.128] ([38.175.170.29])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3a3d70aec8csm10271275ab.21.2024.10.16.14.18.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 14:18:50 -0700 (PDT)
Message-ID: <fbd102fc-32ef-432c-9ac0-c5581f632301@linuxfoundation.org>
Date: Wed, 16 Oct 2024 15:18:49 -0600
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] docs/dev-tools: fix a typo
To: Jonathan Corbet <corbet@lwn.net>, Dan Carpenter
 <dan.carpenter@linaro.org>, Marco Elver <elver@google.com>
Cc: Dongliang Mu <mudongliangabcd@gmail.com>,
 Haoyang Liu <tttturtleruss@hust.edu.cn>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, Shuah Khan <skhan@linuxfoundation.org>
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
 <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
 <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com>
 <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
 <87msj45ccm.fsf@trenco.lwn.net>
Content-Language: en-US
From: Shuah Khan <skhan@linuxfoundation.org>
In-Reply-To: <87msj45ccm.fsf@trenco.lwn.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=ch89uXXr;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
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

On 10/16/24 08:52, Jonathan Corbet wrote:
> Dan Carpenter <dan.carpenter@linaro.org> writes:
>=20
>> On Tue, Oct 15, 2024 at 04:32:27PM +0200, 'Marco Elver' via HUST OS Kern=
el Contribution wrote:
>>> On Tue, 15 Oct 2024 at 16:11, Dongliang Mu <mudongliangabcd@gmail.com> =
wrote:
>>>>
>>>> On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@hu=
st.edu.cn> wrote:
>>>>>
>>>>> fix a typo in dev-tools/kmsan.rst
>>>>>
>>>>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>>>>> ---
>>>>>   Documentation/dev-tools/kmsan.rst | 2 +-
>>>>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>>>>
>>>>> diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-to=
ols/kmsan.rst
>>>>> index 6a48d96c5c85..0dc668b183f6 100644
>>>>> --- a/Documentation/dev-tools/kmsan.rst
>>>>> +++ b/Documentation/dev-tools/kmsan.rst
>>>>> @@ -133,7 +133,7 @@ KMSAN shadow memory
>>>>>   -------------------
>>>>>
>>>>>   KMSAN associates a metadata byte (also called shadow byte) with eve=
ry byte of
>>>>> -kernel memory. A bit in the shadow byte is set iff the corresponding=
 bit of the
>>>>> +kernel memory. A bit in the shadow byte is set if the corresponding =
bit of the
>>>>
>>>> This is not a typo. iff is if and only if
>>>
>>> +1
>>>
>>> https://en.wikipedia.org/wiki/If_and_only_if
>>>
>>
>> Does "iff" really add anything over regular "if"?  I would have thought =
the
>> "only if" could be assumed in this case.  Or if it's really necessary th=
en we
>> could spell it out.
>=20
> Somebody "fixing" occurrences of "iff" are a regular occurrence; it's an
> attractive nuisance for non-native speakers.  For that reason alone, I'm
> coming to the conclusion that we should just spell it out when that is
> the intended meaning.
>=20

+1 on this. It would be too attractive for new developers.
It helps us not spend cycles on reviewing and applying the patches.

thanks,
-- Shuah

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fbd102fc-32ef-432c-9ac0-c5581f632301%40linuxfoundation.org.

Return-Path: <kasan-dev+bncBCMIZB7QWENRB77X6O5QMGQEDWFELDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 11532A03BBC
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2025 11:03:45 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-385d51ba2f5sf6473646f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2025 02:03:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736244224; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jim3c9DKtVHB3smy192nJ2gEMIYmsrRTlacoFAHMiSmrr6E+5YC+R3RpknozHTITzF
         BvxC2/NW1mgS3PWYg1TQoqALHv4Pp9eH5pkaxnQtEOwqwY6xl9Z++pZlorkpMQ57LUto
         2P423f0eGnmYeqC0U0O+hpGxCyoBXAg1/Fm1TpOWVji5E3Ihhs6w2A/1AUxKmfrcTwxo
         p9QAtTrPVIRCwicdEFcbllnQPyGJ180qmfiY7NMFnRHJ7wDabcuHWWTsgiKg2e97ddRQ
         SlM0+Bgt61dFmqERi2dUqWfAjOpeLLdfm1K44d6xgQTQdPdTNygm2Pz+507z12DicCxh
         az9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=ujuTYx8Xet1K+kIWea4nIO7h3ECu87k2iu21nTdl7IM=;
        fh=ZMx3efCXW1XA2ASF/TchuxBJxUj2TYQR7z+//XvAXo4=;
        b=B5BGmuKHBWjOi0WwBpvcwF2VzJjsEvUHx3VqIZ2NyToERD0p8v4DuLwXAMI2QBDeTK
         eI8WPo3LcgdgUVjLf28REx2ebQEuYBtUGwNGqARO59o3qjQRFbqDzpNhqhwc5Rh2ZZ6m
         25qxP0SU1TB9lIZGjigYZJeuGWXtOM4nHwhBAkNw+Bbp4yaf0jhWeDPj7apn1+izXZgk
         i8Z5mg6AKaqvtaKKTSWm7c3aH87JSevxEM08Sa8VsntIQZPbNmqRnHh9WVLbnuAhUqF6
         3WfO4ki+4DqJBQAoP0NRxpuBUvE0RWM0E8Xoc2I0YP0Nj8jmsIb4WprlLDQTt6De6LOx
         ArmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Pkdqx5JP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736244224; x=1736849024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ujuTYx8Xet1K+kIWea4nIO7h3ECu87k2iu21nTdl7IM=;
        b=V2N3XtfLFJDRgny2h+C0WfPMe/At9xw/l7d2OJnUJJ4YNnd306W7epKYYf7nuh36Yj
         gPqo4Vv9CdH6R5ihfGX9rK8ILRfL7VA9S/sefASHFtPfnxNJ8d8lIHpWg09AJjH2r+un
         KODfGfW71W1uARhwfC+Oqg1xzfXw1aSLjy7lBcLItd/UTddvtqI9joyeuz90Yru0HB00
         n6354aQIY0ZyvQ0F0aVqV7A1SfI4+OCjvIi4v3NOzoqE6PbWbwPR7xNcUAFB8Nf0UvSi
         46UMsLO9MMucc+1tStRdAm1t8leaZy7kFceC6syxuURbyiTVF7wlrerzKCOTJ82dqcTN
         DFFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736244224; x=1736849024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ujuTYx8Xet1K+kIWea4nIO7h3ECu87k2iu21nTdl7IM=;
        b=AUVj4lJo8GDvxcXI+aQk471w1stiMzxcprBuhmmx4siF5dKB1grspyS3ZhFUlbhXh4
         0VMYkgWxEpKOqRptnlaT9l7eKbxIpczIofB0aCcGqDFIka2F8Tjm93mMJUC35cIV06bN
         aSu8DjOgU6vmC/9VZSXN63GEp8rnabkgZZXaDely3b26AsQaMP1mWgbu03f3lDjvAz+A
         4LB8W+VA34FKkpINGrt4oofAupchXcuL3YBWFH9i1Fk5NbOMQYntGXw8XiNbvUbjNEwl
         q9vbg6fQyh9a5lXo3umjPtFNbEngtCDydKCQPmcEiAwdXJNRyfBqUsWqBLFXSU1wkn78
         67Wg==
X-Forwarded-Encrypted: i=2; AJvYcCWE6G7YYwA5CHG1p+Hby8s4WxM3GSmRgxkfRtp243WZSVoJaGIHlWNgXEl4rD7zK4qChIV5QA==@lfdr.de
X-Gm-Message-State: AOJu0YydpGc32NpsTTCyedZ64uRyFz5C+IpjmpOZDCC+igZ9LJIeoDKl
	3A8Yh+8OT9rtj4w5qqOEPTnBSU9Uc90pMn+xY04SKeIT4EmfDFeA
X-Google-Smtp-Source: AGHT+IHEGrmt1vkaKNxCbcnungUa/gIqie3ntjb3DAJVoyMIfCgvsFpCg0+Nf4tc2L4x1xtOheZ4ow==
X-Received: by 2002:a05:6000:156f:b0:385:e17a:ce61 with SMTP id ffacd0b85a97d-38a22405b5cmr57353342f8f.53.1736244223672;
        Tue, 07 Jan 2025 02:03:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:618d:0:b0:385:ddb5:8cb7 with SMTP id ffacd0b85a97d-38a19fa5d8bls1493027f8f.2.-pod-prod-01-eu;
 Tue, 07 Jan 2025 02:03:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7lyY1u6OEziQRHRwDQWAYtvUb5Yh4V3cfs6JTq3/JGDqzca7bdfy1B+v+FTPBTK5f8bGy2KyEp9o=@googlegroups.com
X-Received: by 2002:a05:6000:70a:b0:385:e0d6:fb48 with SMTP id ffacd0b85a97d-38a221f109amr51722557f8f.7.1736244221551;
        Tue, 07 Jan 2025 02:03:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736244221; cv=none;
        d=google.com; s=arc-20240605;
        b=BTh6RATAu50HD/+gAdNAQ/ylGi75FWjZNy8AaS2vdQuQ9voOf61ZvGQ4jff1sFQDXk
         CT1FqhLby9PvEWpdpx6zgUTXvcrx2KSiU9nCIeVirJz0TheAkgp+grgRlvSCCiMKgZEC
         e/8+QwNKMfYNaI2qduJ3TfRWXuu+7Hu2smvmfWtrjXJX8jtHxdxmBN8BW7VUvURhJqBD
         ox0SoQwXQms0reLODi1wD61YTeI4+GFN6kSFmt3Y2K7VNatpNcCkGIHE1SfrHoF4vP1/
         KNtLgXzgXX5f4H7hDPugH0Eo9N/kuMYhwz3EKtXgHDxv3Yu2PBrRNW7dwSEbvWme83+j
         BdyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=inhXiiGEDT/3x2+luv/iekRdJ801RxW7QAqWzuoaYDk=;
        fh=Cgj2HdxbFId9kTngQawyLRd4oRr/eiJMmshUCem4co8=;
        b=W9relGOHQZP3GJ+Ajj6h9l2puF3viWBvEkU5YRQ79E8pf0DjH4V/V/xLCjJm7vwD3a
         8ejOiDfjLRiZHC9vLYlKT3CDwR7MrwYVnOgr/MLzNZHVnb2A/8w3GD4Fb6e5BiHkG4N9
         Bc0BC23e8lJelH1anqeE3uHIGGLYey1rfQl/pKYkd8lSDtW5xVsluD6RDvcGQ1w0nUdX
         eWWGAfR2h9McGcbPAO3dVurnWTwoEZd8h2uZfqXcaEccESy5TSANcgn0CbEV/AKOIdCK
         ysCIXdfPfEj+8CFh7zuuB1gCUVbjvGmcTiBnbsSAs1TtU/Pa8PhPJIK20e5WGfXwtArD
         vYVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Pkdqx5JP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38a1c898224si1148538f8f.7.2025.01.07.02.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Jan 2025 02:03:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-3022484d4e4so185623641fa.1
        for <kasan-dev@googlegroups.com>; Tue, 07 Jan 2025 02:03:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWJFRSVKKqIVfFfBQaa+Dw6Uc14fW6cviOiC67oPSbfMJT4Rd1/R2HmvSxiUdrpIbGjPqFKbKHvoOQ=@googlegroups.com
X-Gm-Gg: ASbGncvz9qMf8ZvYdH6Hcmv2M3f5RHfhlDc4gQwDQdtisDgsaDCIm0N8E8KQFE3z/il
	KopjN65YSm2VIBH308ue3FQf7hT6j0j1us+nkmQ0OypA5EE7NbtRSnlZMBNeD30ew88N+qmQ=
X-Received: by 2002:a2e:be1f:0:b0:302:2bd8:2662 with SMTP id
 38308e7fff4ca-304685f5977mr184335411fa.27.1736244220635; Tue, 07 Jan 2025
 02:03:40 -0800 (PST)
MIME-Version: 1.0
References: <CAMF5BpuWmXS9gEU_0==z2YndnZsSms7DSBpG7kcqChLH7R-B=w@mail.gmail.com>
In-Reply-To: <CAMF5BpuWmXS9gEU_0==z2YndnZsSms7DSBpG7kcqChLH7R-B=w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Jan 2025 11:03:28 +0100
X-Gm-Features: AbW1kvZtPbFLdgq7lwE3OjhDMEAgS3eH2KskB9kevvLk8m7kE7acDVyIIRUpwfs
Message-ID: <CACT4Y+Zfg_JpkiWRTkU-30uVU0tFbF+q_Wdwr__CTqsTZ2G0WA@mail.gmail.com>
Subject: Re: Update on the KASAN stack filter patch
To: Nihar Chaithanya <niharchaithanya@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Pkdqx5JP;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

+kasan-dev

Hi Nihar,

This may be easier to do in user-space. Why do you need/want to do
this in the kernel?

On Thu, 19 Dec 2024 at 17:47, Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> Hello sir,
>
> Hope you are doing well, sorry, I couldn't contribute much
> in the past month.
>
> I created a function to filter out the frames, taking inspiration
> from KFENCE, as Marco Elver suggested, but I'm still unsure
> about the method I have used.
>
> I wanted to run it by you to check if it's a valid way or if I should
> retry.
>
> Here are the changes sir :
> https://github.com/niharcy/linux/commit/017e0709f5ee4d12af42e1b647c5559aa36a7408
>
> Thank you,
> Nihar

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZfg_JpkiWRTkU-30uVU0tFbF%2Bq_Wdwr__CTqsTZ2G0WA%40mail.gmail.com.

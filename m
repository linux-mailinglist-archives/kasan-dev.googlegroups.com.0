Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVWA567AMGQEXJKNOVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4050DA6A2A4
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 10:31:05 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3d43541a706sf4991565ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 02:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742463063; cv=pass;
        d=google.com; s=arc-20240605;
        b=dtDi9b/fPg2qypzzxL83z54AzY2j/IZhbPwvvGf5nTgEhyS/3/DrSeG4IlW2eM3CEN
         hwHC8VGf0SFuU+RqAsRHDD/tuBd1g0sEePsvZZ8mdX6rUT/FneAqGUu0h+HX40iWD7/C
         Q+4PM8Ar+KdvtXtW3vOP4KOKGMLQom43y9G7i+p9AH6SMvx2xM72p4EGHPG/shDxovjT
         gbpSJ0724h/UPx1TDP5/4vTGCZK0fPXazwtDim/EnR15faK4ml/k02ZGYgFh3t9jQo2S
         aaEsKiCJnD5HmR1fAA/TG9gEZhjhaMMPNoC7QQPaeu2LQBs8J+TonxwNCK+vej12R86t
         bDvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LqyuGsFygkwgpGrmWnUcfWdNuXYglzZs9PDSWUSQni4=;
        fh=kRAlozxO/o3pxvAKhQ2+EIkOfTusB9rYHfYxN/vhrfA=;
        b=TxU+3q9Ejxp7V7sLi1e/TrJ7hy+017OBcAovWbjUrsbZRSALcorDK9LBSYf4u0jsd2
         BfV155srjU2dfTXFIKD9A/fHIc+tcfql0WR5QA1eU6vCjz2f04S2u97WK0V6NTECl7P/
         brda0Q/LxVQsJ+Kh3EMVZi42I0BKY2EtEHnZVxst/LBADVQ9PWKr2pCUkO2+u5CXx0LA
         9Xc/Hlaci599L53T1pPrcAtE9yQmoWG2KfEagWgURXXYDnudpJ5CHCG8MEUUwqAadGWK
         D82l+jVuDHlajxg8JcQccx+Bms/XYO1+rzplBY2B3WepoTnVWvcgdUvYU7S8sywRHzBa
         XKBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OpCg463g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742463063; x=1743067863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LqyuGsFygkwgpGrmWnUcfWdNuXYglzZs9PDSWUSQni4=;
        b=xi0C46Oa2UZ7KF4bevQH9ZitVDiroJnODWfJSlmWHLexlVA5STw17ThVsa5ZmavcXS
         HNv/+3rt5LBbSfZgVOf3e+RUHATjRzgY7EqVcDhHj9r/KFuX95phUeu8jNZ94JgSF5Q8
         hzQsyfumG/kEpOaCMClhf9sO9EirMAL8n2kNgrXx06ChA6Z+b+CNkjRywkgGh0I1fug0
         7FiUm1GwV03BJdT84Zjbbz7/bn94pMMORAfP4MXsCDloGMcMb9eUwU0V/Gyl8U4meChe
         k+W8Z0A4UhNMH0p7vGWmH8cBz0Ls80IeFmwx/oB5WRFVwBYsvak+RhjVQCxn6Fw9h7SG
         hWOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742463063; x=1743067863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LqyuGsFygkwgpGrmWnUcfWdNuXYglzZs9PDSWUSQni4=;
        b=YtFi/83PACYl6jTgyb65mrQOyQNxbVAx3Zu7coL52qyOgEV0VUcZd4feQ+g43igS4k
         129fiaGBH1ClYPVRbHk8ovNwXwVmJDjYnSkEQG3+JZWw1T5EMqnNfnBjrPq+crdojLsO
         ISJihEx4A3P99KdPvVYBxPRU70ll43Z78kQMMd2r0GcZPu6Ksbhza5BJZDEFhuKOTreO
         uHt4Bh/wpdK/sRuv5bKJPLeV/hMIPqMEy+Da22klxwFuHs7SG96f0m+/Q77H/ddkFC5a
         diWdi6QWcQYzYQXVnVDY2oXh8ULO0oEoo9n2QiPDoTdzVnK1N+eJdqjd1ElHE8uNtyfi
         mxtQ==
X-Forwarded-Encrypted: i=2; AJvYcCXBFtHb3DfDT3YLpZMM9SAJ/bMxbcJ9wG0titrUcJzNXPD9U4fCzOm8gle8uhICZxZuQmENSw==@lfdr.de
X-Gm-Message-State: AOJu0YyzT4lU49KGqaFk0UQhklo6+G/rWn4p76OYmELTpCo82cZiFOvc
	BO3+jTEttnZG45g800kVjEgVynIqk0EgTp4EPkJoIXuGcS1+yRRQ
X-Google-Smtp-Source: AGHT+IEqCKgVkWVfQILsYhgNJ9z7JW8H2kpml6yDoa8RArh9kZ9MJ+wygnkUvwnxfTa4KxPc19OnBA==
X-Received: by 2002:a05:6e02:6:b0:3d4:2362:98d8 with SMTP id e9e14a558f8ab-3d58ebae396mr27958805ab.2.1742463062787;
        Thu, 20 Mar 2025 02:31:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALp31PVkZB80BKbomaBP/62gQG8YY3NoOh3BtvKCMTYQw==
Received: by 2002:a05:6e02:2603:b0:3cf:c8b9:882f with SMTP id
 e9e14a558f8ab-3d58ea82e37ls531255ab.1.-pod-prod-09-us; Thu, 20 Mar 2025
 02:31:00 -0700 (PDT)
X-Received: by 2002:a05:6602:370a:b0:85d:aba6:4f4b with SMTP id ca18e2360f4ac-85e1f4af4acmr311971139f.2.1742463060714;
        Thu, 20 Mar 2025 02:31:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742463060; cv=none;
        d=google.com; s=arc-20240605;
        b=Rideh1nrzcIRs2QFbW5qZecZznTZoNeUvILy4NZMf1my9TJ8Nr5kDlvnOGC+BoEz83
         Nl2qJ8aHGst9Ae3vZvNqmRxAFsnp5K1purYhij8GkAK7/JhAWudpQaaRDw1nwtoV3+Id
         1Qu9de5IO7lo95sqvEzEmEbnMBnHSupngK4RKSuLS6oIRZ8o3l/JQn9fSl3bSO42cgiz
         jqDcv4zUV6A2d8Y0Cl9lqurN9aVReiZwM+r/e7mhoyoUgwcjQtoiORqLj4bVpMWDAS3T
         eifZmGxIhzKbUcTLmQlR3qOy3KB5vS1KvYpLN1Uj2N+GWozDsbvzIZiOohqezmcyn0rE
         Qm6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=L5UHDlZwqtgy2Qf0PGUSBvmXQeLf9FBEdte0Ru5Njow=;
        fh=horjWBdtrzwyyok/mxJGo2OZWv10SWIkZT/kodHu8Wk=;
        b=XEA9ONSNAXDy3KPWH0KjvROOltSf4NSe1SsgjpmXIch/8SSk6aArFHdl5csRUtyH+H
         nm42rM7zSuoSBI2gWW6DRIXZu2I2zOScKzXvQ/R2YHQSz/kFXhT03wxu9X6GNDy3fP2a
         g7QwHZYzRMXivS/i5S1eIAcRb+5AWvsvh256Xh5HMiYPkz3Plylysa9rfasVdkwhH97h
         HMAudOassaYomkgJAqZ4zNs/9fc026FGF/AeWEpzO7fJYNRZJtKx/q9aC8I2fWbZgdEy
         h2M6RTSZ1fjgvP3oNnMB50RXb+NWxjIQkioAWiPwRK/xbmWCkuAmIUL5SOdCGJUTxgXD
         79wQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OpCg463g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-85db8759e52si68020439f.1.2025.03.20.02.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Mar 2025 02:31:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6e89a2501a0so5263786d6.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Mar 2025 02:31:00 -0700 (PDT)
X-Gm-Gg: ASbGncsZCVNp5nE+BZIW+O4e1GDcmvznN28HuZLDqKrs3jnZ6NDVZWCgRCLDMBbYaS5
	GvEbGa4JS+JaeKEDbWQqn9jdtz60kFCi/aBgjls0XEpGuUQ4bqSzZyNCfRfMzSqmEd9ULFq8JQ8
	5Ae++JAl4dOfJOGrTvApuxhbgUZen121YxV2+A2sc0f1kqgtxDUP52elDyWgVSshbeQmQ=
X-Received: by 2002:a05:6214:1949:b0:6e6:646e:a0f8 with SMTP id
 6a1803df08f44-6eb352a60e8mr36141796d6.16.1742463059908; Thu, 20 Mar 2025
 02:30:59 -0700 (PDT)
MIME-Version: 1.0
References: <3f88fc09-ae66-4a1c-9b87-46928b67be20n@googlegroups.com>
In-Reply-To: <3f88fc09-ae66-4a1c-9b87-46928b67be20n@googlegroups.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Mar 2025 10:30:23 +0100
X-Gm-Features: AQ5f1Jq2O9rNNc3GUeKMKY2AWP80zv7oLIunT-_5M5kHnuv5gGudhkeFG_WogBM
Message-ID: <CAG_fn=WtE-+HuR9DSYFEYq2=BkwosWwJ0eUMAQWpGJ9JbhFy9g@mail.gmail.com>
Subject: Re: Enable memory tagging in pixel 8a kernel
To: ye zhenyu <zhenyuy505@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OpCg463g;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
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

On Thu, Mar 20, 2025 at 3:03=E2=80=AFAM ye zhenyu <zhenyuy505@gmail.com> wr=
ote:
>
> Hello everyone, I have a Pixel 8a and would like to enable MTE in the ker=
nel. However, whenever I try to set or get tags using stg/ldg, it always re=
turns 0. Does anyone know why and could you please help me? Thank you very =
much.
> some registers set :
>  TCR_EL1 : 0x051001f2b5593519 : SCTLR_EL1 : 0x02000d38fc74f99d : MAIR_EL1=
 : 0x0000f4040044f0ff : GCR_EL1 : 0x0000000000010000 : hcr_el2 : 0x01000300=
80080001
> (I can not get the scr_el3)
> the page table entry of associate address : 0x6800008a2b9707

It is unclear from your report what exactly you are doing.
Could you please provide the exact steps you perform to build the
kernel and to get the above register values?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWtE-%2BHuR9DSYFEYq2%3DBkwosWwJ0eUMAQWpGJ9JbhFy9g%40mail.gmail.com.

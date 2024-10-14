Return-Path: <kasan-dev+bncBCT4XGV33UIBB5OJW24AMGQEIU2WFIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A8899D9FB
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 01:10:47 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4605b68dc92sf45489701cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 16:10:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728947446; cv=pass;
        d=google.com; s=arc-20240605;
        b=NOye2KP57crgqnijHrmcALhI312GoNP4+YddJC+fM27nI5elO51PiJP4XZTJDPhKWF
         VMjPbNG1jASv+qLd7RedQh7ERmCVEPDyAfqX7OezTgkYQ06VRkKBDZjh0OvsZ0GBmGtb
         7ORLdfyXFe7RnGpM030blqrKRbmVGT1aDJO1K3cvuY6bBq2zxXxOVUzSrYG1K8SvzlcX
         gcd8itbWVJT+kkvNrfAbiwFjLAakWv8gKEo1iOgxLJd31/at4WILQCW58N+qdgQF7p5P
         d4Sm/vn1zvKsBYJxuNQaf4F0SXORCD8SyqDpdWq5IRUxgr85lGrDHbJsfFsKaC4cwF8g
         3ibg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=WZDgNQBN7dz5YFneKcXhCMzUKJH55ellaTyIHhDcPQM=;
        fh=GOMXq5dg0lwFxUyWXzcIh3LD1k5gCE4y9RoM+kY1izc=;
        b=YTyC8G1FYIAcMY3Vv4OVBVkZBOBDxesN8YKKkPln/5uiOyFJ7W7I7x/UbYBPw5zgTN
         3oLbMBGHfW7wdI1LwseFHtJ4Bx6+tWJTKiqeFhW9vopDRfdYBfC7/UVBYEQEOO9k6H0B
         T2oqy8CAXrdb80xHSlI7tBDiuTx5svxmTvLBYE3hUqDrDXHC1ozE2jV1h8lcLB+7xew2
         ufipMdTXQbhJSx7HUKbvMstnXxc+KvnSPEb2SIZyLayDw/mYbh4Jk13c+z8OZ/k9BjG8
         WJwRLX7IlQLYTT8hbhCM7xj0+csW5tBM++5ygqllhwQP//NuRsQZKKsiXVV8VPD5MJ2v
         yqUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=n7Akqvua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728947446; x=1729552246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WZDgNQBN7dz5YFneKcXhCMzUKJH55ellaTyIHhDcPQM=;
        b=qI0Un67LOD83+WAQwLsBLK7smWtZDaKHbDDRMyhWzK0sTRuNMSW3rkDcNRq0hTeXML
         Bt1cOubKPvhe2FnppnYTzpodgLc0BBpMvBS61FmXsPfHUhfTCNyPJgZT8/UgJzmqien5
         3H2IzD4IiM2IJryeVdwBjK6PhTLaT02XppusTnjJbtGMdw2WAdqBtGQOokh7dbBajZXQ
         6sITMx9dErikbQDh43/ocvM5v/HSTrGYTyRwVoI0sKnFCwHllar4drdqN3X+XgNbc3v9
         ccaG+Buh7VwckCvnLVQK5/B2vfTrd1YGyY4mEkR9wYdT/ADmN7jOxcdELmmUQaCpG8b4
         oqPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728947446; x=1729552246;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WZDgNQBN7dz5YFneKcXhCMzUKJH55ellaTyIHhDcPQM=;
        b=MA0MNgaYGRIPoolD2KLMGKFUalRK45fFaT4IqdaBWnn2orb13lL7lZmTyv1oKo2nIK
         N7ultzwINb0+DT6wZxuIAdU0hCmovEtZAZbUv6vqBohnnCr4Vap1h1hiExGe0lGwRe86
         mW9zjp9fBLVr5R/FIAGOggSV6qvG1tCMs1w8nA2CYA5hPnCGo5pzC2oria+D7h9j7mkj
         r8NiKCF4XsjfTrCX4A+wWtKoGGTvcNW+GKPsPx9oXCQav6/0wMf45NV0aaZf1t8O/4N7
         E9c4DSMwSNNADerIVyCcHp7OzM1qk9GTHuBn4mV3s4CTmnkdy5i1I8u4ymm8eeqFWTRQ
         YR6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXws4mTOmuBYaZad0ht01OsDMXbknD5M/MsEXEUyFjvdNADeYIFBVbeMpqjx9oCgjL6FeItfg==@lfdr.de
X-Gm-Message-State: AOJu0YyaD0hTlfuDNzZfI+9m55HVvS0/9ycNB1x36b1ZdW6JgStuwUMw
	kox6PTP+PXbt7qLDaC+CJTsWWPZ13amSd1ILB0pMhAnsUhFy1uoC
X-Google-Smtp-Source: AGHT+IHyrgmu5ETGqaMpht8Xn1thsy1A4q9nlCLUkLgmz87EjTAMbDi7ZFH3uZ3NdYQOimq6Lo3rAg==
X-Received: by 2002:a05:622a:293:b0:45f:784:1b5d with SMTP id d75a77b69052e-4604bbc0714mr170660111cf.24.1728947445979;
        Mon, 14 Oct 2024 16:10:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5906:0:b0:460:378f:7f5e with SMTP id d75a77b69052e-4603fdbda4als45806511cf.2.-pod-prod-01-us;
 Mon, 14 Oct 2024 16:10:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVezDG4ZWWMPIHfAYVvqe5/4YRSxb4dMLZY64K085Z6C4vqsdyMMOyOUKgXiwhXTGgcntjk0Kx3ueo=@googlegroups.com
X-Received: by 2002:a05:622a:1a8d:b0:45f:d8e0:a37f with SMTP id d75a77b69052e-4604bbb969fmr154314351cf.22.1728947444987;
        Mon, 14 Oct 2024 16:10:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728947444; cv=none;
        d=google.com; s=arc-20240605;
        b=e9a8u6zcFdzO18JZzxgrXLqNXyGbJIHa4gOPAiR4aObZUbQnzBRYDHNi9lltVb1azu
         5Pf3X2dFF2+07Ql/v+sT7UsKex3Q4ayk82ofgTaxRHUmMhrz86rHJ9Y8Noty/Vf1PCHf
         m5Wk+4z7wBD3jEXkvSzgY63IK7SZBUr3liEdTu3CJtBxGGtsWDq6QjAducjZR6YzMc2q
         A/S1DbwskaykBnE03SoDmk2eBOdL4txnnT79zf/mCyeaXXAAUJ2Ns3mZfxhhc/1nfhQO
         JqCOU+h2bE2/CgKF0xMBA7q1Lp6j7Y62NpVv8xHlnHrLs/JChZvs7o6QbvUDe9yNoQkP
         fv7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+xa2RPMoT7HUtFnoSzG3qhgooWP5aF048ur6xqS3Vhc=;
        fh=QdRlBBSlAQUtT/yIQrT8NxJTZf2XjZ5RZa/FEJ0z7/g=;
        b=FdGu+Pc7M3GMqE2Lqww1E34UR1YTzMrqU680vvyPFBgrDrqpttdO/vOOuxJoGBtDnv
         zch2SRUfpUoOPgoYgwxmy+GLSeQlhL6o20WKBrvf1jJMCIBA0jn0wwQH1XkPVH2bVfUz
         Ctru+i5y+aXrcYyUBF+p7x3ij5T56PY9i8fqxL6XNMJURfouLSL5Yzi0mZZcEsSkRkSH
         6vI9Osx/DJhZ4ok/74A31uiRBXYeTnH4eSTTb6tsMS3ZbkrFeKo1E72X4/3v3HdgSHEN
         29cUA7fFYmTUnJYytzWtG5KpGJBScdRGRfr59R608LQLmCBK/l0wG5B3jRVUxsBxTyV9
         QqcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=n7Akqvua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4607b258575si51531cf.4.2024.10.14.16.10.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 16:10:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7D890A428A5;
	Mon, 14 Oct 2024 23:10:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 983B5C4CEC3;
	Mon, 14 Oct 2024 23:10:43 +0000 (UTC)
Date: Mon, 14 Oct 2024 16:10:42 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: andreyknvl@gmail.com, 2023002089@link.tyut.edu.cn, alexs@kernel.org,
 corbet@lwn.net, dvyukov@google.com, elver@google.com, glider@google.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com,
 siyanteng@loongson.cn, vincenzo.frascino@arm.com, workflows@vger.kernel.org
Subject: Re: [PATCH RESEND v3 2/3] kasan: migrate copy_user_test to kunit
Message-Id: <20241014161042.885cf17fca7850b5bbf2f8e5@linux-foundation.org>
In-Reply-To: <20241014025701.3096253-3-snovitoll@gmail.com>
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
	<20241014025701.3096253-1-snovitoll@gmail.com>
	<20241014025701.3096253-3-snovitoll@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=n7Akqvua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 14 Oct 2024 07:57:00 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:

> Migrate the copy_user_test to the KUnit framework to verify out-of-bound
> detection via KASAN reports in copy_from_user(), copy_to_user() and
> their static functions.
> 
> This is the last migrated test in kasan_test_module.c, therefore delete
> the file.
> 

x86_64 allmodconfig produces:

vmlinux.o: warning: objtool: strncpy_from_user+0x8a: call to __check_object_size() with UACCESS enabled

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014161042.885cf17fca7850b5bbf2f8e5%40linux-foundation.org.

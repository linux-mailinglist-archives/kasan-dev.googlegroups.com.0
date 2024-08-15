Return-Path: <kasan-dev+bncBDTMJ55N44FBBZUD7G2QMGQEIBN72MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A1D49953988
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 19:59:03 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3718a4d3a82sf496466f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 10:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723744743; cv=pass;
        d=google.com; s=arc-20160816;
        b=EOS9Y3xisobWZjZmTA1PM5AOfpMwsQBaRuFZIkbJR4xLamKJ/RmfsGKDAF7YvmlBHI
         ZZLaO5gxEdi3b1Z6DvaGe/RZ4oklBRBXjHUopq6UzIL4Og7qkFhHR6pH8TcEoqN4b2TC
         GtYkVn42c1iRmQ56EdBX+wq8m66i1JgX2m5XdMBNXDsFG+YN+Wtlj5sfEeQeMkxcyMgE
         baud5fi+eBb8iLbDueJF0ZwQSTrDPh+67nr8stRmYXAsZpjqe0LFWBOOyPCOObFXb7db
         YofJW8DcIS764CZicBDPJQNz5wuHeCaLj5ln6ipTXN2XPdKAyLxcD5oyLU+kyHxz1MaZ
         E4yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fuOwytNXJclzTTPOtHa4Ab2Bmf485RH9G2idgUN0990=;
        fh=/In0bZDF+0+NWAXXzBslfrGlW+mvUlDvwnySHMqjHsY=;
        b=VNY4Qf08zdVWhwm13NOAYX+2pRjUyzGL0i8H5yt3ZXAZ+baEiuE8H8fLOF74sUZMUd
         KFA0ch6b9/joDUP9C0PKbV5cd+WCxflZUKpMni434JYGY6dxNkpwrvZOC5YYo12H4ypT
         UvdLUwvjDuyp9xMfq++tVdd5vHDFEjfxMqYsv1INJi276DoEX9+NPYvYw0mPiwYVHSiP
         y690XhHCA6oqGSiwU0RhnLFT2lGZY1xeJ8dIzO02QBfbAzZ6Sy1Of0Q5eYAcv+VGVwWo
         8WLVfGE1+dcaO9giMwSkuOD6YIYYzEPFKnHi51hRRMjMidwFZnc4bGpxaF4S17KyuAa2
         iibA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723744743; x=1724349543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fuOwytNXJclzTTPOtHa4Ab2Bmf485RH9G2idgUN0990=;
        b=ZajnZjN2C2qexBcmh0woYZB4FvdJAPE8lT/l9Xe044S1dhMLce+Eh+4TotTp8z0dhc
         AN8qna2CmbgeMYURPVxY9WNSfJ5EHU6cAB1OvRnhQmx1IvD54bVyfWuH/GQnazQmAZ0J
         hp7mEL5O4tSGzeJw9QDUF5PaSykmV2kNbiiiGrh47typaW4vMi9scDev3rkRbJudg6fw
         1gfM29msPwvq4814paDg+5MMm1JlA5LuQpCRHTAzDo5VD+e9L90f/c8TEqlap6kiIdgG
         6z/zcmm+CwuvRYUPL/b6nE6FyVPPE2IG739yKfvsR2TTIg7FXbGIYayi6ZEfZqoM42CO
         20kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723744743; x=1724349543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fuOwytNXJclzTTPOtHa4Ab2Bmf485RH9G2idgUN0990=;
        b=wKulGHRaATYMhJ2ASZp63uZfqoNGZeafpHMjVbGjrk54GkPsNRcdWcDJ8Hh7FYH4JH
         bFu0zqxSUMtH1bFUJw/okliMYBPvQ0NDlK9AHBDDeQ99bxfRB78AM7h3QbuV7Qgtu7u5
         TLZZkXySI9DTGVIcnmyYhCG4cpooXxfnKw93/L2GhnWDQJ/bazIH7tDQNvFL/kIsP80G
         HMIfq60UaqkZi9koniNZ7a8/NBd484756rQZjwTtxLKQgGI47ADd1NsEfCl4TQsW4Pyg
         s/OkfcGio7Jc/hKaHDzxHZLxPbl3szx4PkRsGtPTnmw9OxdGbqUDP33nKPMgK9CKuogL
         ZRLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6TcToGZb04NiqZcYYIH5TgQ4CT5uxu0zTRizh4pZPFq3d3FeKhWA+HnRV/pNPPaFGs1QVIEvkdJ9Ft7nWBiXNClehNHqiiA==
X-Gm-Message-State: AOJu0YwovXNvmq7uuK9g1tYMeF1YAAc51/3Pc7NymWY2y1kPqo/P7YPE
	F5Oof+SEEqGGXUtBXAkf6Nbov1xuWG8zk2oN9gMHA0BGU2HZxKKF
X-Google-Smtp-Source: AGHT+IFLc4cZZuQ4O/9iVwn2wocEV81uSapfFbMLf7KHKsedQVJF6DMvZ5KZgjoiGSIeIR3ct5B/Gg==
X-Received: by 2002:a5d:51c9:0:b0:360:9cf4:58ce with SMTP id ffacd0b85a97d-371946a44c7mr91961f8f.46.1723744742547;
        Thu, 15 Aug 2024 10:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5392:0:b0:368:7a83:35a4 with SMTP id ffacd0b85a97d-371868f3b09ls308007f8f.0.-pod-prod-06-eu;
 Thu, 15 Aug 2024 10:59:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXU1pi2v/ztH9U9s+wXBz4YkoPpiRdl11TG2wipNIuHpkCqh27qCzihi4P0Y51I6dMAfpILNP7b4Yhrzy3HsYm0ZNlcp6A77e7O2g==
X-Received: by 2002:a7b:c4d3:0:b0:428:e820:37ae with SMTP id 5b1f17b1804b1-429ed785f4dmr987365e9.1.1723744740577;
        Thu, 15 Aug 2024 10:59:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723744740; cv=none;
        d=google.com; s=arc-20240605;
        b=KUnF7XJj2yyhVhM0YR4vldrZZZ6z2SaqPrbSG/lO2t0PQNSK0BO+mne45P0jSnfezk
         05hhhAJkTl0GG6sNeIpRSFy7Z0DTGgYgfsygzpL4iWjfQSQ7NYzxnxXAJ1McH7+W7nUm
         WBcXiXlPKYllKUbDM9dIvfwjJH2SU0Eq1TIY3OVdCsrX8IJjJ6jUjrPOzBk4LUcw8oqe
         BA0qF5aIxZSN6ZP2v+GWYzXLlmD7gYaAGpE42KFaCNDHBzH19oyDytpu1ysrA4YmVbTs
         H5uM6Xoct6pFiTMUcry+6P125+gDHulVGai3FfG7VjeLsfe7Za2MS3j1us/7hNZ1uID8
         Vkmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=o5v2Q6l1w9ceaNBZ9C7Ww9tq5niKQlAAp7GHeeOVfzs=;
        fh=Pl1jw/2/XtZwGO/0U8aRuE75v7g7MSppfZ5WaK/0X1E=;
        b=X1PbMG789SmBC1q7cf9aXaiZaR8q18J+L/ijn5hjhYGoQ7kmVvxFSCbg8OiaEzPnr/
         LAfGOfDNvVBGnC7FOGgRX1vJts2v+GPeTxBWgrft3SkO9gVkOb7kh3CY+8LRZFVZWuMv
         hQqWPRZp0UpIeYH1aJQsdny1PIPvoa6wFFWUJVEFIz4OpSbaPhy69Rm81za6QBEjPPRd
         3V+lypgYTXmKv7lBz2Kqc0w9s53G68visvgQmx5DzxYXSAj7U0vzS+iE53Phj2mrbCEJ
         Qfo5MfhH3R9N5BUmmuTFg9QNZSL263mdqmZLboVY80ZP9CkN5eRMmf/LHWLDAFSkcR8+
         jNpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f47.google.com (mail-ej1-f47.google.com. [209.85.218.47])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429ded6ff60si777225e9.1.2024.08.15.10.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Aug 2024 10:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) client-ip=209.85.218.47;
Received: by mail-ej1-f47.google.com with SMTP id a640c23a62f3a-a8385f38fcdso83520566b.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Aug 2024 10:59:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUJGI/f2H2wvIrmROa/QwOcNRn911kgclq/p7QLLsolh4HNB16Z9V0/d9xAg2Sa71avS8nOS7IQ+xu8Y+WUiSkS972BkzNTczxKGQ==
X-Received: by 2002:a17:907:e60f:b0:a7d:3c46:f4ae with SMTP id a640c23a62f3a-a83929d37acmr26046366b.55.1723744739732;
        Thu, 15 Aug 2024 10:58:59 -0700 (PDT)
Received: from gmail.com (fwdproxy-lla-006.fbsv.net. [2a03:2880:30ff:6::face:b00c])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a838393564csm132311166b.128.2024.08.15.10.58.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2024 10:58:59 -0700 (PDT)
Date: Thu, 15 Aug 2024 10:58:56 -0700
From: Breno Leitao <leitao@debian.org>
To: Justin Stitt <justinstitt@google.com>
Cc: kees@kernel.org, elver@google.com, andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, axboe@kernel.dk,
	asml.silence@gmail.com, netdev@vger.kernel.org
Subject: Re: UBSAN: annotation to skip sanitization in variable that will wrap
Message-ID: <Zr5B4Du+GTUVTFV9@gmail.com>
References: <Zrzk8hilADAj+QTg@gmail.com>
 <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello Justin,

On Wed, Aug 14, 2024 at 02:05:49PM -0700, Justin Stitt wrote:
> > I am seeing some signed-integer-overflow in percpu reference counters.
> 
> it is brave of you to enable this sanitizer :>)

UBSAN has been somehow useful to pick some problems, so, I try to invest
some time understanding what UBSAN, and see how much it can help when
solving "unexpected" and misterious issues, which is something that
challenges me.

> > Is there a way to annotate the code to tell UBSAN that this overflow is
> > expected and it shouldn't be reported?

> Great question.
> 
> 1) There exists some new-ish macros in overflow.h that perform
> wrapping arithmetic without triggering sanitizer splats -- check out
> the wrapping_* suite of macros.

do they work for atomic? I suppose we also need to have them added to
this_cpu_add(), this_cpu_sub() helpers.

> 2) I have a Clang attribute in the works [1] that would enable you to
> annotate expressions or types that are expected to wrap and will
> therefore silence arithmetic overflow/truncation sanitizers. If you
> think this could help make the kernel better then I'd appreciate a +1
> on that PR so it can get some more review from compiler people! Kees
> and I have some other Clang features in the works that will allow for
> better mitigation strategies for intended overflow in the kernel.

Thanks. I've added a +1 there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zr5B4Du%2BGTUVTFV9%40gmail.com.

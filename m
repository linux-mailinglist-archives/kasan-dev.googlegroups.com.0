Return-Path: <kasan-dev+bncBDEZDPVRZMARB64V7LCAMGQEXF4CTMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 509A5B274A8
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:18:53 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-30cce50fe7dsf869884fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 18:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755220732; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z8KE4YEBUBxKN7vRRaPFuGLzA3wNTTgJZDS1Jt15jIoYRubuT2ZI/BGrl1Q49J0E/g
         qQnYvoWgFmgSkGJUvyc4W6XbuvDXQacY3509vZn7i87htAMFqzYqUJ5JeEGAmaRl8910
         gax0MX2SmM1p51nAf+IkKn8n0M6hC2YiKPzTRmCsTdgQJ1ZE01fTVqnfvCVbBB7pBslI
         P1rtjb0ixbnmmGgtGgv1iJGd61Iz7TioWONFvATrNBuFxuJ2pnS/2pclpjwklIfLslbw
         YRYRyR3zI1Swa/59zxRgCINCyqDrYW+h67uAd+KtSZcs2wd6fKzqYLNy+n61BeIi7kx3
         gLSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fWV3py+0iOnbVedn1lWWh4X7kuJApgUc2bCKkF/TRS8=;
        fh=8ivGLx+iyUTjQK0aUmd80Pj37bxxnayuVvXFDbScmKY=;
        b=WKQCGPNzKybJ9XYkVeTXZmBOzRGZVg6ARPe4z+L/UaM2MJWLZMTXehCJlj78THxeaM
         2CParq7ldKGsE66EEwj0Nz82j2eEEcH7HXfiQCtBeCAMlBqqwzuEarws7WOTvTUeDmDn
         6jhYZe11uCiRFqnD4zzM0s8cxFe1BUuBxexGwvoYUSsCHZ0k+cwg03d/8kqjPY7olE0O
         OHVElFaWxfewrBGNAvIIyniMFN5hMov5nuv6cIuD/DF2uBkXSlYpKiTwMXrh6bTYccO6
         wEi76hh6fn628ipHmOX5Qx0tMHtUHgxpb04u/1qLLZCp9WmgCX6/oP2CW+HuMIHxHbi8
         +uaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C832mawi;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755220732; x=1755825532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fWV3py+0iOnbVedn1lWWh4X7kuJApgUc2bCKkF/TRS8=;
        b=oxV8hPuijZAkpp577noF6hgYG9y5AzTW2fC+GEbOh5A3jTMbDXowXbS5S5RwWSE1CE
         FaudmRM37Jkwpfris2SXPqA6IiKinhz/n+/RDOfRSL+UMYQE1CpRn0vNMNp11JGgjygo
         bW2mtH4PWNFFi956Naplg4CL5zEBrrzKaT8dZ9WrjGROwOMaC1A/hX/mtwgQIheB1ZYW
         3ZUHoqXnB4F8CyQ9cg6DirZ1UV8hfcQR08MwISo/3/cX58qRk42I/v/0XorAJZZox4lq
         1lx5ugKXDpLJb6I4MeEAs9S0eoIq/7LgtU8raQ9eGZZVyebYTOSwDvLyZ1Tsh2ntsWsQ
         LNrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755220732; x=1755825532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fWV3py+0iOnbVedn1lWWh4X7kuJApgUc2bCKkF/TRS8=;
        b=TpDXMoSKbo7s1R3tw6dWEToIdsLwj1rjlyNZ+duTYD9xLDJpJ5BTUGd6T7bmmpd7Ap
         zjJTGYBAX7AyTbvZq7mweetoGTTivJPN7eBFD3s7RjHpMHkxNfy9RcZkv4m1BtAx2KTE
         pjXcmatCIWX66JPn4Ylolv7jvIDZ+7ihiF8T6g6fr0FWejk/84LuDGbAKLHxgihItwo1
         qJQr7c9K7DyG81J2RTwf6G4aJdC59HFKxO/tm/uvsqVsfHvrAsWdcfoIdIPD8OpB6hOy
         1uCVjqDXd4880tYeAsUokcTuH0ufRao19OJ1iVQOXFhZqgoCGb8azSypfs994O517Tfp
         t+MA==
X-Forwarded-Encrypted: i=2; AJvYcCWoMLlIVbTZLDjXn+BcokYUMo5+a6gEdWl0GfFvp6JY6tfVkZPW/6P9oF489TELObVz6qi2ng==@lfdr.de
X-Gm-Message-State: AOJu0YwmbJPpgRnY0FE8+FOvZPgc5cKGPmjarQwAlxFfAzflwoAm7e/5
	53FSY/4wd1b73+kkzGpF79spjEBnmryui+Tnmueh1/OAARu7zdAW6YQe
X-Google-Smtp-Source: AGHT+IHA083JLdcUm4v1ADEEJRde2RhbxbmBwnetaD6nhoktUW4s/FID4xxsCnZHIOAKo34SwiNyHA==
X-Received: by 2002:a05:6870:c46:b0:2eb:adf2:eb2 with SMTP id 586e51a60fabf-310aaf6dcb5mr111945fac.36.1755220731679;
        Thu, 14 Aug 2025 18:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgztGDGuSyXYVXLI2bExgubCi+7z0HwthgseflDYPjYQ==
Received: by 2002:a05:6870:9381:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-30cceb0a6ecls632757fac.1.-pod-prod-06-us; Thu, 14 Aug 2025
 18:18:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6fr8sl8NQmwsU6vJ76RTuY3B76pC1C2OiTjWm3rKCVwx7Hb1aMxfYV8cw+BUta3stk2X/4kPFJPM=@googlegroups.com
X-Received: by 2002:a05:6808:4fe0:b0:42c:f363:1c2a with SMTP id 5614622812f47-435ec48f62fmr104483b6e.10.1755220730893;
        Thu, 14 Aug 2025 18:18:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755220730; cv=none;
        d=google.com; s=arc-20240605;
        b=Yh4GZ81q7MMCdQQdCPYK7BqQXyIqcAUog2HVuS4yc54chNEepBbunSz6lgM9tUSMVK
         IgMM7S6U3MbrGlxHSr3A51b5/AuamL/Ik1Mzq87QYXqKqEt7xw7087XhrxSG9s8Xr06S
         Ka7NLD2H/DrHESnHT6pzc1u5EvsnCi76WRmAmAO7bF/PWRgbPH9gxCmoitofY14sJeoo
         n2r46LVtVe0C60aOWL/1GfgkkT6ekqmd6n3HPjDVr1CL6algxnKdSy4eviiKAJdKOQ/n
         axi7sgRsbS3ZIAzpx3D6AU0pv0AgmEsTcyKcrF/4d+B3VCQ/ZDYGmSWtbvoBN8hFIaS1
         1MIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rkwUCfbW1C3nPkFseFTq/BmTPCiFXIFNtl5CP+d2vwQ=;
        fh=HTYnihPdzA88NT8KMomsT21O6JK0YHnQIEuNEOVrVAI=;
        b=k7BXDWhi85Q4wnXtz3ujArAdrEWnd/HFxZcnsAXl4JI95dRiifGE5ifegdUB1R+Cp+
         w+q9x+18mb20grzU0XcEdO/x9eEm+Pm/YFpJoxuBTWVoIZT0waDn8mMB5fWaA662Gdq6
         X+XmpyGRvEB4tRyW2UsVHPNFg33n7HQQCUo55Mr4gtckJhAHvEjPALbPVk79xmg4gDhR
         AEY4/i9pTsXouhVdpwQ6MIglRA/l42qIQG2UGGu5ZUaFEdiZEu3Jup5f+z7zpDiHA1SU
         W0c0B90VTd/hUmxsOpJor5lIKtpHmMTy8FlpnCU6erKXBBoOTBUMGeipQkn7jCyU4MQO
         oLKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C832mawi;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ce56c67fsi309628b6e.0.2025.08.14.18.18.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 18:18:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 039BD45732;
	Fri, 15 Aug 2025 01:18:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 32E66C4CEED;
	Fri, 15 Aug 2025 01:18:49 +0000 (UTC)
Date: Thu, 14 Aug 2025 18:17:44 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ignat Korchagin <ignat@cloudflare.com>
Cc: Marco Elver <elver@google.com>,
	Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com,
	glider@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev,
	davidgow@google.com, dvyukov@google.com, jannh@google.com,
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com,
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
Message-ID: <20250815011744.GB1302@sol>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com>
 <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
 <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=C832mawi;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Thu, Aug 14, 2025 at 04:28:13PM +0100, Ignat Korchagin wrote:
> Not sure if it has been mentioned elsewhere, but one thing I already
> don't like about it is that these definitions "pollute" the actual
> source files. Might not be such a big deal here, but kernel source
> files for core subsystems tend to become quite large and complex
> already, so not a great idea to make them even larger and harder to
> follow with fuzz definitions.
> 
> As far as I'm aware, for the same reason KUnit [1] is not that popular
> (or at least less popular than other approaches, like selftests [2]).
> Is it possible to make it that these definitions live in separate
> files or even closer to selftests?

That's not the impression I get.  KUnit suites are normally defined in
separate files, and KUnit seems to be increasing in popularity.
KFuzzTest can use separate files too, it looks like?

Would it make any sense for fuzz tests to be a special type of KUnit
test, instead of a separate framework?

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815011744.GB1302%40sol.

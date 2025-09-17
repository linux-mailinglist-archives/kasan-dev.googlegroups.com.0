Return-Path: <kasan-dev+bncBCC4R3XF44KBBBPOVLDAMGQEEYA5BEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 30CC1B7F3A0
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 15:26:31 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-621a820ccb5sf1965076eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 06:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758115589; cv=pass;
        d=google.com; s=arc-20240605;
        b=ghIPUur6D1bduX8n47T3D/WyGd1Baslocru5yxpYBMF4hQeUkbHt9u8/CweJUwKaMK
         XuPmGNLGygdaohfLQOnRXu9br0eVTRR7ZgvIxLE4UNdmwdXepe2B8mNfjPgL8RgV/Z3f
         9VnLlpicNM8VVblz394qBs/peFM8gQgQ+0j/t+8kQgvGp+hvxTMmbvAChP4xhB/kitQz
         h/3He7ZM3IQs9J+FuUIqYsLy4IDvdAiivOS9vGEPCN8xYVaEQIcFlgdajwgmDaDzbImQ
         IYKyikdN2j1sGcIMCiImXxGy8nZETxmVWP5JaSJaLFbkkn+cUQ3ZC/18+Hzljykt8kEI
         5VEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ck1Gxxq8Q1hEW2mNO6fK52m2mCyp7EAwcmXIeYEGxuQ=;
        fh=9ppYy8T57hoeDPrbO0LvqQN9xoXJx+tY9qSdtwWIV4A=;
        b=gUBOayQMNlpLc4BAfnWsfxNKsXxTWqSDXbvJj4XBZHiNlWdpzPwXRLaOl73w+Mm6bB
         kqQweiVQPa3xxH6Dno/aazTL8/U4LbjcIDHJkf6nGwJJ2qp9sRg46QpNlaQHriME8ok/
         YOUcdbnkcc1WbBS9CDo+2Q5qHDgGbj2nU0i1DT2PUi/0Q5pjXQtYy63bWlAUjNe37S5R
         tT2rJvtUhf/e/3yuBrJ429blWwUVbhZxbXqgUCbi8u9+OPCo2v+PhAZfpBdVIAUp87cF
         3OIbx9as5ljAaJ1xyh6LtntUahuFnXiG7K4kGUzivOIJFAaWl43AyQJgerd1PDmK4GA5
         Zt8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fyzzqaq1;
       spf=pass (google.com: domain of sj@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758115589; x=1758720389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ck1Gxxq8Q1hEW2mNO6fK52m2mCyp7EAwcmXIeYEGxuQ=;
        b=eW8f/z/wBDgLF2RP2rNDn11WeZLi87clzRS8j7D2kEmcfQuPGT6nlHEE5vTy2Ao/nu
         646PvPRzIuhL6E83x8C2+geP2GmLBFxp2sPJzn+vYzhYVxZRdDEwceqD14Sg9Ru8nLXY
         eDQO1wMtAZUbgawdS/0Y3z4JgD58/RTupuoX5AkpGb77cc4sKVh1RG5J60wN+2eivwRa
         R5oFIJrywu64jVvv7XNNGmAKSCOygE9pIlEbpRyElpAz5+BzU680T4y9wXVV7LAk/U6K
         VoFagpYeK8yILcMjPV6WESG4G6eVhmASe19GbLlerxOiz3H1MttLixGEBWCBNsNpU4Qj
         9Arw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758115589; x=1758720389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ck1Gxxq8Q1hEW2mNO6fK52m2mCyp7EAwcmXIeYEGxuQ=;
        b=PPDO6qEPpWHYa7yfy6RHEKTbzA9kYSpgh82AZIUDI5Ar8motIkqUfLYfV+cBZ3cKzY
         6pG9Jst4Z5akmk92tjwSGot3MQGpAgZ+h7x4pm8KPKonI/mVkBxFmfH01GyRIOfcz5ob
         uV8OX3rAnMfJaFDAo2FK1MgGCo6aqOqzEXBDjmQqDaNHKWePUGd6zzT2I1dWRQnLvuQ2
         7rRNeC+PK61UlfxYAdMzii+uFWXxmjpBWoVHs6F/MxogFHXM41ivKPUiPZXOslrJJhhv
         FObV5dBJ3VQD6Lga+CWq0cjD4OoBXEcgOUcDHSJesVxBMxVKmPKpW8zq8X8s1BhDdDt4
         +hFw==
X-Forwarded-Encrypted: i=2; AJvYcCVqm5y4WNev3dvdkA4xyGgldcVknDepsBDszjF1yLhdrMFTVXijfvsABGnNEqP/qdlrBsv/BA==@lfdr.de
X-Gm-Message-State: AOJu0YxLkQOuXGS6Z0cexITSeDrIYA51NdqF/QHiaI0chGZe/oiNf99Z
	6firOMmyK2KIPZfbQQCjy+HkCFZIW92k86eiDCF4LXqN+syp/bg+KxJn
X-Google-Smtp-Source: AGHT+IG62dkv69quAi71ngyL8TiB9EbSjzZ/g1zUJLOujWYfcpN+YyLm44e0YwUbeoKv9Gg72PV16g==
X-Received: by 2002:a05:6871:6c0d:b0:315:a68c:d908 with SMTP id 586e51a60fabf-335c0961ae2mr918599fac.51.1758115589453;
        Wed, 17 Sep 2025 06:26:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7SEcLQPXL7ajKawSo66aSll6dI3hPFPAQITB9bDd1yIg==
Received: by 2002:a05:6870:b51f:b0:331:852b:7a1e with SMTP id
 586e51a60fabf-331852b83fdls2420926fac.2.-pod-prod-07-us; Wed, 17 Sep 2025
 06:26:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIa1v6vYJIabfkU7/hkb8K+ZgPujOOI+LNc4nSGW+6mh/bYiYBilDv7vsMfqyKEwXI9VHRCASQo6g=@googlegroups.com
X-Received: by 2002:a05:6870:d0c9:b0:331:6f29:7e05 with SMTP id 586e51a60fabf-335baee23ecmr1100334fac.0.1758115588323;
        Wed, 17 Sep 2025 06:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758115588; cv=none;
        d=google.com; s=arc-20240605;
        b=RX1xa4b32KTBjFIJEGJBSTuma/kEnkX9O9ZD/a9KLbM66/HgLiOIkFqCJ+2y9O7srP
         Tc+vtltXnI5gOJjPdqEWCPN4Ed/QNYHsSAn9KXWRdvlL6hqGQbf4IVwHsUldU4l5g1GW
         fF7FbJ1p7cpzePXZ+o+t1AM+/3mdk8FujrogDKeoOVUdegcfbVtKpY8sP8IEFRSvIwxI
         5693sJvNLK7VnvnlISDbsUFP/v4NFb8xSw1JHWR8Cvx7qiBfLsoheonqPeENX3V13rUI
         LH9NvAkjFGeLY8ojWmlrV3Q8jqV8U/k481ubP8zRx26eH07botGK1LnK2JGvwbKc6TiQ
         guww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lYejnLQQW4dtz6sD1C8ErIRCT8kfcNV3rxw8LWS/PSo=;
        fh=PStneZEaF/QGIPoYqIySklGRorKpRsoNUXTTDraw9Fc=;
        b=T2RfJj2XnWj1+Cdh6w700pTnLcacMc06lJrPSflfl5xiThdwmP+4+EKtmDrCvLoRBZ
         NuBksIAWK0G8fvj7kNnBozb0qufwl29oc7UakhfgU2XlgLoGebeS+iUIxKysKofIGxq4
         l6l7OjinMt6K/nspf1+FA2mluuJVpjnH7npvKK/HExcpTL1RFDtyuUa2EUbNQbPk7ih2
         if5YNPpnEsJbbWZBVJS1gZ8sW/hmLw7ZX4BEHZyd7jnDxoTfjw710EuuWcFMXiRJT+cA
         3BsPMAsGd9fnx6i1+RFBuMNqFBc1ZqzwqA2pcZ0aMgBQtiNPZWRPfO85CetZ28sLLmE+
         KvWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fyzzqaq1;
       spf=pass (google.com: domain of sj@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-330a38bee6csi493834fac.3.2025.09.17.06.26.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 06:26:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A210243C0C;
	Wed, 17 Sep 2025 13:26:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5B5EBC4CEF0;
	Wed, 17 Sep 2025 13:26:27 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: SeongJae Park <sj@kernel.org>,
	ethangraham@google.com,
	glider@google.com,
	andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com
Subject: Re: [PATCH v1 04/10] tools: add kfuzztest-bridge utility
Date: Wed, 17 Sep 2025 06:26:25 -0700
Message-Id: <20250917132625.61081-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250916090109.91132-5-ethan.w.s.graham@gmail.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fyzzqaq1;       spf=pass
 (google.com: domain of sj@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

On Tue, 16 Sep 2025 09:01:03 +0000 Ethan Graham <ethan.w.s.graham@gmail.com> wrote:

> From: Ethan Graham <ethangraham@google.com>
> 
> Introduce the kfuzztest-bridge tool, a userspace utility for sending
> structured inputs to KFuzzTest harnesses via debugfs.
> 
> The bridge takes a textual description of the expected input format, a
> file containing random bytes, and the name of the target fuzz test. It
> parses the description, encodes the random data into the binary format
> expected by the kernel, and writes the result to the corresponding
> debugfs entry.
> 
> This allows for both simple manual testing and integration with
> userspace fuzzing engines. For example, it can be used for smoke testing
> by providing data from /dev/urandom, or act as a bridge for blob-based
> fuzzers (e.g., AFL) to target KFuzzTest harnesses.

Thank you for doing this great work, Ethan!  I think this will be very helpful
for finding bugs of DAMON.

> 
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> 
> ---
> v3:
> - Add additional context in header comment of kfuzztest-bridge/parser.c.
> - Add some missing NULL checks.
> - Refactor skip_whitespace() function in input_lexer.c.
> - Use ctx->minalign to compute correct region alignment, which is read
>   from /sys/kernel/debug/kfuzztest/_config/minalign.
> ---
> ---
>  tools/Makefile                        |  15 +-
>  tools/kfuzztest-bridge/.gitignore     |   2 +
>  tools/kfuzztest-bridge/Build          |   6 +
>  tools/kfuzztest-bridge/Makefile       |  48 ++++
>  tools/kfuzztest-bridge/bridge.c       | 103 +++++++
>  tools/kfuzztest-bridge/byte_buffer.c  |  87 ++++++
>  tools/kfuzztest-bridge/byte_buffer.h  |  31 ++
>  tools/kfuzztest-bridge/encoder.c      | 391 +++++++++++++++++++++++++
>  tools/kfuzztest-bridge/encoder.h      |  16 ++
>  tools/kfuzztest-bridge/input_lexer.c  | 242 ++++++++++++++++
>  tools/kfuzztest-bridge/input_lexer.h  |  57 ++++
>  tools/kfuzztest-bridge/input_parser.c | 395 ++++++++++++++++++++++++++
>  tools/kfuzztest-bridge/input_parser.h |  81 ++++++
>  tools/kfuzztest-bridge/rand_stream.c  |  77 +++++
>  tools/kfuzztest-bridge/rand_stream.h  |  57 ++++
>  15 files changed, 1602 insertions(+), 6 deletions(-)
>  create mode 100644 tools/kfuzztest-bridge/.gitignore
>  create mode 100644 tools/kfuzztest-bridge/Build
>  create mode 100644 tools/kfuzztest-bridge/Makefile
>  create mode 100644 tools/kfuzztest-bridge/bridge.c
>  create mode 100644 tools/kfuzztest-bridge/byte_buffer.c
>  create mode 100644 tools/kfuzztest-bridge/byte_buffer.h
>  create mode 100644 tools/kfuzztest-bridge/encoder.c
>  create mode 100644 tools/kfuzztest-bridge/encoder.h
>  create mode 100644 tools/kfuzztest-bridge/input_lexer.c
>  create mode 100644 tools/kfuzztest-bridge/input_lexer.h
>  create mode 100644 tools/kfuzztest-bridge/input_parser.c
>  create mode 100644 tools/kfuzztest-bridge/input_parser.h
>  create mode 100644 tools/kfuzztest-bridge/rand_stream.c
>  create mode 100644 tools/kfuzztest-bridge/rand_stream.h

I'm wondering if it makes sense to put the files under tools/testing/ like
kselftest and kunit.


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917132625.61081-1-sj%40kernel.org.

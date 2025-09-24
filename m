Return-Path: <kasan-dev+bncBCC4R3XF44KBBIWZZ3DAMGQEU2CBL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C0059B98E49
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 10:32:36 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-eb375529db2sf424842276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 01:32:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758702755; cv=pass;
        d=google.com; s=arc-20240605;
        b=g88bVTuXETcVOGfRgG7G8oux/Vt6Iv0JBI8Jmzo0i4Ld1KLQIiXQQ/+XFx3JQq13uM
         T2R5jGokDPLt8TUO0pAfZb/6s/qlqo7mG3bnTFuSq80cmdRRuPARDWJmEHkjY89hlIPd
         yqPxfTjuAJGuj1hYpcuVWc6h6r588z/T+kKJiFVrnQ1hq3mIgh05Abrn7COzIH23Aqg+
         e0jQTlugF3kJ8TUZzDqw3N2VwBuR5+umkZmTPEfbE5LItEBhLjqva2b9b/KbUR3HgJxb
         DChZ4J/UZ+kGvxEdfMmMMtBSw1XZ9xuXAm1BJO5hTcbk56EU6f2WXS0nmW+u/p+0qbXp
         INvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JWwcdPPl3AqE73VG/pGSEzrQa5JFEmhDZiivicQ3RFw=;
        fh=iIQ5nZnqregmiOiYORiipAZHAYdLnLWHz/HUtaCtgZA=;
        b=B99ydWk1LMj1SakSJAfEHf6mmZ2uiHiib4xHO/eYANRfHBSdqn9VrL1CnzHawMbtcm
         Uh1ub5Rn4/Z3D5t7/bd4kO2lUOEA2E6wArGMNWbXURJ6ijF/s9JGI1sMaEmwtHoVAH5h
         rRdlDfFFramzm8fNOr+1NVBreYU0XyVSJLQR+kAHu4EmYnatFR2+qCp/k6HHehTkAW0s
         eJfxHhpEzrjgVl1aZ34FuswHb9E+uP9a5iUtJtAYIHTSzY0Pg+FKtWKR6aWpJr/8pcHE
         4BUkqthsDntwsaUFIVUOu2OvKOstHPaspdsJE9iiIKc8lVBRE32WJYAk57UPmjooxXNn
         H4hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WKCiEqK8;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758702755; x=1759307555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JWwcdPPl3AqE73VG/pGSEzrQa5JFEmhDZiivicQ3RFw=;
        b=O3SxkWfeVebyihSIp/B9HulviiqOlDz1zThLfvr3frw7NJhQa0o2DnOphM3MeRs7bJ
         wRuQfu32BDc6ZZ2S4EnQDY10cvgDqIlmRbX+aMXlp1xUbLOoyl28zAMzGR/mBtQ+zRDl
         PacG6HKkS2M1x6i7zZBgNttvlUETOKZD9pEJxCq3r873Bm1iE0Nuu0G7di1a1wWKj6Zn
         QTihdG+abO1BQapIVGVrvc4FMAfop1h66wMYihvgy9m2/IaGzfo32XMPxS4HJnuwWZ0U
         +Ns02HlJXfXMjuR5RJxPB6NWqs7IWy5uO0uBqQKOnAcWrMyvohclxMx9mQ5+huoi+T2o
         sIww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758702755; x=1759307555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JWwcdPPl3AqE73VG/pGSEzrQa5JFEmhDZiivicQ3RFw=;
        b=VbJKhnxJ1P/Ao4RJ8lOhsj9MRiVVUO8ED+F6zNQColt3GeKkIt1CgCix4prdnHfh5d
         n46hcH0HKuFCJcTS/5jg2iq/rfKFi1sHXRG6xx/f1cUTHXzxELJ37TZv3ZQdPOQrgYrO
         TbkK6EifF+Siay+ywzDj//+JAXLsSUTDi8YCmH/AIx4y05qjav6eGe0oZeKccWL4tQlh
         2Atze2RJ0fp8CyBEDNvCy73CfhaMcaheD0xkrEoJkhWttotw8u1bfN+3jyd8E8mid7Hb
         yW8v5dc5E59f41g87ZtxEOEQyIX4eU4rAo5kvY9r81Dakq0j0gacrFyeedRPPqO8UOKJ
         igLw==
X-Forwarded-Encrypted: i=2; AJvYcCWzczReh5zQAQDgiK493VmCQy5fOyg7yy8vFm0PNdhq59zLZwe3HnAkEbSNuxauaaCKEpPfBw==@lfdr.de
X-Gm-Message-State: AOJu0YzQSuTK9T+dgpyhnyrYwHC0pESe8auhqD0Iuswnfb8SpOXDxIDS
	8pBSM3UWT692IG8FpsHH+dHmM8XhtU8CoEjomvpOrmMwbrIWEjnK2NW/
X-Google-Smtp-Source: AGHT+IH0cBRt1Z5pTqDXDnRnhOOGi/KijoQpfcXhmQUQWn22XAfi2xP8b9iD1a+zffy10LMReylNUg==
X-Received: by 2002:a05:6902:102c:b0:ea4:156d:2cab with SMTP id 3f1490d57ef6-eb32b1fec27mr4562801276.0.1758702755217;
        Wed, 24 Sep 2025 01:32:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6yyRROziZ7FKvl7rat5pnmyaWxdhzDYSpZHuuhZEdkgA==
Received: by 2002:a25:d60f:0:b0:e96:f5a8:6a70 with SMTP id 3f1490d57ef6-ea5d11bc337ls4644752276.2.-pod-prod-01-us;
 Wed, 24 Sep 2025 01:32:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjgW1OgddCAEd2Nr4oJo+YcLNZahSOMoXNDCDgameFpJWJGuzEaT5bcPJZBbYdVDEDC97Dq5ERr7g=@googlegroups.com
X-Received: by 2002:a05:6902:288e:b0:eae:a5a3:b71c with SMTP id 3f1490d57ef6-eb3301916d6mr4261468276.34.1758702754247;
        Wed, 24 Sep 2025 01:32:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758702754; cv=none;
        d=google.com; s=arc-20240605;
        b=KuU2YvCHPVqkjPXBGjbUw4LJXHuPLHRgee86cjVH08ej59pITY5ERO2d6kC6iwFg+e
         y8M5D+1wjA7tTf+o5btgkUVUJvht+MeqTOyQ+YmYgncesHLcZv7cgM1tf5FEThdCAUo2
         1u8fqrVTM7dbSaDdBt7QADMTq1u1K77XHmPY/cPOfIk6ny/0gRY2YySX7sAt7U/k4TpE
         QJvLPFh4lAZ8awqKz7Ov/E06xZPVQLnxU9+GKYzbxdw06nH+nF/RtDXtnNjKd3ZPUkw7
         NNlBGdjM0PKhWdB8BS/YbkNTpz7UHB/lpj/shutuWp4A00NcWEdsjxlViokUn0FynQ5q
         NS0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yelwEdVyFlvDCiRDVOLVouJn/0aKPQv0jeYtJq158vU=;
        fh=PStneZEaF/QGIPoYqIySklGRorKpRsoNUXTTDraw9Fc=;
        b=En1tiw/pvCy4a+zI3NoygHGTunThUh/AMRdeaWoxG/7VMexmYgmAAsab6ilH5+5eGJ
         npP26cUBGg87iBTwzB2ce+oO8Gy1Nk52Rlap2xOWYGcqMmruaMZtSQsLSlPMdrrISROO
         yPsY/g2FDLgpkRFhIKmAXSTx3dUjjgRPW0b+KAdmpRG7Aa82a8Z65TEelX2RhbyaRUuS
         PontXeFMuwKfogrCfma66QIutDXPoVhuWKeJpW8/HoLBTwlAa35TZ16nIZwX/RwnskOa
         xX0eLBe6r/k4GZ/ErVtaXLbZIDfBCBE4ooK+bolgEkKQJzaBKH9W8kIQXaWBN1hriRp4
         aabA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WKCiEqK8;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea5ce7250b6si803067276.1.2025.09.24.01.32.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 01:32:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9D4FA60202;
	Wed, 24 Sep 2025 08:32:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 276C7C4CEE7;
	Wed, 24 Sep 2025 08:32:33 +0000 (UTC)
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
Subject: Re: [PATCH v2 10/10] MAINTAINERS: add maintainer information for KFuzzTest
Date: Wed, 24 Sep 2025 01:32:28 -0700
Message-Id: <20250924083228.63898-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250919145750.3448393-11-ethan.w.s.graham@gmail.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WKCiEqK8;       spf=pass
 (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Hello Ethan,

On Fri, 19 Sep 2025 14:57:50 +0000 Ethan Graham <ethan.w.s.graham@gmail.com> wrote:

> From: Ethan Graham <ethangraham@google.com>
> 
> Add myself as maintainer and Alexander Potapenko as reviewer for
> KFuzzTest.
> 
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> Acked-by: Alexander Potapenko <glider@google.com>
> ---
>  MAINTAINERS | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 6dcfbd11efef..14972e3e9d6a 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13641,6 +13641,14 @@ F:	include/linux/kfifo.h
>  F:	lib/kfifo.c
>  F:	samples/kfifo/
>  
> +KFUZZTEST
> +M:  Ethan Graham <ethan.w.s.graham@gmail.com>
> +R:  Alexander Potapenko <glider@google.com>
> +F:  include/linux/kfuzztest.h
> +F:  lib/kfuzztest/
> +F:  Documentation/dev-tools/kfuzztest.rst
> +F:  tools/kfuzztest-bridge/

I found you moved kfuzztest-bridge to tools/testing/ on this version, accepting
my suggestion.  Thank you for that.

Nevertheless, so I think the above line should also be updated like below.

F:  tools/testing/kfuzztest-bridge


Thanks,
SJ

> +
>  KGDB / KDB /debug_core
>  M:	Jason Wessel <jason.wessel@windriver.com>
>  M:	Daniel Thompson <danielt@kernel.org>
> -- 
> 2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924083228.63898-1-sj%40kernel.org.

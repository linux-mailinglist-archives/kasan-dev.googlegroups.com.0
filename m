Return-Path: <kasan-dev+bncBCY6ZYHFGUIOXO4JUUDBUBHOULHL2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id CD3F67454DE
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jul 2023 07:34:37 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-bacfa4ef059sf4126272276.2
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jul 2023 22:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688362476; cv=pass;
        d=google.com; s=arc-20160816;
        b=xB8FRZZKRb95sD85A/hAH3We1cIUwCoHyHewkCFCMHsR9nl+EZx8S3FLjNSm/gKWUE
         WepjasjMOaAQNkHfOdiKJY9Qu7f2Ah2oeN5lm73FbnYmufikandm8s9+bZQ0tFeqNu9b
         fGerR7vru7SESCkFzL90yibym8eUoTvlqhZMCFSdiVPgceXjTlk04FONzmVTj8HU4diX
         rqimFsVy0wTQsUykFZrl/R+xymhlU1IP9tKz8oVe7nyDK0A/y6V81Pu/YtjJDXMQiyKO
         Vl25+/QMnaPDK3o7ZXKNHLnFSuP+VLaUv+gfMJilCm9FQ23yHwhC7ZjpjD1eXTOspXNM
         ZgoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=fagalsEjVRLiyhHqSx17Of+WbwF9LzOK/ra0awNUcII=;
        fh=ZaxstQDs9vy1i8SBcDf4FcHZQ3ZFfvM+NvlJd1tlQ1Y=;
        b=N8lG+qHVRnuV+MnWf63arvqf6hhxu64sCf0Uf+8fZ6o9IeDv20qBAaXuAZmow7n54R
         /fmo8fQ9VKu/4h60XSZOIzFOW/xPtVarBdc0aiSG1XsonkV3gWD0eMJuGdaRwgaLlfGO
         DHKlIiqz+3Gsd8tji5jr/lz9ozcfGCHkJ4sgL7L/WRxII1BqIQaBj0Ak+28xLjKQy4YY
         Shg6suT01RsrDMr68opevVroEzBPPiZHuLvNid/3CO/lan7SevX1W6QFIImnA0iWoQf4
         +mx+1V0nNnKT4NYGX/wnTeZfeR3JvtQz+b2m8MUseLVIrGq45fq6KA9Wlw85zj+nasrs
         VRfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688362476; x=1690954476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fagalsEjVRLiyhHqSx17Of+WbwF9LzOK/ra0awNUcII=;
        b=e5+xSr2TjJb3ziAmZsB91+fs/Zmrha4iOddvxFg4SMaYkIVNZETadMloOu3+F54rdW
         NISaKQtKAJeYvY5hfXMDPZxd/vVniqDTwe04ZM/25nLT5udkqiaJCMLXAr/BdviWQ+kr
         scliuGT2Ys5F4EUJMy50snyp/8EDnWYw6HeYAoiw4vswd0Rb1r5+Ox6VrUFX243iHnry
         3IZre3Nw/2C7z3QZCeGat81gW0WLfiExksa0JhmDH1UR67vrxUhCbNNsPTfLuK8EtJWG
         dYdiyumE9F38SFWfbnuVnPMZicgJBQzxByYXqenj6e1iJNVrIJQnVzLtmbG4JAGMp9YY
         8Y3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688362476; x=1690954476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fagalsEjVRLiyhHqSx17Of+WbwF9LzOK/ra0awNUcII=;
        b=FI6W6VaNVrN4JVO5lrXtuivtQLZkq8S3xIdIsRgwsj9y/36zYuCLlBDJoE3ZOHKc7z
         hj8VdtuGUAIWoyTG/7bjDF79TOihkp/h8hv+ThFNmUgQWR/TI3Qkoe/4SnXMGqVDNwUL
         hbXcb+ra6j1kMVXrUIya3ukUqYQB35wV8xMEoESeNBujxm4HbGR6bjm9vOlw2YSmfAHt
         Fi/V9c+tDDkqgntnFQfx64zxpOwMF1wZvbmyIZD2dQ/ZFlhdf4DX55Ixu9ATOBM+uJKd
         Lfkkl1TJ5wIe+fitL4QPItRuLeVDy6+vVSVrMS9BFAI3dsUMIS/xPSZcLeJlJE32JamV
         zaoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaVT5Em4Pd+q7SaIId7hU4fGIds4wrcHqPctl3GGMbDUvQYHVUn
	OFAJd2nK7epekynSFG/Zr5Q=
X-Google-Smtp-Source: APBJJlGgW2NSfh96hZfYgx99j2xIJ1SlTBvaY2bTPHFGGiM0vVGXiNOC4nVgs11HwhXfQwAFnkWQoA==
X-Received: by 2002:a0d:eb48:0:b0:562:1850:bbf0 with SMTP id u69-20020a0deb48000000b005621850bbf0mr7957868ywe.21.1688362476254;
        Sun, 02 Jul 2023 22:34:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:417:0:b0:bfc:565b:9306 with SMTP id 23-20020a250417000000b00bfc565b9306ls3623457ybe.2.-pod-prod-06-us;
 Sun, 02 Jul 2023 22:34:35 -0700 (PDT)
X-Received: by 2002:a0d:d7d0:0:b0:577:3fb4:f245 with SMTP id z199-20020a0dd7d0000000b005773fb4f245mr7293424ywd.19.1688362475248;
        Sun, 02 Jul 2023 22:34:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688362475; cv=none;
        d=google.com; s=arc-20160816;
        b=mzPmnZl+K9OT2fVYs5/DGtPIeRUXj9NRliLnJ7MrNY4JGXiEfnlzxCaA+kknJhAa0Z
         3aQnNEWfojlCR8dFCA4rvxANhpCFlRB9qdlWXj2xArG86at2ge693WeI5SvvU78DoyIA
         hJS6oYK6UBH8L4cFGCTl+PWHl2A/q/KFgbK2nQ/6xjL9lWJnP+T2jEfO0ZF8KqmbBwkG
         BYfB82x41GSCOvVkjqGDjaSbZwsFbaFxA9iNBCPDzrw6dgpAh8BEp7xP6Z6GcvBTz01b
         JRCewaRO/aMk8CCNpqWeZWJsUkju6fPMdqUcMjiIHrEqgwcXLndqw0ezR4/XU+L55G0q
         5htw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from;
        bh=fD4lkVBcoBvBH+JWXSkSHshRpldnOxI3HAalU/AaDTI=;
        fh=jhhGDfXy6EMr0SlvRVd4aZcWEXE0KNGXqvlOyNEq2wo=;
        b=DBrFNIRigtJfuk3bVli504YJKRYsTLz6qBBuV1ytX2xWo+yEuI3X8g6wei4j+Db3oe
         fhZ7rB9BFGU2D7focIkzoKLHkXq3NT0uKi2vQBnzyoCZufuXKHW09QcGhgn+Hr5YK8WS
         PBM5Wt4Gx14vUvmNCZQznpzluqNeJBwDlxeYBKmFx/tJ0qBEyWGxPSVN9YZD3FxG13cy
         eNDhjIp1dNkvS9YsuRmDkMIZ/qk41aSKXKsX0C1S1BK8BB252ue9rjuq8hBHLq5f1TPK
         q60VwDYoPWeEmmcJuLPlAw55aj8ytsJrCBU9xX5HnrYdXSIEZsjfnaz2SQ5Y/VwWdnyA
         UHBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id eh27-20020a05690c299b00b005702be69945si1344467ywb.4.2023.07.02.22.34.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 Jul 2023 22:34:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4QvZP20DYTz4wxS;
	Mon,  3 Jul 2023 15:34:30 +1000 (AEST)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>, Max Filippov <jcmvbkbc@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, Rohan McLure <rmclure@linux.ibm.com>
In-Reply-To: <cover.1683892665.git.christophe.leroy@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
Subject: Re: [PATCH 0/3] Extend KCSAN to all powerpc
Message-Id: <168836201883.50010.16266070359338968346.b4-ty@ellerman.id.au>
Date: Mon, 03 Jul 2023 15:26:58 +1000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: michael@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=michael@ellerman.id.au
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

On Fri, 12 May 2023 17:31:16 +0200, Christophe Leroy wrote:
> This series enables KCSAN on all powerpc.
> 
> To do this, a fix is required to KCSAN core.
> 
> Once that fix is done, the stubs can also be removed from xtensa.
> 
> It would be nice if patch 1 could go in v6.4 as a fix, then patches 2 and 3
> could be handled separately in each architecture in next cycle.
> 
> [...]

Applied to powerpc/next.

[1/3] kcsan: Don't expect 64 bits atomic builtins from 32 bits architectures
      https://git.kernel.org/powerpc/c/353e7300a1db928e427462f2745f9a2cd1625b3d
[2/3] powerpc/{32,book3e}: kcsan: Extend KCSAN Support
      https://git.kernel.org/powerpc/c/95567f46b4d20c047750a5e3029461afcdc67697
[3/3] xtensa: Remove 64 bits atomic builtins stubs
      https://git.kernel.org/powerpc/c/bcea4f7a70dc800e769ef02d8c3bc4df357ed893

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168836201883.50010.16266070359338968346.b4-ty%40ellerman.id.au.

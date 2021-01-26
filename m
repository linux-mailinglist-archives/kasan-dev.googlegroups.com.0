Return-Path: <kasan-dev+bncBC6OLHHDVUOBBMFYX2AAMGQE23XQN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 91B113032BB
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:36:00 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id b62sf903192wmc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 20:36:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611635760; cv=pass;
        d=google.com; s=arc-20160816;
        b=tUYZMcNMFhlnRg6utzFpIdc6E1Ms+f2jEkK8qfKHS96OfWmyFWjbpSUTQ+ZmXTg8n8
         H2zVnlfLTL6QU/EqdSxq7ju6VMMn9wLOMVEAdqqGWTHyNtNE2y6ZJ3fr1iZCbBLCLl+F
         3T8cmrPNbspr3keH8Qr6TSv/XWkOLyBKj3CWC553myGGwT+N2GHVPakyytnfAgZoRbLS
         fgeLLOOI7bGRjqmp1ZmtmDtkiMuJ0R+20bKaLBNJC9vrAFfSaOx5OYgNyRkBkJO0ywrK
         nHSTLAOcwSW1/Dz5yvbBSzNYVrkeRDcwHXmZVz6NuQ5Ksn2qCA2MjVJXYrelhP4cOn8T
         pyZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XX9V18PAdTopfRrnFh1msRZCdsR0mjOvqI8vjXtQauE=;
        b=VWq3Otzy2189WII5Dl/N1p5T31Cg1L0+34BCi4qLWOQ/fU389vbqn6JwuJc4ZlQOKM
         YX/C9kFgKwzGyMgDkXefS0ffNBneIVVWQy1KUg3lbRO2e3UYajY8UaEGrFFnpb1ymbk5
         9s+Oz/piXKUcNvYmA30BPG2lUVG7srI3327sEcpczCOpM4/JjON8EraN+uUD/Zer96g4
         07RClgENtk2249YcO7pjYjTCT3qPBkrB7cDZ/DeFwC5LSuTsWVVbnhmgfCmvsr8b9UAK
         fCoO5eGMe0ZcSmvTQEFPR/bBMZVyDhHGtJzv1plH0IXKz+rTK1bToSyw0wEwx02EToRI
         fhog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QutNPMwr;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX9V18PAdTopfRrnFh1msRZCdsR0mjOvqI8vjXtQauE=;
        b=fmCYG5U2PMVeZc7DAOzhsQW4TrSVFzZxiTuKr/S1cehV4lCDsst3txR+oCXkGSK85M
         tf8n/2F0H7lz0ePiK8F21vRZKdcU+lPY6ijqvF3vV2YDHyOaHRn5p/428+j8+mbkUvWO
         DGdyJ63AoE2fetOby9sgUg56TAnKGuU2nT6shedV+u15W8U34kahUJN/vyo4a8b/Ia6r
         BKjorSuXhjM0hVf9iIgq8g6xYDq82Br4/ZszKnQlUTAEjB5RihcQd1Tuc0acAHlZQC/1
         Bw42hp3X1fGJfxB2PgwjN7V6sZzamh+8xejX3uPof9ObY3P1l2XOBZU4lpcDER0l4L3e
         +auA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX9V18PAdTopfRrnFh1msRZCdsR0mjOvqI8vjXtQauE=;
        b=qXKMiF/MNyv7hCsEQbMV4uR8yePSasfBvjfUu5ubBab9jrcF4CD/AaJ2OPrNjm7tip
         +grk6wRev3ggRxq4Xfdpp3Tbt85d/p+c+5f9yDSqIwCBaOo2oOYtXU+V1DNF1561sV7B
         m89Q6XTlt4w2zKJGZJdy5HHOn9v4PUHX1AjQaeQXgT8IOZLQljqHzKVv+88qhwVLDWsp
         hClkkkeBKGy1+3f64ZpqLp/LB924Dza1w3ho+MVjxDuHMklvwRFurMUCdILhdlqx3fg8
         uh6EFa7d7zykxy8FYotH6pw9ii1A7JIPFYaKWoizzTOyfFVqeht8UndWLA38WQ/wpEUg
         3WMQ==
X-Gm-Message-State: AOAM53260QlU/GCZ5z/HZG+R/HB7bGBAO8hAkmJi9A4PWB3esuT3O2v4
	+KVEPIcsGcLXbAm0Kmp/JJU=
X-Google-Smtp-Source: ABdhPJwu8Rnkny6RHstszd/dB0kMgClrxEP8Mak2T+T7BaCrDXA/xK+UWQGffAjawN5KLQrud8x4GA==
X-Received: by 2002:adf:eb4e:: with SMTP id u14mr3988000wrn.99.1611635760342;
        Mon, 25 Jan 2021 20:36:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd41:: with SMTP id u1ls2639140wrm.3.gmail; Mon, 25 Jan
 2021 20:35:59 -0800 (PST)
X-Received: by 2002:adf:ed45:: with SMTP id u5mr3972492wro.358.1611635759577;
        Mon, 25 Jan 2021 20:35:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611635759; cv=none;
        d=google.com; s=arc-20160816;
        b=iqbRblw2d8tDdFW1pefaOqp1cMBfrLVDcrLMLcGOjTza/5l2OF+CSb0g0KQrvgBCZp
         I67gooyKaPAg34LqXad/3KiDt8CwaWkzdIolEIPg6F+qTgLWT4xxDurcBOU81Muj+fp8
         tV3djCdSjYlEsojMscNGF391gSEBb8qN4V7wDTGha9A+zqGYGkoXnbQgisj0Te0E2rhy
         DGDmM/36pC6TrM9c0wjBTnvrLc1cWo7a5Tww2piz7NifPXTkGv18kZVuftRimNSDm8Fv
         3Yhu8B2D1k7mpULvEovbe/CO8un7fqbbxhrDbXSKBnhLIoK8TnxvU7/GUsmnrgN4WJwq
         fLZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L1LlWkeSbCU+8eK5VQp4zW4V35HHf5JK2AOgO/JAOhA=;
        b=vJHNWgIC1IVinZvf69oH8KhTN4v8HiYYwvObWmNj7XyaUP+7R4tbBJfSbvGuTptGEm
         3SxtCpnxbxCtd1CpjB4UNUt8CDvC1VIRNb813s5ceryvF8Vq/z+/9MoDEmhRzIphYKZb
         43Z4OL/Awwzse93fP4khIGjUXJtjdPBgR5ID8CaqrztCgV1RJ/mmKNj8OT5ENrLykGqL
         Wsa3ejj/NIfZ2c6zY7M12MrBDL8J6L3F/KB2UEsLTDx4x7KA2AXJrTSycFU/5GrBvHmu
         aLwI7SPMZ3oI9QpncVRLtan04y2wTHofCAFc7H66SvVGDYojyXrMW5EmbJ9rzhioh6mH
         QScw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QutNPMwr;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id b5si341061wrd.4.2021.01.25.20.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Jan 2021 20:35:59 -0800 (PST)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id i17so18069064ljn.1
        for <kasan-dev@googlegroups.com>; Mon, 25 Jan 2021 20:35:59 -0800 (PST)
X-Received: by 2002:a2e:3309:: with SMTP id d9mr1900557ljc.245.1611635758956;
 Mon, 25 Jan 2021 20:35:58 -0800 (PST)
MIME-Version: 1.0
References: <20210113160557.1801480-1-elver@google.com> <20210113160557.1801480-2-elver@google.com>
In-Reply-To: <20210113160557.1801480-2-elver@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Jan 2021 12:35:47 +0800
Message-ID: <CABVgOS=sOZ29Q0Ut8YSKD+BrXDQwGftPeYEoON_iOxajK_wL9w@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, boqun.feng@gmail.com, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QutNPMwr;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Jan 14, 2021 at 12:06 AM Marco Elver <elver@google.com> wrote:
>
> Since KUnit now support parameterized tests via KUNIT_CASE_PARAM, update
> KCSAN's test to switch to it for parameterized tests. This simplifies
> parameterized tests and gets rid of the "parameters in case name"
> workaround (hack).
>
> At the same time, we can increase the maximum number of threads used,
> because on systems with too few CPUs, KUnit allows us to now stop at the
> maximum useful threads and not unnecessarily execute redundant test
> cases with (the same) limited threads as had been the case before.
>
> Cc: David Gow <davidgow@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---

Thanks! This looks great from the KUnit point of view: I'm
particularly excited to see a use of the parameterised test generator
that's not just reading from an array.

I tested this as well, and it all seemed to work fine for me.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DsOZ29Q0Ut8YSKD%2BBrXDQwGftPeYEoON_iOxajK_wL9w%40mail.gmail.com.

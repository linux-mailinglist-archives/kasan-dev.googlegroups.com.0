Return-Path: <kasan-dev+bncBC6OLHHDVUOBBIFYX2AAMGQE6AZKO7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24E653032BA
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:35:45 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id t13sf863989wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 20:35:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611635744; cv=pass;
        d=google.com; s=arc-20160816;
        b=VtWomMgjOaSNRS4qlJUUUmvz1GMKaW6DWwUKnRI3AG9sTJUVqh2+qzDIKFQQ/XbJ7F
         Z6p3WDk/ubqlsPUoHKz05KQ+8Elhgf0Qunmr/KaML7upxZSQuuH9Xs8C37koPCwRV0Mk
         yGCBHslCBiYCtSPslzM+qAH0IP02yCF9S2QXok7qUKqgBawjv/lsl31FCINirCJlOmD+
         FHxvmz/9pPXpCpq8309FI/XdZGzf20AsqqjlWTSmztqQoeFDPMLfr+JqkeU5p5ThubYK
         ypmLy2EL8D+/WxsvjPOtpqSxWLXgXlCgeO9ANeJfujUbc7O4aSyiuH59WEV0EbQP4m0M
         H1tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yyCvCDxizbaLFLpT6+eiBxGDCRVeW1cuseNi8RMTybg=;
        b=X9VeMIjH89U1VhHQXK5QpESQyo5/vbjgmrUhCHZplPZX6/IRMmyd6Rd7XUhA342PMM
         qehyWETzhJLv4+j2IS14HTAzoPu6rEvIt4U7nevdVDLwk2ctV4KnVixVmAlGUAsSQe1A
         aj0ZQnrMy7PsAnrpX//0SxvkKI8i3zkwhIFlYtv/KzwzyL0W24Hg3cFFpL8yrwohrCe+
         IsdyN3EIyC0vTpIGYkOlWtubo7h5ka2muvKTBhVQfkxl7cwn2W5cpQuPErW7Lcrd5lOw
         m7meQlIZb777GTvRoMK/9PV9B7AY2XcC9f0EQeSX0a5WrYR+TsY/Ms9H+qmxPfwr7fpC
         0j1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YUZQVBJe;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yyCvCDxizbaLFLpT6+eiBxGDCRVeW1cuseNi8RMTybg=;
        b=ZUc+6LLo+HNBnndUQpuxscQAI0L+HK578Jd8MrQANN7aJNX1weHe3aEMtJ7ylwciyK
         baIiOee5whbt8Fegxzgd6acO6bX/qEWorApT7PGWMLr6nmKkp4XZXYmYHlzj7+M0AgtU
         BiwfjJbkQFu8J/icXzC7bUzBcnSf+ciMj1Kffx2D1ETPKxZdeJjumEfCnlUw/LcYs7ND
         gyXHigN5W110sWaprjDwnUIMEkTjDkWs9mbWqAze/AW92/B/qfHiIKjhfDq/kZD3rJdE
         DfJUe0JAO+N7HKlvXWXTT/Y6s8jpJ2S2xj7h5JB5IfX0r59KTtLxr2WjrQUgUJpHB2B8
         FJDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yyCvCDxizbaLFLpT6+eiBxGDCRVeW1cuseNi8RMTybg=;
        b=JuakArB/mRCW1WoV1RIbDmz1bvnVw/Y0rCp3JhEZSGfXnzJWbA3w9lvV32blmbcQPN
         eZfXhJEH7xuNLkHPgDvg4sUZM7qjVmoIqpXsgNrF7twuHnP2rasgtbdFa/iq6E8X41KW
         TqbMgRQCUKVljNn1k3G+30r3ESz1yLdxNQ3evTWyYPZvb8OyBexMqrHy6xaPWD+abay1
         Xvy/+8pUnbYKUPcab0/FvVDuA74E1/cyZIWO1PISjn92mg5Jz5jMdsMkFZv96GVp0bnS
         nTMeuRvW/BP9+ELPnp1ayKtxr4oX6x67ufhC/Fpy92SGiEvmCX6d5PMAGVBerElFegx0
         3s8w==
X-Gm-Message-State: AOAM533VtOKMhNAFMn1wXf9XvDAvUPdcLuf7j906gchgnGvGFnPTcVfx
	2x4wxN50R3Oc5EiiE4y87Kw=
X-Google-Smtp-Source: ABdhPJydMGQk/ELuxt54sU2H2pADPHSpAF6OdpXtHyVnB4PtOw962p2CJSKjdLmYmm33Bp60VI1QQA==
X-Received: by 2002:adf:d0d2:: with SMTP id z18mr4166093wrh.70.1611635744829;
        Mon, 25 Jan 2021 20:35:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd41:: with SMTP id u1ls2638781wrm.3.gmail; Mon, 25 Jan
 2021 20:35:43 -0800 (PST)
X-Received: by 2002:a5d:4987:: with SMTP id r7mr4078095wrq.352.1611635743856;
        Mon, 25 Jan 2021 20:35:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611635743; cv=none;
        d=google.com; s=arc-20160816;
        b=KDnT5Ra0WNgULNX8vbnpORdzsOcMef6WER/P2IMtBLaDB2iRAgTzUrOXH2Ei3n82mJ
         M2aWIijY6QK91gtlxk+k1zRElBwDAmIUAk4uwzmu7bDpuKYJ58TKBuiQKAnZBdXQSdiV
         QP9jt1R7FeHLI+KFacSMWvVgOw7h6OXlDmuHstNPzPDrLgYZQpHboNDBPx8A+6JW9uZH
         CfZDOZctMgqt7wzusFPTe0KJRBkr4fJAwfA1Ugw04HnA/P4t/P1TrViZksey/9aA6/eK
         ynaivNpTsRW6RMPmGQzo/rM4AN7qAHlCCxsT+JqmFpsN0pznKiBOnr6Q3PbAxQX7aGMB
         4Iww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7bQPTwU7mjRvSNfreXWALEkTbnKEYe8Pe6OmRswGPXw=;
        b=QCn/7jckT262rxb0ckedwB/Mc7iamIx4Us+er8xzcM/otMccjvyJ3xYDzh+5pNK0ya
         XqW+zw3YPs7CFHZ114VjD2BSqrc3wB8Rr2SmxuYSHk9RcWC+KxeNn46itdXLF9UDLrDM
         +06/vOPpjIRLN/vPKp2rOi4HVA3H7XIGNtjpKKR24e3mbbDvOUhlzKd8y3d6UNCTlYpV
         GlLh3PiHbhFT2l4p3uo2Al5wskFQp6YG7lQpWiLLheDwfE/GQgCmCnNxhq6Oc53IuGO9
         amANBZzL4ZNzYYxqJmybSXscxf2Jm6WmMeG/NxGeHFWvNKBnT6m8J8mtQaeYSeCU0LUF
         De5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YUZQVBJe;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id s74si37810wme.0.2021.01.25.20.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Jan 2021 20:35:43 -0800 (PST)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id m22so21034020lfg.5
        for <kasan-dev@googlegroups.com>; Mon, 25 Jan 2021 20:35:43 -0800 (PST)
X-Received: by 2002:a19:8789:: with SMTP id j131mr1727163lfd.382.1611635743458;
 Mon, 25 Jan 2021 20:35:43 -0800 (PST)
MIME-Version: 1.0
References: <20210113160557.1801480-1-elver@google.com>
In-Reply-To: <20210113160557.1801480-1-elver@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Jan 2021 12:35:31 +0800
Message-ID: <CABVgOSnHh8-s+AYifkDjCDKCkkFcm=WiGSuuf2JFiMvjAU1Kew@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Make test follow KUnit style recommendations
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, boqun.feng@gmail.com, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YUZQVBJe;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::12b
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
> Per recently added KUnit style recommendations at
> Documentation/dev-tools/kunit/style.rst, make the following changes to
> the KCSAN test:
>
>         1. Rename 'kcsan-test.c' to 'kcsan_test.c'.
>
>         2. Rename suite name 'kcsan-test' to 'kcsan'.
>
>         3. Rename CONFIG_KCSAN_TEST to CONFIG_KCSAN_KUNIT_TEST and
>            default to KUNIT_ALL_TESTS.
>
> Cc: David Gow <davidgow@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks very much -- it's great to see the naming guidelines starting
to be picked up. I also tested the KUNIT_ALL_TESTS config option w/
KCSAN enabled, and it worked a treat.

My only note is that we've had some problems[1] with mm-related
changes which rename files getting corrupted at some point before
reaching Linus, so it's probably worth keeping a close eye on this
change to make sure nothing goes wrong.

Reviewed-by: David Gow <davidgow@google.com>

-- David

[1]: https://www.spinics.net/lists/linux-mm/msg239149.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnHh8-s%2BAYifkDjCDKCkkFcm%3DWiGSuuf2JFiMvjAU1Kew%40mail.gmail.com.

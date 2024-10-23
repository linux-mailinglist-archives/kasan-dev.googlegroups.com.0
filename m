Return-Path: <kasan-dev+bncBDAZZCVNSYPBBDOF4S4AMGQE7BPQJZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B402D9AD009
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 18:21:34 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3a3b45bfc94sf67165385ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 09:21:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729700493; cv=pass;
        d=google.com; s=arc-20240605;
        b=YDmPWsMMaUv0awq7pRV3+lXemrd06LQ2I0TrQ39jfLHMX0QkzDgAVbmxFxCiMa+PAA
         LTKfCHeI9BFCPAfoK4RFJxDtjpn4I1o0TSZIzv/5sE43/Q/CqlmPsopGS6YLslQlhs0J
         fLmly18rN+WH9SPrdKpfbMuJtqjEV6Ju/9DzxbO/DPQNwMB3orqLNkdAEp2jwQbJWaxu
         Bcu8ZShJmgIFAfgs2gZ8h963bnBpuS9O01vREB8n2xr6msbKCHunPTMm2aRAadXRlV/L
         Ank07B50qOQv/+XObYsMIelR1S9/eDiuq+ygjWlb4nMwvHc5azCgl7H7i1foqwhnR8Lv
         bYwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=J0B59usN2uSOdv61hXSAy8wTwdyCQFzLnzpbUQCpvFg=;
        fh=3LtyxyVPMokdjZ+yiiRv3+ndA6ZD1bGRYuAeU4jgTj0=;
        b=jWIJx4dGITW15kDkIYznVGyMF2RnvA63G4yYcn84tl3E1dzhx76mw2DVjWIkoGgyN1
         gYVq1plQCyrhKPKSUMAAz2OE4Waj6t8r4iwmkaZIKk9JFdguNWKZgd7bLh4+OaMDuNIh
         oraiuYaOL1ecAR/A/IY+DGkwF+tiNhO4+88gTQl0cWD1r04CvYybERpctx6BN9orFLRB
         yfNYPz4ROMVUDGQUp6b8AwlCl/vkt6CNAiQAZ+P10fyYFcKhI///4FUunD/ffZaekGsf
         aIE17psPQJN7boebiTlBS9uAhc4sSi7I+MN6YXVpCV4ZuQoG8FrkWCd9hD2Pv5IUR8ac
         uMJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bpf4Mu4k;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729700493; x=1730305293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J0B59usN2uSOdv61hXSAy8wTwdyCQFzLnzpbUQCpvFg=;
        b=pfUs+bgKrpSr5s5lyr+Rpxzbpb0pv3cq071qU1Oo0WKi6cfHWj0DKB/Sr4Cx0fDlO4
         NONbT4PuK4VUlxUgPdNNYaRO4aLowbWL7VFp3r1k7WT1xpbHjNtYqVHj/9mSeL8b7VjP
         27C7rT9xcrtBp9KjGhak+JWBihDTZA+FzyQS1KYXlKcxWAV5w2kyUw6SaMuO2v6ej2Um
         gwWZeSkZywVmBKfn13yEP2Ww3Sk63YHUNL6KLFJ4IXA8AXwVKPNTOHxmzIchRknEV0bC
         XgDjMm/EYY4mKxaHKUI5u1NmYtOMQhDaAPUOsF0cpr5iA8OnCBs9h26rKjMUlwC+XkKh
         tvJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729700493; x=1730305293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J0B59usN2uSOdv61hXSAy8wTwdyCQFzLnzpbUQCpvFg=;
        b=QGn+p1lnNlrgvToPN8J4NLtzR4k72lg3SGJVJ98rCQ+4Ji4yXCDsJJZh4I6dZYxhU7
         IMm9oowyN8e5aHHU40gb0A2OJIHL02D1xIrv3VAmzU2XXlZoqHvhJ5xbEegvQVCDVFLc
         ykqyVjkIdY6mRBIdFv4d1dgfU/Nt4a/H0d9RyUGQNA5dqJHgCJyA+D0f4HncOx/Jf32Z
         AJYRTNq5USQENdLgm7J/EgrJ269Jq2gCK3+2sA4ELfs8PYG29e37CkaMxa7fgzQ09u80
         kqk0tFTWEzotIdZz3F2SaBScjH8+5bO9q/4JPE0HmC8so8iKNi60SCi2JA8O97KSOrP6
         TxEQ==
X-Forwarded-Encrypted: i=2; AJvYcCUfIl6nwhwMJ9X2kuFqTVTsCdVZrrFjdk6ci9WBvU19E4rIvou8lOixuFOcbfVD+sJAdpzk5Q==@lfdr.de
X-Gm-Message-State: AOJu0YzFgFhtymktQeNVdwlOgZbe0OEGY4PQh5kORriozsEPCzpees8F
	wF3h3oY1rTJokBMLcB7bn7YRfYRh9KcuCeTK703hMq6lu6c/S9Q3
X-Google-Smtp-Source: AGHT+IFa5W9q3blDVy4/ydFO9etp5epFnCcN9kKjxWaeMpTQMkrhHNznugMwHsqhtYaqq6znnikkWg==
X-Received: by 2002:a05:6e02:1c4e:b0:3a3:c07e:e21b with SMTP id e9e14a558f8ab-3a4d592c723mr35614195ab.1.1729700493355;
        Wed, 23 Oct 2024 09:21:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1785:b0:3a1:92ef:d7f2 with SMTP id
 e9e14a558f8ab-3a4dc7f8e56ls187735ab.1.-pod-prod-07-us; Wed, 23 Oct 2024
 09:21:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfV4+G6OAEygB5SVr2Tos7vxL7h+0TFoOBlvj2nO0kIaIwnqbVqFyy/guIxrOTXZq9dxTc0cOr7ew=@googlegroups.com
X-Received: by 2002:a05:6602:3c7:b0:837:f951:38ce with SMTP id ca18e2360f4ac-83af6193dc3mr404001239f.8.1729700492444;
        Wed, 23 Oct 2024 09:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729700492; cv=none;
        d=google.com; s=arc-20240605;
        b=HP3QuI9hjk9A5sL1d4anrChYdfV+Cl3C6+2zQWRdS0RZp90EN5wITBEs9HZfkwqsep
         lU68DLzxy7q0ESJRLuFJLxgiPWDlBC1eYL8AdKkaS1alI5kvUrc7d6RmBxdX8BJ2sh5P
         RPzf/odtW1CffJtiEwZUx2zH0/gatfYlewaaD1/xDccYOxhuZ8B8uNAW4ysT9P/v6Nca
         rxUgyCAgbLzBc1Hu/R+FEFg7oznypPE9nDi/lIxlXdkQ0b/ojzHP3Hx8qpWypmenPie/
         5nuoBeJHX4PJ6Zf8IsCgoK6jpmIlwmFzhstrrp2jlOUB78sCjuUH3duJhCi8vVEehkhY
         7VzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WH2MakY+LFOkgpgUYeHa5H+ibnwxR6eO71iY+dDn2GY=;
        fh=GJdOthScEpQsR5Guv8j7C25uPfMY25zMyncWCl+cTOg=;
        b=DbFsWHU9Lhqtknh8Csav3H21m1N/4XtP9ecTYodoL9vUXre/dxCJf5dDxfbzBTS5Dj
         LxTKqxttwdrzInJr0OkKqzrZCxNi6yZ+bA3PKv+5oQ1Ppxg+TWTInvEbFE8uhZM5n/fL
         Yf5fjz10/mcMC7xCzCzDMVcK+kO39nrODmFaEquO1gbIGwSx3wcWZr/BhF5LCr3J0Q6c
         dFOTSu6+hUfROOowRi11yWn61nGjOvSnym4apBweG7l3kdxd2ihPrFxy9tOVYvC/nvyz
         t1LBFVxguTC7YTg7l2e8rG/AmkGwMM77mTmfyMxMyvPJgKDc9IvdPfQ5hoxSzDvyKSKO
         llQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bpf4Mu4k;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-83af19de2e2si16917939f.4.2024.10.23.09.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 09:21:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5C3235C5C37;
	Wed, 23 Oct 2024 16:21:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29336C4CEE5;
	Wed, 23 Oct 2024 16:21:29 +0000 (UTC)
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: catalin.marinas@arm.com,
	kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
Date: Wed, 23 Oct 2024 17:21:21 +0100
Message-Id: <172969587091.1722746.16856042092493192617.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20241021120013.3209481-1-elver@google.com>
References: <20241021120013.3209481-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bpf4Mu4k;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Mon, 21 Oct 2024 14:00:10 +0200, Marco Elver wrote:
> Per [1], -fsanitize=kernel-hwaddress with GCC currently does not disable
> instrumentation in functions with __attribute__((no_sanitize_address)).
> 
> However, __attribute__((no_sanitize("hwaddress"))) does correctly
> disable instrumentation. Use it instead.
> 
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[1/2] kasan: Fix Software Tag-Based KASAN with GCC
      https://git.kernel.org/arm64/c/894b00a3350c
[2/2] Revert "kasan: Disable Software Tag-Based KASAN with GCC"
      https://git.kernel.org/arm64/c/237ab03e301d

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/172969587091.1722746.16856042092493192617.b4-ty%40kernel.org.

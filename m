Return-Path: <kasan-dev+bncBAABB4MGTSCQMGQEK2TWX6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DAB038BB04
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 02:48:50 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id d30-20020ab007de0000b029020e2f98646dsf6616427uaf.5
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 17:48:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621558129; cv=pass;
        d=google.com; s=arc-20160816;
        b=S7Cu/P1NANkzqrJT/XfUC4RNYSI6c0P6UnxOu90vFUQ1TYbkkdjyOTbPzZ1Wyag6++
         DWxqFALgq3UsYP8qznEAVwuluXdk0i7NaDGlSaS2NpvrESlf6BQzW92KlYvchTNX/TWp
         XNOdY+nupae0REeQZ8y379CIs662vHvAD1k2/HXXK97LOyqS8AaxXBiutZH9Gg6bgXA3
         iA/moO1i3JQrUI8zHy1tB379MUXu245pef25/fbJg9Jj3p5xlR/TnmxcOaw5DdmVGKSg
         6tuaffeja8qlakROQ5vSUfFcFo3LtGzsMk516xEFdg75MLQMsuoeXD/7iRWwkhQpexYf
         fzIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=7f7sfW1R6oftapkgeI0EfDucdoGSSi2PrnO2gKOioUg=;
        b=PwpQLca9zW9r50W6ayWxkORgnXFt662fAzUYPyS/5G8l8wSBryDJb3MkOe0Hcwgszd
         iShLTKn+z0445chIEc9HIv3vsWMacdieGCIKrEPExw6zHffrMdHDGvz0h+1mo3tNfhZ9
         f9+eAfo61LCjimdAPi6HAFcGrvbgpZkLBbCaTUHu3bCPrQmaOvXO8Wl9T4lqK/ZWVhFN
         eAOSV3cD3wZI6Yn6OILLTaxwKjT9FcVZLoLB6c6G3SMo3hOzz9J1Yc0o5KVCT3pm9/Rs
         uu1gjdGA/Hh9P20PuHnlPV8wdNHfiu94KBrvCF+BZiXvjSWec9pjvA9xAbH9vBNCblbp
         y5jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AxmoxEEc;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:references:message-id
         :date:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7f7sfW1R6oftapkgeI0EfDucdoGSSi2PrnO2gKOioUg=;
        b=WJMP2byeaiaf/2c1odRMu3yi2ssbA6xzzFVWd18QJAeAF+sctF9CRxu1BGzGxh8gFP
         EWKTXemFaa2zNE0FsceRzUtDAu2xoy1+v4veY6idhgJM2LBwBfm7aJvMZ3l6ZntOS1nW
         BkbQC6aLN7tzWAZZwABbhx2AdTdDC97sO5PSQ2Bt5dWU602EkgeMOvmnpMvERKaWH50d
         DUC4VkvNDM/R06QATg4CUZ9V/9MLXp0RsxKiUWg4maY3I3T0QMminHXa+jOYFzdEJQxC
         DQ1FN2lf/5uQIzBSt2jLhSUa2UpWR2EDejkIvbAKlisfV9Nlvp+M5XgF9yzpFsGSXskQ
         wT9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :references:message-id:date:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7f7sfW1R6oftapkgeI0EfDucdoGSSi2PrnO2gKOioUg=;
        b=kQECDTLeEjlHezDq9pj62SWzaTWoa8pib/CwChmG0xtGxZ81LAFlMmVxBfSXGU/YXH
         n/XNDDRCh4vzS7ThcyUWTtfIl1Vbhxr+TDkViA56/jZGwqdFnN5E4Y0DodUsuYP1Ai1M
         MatYGmvRvAhvQrbexu9W5bnOuA781pikNL0LTSWTeVxncSRHIUPM35pzoDU/jfHYGQgD
         ELnw8Pf/9ArZVU3qk5SXm3qjG74/vlTyJW21gAEfL07/IMXd6AL2UxcY6csfM/nPUSSP
         3yoU9jC11TluslqY5hm5tFRKayS1dWglKpp8kYiLXe8appT1Uqc0jB0EP1ZYGMyATxCn
         rBUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XRBmsggun82OXcg9UFfO44+tO3hok1dTmD9GaiqvsUI6eyL/G
	2Uoup+LMvfiWSLIIS0fVuQw=
X-Google-Smtp-Source: ABdhPJzrchn3X2bba+5P7FRGdn4RND5O1/kJh/qVnBZ4zI60UkSX3Sfvin1rIyyxPYF8/e/83WkLHw==
X-Received: by 2002:ab0:132a:: with SMTP id g39mr7406117uae.53.1621558129108;
        Thu, 20 May 2021 17:48:49 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f74d:: with SMTP id w13ls936606vso.11.gmail; Thu, 20 May
 2021 17:48:48 -0700 (PDT)
X-Received: by 2002:a05:6102:c46:: with SMTP id y6mr7258916vss.22.1621558128630;
        Thu, 20 May 2021 17:48:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621558128; cv=none;
        d=google.com; s=arc-20160816;
        b=rwp+7RfyTY16E6GBDowphyUZQ/68NYLeV6creuNvSGF9VzMGC1Fn/xlaB8CSQWkqxE
         EN4CNtDZBEcKNyT0fT9VNdgMZ5MA2xKCN9IMNm5Vw0W8Um49RQOPxITKCNqY6rlnVKwH
         PvNIaKMAjYHMJas4m1WSGDgcMyQp8HNPlsnLgGxb9q0n/gXCpOyi70IhaPSNXhery9/+
         CsJHhCgcZUlSCO9VFDbIA+6E3sgFQ6aql1eU0DZbBzUDkbADWSLByBOHac/+92Cs71Fc
         luB7agVKVqx9fD+MGikUSZliwM/qggoJS0G6HcOhQlt9sPd15PqqU8zgBac7k9zSf+mL
         U2JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=aaE2/HwwdBmDRW5FgMokZ5sUjw+1eHzCAAmub3Xp5bg=;
        b=NJfWYd0/tDuUfoI5NloRnpngEB4epsyXk86yGvggy4k9bFwawtI2yjvSHLvl384L6O
         lahKBWLtuEHgoHdOgDI4pbouqPZM/PY/0p0YYHLJdKS7wWS50MGNmuwq4b3dDwDMtzvq
         i5AFHDu7IhsZUKMbM9EDx/d1xgRq9RK5aY9mPSNopX619zuPv+kYiMc5RSYYokBAQg36
         n8HysxfE3IzfQZe7tUpDDMRjpIm7PzBa0Cd351haQjHlBaPGsFaNh8nkYs2ECiulirvI
         23Lllwimx9rXcsLAuuFypYOngllTcx/iG2znt4dcXLVZQ3tsUknh2Q25BHiAT7EyQSP6
         eCZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AxmoxEEc;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a6si302702vkh.0.2021.05.20.17.48.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 May 2021 17:48:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 7F2A46135B;
	Fri, 21 May 2021 00:48:47 +0000 (UTC)
Received: from pdx-korg-docbuild-2.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by pdx-korg-docbuild-2.ci.codeaurora.org (Postfix) with ESMTP id 7691A60967;
	Fri, 21 May 2021 00:48:47 +0000 (UTC)
Subject: Re: [GIT PULL] kcsan: Fix debugfs initcall return type
From: pr-tracker-bot@kernel.org
In-Reply-To: <20210520200127.GA2227122@paulmck-ThinkPad-P17-Gen-1>
References: <20210520200127.GA2227122@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <20210520200127.GA2227122@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git urgent.2021.05.20a
X-PR-Tracked-Commit-Id: 976aac5f882989e4f6c1b3a7224819bf0e801c6a
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 921dd23597704b31fb3b51c7eae9cf3022846625
Message-Id: <162155812747.12405.2567574231982570128.pr-tracker-bot@kernel.org>
Date: Fri, 21 May 2021 00:48:47 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org, tglx@linutronix.de, elver@google.com, andreyknvl@google.com, glider@google.com, dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com, gregkh@linuxfoundation.org, nathan@kernel.org, ojeda@kernel.org, arnd@arndb.de
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AxmoxEEc;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

The pull request you sent on Thu, 20 May 2021 13:01:27 -0700:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git urgent.2021.05.20a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/921dd23597704b31fb3b51c7eae9cf3022846625

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/162155812747.12405.2567574231982570128.pr-tracker-bot%40kernel.org.

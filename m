Return-Path: <kasan-dev+bncBAABBIOFW2GAMGQE2RVG5BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 07B5044DE4C
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 00:09:23 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id h15-20020a4a6b4f000000b002b6fa118bfesf3739520oof.18
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 15:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636672161; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6TZTgi7IQgiBnSOmL0sNOhG5oU0UEXLHNbpU1RClo7Gr2cDo07IVJrc8ViTAA3d4n
         Fcd0NEpnS22IBmkCrImBZMFmvYPIIunhZ1VPFiEzuWA9NOgj4YOh2sCQr1Ui0Oob0mrW
         ONkhFGgxFBF0lT9d+iAUrNOWQMZO2QK6W19+Ky0vWRTltVCGsv6Ad58b1rjZHdkaWnrC
         wE1wszZmZza+8YCSADBWqIKBl305l3Xi+l23WK47J4iC5R2BSlHTxyWWWDFqwDy4fRiE
         ZVLGxaXKWy19YNuKLeS03m8RE5URkmMEWEnxNxOghZGB7PB4/lgIbftFl0QtBUxdBCKa
         arfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=Idw5moccwHEFxjSYI7hOFb2wKEcWV0T2g8/a5jk2oJg=;
        b=nvekQiN/jH/kKHPJkN2xWavdeq3FG0P6bC6CkiRjm/3lBHLkqJw57Aa/Cl5IPqY0TE
         niaauGnWOtY0i7jNc06hZgdsYqg07xja5DvFernmoJGcIWmdMicKJIcCiN+z2CG29/Kp
         McPQJTsc+IprxtRAftClmaK/Zi9o3h2V0xWQGXni1BGOr05b7/TlYu4mLl7j2zB8ah6M
         CKeayC6Emn6/2v7pTA5a+59Y6YLJ+TUuHQd9Z4Tn0De0Vj+7yTS5noYMbuDDlRVb5PSt
         Khzz117zSIX2hI/VwNrWJAkh1Us/FUi1BQofc01iwGCoEBFOOGqZkDxIYfRRDCXN7YFV
         2W2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CqG79oU+;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:subject:from:in-reply-to:references:message-id
         :date:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Idw5moccwHEFxjSYI7hOFb2wKEcWV0T2g8/a5jk2oJg=;
        b=FzP1ThaUl7yCJJId9VSSyrNon2nV8M5cNtwZpJBugKsdK0LmqU2ncdUcUdmfMtv5PG
         bcAScLubVkqbftH+dJK4GsSu6Yij9qDOlyulT8+aBRguivdgDMh20aBTXWEmsNCK9sEb
         wNzWYbjDBQCQ10SbRvJFFlQio6FvzTY6hlyVuaJk3gSCoKoIsoEucFG9toUSJ0F85FOL
         vSxXUDIcX+T3x5+0O1fEPEk+72pGrh3orp98lDwL994v/Qk+mEfKesqiMEIGg3SCfGZp
         a3WQpqVzcQlHsQfmPpdhre08ncCO7NP7wvNQ01BWmet0JVA0L25Tt6+FakJZsNW4ngde
         rvTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :references:message-id:date:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Idw5moccwHEFxjSYI7hOFb2wKEcWV0T2g8/a5jk2oJg=;
        b=nw4HNd2DhQfNWxYAn5fJTnlJEKvNwPb6CsSVhzu7/WjNPKuITN/au0ITQ8gwNzR4UU
         gxEWdgGUBJmm0QAinnDlwIWQanlHdNLIPB0jQQgiCQShfNRkm4l8Qo/u1N5/novfIbgF
         OeuuAygAjgTUEv3bz5TgjhsxhlDz0D10JXfRt5l0HCM5uqwRXKjVczUUidnLa79bDz3d
         HLFP263wJdjPNFSwtg5v2zDmpiANovfEsX73F6aoGK6Fvy4/Abom2C6txuDEXeeEokME
         y6uBT0pZFoqEwfn4Ivmgsd2C6X7p81RW9DDzZZhXy/huYeI2v63Y0shE3iB/99PVtUmB
         Pr8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530odp4MR1EoA3izjqQGwsranhDTQqAWqtBLtzGSF2Gs2U9MoTPy
	Y+5WDSmzZz/bFajAfk9ErXY=
X-Google-Smtp-Source: ABdhPJxKSMNbyemQdPRKTI+Zok2P+W8fMniew0iDeBbaJ4fZm6x9TC+MSfIeU77u/ZW2rOiq2OkynQ==
X-Received: by 2002:a05:6808:205:: with SMTP id l5mr9368173oie.164.1636672161711;
        Thu, 11 Nov 2021 15:09:21 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3108:: with SMTP id x8ls1281715oix.11.gmail; Thu, 11 Nov
 2021 15:09:21 -0800 (PST)
X-Received: by 2002:a54:4e93:: with SMTP id c19mr23179221oiy.11.1636672161360;
        Thu, 11 Nov 2021 15:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636672161; cv=none;
        d=google.com; s=arc-20160816;
        b=cGLY6m2OpUnrGAnotmfQyx9PkPEG+WCNOiN5M6Rk41PlxcEkLJrmberyyAIbj6OOxH
         wJQRvOG321kFC898xI/Gc+4R79h6A08Ktop83HVO+oTMQ/6o6UI//Oc64Uk4h0Hoc4gh
         sMZ0JUgc1rsMbQXRp4A/jl2o0G9H2ahnk3yswqiFtwXASG4QSkvJZCL0K98CgFZwDRRN
         CaD8FJItD1pXnwdu6i0Rtf4SEkJyF90iCmBae2+PUK89gQ6cbpXuYzNReWa4aIkVxkIE
         x8lhP4XZrYIrQmtHCWE8nkTbRoU0VYQxInGZnkxBINnDVswcfHw+UPw8hdYP/F8HyvtW
         6vyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=fZAZOg+HrsFZsTVrA0xBE3maIkvKUF7jNTyhsxsxDqo=;
        b=OOs+XTAMPFdB1vnlsQHU8zc9mk8u6MenaTy9Ho2Wy5n1VEYfB1Yn7ksQ9IQeUUioKG
         16o2v1xfMFCL0oma0qax9VbmoIGdsvrLrTfqjNDi1gBf6PracVGbxdl+IsW7puKGeQjq
         Zwgdw3J+lkcp32CURYY3v/XrD9miPVWKid1CowfV6xr9oo5CT5bga5jKFOP9kQdT8oTx
         eV1W6LmhYwoMhKSXW3mQTTHHZLzBzs3CPEhd77zQA5F2qQlb0vmY40DNJNkhnPQIaNnu
         OaBLQudQqTeFKIzlGjkeIuvI2WE5nuMdvbkqRur0fi49VJj9yjQKIiqxUJtkjMRPJgFZ
         VbNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CqG79oU+;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d17si619636oiw.0.2021.11.11.15.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Nov 2021 15:09:21 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 915DA61989;
	Thu, 11 Nov 2021 23:09:20 +0000 (UTC)
Received: from pdx-korg-docbuild-2.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by pdx-korg-docbuild-2.ci.codeaurora.org (Postfix) with ESMTP id 8A46060726;
	Thu, 11 Nov 2021 23:09:20 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v5.16
From: pr-tracker-bot@kernel.org
In-Reply-To: <20211111162005.GA305579@paulmck-ThinkPad-P17-Gen-1>
References: <20211111162005.GA305579@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <20211111162005.GA305579@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2021.11.11a
X-PR-Tracked-Commit-Id: ac20e39e8d254da3f82b5ed2afc7bb1e804d32c9
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: ca2ef2d9f2aad7a28d346522bb4c473a0aa05249
Message-Id: <163667216056.13198.4431266640784297815.pr-tracker-bot@kernel.org>
Date: Thu, 11 Nov 2021 23:09:20 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org, elver@google.com, andreyknvl@google.com, glider@google.com, dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CqG79oU+;       spf=pass
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

The pull request you sent on Thu, 11 Nov 2021 08:20:05 -0800:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2021.11.11a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/ca2ef2d9f2aad7a28d346522bb4c473a0aa05249

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/163667216056.13198.4431266640784297815.pr-tracker-bot%40kernel.org.

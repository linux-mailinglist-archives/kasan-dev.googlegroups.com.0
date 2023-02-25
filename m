Return-Path: <kasan-dev+bncBAABBLHS5GPQMGQE6347TLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 848E56A2BCD
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Feb 2023 22:10:05 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id j6-20020a05600c1c0600b003eaf882cb85sf1124305wms.9
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Feb 2023 13:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677359405; cv=pass;
        d=google.com; s=arc-20160816;
        b=SpwoZWja3PWGCxWuZ6oHkNigk2RL7AjN9TMU08L9a+iUCZ3l2RdCy05Ori+7KnTq5i
         Q4T/i/AJ+vK0wJTGjUOfApsEL5rJKX262xJ/4xGz79FJBqMoPE/4JyQJbt2PM1bII5Nn
         uWIGTyxSsyqs7IKunGbXGmqo0yfKvHxe/NN5SU3LCF6SKMY+AddC6Jl7TEhD4+5k9eQy
         CC70sEIKmXbqt16kmiROgtMwJ8ecQ/fMj98mHhJ2puu7Vu2zxb2usQ+m44b1O9cfxXUX
         0U1oOk+E6BpYqd45TJCFGJnlg6kIDPwO1vTvYiupDywzrl8tiWwhwm4IwCMw3hTgmwYL
         W6gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=3d87IMmEM5gIzqsfaqUouqWgL9N93b+dnLHm59pDKg0=;
        b=PCAk/Uf3qIXMzyvzpM/8JOPd+q9Ns6ncWClgy9pkBP/eT3qlkN/ycgam3j9lSeEljx
         pB1oPHvlOcSg+goFG9Gkc9CYaqxJmSrwr/lblbfj6PLhr+oXXMsV3rc66Nwh9mqQgOPV
         r0aFf0d71XkGmRpgOHq/G4o1nHPh07UNwHOIN62FWTZRE9iq34mKepQpgZA/Ft9laArb
         6kgEiC2LGdrUlmhsv+kjj8tG6aCOcpscjjW5gU/qWZrk5mdr9ShP3jaY6MvK0E9xCY1M
         L4IHkM0gZLkFLKiTZpqUxajGL8F0ZvHhmoIr7LCnPosnY9lVWlqup9Q+d4qNOXZ7FdQ0
         KFQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="f/g/cfja";
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3d87IMmEM5gIzqsfaqUouqWgL9N93b+dnLHm59pDKg0=;
        b=YvjxYUi2IaQ3exTBwBXWlf7pN8F+rvq332oQUOIDwxRhoNjfzbNjmarlWpsA0RDPta
         eMTFG7sUkt0b4IbPlazkYbZ+97zC1dzw4w5srf/DqZy7IOvBCrK9IoaFb/xQVkV7Hm1s
         nfmMHhcQ70Nkdp+Lb8csBc2et2qyChdKlUUrB+eW8Gy8fj7BmUTZ7g3oHpXBx5TezajN
         fMhswnG8An7IuxXoPuIsCFqxhjr8RmqJsqhojbvKhwamMUYpIyCgTdinMIUN6igQgfRZ
         fTvaTs2cY7UnMLNDcAgAJYnQMzAKGpKr7Obq68JBof1FpYOOivrurXYpzN7W05UPV77P
         caxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3d87IMmEM5gIzqsfaqUouqWgL9N93b+dnLHm59pDKg0=;
        b=JpL9oNxuarj6XhWx6qFRS5LUtJ9qvwDvqy2Cp6FOLyENspeaznxdwpPQ4Fp3JgtsaB
         GS2SRxPRXcOuRZQqNF70m4Xx1s8HkbE6SzG4DZsaxB6Azp4N5vONwPAof6FRoZQIONzL
         htxCUMHaPo2gnEwB7YvJrdliAih4qK7eLzJq/+FP3T9gz1qZm4eAnYb8ULrO/689w3EX
         qg/qp5Baoa6IeBXOWCkRcyE+48OVg1JnB84nWn537QgqAA7VrWsNiyo2/iP4z8QGUeKp
         Fwl3aUxvS/lfgO/WSX8gDgBRWlJ3Rm/Zcdvm8xFilBRuv7rKqvtBv9klGwKMN+x8nalH
         YrBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW+S72zI047OMiHmlWd64KKgO2AHXqXkoVH+xR+zREBreWK2O69
	Zk+uIyaSWHs2bvfq6pt94uI=
X-Google-Smtp-Source: AK7set/GHAnXY0aw7WxM/v6ML5+v3Z2HTq52PSiw3Xjq2Hpa9RbcEsqkwQgGzXeGi7hY14dMIbgVow==
X-Received: by 2002:a5d:560b:0:b0:2c7:4ab:37fb with SMTP id l11-20020a5d560b000000b002c704ab37fbmr1899472wrv.2.1677359404662;
        Sat, 25 Feb 2023 13:10:04 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4d9:0:b0:3cf:9be3:73dd with SMTP id g25-20020a7bc4d9000000b003cf9be373ddls5607534wmk.3.-pod-canary-gmail;
 Sat, 25 Feb 2023 13:10:03 -0800 (PST)
X-Received: by 2002:a05:600c:1d96:b0:3ea:e7f7:4faa with SMTP id p22-20020a05600c1d9600b003eae7f74faamr6602370wms.26.1677359403655;
        Sat, 25 Feb 2023 13:10:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677359403; cv=none;
        d=google.com; s=arc-20160816;
        b=O/YOl1strMZqOH3itT3orew050oyvQU+samlPxtTyKuLeUx7T11hgNmVaFdxteIc4R
         TBeRikLMUKvvwH977xHnANMmWpPmDJfEhCKl6J49H0OHVNL9fTi8GZxYqmyB/0iBsJtC
         mqiS63/GW6dw2Zmc+xGTDqEbQ8mlsjkWSNHNLTiiBdKwPXRHqPGtZ3mOzS6k9aI1XszJ
         nx13c2GKkcZG8BJpmJgnu14Qm8cKyzmWG8XDAKt3qjS9B2YBaDEyGoz+k0gNCiKmqFiH
         A3qnr5hVuzyQzwASwYMqOysWz2jTJ3GN8DQ3v0j60frpVCdxIjnFPnXMp89hHHtDFkuh
         YkcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=ccLCJ1Q3L6bHm3wBqEfOZxqPQopCF8IIDdHCWRKy2jA=;
        b=qxMVcfHvThe0faREGgwPly0uzSKx2OlxlizwWvKiDcY0zHwcQYbjgNZcii0kSDI3dz
         pQwcPPqHzDihdaZg0BwdYBucZDjR7V4hpgGpCtt78JCfG4lFWf87SGXUtUP9O6JxFk8V
         +uCRNZMJQiVDlzQPKdxOYCJCmey7WzMTwV7B0uRIONX4VOn2/QRp5wmT0NFt8kJu4Pq6
         DVsXMlBrTQUWXrqorj3ud5UZG14+In8BnQAY6zuAO6W0+LLLT6KlRnAeIB/YfgZAisdR
         RjEDUzMXE7afx9SUu62uZtxf3gJvRQDBOh/q/clKY3vqlkKB0IuSzkqRZMY325lcJY9W
         9BIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="f/g/cfja";
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id l2-20020a05600c4f0200b003e21b96f27asi223200wmq.2.2023.02.25.13.10.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Feb 2023 13:10:03 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5FC59B80B33;
	Sat, 25 Feb 2023 21:10:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 188C9C4339E;
	Sat, 25 Feb 2023 21:10:02 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id F06DFE68D26;
	Sat, 25 Feb 2023 21:10:01 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.3
From: pr-tracker-bot@kernel.org
In-Reply-To: <20230224182703.GA635892@paulmck-ThinkPad-P17-Gen-1>
References: <20230224182703.GA635892@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <20230224182703.GA635892@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2023.02.24a
X-PR-Tracked-Commit-Id: 6ba912f1c081448cf3d1fa9ada9115aae4594ac4
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 0447ed0d71251e8e67c9d15f8d9001a3ab621fcd
Message-Id: <167735940197.13638.17690529997684329457.pr-tracker-bot@kernel.org>
Date: Sat, 25 Feb 2023 21:10:01 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kernel-team@meta.com, kasan-dev@googlegroups.com, elver@google.com, arnd@arndb.de
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="f/g/cfja";       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

The pull request you sent on Fri, 24 Feb 2023 10:27:03 -0800:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2023.02.24a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/0447ed0d71251e8e67c9d15f8d9001a3ab621fcd

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167735940197.13638.17690529997684329457.pr-tracker-bot%40kernel.org.

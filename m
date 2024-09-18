Return-Path: <kasan-dev+bncBD26JKWO7EJRBY4VVK3QMGQEPRVVT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id AC8A597B8FF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 10:10:13 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2d8a1e91afasf6979390a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 01:10:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726647012; cv=pass;
        d=google.com; s=arc-20240605;
        b=kh6xB2TWJnmGmLTBoXcY5ZOY4cR8INSTMj1bjKjp8hWoPCn2YFOS1ymfmbLofn4yDv
         ir6IxnxDpsWjEjpvCSV1l81NMkoPuhrF4WkUIxioGS/TvRY4a+n91pZTAyyJZ/9StVOL
         Vae1GGJp4TrIIAYPlokQenAwKDBNzqDkymWybOTX3TS1zitDFneQIEwKGyy4jB/j1eYV
         h6wl7HxsSREJI4o5VZuo1sNE4F6e5dWWVVuodKYNo0dUGYok712twYpnYn+r7klIyR5R
         PnHoqbr9m/jcY+WDWy0VweO8Iw/vw1vToYieT1Ea54SnEaXR7FLTuMzSCKSR5dD0GxT+
         Z9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:date:message-id
         :references:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=SsvIoAZBiE32xBmpvGNhyM1qk2/hNoaJjP/ZEeY0N30=;
        fh=Y59XVahv+RR/r7wgT936dbSn3cjgS91jj+KaOV6TMs4=;
        b=MSI6POww24Lj09BXj/HSd0qY1JaQAHduv0SkZ/tCkAPdWdvuHEZ0NqGYgittsinj1J
         Z6MMAmWag+azE30vcCOVMjG6wjRUfnSsXWPbXHpwbQ/TGJHlRBGNxrjxJmBHxDrl6x0F
         7PPbos4WK0CjTvQZnPt+jmUysrHAiE+9Ti6D/5WQRQywuFj5LBifpXs1ZxElup5VasYz
         Di397KcWsKVu4k+KtkDhDnCF/NXJi9a7gz9VFMvkbjmEkTXo0LgZCMcYg1veZqHmTzsk
         M45EOb47R4LjA3EwSsf2QJ9gN4UABZc3HW9bTJSBwoY9R/FnTo1Sd4A88wuD0LWpESGm
         4mYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tm6xn8VQ;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726647012; x=1727251812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SsvIoAZBiE32xBmpvGNhyM1qk2/hNoaJjP/ZEeY0N30=;
        b=SiHKoZc2SYQAujO6AkGx90l9VkP5zTAnKoNKhFmDaJ64J355GK/SAFzypE3tV9s5Qm
         bir+uY0iNiV5a7E8QqaXpwZMZSH5bANeAw0j/F7RQIZ/xCIWmZACLqkWGSiqthpLMQqc
         Y54TFzMCvLnnPdjsUhFpBZYuMhgFz6EpA9t63ib1cIWsS6qxsLH8AKgXTYpCSrfDyBbf
         +mu/vtgqHihvpryo9rtuRxfiszcFkIofuybeBpeJ8gzK/nK68tEL8nXkbODBv/jtFZ+6
         pXbf09/XoMnSJbHggVRF/pgAc9pwRjL1uBvCM5j4X5XaiEYbNoCuHkhhmyZ/CG88KnmJ
         PN9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726647012; x=1727251812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SsvIoAZBiE32xBmpvGNhyM1qk2/hNoaJjP/ZEeY0N30=;
        b=irseme9Cfqrb5qjjW8KN+XokwHyLxY4bmGSgD2HTvs4UwRMdZsSd1cCF30uJSykxs3
         AvjbFZ/eGfymB9WG2Ao2cv7GeYEYQSfqI/fMdXEbF/a/SPH1D4iAPPsLn2hwe23LsEhl
         t9vGf2RscohsK8svwMqhoJ3ri4Plc7G3DYVjBC4WAr1AvmNuWRattSA4HHQDNg2GRTpk
         C2rW3gBlYUcGn72KSfDbsoDbp91nyQjFm1sWUBfIpqg3PGyO7K9MIckVV5sffM85EPG7
         f6LE00Y/bSgxJ5mG99e4GuwOh4JfiE+cVUjXR6GoIG0NjwroP8Tlh7MVSefVgle354SN
         8PTg==
X-Forwarded-Encrypted: i=2; AJvYcCWcJPFthraUQ3DUfWysp0K5Ul2s0ROW64rOjxQhXH1VeyDGBaGi+ApdZdl6CeV5Wo3gUY2g4w==@lfdr.de
X-Gm-Message-State: AOJu0YyzrDQN4lZei2tK+OYDpDl3rfxVBROrtzU8YQeo5dADR738HcJc
	NkItjw++UuI6c2L1THwZbkFGkeBhRJpJVtYp+huYOMI6ME6OMcoQ
X-Google-Smtp-Source: AGHT+IEgsWKTVDmdL+oJxpX6960RrgHAfHN6pfYUqHVHHnTaFHSYp423xgQiHuITDdm3xb4EHuZmVg==
X-Received: by 2002:a17:90a:7f89:b0:2d3:c664:e253 with SMTP id 98e67ed59e1d1-2db9ffc1c8dmr22867034a91.10.1726647011737;
        Wed, 18 Sep 2024 01:10:11 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d04:b0:2d8:bbfe:6384 with SMTP id
 98e67ed59e1d1-2db9f658beals3730748a91.2.-pod-prod-09-us; Wed, 18 Sep 2024
 01:10:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHpvVLZlLw9dP46PdtrrDxo8sZf3JDhWwBu1Qe1LhCC34PAtgM/Z9fFs9d4J4PX8twCFqyoC2N28U=@googlegroups.com
X-Received: by 2002:a17:90a:1041:b0:2d3:c892:9607 with SMTP id 98e67ed59e1d1-2db9ffc2930mr25295802a91.12.1726647010445;
        Wed, 18 Sep 2024 01:10:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726647010; cv=none;
        d=google.com; s=arc-20240605;
        b=f+U0BjYAZX2qxvv4AlhmhRZs91T09AXL02OSFyxACl4zxNfN0voAxyDGUagEas6YBy
         IHujTx1XW8sTIl9XPWwJldTAxpCpxu/SqdMk96ErbQaR/7ux9bGAHH/nvmotF6O2Tqov
         FVzC6euct/3NhD5VyBHvSpklNnJqUd4A+OvScwW0JxCL7ZmRASToz9ItNjeTVhRVjb3D
         Rd+AOVMIF4j34JiE9gq9kf3Z6AgUyrFKRQv0DDS3qQEmL35IktrO3DItWgVYzsfvEpS+
         We753lQbVW2o59MsIA6nn/S+O/omJDDkW4Cmcx5HrK45MQdDcH8NZie09OIltG+PDxg2
         uRqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=0cgJbF5rXAE9Y9Pvny85R6o37a96Kq2A1Fklmz2oRV4=;
        fh=Ax10hss1I5ycuk7Dx0aVIsr8MtDDLbuwtbEqt0wcYHs=;
        b=KHM2boLHyjRujKnmHVrpT+7tfdznqOwGpGvgpnmIRgcK17ndrfqiAPKQgflzDMGmlX
         7SL3gjRyZJHgpL+hGOyf8Dev95HQ9ZGtPDtM3bviJ0rHd2vfgpNr5D19Xr6QxQxZlbSS
         4BKxWj+0xiMAfSXOw85oSsogGPYiYOOcNgL1MVpPOakTh7nicbITw7Wba+N6M5gqNGSj
         ZoR9rm85M1juPh0xdbiWtMvO18DSiLfBGIcbPPUU30R2rqfTEUIDXe8ZdO6QXWDGsUfs
         NJ0aiotCXkwGwh8KBrHWGH0hCpV4DWbDyDdd7S4jc6tNNHzf6qZzskuOvB3B4xDa9WJw
         aRZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tm6xn8VQ;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2dd50c16dc8si265212a91.0.2024.09.18.01.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 01:10:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 075605C5A2F;
	Wed, 18 Sep 2024 08:10:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 60262C4CECD;
	Wed, 18 Sep 2024 08:10:09 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id 67D053806657;
	Wed, 18 Sep 2024 08:10:12 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.12
From: pr-tracker-bot via kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <65bb8a3e-9d52-4f2a-9123-a4e310c88d10@paulmck-laptop>
References: <65bb8a3e-9d52-4f2a-9123-a4e310c88d10@paulmck-laptop>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <65bb8a3e-9d52-4f2a-9123-a4e310c88d10@paulmck-laptop>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.09.14a
X-PR-Tracked-Commit-Id: 43d631bf06ec961bbe4c824b931fe03be44c419c
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: e651e0a47348cea260837ed5b463a489b1e8095e
Message-Id: <172664701118.684502.7882226897741505059.pr-tracker-bot@kernel.org>
Date: Wed, 18 Sep 2024 08:10:11 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@meta.com, elver@google.com, thorsten.blum@toblux.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tm6xn8VQ;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: pr-tracker-bot@kernel.org
Reply-To: pr-tracker-bot@kernel.org
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

The pull request you sent on Sat, 14 Sep 2024 01:10:36 -0700:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.09.14a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/e651e0a47348cea260837ed5b463a489b1e8095e

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/172664701118.684502.7882226897741505059.pr-tracker-bot%40kernel.org.

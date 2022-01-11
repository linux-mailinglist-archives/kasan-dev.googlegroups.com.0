Return-Path: <kasan-dev+bncBAABB7EM66HAMGQEJDWSZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A3E6148B4CE
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jan 2022 19:03:40 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id d4-20020a05600c34c400b00345d5d47d54sf9744wmq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jan 2022 10:03:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641924220; cv=pass;
        d=google.com; s=arc-20160816;
        b=uQGo9BXrE/WUGJbeIys7sLy2riIa4hStS8Qm/e8nKZwqjxWliM43UTqkmIzIqm6WKf
         0/fbSvZtmM82hlKHR6KhjPztjH7fMT3A11DGo032Hb0gm9bPCXEIhBs2WZ/fUvyZRsLc
         fU6e0I38l5/UTgurRsT/GqF6ImR2XCJa3w5nPQTFyEcUU7eyUZefu+mt3zN6mKY7/e8p
         m6A4poAZ6EGXVaCX3if+Y0CNgxxFDrxNJMSFBD6wMrQHGQexowvzjuQoxGWmBfkTjb9P
         Zc57LjRViZsmtnUxNjSPtYrsQiUS87C9RdrRz8bPaxVW83yf6uwNqEMoTj+YZaVKUqkt
         87hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=z8MT0M93G3bSPc5mX8jtyckOmU1iFG3isGTeDNe4/XE=;
        b=peyhzzZKPYHdpNL/MKQyHnPcd6w5lHkAL9dhMAug2+mQRSn/AaETlX9aOpgamx8KiV
         pO2AhyFH3U9CWQwVWdOLGfAPowWU6J8d4QQbEvi/B0jwFbd3UMXt+h4vt1pvlfgLIc3w
         Pq4ujVMM4JeQMO2H7lwAb8dGCzW8FPwrvhpYYOVpiBozkH41xjl/SpmK9edc8eIrFkjS
         fFfMSmxtmoKexGYtC0FtNa801vuwEHXKgDytjMbXOiJUo14KhVeGCiT1GdwAncsYgmZx
         jo2nq6UY0eRvsFv74vfg4z2hrZ6IN5FrOtvXsBtf4Kjcew+TgItXLKdee+sG0JYDpsoO
         2cTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iuvzHhJy;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:subject:from:in-reply-to:references:message-id
         :date:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z8MT0M93G3bSPc5mX8jtyckOmU1iFG3isGTeDNe4/XE=;
        b=GgiPzTCZbsMryKJCvXLfNCYRTD/vEb34xQuohVu1MS0dx/aoHpqwg1DfWtorvfomFj
         JQrna7aYVDeuI6WkuiPvRayJy2PMlk2JeJKOurKLGPVzU65A1/0yNVuwuXky1Kuofa/8
         qpwWmXGILfgahKY2MHUx6ohfdEeXOCCzQvxtpLANbiitJBI1eyZC+BpWN+TRl9zq81so
         m3q5katAsgyrTeaSUoy9IdZvvJoyWs2ldozWAuLngPKaT5TIJ+kUC6tCNNXkEO/G92iR
         4qLD6EPLRh/imRTkeSLTvdYfEkLvqghZU5KfyVs5lstJlAjwxvRw7z67U/7JiCOypHsM
         oDXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :references:message-id:date:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z8MT0M93G3bSPc5mX8jtyckOmU1iFG3isGTeDNe4/XE=;
        b=0z1ZNqCtWs2Bqi9J0VilfkDi2m84Fv/wY5wm6KOn85kMhaLFwHMeiEJPEsjDU9m4Gz
         VmI+c0oCW9UFmcNKGdrlGu6CJDfM5Ay3pec6xPf3QdI7ILcPWXSzzwQCKoNP+dw6+44b
         Hs3JmTe8EfVYfcwRCypv18vyHMKfymx+FsYATshhouFRvtBx4dHnl3YOJPbNqp52rvpf
         AoDxoCV6lcLlrk3u2D7nOC4eX5ZqLNn86J1vlZsL6R/wcmI1uG6u9Fv6h2Vx8anWdrIv
         7O6zChbpA/r++IVyeET+BVxyrR5LqwiSnwenwalXsXebEJCgzwaukXq4ZYT3SQlKGQH1
         JiEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531viJCbqsRsRWSBve/nUwfKlt0qtckFmi7XLqWg4Uh/HhmqxI6A
	JXDuSpn6NRgeUUpFG7L7Jeg=
X-Google-Smtp-Source: ABdhPJxkYbzvzRd3ezEnkUMjcRCETb5b2JQ8zQe30SBPcU1Np2egPTfAF3+ZfbrjmJKGipS9hyXrqQ==
X-Received: by 2002:adf:cc90:: with SMTP id p16mr5005402wrj.685.1641924220246;
        Tue, 11 Jan 2022 10:03:40 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:53d2:: with SMTP id a18ls319977wrw.1.gmail; Tue, 11 Jan
 2022 10:03:39 -0800 (PST)
X-Received: by 2002:a5d:560e:: with SMTP id l14mr4973670wrv.619.1641924219487;
        Tue, 11 Jan 2022 10:03:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641924219; cv=none;
        d=google.com; s=arc-20160816;
        b=oVHlMy7+IepyfwebGfcB3Mio8JVPaKxJgQy9UwQSZU3J9xm/lOaataVcP3EDBn2C+4
         MBGb6DP5ihQrEr7EbLYkWot6LF1/uwKSBK0Welw3u4prWJh1dmkHZfBBW+Cx+k7qebNx
         sKRUyDY2Ms6SufRCTjugC4WkltzF23Glow8d4BKy/M50fneBPzOiW9QEJqWRXcdbhq1P
         wwtxG8r8tRDo+9+/hVsBpOIQ4ooqV25zHibNRAiPj+9/oW/amUrhei8DeGN+tiG2sbk/
         +UlACtiwmNi5/nYuyFO+1pwlnlEtZEu8iWJmv33Uuq5jPXJ3MB2rpjifYhvs2lOcy5Oi
         gZgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=FodEHp1Gplr8b9ukfnQgWr061nYnbza5FzFL7oXZgCY=;
        b=kKIu1MMlEvMYOpjGCmu+IsLyPP94PTtYnEYu6RnAzrJen3Mg7AI9cEQ6DOBVpAs0JA
         UzvPbfJJQW6w4oGf6UwzIh+yrT4w+SS4/lseYaJPpfheOSIKWxYFhfCbwP5vLfN6vPXy
         4LxQx8MYJUSmYyVJGFpuiWdyopjtfjaK8SWBtA5j4IQ8SiFdmrc1JdZa8VM7J1rKw/bM
         GaK8O1EpQK4xfZKlpzr0pnpEbgkkIEOmGoA6eTn54b/JE6dPUFc5YAWoqQFj+8UwKfrH
         wdBeDTTriTcK8ao/BQyhJM0SDAAdWMUb2s+/+8BS5G3x/IJb8CbRT1Y5MNQ+02dKulL6
         w1NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iuvzHhJy;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id n40si129209wmr.1.2022.01.11.10.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jan 2022 10:03:39 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 25CAC6176C;
	Tue, 11 Jan 2022 18:03:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A8901C36AFA;
	Tue, 11 Jan 2022 18:03:37 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 96C1CF6078E;
	Tue, 11 Jan 2022 18:03:37 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v5.17
From: pr-tracker-bot@kernel.org
In-Reply-To: <20220110201112.GA1013244@paulmck-ThinkPad-P17-Gen-1>
References: <20220110201112.GA1013244@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <20220110201112.GA1013244@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.01.09a
X-PR-Tracked-Commit-Id: b473a3891c46393e9c4ccb4e3197d7fb259c7100
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 1be5bdf8cd5a194d981e65687367b0828c839c37
Message-Id: <164192421760.4972.3061477179236406035.pr-tracker-bot@kernel.org>
Date: Tue, 11 Jan 2022 18:03:37 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org, elver@google.com, andreyknvl@google.com, glider@google.com, dvyukov@google.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iuvzHhJy;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
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

The pull request you sent on Mon, 10 Jan 2022 12:11:12 -0800:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.01.09a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/1be5bdf8cd5a194d981e65687367b0828c839c37

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/164192421760.4972.3061477179236406035.pr-tracker-bot%40kernel.org.

Return-Path: <kasan-dev+bncBD26JKWO7EJRBIU3RGZAMGQEPMHPGVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id BC9518C45F6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 19:28:04 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1ec6de5fff5sf47251215ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 10:28:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715621283; cv=pass;
        d=google.com; s=arc-20160816;
        b=BsOxDIUyhV6AwLaDEJDolHEED48PnVw0AP7runGF08Gy404cUl2f3zmZtQP5z8n8Rd
         F+nP9ZjFJnnmYzqfZ6ofErMJ82tKxHGoHBL1pOJ/gCZzhqcOlXQqE4XdNcfJluh+aDsB
         Pf20P/uqokrUHNmXaqn2W5zw9bwNWQ2x8Q3aluDykbeExHrCMpZ8KB3M7x1uouCq7SoV
         ts+gtAlG2nePQdJtlJBImLw0p6yLeHp1h30HpvypoCa9QAGlqKEYu/6GwNbxTt+l79iu
         wVo5IQJ55CP8T91Yid6uDxtHsGjQD0pZZd9g9z3pLp+F7nYnJu9jaMm5uH0FUBtB71a7
         JQuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=Ix1HzWux4G3S1ybWd9WIa/vJWDIMapvTAFC9tuXuTNg=;
        fh=JlJxycH76dDSeM087sasaD535okjrOGjQB4G0q51RDw=;
        b=kAkTWWnBWfFFS/zo9LVVUWGh7RoWnSZ8yaM06V0v4L8biu3uaXbjYV6G3wuqAHdjbw
         Jh7a6khg4WsZqtBozwUUVHPFiNY/YmvACqyj8zIvzwiRwN1oqM3A/6H+PfllZEJLhYed
         gIr50eAcXEnrWjiQHa+UlpGZGsAC6WKcqmr+c/a2lklfaVyoCzv7sk0rF28l5uGX1CMi
         s5swrwLvLhb7P8XZSc++c4a5gbmpb7pFf/1IFhp4xwHSkxOm2PeKBMxxJZacsmn+7OkA
         hlLkYvC8rXsNtkbik57SVvlZKVeSVNbfWHjtJAcEWys5o2miC+/mlLyb/NGB8Y9xFfGC
         0R1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zq5YaLOZ;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715621283; x=1716226083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ix1HzWux4G3S1ybWd9WIa/vJWDIMapvTAFC9tuXuTNg=;
        b=ArJE/E8gG8UikoQlAompxhAXtZ8wCLs2sbIYNLy28ZSJRV8ZyRZLDwKkUaM23zNyVF
         9lOcfoMNB7OGJUyWVcnuE6ROOv15deih3kZYe87DnDzute6CaB/7HhYTe8FDov1XLhjC
         jwmqN+dT9Nrbc40c9zj1TNnVpVliuZuG+D7ECSksqvz3cyqwgT+gfc1vSeIHpmGTHtkd
         /tlp7Be9/GwUglRvSZN/3BVe3g3hJ3xRSdNfxTvwErTX9EoV/5ISM7pETWAReMb8hpKL
         7U7nq3dZ5KRq/5LGk8McXDHu134ktYsAkbmuUiWV1NvDjnjyr21sP8Qb+NRLyz43DrIe
         y8Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715621283; x=1716226083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ix1HzWux4G3S1ybWd9WIa/vJWDIMapvTAFC9tuXuTNg=;
        b=hdjfI+4VkwKNXnJvLyG9r47fgMKVpUSzmLk7V1lruwdRFuCVlw3uy1/3WzR7N/cUU3
         EBHpsV6S+lf+n4xkrv1xoAQz2kSK54ahBEGxuSQBHNN7uOplMQ6R4c2RdYA6H40NnMYq
         s4o8InbtUBqxyDP4iZVm1M5jhV9DdtYoBZMk+edNJn83t8c0FgNny+4Fr+GfK5yytsY/
         0wEaOc29scRYCpPArwBvu/lKpGldwvQOvWWl1pRbZajnzXZYVZH3g1GTVmTGib9Gtb8V
         RsIwZzU5GEh6TTdoHvQw/bWC+MdstwoiRJYqzW6a8UZ9tQZqng4JbBYBuwAwpP22R9N+
         FcPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAtK0E6qLg/d+lCdallUR+GXla3hmzvb7zE1rzb6jbqQUS9E/G7yCL61DWeAhJ6uLQMvNKCzdpxeiPdhe+M7+sIs6PCCx6tQ==
X-Gm-Message-State: AOJu0YwO8H3tP+LGTsxWeyjeDKAkNSVwIgfR6w3X+FAgfRQ840D2Xsm8
	Z7iwWxKbTScuZfrKysHV0YTVqXJk/QJnpAOgdV1MKdwS52ASF/A4
X-Google-Smtp-Source: AGHT+IE04aPmu69oWLNHChKcxfVvVRpB5x+5lrUb9poblFVmgQYK5mJo5gmYStvMPsNWC1vsJuSDPw==
X-Received: by 2002:a17:902:fc45:b0:1eb:1d30:64b5 with SMTP id d9443c01a7336-1ef43d170ddmr137893805ad.19.1715621283019;
        Mon, 13 May 2024 10:28:03 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e74d:b0:1e5:e5e8:73e9 with SMTP id
 d9443c01a7336-1eefd91b6cels30932155ad.0.-pod-prod-09-us; Mon, 13 May 2024
 10:28:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuAuh+ZrhKRCoQD7nVs20zxI0Zv0m00qVruVVVpDq7WUWrOwhlHyk3E1GXOEjjlAfVtgHOthtoj7LRpGiU59KXmSZhF6C0amC3IA==
X-Received: by 2002:a17:902:cf0b:b0:1e4:6253:75db with SMTP id d9443c01a7336-1ef43d1707emr120236305ad.17.1715621281852;
        Mon, 13 May 2024 10:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715621281; cv=none;
        d=google.com; s=arc-20160816;
        b=g+7RkAk2hHMWO7G5wojax+aN1yl/Us8mWFmb8oZkel0HA3sOyaSJnwf0s05gXc3ZEB
         f25Vechzxl5WIaZgxmFJYiMXr82jIdiQpd1mvUALTFSMdptexYG+gMpcx5O/fb0VguxZ
         XONcp0d16wM/AF4La99gY/ve0lPUu9WYDp5YvPDVJno0Mquj3AqQMiyPXrdf/DPoXzBk
         Q1lwCVdMRiKk/iY1Ac56su4XifyBSyiCgllo8HtwZ3CuChadgJm1fk2mxhJ8JFqBmfhA
         rtVTonD7TyEqu+tsnB1C5bBHL/MXkPZav58Ae/mZmgrdD6MPgx16CknkCgZLtSQtKjHn
         80lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=I9Ag3G8t/JizEUouZ3cge2MLphX/JS4+R8xcteHkFi4=;
        fh=00oKL+jHHunkUJXDgQQ1z97MiI8LgeAFRjH+B5haTEQ=;
        b=aG6kJJ9fRgsyilxTkZMSdLAgBghkXM5UuhFwEo3YmtHUxr+mxSmhWHYaQoUFcQ0dWd
         Tzb+xOzpP0fGXZotaX1PxFJlgKWd+VfcP4h+gZpWn26qgkiDuZB7sXVBH0eJ98ahhJsf
         StnZlzL4hxk3iR9XnxTctXvmbGUh1B3u62zYMcMQIkon0QjKk4LpgVWWM+LUSTkKP3uq
         zrZuqwjGLXBv7wHn449y/z8Pb0xh4KFHUiaPxmatnQBHZWylUjm+2m7/Sb7DKw7SuWwY
         2oS5ll1Qg5BYB+3GI00wyV44Ost9X3Ey0+38Ab16bt/oEs2R6UBjL09+OlmqpvdcuNiW
         Efrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zq5YaLOZ;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1ef0bbf09a7si5530435ad.7.2024.05.13.10.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 10:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 9A495CE0FA6;
	Mon, 13 May 2024 17:27:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CCCBBC2BD11;
	Mon, 13 May 2024 17:27:58 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id C0EF0C433E9;
	Mon, 13 May 2024 17:27:58 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.10
From: pr-tracker-bot@kernel.org
In-Reply-To: <ccdfb04f-9d2c-4033-a29c-bb9677fcbea5@paulmck-laptop>
References: <ccdfb04f-9d2c-4033-a29c-bb9677fcbea5@paulmck-laptop>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <ccdfb04f-9d2c-4033-a29c-bb9677fcbea5@paulmck-laptop>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.05.10a
X-PR-Tracked-Commit-Id: 31f605a308e627f06e4e6ab77254473f1c90f0bf
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: c07ea940a011343fdaec12cd74b4ff947ba6f893
Message-Id: <171562127877.25347.11798495440341857877.pr-tracker-bot@kernel.org>
Date: Mon, 13 May 2024 17:27:58 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@meta.com, elver@google.com, penguin-kernel@i-love.sakura.ne.jp
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Zq5YaLOZ;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 145.40.73.55 as
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

The pull request you sent on Sun, 12 May 2024 10:33:08 -0700:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.05.10a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/c07ea940a011343fdaec12cd74b4ff947ba6f893

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171562127877.25347.11798495440341857877.pr-tracker-bot%40kernel.org.

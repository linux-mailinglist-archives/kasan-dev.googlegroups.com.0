Return-Path: <kasan-dev+bncBD26JKWO7EJRBKXO222AMGQEKRQAIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id E9625931DD5
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2024 01:56:27 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e03a544b9c8sf7957004276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 16:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721087786; cv=pass;
        d=google.com; s=arc-20160816;
        b=hK2QIY+W5kN2Y5rGtyQo2nddzoORhchlQd3A7AnUedRNau35KtJOA57AvamzAil2gX
         STMkDhL7I6VDNjxQt/wqVfEXhhj/laGUUhNcm3NXlwor3b7wEDzaOXq18X9+4c2GOFy0
         QOdAMPNTHHGtK7Ijk33vQL4rPExvBuPmk3Ji2cm2Md4614rVeRPbc9ZGvwRKTsjW9GGj
         yowFWATi93ORH/KTXIAtzpzt7pdKbJPuRveBclklD/PVrICdpwm5e/FuGeFYOYmEG9b4
         SwbdzPWg0SKxG0wNyI7M+qqrahKxfXCX1A+2jAhmYh/ZYs+nwjj1bOfiHb7lOyNVkP4U
         aD7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=NSWTDch5x2tkyFO3FpszB/Uy76psM9OvYrk8ndoUiNg=;
        fh=booiEhqlsnFuvm5ti4Y2AQkNZ03h0kGH8C9mBZjdjfg=;
        b=zmfgptR6FVWBegALHU87ZM7Pa/H76nqZ2YtNdbdQnHUT/Y/Hu3mPGpgYFOCV5EcIOx
         CD1+V1vQ8nCjp179CfKk0eOhOnwf/9qMdiMvFu7PQYvsehR0Je+gYX0XPNkN1PptVuEj
         OkPaQPsvGOoKJmbJ1ZkoFcw0lU7vf3DTTHZahCzqa3cFtvc/KjJX/Keh0Q2Ap/PYDd1z
         /MiWfWgukWWndVdGam0k4ivhYDCSD13UCup1JBL2RjJr+3F5L1LreV70XKjzQbCNEk6u
         fYUj7epzEBASOAIlq7Nm1BZ7SgBhAfN/B9GFAX7pqukvmvGYiQrzAgkMjMurg+Wzi/CZ
         GYWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p9TdMRrd;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721087786; x=1721692586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NSWTDch5x2tkyFO3FpszB/Uy76psM9OvYrk8ndoUiNg=;
        b=rD2lsgvTxhA0+iY1XH1imFT8afJ01pfXRCcGIvqgYgQI4Ds1E1/Y+tssxKn3C9tbUn
         RV4Rw1m0UMCO1F2s/5UsDp1TCqNoGc3XwwRrcaRYHfDGrHk929odHf2iq+Pfu6HnuGfP
         0L+UGLH4ILV4dcxMr15IAN36vaPRd0iH+4pqw0VspYbxuPrX/gpRBAy1IcqwV8Qfu10k
         ESyTNQ+TG7t1GJu5S/6TOqRpLN8KzxRXtI5YSnIO6dDL7SdpdYBvHi9axjz6ynjPKZcK
         Khp4Ep5UD1fyzxp1GxkF+TS403daJVWk3zCRrzPX1fO8Xg6D+/Upuxv20xvtgcZw3w8i
         4yUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721087786; x=1721692586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NSWTDch5x2tkyFO3FpszB/Uy76psM9OvYrk8ndoUiNg=;
        b=NOzNZ7I0WzY86PU1VyFS/Epjt6V40+SqMacMcHDDEqg6uiYLOomAXOO7y1A0a24XoH
         sAe05oYtDm5gswBw393DLcyf4RLuDgo2G4/04UtZjClOjiWmA2R/0L9KTN1528yu1+Qg
         FSbkmxs38kKQbp6ixfHtwiMeXrp2+/rAdKHTwyivDEWFW9FiiKYrCCFwnkTSfyDGQn2s
         RvArmEMQF33bRN0rRwXdq+GxCFVQCnPtgcBgAjfhhJGmxIQnypOXmuCM8R9ArQVi3D8y
         T3ioWngs6iVnrpxr7ttcp9cEGRSNBGCxK1bQ00Q71PartuCWRom4mLhAIrZBp22i+lmq
         klWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5pKK4fhTl9dm1g2hwOBEYmecLrAL8MeYIBtY+whDyfMWrqat3SsNd75jooY4Qu2ovuwB/lRFiBiNRFyifIfzDccagJSH5Jg==
X-Gm-Message-State: AOJu0YwzetqWrR1wcMqfXESxVN+aYHd3Kw+qfgJtJtDg3xikUlN8Vkdc
	EUh++8jd4+qD8BEBGjse3ur9mHYkPlhcseApOyg1+E2wRynroi0K
X-Google-Smtp-Source: AGHT+IFVmvd7K89mp+Unn1TuLMjQ0ZxULy3dnVgqbl0T1MTktoTDoX8cgHQFwNmNuU7ZbNCoV7arCQ==
X-Received: by 2002:a05:6902:2b88:b0:e02:8f64:5010 with SMTP id 3f1490d57ef6-e05d56babedmr1101300276.14.1721087786523;
        Mon, 15 Jul 2024 16:56:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:2b8f:b0:e02:c978:fc29 with SMTP id
 3f1490d57ef6-e0578ea82b7ls7458186276.0.-pod-prod-01-us; Mon, 15 Jul 2024
 16:56:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVItXcRgr+OiYH29MRvFIqN1QNOXhDajAyAi7Pe3ykRxSjc+NzSVOJNUbmQJGG9UizEOQCEUA/HI5WhKqStOe58Pi9pZK/L6ybTAg==
X-Received: by 2002:a05:690c:d8b:b0:62f:945a:7bb1 with SMTP id 00721157ae682-663813f469fmr6318417b3.42.1721087785817;
        Mon, 15 Jul 2024 16:56:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721087785; cv=none;
        d=google.com; s=arc-20160816;
        b=fUqy2wW+57oWLcW3ArHu94tja3V/4cNdI9Sh104Tibw6OiL+uKrHiHW2lV1wsiNtBU
         9QjCg5erxYh/DnHDvdT/yueFcVI9WXSBHYdU+gCkEtL53PoYis+SQr0SQb5p2BYGE8x+
         u2PS8GQKajNQREGPMCDE+WXMyDhUcWfrS4Cwfdw7dcXgZ6KqZPR/hJQbRYgWu2prUoDH
         VbsjfrMNokqo2BbLgyFPInWICaA8V+wZPJsaZ5X9SwQZB2Z7GzQlxB/cKY+P89aORaos
         yFUbMrrHS1mWvpe0Qd8INAL8QTA8a7A4EB96rn1T3jdbvkbkhqgChBLqc+bYbM8Sy9jv
         JOmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=KRnsKTmvTD4XB4M8Os2N1o47gB6MIWo0IIKh90NpIws=;
        fh=hVIvB7hz9z2qFfJFF0h2Fv78Xk5nl2eSmasy6B6kHJE=;
        b=HVQhXUXKw8t9yhXDYkaCSGr+UQE/L5Q1ER9An0gn1I3f7JHbodk3iQQg1VctVAzo0P
         EtK6uLLojriYcjR4ZmlWPA5FCP7LBZSa07DN3lkt17IrTiF8XhNi0XKOS2oxXyWS03Sa
         fAE46F22NPcVwHw4UjKDTksnH2eypHC7NyIRFQH6EXOnInxaVeTTCR2xa6H7rhAV/vVC
         2ZTgRFyVdJuDI++rInGLvCeC9Wn/KnA8V2tbuUKrf+szDhc8CgX/cFG70KUqbOVtTTlV
         laY7VpptPQiRD6ieYaJ1j1Tro0baUo8OaH9nVBOm5kq/AL2TMuHLl26PbwCDJD/EKZAG
         rOAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p9TdMRrd;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-65fc3d86bcfsi3038287b3.3.2024.07.15.16.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jul 2024 16:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7325461309;
	Mon, 15 Jul 2024 23:56:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 40D67C4AF0E;
	Mon, 15 Jul 2024 23:56:25 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 379A4C43443;
	Mon, 15 Jul 2024 23:56:25 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.11
From: pr-tracker-bot@kernel.org
In-Reply-To: <6d532a3c-709f-4038-8482-34dc2dcbfaae@paulmck-laptop>
References: <6d532a3c-709f-4038-8482-34dc2dcbfaae@paulmck-laptop>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <6d532a3c-709f-4038-8482-34dc2dcbfaae@paulmck-laptop>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.07.12a
X-PR-Tracked-Commit-Id: ddd7432d621daf93baf36e353ab7472d69dd692f
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: e4b2b0b1e41e3b5c542a18639cd4f11c9efbb465
Message-Id: <172108778522.25181.1636303695976869353.pr-tracker-bot@kernel.org>
Date: Mon, 15 Jul 2024 23:56:25 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, kernel-team@meta.com, elver@google.com, quic_jjohnson@quicinc.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=p9TdMRrd;       spf=pass
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

The pull request you sent on Mon, 15 Jul 2024 15:23:32 -0700:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.07.12a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/e4b2b0b1e41e3b5c542a18639cd4f11c9efbb465

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/172108778522.25181.1636303695976869353.pr-tracker-bot%40kernel.org.

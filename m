Return-Path: <kasan-dev+bncBAABBTVO3WOAMGQEUJV5IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 745FE64A4C3
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Dec 2022 17:31:11 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id j2-20020a05600c1c0200b003cf7397fc9bsf3595307wms.5
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Dec 2022 08:31:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670862671; cv=pass;
        d=google.com; s=arc-20160816;
        b=b50m/yDq/ech16li7p+7zA1VkFoxZK6ePlQXXVPwUCyHyqQeYIE2V0a1p3DRK1mJxe
         WCI58CTjoznHw8cTdm7SOgzwCGuc50t84srVFZ9Up7xsa1o55KaCO3TumCqC8qwFmUPZ
         4QGcBevPNSDHr5rgkYkXgUpdpWaKKmuW5gGMT99FdvMyos3PODdv77A42bk9SXxHzM9D
         zaMyp7TgaPRo3oGL5feo7WQMxxr2AcQmAeZHQivUqF6wsVrfGgfrNjtO76JPkb6cP+Sk
         2sHErN7D6VKDcGLA9C5I60iRChjQIPRSIi0bPfHdqM0jCT0I3cWdo6LsFzQUGYzWzeT+
         eY8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=Boqo20iSIn573qHD/QbWf5qPilBG6UMidp/qfSYiFXI=;
        b=QyRcLebZy7cPFLffXI00SlrX3Tqn3JaIbtFoIE+1CR5CSaDKhs2xAGjMVERll0fhJQ
         3UUwVTIXIpqb/HS9OfPT5n/cQ+223HD1/bG9JPDW0zUYUnq1xmzfAOhX0ipj+tuRGbTZ
         /L8HL8Nr+tBQnVcXwVbcl8HkHLbV0giqyDzLNo3DbaTe+vVLe0oms884NBaMh+Tkq+NZ
         AmVhkvozlmNkvyqvayW/LJ1E7gZaJkgzu8P8G74GcnGu0B+TW+8Rp5LJ0MaiFI5eoE8O
         Ouwb08CNPgun/JOaNFoy32FWorMytstxYS8YNZYmbrQAvu9aSS4EaoEN8HIeFT6v6Ct/
         HriQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BS9TYTE+;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Boqo20iSIn573qHD/QbWf5qPilBG6UMidp/qfSYiFXI=;
        b=QKBuixhvBC2V0O9XXeTuCjtO+TRDMmBRzFWAIycjiXU3zmXz1Q/f6R1VNFuC7gLmik
         HP++acoHuMlZM/+XjKuAd3xLJfiD5OvPfSW550K8DuCkrH87JFfxftdoWWCKZX7RL8wI
         MO2JDPBEDjc+cIFo0Xy1/ux12Iqce2kbXIT/c+XJoToyoDtyBrQ8xrXa2o2TtabmORsg
         DFk4Ps0CAAIUFzPtpyFowRVQyr/66gIf5dVfF6MH2kDhupVYFIF7ThWqAcIy7lsXY/o5
         ALayfVcgalnX4FP8S/zfsu3s63frrSYZLeSpbASpY7pZXrhJU6R3wIaYgXbJ/Rv5l4bD
         GR6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Boqo20iSIn573qHD/QbWf5qPilBG6UMidp/qfSYiFXI=;
        b=p3qDyOP3996mP6MVqdtxqzoyAtJFDdj7RO6IivJS0Eyh2UjL/IcGuAQ3FLBCIWMHaq
         ST1z+PJeR38JOn5BQZ0WkIe3kzZz7MPX9bXdmHcs8gAPzR0R/WFq3BAYA1t/s61NH332
         GJgFrmGz5MnsRC1U6cd7GLMUctSvtwByPnHKitpoVSuhcy69WARnnTwELNy7rWA8osa1
         y9OL+reWhGjI0+p0BLE2Iybo1XLb3nvW5lULkUQ0vhfOA+DiSc9pK5HKzngqZLsC9Dar
         29WCd7e56F+hnh2oDEJZDWdMT4vAg/QUIeRoDk/26Yd6ZsSVhUfaC9eiRw1AUdDs87Bj
         c92g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnAltuDHOV9tWaGUccemwg5L30JjP0aOEMA5uhbpz9FF8cEVU8G
	AUP95/0y44aUMhyU78mG/XA=
X-Google-Smtp-Source: AA0mqf74ZtNhqBDmmG+y0a3D8b6qhlYM6VZ3EuuR9UhLpJ5hLuPMous6kq9ISxJosg4oij+Uc13pzg==
X-Received: by 2002:adf:e5c6:0:b0:242:5c6d:30d7 with SMTP id a6-20020adfe5c6000000b002425c6d30d7mr12027717wrn.316.1670862670969;
        Mon, 12 Dec 2022 08:31:10 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:600b:b0:3cf:72dc:df8 with SMTP id
 az11-20020a05600c600b00b003cf72dc0df8ls10691722wmb.0.-pod-canary-gmail; Mon,
 12 Dec 2022 08:31:10 -0800 (PST)
X-Received: by 2002:a05:600c:1d02:b0:3cf:6d9a:7b1f with SMTP id l2-20020a05600c1d0200b003cf6d9a7b1fmr13349821wms.32.1670862670231;
        Mon, 12 Dec 2022 08:31:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670862670; cv=none;
        d=google.com; s=arc-20160816;
        b=MSLCNr+fd1p9Z1gh9YTiCNYg6wco1XjnOunDBZPW0+rTSW9SkhCyUoY0fplJgDTkdg
         Qnlt9Q2hD6JKpR6bqgaeVH8/aiEi/JiawB15Vz7ZxJym8d8Am+ZOvZb69u4Awy2HIYhA
         xpdrykEudEjA4LusaXppD6fq/pZ6cJPDoBEft4I86BpJoNT5i+692+Gg3rjaRnfTfOBU
         6r8iyLdsV+8+WfMl+PKSNTXhSKbFRDbUoPrQyTTl6gDPM53yYS0Rrcr08DBzsK9BQTFW
         F5ftpLWNgeJTwWiFKN0SQySkWE/NkPS3QJnqaX89AF3RHGESbFPSGl/kHHmMkXzYmwJk
         kh1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=B+iBTW5EgjRnYYuwcbYEb1pTa40fi1SG/6yIhET73bU=;
        b=Re0OznE9r5HvalAOdipSQfM8Bhx+xSyFxy8lmcjjOJFmISS3eNIaPqd0crl4OcQXg2
         Y0Wx6/nyfoN8SGZOCc3+27hJIb7D72Ul6UL2aLbyj2v3WH0OXBSYxbkXYaiOAd2eilDU
         pqND0NeS1JrKRI62xPcpLUNx8AXA5RAfiPL+czQ4h9ccOZVmHIWR6dWbm4Hp8Kav99B+
         8MPLCBnYa+oSDQmFaFJ/zvYU1hyXFaYDo83gSnJ2UvQ71Rm7uctW7ExyVm1WpItamMHR
         9gsDPThPAcENso7kvlP/d/rpNHi65R6Z/1l8OR0IP7EcmUceEcPM/0k4mIxgd33nxBHa
         QmnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BS9TYTE+;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id l189-20020a1c25c6000000b003d090dbdab3si946262wml.1.2022.12.12.08.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Dec 2022 08:31:10 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D17E0B80DA7;
	Mon, 12 Dec 2022 16:31:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6C300C433F2;
	Mon, 12 Dec 2022 16:31:08 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 5B1ABC197B4;
	Mon, 12 Dec 2022 16:31:08 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.2
From: pr-tracker-bot@kernel.org
In-Reply-To: <20221203012343.GA1816460@paulmck-ThinkPad-P17-Gen-1>
References: <20221203012343.GA1816460@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <20221203012343.GA1816460@paulmck-ThinkPad-P17-Gen-1>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.12.02a
X-PR-Tracked-Commit-Id: 144b9152791ffcd038c3b63063999b25780060d8
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: f433cf2102fec78cf05ece06fb8e24fbfc6a64d8
Message-Id: <167086266836.18680.5671944128827662652.pr-tracker-bot@kernel.org>
Date: Mon, 12 Dec 2022 16:31:08 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kernel-team@meta.com, kasan-dev@googlegroups.com, elver@google.com, ryasuoka@redhat.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BS9TYTE+;       spf=pass
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

The pull request you sent on Fri, 2 Dec 2022 17:23:43 -0800:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.12.02a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/f433cf2102fec78cf05ece06fb8e24fbfc6a64d8

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167086266836.18680.5671944128827662652.pr-tracker-bot%40kernel.org.

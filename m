Return-Path: <kasan-dev+bncBD26JKWO7EJRBEOZ6O4QMGQEIILO3PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 997849D2F23
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 20:52:50 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e30daaf5928sf2129170276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 11:52:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732045969; cv=pass;
        d=google.com; s=arc-20240605;
        b=GVNcchXCzuIcvSnSNcCky2nSJkAVMpjRxVWufcVglDjhuaVJjw3NTYHypfot4Hc/R0
         Y7pUzEad2FIJ3dhWqo6/2UqsEQak5cthzdS27J9Ga1KrmbQLwf4y2VJesapJeBh83cr/
         XB76lBnf2gT7XS95+Oab95soPWuu97xu3i/cxSeabaLQIJ1I6bGaRRJY6KpkZjEklUQ8
         SD1sE2xq+xR/MwLPiGYdCcm52xvzmD0Ei/xUkf+bZBIg4hBLkO9wD3euS7F1+WofxE/g
         RBCqkahSJ4E2DKvT1cAjIy65jnuqD+LtklGADCXLoxJXGAmMmPyn7L1H/jr9euCGIUid
         PX7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:date:message-id
         :references:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=+NbwA3dKcaA4RLv5qPHfs8C7h/vMAPY18smKlXsKwFc=;
        fh=5Ol4k7gB6DPzfLtVLBRuWKvz5lZr4QhuKSj0sk8Y5LM=;
        b=dmc85TG+p04qaBQh46fAz4pLjasnl0m/qU6yMbgZNH98lQ9Igc9G3QTvQWF7a2DL64
         R2XivKZCbVWo4hM3fafgsElV9rwIlIQwJwkG7dRGB71UYxHjloxc2fyQj7RYyyu2YFZ3
         y3po6IhC62Zu5yU4afX7K03Ujz4fhwJ15iX2YFm3Y5lJD3hB8I6VV7sS+6rJwQbMWRlD
         8ylxznwgIIZrv6XsohE2X9F4aMPcCZMOLiTXsR20S0d77hq3S2HsvHvP3Y6YIgMI4Ob+
         MttL4VZjARUMQoqheQXzBYbITjZAK1JfTVg1d9jGFzyBu3L1xBMgfSYGqQKdrt3X998Z
         mcjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hlBzBDR/";
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732045969; x=1732650769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+NbwA3dKcaA4RLv5qPHfs8C7h/vMAPY18smKlXsKwFc=;
        b=K8RLfhQeVz6F/144JqSikEMH8QNqF/pW9DwAlRlGSSaG1rF55jnVBikGwqPoKA3rRp
         wr3zTZScTb7qZSey6iMgJg64xUSuzs8l2cfPyYhBxV12hUpWS2+/Q0uMXKRMhgeCP5+J
         iFCYHShIEVD/CVf3EaMplGbZR7gvHLrbKdH0Gz2hUw8uAmMfiYfeOS+tz7lDnXxELdbF
         PyC8Qb4RlbgeLZbU7UaKVvOSpGfYzBgQLKXlGtcPv1s3Uv5JMZnoeetIsLwgq3fYf2Sy
         bKTff2VsY75bwyitxrvDy/AyWcKlFOuEdYVCloA6pY9O/IDGUiByn2XWCS205eZjWAHx
         RkUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732045969; x=1732650769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+NbwA3dKcaA4RLv5qPHfs8C7h/vMAPY18smKlXsKwFc=;
        b=iq1nJlf0UJBiyPAESeOhC3932biYEjqZeb5bCrujabZP6sltkC6KmMmeY+oIg0sQbs
         OHz/zfo1Ejtzz1MiS52pxpcpVzOqVgBtj6LA9+KDGduVLmUaXxQQF09KDjO9OVLQQ4zc
         TlDL4lVKO0MTLsTCB5NuZbk0+c5PVGY17FZUFGcxcwAXoLb4y8/2Wy6bwtE50vmTJ31E
         PeKqi6VYaCkWxq3ex4fOz0SofobFMxcxHVg/qh8gwoG+yv4Enz9PXIVTDwjekc9LLQGK
         B8niOrklaYmWeWafTf7Kbl8/5qIgbVby31PW7XMwTS1v1ODtM+k5GqeNM0Rs38KqAwBG
         M9QQ==
X-Forwarded-Encrypted: i=2; AJvYcCVoyF1roBSjQJWauKPi+6saUAYgBvN4QkVmqZ+sXGe/BurinL6oxffpbrEUACKOlcA3bLG1Ug==@lfdr.de
X-Gm-Message-State: AOJu0YxDGp+1dwTHwYDg6nCIm4cfAbIlwHe2M0S7iuLcMOMXHjPEkcwB
	IRw1wG4E9vjZLT2KByVQy3esSRfPlePpjGYN9SvCyUJ4h/3mAwQn
X-Google-Smtp-Source: AGHT+IG7B7rDC2/jDjiRdxb7S9M0B7WFmoS/2G7aYVEElzRIcucyosqi0od3Ccxm59OtHn20y/B0ZQ==
X-Received: by 2002:a05:6902:1b89:b0:e38:9735:61b3 with SMTP id 3f1490d57ef6-e38973565c1mr9131096276.20.1732045969456;
        Tue, 19 Nov 2024 11:52:49 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e806:0:b0:e38:94e3:87e with SMTP id 3f1490d57ef6-e38b6bc15b0ls150647276.0.-pod-prod-07-us;
 Tue, 19 Nov 2024 11:52:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWCkNq3ev/+49szzhdoi6MJi0gNIQuwhtgujU4ak4Z1CXS0vVBYftycZSnobByfAwQOcc1FwfG9es=@googlegroups.com
X-Received: by 2002:a05:690c:74c9:b0:6ee:b5a6:a67e with SMTP id 00721157ae682-6eebd2b0d76mr1158517b3.31.1732045968640;
        Tue, 19 Nov 2024 11:52:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732045968; cv=none;
        d=google.com; s=arc-20240605;
        b=GrZR3RE5wQCIX2pHyrKnT+EWY+Xr49LCZJy+33knV3ccMs7L0cgz7lk8HjfGas4a1g
         OBZt7YAZjQBncGTsb4fnynriJW6ZpZYjfks1qzIos2PbMzMn+KzV89NKVJgvMnTDseHy
         OahdqRPyDfxqSRXLVTFBNZxiufFKs8F8EM68hqJnOumyFYmC7D+E4UJTqry6bo3dic0V
         s/ivCjS0We+Bb1szNyHz6VHHAJQug4iWsmKo4pCsvbcchdLbS+z/GT96PZO6QJSGQ6hr
         9kVX3C65wXgi+V4+/Ib0BH3Zq1LbcCubyMDmrJCWXV7SCqogkwm/g0sKnHeiZXEEDly+
         MUCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=8ZAiNwo6EtxLkDc3bpQ+6taHEtvQ0aj00++QyYEoqtw=;
        fh=JFG0KkXkmG+mzMjA09OCRMWh/EhKjXsBpXMKGE849Go=;
        b=EaRRYZum1y2cFkZRerl1uRzegqgHrYHAS9/G1COa/0ceS4JnzADEklAMjkZjBhN/4o
         vSGt4mJFu4GMRDKKVj8o3usUHMfVxCyJqwYRf+AXW7R3hSWhwDKlZe233EwMjHYiQt5q
         ya2mxIGtEfpERFa1RWQG4zOGjQJtPM48NZHQKouAf5EKYomtI0/J2GwL6YQG+XVbt5+x
         czsZvhCeDPWSWSx7hXTftp5y0W8JXizpo85LcnQtJ/TvgtJr6zU5lEihaOb3JeZYVcPD
         kATPwTcc0/RRqYE7ucz/HiBzns4dfFUW3AaeXiyeVhk5kbWUFo/YHnluAUYqzS8Y3Akc
         2jFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hlBzBDR/";
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6ee71273309si3488047b3.1.2024.11.19.11.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2024 11:52:48 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 131645C587B;
	Tue, 19 Nov 2024 19:52:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D941CC4CED1;
	Tue, 19 Nov 2024 19:52:47 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id ADC5A3809A80;
	Tue, 19 Nov 2024 19:53:00 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN updates for v6.13
From: pr-tracker-bot via kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <ZzsHkNopkQpY2nwy@elver.google.com>
References: <ZzsHkNopkQpY2nwy@elver.google.com>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <ZzsHkNopkQpY2nwy@elver.google.com>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20241112-v6.13-rc1
X-PR-Tracked-Commit-Id: b86f7c9fad06b960f3ac5594cb3838a7eaeb1892
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 769ca7d4d29748f1c95b4ae4ce325ba4ea8cd2b4
Message-Id: <173204597913.668199.11932969787943956858.pr-tracker-bot@kernel.org>
Date: Tue, 19 Nov 2024 19:52:59 +0000
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="hlBzBDR/";       spf=pass
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

The pull request you sent on Mon, 18 Nov 2024 10:23:28 +0100:

> git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20241112-v6.13-rc1

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/769ca7d4d29748f1c95b4ae4ce325ba4ea8cd2b4

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/173204597913.668199.11932969787943956858.pr-tracker-bot%40kernel.org.

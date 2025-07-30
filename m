Return-Path: <kasan-dev+bncBD26JKWO7EJRBXORVHCAMGQEUIS6NYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AD63B16685
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 20:47:59 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e3e973055fsf1577495ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 11:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753901277; cv=pass;
        d=google.com; s=arc-20240605;
        b=hLBHuvT4zlkVbOJRpagH5bFEg78N5HaFzp1+D7sSbFs48GsBTQp3IpVoQ5Xap39K3l
         NgBj0H5f5JR2tY75jU/StdDNod9yiZNj1dCPWTiRndvGxkM534WFli3+Br9cLSpPsm1W
         6S6P21YMbNnLr4O3r9g4N6MuIgzsa90eEitJirK4H7fti5xyFjJK8J64dTAPm/S6hw/B
         W/EOzsmepcznybU4QMv9wluXs/MP2PdHR5IcohRm408yx04B0zGLCHJcB8ehnht9KtkZ
         htzAmh+h07BFiqa+nyyOYVkn1UlSK75u8NcW5FIuotaoe+ykPM6C41uHSUxmPbJQKnqg
         cf9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:date:message-id
         :references:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=0PNUYuY9VvtvKx9Teb6Iohvx/0mn8H9Rz7mq26pubpE=;
        fh=8XymcIwTI3zXuBr4tyHAiqaFKpiL/ElEdYU77CLf74k=;
        b=MkhXW9TY4Kubg4V10sL6IR4Z1XxM0fsDXjBACH9S3n8T2krPNPCTEFrcnE8ledvqXu
         r+qrfohQGR2CkIZzjjvZiGbJon09OkMa9fyC99n1s7lR0FHzRTPVqMAeOCDxABpXI+OE
         cG3Ta9UASnOHcilJ3eeN8qjHUEjNl47IIdouFAjJGB5cXzY6JNX1aP0o1+ccTb864naV
         WU2zrr35gQBOhuFyGul9MZIMDR+IjIzz0kN4G5EHwF3DB7RKb0JxFcfrBy5qi9n8Q8Rm
         +cSaaz+fdWqW0gsKCxBACG5SPpeCy/7t4F+/dC8D7SdyBm38yMRjI5uHuGpj0lBKNa1l
         eKbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=spcRqDQs;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753901277; x=1754506077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0PNUYuY9VvtvKx9Teb6Iohvx/0mn8H9Rz7mq26pubpE=;
        b=chRafwwwwAbtPUSo8rBh97SaxZTLbeckKJkjIEnX4VXyrE20P9LcwUtblRVdIFpH2n
         kbZNIhK6CL5gt1l7kJPlTQMLXsQqZP5XyhONIggZfSuWm+8CFwz/M88K9hNpK8MXzldn
         f410ZYjlE47zG0UYLyoi+GP0KeAJ8fscxGsbY696+0af4MREgVVlWA7P/ZsEvCUVn3Jb
         5StxxHmtdaSPlH8JgT78MYSyl+0CsSnjFiXOpiigaBxcD51VZu4u/Pu1du/wyG0czH4d
         woxbwiwiutP6xOT++zfJS5/rUUgk3hWEmQ7unrcShojCpTc+0ZcO/L4fJ4mLmAtp021X
         VMuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753901277; x=1754506077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0PNUYuY9VvtvKx9Teb6Iohvx/0mn8H9Rz7mq26pubpE=;
        b=MqhEt9dRGeQCPZbT9ixLw0GWF3Ao7+5lscX2IrWvkmaYULlredWczQGC+sNBetRXsq
         AGr0+X8ufe8S2SMPoJxbHa+mYfo6y/ruWBjPjhZchNxaOZUw+Pp1e5MeBp8lfei9WF5a
         Ig2IPes01N1UFOdsLSyW/ovUMQnXSrVkpiM2AR1JDNMu0LNe4jIIfX5xQgALr+Yqsln3
         FNnHB3bcz5eEZki+6Y6KcaPUqVMff6sNozeHeAFVBQyAfmMNwfXKTbJI6ibNv1XzRl7R
         krmXbxB37qHaqEFJzeoaP7xBKPK+F63dfnqKCqcEBdtLtmuhUgRAGWkBHvUjrlckPXhr
         UkwQ==
X-Forwarded-Encrypted: i=2; AJvYcCWOfn4Oqq+3w66e/+bbrT1+H5QD8dv57lBAYQ66+n+UH92dMtoj63FcnoE+XJYkuns3c98Qqg==@lfdr.de
X-Gm-Message-State: AOJu0Yxw7bZsAfwCaQ23ru+S9Gu7Qi/EVzkoEEFvD8wYjLSiXZQEpQno
	t3i89Ruwfvl+SgGy8bhDirgl8KZIxtoayOEyQkaGA83XJYlSUY33lnsy
X-Google-Smtp-Source: AGHT+IGWJHHLC661TMAuPv/YHRzKPRAYWP/A3vwlRgiIhPWpMfZOOHdvJiJuIvDMd3dNx/DDYBfHfg==
X-Received: by 2002:a92:ca4b:0:b0:3e3:cfc2:7e55 with SMTP id e9e14a558f8ab-3e3f61eaec5mr70955655ab.7.1753901277512;
        Wed, 30 Jul 2025 11:47:57 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetwbXmp7P3w6rj4Xo5aG7+vu1888fuXTxy2Gq1YPFVgw==
Received: by 2002:a05:6e02:8d:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e40252fb2cls270475ab.2.-pod-prod-02-us; Wed, 30 Jul 2025
 11:47:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/Opsm+ov9DjIwpm5Om8oDq7M8pFGKrb8HJk9zfQ7xTfkSBwMEhcmEENsenVpuIGdOHfV12Y1/O4A=@googlegroups.com
X-Received: by 2002:a05:6e02:1a81:b0:3e3:ef06:674c with SMTP id e9e14a558f8ab-3e3f629724bmr70820095ab.20.1753901276148;
        Wed, 30 Jul 2025 11:47:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753901276; cv=none;
        d=google.com; s=arc-20240605;
        b=QthXHaWbhhRp9gKFPVtrNRharSuTXiaInNnVpuOUxuz0R1HH/sVH0b6mlvOJr2K1LZ
         gNeQF7k4nEAd8Pmi3BSmGJtbgt/JlBfbNqewJYIitm0++lru5D0HezSJqlxOJBSg01m7
         venuuzkv6oxxMd0fm3u4Ksd1XTo9badRDx1PuFvQMDD+n5AQyxjjHwqiDjrtbiC6PFzh
         TDZ8tUtBtI26SRFMo1dlEMAFteVFLR0D+3m9oYYZK7HNONDYmNbeRvjx+n83MLJYJSLo
         +KC3JxYVyVhYsHkwdPBKOLJbCohUjirmabot4bR4ntoSJu1DQblarlNups9Z+phD9tRW
         E57w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=z0QZlZoppH5ZxaMFiuHnPCqO8nlD8luS3n1MLNRWLGc=;
        fh=T006y1IzLYlwSnizRC67tcxXZshsKWEsDrzEFre37ZQ=;
        b=Pzv+o1MJfUSxorLhpyPJ/X2T6dff/bZ35lXzp6klWLjPc5g7LOcdJ8HyNwGW2RzewY
         w3jFlbBOFhZkCjUd2hZOYuvW41jzfU4MZUDvyyklPSLC7vNifxNOEfSvyNdigWreVpbH
         L8YDWby/cYz4F5mO0tCI+1QsPJLjTazTOwCgk4xgQWVap4TeafFsHvMHKXsgL5qa51Vi
         7WJUa7+7Q0Rv7kf9bAbCFk+LSxzCP1jDCkbZDhXip3x8ejunO9srt2iM01KZAeSWRDXu
         uDeUC4NRnc3Enm/CM1CQyjui26OtyWF284QTrHtwqGI8AOr501hw+7G/YOcuV7czMj6e
         8OKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=spcRqDQs;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508c92ed610si597129173.3.2025.07.30.11.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jul 2025 11:47:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A4D495C5F88;
	Wed, 30 Jul 2025 18:47:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7350FC4CEEB;
	Wed, 30 Jul 2025 18:47:55 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id AEB14383BF5F;
	Wed, 30 Jul 2025 18:48:12 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN updates for v6.17
From: pr-tracker-bot via kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <aId-o3ijDLf38vtc@elver.google.com>
References: <aId-o3ijDLf38vtc@elver.google.com>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <aId-o3ijDLf38vtc@elver.google.com>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250728-v6.17-rc1
X-PR-Tracked-Commit-Id: 9872916ad1a1a5e7d089e05166c85dbd65e5b0e8
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 7dff275c663178e9a12a0c0038e4b3be2f3edcba
Message-Id: <175390129138.2433575.12004645258274497693.pr-tracker-bot@kernel.org>
Date: Wed, 30 Jul 2025 18:48:11 +0000
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=spcRqDQs;       spf=pass
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

The pull request you sent on Mon, 28 Jul 2025 15:44:03 +0200:

> git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250728-v6.17-rc1

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/7dff275c663178e9a12a0c0038e4b3be2f3edcba

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175390129138.2433575.12004645258274497693.pr-tracker-bot%40kernel.org.

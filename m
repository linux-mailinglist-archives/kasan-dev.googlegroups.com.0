Return-Path: <kasan-dev+bncBC447XVYUEMRBUNCQ2AQMGQEMVISKVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 18E43313EF9
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:30:26 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id a19sf2529292lfj.15
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:30:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612812625; cv=pass;
        d=google.com; s=arc-20160816;
        b=si3l24ZMTozkw28npOKIxsg2lZsFp1p83WqMSkqchzEMsPzHt/yeRq7hqCrlf9WrrS
         soHmxVCl6SrgFa01B/omBmD0tVirctQLRck4kCYTQa0UCLU+aix/YU4qF4sQQvyPZNNa
         /3ptG3xfz/hkQ/8BFa36dDaH+HVYuC0lCRbaLwdEI413sS5bYz4rRPzTuhy5aCgI1QpV
         tdotIF4L0SVO82KxcwwQjPoYqBKrbO+mI5FPV9gA8xaBz4XJ7vSDKlG4qqlsd3A2nZxX
         WdX/VBs5k1/6y4XDV3+sSFerJOTgekNqgeGufFpSBXKSnSIpdd/psQV67UhPqI9ES+XS
         xHWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zB498fPa9s8u8i43FhU/fBFJkgCSWbakhqZglrmgTRc=;
        b=HEN30aLDXpwqzgQO3xHIbOcTQeE2e8chwgB+MB5287oiFVFdNNxhF/OW5Kc2TOlDAS
         WI1u2NTIwuenl0tonT1ZomCAc9h9WCGtLvll7MTw4inn5pxy2IpT89tzIQNSboWDSKBZ
         qvYPmAXoSrXcFBb3RXp34ZDJwq524W4yemNCcockQF2tSIfIE6U0ujAVDmS0K3Qnh7Pu
         5RF7Y8vhNp4sJeDIJHUfIPz0lseNe1C4q6FYpF1rowICq6G3BBKr1eFFzEnjdjCJxSsI
         yBLFz/3PAEdBhW3V/uLI9l7JrZK8jTzr1lKJIPhITTTX7gsDbHRa2Z3hdGPsR7lBcJW2
         K+3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zB498fPa9s8u8i43FhU/fBFJkgCSWbakhqZglrmgTRc=;
        b=cBSvhVFZDZWzTBOKzIgnqlllNEoc5uQ6C+DiqV+K2DZe5UjN5c/g+rv7+eIzfU1ZfC
         9eEZo6UlD6zpyw0NPq5ZiuaOMEFGrfv2C5LsKTe0TB4ZNCyPgGtZmwW0lIGHLJaThgxR
         uj/58CwvBdssbsw7FRrWrfYDeXz2QRrcqsoOVizX6gw++Dk3UKfrxW1SdhO/F0PWspuN
         7Cd8V6Ro3WtKzVeShz0Cfu1aPjDtnTljarIslDRTC8txm1oTrJtp802os7V32YqsXCaL
         sY9qJUGt0zxn8cyEsKiceAxJ2sfkjxJZ40p4YagiO/vUc9sMiT2VvOOmteOnhnQhIKZq
         QnQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zB498fPa9s8u8i43FhU/fBFJkgCSWbakhqZglrmgTRc=;
        b=oX27PssHgOr+DQBGHH8GIROGD5vhM5rnoRN0rSnJuD21oLokLUBrCYGdpDVgV0f/Qr
         p1Jl8b53iAHMQvTiXj4s4n0oKqC8MM5z47j1ISBDOVMLWKM8D99xGUjX+IhiSNPir3Gh
         IjYwd8jn93m7kf1Q0PqlF2EFC/olZJnIgS1oNrlhnooFeX6EHUHS6dpynBV8Wqz0Z6s8
         rlYlbIzxETxlx3sfw/wkp6zLWEr08UR+HyED9NVe/UN0wU7rDT2ZQjvOjulIiwZ18GUw
         kLmhO4bmKV7FYlo2X+hVqI5pfbfNc+trx+uvK1YZBdAeRXSj9BpInIbCdth/9f+UTTe7
         1RkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533whDspPrv7uIPwB7WTyz+ubEP4wZIoSyx1XjwvTMDm5osv7L1o
	nnY+YTzOMd23jCrJKTHLH9Y=
X-Google-Smtp-Source: ABdhPJwUe3cqOTG18eiAS98PU1nrMRhbYWZdbWBE1j5+B3uG0I+dKo7b1+mzcKE+/jdk5sOjiURo8Q==
X-Received: by 2002:a05:6512:3704:: with SMTP id z4mr11924327lfr.104.1612812625676;
        Mon, 08 Feb 2021 11:30:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls43290lfu.3.gmail; Mon, 08
 Feb 2021 11:30:24 -0800 (PST)
X-Received: by 2002:a19:cd2:: with SMTP id 201mr3010691lfm.110.1612812624748;
        Mon, 08 Feb 2021 11:30:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612812624; cv=none;
        d=google.com; s=arc-20160816;
        b=kgPCs6ErDW0/FGdhTKzr5oqijOOe56D4cZmm00+Gh93KYoitIBGeTXAITnm6UnlLLJ
         YUC1jzVUH+5cv+XrTE2663vaSqLAwVcnktXMPXeIzo4MACUcTV45fcewO+EAM8uQO0u5
         yr3t/6S4T0hSqYzJ1frIqk2nTu0ITl48fnNAUcqvyNRZ6a8lxbPa+t4rRJECrGMoG7/K
         b9B3RBh/IOA+aoy4xj+++sbNe8iPrUkM5OZRlz8m0QMDKQSbEbpMq9ELGgA372ussVvh
         XtcIelgSZXMSeQ7FuhAmHtIXRJNQEiTiEoo8aicn4z02EHnhDBcdWkeifdr+6qy6+qRE
         +UMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=0l9g7N5eQLPk7YVqRqJr74edpKTvZBLwb0I3q9VX8kY=;
        b=QuXG6DVw902ABREEXXfsFszh7XlcnXrVkLvj0RH+490KehhDeM0rzlq41h+GFUKDHc
         3Zf0TDqZC9Jha7LmvT/h6q72nN5P7RvvvFQLbQz/Ievc+R74qXRURib76QaJL8ay/d4b
         jz+7bf4zruviV1Zer5uqfIOAk8D34nBeRCytpqE6sniZuS4VhmMfMfBQct6v3oshccbx
         79ZvTmu9dSxXHOMv7Uh365qAb+b4GgLkNBLr9hsmf49gwLs43VqUPYSMP2w0+bbHUsAB
         LBgyp06+1Iu3n8aC2EPGPkvJ7RJ09EgHH6SVz2BSnJMeww59Mnor/3Z2jCJaagd/c0Na
         mmMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id m17si561795lfg.0.2021.02.08.11.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:30:24 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.195;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay3-d.mail.gandi.net (Postfix) with ESMTPSA id C803F60008;
	Mon,  8 Feb 2021 19:30:20 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH 0/4] Kasan improvements and fixes
Date: Mon,  8 Feb 2021 14:30:13 -0500
Message-Id: <20210208193017.30904-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.195 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This small series contains some improvements for the riscv KASAN code:

- it brings a better readability of the code (patch 1/2)
- it fixes oversight regarding page table population which I uncovered
  while working on my sv48 patchset (patch 3)
- it helps to have better performance by using hugepages when possible
  (patch 4)

Alexandre Ghiti (4):
  riscv: Improve kasan definitions
  riscv: Use KASAN_SHADOW_INIT define for kasan memory initialization
  riscv: Improve kasan population function
  riscv: Improve kasan population by using hugepages when possible

 arch/riscv/include/asm/kasan.h |  22 +++++-
 arch/riscv/mm/kasan_init.c     | 119 ++++++++++++++++++++++++---------
 2 files changed, 108 insertions(+), 33 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208193017.30904-1-alex%40ghiti.fr.

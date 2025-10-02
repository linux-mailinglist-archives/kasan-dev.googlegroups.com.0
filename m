Return-Path: <kasan-dev+bncBD26JKWO7EJRBHHW7LDAMGQEOMROUYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E63BB4BD5
	for <lists+kasan-dev@lfdr.de>; Thu, 02 Oct 2025 19:49:17 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-79538b281cdsf24473986d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Oct 2025 10:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759427356; cv=pass;
        d=google.com; s=arc-20240605;
        b=jcpLZhhsgB/b9IhaYJNzhR2EWvR9JieymY9Rg8qrTWyNpl0Tk4u+1vFCb/sHy71BFV
         uAHpo6LipRk325TbOM52WbDzqsWxtvlKfom+TFDxs5USg3Ama2c0gBxSsoyAugUUOkqP
         kAlrtGEYSdVPCVYtfUElWWn2pY1nGg1nV9YBbrcm/eB8u7n5QY8MRURzTeGYiqnNZ/m6
         Sr0G7MZk26zyom5eCWLt/HD9YSpfn4YrLQShW/N2y738WUFYzBNz756KhaBxOREeC2GI
         2HkfGuPOAB8PR6N+L08rYfh0R9dUi7bGz7MnyCjNCa8c7F/N8I73cnB1HpMqEm7vKkoM
         Eihw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:date:message-id
         :references:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=dOCI98AtxYyzU9xvBr+vTzerF+3yHB3OWKGPuGNAt3s=;
        fh=qnuC3y9wFNYOZuWD6eYRvUl7ZMwjhw6/ywn4rMZKEa8=;
        b=PxTF4pfgVgYz/rWMHi/yaWuVnbmL2vh+2yLOwpV3YjwiJYCGpfTd6l72xvhiTskyTE
         Pn7ZLd3ze/ytAloiArg8l/CgmEZtQOp5VG2mJh32keN/7qoY1R/JeFL4TIO9nims66FF
         zeLGIJMnm2M5KIoEWJtRk0mau4/ka7wQEEaKptg6Qvft64NuqOCCq951CYJYNqFJ2FoO
         ibby0guz24YQU1ENjw8JuxVtmHFRMuKNLeXsOqLObPyb6WXXQQB90dibas/Z5GdqVjbl
         Mvjm5iCRXXNE14cyo8O4Dm0+kRZeHotFNBXDAKxK9gjiiec42wz5NWVeVo9fUQrNzD/e
         RGJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e1trikmA;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759427356; x=1760032156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dOCI98AtxYyzU9xvBr+vTzerF+3yHB3OWKGPuGNAt3s=;
        b=WGmUqk6+WdLgr35RyqkiK6vc75+y79OLSITDY6OH2ueKBZo3S7w1rSluxXxuZIWG7/
         cTWJjArZ+KnUi293BQUa91GBd8DefATu3r8hseSjTlYQGxfvRQXMkqmUyfHulwFk2ME+
         naFK41GyNi/4Ds+OTitzaI2yHoxV+6F5RagpnKg+r6ubWDICmSwcauQhcqvCMJIfVIsX
         4/sqXAIUu1nqJIMljB5wNF11PX7eYT6edyUbDthXI/c1Kn2LDoAeKtUx7tvo0Abgn19y
         Appl3nN/K57aVNIbHb9mx6Q9OkpakB5uTlWKAbhvCt5/hMaivMKk32bqNvra8OEPkPDn
         z7Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759427356; x=1760032156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dOCI98AtxYyzU9xvBr+vTzerF+3yHB3OWKGPuGNAt3s=;
        b=P99rvOrlgQjSKAsdUl1BlyJvPOl8AHX4hd/Qd0CXMjCoAkQOl/zvVhTCK2GOZjih40
         m29HgWb1tE+U6JnnVX+tO5oW79rmpbGw2SSgS3EYkzbMlOSxn4twzJUqphr+A8gH+1yZ
         xkHiwS6aWL2WG9SAoRGSx8S3i7DrRfehgKtAiu6EtEi8p72mX+KbVqfgxGlb7TwpxED/
         KDTFiCeyXJX4caeUDpG+7AGRulSG4GMPTmgMr/ts/zWLJDKzxDPioe45x8LqhYvOUANU
         /sKt4M8OTlIn/mgUcRxoFqbX6KjhSLJg7BHYiC1MdYuHuwAjTDMbWACRCdy5DtTbm04D
         XNMw==
X-Forwarded-Encrypted: i=2; AJvYcCXtuohYNSXXJLET2mHPMqiapb9suXytQYv74Wjs7Jxl0XVOPhhLofxzqZY8pMvV4VXMe/QIXw==@lfdr.de
X-Gm-Message-State: AOJu0Yyab7CJ88ntT1nBt2vZVbLansTyaFm4Ag3ZkAvjeSou3y5jTL4s
	L0shDzYPfuNffBOGND+pV1t1UP0LrUfF5Wo3GFwov/XHL/l3E0cKZuyT
X-Google-Smtp-Source: AGHT+IFGkSZ4gx/+hpMoCmfR0m7fM/fuGXMjNwR2yK8sazMJ9m88jhwOGczIPbj5ASild9t2HtaeTg==
X-Received: by 2002:a05:6214:1c07:b0:70d:ba79:251e with SMTP id 6a1803df08f44-878ba0ae50cmr54903106d6.13.1759427356454;
        Thu, 02 Oct 2025 10:49:16 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5ZM8zAeUiI/gJp7LSz5SHI+nDYTySTvME7fzeViGALVA=="
Received: by 2002:ad4:5191:0:b0:6fa:bd03:fbf2 with SMTP id 6a1803df08f44-878a08e960fls11840596d6.0.-pod-prod-00-us;
 Thu, 02 Oct 2025 10:49:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzc2z7/ReuPfHOY6niR884exw6Ht7LfFd39vPHivFYI3FubN1tpb9fF4E4RyN5FhwE2eNDkllPjL4=@googlegroups.com
X-Received: by 2002:a05:6214:f0c:b0:79b:53f9:412b with SMTP id 6a1803df08f44-878bbf0ea08mr61552806d6.23.1759427355640;
        Thu, 02 Oct 2025 10:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759427355; cv=none;
        d=google.com; s=arc-20240605;
        b=eR00z9R1JtXfqa7Uc/2nLyjRYk5JmyuGKi7ll3hdBfzpi1c+Nfq2X0IaDFXuRyOAWA
         x25mS5kaVb3tSic0us4OC0CZgr76QGndGRkswOhVIQk7SlKLgTIf8OncsvvML0cQQAbW
         9RRRMWs43u5lXsfKgVff/NdqmyjOWdXdobwSydc7/u+xL4/xuIe1L2IhAWnNbRvcTxFu
         WB76UcxsI5AEKU7nKoiyjWxKtZPDjmN/xSooWCWatWort99JyuQKyPXWaPI3Os6ulsO7
         D0Lsngvs2NQjMoufwC1zNzSitPcRCW+aCOWVFP0xqKAK7GHLRCXk2vlqAsQJ0dvM5aQt
         hIBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=Q4m4rEVK0lME2HG1avB7odcJPePXmiDNCRAAbpG9RS4=;
        fh=T006y1IzLYlwSnizRC67tcxXZshsKWEsDrzEFre37ZQ=;
        b=irbk3ISEq1YIwTw0d9c2W+vJW8cl4tclUt12NiCO0iKZJkRROCQQRVfc9d9GbykBN6
         dWPGJ23Am+tadocq3iyc3XQpHNmxxFKo3Bn1ZCBA22HOtYgbjCy8DgMZs4LeDR8umKlD
         gpXdRk841XTRkylrcE7dZ9RJtmKDvBi1/R/ws1TqoN8FFowWCKUJrSEz6s/JePdrZ8yX
         1ITABUcsJo7/Sj7ZD0rc3kbMZX3Pk0BDMOSpTj4sj756V5SdWlJwjdpPfdQyvFPktgt7
         TaVh8pyyXiumnj8GUsb9CSCcXPAIjVbynd2Jl4edrn6vuIDlquUaqeApU+MvKQVEX0OK
         C24w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e1trikmA;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-878baa7025bsi176636d6.1.2025.10.02.10.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Oct 2025 10:49:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1FBA3601FD;
	Thu,  2 Oct 2025 17:49:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BF1FBC4CEF5;
	Thu,  2 Oct 2025 17:49:14 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id EB6BE39D0C1A;
	Thu,  2 Oct 2025 17:49:07 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN updates for v6.18
From: pr-tracker-bot via kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <aNpp06-SzK-OOpUt@elver.google.com>
References: <aNpp06-SzK-OOpUt@elver.google.com>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <aNpp06-SzK-OOpUt@elver.google.com>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250929-v6.18-rc1
X-PR-Tracked-Commit-Id: 800348aa34b2bc40d558bb17b6719c51fac0b6de
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: d7a018eb761f44f1f48667540185d025354f33b6
Message-Id: <175942734657.3363093.9632543332234597481.pr-tracker-bot@kernel.org>
Date: Thu, 02 Oct 2025 17:49:06 +0000
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=e1trikmA;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 172.105.4.254 as
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

The pull request you sent on Mon, 29 Sep 2025 13:13:23 +0200:

> git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250929-v6.18-rc1

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/d7a018eb761f44f1f48667540185d025354f33b6

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175942734657.3363093.9632543332234597481.pr-tracker-bot%40kernel.org.

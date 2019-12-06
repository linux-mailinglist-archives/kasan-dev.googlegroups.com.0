Return-Path: <kasan-dev+bncBAABB7NFVPXQKGQEAWYOUOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45764115926
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 23:15:26 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id v14sf743110oic.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 14:15:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575670525; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZkqN7rAXcCUnGQBR4CQhmEcAHcyZrVmNFIoNC+h41qVF5ypEHPlxboFnaE8hKm4QpQ
         ZBqBFht+R0PXztjxnwzRpooaaL0xkWQfua2nZN4ywyg1ZOwYu0yfdNU/6z60RSHd9Pvs
         obOTeCZ6ZcvR/loSvW49FPzQtkXoxCH93k+x5c+0V9GUuj7G9OQxj7Vp0Vy4f2uFjsVT
         lkgOYcUTZ/qypCg6XuHcPwvDnWsr0u6rP+p5t2TEEOgLRYKPTOxjxoiX65SeH20tceEk
         wB2eJ90WNqiMNvs5mL+r5rx1fKbCDglSBA752ieCSUFCfzcMaI4GbFF/6aMl/mK8Z1/6
         xuXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=WbEu3lL+gResPbTJ49g6dJ6RhhWmdfnVkPdO+w/aTK4=;
        b=bZZalhTE8tLdSNxdqzcVeUfE2eLYDSQA0ns4VBggEUan1M5I0oRXfS5yUAr49lK4Tw
         zD0cAs7T01h+pJV2ewv/jJGxv4X0qCkV+g2jttzXI66qld3nBwxPfqbqJD/fITUlLX16
         hYxuyaCpH7YpFqbHK/Kh/lAjVruOb7X+cHIPPVA0nDfmQNcnC+PRD7Fi83Z1PXXRlNgq
         g8ZY78ZwrHAY40Fj9IuRVHRckRXELsKVrafoSjd86JozLROizIACWI0/MrLFxNa1bFfh
         mogkEgWYzD1oCc5UrsjfSL4VHezC1wRkxFuF5CWMTyo2KbjJiLoHYcfCD1uHJOhMMV+l
         7Nxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZhHLnMwv;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:references:message-id
         :date:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WbEu3lL+gResPbTJ49g6dJ6RhhWmdfnVkPdO+w/aTK4=;
        b=bwVZFF8wgde3xoUEl/IVvphGXEt+kTPSB9VqWa8PEBi8+JGVXEAVPwUzfKfsEA03od
         U6FZx4i0AlGo7Z0OVP5yRlaqTkcJT7E9qNczML3qhtpF/P7VoJqFFS40mcFZVO4Y7qUS
         wZvHDbcTNhhvP81TLwyQt+dOQghrB0C4BUbZJ5xzMf1TPGuU4tEBBZSSM79mmpflFI0P
         NWQNLLpZW4hIvQZfi/MhtTbtsF0AADyh1ajLgnfCOlxk1TRuIvu2zOxwWFVnzZPik2xY
         YcPA3KjIqfqEXhblH4jcBbY1gnvjlYldejseQ82o6W0hbeXILLtaznGn7TyvBTiCRXz+
         TbjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :references:message-id:date:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WbEu3lL+gResPbTJ49g6dJ6RhhWmdfnVkPdO+w/aTK4=;
        b=jOrAf8HcKuWPdc1zuoTOSwU5aOPWpQ5xVdUcQKEhVYmZQMIXQfS+pcKuvY8uhGOEhi
         By/zJRv0ok4EDhSQEFs5zf4gK6mgUCkdnWJoBYnrHUmcgjx008WyJMCuEvIB+MjYiLVh
         okqd5TdDUxI1JOyU0G3HHKy8dtg3MVstxVYCY+Usgla00CcsyrJJ7dnAVWcLNwhZJWXm
         w8M0tKwVlr+tHZ3mHMkWsa647MxWxlKmWhbTKlDaTP9nikFd/imWM5HDAbm+nH1nND9X
         rM6tihyBp/LL1EkiUyeMZhZg0oAlisWGg6wz+L4ZrSoXVqDoyftk/VgrdgUXsUN8t9Nb
         33mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUTey6qEqetvGs0tGOV+62BpDFLOIxCwDn232OFc6mySZA6DlbQ
	w2Jcvx5sb9zw4IxHD3whWsA=
X-Google-Smtp-Source: APXvYqzMeXRRLzJiwNQosEvDkBY+w3MFp9+LRXZZHhL+QwkPZciVPkgDVpwp8OlIjrVNTpRiGMYPOA==
X-Received: by 2002:a05:6808:12:: with SMTP id u18mr8609129oic.51.1575670525121;
        Fri, 06 Dec 2019 14:15:25 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d549:: with SMTP id m70ls1556923oig.10.gmail; Fri, 06
 Dec 2019 14:15:24 -0800 (PST)
X-Received: by 2002:aca:ccd1:: with SMTP id c200mr15028285oig.26.1575670524793;
        Fri, 06 Dec 2019 14:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575670524; cv=none;
        d=google.com; s=arc-20160816;
        b=BrEIDCJjta8ognjvdLWbhFxEzESi2ja2VGvnh9VFXEaAEdhMf6vefDJiQmyrM4JhcO
         zOy4PKLGLSVLb7+ciGkBzQDHsex9aascHdSCld4O8bsSobYrKpzDp3gPHxiZCTUKo9Vl
         YNb3+Q3V7mf0ZOZyOYKoD13XzpP1KgVT8Vz2bCPKeyN58Wdn124olNcQrjPasWkJWt2A
         VlYBEi9BWCXtQmftKEYPJAEeM7GEWHYDVxLMZfXtKmnlM3eVF075yRSspJNUZv1pQRSN
         UYHqaYEgORqKjg/H0DrItj6AWqRH8gzC4TiZGK7bfkdyIV6PmDx1RFnHJ2HFnmnZXj7r
         yOEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:dkim-signature
         :subject;
        bh=JUE8oo1XfKccgAOlYtzpnSiUZoQKhcPg61t2rZufP8k=;
        b=if6saQO51LwoUjU1kwoRWI0+J7xEXVw9WLstvezHjS4onYipf/hngipAUEx0JxLdQ5
         4FvH1yv/zq7fuQGG6BYsK04+DxRkTDep2WX5Ko/TfhymtoaXBEuO6Qj7bXz1qkEcz6ZP
         e/+BmgUzxF4VA6KmeYOw4aYVewe8c1an219Pq1CZwFBOI2W5e7am3Yty/i2seqR/1b+z
         VS3Cop0wCmAWUoGmppLUL7oqK8Bj0T48CRu3gRWiqvOhTk98k+YpUDdmZuNIGUrEdlGq
         gkh1hP/8Qht52eIjF0BPaYtQ51aFlkqSL6EK/x+IuTAznpWzMljVfvuFukLV8nQxhocA
         IzZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZhHLnMwv;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w63si867782oib.4.2019.12.06.14.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 14:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Subject: Re: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag
 (topic/kasan-bitops)
From: pr-tracker-bot@kernel.org
In-Reply-To: <87blslei5o.fsf@mpe.ellerman.id.au>
References: <87blslei5o.fsf@mpe.ellerman.id.au>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <87blslei5o.fsf@mpe.ellerman.id.au>
X-PR-Tracked-Remote: https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git
 tags/powerpc-5.5-2
X-PR-Tracked-Commit-Id: 4f4afc2c9599520300b3f2b3666d2034fca03df3
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 43a2898631a8beee66c1d64c1e860f43d96b2e91
Message-Id: <157567052394.8833.9919496603126638238.pr-tracker-bot@kernel.org>
Date: Fri, 06 Dec 2019 22:15:23 +0000
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, dja@axtens.net,
 elver@google.com, linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 christophe.leroy@c-s.fr, linux-s390@vger.kernel.org,
 linux-arch@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ZhHLnMwv;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as
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

The pull request you sent on Fri, 06 Dec 2019 23:46:11 +1100:

> https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git tags/powerpc-5.5-2

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/43a2898631a8beee66c1d64c1e860f43d96b2e91

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.wiki.kernel.org/userdoc/prtracker

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157567052394.8833.9919496603126638238.pr-tracker-bot%40kernel.org.

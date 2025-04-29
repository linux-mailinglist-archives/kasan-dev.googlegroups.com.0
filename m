Return-Path: <kasan-dev+bncBAABB4G3YPAAMGQEBORRA6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B1E89AA1037
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 17:19:14 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-227ea16b03dsf89990085ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 08:19:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745939953; cv=pass;
        d=google.com; s=arc-20240605;
        b=IgcPKhxZRZeC+0yLpnHFjs0sMxFoMJvcfESdJNeZMXoKQAvm6Hi7ii++p+he30Aksb
         TuhYw9Jz5QoUEcYkCGDdEwlraxjaTeGYZ+R0wenO8T3eAoSFhYQLF22t8cNRo5//flHp
         37DXheo9rTFYDBA9X7usaoq073FkAq4eTcFsLjw7aI1CIH/kROLbCq30cRJEZWnAJdm5
         037bSQLEXpBki+I2b5D+VDek9zFh2J0DbOeaP2qVaehD4Lh+pV6Wvq5rA1JerJVGfNS5
         j644pI8fzRragxdTw7MigWO3Uufnl1HKOOib7WVc5LHO4d3UkkZHMBIYY+TObLZ4GaVk
         tGug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=5JGgODjBsG9e4D2btcb0R4H3HfqjxQdGgeftz9XPQL8=;
        fh=QfvuKYwBfiyFkAS4Uku5aAjJTtPi2KZ4wjIpqBumaJQ=;
        b=EnakWcCtkpvEdndO7OCQpgXauWjj9co1VrNz9Ja3swQwYf4aMqEWxLmy9jtHCloHW6
         0k5N/ks8OemG4/5AqTU69aGkm4f7fWQnLTbn05ZEtHUzjgcroG1SZgnJ0xpXTbtGSlYo
         A5O14lNrw4F+z+IfBx/loiMt1BRjaDxWWy93ANPUIZ4KWNjy088RyRSI7EInsXwM87+/
         vdOG0Yhf1DIEf2SgRJuFgwmurpu/YegOKl9IrDeyJW/3E6NvNlNokmhUZcDrsYULuGI5
         rWsZyw0BMCRMTlzewNMhJIoOtbyGyaRkMeAlSaTummaFprl/iMVzWVLptDyjhMiEqTQk
         13Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mvbdb2eg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745939953; x=1746544753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=5JGgODjBsG9e4D2btcb0R4H3HfqjxQdGgeftz9XPQL8=;
        b=rt8gc3kebZY5aLBl9OSyR1AEWDuJk/biafuAo8VgHn7BJT6cA7cI64czmA8dvdjFOv
         woJOI8U9zX3/iVDVxBu9br0dvHmA7rpq3LW4EZTubYdWHne7ZRqJN5w+5hSbkPIhBYGz
         n4vuTJzPPBMBdWdy2BIKQ4SflO0Zg8IqOaZ1UCDJQP6iyfHvGf0auohhnGi9qouv9Lp2
         jPzuLqjUwcYEJkBXyyNAqRtvyDlZU1e45EKXL5oMl8RqFhdoE/ACSKkJKgpQw7uZc3Gg
         gTTyHtscnWUyKSUHxdBGTv2Wey2j3nmiPEDE0JWPUipQZblbM2pFY/WaAndYwByatruG
         QVbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745939953; x=1746544753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5JGgODjBsG9e4D2btcb0R4H3HfqjxQdGgeftz9XPQL8=;
        b=TXCglvcwr2/20QJ9+FNVaO4HjJnyWeLTLse/VJosihjqm/SqhD5u66WJ14Iq5WQdTn
         EQ1YFAXXaT+vUEhJtDaI5jjdZVdFvCmrizZept6Zo1l5US9Rl95/Fe3inu+jjm/D+YKV
         cM2bDGICeuAxHRmbLGQL2WDWh3yTk1Tu0cJhmOzdJyQIrUo3dn+MQfRP07018H5xGygw
         agz2S2y9qVLwYXLiPpNh1wfQcvyhkbUK2K2EvKSN/nCt8qQJuRLilfMFtH4tbrr1nGxw
         i9a/7oBF/IxznHcSv9yhJt4j/uOQe43Sg+F6pY45sZ/aUJ/fIwX3EbRcsZbwWAH7/hkr
         UuoA==
X-Forwarded-Encrypted: i=2; AJvYcCX9j1hLwLpDgE1ddFk9KRz6Ab03Q6YjY+FJ5LBiOmRaU0HZ4O4aGOKb03PYSfm88Fj9UvMX+w==@lfdr.de
X-Gm-Message-State: AOJu0YxFIc/ZkECU2ZwQjx67Ig/I+gMc7q//WSYbJxBcjAxo/38yOdR4
	j7T1UP8j3zwcSzpGzWEa4LaE2adpPiEgKY7+g6OJ/px0ZIsX7ZVY
X-Google-Smtp-Source: AGHT+IEh0V3qpOje0woiPdk/Y+Nx302a5/emN0oxynmGLdA/q+xmIMzPk7YrJq4lQBELZpqoMhXyyg==
X-Received: by 2002:a17:902:da91:b0:22c:33b2:e420 with SMTP id d9443c01a7336-22dc69f82bbmr173564445ad.7.1745939952856;
        Tue, 29 Apr 2025 08:19:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH6m48/X/sZdenCgeLmNbIR2Cik8Mlj0ZLnxh39vw+ZHA==
Received: by 2002:a17:903:2f47:b0:216:59e6:95c5 with SMTP id
 d9443c01a7336-22db14d1f54ls3211685ad.0.-pod-prod-06-us; Tue, 29 Apr 2025
 08:19:11 -0700 (PDT)
X-Received: by 2002:a17:903:41d1:b0:22c:36d1:7a49 with SMTP id d9443c01a7336-22dc6a8a99fmr214512345ad.53.1745939951534;
        Tue, 29 Apr 2025 08:19:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745939951; cv=none;
        d=google.com; s=arc-20240605;
        b=iBPg7CovbAUROE1FZba7VOk19lXtHRAwY4D9yPtJ+1FxPomu6eH8nVPLwxQisczNTN
         ipsoYiGKasN5bha5VS6UOdbkVlrb5vRXSojNirJ6UOro17KaBXBt7ELtN/5M60+jRhnG
         lagiKfqqmrqbtOgH5EToNXU1suIyXmV3n8c7Oq0K89sGwEiUnil4pcfyFbi/4oo+epK1
         SH4XBDDKokVaanmLqVgYJfoq6YczwROuYRiFtC7mzY8dMUhN/l5SyBzCItPd2c/dgZrj
         gWtd4lE0etXXGrV9gjIsFsQKrrCA0OVSMvr/PMgimWio0eRg58XNk2QoE096VxtLSViv
         MDIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4Nvj8zW5Hb7mWtDEG+/pJ+m42K+9BXKXE67fSPoNJHo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=LQDNWm6XdpEcWrYM79lAJXGQmBYUCxmG1G0zoadH3huO0IxVgjJtixS1Z5HjAAYNEz
         iVKt1AyCRGH18co35hLb1/NTwKRwshGGaPbyYbrVtlOYkgjsKsHb9bmAF4O+yXJWCh7H
         uBuwLtpKCn4mAf9S7zXn/lhrpmmSWoL8/QYSaxsaPJ5l4Dn0ihCUE6+du1GLCFjP34I7
         YfBk+ak7rzL6VD1NO68oG9uKhgN9JMXkzspEQzn93pYB8jbA6Yd1Ti0MaYPn0Uwo5SyV
         u22BKNLgs9rHHbUgpca2KnmN4nmwWAXk1cMvVJADNWi8xvjAguGZWfsnTsTBHTUMPQxp
         O3rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mvbdb2eg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22db4d98fa4si1253095ad.2.2025.04.29.08.19.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 08:19:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2130C4A90C
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 15:19:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 30574C4CEF0
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 15:19:11 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 29B79C433E1; Tue, 29 Apr 2025 15:19:11 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Tue, 29 Apr 2025 15:19:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: kubakici@wp.pl
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-199055-199747-0l44cQzegs@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mvbdb2eg;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

--- Comment #8 from Jakub Kicinski (kubakici@wp.pl) ---
Dmitry, check out this diagram:
https://web.git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/tree/include/linux/skbuff.h#n734

We stuff some metadata after the tailroom so exact allocation won't help. Since
we don't zalloc I presume KASAN will already know that tailroom is
uninitialized?

As for config -- no preference. CONFIG_FAIL_SKB_REALLOC is meant for syzbot,
too.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-0l44cQzegs%40https.bugzilla.kernel.org/.

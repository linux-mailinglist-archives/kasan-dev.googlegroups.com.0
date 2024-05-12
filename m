Return-Path: <kasan-dev+bncBCS4VDMYRUNBBWX2QOZAMGQE4NOTSBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FF988C37C9
	for <lists+kasan-dev@lfdr.de>; Sun, 12 May 2024 19:33:16 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6f0fa7ef532sf1813786a34.1
        for <lists+kasan-dev@lfdr.de>; Sun, 12 May 2024 10:33:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715535195; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZK/e315wLVaDiTqxufBQrhB5xBophbblw2zPt49Ue4+RKrG0J8dEMYT3tczvsYTTod
         stMrapmbZsDfHBy6UDlwPZLiGQyYgEtT/NbxUSyCjewt0/XvPftItlV5b0o35ne5P+V0
         gbnyrrEvqGiNdusuHYks2Cgt02C5HdfUmKM7ydjVyvsGxx6t1V/S55JPnrtPJryvb7T4
         a+nol6CNqxZ7Mlujrj3/xB5O7JmBk7gQB2kARZtgDhYd5pf+rusrDErWWsCMra1e0b2n
         jRpIYFjXBBjysx92Bl9KOb4ftHqakIdQcdjlhErmq3oI6ETXgpQhSMP3N43VmBycdKDl
         8k5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=nEQGKfIxTlW1V6jBMFzabWs7EuO5IPwWPxS0iiQ5dHQ=;
        fh=mIjqFEkDbSWTGMAPFE8yHEoUN1JampRVDSm+wD4Kdgs=;
        b=GnZWVUa83BUieglDvD24vdnF/05zdaa3QZUaiuxZvrPghCBJscMEOyZLwR09BpRojV
         VgYGAAuVWM7izy9doDNz0NEIp5lMf6CkF95POAPhEu86dO5Jz84VuanSxqE9sjL9tynS
         l4b48Z217FcEfeGB/s8p2YygKGF/uFQjTU6tpX+ytHJh/5pZaoFimT9T+9bWGh6yfdgc
         xxXNDHBg52d4qmthaASYD7iyTx2aoolHopiIMPaqyUMPUUG5Gr+dk7qOk5fazjunL/S+
         1meDmM9j0/4cPO5A6pUJL67pxaZXl7DLMF88n2keQWkGDkOnOt5uYFdmgBhtpSnlxEtd
         DVzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=maKwvppI;
       spf=pass (google.com: domain of srs0=oxfk=mp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=OxfK=MP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715535195; x=1716139995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nEQGKfIxTlW1V6jBMFzabWs7EuO5IPwWPxS0iiQ5dHQ=;
        b=w/VUzL9gF3AaK3LVrjScE1WZl4EYsUVHQNNOYi+5ftrbnMaK0BfPAUW6sgQWhk1tua
         6PNx15gYzztufVP5J4Rgde74xKVKgs62gnuXbecwbEX+8ypWFDrHz7ggcrg6IOS7Kh/X
         oEkwmOQH3JEwMGD5gLPppKgWQvQZKCZ2wYHT0F0eUbhJoiTRbFUxOn3u8JUlpEorETzw
         Y/Bki+oopx84NLISKeQUfquLB9r40whk1Q1/HfktRFnC76i0O88O+0iRPb7EO4eTB/dB
         mcn++LOuUyiDAZ5Fo1qy8rk639O3Oi/EMEQgk24Vj/YKqiFxcwMfve8VtXymiWlE3PXm
         CnjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715535195; x=1716139995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=nEQGKfIxTlW1V6jBMFzabWs7EuO5IPwWPxS0iiQ5dHQ=;
        b=AQXyHovmd2OSo6/tfhREtvvAdQEJ7NhFLQATZ9+vx77vwHacGh6ePj+RlijwWj2zXt
         AKWIzjHniWLbuMZXkXZlBwqeU3cfbgAzY24VmkKYGCSSFc9Pr+YeP3/JvlLghuXCw0wI
         4IPRtFf+6zLi2H4FWNJHbp8+0X5Ci96sbp/Pzsc5P5uXnB1V7cfPuGXALPgcqcd+MPsT
         6yqPGdHUKrt2F/saHASQ9bag2PQPWLAiLDp5a6ja29LK4xyhmCTLBxYYjk9pKf2/lUzv
         +aTn5AzqYZ0fBqwoPjdtmNFfdGyIkbBdoOjxF6Q3mjJMQi0O4imOYNjtDFrPBVkWpsAJ
         Fm1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVMXnA6VeHEHVyR6fAP3kZLAROvqRKmFJgchVccByiVda2zBqbt2YPXV6Bhoo02StWEY7sAzyY8IHb5OiG6Dvo8nUxVZzSdA==
X-Gm-Message-State: AOJu0YxMdBqDArUbenYF0MBlSnEl6/FSoL8/TcPnCnVM0aR/EOMGnUP3
	AO3j4427DeM8DEI1SOSjG1RwLGXOvZRkhDsEUFyO6jCZdHQsYOoh
X-Google-Smtp-Source: AGHT+IEG1CW5x95x52mf5JO1n9WF2Q0viUn8pwHhGPnVyZkdVbksW5Ep5zZ29pAL9Tn+jWD6etE9gw==
X-Received: by 2002:a05:6871:d048:b0:240:889c:4b27 with SMTP id 586e51a60fabf-24172e41e17mr9991838fac.40.1715535194827;
        Sun, 12 May 2024 10:33:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:15c5:b0:23f:a7c6:82 with SMTP id
 586e51a60fabf-24116925f1cls166556fac.0.-pod-prod-03-us; Sun, 12 May 2024
 10:33:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQGIxMAlFu8pdaxb1R29WJYfB/cNMr5oKsQYNosuwudpwsjqA6UeQ1gm5lZtiTPVYdFJspe2/6cJoLxLkZ1OImAZM3YkUPoBnmow==
X-Received: by 2002:a05:6870:ac9b:b0:23c:3509:35cb with SMTP id 586e51a60fabf-241728f4da3mr9672236fac.6.1715535192598;
        Sun, 12 May 2024 10:33:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715535192; cv=none;
        d=google.com; s=arc-20160816;
        b=LCmH0wU+r+2g4fmnjIf1OmqYj9/FkGCwjZv95oOfx2fvCe7J73Dd/hmgAjjzLDKCbm
         WfNGgGBJlCGXTl7AjqV+Q3gfMtlQ9qbtBdhv75b0f1hKIwPtu3/05M0cPOJP5E+IbfN1
         FUNgmmvaHtD1rLIw2A7q17ZDaSEyfUqk7dD9y2LUQE/YZ61bvmAUGdUoBWq+tfbN0FoH
         7x193j/MOklzu4CGKvIbQ+Sz4cleWso0Ytf4EJUwnpjAlXC5K7dY4MPVT5cjOC4f5Pjj
         BvbHZYF6PPzizZ1bREpDqow2EgDGZcvOTrK4rpd/Xlj/WZSbrlNcPBDWkdGDgdyVltg0
         TizA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=uH9ssFQWCovgiFIzzN+yE2gHBu2+zYk7U4eQHQp3apA=;
        fh=OgXIwGoTpfKTTFWpc3O3nxHrPiUR3vXAp8tx3xelcJQ=;
        b=o5HDn14oX0f6mr4uMOnlfynDSquNK024M3UNKyISWv8KAUJaXMQvNvBZqoUQVZloQg
         PMAjZyXAJ6GhEznOD+DmfggBcReSuPcHgXoai/Y20mMfu9+tYjK4JDMWkX7NhY8jZsTf
         JJrSKWIZuPM9Ogbnyv2HF4BT40qbbWTf3wxNoL6+Xd+cVsSESEMzYQHrkwdaPcoQqsfI
         iCiXFCMjK+wevJE6pUDS0I0cfCPD3a+dhzJLnWYA3p07RHekkgEql4GoCVeMIH82403W
         Waaib6xU8hLDQSfnL5KkKAt99dHQEWsyknvxXEYcX+DnCK1wfc3kdIBj3UF47Xx7hqNb
         jbqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=maKwvppI;
       spf=pass (google.com: domain of srs0=oxfk=mp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=OxfK=MP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3c99388bc7fsi358641b6e.5.2024.05.12.10.33.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 12 May 2024 10:33:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=oxfk=mp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id A8B02CE0ADD;
	Sun, 12 May 2024 17:33:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E0EA5C116B1;
	Sun, 12 May 2024 17:33:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 4BA5CCE105C; Sun, 12 May 2024 10:33:08 -0700 (PDT)
Date: Sun, 12 May 2024 10:33:08 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, elver@google.com,
	penguin-kernel@i-love.sakura.ne.jp
Subject: [GIT PULL] KCSAN changes for v6.10
Message-ID: <ccdfb04f-9d2c-4033-a29c-bb9677fcbea5@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=maKwvppI;       spf=pass
 (google.com: domain of srs0=oxfk=mp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=OxfK=MP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello, Linus,

Once the v6.4 merge window opens, please pull the latest KCSAN git
commit from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.05.10a

  # HEAD: 31f605a308e627f06e4e6ab77254473f1c90f0bf: kcsan, compiler_types: Introduce __data_racy type qualifier (2024-05-07 11:39:50 -0700)

----------------------------------------------------------------
kcsan: Introduce __data_racy type qualifier

This commit adds a __data_racy type qualifier that enables kernel
developers to inform KCSAN that a given variable is a shared variable
without needing to mark each and every access.  This allows pre-KCSAN
code to be correctly (if approximately) instrumented withh very little
effort, and also provides people reading the code a clear indication that
the variable is in fact shared.  In addition, it permits incremental
transition to per-access KCSAN marking, so that (for example) a given
subsystem can be transitioned one variable at a time, while avoiding
large numbers of KCSAN warnings during this transition.

----------------------------------------------------------------
Marco Elver (1):
      kcsan, compiler_types: Introduce __data_racy type qualifier

 Documentation/dev-tools/kcsan.rst | 10 ++++++++++
 include/linux/compiler_types.h    |  7 +++++++
 kernel/kcsan/kcsan_test.c         | 17 +++++++++++++++++
 3 files changed, 34 insertions(+)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ccdfb04f-9d2c-4033-a29c-bb9677fcbea5%40paulmck-laptop.

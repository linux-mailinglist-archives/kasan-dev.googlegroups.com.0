Return-Path: <kasan-dev+bncBCJZRXGY5YJBBSGP2GEAMGQELHZ4IEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E70E43E9B83
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 02:14:01 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id z1-20020a1709030181b029012c775d35e1sf2436783plg.20
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 17:14:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628727240; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3O3xE6FlkBJbHeGwS4WZqnmHvtgbbNpe7GBYyunh9Ft9lrR1HHr5uNWs1NiMnFrsE
         8we85pPrNVMshoKZse6GERUy0U+s2r8H22dBrbQBRxUR5C3eU2gA9jTdCE/Uapjr/Xg4
         xtn3VIXUxYH01xSBdpRA35MS6X4XWQcJ8trpzF4qN7wLIRe8LX6cNcdCVaEWvUh6c1lr
         CpHqMIFn0kjSm7Y36zlyjhn5MWZf7msIiDrDSNqyMISFM/ZB94/d4fCbMz5fQN83pCrE
         vHWLgnF29KFudN/PfNY/z4vjb4CWPG2Hpasee0fnK2maO3dahOYLbnVncaL1UavhXCBf
         KuSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QNISp26d502hwQRdscXmM6jSQnbF1mUV1Sum7bCI7MA=;
        b=w/sLkCli6/Wis+hn3HBOvUhR7UiyWoslgs2gy2XHD+Ace7F5IAjDdf3TXBuXl9qw1j
         myK+iLLfOyArE6VdtWRvsepSmSzCZG1lD/LTHSa3kfi2xKog22CVFL8WqxZTd0t6VyK8
         BgdRo0v865P9EaBDxSQFpFF7mktL8Y2OPLWgUFQ3lAGpwIlj967Zm0PI1mc1BVauKWKV
         +WyGs5PCd1t4q64cjNgTaE7oM1hyDpx7BTAKuG5kZlJ24fW9RUvqkciVDW6XyNuO0ANg
         k0c8WoIL/bQRvZ7TbCVAv6PhIRdvnUrYLbpYDnXODRVu89JrsR81lqFvqpj49QT5TnDG
         BXvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPHbW4wd;
       spf=pass (google.com: domain of srs0=whka=nd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=whKa=ND=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QNISp26d502hwQRdscXmM6jSQnbF1mUV1Sum7bCI7MA=;
        b=BAiS/nq1Kt0H1pBc1Hr368evPE1JaJrZ4S3qeWG7BwYDy1f4EsXVKUM1cAuiDQUA5z
         IFwbARTvil5eYc0PmfZrtsp7/UsZxfz8CWe6Pi9f3zoPJyOd7z11kYsFDp4T2YHYjB7p
         UOXkcv+AogbR5XegbiZFLt0wyQQ7lAnES4kBHDwX0e8h3sgk1yKBr4MitiOw6xXRxbzY
         3zsbIYhwAx5hjVAND+r1kz96CzL1GSfFTJLWJGuuSpEh3d4cMsOkJkaDo1dZ6Vqdn8lT
         pCYAhIDh2E82MSD2BeAsDE9NCMxgokfoQbxK3btbt5kHUhknxu3IqpGG+TkKrkNAzD9r
         +N4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QNISp26d502hwQRdscXmM6jSQnbF1mUV1Sum7bCI7MA=;
        b=ndy2mAMtumhgmBzLu2m8//WJlcrpJpoBs99ys+NFW89xVlE52nI5ni4BwE3kvRsxLH
         otfbJ3axeLVivTqtWj1CDbI5JT9vemFQ2Q0Bby6gFmjT7Vm65fTfs8yk+mhMZU8NvLsB
         Jj46vPKhRjbwGAndKrcXl1vGXME4Ho0QFDiU5wTw4Z1RJDmzKFIeywQ9gH+OhD1wOy3U
         sXft9MnK2M9JYu64ZlXkWhTUy7VGk7tY06a7mAzDaQ8Sb6a9OSJ6mKoERB3iQct0pupQ
         yi5zQufddXBP4ACntGZ5+XyiVQZxVRBjvV/KVJ1u9YE2lpoRApnrY8Wmh2t5iV1vkcBZ
         rGMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322V+k6SInH9ydQSFrMXgwvgRKL4BNDTm8QP/+90tASVEr9EtoI
	1MSxR7mydg944Xew3isya6w=
X-Google-Smtp-Source: ABdhPJzHabRKtiPIAksr17BuYLRujbTz9z+J3tpzH+JtGOpdSymTsPI4eLHa+8qL33DFb85g8pkwdg==
X-Received: by 2002:a17:90b:e87:: with SMTP id fv7mr5153627pjb.85.1628727240404;
        Wed, 11 Aug 2021 17:14:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed82:: with SMTP id e2ls1697589plj.2.gmail; Wed, 11
 Aug 2021 17:13:59 -0700 (PDT)
X-Received: by 2002:a17:90a:8688:: with SMTP id p8mr11670821pjn.154.1628727239866;
        Wed, 11 Aug 2021 17:13:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628727239; cv=none;
        d=google.com; s=arc-20160816;
        b=jePKSmsWaIUq5GNpyCpj8FWaWCi+UHnAf8PS4t0eRYAoYxn8kAHlx9xxY8p9OsbtVT
         zCpR+sOtkXlHVmaRIVKO0/DEScJnFPKP0wMutD0syWFdCWG08pw5pn+hlIvSzQcLC4Zv
         aMXVNKtal591Fs2q/pctuSpqf+dPAfCn3k7qB2A2VQrLMHtooF+j7JvUtVB8oQoDZEoF
         PPK6a/IRVM4SFL00tvUuU4ULtCJ7nP5Ny60ELwAVP6hvs6rPVQp84Pv3G6kE4eJOLblp
         sGqGPmLahsfnoEUV5LuNewxnBo8pPiNB1j27VwY/E0aLc+z7EOaw1mPNeAY2SOEnKJXx
         BsbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=/qRQAh0GwnTltnZC0lRShRhRfQDzQSkHQnVR9W2rKtU=;
        b=YmcRGse+dWStddpplU0G6hX+YvrTjktnSR0cnxbSHQODGd4m3MdWYhpD+ExzTsA7Bn
         uO5B/ki8+11yzG8MhhXovAiK/4uhDrsmeIPtVEb0meBIQrAH+uBO4ZlqQVFdZrrmwOUI
         haeMa0zBd8AXfP8oqV697GN7YzFMuzOZJ+u8NwdbK3V2eJybdyokVaGJx1O2xq0stQTN
         YcZZD7VNWT7FyFXBHcz1FrJ956kEgTxTnMBpDe8sqRiHMdDviZCJwkONuJghdZK/wEEy
         nu5WcUnAKPKEVtuF5AmFUmrnHcdirX8gF2ayTr4fIzOsP5CGXVQDuhp7y5oNyXdyT8wa
         y6eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPHbW4wd;
       spf=pass (google.com: domain of srs0=whka=nd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=whKa=ND=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v24si38562pgh.2.2021.08.11.17.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Aug 2021 17:13:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=whka=nd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 77A2F60EE5;
	Thu, 12 Aug 2021 00:13:59 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 465075C0981; Wed, 11 Aug 2021 17:13:59 -0700 (PDT)
Date: Wed, 11 Aug 2021 17:13:59 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: elver@google.com, mark.rutland@arm.com, tglx@linutronix.de,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com
Subject: [GIT PULL kcsan] KCSAN commits for v5.15
Message-ID: <20210812001359.GA404252@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SPHbW4wd;       spf=pass
 (google.com: domain of srs0=whka=nd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=whKa=ND=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Ingo,

This pull request contains updates for the Kernel concurrency sanitizer
(KCSAN).

These updates improve comments, introduce CONFIG_KCSAN_STRICT (which RCU
uses), optimize use of get_ctx() by kcsan_found_watchpoint(), rework
atomic.h into permissive.h, and add the ability to ignore writes that
change only one bit of a given data-racy variable.

These updates have been posted on LKML:

https://lore.kernel.org/lkml/20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1/

These changes are based on v5.14-rc2, have been exposed to -next and to
kbuild test robot, and are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan

for you to fetch changes up to e04938042d77addc7f41d983aebea125cddbed33:

  kcsan: Make strict mode imply interruptible watchers (2021-07-20 13:49:44 -0700)

----------------------------------------------------------------
Marco Elver (8):
      kcsan: Improve some Kconfig comments
      kcsan: Remove CONFIG_KCSAN_DEBUG
      kcsan: Introduce CONFIG_KCSAN_STRICT
      kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
      kcsan: Rework atomic.h into permissive.h
      kcsan: Print if strict or non-strict during init
      kcsan: permissive: Ignore data-racy 1-bit value changes
      kcsan: Make strict mode imply interruptible watchers

 Documentation/dev-tools/kcsan.rst | 12 +++++
 kernel/kcsan/atomic.h             | 23 ----------
 kernel/kcsan/core.c               | 77 ++++++++++++++++++++------------
 kernel/kcsan/kcsan_test.c         | 32 +++++++++++++
 kernel/kcsan/permissive.h         | 94 +++++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 42 ++++++++++++-----
 6 files changed, 217 insertions(+), 63 deletions(-)
 delete mode 100644 kernel/kcsan/atomic.h
 create mode 100644 kernel/kcsan/permissive.h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210812001359.GA404252%40paulmck-ThinkPad-P17-Gen-1.

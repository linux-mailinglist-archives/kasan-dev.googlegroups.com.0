Return-Path: <kasan-dev+bncBCJZRXGY5YJBB2UZTSFQMGQEI35QCRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AD9F42C6A6
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 18:44:27 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id z10-20020a92650a000000b00258e63b8ea1sf196266ilb.18
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 09:44:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634143466; cv=pass;
        d=google.com; s=arc-20160816;
        b=dyecL7ur3Ar+EUJXNX0WDNsM45jxMW/0fG0Ph/FIarp04qWRoYjw07+r7qzjk6Mj0L
         YH1wG6ZYGOavhrIbLek+/IT360K7Oi3dFHAi3xQKA2FH9nbzyOy5yoOwWkVTOBifh5So
         SX2fVry52gnBzX18CJqtvXJUDs9ges4SPndpNhbdsJYYuJKWrkRtN42MKniaOK3T5Nie
         F5WLUDsRnEeCfU3Gfl2HXB5QbfT/vPauvdjBE+ltZ4uqblenoAOn7QlT63BkUdkMiSKs
         a/KpiDMDRENVvrHV0Te6PxbdErd6uFJJLqbDAVkz0aUGrBVI2L8/CwCV5ov4QmQF43By
         lKPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=obujq6zZveVPISNk3YKSfhh+Ynquu2PGViBRncIilYE=;
        b=HB70QJSIqADe5LsmA2xPZafUAKz8pi1ePhoMxe52B9AtxoHV3MAIIrdyDHQrn4A3R/
         JgWCqxKgxU4fFR8/fxfq31K9WXE3DSpSfPVQurw7rdvck2Rf9/VvyyTiKPbToamPVn2q
         f6D2nlsqEcv2vM9EjrMa2kb4j5OT3+xQ0VtjjqWLBujQDpDhTdqFVMZ5adE5s1PPfCdC
         MY3Ff3jMr3K5mANEA8l9F4W/mQH27KP54PC9x7JKwi/E2fT/oqsH9cGRy6LW+lrIRcvP
         pAQb/Nxsg32xZWs3Dk+TqECcOWFGy1DbLr/3Uf2RMDNUYySdIWwC0D26UI9weaeBqfJY
         rKfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=djWf7Fv8;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=obujq6zZveVPISNk3YKSfhh+Ynquu2PGViBRncIilYE=;
        b=Yg1yMM2Nv8dLhwoVqwMORZNLd6tmHmNjIWIrSCzSgZ8i/DTPuNpONqY6J3M7fYAfhC
         ALYiCAUcvDvRo8jn/l0Ro8B8m71JGSain2ikwvRlCyZEhEnZPwdYaIz30hmiOXHxDILK
         qLg/+QvV4HqE8JZZcLKUDFQTHBvqGRBjd6ff+Iunl6uIkmNdbp41im2vjgcbatI8bdgT
         d1wU/wZQx3gxnOsO4qFgnhfdhgjY8iDKChuvUfVAGQPCS0yG6xOj4KTgUWt2Btbm6rgq
         R+Xmvh3FiTqPzSRBsgqKyExKXZ91ERqvdRhPVEoCbGsy/KYErqMgj0Gq61VFJD/tGUqR
         Ac1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=obujq6zZveVPISNk3YKSfhh+Ynquu2PGViBRncIilYE=;
        b=0P7Z+myLMlJbGQkYVO9f/ui7Fc3BSzxF4An0VdcXNCbkhDI2hGu+c2ktDFfwT/JqMg
         Vzw6524DcfDjYisIME0d+KVK1qNOemf4UIMOmBIigfpc1KTliY4U7PxJLs+Sh4DIivgS
         fo5/0WpuiY24W3Mv4qty6Q9QeuH6oAN0Bowd0fenNF7S4Jj7LkwH5rggz/C4oAIWkGjq
         UJ0oyot/Lj5ZlnfccKVLnTTQH4421PGwrNUP/dNRxsnpijlrNiCRU89Ya4gLAIIEU/46
         H9P0lXloSdQ8zDgbsxZOPhvOzdbyeW0035pSFquMapzfNYpoy9RL1HUc/Rmi8AUcE8HI
         FybA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qk1eKBH9yDEXOim4ofv5mm8OEGy/PrdljSrasgPjd3DOmYhIS
	aBNlKTIx39JO77WqarInZoY=
X-Google-Smtp-Source: ABdhPJyYWp1X8sI+ZhnZEh8Bs1GjedQiXKUWAykkYikTgaeNzZEWQNpp+VkiE3MexrynCnfFSi8ObQ==
X-Received: by 2002:a05:6e02:154b:: with SMTP id j11mr89702ilu.236.1634143466092;
        Wed, 13 Oct 2021 09:44:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7ac:: with SMTP id f12ls798015ilk.5.gmail; Wed, 13 Oct
 2021 09:44:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:190a:: with SMTP id w10mr59360ilu.243.1634143465795;
        Wed, 13 Oct 2021 09:44:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634143465; cv=none;
        d=google.com; s=arc-20160816;
        b=BvEZ40J2XClBIHeJ3qA/CzdJiOxUobfZLu5MzWbi0NPsbiD5CDdKZluRoVptMo55yB
         Ty0Kwz/HDbjAY6rOnDtwDKM3unYJFWexaoI7118ZHku0aZ9Og472b+cMG7Sx11wRu5T4
         6CIeXOUYoULlqir/ms/ftoQX1gs3+6GxBlDDkSClDOcNj2C5jPYD1a9kc1mWMOL+mLX6
         iH5PbzwHGyOJGtZ3VK3qEi5S62qSTAUE5b2fcvEvIOl9Vi4SY3QTJRcpRF2uVM2UMswW
         2R6sVpylmBrHgnmNLqjqT7J6ZXPQJbE63Ed/61YVUGyjOcJJ2KjB6JQKv3L3xQf2xx5Q
         aHSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=j0RlFYjv60E+awOtrUn0ONRy4eLFVOgf491IXoe1R4o=;
        b=wN8JTp8ar+XiLosn4+PS0jPbGceHJ5Sh3rtkZx6dTmyxbeGzhSgCc1pGzRaoHtBSGc
         66i3vL+u6AmSjybBL2tNS6vL+yt9P7KDO8+RVC4OWy/2xVaHq0VW3I1I5iY6btRYOeeY
         0N3mn6LVMO02TneBjRXZmhFWzGdFFLSsu6QAuedQ/a1c3nQt0QfJA8uwzsC3Dd9s0cUL
         /xchBBifUZGBypwRtbmpuuc/THkpD3ojmLZ1tpLv1825Y6aJKf4KewnwwbXjH6K5+bou
         CDmOtKOhdEMxvM4oDwWzmCuSNhvtHLZOWJCX9I/YxvGJhmVqvn6n7qT94zNYSwi9IBvO
         j2ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=djWf7Fv8;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e16si11250ilm.3.2021.10.13.09.44.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Oct 2021 09:44:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DF8F460C41;
	Wed, 13 Oct 2021 16:44:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B0ACC5C0687; Wed, 13 Oct 2021 09:44:24 -0700 (PDT)
Date: Wed, 13 Oct 2021 09:44:24 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: elver@google.com, tglx@linutronix.de, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-team@fb.com
Subject: [GIT PULL kcsan] KCSAN commits for v5.16
Message-ID: <20211013164424.GA2842388@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=djWf7Fv8;       spf=pass
 (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

These updates fix an initialization issue, update tests, improve reporting,
and provide support for scoped accesses.

These updates have been posted on LKML:

https://lore.kernel.org/all/20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1/

These changes are based on v5.15-rc1, have been exposed to -next and to
kbuild test robot, and are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan

for you to fetch changes up to ac20e39e8d254da3f82b5ed2afc7bb1e804d32c9:

  kcsan: selftest: Cleanup and add missing __init (2021-09-13 16:41:20 -0700)

----------------------------------------------------------------
Marco Elver (9):
      kcsan: test: Defer kcsan_test_init() after kunit initialization
      kcsan: test: Use kunit_skip() to skip tests
      kcsan: test: Fix flaky test case
      kcsan: Add ability to pass instruction pointer of access to reporting
      kcsan: Save instruction pointer for scoped accesses
      kcsan: Start stack trace with explicit location if provided
      kcsan: Support reporting scoped read-write access type
      kcsan: Move ctx to start of argument list
      kcsan: selftest: Cleanup and add missing __init

 include/linux/kcsan-checks.h |  3 ++
 kernel/kcsan/core.c          | 75 ++++++++++++++++++++++++------------------
 kernel/kcsan/kcsan.h         |  8 ++---
 kernel/kcsan/kcsan_test.c    | 62 +++++++++++++++++++++++------------
 kernel/kcsan/report.c        | 77 ++++++++++++++++++++++++++++++++++++--------
 kernel/kcsan/selftest.c      | 72 +++++++++++++++++------------------------
 6 files changed, 186 insertions(+), 111 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211013164424.GA2842388%40paulmck-ThinkPad-P17-Gen-1.

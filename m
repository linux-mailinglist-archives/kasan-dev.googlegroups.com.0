Return-Path: <kasan-dev+bncBAABBH5AYX3QKGQEOYBSPQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 192E02045F2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:13 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id a18sf9178849oib.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592872992; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgB/DEJqeOXVk5MfnrKEIf2F/LkMXogu14KjUHvbS2ov17pAJ0UUS4J08WCfvcyV6D
         OE+EWm0AB0Mk2NjOb/pfbady23cPC8MCB57wjSK2lwAdirgSBSIDSO+jIL7cvxwC9AlT
         AX9JLO6/GFyVOuPhcJF4ZujmB5mJ3J9S/NXdJwep+Kbo6/nqTw0+MYeGX8VOkx95oZPy
         zPCvyLwFIHUauN3KH4tdBjlqkKrfIGkrIM7nCUeZdxxRQxiWoFjndZEM9IjX9/977sZy
         qIYne6yakwWXgdgbebhg6JiU4yY2IKkVoqTreG1+jBmC+hTvlm3jlceCjeRcDKBkXTi5
         QaHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nWHbWUKDYIX2KCFsNgph3+49EZVkJuSZrvRbyPjSCu4=;
        b=C4nPaf8J/omlxao7a83dZooHYOwhDKLEDj3H7zxB2fBhJx5SWi636vFHuh3GDfklKY
         bvgQYfYks9TO/wQPi89wse11FvpZhKWJU+Tjrdx/AgCKhpjNLqbygDuru2BrssIEHkiA
         cXEyPPA8oBIj22QYEPw/od4aRAtPMtgg9W7CzPBjNorJOb0uU99b6ivR8HBpmMIIqPPS
         DHypfVcVEPu6dOMwgy/xkrTkBdNZFDx9QngjaBwyMM1UzQ558yWIr/iw5/z/Z+yH84vt
         o+N/0fRc2gRfmhnXs2y4gAQ3oEtiVtjPAG4AzvXCLv1J+Lm3xlE3tlB9mSKSGFClNMrk
         LW2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=REx5tHWK;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nWHbWUKDYIX2KCFsNgph3+49EZVkJuSZrvRbyPjSCu4=;
        b=kFUBAXaaV0UDoo2wz5SPfospeyOvRfsRdysJNZz53MIxNjdc19SOYLakqui/EULlYx
         iBy70NxybG4OyBevIej/G1ZoT4pgQoWHwa8lSttNqKyCl5vfnWv6AzXenyAneHa0OjlG
         epvZzOKdLDBXTEPKZKaf39TsPiz0IEjxrP1okQtCFmM/bzZUlawWbMtmlxAerl/EsCjI
         ZFbnVEXqb7bqdJkaDUB8poTwZieDO/JR9/hPq8AAeTScm97sKTwZP7HOzrMhuCBlnV5U
         9aY2BqCX6sg5HKbZYYxefcwFy7QFcHpeev9I10pWdDW/NV0FDw0QxX7tPQiIGFjRp3e8
         vB2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nWHbWUKDYIX2KCFsNgph3+49EZVkJuSZrvRbyPjSCu4=;
        b=KzmOCn5qvvMUofV/ljBoiZKFxyQvda6RmyM/9UqkI58EPkbkFJ4r5ZNKSOpNpp7mK7
         YlJFdZN/Y8stTIrnbiXGWRDOqTpvy0KzprZFX1dH8ooU5bWOD/R6qd+Y9LSU/H8z+AZe
         McyxE2NlrD1gDGvcwiZ7SoEh0TVUbzqiMXePJVPuc/K5flyL4GEjn9soaA3X7WDikRdE
         DQFzmuOoKWwDUEDxLIzOKFC7Ay85xg+IYRAWTWdPqfXfJkPy4xg9C0A594pB+8YHz3bQ
         xNl4M7j4micxBhoij3zY5vTT9JtOOgwoweO3Ood4uOi2Q16ulHxWVSGlVNPl9a3u0Y9K
         hJwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bmkGQgDxHXpFgV7SBmgvSUTutGYiVPfYmVXVPNh+hZJYz1TQq
	VsEYBCUanwIAnIGSnmRnJSc=
X-Google-Smtp-Source: ABdhPJyutgriGq7anLNBX6reU89jk4fiB2PDJyf+cO1iEa3MBEAIZoIlEhO2DJ4782cUD/hRyv3fPw==
X-Received: by 2002:a4a:3811:: with SMTP id c17mr16339418ooa.91.1592872992014;
        Mon, 22 Jun 2020 17:43:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:544a:: with SMTP id i71ls3627731oib.9.gmail; Mon, 22 Jun
 2020 17:43:11 -0700 (PDT)
X-Received: by 2002:aca:f5c7:: with SMTP id t190mr14988494oih.157.1592872991755;
        Mon, 22 Jun 2020 17:43:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592872991; cv=none;
        d=google.com; s=arc-20160816;
        b=Px26yU995kXDR4QRShW5JxFnPBdSLsUWlTDv6qMCVAyv+kJFCzig9Rf9YXvO5lC42D
         FfxuLbE85qBTf2ZM78I6jbmgkYxMiDQRl4+/9s9DrCBOU9+QY2FfYmJfZiZj9hLc2bP4
         Vi1QsFSB1wau1CJ7tUhAhbg7Z0LxIy7CU6WMXQ6czK+hyOzbAwzw+Rn9amXFXOLaaNdn
         tzYLDYIfjerDEPCr4/0aztRFs8NxoraqgEeqxxzpoSG+VlLa0thjB8PlNfNyiA5v7vG2
         XrbH5C3g+jJ3yf10d/DyVR2QnzB1Zn7p3INRtNVHT5MrC6SNL0R0gjVklH5tcZq3QMjQ
         DtOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yJ23zITq1WdGuQ9tmCvfFE+sbVrBcsmI2UhVe9v4hHM=;
        b=Hx9NPcP0YuK4Sn/o0sKpm8upx6PbCbqjiDSoR4B4m+Mrhu9Xp13E1D9Bfoe0dfCDPq
         Zk47+5Pp1WIrZLDg4OP0Z6naKHH8mMKANv+RIlLhvV+rk/sRSb1zNU+ghi/p0FnJvq3h
         tnVLY7oW2YwoQeC6FGKz86x8iMlmympRVwheSWXs2754CAsN0PIPegsRWprq6f8v/E6j
         bhZWSZV2obpzY8fxm4ynaaE9OxZQQzR9GzuMhzM4183AMulvL7bjH6p3CwhlJGSA9YBA
         DvMoHYYnMd4KoP9Sno0u5EKhOQdfGxfKO88/xg2RezQWEb17hJhyw0N4jChtpDDjU/CK
         4oDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=REx5tHWK;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y198si719407oie.1.2020.06.22.17.43.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C9FBD206C1;
	Tue, 23 Jun 2020 00:43:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A9304352306A; Mon, 22 Jun 2020 17:43:10 -0700 (PDT)
Date: Mon, 22 Jun 2020 17:43:10 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/10] KCSAN updates for v5.9
Message-ID: <20200623004310.GA26995@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=REx5tHWK;       spf=pass
 (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Hello!

This series provides KCSAN updates:

1.	Annotate a data race in vm_area_dup(), courtesy of Qian Cai.

2.	x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.

3.	Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().

4.	Add test suite, courtesy of Marco Elver.

5.	locking/osq_lock: Annotate a data race in osq_lock.

6.	Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.

7.	Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.

8.	Rename test.c to selftest.c, courtesy of Marco Elver.

9.	Remove existing special atomic rules, courtesy of Marco Elver.

10.	Add jiffies test to test suite, courtesy of Marco Elver.

							Thanx, Paul

------------------------------------------------------------------------

 arch/x86/mm/pat/set_memory.c |    2 
 include/linux/rculist.h      |    2 
 kernel/fork.c                |    8 
 kernel/kcsan/Makefile        |    5 
 kernel/kcsan/atomic.h        |    6 
 kernel/kcsan/core.c          |    9 
 kernel/kcsan/kcsan-test.c    | 1111 ++++++++++++++++++++++++++++++++++++++++++-
 kernel/kcsan/selftest.c      |    1 
 kernel/locking/osq_lock.c    |    6 
 lib/Kconfig.kcsan            |   23 
 10 files changed, 1161 insertions(+), 12 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004310.GA26995%40paulmck-ThinkPad-P72.

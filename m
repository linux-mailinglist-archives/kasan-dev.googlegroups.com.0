Return-Path: <kasan-dev+bncBCJZRXGY5YJBB56YQCBAMGQE5TIA5QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B7432C3A6
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 01:40:24 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id e12sf14241170plh.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 16:40:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614818423; cv=pass;
        d=google.com; s=arc-20160816;
        b=eY799t0qQko3X8/1EP5WKhxZ2aV3qNUzXxcnAJVNp5fXPU1nl9fe6jE3jLavu96BIl
         Bqsj+30yAra7g4vCPLNh+a3L2+j3AgiRDkeoETGrcjVqRX0E2u90XjSKFbzDxaDZEiFZ
         eKQEcvbaS3sRe6K3Tk7GDL7D4XIyP5z1lKLscU8jcvbxM8h2pZTW9+6KKgLJe/cDneaz
         Q3yWXc+1R3tVe4iYiRSa+qtptwsmpEesEMJ3rKg8ybqKSAoIEGF7QPEFGhTa23G4z1gl
         B2oCx3wTMByN/3B6WEDiM9MP0rg6dGlXg/Wi/QvfZcE9XZAK2usrRIznbqAkNs6JLM7X
         GA0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wSGhNDNP5fv9FLol6JRCkfU1J9uocPDET9IM8R43mDI=;
        b=dCg3WSnMSrQ4YI15Y1KOprYlPpoA8paoDbZUFjlgTgcitwlPmykDD4KJcRq55HePAl
         js0n14+QEHKIo35qPMN9kF6NGpbcDebqpfbLrVpHljiwvjY01dsWFYKv6u8p7/Ed64IE
         W3h5PjSpv+1tzsZspzwKPNW/0rbxUC+3WpkT8uMAwjfPpSXisiWnxAnwBlCSlenZmtNK
         aQcNTbU3V7q9hFGasVwxkhJLmqPxm08i+z2Y8LOI83Qr8oi4S26XyADG3VK4/wPUa/UR
         YorL9nt6U8vcOAmniZ+9S1EFlaGTqsWE4U1GHWNG9aDwCRKYrVzYD5/ACBPKQFEVsKgR
         ZcQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K99jB5k2;
       spf=pass (google.com: domain of srs0=8tds=ic=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8tds=IC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wSGhNDNP5fv9FLol6JRCkfU1J9uocPDET9IM8R43mDI=;
        b=cwRTL+QpRuRPP5Dy8OMYRHzM552qX81BRqVbnhXrCdOmCtrj4SDFLldSs88OnO32Oe
         oYxa0pGRv8ba89KBYQjRfVPAnQeOx2LWEr6dKcg4DllrNtblGRvpWTR+TR46qf7F3RJn
         fB9gCQDDVoO1nJI6lpFgKt8m1CD1TS/tH1jdninaD6UvGFqghAKT2oBs1kFuJFGLvBze
         8eMseCqrSr/nueRN3J+hsDu5sAI4opN2/uLenk0QixKdsrKj93FkEz7zrnDXAdINkxJW
         McqK8VpVb6D85VriPqT48FSu5nln3qMZTFXdJxs3Cd8f9Pnf7vXo6Je9hVMBPMqmAQQV
         tVSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wSGhNDNP5fv9FLol6JRCkfU1J9uocPDET9IM8R43mDI=;
        b=t54ewia5q2oqmQ1v+Ct1huoBug8XlyrDimmfJeFYYc1mAjxfQoeBeO7LaeQ7wmzJX5
         Id39tsbFnD5itA2pFr/9iVbzDRJNacr7tMk7j3HUCahh3PtCIEeJkwc5UDGg9usjAou2
         YBOrsULeittuzY4Xcp9F53m8rN5MS/DqzIUAppQHcrKahQNdB5b5i54A71sBhMThggKa
         bAYllnVGFhIVWllzA08r3ndEegzFIjr45CE/Fc35lzbEFBMskzgonUcp2inm8gDx/Uri
         44EWsDSK6++OkxsXeMak4p2GhegoEUPLgR8R7n5MRgxBXOC0rwHCufr6XMBx0f7p8N6P
         g3mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AkN7DyKyGAZ6FIq/6vsqXuMPP0OyfbRG1RRJHUL+0gFeWt5fD
	DqUZQjI9MpYSnIocH0w6LIk=
X-Google-Smtp-Source: ABdhPJxye0+7fTv0AR4AW5YBz0QZknrNbAlV7DlKJkycYHQPtlXr1W19mWzGpEoz3T9oFHO5mUX3GA==
X-Received: by 2002:a17:90a:ff15:: with SMTP id ce21mr1708350pjb.172.1614818423672;
        Wed, 03 Mar 2021 16:40:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d8:: with SMTP id n24ls1664474pgv.8.gmail; Wed, 03 Mar
 2021 16:40:23 -0800 (PST)
X-Received: by 2002:aa7:8889:0:b029:1ed:f38:4438 with SMTP id z9-20020aa788890000b02901ed0f384438mr1586417pfe.44.1614818423080;
        Wed, 03 Mar 2021 16:40:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614818423; cv=none;
        d=google.com; s=arc-20160816;
        b=u57l1d5K2neJeCoMUC8vsrF8Yqhlbag6KDK2b+1atmMRo2ohUJ1P5LkExbUKALNGRl
         VzPlExwnw8Qi5Z046CcX/eP0x0Wjyu03G1kMkNepgXQToZS8ZmaQVxPT1ug4qvF7N4as
         zdJt3jGUpucUM+1eeOyaVnAKk3xXWlWGi6ttPnrPUSkiqm0UJR+Zj3XRbY3T4eAgJMZJ
         SwcaLKiggfU4sa2A0xjwg/WW0Thij3aPICwPI8GiRHbpjqEWgk8aGL/ZjofX0SbhKq08
         yDafsGgoDFN6vUi2zKjoAASk4ADMPX48P+IE2/vSB0JCUn0+ROQXuu2ZMcHvJlYHSJ9/
         g6Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1ZUQeab4WSx4S7ZXXzRbyeeLLSeoH79ULg0EnGjOBMI=;
        b=CNj3NeOqp0alY+EfFLmlUClmpSZIPto0I3z2J+OXykm2XbyTQYb+0v6vTFYycioEXI
         scYtT8JfmEGY9EokZWi4JIgrnu145yyf15icL5rwR03jBsuJZWJPX0FWbe9WHsRlu4Tf
         0/focxKUStpsdvGRkJMROALqvsTT37XQUpPU7b0d2UGh3jTyP2T54PjMonMr3X+Wz6NO
         +hpIU3wNzHXsDJt6ppk845TG6gVwATStjJfMBwEmXU3Pmgl6pD2ncqeo1lYJxK2dS1HI
         8akzyD1vvqn5n/oBuDv9SC1mK6Lh/PkYY79h3gX92gt9LK9XpOUmHDGyw/s6eglRgKUq
         1icQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K99jB5k2;
       spf=pass (google.com: domain of srs0=8tds=ic=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8tds=IC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e4si1320270pge.1.2021.03.03.16.40.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 16:40:23 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8tds=ic=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C3C4564E28;
	Thu,  4 Mar 2021 00:40:22 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 97FB03522591; Wed,  3 Mar 2021 16:40:22 -0800 (PST)
Date: Wed, 3 Mar 2021 16:40:22 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/4] KCSAN updates for v5.13
Message-ID: <20210304004022.GA25013@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=K99jB5k2;       spf=pass
 (google.com: domain of srs0=8tds=ic=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8tds=IC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

This series contains KCSAN updates:

1.	kcsan, debugfs: Move debugfs file creation out of early init,
	courtesy of Marco Elver.

2.	Make test follow KUnit style recommendations, courtesy of
	Marco Elver.

3.	Switch to KUNIT_CASE_PARAM for parameterized tests, courtesy of
	Marco Elver.

4.	Add missing license and copyright headers, courtesy of Marco
	Elver.

						Thanx, Paul

------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst |    3 
 include/linux/kcsan-checks.h      |    6 +
 include/linux/kcsan.h             |    7 ++
 kernel/kcsan/Makefile             |    4 -
 kernel/kcsan/atomic.h             |    5 +
 kernel/kcsan/core.c               |    7 +-
 kernel/kcsan/debugfs.c            |    9 ++
 kernel/kcsan/encoding.h           |    5 +
 kernel/kcsan/kcsan.h              |    8 --
 kernel/kcsan/kcsan_test.c         |  118 +++++++++++++++++---------------------
 kernel/kcsan/report.c             |    5 +
 kernel/kcsan/selftest.c           |    5 +
 lib/Kconfig.kcsan                 |    5 -
 13 files changed, 111 insertions(+), 76 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304004022.GA25013%40paulmck-ThinkPad-P72.

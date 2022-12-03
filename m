Return-Path: <kasan-dev+bncBCS4VDMYRUNBBIOKVKOAMGQEPYMLK7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id A886F641304
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Dec 2022 02:23:47 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id pa16-20020a17090b265000b0020a71040b4csf5827351pjb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Dec 2022 17:23:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670030626; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fdm7jRbtuKTnryoTsGaSsIyZbngXookDpOuwjA0uW92pm/vqmYA/MI8eWZDi3e+Hi9
         2b17xq/Aw7raBcO+ij3yFF9mwMgt5oprPxMbFLhxcyfdGbdmoDdTc3srjJuH6Ah46syR
         UuiIOAUPYlVKhICoKMCNpUjXrLJX5mAPchDIxHqwhns9xTZXNJIuTCpoQMWbARVmiyaR
         jKmG4Fw9i21JGP/MEojVzR8540CydYOioPW39ysWGcKXo0AfzFaYInUccwG2J6yrbLSk
         3GqA7JZ1u8fN03XEoiEE4qAIrHNgeZ6SQyWYdJVTFqC9JeNTMtBzNYr6SLG0dF356ELL
         wifg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=01FMeU6kDalYYpd4Cd5TZVkuZ+8ffdxixjflk9UZ9og=;
        b=inoIWb4ptJAHFLPlWGPEV5VyXTytxn723L3eNJcGMJqpm/ZbBYanx7KaXUFCiliw+o
         pFKWPAyNryOF+HDO3XYFO4RbVagWSZ8AqKIu3AcEzeHWidUIbRVHpQi5bkM9Kstx5Hqa
         Jzm8xtay5sqjJE+emgZW/lnVmijEP55br3OIo4YPN+/Yr1T3eMerBXcZHR1HkYAi+X5S
         QUriCvQpp/WKpBGQP/KAGb+Z6XMC1Kf8K6G9tOF4hc5pq+5Yb5qjPupJ2pDDHHoJxEsC
         5r/sMoTx1lOZk7wo6tqg7SDr2LDNVzbS96hc7yElviI9HnIUrEN8fW4q49VQFMmm0NXf
         fmUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="KjDpCt/Y";
       spf=pass (google.com: domain of srs0=0hk0=4b=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=0HK0=4B=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=01FMeU6kDalYYpd4Cd5TZVkuZ+8ffdxixjflk9UZ9og=;
        b=MK1/g2dERSMobETsfC8v/U/vL50J30FbI+tQ4i+s4zVmQIdZoQ8/wonwynV60T946V
         tCcsjR1TL7srO9VCF2kTcJ9Bracl9vVZeHRngZ6RGhEGoyYy+YN8c28DHUB2nWm7FPge
         RyxSxiVohZ0bHzoEju/ltJT3AhkGFPiez9mjw179vk1WuDhFjnFPrbDuNktRiyBAl+3+
         3gCgy4d4ySpEPdmBW588t9VwNR4v0sFlW+n0bgpbIveqpgVc/clCX2SYOVk3Al7ZJQ5J
         tdH0Ypx35qCk0D1EDgUBVQOsLk2H+uGaVRg28ZTRlVAvWkMYsK5b/YO0uPPhdhCJFoah
         5WtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=01FMeU6kDalYYpd4Cd5TZVkuZ+8ffdxixjflk9UZ9og=;
        b=WPiuQV0q3Fji1+uiSsOfrhg2r39vNROI2coqU2RMpE2iWL97xBUrES2XYCAtUcCoav
         3kkLw8u60CfsoTsz7tcSFeoQmSZg8aqwwaGJxnRbLfLGMfgAYT7q1Q/U4d+LzfKD0M/x
         UFwKlW+br2NDPsIvOpxHcB7auqnH3XSpFlKou/TREokZD05XLqendzNrn7Iih/U3J2Hm
         eOPc955d3Xg6yxvcQMab6507vD+zG4bu+Om9kYhPglO9blLnMs5JR+Ec9sm1pHu4CmgE
         3OTP8bRG8GnBGWrq2ry5SgWOAhxYdBHTjs4tZHn3UNTvQC6MGJM4hCDhR55ah6jAQbGS
         tf7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pl/flusgxmsQS60+S0b1mpBgke4jnNxRc2jx4BcerZKYHvukFGa
	oeFKbgF11fJ60t3oFYtldXU=
X-Google-Smtp-Source: AA0mqf4Ie8X25zcFXe4rmEccUJeCNAGYNBdme4nIyR4NuFS32nvLzoJj5WL6za0Atju5Zn78M1icDw==
X-Received: by 2002:a17:902:ef44:b0:185:40ca:68b8 with SMTP id e4-20020a170902ef4400b0018540ca68b8mr55862190plx.16.1670030625900;
        Fri, 02 Dec 2022 17:23:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6a03:0:b0:477:bbd9:2d09 with SMTP id f3-20020a636a03000000b00477bbd92d09ls186284pgc.3.-pod-prod-gmail;
 Fri, 02 Dec 2022 17:23:44 -0800 (PST)
X-Received: by 2002:a62:3245:0:b0:575:4413:308a with SMTP id y66-20020a623245000000b005754413308amr25780745pfy.32.1670030624814;
        Fri, 02 Dec 2022 17:23:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670030624; cv=none;
        d=google.com; s=arc-20160816;
        b=VqGU3jA3WVBeUjC1FloGZusFufG6L4ubsA9DJ08F5zzAnsrFnLTRDjgeSQJnrvKQWv
         cv5SNxK5sePQPRlCfLApcPxTuvSrWKl5Zq7r+PGX/d2Aq3davjNv0z/02USjE8+n6DEt
         D+UqLTl4cQoCHQRFp1JC/XfMwfcsVR31WKLL6OqijAtcRbJAS8cXrAYQBGDw4g3QE+ES
         u/ficOjZBWRIHanE0WaDv1xWUoWZHJFALTET1pnq03eOaIaXWHwfH4QIrcrmn4mCumKS
         bfb7xLp+zjC4yB0+HkKZCt0QHJa+yxIPGx5B7gEYYx6ijoRHDLnyVYlEZcr+AlEFL9bN
         PqkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=iqAJ7XRaOkAtoi2A9S0Sd8KFXKLz21jeyiJ0BvhJ6oo=;
        b=JnA7Tu9Js8zDkty474TBZgOKHtQa5Xk+/GyheG8aFxulqZeQxjvOiGbIrU+xIRl8Q+
         ugUNBi3uaLcWD2KpTt3ztji2FYjuwK79QlwW589+36rU1rWmyQnjICqlkLR4Rd0gt7jt
         dJENlcDv4FA3YHlpyeMk5V4UYaU9q5Ee+43n/BGoucNATrDp1xXvxbjcBWhESkL5550j
         4i4/OmDFdkF+r9OsrSXp+yzcmS7nVny3vRfMVGuZ/Rz9xsp/hUGLuLX+koCKnkvexQlO
         hMrdJENQoJ7tapDyxdpQJOoTy7WdB2vq64xvTh1tumqsOWwSqJDZbXs0Fxa2QersVQHn
         IRdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="KjDpCt/Y";
       spf=pass (google.com: domain of srs0=0hk0=4b=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=0HK0=4B=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k14-20020a170902c40e00b00189348ab16fsi565109plk.13.2022.12.02.17.23.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Dec 2022 17:23:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=0hk0=4b=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3AE2D62477;
	Sat,  3 Dec 2022 01:23:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A3219C433C1;
	Sat,  3 Dec 2022 01:23:43 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 43E675C095D; Fri,  2 Dec 2022 17:23:43 -0800 (PST)
Date: Fri, 2 Dec 2022 17:23:43 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kernel-team@meta.com,
	kasan-dev@googlegroups.com, elver@google.com, ryasuoka@redhat.com
Subject: [GIT PULL] KCSAN changes for v6.2
Message-ID: <20221203012343.GA1816460@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="KjDpCt/Y";       spf=pass
 (google.com: domain of srs0=0hk0=4b=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=0HK0=4B=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Please pull the latest KCSAN git tree from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.12.02a
  # HEAD: 144b9152791ffcd038c3b63063999b25780060d8: kcsan: Fix trivial typo in Kconfig help comments (2022-10-18 15:07:33 -0700)

----------------------------------------------------------------
KCSAN updates for v6.2

This series adds instrumentation for memcpy(), memset(), and memmove() for
Clang v16+'s new function names that are used when the -fsanitize=thread
argument is given.  It also fixes objtool warnings from KCSAN's volatile
instrumentation, and fixes a pair of typos in a pair of Kconfig options'
help clauses.

----------------------------------------------------------------
Marco Elver (2):
      kcsan: Instrument memcpy/memset/memmove with newer Clang
      objtool, kcsan: Add volatile read/write instrumentation to whitelist

Ryosuke Yasuoka (1):
      kcsan: Fix trivial typo in Kconfig help comments

 kernel/kcsan/core.c   | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan     |  6 +++---
 tools/objtool/check.c | 10 ++++++++++
 3 files changed, 63 insertions(+), 3 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221203012343.GA1816460%40paulmck-ThinkPad-P17-Gen-1.

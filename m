Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2EEYKNAMGQEWMSI75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B6E96053A9
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 01:04:10 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id bx1-20020a056830600100b006618cd93358sf8962841otb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 16:04:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666220649; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTGZ1/8ONaGyfVfT59cVwuFbAmvKS/UAaST9iJ5BvrUwNHLpam81UE7OYvE2IQmP//
         RadIjbNV6s9GaQFAVoYCPS/xbD9a0fP/n9sSDWGecY+Ne7MPUad30vQKe8PA3twPme2E
         lSdworCYnrr/1Mbf1ejm5ITKHdDmEadG0olPV+MPn4QJr403/vpmowIZoqhQ1adDId87
         n4rWmLlsvwDrcDd+NtdIlrQ8g3f00KfmBls0Hx7sP5VXasIcNIqdpR230Ppu1m7x0P/d
         kAx4KGMFadg6cn3HpP1nL0iQSW3KMnW+zH4a7s+X5E85lUE/qkjSKPqYd3nFwY43AuwK
         Y/lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eoNu8HMLtHSUVdy9ThQLHaxc1Tk8Lljf+vISP1RGeVk=;
        b=zeFRRFyqicjoRIadClIy/gzsmpKatDWpGKAbpVlJKzd6IPFdnOPhFRl7WzGXoMa1z+
         6alca/Z93nw8/r24QgcGUmFACxsfXzkDTjMErAnr3/sRXBeZMx3BLwijfWXpoN/ogZ+M
         PnrMFvLlp5M6Meqbipy80Rc1CDuE7cYPBCKt+F9ZtrAT+aa7YUZF2KXQe7NM/coTic5G
         ftuBAJ52lxGG/GQkHES20LJ95mcP5vj+UVCts7RmPmxwTgwAKy0r09nURHTHNymGPaY7
         RwBkyt3sIZGhPCqCOALzS6ldshAnPj1NM5UooNfCbpwwRbj4gkf64BVZtz+tthpVsaTe
         fxLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RnuegenO;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eoNu8HMLtHSUVdy9ThQLHaxc1Tk8Lljf+vISP1RGeVk=;
        b=f41+nBJ2qVWL2zlu+CEqcXIE6yJKXVx+FAFS5qOBA+SeFixlYv31RNC972a0qOi/e7
         xPS2PtFIC1atQGSLsnHfzKMWPNEX9pOe7W9+gy3Eh/6iLIsXwv5lLzOZYO2fE+GeQ/dE
         P9ANPXDhG+DqXyd7sBoHs0jM4LCHNUg/+0OOWpEtFp/OfKF1r30JCIoW9ye/gQ2NK+T/
         +OuEYbKPjXFI/sRZz2tiHXuNVFUqvsXCod74Dbpp2ey+rRL58cI+C27+z5YPLnabxcp9
         dfgXIkLkUeTvkk8QtuJrLVXAumiZgEd1g1LxtdHxeWbs2rvNHjZqxBRFlSmngwgXtOJu
         9g/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eoNu8HMLtHSUVdy9ThQLHaxc1Tk8Lljf+vISP1RGeVk=;
        b=IJQ5gpeK8ObilkAaLuTT0QpGmTCWKxx9iyuQMgbBDUXLyOm+dxXD9P+cr5gKoqegD1
         zULqrqcc0NQll+oa2Fp9Tpf3wMslSj9BaN/SyHFwsYtWF4pq3dQsv3R0MB/DabBJVaz3
         JwAKjbTpawKXt5r0XrHRfMnmBfwCit0Ue8fTQzTS3jBNxgawX1S00f23SBpnubfgmQLs
         Sp8VAy9ohLCX2AjE1z3eMvzKSMDNYq/xUjrjikJNbB6JkeIYVKRicR3qGdcC0+B8vCgw
         Sm0cScFwjUje+3X7WNzZkPgkE1EuJ0+T5nwDVRihiGG917EzQ3yGmIz8w/jjCCx+3m4h
         ofyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf01zWO4V4FIbkDYpIEklP4l6l8HqKRTr97/xTWpYiSX5uiLE2rP
	KZwKlQUxY26GJ7WWOMPbkWY=
X-Google-Smtp-Source: AMsMyM7uxazHVVzy56yQchlgqzBUUHdcZkmDFuAHO++bvPLY9MOVBgudww1EOJWA0hWHoLkrT31TWA==
X-Received: by 2002:a54:4506:0:b0:354:943f:bcc6 with SMTP id l6-20020a544506000000b00354943fbcc6mr19841588oil.180.1666220648915;
        Wed, 19 Oct 2022 16:04:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3a2a:b0:132:8229:a3d7 with SMTP id
 du42-20020a0568703a2a00b001328229a3d7ls6375316oab.6.-pod-prod-gmail; Wed, 19
 Oct 2022 16:04:08 -0700 (PDT)
X-Received: by 2002:a05:6870:f60e:b0:131:b7cc:f994 with SMTP id ek14-20020a056870f60e00b00131b7ccf994mr6680415oab.113.1666220637894;
        Wed, 19 Oct 2022 16:03:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666220637; cv=none;
        d=google.com; s=arc-20160816;
        b=KaDW3EdbRaoEiSBky6q3SoPqUIKRaH2THeARDiHJcZXovG6eBWv7tjEQKQ/JdKeYh3
         pFwfqBToGmeJFulUXMS1WbCTDTMvQP1ThQZIwfrt0oLNFDV7XNbs2Qonkzobg2XrKpgg
         TWf8VORcF27+olRjbTQgbYMsicOCA+gNWENy6DF3IeRrfaE02cHAP23QKROnku9hmU7K
         3r5p6rGwVISNgdqFEciyTxpmF58jxq/pOWc8JUhLszysknG4tCEeMuX7XHg4WF6ZGPxJ
         E1m+D+gSZ9aN7JccjedUqaXovApIdAXklmAkdJTmzqm6qDN7Ijd/hV1aMxyzonsg6sw9
         OK+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=pV19HddInyCN15BkCZcjOiYZcpT7oNlcytppdKle0Hc=;
        b=sKi/cu5mC0tbYSYjSz1/Ah+0vlC2kQKpSy/CjfDtw3fLrlsbYuMTh+E2g/Gx6IZEMI
         Ql9mbriivvgxwLrNSOyCCapO6dGcOnidn7QNInumJ5E6xM+uMcu0cVCHxlmeE4CYXO8/
         N89ZJqkq5dW1uWDIyIzzDhWHE/dkQL3M3MTxe9SNq02FWHoecifEGFiR8Q8D6O175AUT
         JScgyZ90Ek5tCK2ycYLGETWQJjsTDbBu9PCAYyUIJVhtP+LjZVUC1SeojRBy91l93+eu
         5apeDCknKM/Yh1sEkYFOnPfloX0bJc7lfKDvBqT4GJ6y7+sZi9Te9JxpoJDLOJ0DbzUg
         OjPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RnuegenO;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y128-20020acae186000000b003504d4fcb12si987260oig.0.2022.10.19.16.03.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Oct 2022 16:03:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9D5C661962;
	Wed, 19 Oct 2022 23:03:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 031B2C433D6;
	Wed, 19 Oct 2022 23:03:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A43B55C06B4; Wed, 19 Oct 2022 16:03:56 -0700 (PDT)
Date: Wed, 19 Oct 2022 16:03:56 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/3] KCSAN updates for v6.2
Message-ID: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RnuegenO;       spf=pass
 (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

1.	Instrument memcpy/memset/memmove with newer Clang, courtesy of
	Marco Elver.

2.	objtool, kcsan: Add volatile read/write instrumentation to
	whitelist, courtesy of Marco Elver.

3.	Fix trivial typo in Kconfig help comments, courtesy of Ryosuke
	Yasuoka.

						Thanx, Paul

------------------------------------------------------------------------

 kernel/kcsan/core.c   |   50 ++++++++++++++++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan     |    6 +++---
 tools/objtool/check.c |   10 ++++++++++
 3 files changed, 63 insertions(+), 3 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221019230356.GA2501950%40paulmck-ThinkPad-P17-Gen-1.

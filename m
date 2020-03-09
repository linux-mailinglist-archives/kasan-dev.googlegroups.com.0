Return-Path: <kasan-dev+bncBAABBOVGTLZQKGQE3MZ5EVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B27017E7D1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:27 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id c6sf378280pjs.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780666; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqrsWQzL4ro1pKoTCYLNyhx6Wro/PXeCbha04jYnGV6xUqRjPIIT655z2sv0/EiNa+
         A7zyo5ILoRW7mnuQl75k2OuyeMr1/vyaholLxdKSsoA1evUppEifAvAWUQr7KKflDrH4
         KA/7yj8jmC9vc5RgWhDlQysWi6vCoammQzLo/31RRQ0ZcI4tfqoTsmTqbOADfV4Upylo
         9P6y3iW3npz4s5GFLPMJ4gcNAG7GMxzyv/tyldiUCzsZj0vmfTswfk9JM66MQhGb3gyQ
         wDnxN78BnJrYo4yc7Yyzz3alq758b001VIxz3haKUspYp8FcC4Q5lxO636/Ra+64LoWH
         A3QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=cV/eOBKgJv4LBxUI5RbnTIhgjfHKdJti2JrK8CRSOks=;
        b=DvUx4frn7/63RL+0BzoX/ns0OqTcFM9WPxCgVZb6kb+mMxiNWtRLH4PkSnptZ9lKaQ
         O/B+VnQubjtjOPSLsXX10ENUIinEpNiaN0BWMXDXocJUZncKmunyfP+Wv8R7kkZv2Tkk
         rdBgAIsn8igVJfStbLYpR6IpgoUKH4sESjhZYeUKLNtc0u1Gs7FeIJ6am2t7PnPb98iR
         p8mGmjshbHuek6nZROy3Sj8ImEKYyIKXQTPLm87qCKs+fd/duHaFm7RjmXKwVDjB9gtl
         uuZ9RQx/nqEKwYjHNCyUpYnbUDt0TmP0q2E7N0S3cgMhhcjmxamEfjuDZkLF/LKWS4UM
         oDrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Z+YIvqnl;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cV/eOBKgJv4LBxUI5RbnTIhgjfHKdJti2JrK8CRSOks=;
        b=Q8h3WTFSaOdf4KHKI2qlpnfAohj21xROTcfV6DgFHNL5AaL+OHcqEQgMI+/6RmLD8F
         XEw1g0npcSR6zdEDZlE2kK44mgI2k3TDyUrFWpmxv9KBLUCcG/o0D7A8hj7rVhBCHH9K
         YZz7hHv0+UZCdAoyn8if1Dr4kTIS5UjPR8a+WT/pqRJZd3N14LmuoXv0Hk2kWV9HiEtT
         F9lzlnHh8fk41S05S70gzfHfq9AyBs+yqsS+S83czj4T9zH68ynPtPgG92VoLAG0hgbv
         uYygLsRFbta0t+rsZ5IoTUrkAtXmHyX7fkcx60tUy0ZZQnbGOGSBlAW2SwDacTUWEytI
         NgsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cV/eOBKgJv4LBxUI5RbnTIhgjfHKdJti2JrK8CRSOks=;
        b=ZN1E3z50+5TPUSoj8BSrHd9bRoNJRs9mK0zStDns2YLi8kHO1c1F2VfnVP6XADj/SU
         sTdK6hbEoa4lWCva2AT5EWjafyDOu/2pc3+G25UbWKEnmOvcbkyZ1Cgguiiy9ldQ3dx9
         PnuqSki7BjkYkoVHYSk4Hte+B+/2gog/tRKIhVne0FhmkzyRqFraBYpr2MovM9h7oeKZ
         Gw0dgrIGm4Jifnj9z/FilAlmFHYCYYivhbnk3hRXcv6rliavDqPJJ1ifNSMIVmwn/IgS
         MEZu5+4DcT8+V43PFxhFUCkEoxE/UySQ+/SszyMyfqOE1814t1bJ47w79ZkFgVZsjG9Z
         S4cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2IWck8PjOCakLAmg2QMHllTile6k7mQWoqKHkn1qNWV+t6Kzr6
	XsvHNHQXFc970pa29JtJmuc=
X-Google-Smtp-Source: ADFU+vtyqc/Y4B9S/5NJYxwFwADiWDE82F/kXAxJvJUz70sF3ewsBGiZXJdUeoQ/JPZT07fntN7+Yg==
X-Received: by 2002:a17:90a:da01:: with SMTP id e1mr834325pjv.100.1583780666087;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:898e:: with SMTP id v14ls383629pjn.3.gmail; Mon, 09
 Mar 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a17:90b:1983:: with SMTP id mv3mr818673pjb.86.1583780665695;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780665; cv=none;
        d=google.com; s=arc-20160816;
        b=dBUCBhJuj4hXH1/ileyPqPR3oLJLPesFk2T/B3aH5KMmP9LiObsm2bq827tPMD1DDd
         Ebib5HSGEfRC4v91VM8UYkhfHCk+7BT5i+VIELjKRJ3h5gBeEqLziFnH84LGo4mf599s
         keh/DvkF2oWF0FiM4zIbfr6jyv8BoCOq9BzfZ4809Zv4e0r+squ7MxcICwD5I2aXRUVZ
         gAGyMK4WUCuWmkJlyWVtVkdKZo1N4kRK29iNFi84+AJ0FtjF+7MDoxKOmQtbKpo4RLYG
         phpBFRfZGSQr9s8M9dm3L801a+pGr8Z997G2n2xLc/I9CsNiuhqTN7/SVb0f0mUVpDGM
         O7yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=nZ+haSDTYnZpqmGp73tWQjTP+GHGtnS1jakYERUPeKc=;
        b=s5HhGfSffUu5xxHjW1UEDAdEiY0ceVyDRvva1X8bQHKRfKQC7gZ/uMGzpW3no9Yveh
         qi+lrfQb5OuvOKFKu8wq6TQUk6k4PCXGthZvFt6a8BTnyjxSqY8Wq2seLGSUpl7v1mOV
         BT8BcoJyFwItQIup476D9iKPKqn5ERAIKA7ShqmLub9Gpw78fv8Mjw7AajLN/98JbXsq
         mYgSRwIFa2hBJr0mqzRbjbAMuRmlYgOJ4uFAFsBuUYFMRvRi9I6x9YZRyogyMTTl3qvH
         S4nOyxi7RY/rePbhGBI8i1ab9frz+Cd46942GZnBP1SjlyD0OH+puVLuQ9L6M6FkUCJD
         kLkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Z+YIvqnl;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 59si597360ple.2.2020.03.09.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 56EE524654;
	Mon,  9 Mar 2020 19:04:25 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 13/32] kcsan: Clarify Kconfig option KCSAN_IGNORE_ATOMICS
Date: Mon,  9 Mar 2020 12:04:01 -0700
Message-Id: <20200309190420.6100-13-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Z+YIvqnl;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Clarify difference between options KCSAN_IGNORE_ATOMICS and
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC in help text.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Kconfig.kcsan | 16 +++++++++++++---
 1 file changed, 13 insertions(+), 3 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 6612685..020ac63 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -132,8 +132,18 @@ config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
 	help
-	  If enabled, never instruments marked atomic accesses. This results in
-	  not reporting data races where one access is atomic and the other is
-	  a plain access.
+	  Never instrument marked atomic accesses. This option can be used for
+	  additional filtering. Conflicting marked atomic reads and plain
+	  writes will never be reported as a data race, however, will cause
+	  plain reads and marked writes to result in "unknown origin" reports.
+	  If combined with CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n, data
+	  races where at least one access is marked atomic will never be
+	  reported.
+
+	  Similar to KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, but including unaligned
+	  accesses, conflicting marked atomic reads and plain writes will not
+	  be reported as data races; however, unlike that option, data races
+	  due to two conflicting plain writes will be reported (aligned and
+	  unaligned, if CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n).
 
 endif # KCSAN
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-13-paulmck%40kernel.org.

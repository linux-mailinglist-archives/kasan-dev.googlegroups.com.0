Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2EEYKNAMGQEWMSI75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 180B46053A8
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 01:04:10 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id y126-20020a257d84000000b006c554365f5asf5607491ybc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 16:04:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666220649; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4093ZbEBUfZq4adW2hXGo3zvG/rVN2yQ8XaBJvUNqVjaVhKLH8W9rHX7dhQ7uxqfX
         KOTaVGqVWIcPQdw5RjRsKgrJNvMe+NXJU7vnsd/b/mj/aVkHbIQ5cXDmMQKxJIDge2Tz
         YDULCMqBQgyXJhNrPexkob6ogQYm1275iFezvrzZxbmoMHG1JSyAhuEiHD+V28xUXfqg
         f2j4mV3pgAT4VGpHAH6OkMWesmoBcJIs5EYNDFct/wN5UDn6dH6K1wKDpvrEt8en5ffG
         XcxBE2MbHKMFJbqiipGry1M+fXxYpm/6toXKgMKDzxpm45V/Jlznc4ilblNcNnTNXH9P
         QKTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jX+RwyhMBIk8atfCRV28lVlCU9HPXFALATO9EsJ79DQ=;
        b=rtvulj2kLwaAVdaMVQGH0iSUVdj/nVhzKjM1clep5EKuRz0DMvaa7aEBeCJSroyBPc
         wobC+eWKFdXPR74qdoeXzBRczndapUYxjWrXPm2lYRYB9lpMLh22GN50y8ZZGNmZ3pHL
         NPkR2J+Ylq1f8kV962U4tkZm2MAZlFjpun4dx13tjXRi5z+9Qnp5Shae5NkKrzbzv/Zk
         T8Bf7vSRd6D9lSrDFGGj2P0wTSyWXOsPfgeBm5o2oIjSRWeQH1qsNi+X43uiO4OJIDZf
         JGQjJ8AtVQXDtj7BPTlbdHR8iIUhPZgQhCKM/ihHKCD89jJ0qoLJobtspL7n1Yfj3y7q
         H+Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IEzk79e3;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jX+RwyhMBIk8atfCRV28lVlCU9HPXFALATO9EsJ79DQ=;
        b=TcRSdUt6nSh2JoVmunS2KSjbxsLVTZefFUNMDzHXGiwkwKVpSHAihpomHwqGODvCzE
         gCxvJQV2+reOSIfc3k01kCupxzRCQQz3jzlWmseq5LnjkFYwlqbsTXGbPzCaWDcvc3O0
         UQAiDa7zv4PBV5zrOfb6AKDQejfvbuvA2q65Aa6+aitzpL/7zlDcSNb4KL0hoAM3EziI
         NYynyPXDJkNlnICPubnDzC11+NxWeqCNB6KSsGAJA+ixeETXV6i+lf8X77o68B3D20PC
         4TsTA0GiH2gDXd1qsTapGCQ7LE/vCJzHHOGTyWSuquV1CuLzsBbpwRDXKSSRoWoHWPLa
         yaoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jX+RwyhMBIk8atfCRV28lVlCU9HPXFALATO9EsJ79DQ=;
        b=d4HEMQuhgnlK3jQpCBL/gxo0hrQXLXHlT/BLk3xwchJ0WVoi/7Yy4PW6Uhdg586LHA
         f3SIJcHQ79YXr38vz33m1plvXQLrwFvrE+wz8tb3TcRuHWuLhKDS5+XZiKJ1Tu0EK/wN
         fkiSOYos8HY0fJz9QCjO7t2vWpuuupti/H9JKHOlAn4xnbhyRlMhhI4gOen4zH0rerrG
         z/nvIU4hDBM9MeWo7YiNBJ9wrkXtUr1Ti/k05V3IXpZrn7xeroRUUidleQgzmQ+P7oTt
         8jetFyN3A2OkWW9S/aQBtqYWC6U+/1TKJnz8fuWkbhxEyqiyjeqJDgb9z1D5O2g1hOj4
         3D6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3nEFgwrMksuNFSMRQGJkMCWU6cffZfGYYnP4z5446MeGF16zBJ
	sU6PWMSPsK5MjOgY2I2+PUM=
X-Google-Smtp-Source: AMsMyM5OKKweRmSA4g9h+8sMCccX4HYFo6Ja2XgRbvOBYmkPn9ITz3kF2gGk9FR68tLXIco86FJpxg==
X-Received: by 2002:a25:1606:0:b0:6c1:7c57:ee97 with SMTP id 6-20020a251606000000b006c17c57ee97mr8365682ybw.503.1666220648938;
        Wed, 19 Oct 2022 16:04:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:79f:b0:357:45b3:d075 with SMTP id
 bw31-20020a05690c079f00b0035745b3d075ls7485616ywb.8.-pod-prod-gmail; Wed, 19
 Oct 2022 16:04:08 -0700 (PDT)
X-Received: by 2002:a81:bd3:0:b0:358:ecd5:291d with SMTP id 202-20020a810bd3000000b00358ecd5291dmr8670540ywl.305.1666220648360;
        Wed, 19 Oct 2022 16:04:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666220648; cv=none;
        d=google.com; s=arc-20160816;
        b=hD3xkxFyVba57Pq2jN6HrOdR/X/uCahTW5IeIrtZTP7TwS/b8UCDwzmLtNbHX0+gSB
         uX+Q9ISnqniKMWs0ZkdQx1aF/I4L/TmJDZMMVDLo1cNVnroVl21xYykN7CFLhTPZw68f
         08Dnl78cdnWs9hYQkdv1uaDUti05IMu8CFude5bBlqmzIzQip+ABswxibkv60IPVaXtK
         pgkVEI+LDBJBPw4LTz5QS4oDswfSzyqxr/pEam9h53+eqmU9Pew68KQJGtOS91XzVlCF
         PrbheikOJvnuqVw0myIf1DTOuoFqsrKcvayg9Y44GmoUZwDhqCc/44cIJ/F2mx/UNVjO
         4SuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xSP9rlOS9aRpp40NQjKXUsx8yG28YUDXIkQYgRT5YSk=;
        b=tfdAHWMoizduXWnqzDhPNv3ETgT38wIRoveKj9Jf2Tk8slJPP2U+NoCFY+945KQS5k
         zz8QKzpOS4O4SwBzcKkJHJ5cyCgrrWSbq4HO7mU4TqS/R5bP2w/m51M5ATtLNkT+RaM5
         pdh0xcenBSWMUQzS6VbdxT8cSTnvHBh6wZyVuQDE+Gj4SrlIUzUYNmVgT5TjOSHduXVZ
         NxcvILttDuf+4y0OJ2yJTuzpIPqydGZH5wg0yQUYowsBlAHNGpLmrdzV5LzN2DxfgoYJ
         Oq6poPSwWz/rg9cNmOfcUmHQnSoeKeTXb8gv3c0pV6IRV/lPG/YgALavvLalJQ9k9YjJ
         qQZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IEzk79e3;
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s187-20020a2577c4000000b006be3d17ff2asi1071110ybc.1.2022.10.19.16.04.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Oct 2022 16:04:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 14342619DA;
	Wed, 19 Oct 2022 23:04:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7104AC433D7;
	Wed, 19 Oct 2022 23:04:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 2EBBD5C0890; Wed, 19 Oct 2022 16:04:07 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	Ryosuke Yasuoka <ryasuoka@redhat.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 3/3] kcsan: Fix trivial typo in Kconfig help comments
Date: Wed, 19 Oct 2022 16:04:05 -0700
Message-Id: <20221019230405.2502089-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
References: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IEzk79e3;       spf=pass
 (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Ryosuke Yasuoka <ryasuoka@redhat.com>

Fix trivial typo in Kconfig help comments in KCSAN_SKIP_WATCH and
KCSAN_SKIP_WATCH_RANDOMIZE

Signed-off-by: Ryosuke Yasuoka <ryasuoka@redhat.com>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Kconfig.kcsan | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 47a693c458642..375575a5a0e3c 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -125,7 +125,7 @@ config KCSAN_SKIP_WATCH
 	default 4000
 	help
 	  The number of per-CPU memory operations to skip, before another
-	  watchpoint is set up, i.e. one in KCSAN_WATCH_SKIP per-CPU
+	  watchpoint is set up, i.e. one in KCSAN_SKIP_WATCH per-CPU
 	  memory operations are used to set up a watchpoint. A smaller value
 	  results in more aggressive race detection, whereas a larger value
 	  improves system performance at the cost of missing some races.
@@ -135,8 +135,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	default y
 	help
 	  If instruction skip count should be randomized, where the maximum is
-	  KCSAN_WATCH_SKIP. If false, the chosen value is always
-	  KCSAN_WATCH_SKIP.
+	  KCSAN_SKIP_WATCH. If false, the chosen value is always
+	  KCSAN_SKIP_WATCH.
 
 config KCSAN_INTERRUPT_WATCHER
 	bool "Interruptible watchers" if !KCSAN_STRICT
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221019230405.2502089-3-paulmck%40kernel.org.

Return-Path: <kasan-dev+bncBAABBMUQXHBQMGQE2IIRSBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 88ED0AFE62C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 12:45:08 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6faca0f2677sf136405146d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 03:45:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752057907; cv=pass;
        d=google.com; s=arc-20240605;
        b=Psj1XY4SzoToPJULC/f8h3GVfNbKEIuR3ilP4/3XuBacZAbfoyNAP42bgecNG/d1xh
         +7Rcnkz9JnsRywpRG7eFe7uFYyKjmONOJFBsWPNGwSCSfaYauxXE83aN48bkrtnsQ5uK
         NXqlZjI7SYqwps9myKS5DEylR9l+4MXsxm8Q3qVg922wBjPa9H+onZH8MsLKxxlqUDLe
         ng8HTBaSN/uVQVCzfeBc19XPW443/vxnWo/PuyTRmLUvHAKeJiGvj3L+MINwRTiiPv2y
         hs7u3j+HdecQ9rTT61eIarcpIMo9Qt6KcsnxLDZPVIQr8yglsnpO0EhamhYf56HaagIL
         WTrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YkCvv7CwM7DOtOYOrRFTAe/g8KX0Uuf7dkFE8ALaVXA=;
        fh=3IYUvXhH//71T9swE3w+d21/9IVY84R/LF7UPerbfRo=;
        b=SJwEQpiGkPjVdul9zIW+gOlAPmCcQS3aJuqMIVms0eaNABMonNUj8cAJ5CX7l8ZbMb
         NMoACRbB3+OzXdshPBuhtrD4fkzWpBXcixYi23hR/rsAyoPw5QyuMNbZtOn3x8tuUaBq
         mZngWmJGZF0nCyJ30YHeu+QlA7vaSZ9tFzguGqfSvmDHMOWw7ZSQTrV7a/VCRYdGrfd7
         w9LkFsJYgQvfv1uH++ZRIM6A2lBnoDnMCd6urjNDChaqEaAZWt143Yvo03jTqo27rSRa
         CpIfmsv755J8hgJzII4NWpSzLXLP+ZyqKal/wljBgUSLa1McPK3uIPendunGuyUOL1C4
         dXhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i4g4NyRe;
       spf=pass (google.com: domain of neeraj.upadhyay@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=neeraj.upadhyay@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752057907; x=1752662707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YkCvv7CwM7DOtOYOrRFTAe/g8KX0Uuf7dkFE8ALaVXA=;
        b=FxRxux8SWJfp2tm9I/SX/cH5JjF8Q80W+DwZxAdpb8DOk6dtnC5r7SOtI0Gvpx1mzR
         WWX4F+hVcM3RQvEERuJfgTGpPXTWTlaPXUpFRUcBeWTXMGFEZ4XzwvEoLcIoGQdqP4Gi
         N5Oxg9o1TH4DQqkdE1nuh/16EDJTiupA1LUwApl9VJGaWByDY7Ib2ORxbaaGswa5rKLO
         KtIWtXNOShq8V4N0NUmCQBRtOpdRZSpIeWhA/vKRI2V/WLxzloEKewWz3k3V6IJRocU+
         mUuZvVJX81i0t51gt0dR27ZHQEaUo2AOy+LxSO6UH1r8efnB5DRwFSXrPQy4vMWAl1Ny
         CLAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752057907; x=1752662707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YkCvv7CwM7DOtOYOrRFTAe/g8KX0Uuf7dkFE8ALaVXA=;
        b=rbixG0FOzqc0vnMnGDsC8ZTRCzCKF4+eaNMnXX9oQUbhshrI+yNg1OMMLeAr2hc3mc
         wDGVicOf0UQjBJWjhnC94tgV0tq+zVpkxZqRguUIJ/bjMVlT6UkRc8NMr8pf+POkxtdB
         FqjgiEWW6oPjMqfD2Hdd0RJ1EI5L0PHZV/mI/uitTeKvSCTKLLI52QaBhG6qQBnzFhEe
         T1DU/Yk6QXRI1aEYNXk1HGX/YKz9GQYpcwG8RZlhoGRXXHjdSaxF8jJGX8P7BBZc1MNL
         u7Ff/hFvYnVw0vE8relwJqbEP79mmdZofevoZvpY1BkKwFBslE2rSmGfiS0IkFvCM8F+
         HwXw==
X-Forwarded-Encrypted: i=2; AJvYcCXKl+HhmuNlMvdk7dvRC83/Wtt9qrkKAAHSMkrwD4o7cxUZ9eV51jRPDX92+5k8NTyiVjz42Q==@lfdr.de
X-Gm-Message-State: AOJu0YxBN7WxlwH0TThKFB4sOJBp/TfTIiLnmDv13t/1M9USbny8lXXy
	JKKJpidQ9PXXaDj1LIyEDLqAvXL4xyBiI6FzJ7wvPdVJWEdUW9RDe/La
X-Google-Smtp-Source: AGHT+IHiqp9ldefh6n3nc8d4XcuKjrTBxU/OcDQrIW3gfVZ7/8k9s6ydxETnHpjbYlEctsmlnKZChg==
X-Received: by 2002:a05:6214:260f:b0:6e8:ddf6:d11e with SMTP id 6a1803df08f44-7048b94c5dfmr25592586d6.21.1752057907085;
        Wed, 09 Jul 2025 03:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfXkVDfg3l9WXtyJJ0H6qU3wjwL8GIdXE8jV66whi+fDg==
Received: by 2002:a05:6214:d6b:b0:6fa:bcf6:6723 with SMTP id
 6a1803df08f44-702c9d2dc60ls83133146d6.1.-pod-prod-04-us; Wed, 09 Jul 2025
 03:45:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrzALNxFq9FaeFAEt/Jz9b/9SG0OKEZS6sfEKPi6dBOA1AehiKex2NQ8E2CWGR8lFxiuANfte6Fiw=@googlegroups.com
X-Received: by 2002:a05:6214:6214:b0:704:8fa0:969e with SMTP id 6a1803df08f44-7048fa09750mr9128886d6.41.1752057906066;
        Wed, 09 Jul 2025 03:45:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752057906; cv=none;
        d=google.com; s=arc-20240605;
        b=ZWL8NmgEoJYUo0pmrJsf+0/RrfTov4Tse8I62AL9r7/52SBnpgnowGZ4C6WrTVhizI
         LhyzYjOs8/5CMQ+gSz7gSSCMjFBu85WTO9Eiat5u4LrTVYhH9uEKs0KXANi0Oce4tjFi
         GNTmDGc/H9Frcj4MTXlNr36tDLCqAUceBs398IVQfQHrJ2MEW+zzKaD0KdWzm6EzLi/j
         RWqXwDNrfcIJxsKGb1DNYiOMeZfmFidSosz/8yhVDLiPWl72Wj0y+MHUoFH6vcZBOl5E
         IGCn7HgnM8FwjblIbEqnBpyrfKm9XG6EGFNH1KcP5RtUCfpYWpX6fhMHyXFcJLqXbzhY
         kytA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qAfYco4WfrGmByfZk6qWtv5WDZbE7I4F4cu33eC8eLw=;
        fh=1Vm7G+nURg5qLIv9oLN4HoGLEhEB6Hu00EHWeKSgmpo=;
        b=WRyqbdAcqxwxSY3Lip2adUA0Qj+0qc0rj4T26YYpjCxp1LzBsY2QQAqndsC3ysdZJO
         v6u0SuuVcOgnpdh7pRbGS8y2SE1HUA5luD6jDgoyjKj1+kk4AR8wsYZp6lGRmzMWDW0N
         7eobdyJvh2V44uszwNHHnBJ7G1oVgLCB6ZVigCJluJJVvNpHbWXCMAO2KM87NVvaGX0D
         XokDQaq4h/uKGntolimwaJz9JPmCRAAgCqVFbj1zwZ8VkVXboULrF+uYQmtBIPO7RLav
         Ji9NAF2vxD+hKBjKwSYq/8yLOzZLErgsfDi6QGnl5ciTpKjMzMLvN6ACATj/iEqXxvyB
         0xwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i4g4NyRe;
       spf=pass (google.com: domain of neeraj.upadhyay@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=neeraj.upadhyay@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-702c4d292ffsi5513106d6.8.2025.07.09.03.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 03:45:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of neeraj.upadhyay@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 28F7D447C2;
	Wed,  9 Jul 2025 10:45:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1A58C4CEEF;
	Wed,  9 Jul 2025 10:44:58 +0000 (UTC)
From: "neeraj.upadhyay via kasan-dev" <kasan-dev@googlegroups.com>
To: rcu@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	paulmck@kernel.org,
	joelagnelf@nvidia.com,
	frederic@kernel.org,
	boqun.feng@gmail.com,
	urezki@gmail.com,
	rostedt@goodmis.org,
	mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com,
	qiang.zhang1211@gmail.com,
	neeraj.iitr10@gmail.com,
	neeraj.upadhyay@amd.com,
	"Neeraj Upadhyay (AMD)" <neeraj.upadhyay@kernel.org>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH rcu 06/13] torture: Provide EXPERT Kconfig option for arm64 KCSAN torture.sh runs
Date: Wed,  9 Jul 2025 16:14:07 +0530
Message-Id: <20250709104414.15618-7-neeraj.upadhyay@kernel.org>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20250709104414.15618-1-neeraj.upadhyay@kernel.org>
References: <20250709104414.15618-1-neeraj.upadhyay@kernel.org>
MIME-Version: 1.0
X-Original-Sender: neeraj.upadhyay@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i4g4NyRe;       spf=pass
 (google.com: domain of neeraj.upadhyay@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=neeraj.upadhyay@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: neeraj.upadhyay@kernel.org
Reply-To: neeraj.upadhyay@kernel.org
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

From: "Paul E. McKenney" <paulmck@kernel.org>

The arm64 architecture requires that KCSAN-enabled kernels be built with
the CONFIG_EXPERT=y Kconfig option.  This commit therefore causes the
torture.sh script to provide this option, but only for --kcsan runs on
arm64 systems.

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-arm-kernel@lists.infradead.org>
Signed-off-by: Neeraj Upadhyay (AMD) <neeraj.upadhyay@kernel.org>
---
 tools/testing/selftests/rcutorture/bin/torture.sh | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/tools/testing/selftests/rcutorture/bin/torture.sh b/tools/testing/selftests/rcutorture/bin/torture.sh
index 25847042e30e..420c551b824b 100755
--- a/tools/testing/selftests/rcutorture/bin/torture.sh
+++ b/tools/testing/selftests/rcutorture/bin/torture.sh
@@ -313,6 +313,13 @@ then
 	do_scftorture=no
 fi
 
+# CONFIG_EXPERT=y is currently required for arm64 KCSAN runs.
+kcsan_expert=
+if test "${thisarch}" = aarch64
+then
+	kcsan_expert="CONFIG_EXPERT=y"
+fi
+
 touch $T/failures
 touch $T/successes
 
@@ -392,7 +399,7 @@ function torture_set {
 		then
 			chk_rdr_state="CONFIG_RCU_TORTURE_TEST_CHK_RDR_STATE=y"
 		fi
-		torture_one "$@" --kconfig "CONFIG_DEBUG_LOCK_ALLOC=y CONFIG_PROVE_LOCKING=y ${chk_rdr_state}" $kcsan_kmake_tag $cur_kcsan_kmake_args --kcsan
+		torture_one "$@" --kconfig "CONFIG_DEBUG_LOCK_ALLOC=y CONFIG_PROVE_LOCKING=y ${kcsan_expert} ${chk_rdr_state}" $kcsan_kmake_tag $cur_kcsan_kmake_args --kcsan
 		mv $T/last-resdir $T/last-resdir-kcsan || :
 	fi
 }
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250709104414.15618-7-neeraj.upadhyay%40kernel.org.

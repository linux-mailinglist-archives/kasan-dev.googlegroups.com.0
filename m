Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C43C0474D96
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:48 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id n13-20020a170902d2cd00b0014228ffc40dsf5688051plc.4
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=dHcjk1C54mhGhSN7s4ayeXR3dQHX6qb2Y/qaoRigZ5S0w2osR4ZDM8HPUa5NlHBM1h
         ClbQkSiP8Lz808DoltowVzmiKasBIwc+HdDZVSfL4xfY+NqxN8itWJBTIzWi4cn0R+7F
         UGUqhzxO8U4e62wIlaAbfzoa4Uf2/rNm1daoO1gcqXf8oiPca4Gklw9wKIQIKMwk9XS1
         Jdg9xjiVRo9ljMVPpdQRCGsJAQfIxQXK6RXZ3+YhrOqUINoDBXBw48dFsh1wgoPbkN/Q
         mKSi7yBNHUrHen1X+SDEHrnkmzNea17Bhp3ZdiRNh0onynIHUmr6R6nswtYUSs6ilNmY
         zhqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MvIoVjC9NkGIg4gweNhL1Ua7LTzq0RoCH/ASUrKVeK0=;
        b=vpd9/T4WIvV6MjKaoZMZ9IHS+H3cSjQCl3V9XtXTeUp2H/6JF4umfKOejQhdy3v5kN
         lO87TCO2x8gAVqPpDo67A4Th1l7AXxoJJr7WRA55uzdvJZBYzVRHimZnrOFRpKnRvkHZ
         P59pUL/vcWbPvOnCfBai4BNQXoySCy6VD7U0C8JDmSODIY3rlJSNB+LtV0NfY+4rzp/P
         mOHX84jJ/9tqMl/S4Gm0aylOhgB7h8Zx06GRXeV/26Qae+ZW8JW2R7dWKSaxWJR6KM9f
         U31+mR22XqM1fqXowscg17BarknaA4UT3Vr6IMk8g+NMPsTjAHQmSDoVipwNBIuETo/0
         4ypg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NLXyvB1f;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvIoVjC9NkGIg4gweNhL1Ua7LTzq0RoCH/ASUrKVeK0=;
        b=qkqobMxNJYyKnvklvhDqsGHQYEGqn8JF/Vo8ZeT2pomI21QBMrF1765dxTGwK6TYPp
         YRq8J/efxtzHr7pMstjfLkOzXAyipWAZTEj30/VIfWBl4+XEglhCG5xgQtu1NUYVXvn7
         Rm0/Fd6k924x8ffJcpDr4S9D+xdjG+bi85tWyIIagxOe/lxgjCP6+S4a+MemP7/H+Br6
         LYWR2M7aIFCd1TFgHwVmanBXWAA5+NkNncitkY47N5XHoSIP/cniEKj3SVbAaDKMNlXa
         MHueduhF7Zg/dLGlq/avFXaHqTgsPlYufEwhCm/v850nmERkG/9FnzK7PGv1HgnGTnPB
         Kd0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvIoVjC9NkGIg4gweNhL1Ua7LTzq0RoCH/ASUrKVeK0=;
        b=6aGpjDeIiyLqcO9jD/LbaVM/RPSDy/wIGgOaJhUBJaVy+/x1+6bxvMV+9irIp6wyY3
         h0D6GtS5RFhx0h7bv8N4UfSkNFQEUlSlBtmztpuC4tEsu68tNAknEmi0Hpq3KKw0Pb+g
         5FD+4jt00F7GbCtG8w9YiTOCCHxuaXTWV7jfJa80wdSYjkTjGwvocI5qGjxnf1V9nc4P
         X/qcHk4Mh7VN0UCHjsQKTuhJ9QNR0NlfmmM85INRMvadMWpBODgX/AA/niByzDvAjzLA
         46g0IWBbet5h2uhNM0bUl+amM6jp72RmV51/+jwbyea678RGUnlwhPoriDcJeP86IIpl
         t5yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mexScZ7m5aFvQe9RYRMHKQrPqI94QbvHheSQZ2XFWwpn9SN1+
	1/7r+oBozolI09lJyF1fs1Y=
X-Google-Smtp-Source: ABdhPJzBLmv2rxgVNISSNNXdDNuU6H5qkybdYsoUc8R1cMGQoRHdd2F+YE5YEBi/XC/xtMLmYiwXxw==
X-Received: by 2002:a17:902:d641:b0:148:a2e8:2789 with SMTP id y1-20020a170902d64100b00148a2e82789mr1515712plh.144.1639519487419;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1bcf:: with SMTP id oa15ls1373867pjb.0.canary-gmail;
 Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a17:902:d4ca:b0:148:a799:b4f5 with SMTP id o10-20020a170902d4ca00b00148a799b4f5mr145090plg.134.1639519486715;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=IDLRqszj7r7lLO4r1obs+y5v5yNBA/EQsj+Dmg05zgSB9ha48zP6Knr0YbVGV6xkTQ
         D22F+xPbZFso38eFU5v2D7ataIIBCSB1kUQRvpes4Fl9Ts2vOF0svW/3LhmCsc42i6/0
         U20eEmLwom4fcfTFZTxA2UXeG0Uak0b72qL4l+sByqpHp0VK7hIZ1A57EZ1kEsS52gcq
         bFXVi48lE8I7qMya7gs9FFkCxeX+4DXhbkUpBCyKBLCuHWvLlIm3f9BsDcdIzVXG+TmK
         12fTNEuUCUi3DvUvcHLd75Cz2I+8YQW5+Xj3xmUrbtpgjEVQLJ5jYI6O/SWJXPr/x8OW
         YenQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vBwHLmpGe12I2qg6xlCrzI9gvHJaf7bWaCJC2b+mu68=;
        b=vOTCjV6suQBlHftk1cpNp68W7lb69XjmERMgE/1Ki+n99P3Y8OZQ9e30HiSM7lTmcH
         xD6gq1uDg3xQQNQeXj6htziHAXw56TTHIFNX655xMFeJ1AaNDvmTlZrYcU6u5CmM/UUh
         wzrYqbyJKmdiRRjkUbdnnXJ1cEPiYVculWXuHXu9KgzvPpNzjcftQEPiXjB76V7hppuP
         M0iGugKNThPKbcLjRNDNWyE/sCUzuDuxNQWzwnhOoY7BCBgDnPlWVs8r5Ju1lNycJ+Wn
         DKXJXMxgqnTWZeAnzQ5oIcUp09eRsZim4aCCsSUpilXCuM/Bf0DyFAEVIL+9R1+LjcH8
         f9VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NLXyvB1f;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id p17si44754plo.5.2021.12.14.14.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id D4ED9CE1B05;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 473CCC341CA;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8E1F95C2B3C; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	kernel test robot <lkp@intel.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 27/29] kcsan: Turn barrier instrumentation into macros
Date: Tue, 14 Dec 2021 14:04:37 -0800
Message-Id: <20211214220439.2236564-27-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NLXyvB1f;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Marco Elver <elver@google.com>

Some architectures use barriers in 'extern inline' functions, from which
we should not refer to static inline functions.

For example, building Alpha with gcc and W=1 shows:

./include/asm-generic/barrier.h:70:30: warning: 'kcsan_rmb' is static but used in inline function 'pmd_offset' which is not static
   70 | #define smp_rmb()       do { kcsan_rmb(); __smp_rmb(); } while (0)
      |                              ^~~~~~~~~
./arch/alpha/include/asm/pgtable.h:293:9: note: in expansion of macro 'smp_rmb'
  293 |         smp_rmb(); /* see above */
      |         ^~~~~~~

Which seems to warn about 6.7.4#3 of the C standard:
  "An inline definition of a function with external linkage shall not
   contain a definition of a modifiable object with static or thread
   storage duration, and shall not contain a reference to an identifier
   with internal linkage."

Fix it by turning barrier instrumentation into macros, which matches
definitions in <asm/barrier.h>.

Perhaps we can revert this change in future, when there are no more
'extern inline' users left.

Link: https://lkml.kernel.org/r/202112041334.X44uWZXf-lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 9d2c869167f2e..92f3843d9ebb8 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -241,28 +241,30 @@ static inline void __kcsan_disable_current(void) { }
  * disabled with the __no_kcsan function attribute.
  *
  * Also see definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
+ *
+ * These are all macros, like <asm/barrier.h>, since some architectures use them
+ * in non-static inline functions.
  */
 #define __KCSAN_BARRIER_TO_SIGNAL_FENCE(name)					\
-	static __always_inline void kcsan_##name(void)				\
-	{									\
+	do {									\
 		barrier();							\
 		__atomic_signal_fence(__KCSAN_BARRIER_TO_SIGNAL_FENCE_##name);	\
 		barrier();							\
-	}
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
+	} while (0)
+#define kcsan_mb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
+#define kcsan_wmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
+#define kcsan_rmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
+#define kcsan_release()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
 #elif defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__KCSAN_INSTRUMENT_BARRIERS__)
 #define kcsan_mb	__kcsan_mb
 #define kcsan_wmb	__kcsan_wmb
 #define kcsan_rmb	__kcsan_rmb
 #define kcsan_release	__kcsan_release
 #else /* CONFIG_KCSAN_WEAK_MEMORY && ... */
-static inline void kcsan_mb(void)		{ }
-static inline void kcsan_wmb(void)		{ }
-static inline void kcsan_rmb(void)		{ }
-static inline void kcsan_release(void)		{ }
+#define kcsan_mb()	do { } while (0)
+#define kcsan_wmb()	do { } while (0)
+#define kcsan_rmb()	do { } while (0)
+#define kcsan_release()	do { } while (0)
 #endif /* CONFIG_KCSAN_WEAK_MEMORY && ... */
 
 /**
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-27-paulmck%40kernel.org.

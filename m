Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMH3P4AKGQED52UWLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 79F3B227D04
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:41 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id i12sf12859896wrx.11
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327441; cv=pass;
        d=google.com; s=arc-20160816;
        b=i5ZdCYClkha+35Kc5vLaUiy0hBdBvv0od4q9GO/tbbhJWs7E2EsLvgqkpQ5iUF+1oV
         jLLae/tRMpn849/7i0mfmPhCmrC0954Hahy0H9eXik2bt1zL23qDkBSM9pAgoQVvuhgO
         xTnt8RuIjkabaEvkjXSbJlG6lnsfg2VRJHa1r1nWS6aJAgXf2Mswdx2ISCpPQwWor+2u
         xHTai0ArHjWqfGbn4LnFnXj5rwNFrvmGsEJ+JgN9GJsqOEJ74xtefUzYkV1RPTkNqXNY
         GTNq6E418HeiCUPxg8MJf0mguIq3MwHzaRRzK3PJt/tdYBQDBTVrU0Ua9ZvlQPn8A9Aa
         3Z3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Irwu7gWHymfiK4RN5D1qJAtWHqzxm7vD6lF4UX0VrYc=;
        b=KS25+yZlHiOf7OckflFS6COsOov6biCccCX3ghsX8Ps2NJUmu/1xUmWGK0+Gjr+n1M
         Qr6epFH/ImFZvwb+4QdIdcyG84gcjJMntNcrOvlQG4OT8D1XK6iQB5uk71Hb0rKhTwU+
         +0IEwmg/ZRKt3dhb6aRFdeXe/4+20+d2ZHX+aWBZbKE/xY8K9BsBZT853b5pWTp+CgS1
         FHn/DuGQCvGtgqmjS/O83ic+9pDJVTcFXzWCY0h7YoOVCtQhmM5QatiJX4mW5jJasUG6
         4DiFe2eZo+VrIwKTqkYpozDW7om+in4+CfTxpT1Ynw24e41jr+IcFjiCLs6/a1Z5wOrS
         G3Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MwwVb4fG;
       spf=pass (google.com: domain of 3z8mwxwukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3z8MWXwUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Irwu7gWHymfiK4RN5D1qJAtWHqzxm7vD6lF4UX0VrYc=;
        b=CRJFYiRvQq3jyZpbSDJf3adn5H8uH7snROlTkO4mQduqjehhDtm2Xgxa1mHRL4ORSj
         GggERt7JxmAv+qh3+qPsyezH46bTEe6YTN3XG5epFtVVpEF/JkGVsulBCPtoMTlRwikj
         cyOsxVMRe0w87sjsN8pH70yu6i6aKdE7l2IbYBM7jpJhKKYcar1MM1qVXZro2CkkY+W4
         bDyVx0u2dQ9ojXjMcMZnMjWPNTkkXsRoX4n7VuUMhBRNbn44SyvLrgMO8TiYPR8XP0Sq
         zxg/3DLAJX6WHnN5+Ar3SrM49+HyMZusFlAIaXHpjhO5CZNHCWoG08e7jAAe3EMLpymg
         pcjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Irwu7gWHymfiK4RN5D1qJAtWHqzxm7vD6lF4UX0VrYc=;
        b=OxL9XqWkpYDTT/zfaVCJdYZObKkNV1Xp6NbJjlaztBCJw3ek/zs/vCH9FZhrha8HpF
         0WpzXCeZnu8mBiCjXjuSr81BTTUnkkFlGtPu0rTDvkGQqcpoFeY+bX0C6XY1KL0G7oXY
         KFkaAD8U3d7nWC77RUXDz6mifUojk6HzOV+hwhbDnvGkzqMR66q0PzKCM2p75SFzJobk
         3nkYTL/O2x5TAsnVXpjsP0xXqOQCjHY0pW/zmneHlXZOWJHM/8Q9RWh1VIfVdyJNcffZ
         JJPx+YfLhnIoJX6eWiX4qlLcoSRyPqsbehKXtLBMerxHx2VP3xfWlr21/8/Fm5A9LpLh
         1TEg==
X-Gm-Message-State: AOAM530dlC487FhuiSG0oBKRGQWtOQKAdAzpiHoOcRGtFMAIquDGxzFQ
	7SfkzOIX3iUtvSG9wbpyWEM=
X-Google-Smtp-Source: ABdhPJzDifkk0CoifAebvZKBKyjjAkZH4mWTC1GVma1T8n0iaQEiJHIvh0O1xBSU+sf4XdBLak4EaA==
X-Received: by 2002:adf:d0d0:: with SMTP id z16mr27431244wrh.95.1595327441257;
        Tue, 21 Jul 2020 03:30:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6507:: with SMTP id x7ls1023268wru.0.gmail; Tue, 21 Jul
 2020 03:30:40 -0700 (PDT)
X-Received: by 2002:a5d:6447:: with SMTP id d7mr1203248wrw.187.1595327440695;
        Tue, 21 Jul 2020 03:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327440; cv=none;
        d=google.com; s=arc-20160816;
        b=MwT5979f+O6yMJFdzRNg9+z0LHg7FD/2odyyXYvGButaxR1dpaz9gq2Ya71iUmo6a9
         WH06hcXJ/wahQXhnq1tHjhvDhK8+AQXzwL4Qkl6Zvfhi48i6ykeUNR0X5DYCKv/y9pBE
         DTEKCSDMCDVPGdQ50HO1zysX2l3A9aKC9f4XW+UhDQ8DCPTFqCt12jTyODG3PNiuRDp/
         uLsQ+oEck99MoxNTnF7UoRFb12M8BYg9u+gQo459GGpN/XfsQ2GralOlE0IfLdE0qsat
         CX/YI8ZahIjM2z1JwlG71Ta7PsiqbSntynS0mo8NRIoPWDqS6Fsc6BE8+nUq8eBM7fJT
         z3Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LMk4339Zjhhu0K58clMlPfJmEmRgvFiVE2OU6iIU7ro=;
        b=kp0rM8etX9AzAn5vs1+6KgZQ4ZHKuLottM4DrFWX4DGTEGsXUATd2F05qcOtdJytJO
         8u62Za0CzqKw5v9NwyNl0mG2sLJLvA6pbgLqNLGOH8Lrt98TC1SL6mbLJ/9GoWwEVHWW
         K/vSbTBM/GsZPYH/e4USYtOjrl9xZGpnfHPZ5ju9G9yiKh5zeaBFOjI1fiPHXRXLD0Ag
         66s7i/K7aeSJWkjECaimY0vJSLMT1ffliws9Mfy6B8nsItg/iBDlOh7eToa9wl1dA39S
         j3gm7uEr6RvaTRlhOUqQxSGGbeQQvK6ZcIiCnEDCdG0hWRY8hkW26C7Jo9NJNn2+v4Dv
         V/YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MwwVb4fG;
       spf=pass (google.com: domain of 3z8mwxwukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3z8MWXwUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id y12si345739wrt.1.2020.07.21.03.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z8mwxwukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id e15so1074253wme.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:40 -0700 (PDT)
X-Received: by 2002:a1c:cc09:: with SMTP id h9mr407498wmb.1.1595327439944;
 Tue, 21 Jul 2020 03:30:39 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:12 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-5-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 4/8] kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MwwVb4fG;       spf=pass
 (google.com: domain of 3z8mwxwukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3z8MWXwUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks for the builtin atomics
instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
Added to this series, as it would otherwise cause patch conflicts.
---
 kernel/kcsan/core.c | 25 +++++++++++++++++--------
 1 file changed, 17 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4633baebf84e..f53524ea0292 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -892,14 +892,17 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
+			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
 		return __atomic_load_n(ptr, memorder);                                             \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
 		__atomic_store_n(ptr, v, memorder);                                                \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
@@ -908,8 +911,10 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
@@ -937,8 +942,10 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
@@ -949,8 +956,10 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
 		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
 		return exp;                                                                        \
 	}                                                                                          \
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-5-elver%40google.com.

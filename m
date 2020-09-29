Return-Path: <kasan-dev+bncBCS37NMQ3YHBBCH5ZX5QKGQEZUL2HYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 934DE27D5D7
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:35:53 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id n133sf3374796lfa.19
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:35:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404553; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8W0pC3bW9uWGcSnHzD7QlpW4JL4sWcpTeyhUwkWJtjeJFeP+HWpPBKD3poxOzldhJ
         iS2ftFF+p2eOH5sZTbdUHpYiYoylY60hXlHViyP45NNlFg1eM2w8xuslURfVIviR5n7Y
         //jOPwjfl9VGJtpePCekt9DoHlmeimwlOczvMjNTrcu/0ulUbUaJowQcG/D0GHrDPEEv
         B/aeuf2RPxfTVI+sGgYq8gthrmZOv6vCpEMNLGsp6BQCfY5JqqrOGihQNPQOf2aE5fi+
         vI8jHjxOdexygxxABrYK/cN6RdlV9yK1bjb/88T42D8K6qX5gtuvaJwPrZ8wDUpmBzKi
         Y9IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MUbGy5loWunEyDgwcb1SxxX7WF/m2JiTnOi5ppG4wNU=;
        b=HZTdNrSF+2aSb7ofwerS2oLwTMXMK2HjLsU7C8uDrZREuESbw5dkrz9NpjOmlznyUR
         rJcHFF1SPHBEBuD8/8wticSlhClvTdgkC4j91GuwIDslD+6WKYvg3hkkpQ334uwKjx4v
         Fe0DsaNfrlYObuViOOKo91pXT3AZemfEKWgha6c7w5TfL/Xqoxc01grCWTmKZ2mFWReM
         TL9F9njuT370xEHgCDd+ak0V4KZ0cckK/vn0IFH4hVAibrJSi9iIRfwU2p3F4ttUETlT
         rdjHz8I3Jhb+mif/nNUpdIlcWvgaCNxm6zmf71psqrrRE4EMDSPGJJjIO2SNSx2du6Sz
         N2Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUbGy5loWunEyDgwcb1SxxX7WF/m2JiTnOi5ppG4wNU=;
        b=s732VdVju9Y50wnHOsMaA3IPdHJfUlVHARB0SrRVoUV8zZM5CXy5V0S5Hi9pf0zZbf
         IX7AHh+aY4iAKXCCQj8UL5dJ4DCcDko3CWxe0J4/bslA/vPih/S0zw23wt1SVqEQMg9x
         jxShHpXMzJtE7p6vRT/J4i/YYi1XOKfqbwWeLCRQM6di+/PgdRRHL4Q8eYMYm4J1kucX
         q8OYdUDRk0G8PME6RATHIoK8XEkF5G2k4+T47BQV9vAOM6xNRDCwGYecWSpZpJ5LmNEH
         uEtWinycwRt7Y5Q4ZwfFw3i0buS/x7XI52zOklsxvoBm6g64+4Xs+k52c1sbBECpG1Nm
         MtJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUbGy5loWunEyDgwcb1SxxX7WF/m2JiTnOi5ppG4wNU=;
        b=lEh5dUmr3GwvF6zvggtmhU5/fENtELilTIlRgEK7bZWOk4LqSqYDxWgwcAPJSwCE3Y
         1qIfnEL8ZD84mbX49pry32hrEYrwByLdw0KozWdN5Pj1f34vyhzHeECMzUD0LcutjoC5
         mzO9M+MVvre1sZjac/jTr3Jy8II4qRxgLs7/v2ZXUBTSeaF12bAru2WdSIEQo/7ggiZz
         yehXeynlKGdCs5W7/qed0dZwMQoTtL3uRwlY98PEsY9zbvFSg/ceKkvx3MTCxTTIYnmj
         mb86tieups7TSh04A0bBPh22CTqnHREY2cX6MBa4edxww6qk5hHwz/hAu3eDdGGOmaeF
         l65Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hwm7nZf7aY31c3cERpRuR60QnIcK6VMX0BvdhccOFn96bNaNN
	7/UJzFGfiNxAd0a4rKmW0fg=
X-Google-Smtp-Source: ABdhPJzaIlFAsFwBV2GdTZaD8BFUgxSY11o+DTsYBg4Y3uP8hiSoUK513l0vioOzAsGmrGpLkLEEBg==
X-Received: by 2002:a19:549:: with SMTP id 70mr1868723lff.529.1601404553139;
        Tue, 29 Sep 2020 11:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls1304397lff.1.gmail; Tue, 29 Sep
 2020 11:35:52 -0700 (PDT)
X-Received: by 2002:a19:3f0d:: with SMTP id m13mr1791187lfa.91.1601404552115;
        Tue, 29 Sep 2020 11:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404552; cv=none;
        d=google.com; s=arc-20160816;
        b=xCQVgr1MHEgJt2H0ZJU8dLtClKZFxfWnkXZ3r1LPrKdg6C8bJ7mNaha8xqwQ8tbrXk
         pD2BPrQPHhmbx9McnULAe2yM0InkRqk2EOxsDm2t2bZ3deOc8I0YAZXZ366LrICNdo9f
         gqlNhzqnMJex0NIrsS+wFtjWJxps++Vb1fDpBXfi/PS+WdCFgkSstSbYWwnm0a1qQaVT
         AJTZlCu3T5BIk3iF6q1/igGdDyYRS6JOtScnvubslo3m43AEwVbvwnmfYlpZydOiZUQ+
         ozVwtUe43p/sjFgrO2VmVhZBev8qssOT/NAhxF1TG/l1889Jmt0bRqHY9Vgvdt1eo2UB
         kudw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=2bxuhq/r6r8osy7pzVzO/JXpG1ASc+MUIPI5gsA7kxI=;
        b=pUhy4H4/vm618MPZnNILHAtOe9GMQS9A3D4tCHvfpcoYqdOAZHS+LUd5Uy52xjwN7S
         8/oZA14V6/JHu8K9TXT6MwuRbkLOgvXPupufDj/EGN3NdFfXlNRiyT96yRzoGp1znPqk
         O3qGoEcpnHqEu0i1rf1Iv40G6jiTGZvBRFzT3a8Ux6RmVSTl6KSp/m9R0iocjihAEm+V
         hQUg0bZ9/6w9rVqbYts3BCQV+wMUNcBGDaeAZ4tuom4B8wUnWn+5ww5ZIgVxyEFCY34+
         XMzoQRBlMNenXYS84f7mNfep0g4xtU4afyDlefAkPRwGuaVs71rMigbyxmEH4nKe+jZq
         /BpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f65.google.com (mail-wm1-f65.google.com. [209.85.128.65])
        by gmr-mx.google.com with ESMTPS id q20si310079lji.2.2020.09.29.11.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) client-ip=209.85.128.65;
Received: by mail-wm1-f65.google.com with SMTP id s13so5628866wmh.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:35:52 -0700 (PDT)
X-Received: by 2002:a1c:5685:: with SMTP id k127mr6197810wmb.135.1601404551593;
        Tue, 29 Sep 2020 11:35:51 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:35:50 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 3/6] mm: Integrate SLAB_QUARANTINE with init_on_free
Date: Tue, 29 Sep 2020 21:35:10 +0300
Message-Id: <20200929183513.380760-4-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Having slab quarantine without memory erasing is harmful.
If the quarantined objects are not cleaned and contain data, then:
  1. they will be useful for use-after-free exploitation,
  2. there is no chance to detect use-after-free access.
So we want the quarantined objects to be erased.
Enable init_on_free that cleans objects before placing them into
the quarantine. CONFIG_PAGE_POISONING should be disabled since it
cuts off init_on_free.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 init/Kconfig    |  3 ++-
 mm/page_alloc.c | 22 ++++++++++++++++++++++
 2 files changed, 24 insertions(+), 1 deletion(-)

diff --git a/init/Kconfig b/init/Kconfig
index 358c8ce818f4..cd4cee71fd4e 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1933,7 +1933,8 @@ config SLAB_FREELIST_HARDENED
 
 config SLAB_QUARANTINE
 	bool "Enable slab freelist quarantine"
-	depends on !KASAN && (SLAB || SLUB)
+	depends on !KASAN && (SLAB || SLUB) && !PAGE_POISONING
+	select INIT_ON_FREE_DEFAULT_ON
 	help
 	  Enable slab freelist quarantine to delay reusing of freed slab
 	  objects. If this feature is enabled, freed objects are stored
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index fab5e97dc9ca..f67118e88500 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -168,6 +168,27 @@ static int __init early_init_on_alloc(char *buf)
 }
 early_param("init_on_alloc", early_init_on_alloc);
 
+#ifdef CONFIG_SLAB_QUARANTINE
+static int __init early_init_on_free(char *buf)
+{
+	/*
+	 * Having slab quarantine without memory erasing is harmful.
+	 * If the quarantined objects are not cleaned and contain data, then:
+	 *  1. they will be useful for use-after-free exploitation,
+	 *  2. use-after-free access may not be detected.
+	 * So we want the quarantined objects to be erased.
+	 *
+	 * Enable init_on_free that cleans objects before placing them into
+	 * the quarantine. CONFIG_PAGE_POISONING should be disabled since it
+	 * cuts off init_on_free.
+	 */
+	BUILD_BUG_ON(!IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
+	BUILD_BUG_ON(IS_ENABLED(CONFIG_PAGE_POISONING));
+	pr_info("mem auto-init: init_on_free is on for CONFIG_SLAB_QUARANTINE\n");
+
+	return 0;
+}
+#else /* CONFIG_SLAB_QUARANTINE */
 static int __init early_init_on_free(char *buf)
 {
 	int ret;
@@ -184,6 +205,7 @@ static int __init early_init_on_free(char *buf)
 		static_branch_disable(&init_on_free);
 	return ret;
 }
+#endif /* CONFIG_SLAB_QUARANTINE */
 early_param("init_on_free", early_init_on_free);
 
 /*
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-4-alex.popov%40linux.com.

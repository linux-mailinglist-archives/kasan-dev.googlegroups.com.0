Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id E6ACF40D0E3
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:50 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id m9-20020ac5c2090000b02902851a6b61a0sf1074620vkk.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=RKq+XFWSFWhVKZNRwozaKY+m8JBcOty4GhLqNDGDSk9uWpUSH/+nPQWm2bHDV5QOlb
         QlUPpuXD3KYnQYqSFykkc0WLbFal7AqZOieqZ4b/9K26PykW5u5orkGlbQbnK62luGH3
         Xf20luvK9OZ6d9nQzYMh1dPu27rQFLgdsd4dyIdYC94y/V54UevXYjYG4z1YNrObjQQF
         qXlGCym1f5yCswT1nu93C1ZFhtjWi/cNnGBb01aU1mudajcpVLLNRyAg9fS0lmK+fvzu
         w+GwZc+FewtT9E/hlWu9owdhi5u08CBGnt8WHUaf3svIn+TT4Cxjl3QUOXjlAarVCzcT
         t9hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JurxVbVxv41IHb8ce5drMi8FRYt5/bz6fPCa3yNyvrE=;
        b=ExdBu1c7IXQ7KRlHlw1HdhDMzhdLCZA17l1zCZ8/QAlopoMh//aVLeREOj01GQedPQ
         CU/RPcOkQVdzUVsyC4TvQa7SQ+n8+SBIMLNRRqGCIlM498pyKun7XhMLBf04kfLC1eMc
         golaAkpmeIH3BFrBUAsoMP/DJiS930lKBKFfSHSUT129Wvq4MSLXivgzV7wvNc5vPVza
         1rqIP2Fh9oApP4qmxsqamuh06KKtX8tl05+XJOP99/w/p1Pl/ZFVVXA78s7VCgiaCgJb
         ABJimGlnY64ukZ7pfTDuiguajaWjYA0l8oXGbzkNPs3qNY/6wP541U0hqed87b5UnxeM
         QBug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KkqA+aI9;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JurxVbVxv41IHb8ce5drMi8FRYt5/bz6fPCa3yNyvrE=;
        b=SCuaaXHC00l7fZyMAFUUWhdAtl6z+hZLvGcUXcxUMW/T+oulQkzHJkxUVMTMh0wtEE
         Or3IH5PejQbM1JMZ/ZgjydE5F60byABKQtnxeH/j4Gelai/A4tU5GB0VR9YiOxE5AQc9
         Wjb96DilnsxldlwwEJwqcj7VUq3bt2VCFadaLsnzmj7Z1WY8TP0iv2H4/qxrDAQW50P2
         LKU70ZGKPZ7Qk3A2AjzzpdhYOyzhrk542SIkgKUQlccc1X1em3jOnRerK/3Px8+JB17f
         ym+bDqm6BqGDhqBZAtRcKvyOWbSr59lXpIA4BEasbq4HnIoAqLVpAeRiSvGxAy1/8ly3
         eASA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JurxVbVxv41IHb8ce5drMi8FRYt5/bz6fPCa3yNyvrE=;
        b=U+3HR0QiuAsYmwJkhhnU2RiitASRnSsKbL/wplZLAHeLXvkfw+tCiK364J0PfheYjr
         zmgdCb5a3gh0tQ5vk0qNU2Z1Wm0AJGDt1JuXkPX9jjnhrG7GTqwFuHAeON6mjbIeCgIH
         fV3vQM/UVTtQ1UBrdjDQfnrYFtUbmURYtYtfVdZqUU1XnX4hSR55Q6RMyIfKY2YT6Sow
         qMMUQ+sCZXcqxZxuK6vopQPnA7viFqukPIrhaqofwVndHQsubqcgLszPL9lhynxaZWXF
         vtyB4lA2ALpZwcFX44Wdf4lwMcM4AVbP57mw/+k0J0Omr0iGbByxPGkVrWBjEJTlx4aD
         Uhqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530sF9dvtm9THRwdtAmi8qS9d6ETMkMsFyhvhegxISlNdqLYT+rA
	S13wlG/iMh/f+zEyQAhqS7s=
X-Google-Smtp-Source: ABdhPJxhoPNTP3OL5RdDIFkw9NpxkIY/0f0j3aHdt28eijQU3k2o3bWW9fWlgDDhKH+7+A0mOEtSSA==
X-Received: by 2002:a67:3307:: with SMTP id z7mr2622404vsz.61.1631752309407;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4d6e:: with SMTP id k46ls356180uag.6.gmail; Wed, 15 Sep
 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:a9f:2070:: with SMTP id 103mr2552265uam.34.1631752308889;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752308; cv=none;
        d=google.com; s=arc-20160816;
        b=Ip1vAojjmmxR48yDNgxudg4f/wqEb2E8wEZTnRiWbBKTbcSoTZOnpWmDWTKXiDWPux
         Ogqa71tsUi7S/8AcoI6qvZSmoEtCEgyRfNOV7Kc3JyE7NkD/61rqzB4kxluq2DkDnlf5
         j3oZZIW4Sfs6qMkwVNE8i3uA+eImgeWNraaFiLF5B5cc0dixO7XsLac9LEPWoSHdUyet
         Wp2DgoUZkiK/v+jPx/p0MKcSKIn1Oe4oGqqYQYqCnbnI3sp8lLOG6fDLYmrtxlSeNv7T
         zrzVK8fI8Xfc6DJMkP62yOf9z7h62hNoUT7WkYjPx8LDaFR7pHJrGxS8cR5f1hRJtttD
         c3nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=STg9mNqmgxoCLN7TLvKUtZ7oZmBnAqaS+ZhaNT75I6U=;
        b=a1HbWEtNnaG0bxfUC8b6Eg7TUYPEOssBAjFsmbyrR5ehgfcmuH33+0rBkNn8jeNfEe
         Yim4hrgKhzhedJbLRBKCymHBb8KN0P0j1+eKnNttDycqcKEFlMMBG+NXXay+Y7a0D+3E
         s1Zo8Imu13/psg5Ltym01QgS5qHfM3vJOEt3UV6gthR2tLQnIcdAOe8i86Ir0nbhEkoK
         nnsaCx4gUNAdsTakLsi5ULEHceKZYEQEIJsAu5p/TOVsknS3JazGO1dW2A517GdPVxbS
         bMSW+eSMO5kfN3n8r/XE4AMMhlyMxnG4/RdHKRXLCSv8zoPre9B8Lxp9xJhoEyzIsuMR
         ceOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KkqA+aI9;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 4si355046vke.2.2021.09.15.17.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C3FE46008E;
	Thu, 16 Sep 2021 00:31:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id ABB635C054E; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/9] kcsan: test: Defer kcsan_test_init() after kunit initialization
Date: Wed, 15 Sep 2021 17:31:38 -0700
Message-Id: <20210916003146.3910358-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KkqA+aI9;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

When the test is built into the kernel (not a module), kcsan_test_init()
and kunit_init() both use late_initcall(), which means kcsan_test_init()
might see a NULL debugfs_rootdir as parent dentry, resulting in
kcsan_test_init() and kcsan_debugfs_init() both trying to create a
debugfs node named "kcsan" in debugfs root. One of them will show an
error and be unsuccessful.

Defer kcsan_test_init() until we're sure kunit was initialized.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fc..df041bdb6088 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1224,7 +1224,7 @@ static void kcsan_test_exit(void)
 	tracepoint_synchronize_unregister();
 }
 
-late_initcall(kcsan_test_init);
+late_initcall_sync(kcsan_test_init);
 module_exit(kcsan_test_exit);
 
 MODULE_LICENSE("GPL v2");
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-1-paulmck%40kernel.org.

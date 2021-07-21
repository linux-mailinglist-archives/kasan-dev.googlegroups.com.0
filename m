Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 782943D18AE
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id j22-20020a17090a7e96b0290175fc969950sf456980pjl.4
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=nrwjEsYutzJOkiZt+oCjveyWvOM8WosXBcWeGwGicQ6sD6tCoG4Q5l7VATWfxgSFi7
         G32ck4c2x2PPtDzgw5IIqOtgdroF4Hzeab6PK7VWYG6jaEfzxsOXDy6aFEKDSf5OHDNG
         mPx3titZpYfF8TwFSY3LFQTriUDPotpzwRlGlmeC9J1q/qprIR/zz2Dam9oGIIM4AyeV
         1k4UK/JtaRQwOMZxsedo1Pna1cNn+4HoAxy81gP9RVse/A3mitljDu31K70UmdZ5a7uB
         ktmAyucgR7v4BRSWmSCoMZsOhA11waP+Y3LoIqldR7VJUHKx0tfXuzr1bW3qCinjVgH4
         os7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OG+U6CDeD9QLn+doc06xxJJQYRuAAJ0x7JZqooD+XuM=;
        b=K04QQbowUYye7w6pJ+16Lu/87bNlgUR305d+eoAAzAOMPY3gxl5ySACWZmadgJR55Y
         Tr36V1NK+ta5Zyuf9Ve+nBvmx7+VfYnw3DUoUMtYnntgDyK4vkNQDjojJ4VriUBstB5h
         29oC4mgWtZNleaDp5+rIpsfxCW5bvF14BHRSqtgz4rXwIP8EqX2JmwdpMl0k37iSUtVb
         6YvpeMsIeUQK451JdvujrdNWnPYLEnDb2tIo1Dagno4BZ7iOgYrQg48MZikZ2+xuGecb
         BwfqwbruMUoO2aZG4gBO3oJADMO0hZQTffYFU88NVXLnV+IBD6DY0Slk9kDYnJRnsPZh
         Q3YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WFJvoaHl;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OG+U6CDeD9QLn+doc06xxJJQYRuAAJ0x7JZqooD+XuM=;
        b=hM1yP4VU0T09tnsahtQMJulKuzVKm+KDglFcvo8VEDlZTmzyCPYtfFKC7HqbA3SCRW
         JfKsoeOGPc4paEWSJq06fsqluS1i+xfaRHrDT7HyVbnq3AOusXO9UmiO7rCxIHhRC4Co
         Q5f5ELNYpQtun3D8+eIRYmpACVtEYKZVld6GpvOqe7RaVzavcjtomzrZ0l3J9XIx4nlV
         Lz+IkqBiJCIIWWXLus5iabBRJ9FhmSuovjGbKgkwKYIi9o45kQJh6Mqna+oloxy2HYge
         ek/bWPy4qIBBV9aZnWLymFc7rkwyzX1dG3xjQH/j2xZC3GuVOQ720GcykvUo7xUCjDF+
         sgrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OG+U6CDeD9QLn+doc06xxJJQYRuAAJ0x7JZqooD+XuM=;
        b=mDUFyk83EBjPpbSv0E2qq2S6JlDMKV41k4f97lI70eiqzH3TaZ2D5XjFFUDb3B4sbv
         jlUznVOBmPZEg9lx7pIBS91vW+nRh2prURWGqKRvjBU8u6rmCoaaAlBOd8p7LG/90BSB
         inFCZ7CSeDIjljZJhGqf0R/0QGYnPdcgVSlWO7I7F/lxuRiNbndbfxPByX/JLOFBwdYQ
         BquSHzmPuht3dNv2GyBUKTBszrk+VWlajWygPjFjKjrU3mkCNM9uMmwagHSv7FQu2TA/
         RaYWUCFQDhoraih02BfloVczs+j7d2Hv1F0xb7H2IvsnDJ7jEIJdidiSsD55U5D55Alw
         uMeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533szb8CHsAxYV1Bwk2d/znqgswC8GvpyQyVihJHnO76lg8pqiy9
	LOoLKw8JoCuTG/P5Bs+criw=
X-Google-Smtp-Source: ABdhPJwvRZ/VhJuooxqGl+MrPOg6mASTQ5CkDs0KCuJQ6pqF0n+MD9wO1tT7oQyrLVZFSZGZ/zZqOg==
X-Received: by 2002:a63:5f87:: with SMTP id t129mr7532444pgb.85.1626901696184;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:16ca:: with SMTP id l10ls1536928pfc.0.gmail; Wed,
 21 Jul 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:aa7:8e18:0:b029:2ec:a754:570e with SMTP id c24-20020aa78e180000b02902eca754570emr38001997pfr.38.1626901695636;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=uLFv0svGysmz3TNxMU5CPADNKJgZ6gjRg1MboLNeog45gW7nmBgIedsmmDPQOZAHCc
         irAKvYknldWPbrbJDZ7/VJFQ2e+5D/j8lYb/AlANhQRIgEm7FxqoTPzaPd4NHlj5pKoJ
         60QllymJAfVlOwvsA4n5aKc9tfVSl916sNz8K9OegIAr07zAa0U6a+rn+T2AFpWOvX5Q
         W/NYxqlr+sMoH38rt/FBNuO+cu0W19+Q8fhy76IwU0SPZycpEh/CPiypt/R90IUyfmaU
         PtPaDdIvxJ0YI1Liwa73p9uLej41atyyvEYneMk8HQ163gNoqCJpyJ7LhdYKnM7/sR95
         OhIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XD7qTkIdI2wcmiG7hw9VLQk5gonPCKM3uAF9yfVjV7U=;
        b=lNVZAOAuXtBxU5m2MRJFpgpK5vOY+lMZERvtJtiPiJB48w0Wh8WqKcOpc6S5aQHPje
         I8M6iQtSaJovPWvvw2+MeS4HbPVfdWTeHXLqMms3fBGl0W/w7n889BbPWD4OrzvCxd6s
         Nhfqx9Z8xvBFnQv4N/vmkJ1fzy8NKtOZ7LTKlVV3itkT3sg6feVr+lHO2J08dNHpDD16
         zHZhPHh2aTaaa6AGkQ0E+BwjRSJCIxOJHWTqom1BxMRwrOO20oVZ6RsLKAKK1TigE0H/
         uRM6ecqRqFB2R+qOyCe62Vqf7iaB41GatEaPaDiwJSCKUn6vlHp1opav4U12VyKNP6DH
         qF+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WFJvoaHl;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bt9si89600pjb.3.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E9DA66141D;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7285E5C0D47; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
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
Subject: [PATCH kcsan 8/8] kcsan: Make strict mode imply interruptible watchers
Date: Wed, 21 Jul 2021 14:08:12 -0700
Message-Id: <20210721210812.844740-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WFJvoaHl;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

If CONFIG_KCSAN_STRICT=y, select CONFIG_KCSAN_INTERRUPT_WATCHER as well.

With interruptible watchers, we'll also report same-CPU data races; if
we requested strict mode, we might as well show these, too.

Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Kconfig.kcsan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 26f03c754d39b..e0a93ffdef30e 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -150,7 +150,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP.
 
 config KCSAN_INTERRUPT_WATCHER
-	bool "Interruptible watchers"
+	bool "Interruptible watchers" if !KCSAN_STRICT
+	default KCSAN_STRICT
 	help
 	  If enabled, a task that set up a watchpoint may be interrupted while
 	  delayed. This option will allow KCSAN to detect races between
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-8-paulmck%40kernel.org.

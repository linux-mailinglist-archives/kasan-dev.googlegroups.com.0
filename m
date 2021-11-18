Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIEV3CGAMGQEV5RK5EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 13E8C45565F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:13 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714sf2244447wme.6
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223072; cv=pass;
        d=google.com; s=arc-20160816;
        b=pUS8tc9OBHKkbK4V2plgMa3tqpc8milINAyr1IdaCwPDbhQrhUUYFtju82t0wQ0YyE
         Kv4kMvlN2jfYa6t9BXmzk76crTdyK1d11soz8mpjsl/4rzU74JD2Tg6M0IzfBWGixRjq
         S5JkFi2Ed4Qv9SlDCv5xJjiIPGgFLGQWSrOtzdweawGxDeM1k6M5+QmJVJI6J81mFAXa
         Asq6/Tx5xLAXGriXBmNR1MijvFXGBd1d76rm8nNpB6eUl2rGp93GQrXAniDZlyD+q6Qs
         QHM0IPIJkf7tcgLO09nEvcKTzGgznyi6+Yx9iReUjUptKiaW93aax3Mek3Xokr7+F6pr
         RvYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=V9fXz8xkfy64YCirURCpEV0OdVg6NsC0BKxCJ66Fv4E=;
        b=xEiKxTOVOMfgNhH8uHh6IZdjQCnr464BzayqSgUKikeGFkJ3EEmMITTQ1X43NLuRGB
         wlNTEi0keb5XOb8nwBZ6+xW7722IB1EM1PYQDCYIppFVfVnrsRyYVPvGoC8bEW9Anhkh
         ZzTY7ISIjYMTNSHVMiLXOQXiFvUlI11dm+sNVsNwd533r0CIe6YjNZDqFHT/wqkvRAgF
         x7rkPHri/EcH9GEjctNGfbsof7FNFJBxP0zL6rOliMnd3MZwBFNRfAcZEcHOw1lr2ZAp
         pfb8NUF/o5/vk1W8bmdpPMGd+9NIpdXOz3Pq9BjYUeCP+tL/zbDX/vhHB4WmhgOwoI1v
         IQqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lSb0Xjst;
       spf=pass (google.com: domain of 3nwqwyqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nwqWYQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V9fXz8xkfy64YCirURCpEV0OdVg6NsC0BKxCJ66Fv4E=;
        b=VdRvBVxOdwlqtoJ7OQSNv+k9W2yq2F1c+Tu7KKSCwrGnZJjd5YyKs4H/rs8gTQvmNW
         uD68yZS5VRs1Y1bMmcALU5TEAxGbnQgjHUxM9f+hwMrAlerJDnpFAeatcr3VgjvFXvlc
         pxo8B5x+XI7dJ4hLqoygB9HCzqkHgSsjE/9QVtCiYKYUQgNInPnZpADUhFNR5uoLwITF
         kI8xiHyScdAGRvJoJumuJwU2pRXzlZp6dJVY3g5M1fRigsniHIUU/2scDbpQC3CcBIHW
         3lUniYKzI2Ea+/TgltZ2SAjzrrCNjLlgEKs+XDLtAeruBYdqF+azrZ3790YV4zFEYR0S
         IiiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V9fXz8xkfy64YCirURCpEV0OdVg6NsC0BKxCJ66Fv4E=;
        b=Cf+XNxVkzDsaPcUFzehjhroA70cm/1Tuiui5Ks1OBxivRKWHqVxY7869VU7rPdcrs0
         Rm+Nr0jW9P9vEPF8OW+giNNqc1wSBDPZj+r75a2bW+eANTI/O3n462ghZyuTvov4ZkMc
         92qSnzKE5tmFoL34ZOd41lcpJlxhVFYFIYgZFlYO3h0A5BPKIIiBMb1Ln4kKohAae5kC
         mL25Fp9x2AhrH8j4rTPEwOYMSoAao+INaiqnnKF6E9ZALd+6U1YYC2MP6hwv4RnGyGjU
         ih34tWmobtU/q6P2bogIJ++U8GCw4zq/MF20KzYVnD/XLBzBdsbcAqMViuTetT7PNpsH
         8v3g==
X-Gm-Message-State: AOAM533WQ1GXITPV1negZb1mqRxd/hFOzz1/CqNmhEhNDxuxhpmBTjpa
	/5CXqb1LyxMqqNzE6bSjkWA=
X-Google-Smtp-Source: ABdhPJwmZQRFncwJ6wXenzJA7HR5iki5r/QxyudJi9m24SCxhaU2JEu/G9rI1dez2SxxS/w5R9TJug==
X-Received: by 2002:a5d:6dab:: with SMTP id u11mr27691783wrs.46.1637223072869;
        Thu, 18 Nov 2021 00:11:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls2318751wro.2.gmail; Thu, 18 Nov
 2021 00:11:12 -0800 (PST)
X-Received: by 2002:a5d:6e8d:: with SMTP id k13mr29757292wrz.295.1637223071963;
        Thu, 18 Nov 2021 00:11:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223071; cv=none;
        d=google.com; s=arc-20160816;
        b=SAai+LMjgRr2osRWDC/YHQkv/X5ERtRcy+hn1uurw0gMq6JC7YVbpQ6ZhZwKrOb63x
         LseD+f2ymVWwuSXiP37RgYOT/EfOHJQQ3kVGbW/zKSiRD9Og6tliQOx4rZvdgJcNkwvD
         ENY4J3zVmSOC91jkaCUWNUw29FYBR7Uaz+OyLa9L7aF4NiG1o5LsktRh4GAF2QAfZodk
         fOqH449hEt7tSlzwAeqM1BZ+FntIqbjmqIHoeDcEjbKHk/iowgSjbmT56BNSobhx9AVQ
         g14b1JiguvscRiUmUO0Tt+KeJ1eK6thd71a8NOf8gZFbFYXqf6KVhg1btDYI03u7Ogmv
         nH9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=K7olqGN/TGjGn55ZVkEX4B3oA8fATuBzpoXYDPWo+s8=;
        b=Xva/dc9OLaJkVvDj9bAAc2iuf0Y8GZ4xnXFCEedOIM1k8zWHbzmPKogkpGciRmKJJn
         1zz8KEScYTEC1rpyyfuK2sjlVnyytu+k4/6zt4wu+tN7KHFf9dBlgvav1mKST74Wt38a
         AumTc28RKABsTTmtjg1//TWEpKKm2EVSb/Zy4LZoiIAD5hPTFkh9SZaMwJDEvxtbJ3ac
         Hltx5Ls0gonra25Bk62lrv+c68jM86ms/2v4moMsORsEjdb/jNCB+Ssoa2gVGnV2JsDU
         dariQspbVxkygRkkAGzSFrO/pz1OCLvAlnP65FOP5L9/romhGu8bAwkL0R+LJqzLdDvT
         Gvuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lSb0Xjst;
       spf=pass (google.com: domain of 3nwqwyqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nwqWYQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c2si846953wmq.2.2021.11.18.00.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nwqwyqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n41-20020a05600c502900b003335ab97f41so2729920wmr.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:11 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:1e27:: with SMTP id
 ay39mr7793632wmb.84.1637223071430; Thu, 18 Nov 2021 00:11:11 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:10 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-7-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 06/23] kcsan, kbuild: Add option for barrier
 instrumentation only
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lSb0Xjst;       spf=pass
 (google.com: domain of 3nwqwyqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nwqWYQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Source files that disable KCSAN via KCSAN_SANITIZE := n, remove all
instrumentation, including explicit barrier instrumentation. With
instrumentation for memory barriers, in few places it is required to
enable just the explicit instrumentation for memory barriers to avoid
false positives.

Providing the Makefile variable KCSAN_INSTRUMENT_BARRIERS_obj.o or
KCSAN_INSTRUMENT_BARRIERS (for all files) set to 'y' only enables the
explicit barrier instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.lib | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index d1f865b8c0cb..ab17f7b2e33c 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -182,6 +182,11 @@ ifeq ($(CONFIG_KCSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCSAN_SANITIZE_$(basetarget).o)$(KCSAN_SANITIZE)y), \
 	$(CFLAGS_KCSAN))
+# Some uninstrumented files provide implied barriers required to avoid false
+# positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
+_c_flags += $(if $(patsubst n%,, \
+	$(KCSAN_INSTRUMENT_BARRIERS_$(basetarget).o)$(KCSAN_INSTRUMENT_BARRIERS)n), \
+	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
 # $(srctree)/$(src) for including checkin headers from generated source files
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-7-elver%40google.com.

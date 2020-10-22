Return-Path: <kasan-dev+bncBC7OBJGL2MHBB57BYX6AKGQEGZIX2CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 42CF4295DAE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 13:46:00 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id i6sf518160wrx.11
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 04:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603367160; cv=pass;
        d=google.com; s=arc-20160816;
        b=bu9AnQALQDsr9swAlzZYQIm7XEs0c1aYEjSBkEQp8DgFc6/VZn8rSCLYtXhReaHgEa
         M9i2Ws33Wm5F1SEqwUg/DoA65rjaXFtandXftyzfHJNi7EpvwHy4rWpJWT3o2/c/a+b/
         x2kX93I0JDU8zywyBYzf7sRQOkj2PWhRDv9e4tmU4uxrnTdHZsscqOnpuvcIT+5K24dh
         X3UATCs/BE2IRxrC+cUPA8mAz5cOPyasWXF8yOxrsbyqQt8u/lNI51Z7GjZvTYEPO3sm
         td0g8DAZMCoiGKlC3S0BOu+3HDAqZGzoGjQziYSfuktevrbu7KcrAMNe5qvmtlT23cuu
         wyiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LvM+fafOO6JntQS9cALdmuAXGHUVGDd8D4WeXELIHsY=;
        b=nj5DUvRNIQrezdq9ARVKapLd3LLhxjugVGeB8EF9Bu//y/CXBX+EuIi70ONKU9ujq/
         h1GA76Jdg5cvpzgCT2vN3x5tDMOHVxBe2Z4LgMTyD9ZnDHLj4pe9EOFvP2OaId/OdPmb
         P7XrCZ6P/1TW2reu9lt0iN0/0zC+vqMhJZo9VmppWWBc8LpV69lzTU7LQuSbh2KVkrTd
         V7gLCCQyiJmqIdYcOlshSfedgK2BHUnaKHnR29hC8YWXEABbax1nwsfi0Ock9a3WGQLf
         4sgI0pHPG21zqwm2XCNhoTmYNfXoCLiUNuCpBxcyfilSZNgKH7RQLNR6TkK/dtIuWYsM
         dODw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPOv1QmJ;
       spf=pass (google.com: domain of 39ncrxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39nCRXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LvM+fafOO6JntQS9cALdmuAXGHUVGDd8D4WeXELIHsY=;
        b=mJPTF5VcPqlcwnws486nu4r7C/yXy81qU8QoUzSWOoMYHvY64Tmi+RpgLjQnVRccej
         8W4sPnAkLZQDIhWPYFvhPUmjOlFEy1oyqTt6OsA2ixHt3tqukBHTng9UwevXFpoKQZBq
         NuxZj6qZktiusmrZCpMoRswe1zMCX/OVXPZ5ZIkw++uQb3lM5oGiQ0mpmq0qBmPVwYU6
         up5/Vu5H+3u+kf6e4k4TTuaQ0LdCYYs+iz+E8MYCVjJp7Z0w/Y0O7LZUEnNgtnYa1bSM
         /IKKn1wNHZZWbmwPFWhjIeKWvuIvKpcNMzlLsVwkOVTwG4Y/NofjS57wZFgMNaxXpWIy
         d1Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LvM+fafOO6JntQS9cALdmuAXGHUVGDd8D4WeXELIHsY=;
        b=q7v0gfX96KnxPlWNOqWbQ47dfjjFhS80N7mldSLYzcCH+Qv6AzxU4mYZ9rFWgrAuR3
         RtWCGqYRmHSujQSeTMMErFUgBsHoloB2Ia/xMNCLiXDwZfDWCSyoWJMLB/+RkZnKLAAt
         Xdokp52Fz/HHYl8+uxU0euWu8rZBYKeqqQRBA+ysW0+0HLTK4auS464NMlqPGJajFebb
         SVzcYWRDKGkjvoMI/Mz+jXn4vswGghrTl3cUUmrTbeqQsVQ0uRkvbbUGXoJKfxKqU2fg
         jF+NDzxCQhD82d+qz4X+ONyxQhAbCGwO5uKmxI9Q4HviQGu50TV4BNoXkgEkWHditpou
         AQJg==
X-Gm-Message-State: AOAM530Cx6aRr1PwrM8wTVqNmG48SF1jOMO/1lB+AVGxa4thSaEIF+Yo
	KJGg4fw5gXDhp3OhHwUfnm4=
X-Google-Smtp-Source: ABdhPJwYfe9fhNrN/7gU19HdJGNPUNThBVuPNVuzO8mZh/8AJ2NBVY7bxJVw3acQ+QK4busFSOOo5Q==
X-Received: by 2002:a1c:ab0b:: with SMTP id u11mr2209262wme.165.1603367159883;
        Thu, 22 Oct 2020 04:45:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:208a:: with SMTP id g132ls841680wmg.1.gmail; Thu, 22 Oct
 2020 04:45:59 -0700 (PDT)
X-Received: by 2002:a1c:4d13:: with SMTP id o19mr2288239wmh.185.1603367158960;
        Thu, 22 Oct 2020 04:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603367158; cv=none;
        d=google.com; s=arc-20160816;
        b=GsmAUer9rPvriB/o8lShb0RxGrFsQxgD4PyiHH1lab6iCSNIh8uJzxjd27UqJFTZZA
         XyGkTJntyt9RHouU6vmGVvKFrq1Pm/P4/23L3geF/0Q0hit7vywwDvH8y5IJlpjQo36o
         OJ3e+V8jtGFTM6Zait6tsRWCiOcxw7gdhIt9RzVsTcR6GScO49AFKICVwZsfP2qe/WWJ
         TBpUvuEaGUIjgQb3d0lsXs/p/OV0sYVe+pNE4iXhXAh1OhDMA3IAu7eHVUcgyo1NKEIs
         WbDtMy6qYkx7Ls9fAQwSXYLoQU7gb6E/bdixMRG7nLRhQcb1sL9JnGtrs4RdFxaXuckb
         dvhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=g50aig4WnJQhcCcuXsue/eYMQH3ofUeze+geEk++93U=;
        b=D/MBNgYkv8DSlRYyc3AKR/Ra23vSsEA+OGzIUbx2ShRBBGZX/NcB/KdVw7OIlx9q9b
         EEc0jH54FBUA/t/D/r80xmiyEr25KQkOiwpm4CDeI6B58kFposH/lUVqxBEsVb8oAgiH
         mQGulirOOCs+2jO6gwYNwQ5tMTMHwFenO+W4o0F/ew07G7klNd+jylpay7/Lw5tbdEm7
         5xlenWX4fC2hxWvsu7LcetDUCLAxc1B0p4AGobb1a9OTcYLLLRPC0SLMHN8qhSB9V7WU
         73Aoj2A2xmih88F2nDgDBrgWZAKjr+GhpNkGSRERvt0l9UbtAU2cN9Jr1bGd2S99kiUF
         fOUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPOv1QmJ;
       spf=pass (google.com: domain of 39ncrxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39nCRXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 11si45715wmg.0.2020.10.22.04.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 04:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ncrxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id r7so333370wmr.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 04:45:58 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:6551:: with SMTP id z17mr2295237wrv.266.1603367158475;
 Thu, 22 Oct 2020 04:45:58 -0700 (PDT)
Date: Thu, 22 Oct 2020 13:45:53 +0200
In-Reply-To: <20201022114553.2440135-1-elver@google.com>
Message-Id: <20201022114553.2440135-2-elver@google.com>
Mime-Version: 1.0
References: <20201022114553.2440135-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH v2 2/2] kcsan: Never set up watchpoints on NULL pointers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bPOv1QmJ;       spf=pass
 (google.com: domain of 39ncrxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39nCRXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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

Avoid setting up watchpoints on NULL pointers, as otherwise we would
crash inside the KCSAN runtime (when checking for value changes) instead
of the instrumented code.

Because that may be confusing, skip any address less than PAGE_SIZE.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/encoding.h | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index f03562aaf2eb..64b3c0f2a685 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -48,7 +48,11 @@
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-	return size <= MAX_ENCODABLE_SIZE;
+	/*
+	 * While we can encode addrs<PAGE_SIZE, avoid crashing with a NULL
+	 * pointer deref inside KCSAN.
+	 */
+	return addr >= PAGE_SIZE && size <= MAX_ENCODABLE_SIZE;
 }
 
 static inline long
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201022114553.2440135-2-elver%40google.com.

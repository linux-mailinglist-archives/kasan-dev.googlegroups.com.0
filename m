Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJUI4XZAKGQEJLH5KTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 80126173D6A
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 17:47:35 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id 2sf2009485plb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 08:47:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582908454; cv=pass;
        d=google.com; s=arc-20160816;
        b=w82hEU8n84tylVpoDSgZqoMkfAFOd9UMs95qek/8QJIebGV/nK095ptZzgM1z4xfZX
         cu7Mkc/CnNWB3JXAE6NYRV240DBrdE9loetXsFT7wZKdJ+SoTDMPwhPzZDNi09yg3KUL
         XJU+/AG/fGy4GJX+Kv7QM9DrR3IqNQfg8Q58MygOttS2SLxuEmyTaCFX60rsDZSb97pY
         a0MK4jr65DXdcMfFljOvJ9Y5ITnO5qwzIGGshJmvuuaSr32kVovCOlG2DDb7xSwuVWWD
         z04Xnyxcw/NLFfGSPy1gwA3K9Bessufxs+pRR/LPqlduQap4rDIaz02Y+QnZt4IjLY6b
         vPJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9APNEZcs4U6crkVDYoGNmRa/GVyjogWbQT3rBcVTKaM=;
        b=whKOA707KmCK8n9QHg/yHj4fM/FmIF8exP0MS0I5xGZWgCNF/JLeofX5TTpJr21wrr
         nWhOJlVkMu/hnCu0buU0Lr/t3Ktx10PGc3s53kjMIA5o9rmND3rxNonS1WZkjptzpL8e
         dqq2tzQFUEiR51sk8k8ejXmvVm0nViluz4IC6V4TxxXc5eW7OeXgSgWcMHsCWkiGA/as
         UtnOdYU2RqWIf9pkep2lt6KYpfo6PIWhyRZzvoSwdWcQKdkGuJkrmiR2gG0KWyntCtRT
         yqzLbOi7dZMFW5Rl3/GAOAd9/L2PlO4sr+9kRYRWShG4cSbXqKhZuQUr2OlznKwkqcN8
         CkGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oKHI60QZ;
       spf=pass (google.com: domain of 3jerzxgukcqspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3JERZXgUKCQspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9APNEZcs4U6crkVDYoGNmRa/GVyjogWbQT3rBcVTKaM=;
        b=ocTQWPrPz+JC8HEAVyTOXt24p0Fq3Sw4VWGITgrTVJ+d+NY8A5cMHt5pvBrMZy1uOk
         3Fvs9I2xJvRZuDLGhmXXN8B/ZWKhhAYfTLAdihvgDrB94z37+AIoreK7ppFWYoWscUtf
         eRoRDef43j0/kMNua/22snoGBq2FaoVFrvw2VGIzbpq/wWq/m6GPby6j5cMSlm1rm6ds
         Jdilr7yjZWyml0gROqhJ+YjmllysPzIWTlQmwpaY2hGPonmOiakX6UR3DzzvLj7uAwxk
         u07PyeCqwIIvDcueZwt3GcB1+utU8WUFOhlkmTlReNFvgWgYkLNKu6GC1Y20J8WTauG6
         pQrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9APNEZcs4U6crkVDYoGNmRa/GVyjogWbQT3rBcVTKaM=;
        b=MohkqS6Aw9xaXsr0a2/YVyxALtuHLkGsaaYEDZKcC52EuTcyCYFiy6dKe0VKd2fya9
         MNA3+nLjUdbIhTTwIEhgOmvOwXC31r8LklMIbaSwjUX4bur+7b14HFjDPm6daIrHaL+c
         Dq42dUh2Z23ifiy9yG5f4YZVEAxDTk/rM8VXn4JFKWhzcuvztXNNHQkFJsEBCKd7zgGs
         l+UIWCU8F+9TjKV2hDNZ5M7JvZjHo66mtE/wtB2yXsyu0HivcGLfOvxkbzp9Q4tQ48J3
         zmN7LQeknAgx12F8ZqpFM/KtTW8diqrTQ9WZdj3/QWvgM8v/pFzY+gm0lzVMeLSULr0d
         DErQ==
X-Gm-Message-State: APjAAAV69JYH6wxG9PLONwqhDxfD3PLh9Wjk/bf5bdw5nIl2MjS+MjfW
	T5FuUZ3B72tcBP+vP1oXOjg=
X-Google-Smtp-Source: APXvYqxkoj3c/QvfkMVvnDrhALbAGplgLFadzb6mJKJiApojsffkwyFOfs+bHm3GnupUIfqPNKXPDA==
X-Received: by 2002:a17:902:7009:: with SMTP id y9mr4934136plk.254.1582908454203;
        Fri, 28 Feb 2020 08:47:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d70b:: with SMTP id w11ls1151227ply.11.gmail; Fri,
 28 Feb 2020 08:47:33 -0800 (PST)
X-Received: by 2002:a17:902:a414:: with SMTP id p20mr5040323plq.7.1582908453683;
        Fri, 28 Feb 2020 08:47:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582908453; cv=none;
        d=google.com; s=arc-20160816;
        b=vWK8mGumjtE5kAm8Df/7W7AWDBSV87LuLTd15G21jnNwDB+VxEXQMXS0+OYTyDadyK
         EeKNvl4M+A1UoHmR68Y9zjT6X8hjLW2qEugHnPgtchgdoIrBNzzpLyH2ByR2HTd+66m4
         c/cYeYPLIKA3IXn28mQIkSYMmxOhNKH6VKURFBLYTR64bGL8oP+PFna+U4mdu5xaVggl
         JPxwrOWs6YQ17xe1aZhQtC25F4thfJAXIG7ov4fCrEIrA+A2+BcFEvlK/9+nn5ot2aDJ
         FaydV1CJZZxdjElefCTtXi/p0rZ3R1JScHjYuGzXuq5X/wEqbKquyuoVdIUeQmZkOTvD
         ypjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=BnK1UC8c2/CTg4QSSZm4VfbP+eP/ZMTQTgyW0tFmuUo=;
        b=TWToMOkgZuW7ik5DEmB3NRXZsetwI6qKLksMoGWXndIJ6026DgSHVVGmizAGepRLno
         MEGPaKrsBEG08pw2gTDhVfGK9RClcnNz+HMQxhpXg5WtIMq9sPiaN1VimbmV6HcCUgXQ
         LXzwnJtifj7LqtG2S+2FLwDy+bfSeRM3Nm2Rb6fYmLBQYzfqXTmFalPhwD0VFoWMJjpJ
         nu2thKxbNpFiMwQ+8/mpmoMGbqtdgC7NkFkM+3Cw3SArzKqI7nQDa3ZdJG70OmXeQFkV
         MQqKDqo5jDJ1D1IYSirZymrdb6wN8ctHBCkdziRsu9YysUe4rWKTCc9aph29/oFXEjKq
         Ua9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oKHI60QZ;
       spf=pass (google.com: domain of 3jerzxgukcqspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3JERZXgUKCQspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h2si553829pju.2.2020.02.28.08.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 08:47:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jerzxgukcqspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id n130so3321332qke.19
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 08:47:33 -0800 (PST)
X-Received: by 2002:ad4:580e:: with SMTP id dd14mr4596272qvb.84.1582908452572;
 Fri, 28 Feb 2020 08:47:32 -0800 (PST)
Date: Fri, 28 Feb 2020 17:46:21 +0100
Message-Id: <20200228164621.87523-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.1.481.gfbce0eb801-goog
Subject: [PATCH] tools/memory-model/Documentation: Fix "conflict" definition
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	stern@rowland.harvard.edu, parri.andrea@gmail.com, will@kernel.org, 
	peterz@infradead.org, boqun.feng@gmail.com, npiggin@gmail.com, 
	dhowells@redhat.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr, 
	akiyks@gmail.com, dlustig@nvidia.com, joel@joelfernandes.org, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oKHI60QZ;       spf=pass
 (google.com: domain of 3jerzxgukcqspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3JERZXgUKCQspw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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

For language-level memory consistency models that are adaptations of
data-race-free, the definition of "data race" can be summarized as
"concurrent conflicting accesses, where at least one is non-sync/plain".

The definition of "conflict" should not include the type of access nor
whether the accesses are concurrent or not, which this patch addresses
for explanation.txt.

The definition of "data race" remains unchanged, but the informal
definition for "conflict" is restored to what can be found in the
literature.

Signed-by: Marco Elver <elver@google.com>
---
 tools/memory-model/Documentation/explanation.txt | 15 ++++++---------
 1 file changed, 6 insertions(+), 9 deletions(-)

diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
index e91a2eb19592a..11cf89b5b85d9 100644
--- a/tools/memory-model/Documentation/explanation.txt
+++ b/tools/memory-model/Documentation/explanation.txt
@@ -1986,18 +1986,15 @@ violates the compiler's assumptions, which would render the ultimate
 outcome undefined.
 
 In technical terms, the compiler is allowed to assume that when the
-program executes, there will not be any data races.  A "data race"
-occurs when two conflicting memory accesses execute concurrently;
-two memory accesses "conflict" if:
+program executes, there will not be any data races. A "data race"
+occurs if:
 
-	they access the same location,
+	two concurrent memory accesses "conflict";
 
-	they occur on different CPUs (or in different threads on the
-	same CPU),
+	and at least one of the accesses is a plain access;
 
-	at least one of them is a plain access,
-
-	and at least one of them is a store.
+	where two memory accesses "conflict" if they access the same
+	memory location, and at least one performs a write;
 
 The LKMM tries to determine whether a program contains two conflicting
 accesses which may execute concurrently; if it does then the LKMM says
-- 
2.25.1.481.gfbce0eb801-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200228164621.87523-1-elver%40google.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFF2UXFAMGQEUDCYNSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D960CD6749
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 16:00:38 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5959d533486sf2931229e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 07:00:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766415637; cv=pass;
        d=google.com; s=arc-20240605;
        b=YqyxMGkorOjwHyszX0gpZMN0dwkN/1WpSabbGPvKNHsOYb1yGqGJoDNvCr+RSFnuih
         kuN0CDIQ9HegMco0UnUTduGM4b9tDswu4iaPIyQEetvDpbfHBhSc75Ciahu77RbX+skW
         7i0+fBVBQsL66YIBGoBGF2+Nte3BFB+RCcSGh/8RcgqoVkJAsbs1WVqU/KRL9mel/1je
         KJF7io68sRKXyDJ6/KuEPLprYqcN9NdlNTKBiISuGYzzE/8JwhP8Fwa0/ts19Bo0J42I
         109I7PfGFNGDGAfyJA4L8De27MccBN9ms4fqG1U6qkT8vI0yJ9yn2d6+SgwL1bvZ9yM9
         kTlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=oFuArCbsDDeunzEqR7GD1nglfEvbqFAWac9mM3QeGFs=;
        fh=o9+HNTT4TxcAFghhe5qz3rbxNdySxOV/7ma7bt3Zffo=;
        b=aHs2XCAYafEuX7TOXTHlSBT3RCVHc2J3y4RW8yp+uM369GPOn2fgjMTxsADiy2m3az
         LNvyAtqsdLYgcxRlAgqfly5veMeoZvZs4GM5bRioBWm3jjZqQDQLHabCXCVS3z8OF4up
         0MSg+0/zcHGe9xpocXTvtTnuHLwej6z9gK2VFSZbwjemp0HVZfgQXOifohhxrrKsPYF5
         /ItylBAeY+rkmCbRs+6PiVkNMlHxOH4gdOQ6Z90sCItPCB8OhmGaZgCGJYV9dAfoqPyL
         2HQV0A6MQwF/E0GVvdfzfGocASPP7szGn6gnDWXClQ2dLjeWaDqq++gA+yXo8yZ9jpMf
         CXQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=InvtYTMc;
       spf=pass (google.com: domain of 3ev1jaqukcuiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EV1JaQUKCUIipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766415637; x=1767020437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oFuArCbsDDeunzEqR7GD1nglfEvbqFAWac9mM3QeGFs=;
        b=uBL8WlKXiGi7w3+3HrWY26lk+qLmpU3MKJpmznzz2ggcS+3RIIYRK1OXVPb3bfKC+F
         jaP1wAtSvHLd9UlQFH/Rx73TrMgLn0L4koHlEY6wGblTPCVpdaGl17g9FYT9a1lmGGnB
         K5UsxQb9XnrvgQXGrT+rgDvhbp6fepUUZY9NRm7kVQ1e0RxxlaJNsRGNo9jJv0FCeX8n
         Fp/P/RDZqh0eQYiW1UFWYTktz5KxPb+YLAQYKPSuQ74pU2lt42Jx4mihrFvDk6MawKu9
         LeYeWsUi7WPieII/sUteYv9RGVErUqdCGwrmDKnUWz+eGca9ejpZNhe4Vw1FNB8ao8Rb
         Zr0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766415637; x=1767020437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oFuArCbsDDeunzEqR7GD1nglfEvbqFAWac9mM3QeGFs=;
        b=JhTcWat3WXw/d+T2gteUJoOonAXW+3TWFC3+5a1ZbtMmXjUY+0wKZT6WSPpffwB6Dv
         7me9Sudc32HBQMOQkYWQ6WXgUDbgMSmvE20anO8g10JXWrheJBQl+vP0tiO7SyZSs8RV
         65qkMOZ2syG4w63UL1lS6am7mPV1GV8W4WrD/90l39iL4/uA9I1l5bXyBmlqu5ooTz2H
         jRla6XRrJuCySvRQOamJSn6meyVUBPhRdqY5l6J/p8vxckX0Gt3b0YfgUamFsz3Z8jtt
         iW4GYoYAJQ43iknTZ21CJdNmJcvKgUX5WYullyvULizWMPup82ZUHLzrtsJWxPcr6XN/
         ncYQ==
X-Forwarded-Encrypted: i=2; AJvYcCX86HY31PUTEjmYZxctDAGqAzMD8R8eOa+3jogfjoP6qStCehuyq/6e8xsELRhvVJld2nQl+A==@lfdr.de
X-Gm-Message-State: AOJu0YxSurjjNMHcNZWcR8dw5XhIp/uVEW/ACrXZdEVlotH8ai58oYPw
	56cgjMquEHlzCia5bSl98w2wn+9pYRoN1gAuYj0ayHxt+TKTThNycU5/
X-Google-Smtp-Source: AGHT+IHi33CIkvzEKDWAq7wg8hv9xM4Do56dA0yikqdISZzsP00jGVMpNh6b/VY3aleJqgJsyDh2Vg==
X-Received: by 2002:a05:6512:4006:b0:594:248d:afa7 with SMTP id 2adb3069b0e04-59a17d58ee3mr3997935e87.13.1766415637010;
        Mon, 22 Dec 2025 07:00:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZnAlqzGso6o4ZVNVmaKrM/sJI3evEGMvRG8FFPCDqczw=="
Received: by 2002:a05:6512:1113:b0:598:f445:11e4 with SMTP id
 2adb3069b0e04-598fa405c7cls1056763e87.2.-pod-prod-06-eu; Mon, 22 Dec 2025
 07:00:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2ykWb/xTVXqy0rOPPsKefXY8dqqW1mz8H0b9+eJ0Joy9DgSmiCbtMZsvYqHeTDK5WvYMKoCYbapU=@googlegroups.com
X-Received: by 2002:a05:6512:3c9e:b0:595:9d6b:1175 with SMTP id 2adb3069b0e04-59a17d5905dmr4231991e87.14.1766415633919;
        Mon, 22 Dec 2025 07:00:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766415633; cv=none;
        d=google.com; s=arc-20240605;
        b=bRdZYWIcRCnA4VyKAaWxs528cHvjPBahJp3hoJjMFJ94zGvYEts3yKN15USPvknocv
         zIghn3DQ/k7RQ37ILtcCRv8VGx7/fmdBnuj6P2qkeKhrcR3Gu4coKu1Z3/qCOXMqEAmS
         VAHDBwUeTcI/3mhI5/wThRAllG+VPZpQl5z9G2yOWhCRyKnDQyLxAxnqfgMVLw8E+kOF
         wPLB7PtH350qPU5u54khGLzydZsvwdBblw+RB0IVjxIYn32oRtVxJxPfgNfuWJZKZNpS
         AP3qdoeCJa8/Ak3T5O5TVrW/aG2adcVo3OrSy8OjP5yRK/U0HLOiixdpkKzKC8y8Gnda
         jIXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=SLecpNCzVXawwP8cx0xrGTVH2kk35JOIvedfHtD8OOw=;
        fh=FNWSLXKidKpTXFwoqVPpp++E7modzozwBd0gkS2jLak=;
        b=cgOYez8Zre8Igsj6DU0W4yQOUkosXQitQ5McsmFaYY/lk72a1QT8tulUIxTzarUh0S
         wodKq8iyEPm20gPXfyzGBkvOLeT2woG3bZAbCT2W5Lf0lt6GyuNYFahdJ8HNZlNhQ83T
         czFbx+YKFKYkOl/BW5/sbE5fRz64sEQVE3hSqRgc3KAss/0dX8whCXa2yqlxLeOhv06j
         IOi3f0+Sisbk4zeMkZd2X7X0NeWWy8TITbdAweDJnDDu2o45M6PLbSHWhtBsDQEH98CQ
         nwbDigb6tM+UYWuXU0NSEdPK5tm/VV/9oxU4H81fW8+jucSmq12BWWjT1sJ1KpF4sOmm
         AGBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=InvtYTMc;
       spf=pass (google.com: domain of 3ev1jaqukcuiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EV1JaQUKCUIipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860cf52si216268e87.3.2025.12.22.07.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Dec 2025 07:00:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ev1jaqukcuiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-430fc83f58dso2319956f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 07:00:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXdPBE587EeHJ0dHtkGFc3WzjYgBNHYJHr1XEGLbBEkM8yJ7uves+DQ/hQOrteZ0gU1XfVQCWMN524=@googlegroups.com
X-Received: from wmco23.prod.google.com ([2002:a05:600c:a317:b0:477:93dd:bbb1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:46c4:b0:477:7bd2:693f
 with SMTP id 5b1f17b1804b1-47d1953b80bmr128913385e9.6.1766415633343; Mon, 22
 Dec 2025 07:00:33 -0800 (PST)
Date: Mon, 22 Dec 2025 16:00:06 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251222150018.1349672-1-elver@google.com>
Subject: [PATCH] docs: kernel-parameters: add kfence parameters
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=InvtYTMc;       spf=pass
 (google.com: domain of 3ev1jaqukcuiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EV1JaQUKCUIipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add a brief summary for KFENCE's kernel command-line parameters in
admin-guide/kernel-parameters.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../admin-guide/kernel-parameters.txt         | 35 +++++++++++++++++++
 1 file changed, 35 insertions(+)

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index a8d0afde7f85..1058f2a6d6a8 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -2917,6 +2917,41 @@ Kernel parameters
 			for Movable pages.  "nn[KMGTPE]", "nn%", and "mirror"
 			are exclusive, so you cannot specify multiple forms.
 
+	kfence.burst=	[MM,KFENCE] The number of additional successive
+			allocations to be attempted through KFENCE for each
+			sample interval.
+			Format: <unsigned integer>
+			Default: 0
+
+	kfence.check_on_panic=
+			[MM,KFENCE] Whether to check all KFENCE-managed objects'
+			canaries on panic.
+			Format: <bool>
+			Default: false
+
+	kfence.deferrable=
+			[MM,KFENCE] Whether to use a deferrable timer to trigger
+			allocations. This avoids forcing CPU wake-ups if the
+			system is idle, at the risk of a less predictable
+			sample interval.
+			Format: <bool>
+			Default: CONFIG_KFENCE_DEFERRABLE
+
+	kfence.sample_interval=
+			[MM,KFENCE] KFENCE's sample interval in milliseconds.
+			Format: <unsigned integer>
+			 0 - Disable KFENCE.
+			>0 - Enabled KFENCE with given sample interval.
+			Default: CONFIG_KFENCE_SAMPLE_INTERVAL
+
+	kfence.skip_covered_thresh=
+			[MM,KFENCE] If pool utilization reaches this threshold
+			(pool usage%), KFENCE limits currently covered
+			allocations of the same source from further filling
+			up the pool.
+			Format: <unsigned integer>
+			Default: 75
+
 	kgdbdbgp=	[KGDB,HW,EARLY] kgdb over EHCI usb debug port.
 			Format: <Controller#>[,poll interval]
 			The controller # is the number of the ehci usb debug
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251222150018.1349672-1-elver%40google.com.

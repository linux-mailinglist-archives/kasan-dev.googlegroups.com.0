Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWEVS6QAMGQEWEG7CAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC036ABDEB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Mar 2023 12:13:29 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f8-20020a056512360800b004b8825890a1sf2619858lfs.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Mar 2023 03:13:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678101209; cv=pass;
        d=google.com; s=arc-20160816;
        b=hi9YfkMaMlokHeQkFdkJdEUgiNYTRAN42UqtzShOsxKREdC1xX1YcED7D1vTM+lVus
         42gR6PhLWLtrfrx1RCr1IeWNdmvaENZx9zxdI/wjhkWQBeim4MfZnPafXZHC0+SutVPt
         O+2K5/kkb/jv3rymcspsiFrZzrTC1iNJOyiALYOkI5wNrdWoJn8koim4YTcPROq0EoIf
         1Ptt/31FHZOcupAOEbpUSYWtukHKhx/so2quJOaQdOqCkvgGaibr2a6An5R6oJ9TEEaE
         4N/jiZUGeRPqY0MBrtoDOoQ64snK6CwTS7imGG0ehxe06gtzLqbuuBnyQHpGgEG4YUAB
         aHiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=iYLSzL10OLydBT/Dl3wuNvNyNUJWKPwHPQgFHjy0Ahs=;
        b=j5M+EKJvNSVDTg/kv6I6lYEUiQu37+l3OfypCG6tIrCiCBY26pkIJ/T5VSq2IdXn+g
         ax5dLptfRboPmPOfZJdnU320OMurNC7f33Tt4JmbyLLrTyVrcKpE3ZoIKN7eZdxBDc6C
         2Fvig77WxuA/0wcYnZy+61pKXJdfC/xwNltAPTYAtgdAAwzFh54h/YPRbO0h18AaGo27
         m9SAwVUgjJItTvghHek9uuqlHqK+B19ichdGz/Ff9Re2Eom8rWJu6a+JCShTSad9Jx2P
         2l0W3HgI+BPxLwQ6NWbQjSVBpsx3ftFI7vjDO5l+GN8iZA55zPdgYZUEShvutLrJWf0+
         VjfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GQwsOOCw;
       spf=pass (google.com: domain of 31sofzaykcakpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31soFZAYKCakPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678101209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iYLSzL10OLydBT/Dl3wuNvNyNUJWKPwHPQgFHjy0Ahs=;
        b=cE7v6NwVzNnIKTTxN11Q1LA0ZRqXyu2ie2LN5unLkJrH7ttwQ44dIMY5in/Kdx1qrr
         pddCxrcpPGn90QRiiEuE36y9WqnFo+G7AA2eYQOCp8wPEXYZM72KrVHttiNFeTTVeK2o
         bQ6xXFA/Oo5Udjag8gY3gYNZbnhn5eLKEI0x+5io3dhtf7i+BeO1ZqhHb5r9OkDPftq/
         yR9qkM21YXHPs3Qp7I2QYDlRGdcSY6XPkYNeOMc0C/nRgLIwHWvyXWZkj8KJGdp1ifSP
         +H80AMI4z1qDhaSHhaFb0sDp4hEFGumpFJFh2lUBdNNLMQpnEwocsf927UlLMm9kmD+9
         LMMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678101209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iYLSzL10OLydBT/Dl3wuNvNyNUJWKPwHPQgFHjy0Ahs=;
        b=W9QgigqaQKWPcj7bqsodjQQTnSNKgD1aVZo6nxZ7U7nCcKPVYdDPFxkB8PCTDITIDX
         5R532jO+2YSeb5kxggW+n7WtqPDcjA06MVhhH0lhOLFANSfZSAvm1BnMmA+jf/edy8oP
         O45AZ5JbG+qX1QM9N1CmHEqZNRoZMz48H7GyZtMCKhE1nkYZZeaghi4nZmCgPPnPs3Y+
         6NtEfH/GVUxXF6cxFTP3A8EAqihqtK8AZgAM0C4RuH7TMxA1YSyAH2uKjFyelq015Q2m
         0Bi1h3QD1rMqcd2465uqsIEQpSFMZQVRMsHmgCFNb/0DaApbcepUYcoa5CdVh64EJogS
         RjmQ==
X-Gm-Message-State: AO0yUKV3+clawbCLLKxn4Vtdnb8CRdFKlNanr9uJZMCMze/2N3kcru5m
	Oo6lNyHxnrsH7kyfTPPuAp4=
X-Google-Smtp-Source: AK7set9TVRaDGnSgMGyv2jtkoKxQCH8vXEmG8Rayh7Ffnt89kQA+bdRAtfct8+gu7ajGIb7ryCbT+Q==
X-Received: by 2002:ac2:5689:0:b0:4db:1a0d:f270 with SMTP id 9-20020ac25689000000b004db1a0df270mr3041292lfr.0.1678101208552;
        Mon, 06 Mar 2023 03:13:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1610:b0:293:12a9:1ca5 with SMTP id
 f16-20020a05651c161000b0029312a91ca5ls1583766ljq.6.-pod-prod-gmail; Mon, 06
 Mar 2023 03:13:27 -0800 (PST)
X-Received: by 2002:a2e:b163:0:b0:295:a5d9:d0a1 with SMTP id a3-20020a2eb163000000b00295a5d9d0a1mr2771757ljm.50.1678101207023;
        Mon, 06 Mar 2023 03:13:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678101207; cv=none;
        d=google.com; s=arc-20160816;
        b=NLUEl1Pzv0IRJ3AlP5PTYTDEi5W6XAFGYVLSO2BdfeHM8tKkIzEwcJO7m7OvBLCHAR
         8+tLHacUAR19yVhX/Wg3UxsNuJ1jF3HzGVqgJI7jyVayHnshmv2L5/QXqxo7PhUkMj/4
         kgtqhpvTeLRrcLDizoz6r9/bT3kU+zm0ca7SpOcZ8nAohSzcEWTgAGI+n57tMefN8TBh
         t4fxGkIZnLYVnG4JPMdJT1q+uNdXEYqBEgwHsHh0gOJxhXAIZ1ad6FIJzqFqgBYB6wvk
         Qhml+TELqOn2E/xCNpsLwn3oErtZiOlW199puJpeGnXVu349ENygOCqrN6roGs5Sbr3x
         Rh6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=1YDcalZhdE7jkjuSChjdb8BwAiaOVabLcoERtRrllCw=;
        b=bxEbQJ5ijRiVLqeH5rNd1hIGkBKH22+ugPrR6mPVmtCQHIBRBmrzNq4ycpWcUeasoa
         3Pp8uvtNDqCyNFm582qImVqMAw1hFSzlLQdGlx96+sqH5J6j29x3xVMRGLXVMvuFObKm
         J/Dz8TKeyiPOAk42d1tvxqEA8ImjZ4gsfEmjoMu5BozXem0fxhPWJadyyqWoDdIVmZjS
         4fLyULDVxVHBW+NN9m33UH6QoA6AvKsOLy6XNxqviLBOAN+o9DbDu1ZNwTm18NDNkaD+
         FVqrYIMcOWT4oa/zExprq4Td0nEkCYmbB/gary7fnqF439lQbva7GG9kdOM+yQzK29tj
         FwqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GQwsOOCw;
       spf=pass (google.com: domain of 31sofzaykcakpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31soFZAYKCakPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id h13-20020a05651c158d00b002959fe5ccd9si363828ljq.5.2023.03.06.03.13.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Mar 2023 03:13:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 31sofzaykcakpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id k12-20020a50c8cc000000b004accf30f6d3so13330892edh.14
        for <kasan-dev@googlegroups.com>; Mon, 06 Mar 2023 03:13:26 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b93a:5d85:6f2c:517d])
 (user=glider job=sendgmr) by 2002:a17:906:ce38:b0:8b1:30da:b585 with SMTP id
 sd24-20020a170906ce3800b008b130dab585mr4991214ejb.6.1678101206445; Mon, 06
 Mar 2023 03:13:26 -0800 (PST)
Date: Mon,  6 Mar 2023 12:13:21 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230306111322.205724-1-glider@google.com>
Subject: [PATCH 1/2] lib/stackdepot: kmsan: mark API outputs as initialized
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GQwsOOCw;       spf=pass
 (google.com: domain of 31sofzaykcakpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31soFZAYKCakPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN does not instrument stackdepot and may treat memory allocated by
it as uninitialized. This is not a problem for KMSAN itself, because its
functions calling stackdepot API are also not instrumented.
But other kernel features (e.g. netdev tracker) may access stack depot
from instrumented code, which will lead to false positives, unless we
explicitly mark stackdepot outputs as initialized.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 lib/stackdepot.c | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 036da8e295d19..2f5aa851834eb 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -17,6 +17,7 @@
 #include <linux/gfp.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
+#include <linux/kmsan.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
 #include <linux/percpu.h>
@@ -306,6 +307,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
+	/*
+	 * Let KMSAN know the stored stack record is initialized. This shall
+	 * prevent false positive reports if instrumented code accesses it.
+	 */
+	kmsan_unpoison_memory(stack, required_size);
 
 	return stack;
 }
@@ -465,6 +471,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	struct stack_record *stack;
 
 	*entries = NULL;
+	/*
+	 * Let KMSAN know *entries is initialized. This shall prevent false
+	 * positive reports if instrumented code accesses it.
+	 */
+	kmsan_unpoison_memory(entries, sizeof(*entries));
+
 	if (!handle)
 		return 0;
 
-- 
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230306111322.205724-1-glider%40google.com.

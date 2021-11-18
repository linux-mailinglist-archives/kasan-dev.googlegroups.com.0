Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ4V3CGAMGQEQZ56DUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D7D345568D
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:48 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id q17-20020adff791000000b00183e734ba48sf876473wrp.8
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223108; cv=pass;
        d=google.com; s=arc-20160816;
        b=plFfgvDaPdi+7GXDTpVdJyRArTsBSWUmgRtdvU0reFXj0iPIiLb1EVz3iNOZdGTgt1
         LLkq6s2W/w8Cw39ic4hVk6w6L+rPLedNQgCJKO35AHbXSyv+TXecHoZkwTbzjayNliv2
         HheH8Ako7hseu2wKEuYvfCbzaRM9ErkM9rP7DngQoSfwU9hWofohFn0FEHPCdkiHwYk6
         jnVpATAMRHEhV2TjyVFFAZGl97YMBUwXU5yROJzUB3vELV394tKDssJmZL6/jnSjD2w7
         4x1v1fYOMLtpPoZjEB2ndocs1ywG9LoI8Nawg3Qer2drOQ9ucxKGr8fU46xvx2UtroR4
         o3IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ov17x5B1qrz4DnBi12YJJC2HQjFG/FexXE3DFuzIL24=;
        b=F1nqG/rLziHp16yKowgdb/u5gjNYlUpT/zmQjjx1Nc5SVVoKhFfq21aEvUG54S5XCr
         KxqDTxDkn2UunlDUL0Ay0wQm8mfAxUHD6A4fM+T4gRTUWa9oP0JnWiahDvHp3GnLrCkh
         JFsIFLxGBStANoWQ1jhNIr4IvbfmuCkD+Rft99EEa1gAP/MBONF/OqniY42GjzzYdEKP
         G9W1uwg5kuOEK4fc4GIU0QNGC5nV9sm4q+8N2lo8isLGgYcL1RVSNXzhSE9dVeWria1f
         RiyO/vJsHyL1QRIJtF2+x4V/VoXs5GR3a7hPKA4SSJmESrYdMCKYvOEos/BQSBYRFQey
         BbgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lywc3NBH;
       spf=pass (google.com: domain of 3wgqwyqukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wgqWYQUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ov17x5B1qrz4DnBi12YJJC2HQjFG/FexXE3DFuzIL24=;
        b=D0mPOijJjRgqH58Dcemp7KRyteb5wghX/O47acFjsgdbBgqCwYD8cnY0E75HFh6G6f
         h+Y99EyC94vcLZCchchH8axYBr109T9m7MncKrYwCNPQ6zIJHk/a0fwtNMN+F9kRTmbB
         kSwvfNXRejQXUo7dgiXBvcHWUB0molAc+0z3wsdo8GIRIRRTaKwAH8AMIjBk461KwyBk
         l1GjhCcs1iFhIrpXW4Qje+14RrtNt5saugdH7GosO98E4zU8fXGPkk2M1FkK2fY+BqB8
         BEzyv57h2fZaY6Zw6PLgQHV87rrlE9hog+J+Z6U4xKVjOmQ5clqycRqxrUgJebFTphen
         oMaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ov17x5B1qrz4DnBi12YJJC2HQjFG/FexXE3DFuzIL24=;
        b=dQnl57J9/jPHNQTr2gtJlC4LnW2sfG0dlnvHQm6sH0yNRN0mOiOZ/ytuFsLvlSUJDH
         xOJBaBf2DXFXBjHECDRm1cKcTeS901myHidZiuZrnjZckroQ6F1IQFvdWcMH3iCVdgoW
         bmDnW4toRohIc8OsBNV9bnqVJyccQfzJamrHPmZJV+G22BCxwUYSLXFXTaARMuZyEI89
         5r9N72rXZWKanlyV7W8aDKIreOpzOnXTuEvW/letzG6RyWZl6KYMkB/ZkLD/hq4xbpF1
         Ww+WUZIh2m2xiwcSPds6Cr5DJXt2JKn9IFZg74SBMZqHYh6xFkamD3bGo7Xgst8SAJ0Q
         EtSQ==
X-Gm-Message-State: AOAM531gR6K1ScclCzrd5orxJnPuen4+DwuGuZebzgqOOf+awC7L0Arv
	i6FPz6vuoSNXeXSgwppKXMg=
X-Google-Smtp-Source: ABdhPJzs0lMJLahxvyhQ60rc1NHpN8Yv8LOHNHsh+KGarADDeMRD6cE57ZQ0ITjvTjd9g/YR8f+mSA==
X-Received: by 2002:a7b:c409:: with SMTP id k9mr7707277wmi.173.1637223108057;
        Thu, 18 Nov 2021 00:11:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls4704919wmb.3.canary-gmail; Thu,
 18 Nov 2021 00:11:47 -0800 (PST)
X-Received: by 2002:a1c:7201:: with SMTP id n1mr7718293wmc.176.1637223107153;
        Thu, 18 Nov 2021 00:11:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223107; cv=none;
        d=google.com; s=arc-20160816;
        b=SI+t5M847hCU7jQzW59OT9szMmYah/ggW9amnOXcVdG6ZqOGuHKQPzTvVPmkNr6yWL
         nsrOnfQGOsgKXvVzy5DIrEBdpxjD+LbzevWVCbbi2dgx+4POHl4fyTx2gq1wKcGCRdab
         ve4HS1MzlGbUlIQnHkg41/zc/u/uNbcn+IEB3ABMQsU3Dl3xtzynn7kCaa0UVJ16B0zE
         03mpFoN+uiXnM0bzedvBQ5brRc93VZp7lHSHKpikCLawElweEMXeeT3Yo81+AoGL4XLq
         IcnqjDZDkQogJG0uKMRoBFlOJzRAu3oRWu5m2udKx/5NR93r9nxMRjRyiRbQq/XGKvgy
         kwYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rzdCErYR7QVJMqQ7C8iOEn+pKBOJL+BpLP2uqDT2sRI=;
        b=tByHW3EuiW8d/xE2K+6XjXYm2udZEBTfWbH/7w84/rEXfo37vwZAb1NUnlv1PnJIHi
         zTTYTyj1piPZogO5Gb0mYtbNuunCqQd2sxq+AFkuk0gMa8CSDFsz7x2hB//3NXQoE86s
         +/1zp+50JoNdi7VGcvGLDcCQCKG5Bug2K1176ZHZcL7vH1wVyPWoqMo3chdtF3YueEL+
         rYtmhb5m++OZ1n8W71blqgo/Bs2wGnM7huvFun5KOnmq9VGnPAF06sokXAUAer044tB+
         iL/wm1AkhgqmpAyfj9D079/mRz4bfbUyafCK6LUvIiwoepTCwtn/q9nK8iMIoP9l4yvD
         HnXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lywc3NBH;
       spf=pass (google.com: domain of 3wgqwyqukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wgqWYQUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d9si114369wrf.0.2021.11.18.00.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wgqwyqukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n16-20020a05600c3b9000b003331973fdbbso2747332wms.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:47 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a5d:6043:: with SMTP id j3mr28104905wrt.375.1637223106899;
 Thu, 18 Nov 2021 00:11:46 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:24 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-21-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 20/23] mm, kcsan: Enable barrier instrumentation
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
 header.i=@google.com header.s=20210112 header.b=lywc3NBH;       spf=pass
 (google.com: domain of 3wgqwyqukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wgqWYQUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Some memory management calls imply memory barriers that are required to
avoid false positives. For example, without the correct instrumentation,
we could observe data races of the following variant:

                   T0           |           T1
        ------------------------+------------------------
                                |
         *a = 42;    ---+       |
         kfree(a);      |       |
                        |       | b = kmalloc(..); // b == a
          <reordered> <-+       | *b = 42;         // not a data race!
                                |

Therefore, instrument memory barriers in all allocator code currently
not being instrumented in a default build.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/Makefile b/mm/Makefile
index d6c0042e3aa0..7919cd7f13f2 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -15,6 +15,8 @@ KCSAN_SANITIZE_slab_common.o := n
 KCSAN_SANITIZE_slab.o := n
 KCSAN_SANITIZE_slub.o := n
 KCSAN_SANITIZE_page_alloc.o := n
+# But enable explicit instrumentation for memory barriers.
+KCSAN_INSTRUMENT_BARRIERS := y
 
 # These files are disabled because they produce non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-21-elver%40google.com.

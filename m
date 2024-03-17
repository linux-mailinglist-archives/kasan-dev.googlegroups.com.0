Return-Path: <kasan-dev+bncBCS4VDMYRUNBBPON3WXQMGQESBRBFYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 9829087E08E
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Mar 2024 22:55:11 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1dd72cc8590sf43767065ad.3
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Mar 2024 14:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710712510; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q3ZOSwOjCQDI7ELCNzzhjLmI3eRHe4TeJnOmBervfnmfp/3ZfWc/5KtDLrkLX8H3bG
         AK3sM06iK/VNhzINgtpvgQjwbyg4bEFPFW+nkhlCr17+Lq9MUzKL4lkP2QgXJ0x0GKOb
         LKIEHW/ioQhSNz5o5iM3qgXR5NXQGAWvwBrj/Tr91oI6Cv5xjQeP+nffw5XLp9nlietG
         RqAKXptDgmEP3IO15P/bhiXNQFbjUddXe4MBHie6xqaJigjrUrzwin8Lv9yFIc/EY1+L
         WweeWOZrztQb13atQo6TQ8pqbRzeLPCA9v7KSv9Iz22h+5PAkn4YklAjpZYmkwKkxZIo
         n2NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=4OxMDUZbCnvTNobvYxNZlHxiyTYkUA1jzSsaU9OWrFY=;
        fh=LQkfWyu/lLLKm8bcRxxjRHuy++gR5dRWYwm/CPZzRBU=;
        b=U9FpDU5QbDkn8WQW/ke815T0XB1xD2M7KBTqYshV7t90LKDMNlgk2Px+EmXPMIihU9
         /79FW2MKVaoQzbEIo8jxXsCrFJNJgiX26h736wNVG3JD4shuSG6pUW6Xr8F94lXKRCuj
         0jE7bS+qkSv6XrLulGw7U8M3dVxP9vCTvX6c4hjfiMdgm2PFYQrYKeJx01XXp8JMX+hE
         vV1pf6ObLFT7v7Mc53Y5Q9DmJ3qiFrQjUhlCFEFyGX606yzSRXbchL4GyaGilFGsBh2+
         73OxCq4IEGopMzItLcb1aOZjeCN6dUeNQ0GWcwnalM0Px6gafXxN/dM+MBTUhkb2DIOU
         bgqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eRal4fPo;
       spf=pass (google.com: domain of srs0=mcas=kx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=mCAS=KX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710712510; x=1711317310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4OxMDUZbCnvTNobvYxNZlHxiyTYkUA1jzSsaU9OWrFY=;
        b=Xo6QTtZk5c31hrK9d9ajzwy9FyLy42q4/xHL3kpMmo3ZvrgLFCZ7BWQ5Ur0cX5SfLO
         Hyf8lB4kM+JQnh7tuSLIDtYJGGqsnwNfA/gU7NzuuMSYMZ8xPV3JoEYy5qer9SKKU6Mh
         PoqmoyFg7nkAo1dlpdGBcim9o36o1+cWsto1kP+ITVOZ4IcRJE+9YmDu3yNrWjF9LqfJ
         4LUI/wJc9CV3j4sO2rSbkEEazIo0SmcvlNW46G+7z/u96pXE7012pgEJq2567axlScB1
         ZaI3Nrczn6cnDZyGSCHLwaADqDM7RY7Q1GL69L5MeBnCVASuzUnRDU7tv17eDB7OuzDH
         5btQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710712510; x=1711317310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4OxMDUZbCnvTNobvYxNZlHxiyTYkUA1jzSsaU9OWrFY=;
        b=sRgcLJ/2ZSS27mD7+6jSW2tGOZCSpp36xvEFBG5XnKyft2t5ENpCyZo8DRhYQMxMJJ
         XZJnIwCiYHaAWC8yjZdoWz3JeFnoi7bmhTlZ3sA3PAc7qDzIl0x9oZN2t1ChPwKqlXle
         M4msLWM4QIsxNdz78gIu3UsUf5UQ94rAbkD75eBIBh0oaNTVlqnfLmoaSk2rRfOvdyHp
         BFkQfuJr4sgUiRFEoioPin6MVRK9PYvVmRc0oGBf7q05xRwjrAK+V5GE6AKG9rysrcS1
         MN/vQx3b1uVagVOaXDu/U035+akyq0nHGMZ9+QTyncgy5E7mK0yRbh6pzmg/vCh4qmOa
         TKxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+NDzrWTQNmAx81X/2FE9AS1xVt5fpvRNEtSAcnMrwdK+c30NHtgA5Ez/RsXPn90PjkLuKEZ0c4/XmuHt5SgFX0JP+e6B5fA==
X-Gm-Message-State: AOJu0Yxcdkyvy1UlLOwNOU2xY3wuwROJEVlqrZg9BGVR5LHFrP1BHnrd
	r6X3RZcgOEY/XV4eEsDmN5mNujOYYosNzR1ADWepMPVNSLBN97D5
X-Google-Smtp-Source: AGHT+IFaqHDa+8KCc0jrzzCQhlfF2H8VewSTljqz6egR/DeCsBrD/pr+ib3g3ATuS90lNbBhkPDYFA==
X-Received: by 2002:a17:902:7ec9:b0:1dd:68cd:728b with SMTP id p9-20020a1709027ec900b001dd68cd728bmr9911958plb.17.1710712509720;
        Sun, 17 Mar 2024 14:55:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:18a:b0:1dd:b73c:cbb9 with SMTP id
 z10-20020a170903018a00b001ddb73ccbb9ls1205470plg.2.-pod-prod-03-us; Sun, 17
 Mar 2024 14:55:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlon+XA6g5WeXZTV37ddyu3th+tRUHtHKcuUj6c/Ein9huOiwjPwbiZNUAkWRa+uFjcsLxNYCZHQBEw0dHR2Ezi60SH+RmW/I20g==
X-Received: by 2002:a17:903:484:b0:1df:f624:a542 with SMTP id jj4-20020a170903048400b001dff624a542mr5221633plb.16.1710712508357;
        Sun, 17 Mar 2024 14:55:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710712508; cv=none;
        d=google.com; s=arc-20160816;
        b=vuc19fRCZjICFSsqrS9DPJzw+8qimwq4p/SI+6npHfsfJmsHCg+CJLXQBnVyWBHhFt
         K65CHz7Jv/RELVgeoEJzSLiWb4YKXBI/XcoCwCWeo0himnmZl1zFtKM8eoWSaPxTodxc
         1Nx3sf06iHywHwWlr7qzZM1OB2ORpSwfl7ACuJn3j1+SoTO5qMXM/rrQaIChE8wpObuk
         lc1yP86Txyfxcu5h7m2Jg8od61Yezyi5m1mq4ZjdLXbzHFbRKvdvEWIZ+kxGy2+Jsy1c
         SArpPr2JUtq7CIVUqZWcTUNL4kX/4A3eFQygPlkwfvAZh61UaU8YAU6aqJ1Zcy6rN5JF
         bafg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Db55Er3bl9HXVqSPKfjdpRbYp1BJrQbWea72SkbG0H4=;
        fh=rQPPKocvcSdU/KZDT5a1aA+odI3+PtCpik6mL0wgMXY=;
        b=aAuDbNdxo3hPh5k6qLSw2P7hPYAx5vROeCagAu2qDO9ecE9NzMWFb5Oxp6EWD91f9f
         oqFLdN22NOJpYqCvkm8m35ZJm0tQ/VD2L5UMTipvsSG8KQ5r/47d+hQ96PUESvyuHWNu
         tGMMjaP/QCe/W6VQnAFEFM2JyRqtP1Yq2oErY/ZHYljmWaiol1TtgczI5D+2hBrNeA94
         onXzpUZVXYr4rgKXEdouDKyiVBoeKzJlTz/RYKCJKCRtd9JtV+LBfpBN7/9O3Hxn5Ph1
         RRk8+I5DU5Eo5D9+dfQGNK8WRJ1vK7cmgwG0m5Ki8I2lXNXLtQ9gdj4TmFVATFI0MR8E
         heGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eRal4fPo;
       spf=pass (google.com: domain of srs0=mcas=kx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=mCAS=KX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id k2-20020a17090a9d8200b0029bf3ffa9aesi470756pjp.1.2024.03.17.14.55.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 17 Mar 2024 14:55:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mcas=kx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 72E78CE098F;
	Sun, 17 Mar 2024 21:55:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5A35FC433F1;
	Sun, 17 Mar 2024 21:55:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E7745CE0D83; Sun, 17 Mar 2024 14:55:01 -0700 (PDT)
Date: Sun, 17 Mar 2024 14:55:01 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com,
	glider@google.com
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in
 rcu_trc_cmpxchg_need_qs()
Message-ID: <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
 <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eRal4fPo;       spf=pass
 (google.com: domain of srs0=mcas=kx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=mCAS=KX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Mar 08, 2024 at 02:31:53PM -0800, Paul E. McKenney wrote:
> On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> > On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> > 
> > Because not all architectures support 1-byte cmpxchg?
> > What prevents us from implementing it?
> 
> Nothing that I know of, but I didn't want to put up with the KCSAN report
> in the interim.

And here is a lightly tested patch to emulate one-byte and two-byte
cmpxchg() for architectures that do not support it.  This is just the
emulation, and would be followed up with patches to make the relevant
architectures make use of it.

The one-byte emulation has been lightly tested on x86.

Thoughts?

							Thanx, Paul

------------------------------------------------------------------------

commit d72e54166b56d8b373676e1e92a426a07d53899a
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Sun Mar 17 14:44:38 2024 -0700

    lib: Add one-byte and two-byte cmpxchg() emulation functions
    
    Architectures are required to provide four-byte cmpxchg() and 64-bit
    architectures are additionally required to provide eight-byte cmpxchg().
    However, there are cases where one-byte and two-byte cmpxchg()
    would be extremely useful.  Therefore, provide cmpxchg_emu_u8() and
    cmpxchg_emu_u16() that emulated one-byte and two-byte cmpxchg() in terms
    of four-byte cmpxchg().
    
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
    Cc: Marco Elver <elver@google.com>
    Cc: Andrew Morton <akpm@linux-foundation.org>
    Cc: Thomas Gleixner <tglx@linutronix.de>
    Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
    Cc: Douglas Anderson <dianders@chromium.org>
    Cc: Petr Mladek <pmladek@suse.com>
    Cc: <linux-arch@vger.kernel.org>

diff --git a/arch/Kconfig b/arch/Kconfig
index 154f994547632..eef11e9918ec7 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -1506,4 +1506,7 @@ config FUNCTION_ALIGNMENT
 	default 4 if FUNCTION_ALIGNMENT_4B
 	default 0
 
+config ARCH_NEED_CMPXCHG_1_2_EMU
+	bool
+
 endmenu
diff --git a/include/linux/cmpxchg-emu.h b/include/linux/cmpxchg-emu.h
new file mode 100644
index 0000000000000..fee8171fa05eb
--- /dev/null
+++ b/include/linux/cmpxchg-emu.h
@@ -0,0 +1,16 @@
+/* SPDX-License-Identifier: GPL-2.0+ */
+/*
+ * Emulated 1-byte and 2-byte cmpxchg operations for architectures
+ * lacking direct support for these sizes.  These are implemented in terms
+ * of 4-byte cmpxchg operations.
+ *
+ * Copyright (C) 2024 Paul E. McKenney.
+ */
+
+#ifndef __LINUX_CMPXCHG_EMU_H
+#define __LINUX_CMPXCHG_EMU_H
+
+uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new);
+uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new);
+
+#endif /* __LINUX_CMPXCHG_EMU_H */
diff --git a/lib/Makefile b/lib/Makefile
index 6b09731d8e619..fecd7b8c09cbd 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -238,6 +238,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
+obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_2_EMU) += cmpxchg-emu.o
 
 obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
 #ensure exported functions have prototypes
diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
new file mode 100644
index 0000000000000..508b55484c2b6
--- /dev/null
+++ b/lib/cmpxchg-emu.c
@@ -0,0 +1,68 @@
+/* SPDX-License-Identifier: GPL-2.0+ */
+/*
+ * Emulated 1-byte and 2-byte cmpxchg operations for architectures
+ * lacking direct support for these sizes.  These are implemented in terms
+ * of 4-byte cmpxchg operations.
+ *
+ * Copyright (C) 2024 Paul E. McKenney.
+ */
+
+#include <linux/types.h>
+#include <linux/export.h>
+#include <linux/instrumented.h>
+#include <linux/atomic.h>
+#include <asm-generic/rwonce.h>
+
+union u8_32 {
+	u8 b[4];
+	u32 w;
+};
+
+/* Emulate one-byte cmpxchg() in terms of 4-byte cmpxchg. */
+uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
+{
+	u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
+	int i = ((uintptr_t)p) & 0x3;
+	union u8_32 old32;
+	union u8_32 new32;
+	u32 ret;
+
+	old32.w = READ_ONCE(*p32);
+	do {
+		if (old32.b[i] != old)
+			return old32.b[i];
+		new32.w = old32.w;
+		new32.b[i] = new;
+		instrument_atomic_read_write(p, 1);
+		ret = cmpxchg(p32, old32.w, new32.w);
+	} while (ret != old32.w);
+	return old;
+}
+EXPORT_SYMBOL_GPL(cmpxchg_emu_u8);
+
+union u16_32 {
+	u16 h[2];
+	u32 w;
+};
+
+/* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
+uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
+{
+	u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
+	int i = ((uintptr_t)p) & 0x1;
+	union u16_32 old32;
+	union u16_32 new32;
+	u32 ret;
+
+	old32.w = READ_ONCE(*p32);
+	do {
+		if (old32.h[i] != old)
+			return old32.h[i];
+		new32.w = old32.w;
+		new32.h[i] = new;
+		instrument_atomic_read_write(p, 2);
+		ret = cmpxchg(p32, old32.w, new32.w);
+	} while (ret != old32.w);
+	return old;
+}
+EXPORT_SYMBOL_GPL(cmpxchg_emu_u16);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67baae71-da4f-4eda-ace7-e4f61d2ced0c%40paulmck-laptop.

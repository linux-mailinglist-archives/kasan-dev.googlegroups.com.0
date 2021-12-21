Return-Path: <kasan-dev+bncBCXKTJ63SAARBDESRCHAMGQEWYBCGAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2D747C496
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 18:04:13 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 138-20020a1c0090000000b00338bb803204sf3006956wma.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 09:04:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640106252; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpJC1rKhD4+0mHyr611ZYYgO2fop3NiHaqLlrRkoA2GLT6Pmbpi5ooWXFeqpjpK6Xs
         wTq9PT3slnTYpiqBAU3apm3vBPYTDw1KQaTGfDcdp+FUvPszwwuz1eghjqgg+tW+tYfj
         2TigNjQ0EYzPmzI8jaOj81BxQO9P35i65Pn1XDteMgT1U4Dis8OEcelk3sFq8cSJBQm9
         3RfOG2iKrtpYevu4MA7MlG1lXm/Gp8xqoL8A2bhNWpzOcVfPDjc+5xxLK8xF9JB5Zz32
         NLMH9UsyNKCvm/lU+wibQXiGKLin/5Z4O87u4l5x6a1mUDSxxc5yvgLFSxM58Cxi1krc
         vCOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Gyhv5PEkU5322eKIPxsCCYlkwvwBMJPeBkCIpc8dSNQ=;
        b=Ao2MXVdP4vxWfKcauh5Ziqd0F6fB3QE8iHbuAZ3NBSUZRS7GZ1NDh1z+DLCa76sJs+
         jYZA1zaz0mCa9Fg6FLg+/3AVMdOKYN4wpWQVbypmUalAtdw8O6B782XgFlYgfYPFhdNY
         TLYinRbrV4cftbHE4029hkNLG3EaVY5GE2sQ9hIwkyvAS6UnepnnttykFwU+NF7lfPaJ
         CXzidb/P7PBX98W6vSbRAnFebvvF8pz/10vp+JstIL0yx1W8SWfLINWgFyDdcUZECLCg
         3pZao6iXvTfjAgJ8c3tIWJRPB+vIDxbVJv2ADeqpoes0VlaGtnuUW+1cAFr8TR/F2O8s
         lfbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rwpDUr7B;
       spf=pass (google.com: domain of 3cwncyqykctojkcegdckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CwnCYQYKCTojkcegdckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gyhv5PEkU5322eKIPxsCCYlkwvwBMJPeBkCIpc8dSNQ=;
        b=P1sr4repbt/Sgj12BPA5Y22PkMiBUZHLAf1Lwub+D0x5MTKbGwtiWefJLG/B/Y3qWA
         ZUhxI1nS5w9nfzHPLh4GtbS+r2xE3jkZAofFUk6OLlBMqEIy+hVwRWz0+tGxjllJRvHF
         cow4RqNBtKO8yJvJEjJJGq4UO3Ero/lIIMwJkdIIaWLrD2/ozpfgbwUGUsvrKYnaLGUS
         wn6gGWg988mTEZWJedo9+GJH1r3oerTmLxabeQIIv8eppJ8dAy4Q7sEq1t/coOhqyrsh
         7cRTigX2nDs/bGzz3FAOO5snXgoNqIR/jkvYzfYegJuHm+tlm3gP9jnxfxWnQDST+ayC
         Fdqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gyhv5PEkU5322eKIPxsCCYlkwvwBMJPeBkCIpc8dSNQ=;
        b=6zECjKo0R+R4lWtQ/gLOjGuFyCpkNaeVuNmAI3IHtKasZ4vLslubZvdwdPRxDXyH25
         e3V4g9Ua76aV2tm2AyqFCIUsnF/s1MDbP9xIoHHfx/yDRaafsHcs/OFVMuneM8qq2LdR
         qu92N8Ep24FFp5kciNwPSh03fk7crTfkI8AHIIQswzCzCeiQ5xA/aOer+F09k/s6u8Ig
         hJSdbIN94j6YA14/cKt071kEys+yZL27mMY3vj4EcysYvGmi6GsZ4Cjj+G0hOd32GZpq
         iYo7qR26kkX/UliBLFtHTGAycNpIttZNh/41h4RRqAraURfCq9oTp4Q3x4qmqfsIAx3k
         smhA==
X-Gm-Message-State: AOAM531YXe/X4laA1G/1oZVeJgXFcCWb58qT5mgwbMcNxVgFIrnQbZRA
	4VpECKMu3h3im4V3DaJFFfU=
X-Google-Smtp-Source: ABdhPJw6gekY27S1BuhuxdoUiRFUQZKaeE6dMZ1vr+IouvicyvAPshApsGX3gRCu/NbXJG/57XvMLQ==
X-Received: by 2002:adf:d0c7:: with SMTP id z7mr3365834wrh.236.1640106252670;
        Tue, 21 Dec 2021 09:04:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls240198wra.0.gmail; Tue, 21 Dec
 2021 09:04:11 -0800 (PST)
X-Received: by 2002:a5d:440f:: with SMTP id z15mr3337579wrq.29.1640106251854;
        Tue, 21 Dec 2021 09:04:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640106251; cv=none;
        d=google.com; s=arc-20160816;
        b=RZraiS1uVpHMue4sRh3QUxYVfIIUb+bXWWuUO4HiQ6zrWJZaVU9zHSjslNeIPXArcm
         JHDR0SR5fh0tNZ/ReTmOuZaSyO9wzgejeLlcIDsRCcm72b+i3wt/Af65v6kh7yLgBhSR
         3vmtKGjaqWBk8FlaWtFAJ/b73LXfBsk+ELZ492sNjgD8AakX6/OfZhf2Er3NK6z2ZxoX
         sVcOP1nLDbTv4P8vZqHsVkf+2wLqgJSqlFPF4n85p0haF1YsWy+xbwCnIZ65ZoA542lk
         moY6h6co0N5H/WpkoVFQiTLQCs14TKYJe8snGkuVjcTPjxGQH2KWRd6IsxoVyfHbgLhf
         hMLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=E92eP/emmd4tPCtN84LURrU10uCO5laN21sGBPTutAE=;
        b=wE0ik8ap7p34GN5ZteziFX9L5a6DBcsY856yzw1t0Asyr8zdZ2axyS8Bvi88HF6S6V
         bi1FBibyUgpmhe4Sbvl84SVRjRoPlYGXAZWyaon5JtXyNPlsQKTbSIzJjo9rkI+7saEa
         dz9YxPQhwPrS3ksw+7LsmowQvM+12QOqxbpQjzYoBFcsFrg8uGXzzfbvNjbwXdPCo1p7
         OWmbrY3hEyZhiwI3lrvSsasomY5ugQj2J0DvgL4iMA9pVBDCe/TWVXysz915TUQ5RmWa
         GZxeKs9OEKfjcWH0XTOMk6E2bTsxC8urvGknK3w5GB3XNwSUPAy/OBst/kizbNC0YwNq
         tLSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rwpDUr7B;
       spf=pass (google.com: domain of 3cwncyqykctojkcegdckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CwnCYQYKCTojkcegdckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p20si130058wms.0.2021.12.21.09.04.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 09:04:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cwncyqykctojkcegdckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 85-20020a1c0158000000b003459d5d4867so1557010wmb.0
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 09:04:11 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a1c:9dc7:: with SMTP id g190mr3701479wme.56.1640106251428;
 Tue, 21 Dec 2021 09:04:11 -0800 (PST)
Date: Tue, 21 Dec 2021 17:03:48 +0000
In-Reply-To: <20211221170348.1113266-1-nogikh@google.com>
Message-Id: <20211221170348.1113266-3-nogikh@google.com>
Mime-Version: 1.0
References: <20211221170348.1113266-1-nogikh@google.com>
X-Mailer: git-send-email 2.34.1.307.g9b7440fafd-goog
Subject: [PATCH v2 2/2] kcov: properly handle subsequent mmap calls
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rwpDUr7B;       spf=pass
 (google.com: domain of 3cwncyqykctojkcegdckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CwnCYQYKCTojkcegdckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Allocate the kcov buffer during KCOV_MODE_INIT in order to untie mmapping
of a kcov instance and the actual coverage collection process. Modify
kcov_mmap, so that it can be reliably used any number of times once
KCOV_MODE_INIT has succeeded.

These changes to the user-facing interface of the tool only weaken the
preconditions, so all existing user space code should remain compatible
with the new version.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
---
 kernel/kcov.c | 49 +++++++++++++++++++++++++------------------------
 1 file changed, 25 insertions(+), 24 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 5d87b4e0126f..d6a522fc6f36 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -459,37 +459,28 @@ void kcov_task_exit(struct task_struct *t)
 static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 {
 	int res = 0;
-	void *area;
 	struct kcov *kcov = vma->vm_file->private_data;
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
 
-	area = vmalloc_user(vma->vm_end - vma->vm_start);
-	if (!area)
-		return -ENOMEM;
-
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
-	if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
+	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
 	}
-	if (!kcov->area) {
-		kcov->area = area;
-		vma->vm_flags |= VM_DONTEXPAND;
-		spin_unlock_irqrestore(&kcov->lock, flags);
-		for (off = 0; off < size; off += PAGE_SIZE) {
-			page = vmalloc_to_page(kcov->area + off);
-			if (vm_insert_page(vma, vma->vm_start + off, page))
-				WARN_ONCE(1, "vm_insert_page() failed");
-		}
-		return 0;
+	spin_unlock_irqrestore(&kcov->lock, flags);
+	vma->vm_flags |= VM_DONTEXPAND;
+	for (off = 0; off < size; off += PAGE_SIZE) {
+		page = vmalloc_to_page(kcov->area + off);
+		if (vm_insert_page(vma, vma->vm_start + off, page))
+			WARN_ONCE(1, "vm_insert_page() failed");
 	}
+	return 0;
 exit:
 	spin_unlock_irqrestore(&kcov->lock, flags);
-	vfree(area);
 	return res;
 }
 
@@ -671,25 +662,35 @@ static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
 {
 	unsigned long size, flags;
 	int res;
+	void *area;
 
 	switch (cmd) {
 	case KCOV_INIT_TRACE:
 		/*
 		 * Enable kcov in trace mode and setup buffer size.
 		 * Must happen before anything else.
-		 */
-		if (kcov->mode != KCOV_MODE_DISABLED)
-			return -EBUSY;
-		/*
-		 * Size must be at least 2 to hold current position and one PC.
-		 * Later we allocate size * sizeof(unsigned long) memory,
-		 * that must not overflow.
+		 *
+		 * First check the size argument - it must be at least 2
+		 * to hold the current position and one PC.
 		 */
 		size = arg;
 		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
 			return -EINVAL;
+
+		area = vmalloc_user(size * sizeof(unsigned long));
+		if (area == NULL)
+			return -ENOMEM;
+
+		spin_lock_irqsave(&kcov->lock, flags);
+		if (kcov->mode != KCOV_MODE_DISABLED) {
+			spin_unlock_irqrestore(&kcov->lock, flags);
+			vfree(area);
+			return -EBUSY;
+		}
+		kcov->area = area;
 		kcov->size = size;
 		kcov->mode = KCOV_MODE_INIT;
+		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
 	default:
 		/*
-- 
2.34.1.307.g9b7440fafd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211221170348.1113266-3-nogikh%40google.com.

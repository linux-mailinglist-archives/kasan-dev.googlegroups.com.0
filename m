Return-Path: <kasan-dev+bncBCXKTJ63SAARBHM2S2HQMGQEKQAQOHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 23F5B490B82
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 16:37:02 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id i81-20020a1c3b54000000b003467c58cbddsf14168920wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 07:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642433822; cv=pass;
        d=google.com; s=arc-20160816;
        b=bruWH3XUCrtutGtwkUT6bOigsRK+Vf/WpXy9MHcwL8XPMxxV+eZxLj72K2FEvtbuq7
         mDHh51AYLlaSp5QvUn3tXBkBpniKrfbD5ZY7j0kBhs6iy6JWc+IQLG8iCdoZK1tRLrCZ
         aXxzwSe96W1Oh+odlpvmq6pc1TdQZt/4nmppm3SFX35VkCraQsmunIYaYcabR3dIL5IF
         EyDfDp68kUmN4i6e8DwXyGkDZsXa7AQcoGpHC6ZQ2eaL48JAa2qabAG2I6z/DzKFQHtw
         H+gxK73sr6K+Bm1mqksp9YmP70c8nGmWrbQdyiR+IX5pte3ZyAHHVjIJ+B7DH1jgj7TD
         ph4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eN6AZT1ByEgOtFk32j6UutLpcTdPlHI65ENVsMlF6pM=;
        b=Durlkm3KcVUnss9rJ7C24oz51GGUm9rPpYmUA8q61LPO2Rj6utDwiz8Kjzgxz5mI0E
         Uo79qarZgVg6gLTHLvbnwvWcAaIWNRluiR7t+WmxHcVvn/eVeLlJy7JQlrNTT4X+N1ZI
         f+OxiG3YDnIUhic6WfO+SMysBDRmyGg3lwq7Pf8L4WGaf+v0gbvkpDiO8EbsHNk63b+d
         vAthHB2quJaIn8KtACqK2rwNCzisNd4P3pFbASpWez9BR8d6sCQkfmRreOmRu6KnoEud
         +8rzR2cBRVtX9Rs3WmHwWp6tg30UMksiWUBhKXozf1miOqv7KEe3WCcV3BF4gUMyYHHl
         sqlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Mu/4nG9M";
       spf=pass (google.com: domain of 3hi3lyqykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HI3lYQYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eN6AZT1ByEgOtFk32j6UutLpcTdPlHI65ENVsMlF6pM=;
        b=XuNO/KTr3+vWY3Bx4x1ijQNFjjlV/1xg34pkiNwgOvZ8Ajpb8L+LFHO22tescaXMB3
         kLepkH6wi6mW+VxgMatSXvKSI5woeuxyiPMLbv5hWubZwudaEPmJqyP4pddYSuhzcZ4r
         PeC3mjiFYS26u0Hl/fY01TD6UD9iV6M/mnmxxcVExRaywAfilsTJ3SYIEmr5sBXCT5W6
         hRrjvSPuOZj/mMCGKrrG1dUIEH+13RDcyjisQMQGPMznvY8rzp1pnlkL3mveBdP4RGt/
         ZSyabzgHrzCbpgMeSgnOOGuJazsUafRFYq9sG8UuSN/sHWqiM8iRCGEl9KhbWAD5o/N/
         H3UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eN6AZT1ByEgOtFk32j6UutLpcTdPlHI65ENVsMlF6pM=;
        b=GgL2z17tiRkjpjfzAk2BH89Lsbl1TauQHJ3jv4C0ExCSdnv7ehdz7Xpr4zVDSvGGQN
         7azRjPpYfgH+Yx2squymmzR1IS9R97VlF+UPaykcP353zt05PTL9Fdp5w5bE561G/K0f
         fgxXtmoQPLVVf5XwrampVe5eribWTNXSo4E1fBCxEx4QWy4ck/pG4y2hqi7qT8XiLXIo
         2AOWD5hXZ/09UPF+tgBgOPpRqIJ4A1gfbf6fW+vmYp5oe9Zo8Y4FT/42ngFobYaGd+Kd
         TKetak4R0AUeNRwbf3Rd+ysCQ95Yc8g6hH9lAAijEWGDYHkYyBuUbhbOQnUGgEep1iCP
         /kRw==
X-Gm-Message-State: AOAM533pRiviKWF27OivreinsSoLdJ7hnMSZgEGZFAd0eOXsop7aYQPt
	vfw8chOJ6K34wOfy4thaPkk=
X-Google-Smtp-Source: ABdhPJxb8smq0oh26cN2MOMPTfJwRGGA1tAv1OvhztrP5yCTpDQeGGyftvAmlb4udCdiMVBa0aIHNg==
X-Received: by 2002:adf:f9cb:: with SMTP id w11mr20376518wrr.106.1642433821930;
        Mon, 17 Jan 2022 07:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a158:: with SMTP id r24ls1308916wrr.3.gmail; Mon, 17 Jan
 2022 07:37:01 -0800 (PST)
X-Received: by 2002:adf:dfcc:: with SMTP id q12mr19973516wrn.485.1642433821153;
        Mon, 17 Jan 2022 07:37:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642433821; cv=none;
        d=google.com; s=arc-20160816;
        b=igDtDVc1OTTFyk4mk2HrOk8svaEABjB+WaxKYZ4GqrnFBDBTXD2qJ4/mX50O9uMEn5
         DkY+0WEemOoKJC49VvHl/zqssecAvwHkMePXGFvqnUXQ70AkbzB6wgUEwlDFcDViVKnT
         f+gnGgGb80o9Gsz7Wvl8Y7QMDeuG6L3f27kz3c7VEZlr9sEUBfS47/yfCwiaVuhVoXG/
         jml29UusMJpwBAbiVzX8ucXyI3Ib3iRstvf1qQerEe6PCqbD0UU/PTHV2o5orF8ejOth
         YXWyH61quz6DmeZk6RTDYFlKm5OsiSM4nLJWBhxbWKgADPSK/v2toHAzNqHzg/NJWCCG
         jizQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1thsq464ntZ1Q6hN1oNhhbpxlas4Ufptak2u+5NaEgg=;
        b=dTANKrGU1fEMqaQ0mwKXkXwCluRq8P5Ycni1maeZqrw+n+dvniU2Qigy7Uswxdz1Cf
         dzx5Wv71jwnuylpbz0wt/4OT9jBcBBXBOl5SbYzVGjtEI6muigxFGptc2OgKcMCHsB6P
         eRrE4weNJ0xL19lRb620icO64xltsZPAASLVrjVn4LLHbX6oRz1Ktrr1VUd9KV0XJ4Oc
         wPqYrtGDjuWYsAyyI2Y0+UpCsjV4rlsvQpzAb0E8S1YmDHv+Oq0Il4PMePp/pnftjQyI
         9yoItEPu0b/C99vkARi46Ix+N1QYR0d6aGbHytuZjBfsv7qIqe8AjU7gZihMbljKb5K3
         oCUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Mu/4nG9M";
       spf=pass (google.com: domain of 3hi3lyqykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HI3lYQYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 189si4685wmc.4.2022.01.17.07.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jan 2022 07:37:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hi3lyqykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id bg23-20020a05600c3c9700b0034bb19dfdc0so231622wmb.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Jan 2022 07:37:01 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a05:600c:33a7:: with SMTP id
 o39mr20091461wmp.6.1642433820772; Mon, 17 Jan 2022 07:37:00 -0800 (PST)
Date: Mon, 17 Jan 2022 15:36:34 +0000
In-Reply-To: <20220117153634.150357-1-nogikh@google.com>
Message-Id: <20220117153634.150357-3-nogikh@google.com>
Mime-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com>
X-Mailer: git-send-email 2.34.1.703.g22d0c6ccf7-goog
Subject: [PATCH v3 2/2] kcov: properly handle subsequent mmap calls
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Mu/4nG9M";       spf=pass
 (google.com: domain of 3hi3lyqykceeqrjlnkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HI3lYQYKCeEQRJLNKJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--nogikh.bounces.google.com;
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
 kernel/kcov.c | 34 +++++++++++++++-------------------
 1 file changed, 15 insertions(+), 19 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index e1be7301500b..475524bd900a 100644
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
 
@@ -674,6 +665,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
 	unsigned long size, flags;
+	void *area;
 
 	kcov = filep->private_data;
 	switch (cmd) {
@@ -683,17 +675,21 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		 * Must happen before anything else.
 		 *
 		 * First check the size argument - it must be at least 2
-		 * to hold the current position and one PC. Later we allocate
-		 * size * sizeof(unsigned long) memory, that must not overflow.
+		 * to hold the current position and one PC.
 		 */
 		size = arg;
 		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
 			return -EINVAL;
+		area = vmalloc_user(size * sizeof(unsigned long));
+		if (area == NULL)
+			return -ENOMEM;
 		spin_lock_irqsave(&kcov->lock, flags);
 		if (kcov->mode != KCOV_MODE_DISABLED) {
 			spin_unlock_irqrestore(&kcov->lock, flags);
+			vfree(area);
 			return -EBUSY;
 		}
+		kcov->area = area;
 		kcov->size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
-- 
2.34.1.703.g22d0c6ccf7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220117153634.150357-3-nogikh%40google.com.

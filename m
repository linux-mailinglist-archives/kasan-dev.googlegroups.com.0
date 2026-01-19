Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKPYW7FQMGQEQRP3IBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id BD2F2D3A350
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:40:58 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-38302f5aba6sf22521151fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:40:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815658; cv=pass;
        d=google.com; s=arc-20240605;
        b=WzLJV4+DABu+OwU3Gr0GSjM+XubktQx1V089cCPc/teJMV7L2iz61cA+R3zgaVzDRe
         TsUJMBDA9un2Dthe7wRpnVT4ua5dTRb0O38BAku9V1OCKbgniQuS/zpTtC6xHaqYpUPl
         F1gZ1dVgctonC3tYQzaNqMX8hsIKjN/XvixI6EyUt4VMhFduUr5nMOnBj+X9Zzc/oOXM
         1VouBYJZLCLJ88+cc1+M5E98C2Q7qbGcrdGqzN+K8w2JmMFyeqCzQDcXZBctaPEf+Zg5
         +HHvvJyuT+GuzGYaGNexNTyKFmWr/1HUrM9ZrwFrpnMzwPYQgj6L9Ri9fFhqjJAEszvc
         RHlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pq/dIaZgOmM2DlnRS26ZAOADlm3clx16Ra/t1HU0aJM=;
        fh=9crUaHf2nAHYdr16FFwY0+Ut2CbtgZqGNKdapCxIBK4=;
        b=ZKLY3NxceoJGNl2uFWxqv2+PL+A3dis/2J+GgFwQn70r8K/Z43+5RYplvXwFyhFVEa
         Wl4qYkpaPK1dIqfI7drVtNNtMse3NvF6AXxIig1xmQduXIfgOWYCn854pNbQB5SFDkJu
         GI+1QMyU13OaeNxckBNXCycRDHJ3VDpqT4FUVqR4cKUuQuxXR4rYebvJSU6S/lXyswVR
         55brYK5v7conQGq3Dnb8HLoFfE2Kb8rFEnz2YDkgW5fMGywPCuJ0izWghQKUutUIzWck
         vCmbAmaKuxJcDKTLu3dPmxhpZYFgvecxYSzJadI/UJM65kOSAfr9Vdry5pTPahGxpQqy
         M54Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A6zArE+w;
       spf=pass (google.com: domain of 3jfxtaqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JfxtaQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815658; x=1769420458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pq/dIaZgOmM2DlnRS26ZAOADlm3clx16Ra/t1HU0aJM=;
        b=pXrefWZ6qCnKIXZtt01AJAuI1JjGjw28dSgpCFwvVsHLMg0TAGA70BEiKBgkoVm/TH
         QAF1hq2pO/5OgX8hGUzKVc0knPt4k3A+XLPw7F3lWGuOI2c+7yquEvLyXyAw/N5EA1LD
         gz9OjFch+NyGNzIz8DtDe+lJml324HlBWyyRhowelNbHV3+O6PWlyZYYC6MIIeIwmoPt
         RZ/W3FZn3ihUBnKLY33SYkOJjSZubY1aG8jNrdJ1PYyMtLZvG21QG+SaaPmRu6Fd14iw
         eLUHeAUFsiuef8GK8f/4CsciPhi+nOfe3J9DG6/918u/qKgtzYkQlMMQN2WTBwBTxCCR
         ZJ9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815658; x=1769420458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pq/dIaZgOmM2DlnRS26ZAOADlm3clx16Ra/t1HU0aJM=;
        b=sUWGMrQ/9+jgyNhwUopNSaDuJHamk1rOfxRbcNTl2Y+Yc3VMUlcLz8YdtE9fCIgHJx
         F1kruKRzwigvyU53BaYEN019req4lWNpn8Qf2R1kVzIHYFlI5ol2FnU/fOQbV7pdRt3H
         ND0ZIwsqD/3xCWtO6YI8b2emCqkoHeIRXjNflL6Acp3FEbyzSag7eVgi7BGADmzIspLG
         5zoDFY602qYL/Ow0s3B/QKeyoTrv/63t4pnJcN75NA8h3xyc8QEK+EnQqtpXbf9feew0
         GGchZcl3LtZqG9O/7OWjN1fsz6QFhvxLN6QfMXMfF6AcHNsqCxPRuKwXX0Y0Qb1FbB5G
         dzvg==
X-Forwarded-Encrypted: i=2; AJvYcCVv/ZUgfKMCVn6WhLml4ONLKLOARf5vUrhCB4zQ9oNyFZGrehVcqK3C1Qh8WJRFUIDhSxUUFw==@lfdr.de
X-Gm-Message-State: AOJu0Yzr2jEaUQv0HoJyJKfh3Ss772bL1Pwzeo5mOAgzk7BtyVPzNX1k
	r9XCz8BJiT5T8ZlCEG+i50X3Tgd+x8wQNjEerC98Rzt6XWWyNL0457Q7
X-Received: by 2002:a05:651c:41c9:b0:37b:bcbc:58dd with SMTP id 38308e7fff4ca-38384176341mr35827301fa.1.1768815657755;
        Mon, 19 Jan 2026 01:40:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G2TkLrj92y5xVu2uPMwVqeZuLPlZKnX0dB7mNln9gyqA=="
Received: by 2002:a2e:7a11:0:b0:378:d368:a117 with SMTP id 38308e7fff4ca-3836f07264dls3682881fa.2.-pod-prod-07-eu;
 Mon, 19 Jan 2026 01:40:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLd8oP+12vkjzl3s/qBHwsPeHqMMKisxdMTs8yocLl0d5z+wBH4sfMokXCZsLNXLjwhNoWSRuFgkQ=@googlegroups.com
X-Received: by 2002:a2e:a808:0:b0:383:1c18:ade6 with SMTP id 38308e7fff4ca-383842a82cdmr33878381fa.20.1768815654521;
        Mon, 19 Jan 2026 01:40:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815654; cv=none;
        d=google.com; s=arc-20240605;
        b=RYQO4+/jRHAXFOFYTcdj25o9q+NU6FgOl7ZzW3UH4hVZIt+TjDZQ5QnfglQPDzkXSm
         pDYHzW3nH/9JT8/pPqgtpN1mcDwIpdOAE6UZ/69g7RSruivJUiBAI+GXSQWEiPZWzQ58
         UdP3IWJKffcnpkGQnjfaCtrKCpDWcG7LqGjYlhiz/GWIcNKSYra+/JirOU1WRz0HDEYg
         Aedhjlijd+/zIFnUp/RB5EcLAHz4OSVbDNrYCjMqSa3WPXQS6CnJ4vD2nYfcNhAYamKm
         A5J5U/1FuLXu9kwfBonYgjpmH1clVVZlVFhZiUIRJq9Y7eq9MGduwDuRWbwfIu1T4qL5
         ve9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ewHt49qLKu+2CyU8hq2cJxrH6CXFZn4CCknA2bnTf50=;
        fh=BiWf4UP4fIyquLies7QObjNZ/PhqdffgVU1dIbS6l5U=;
        b=ceJjLaqHueKBodA3uoJWCt7VG0CmuuMSIXlCQyTeE2hB90KfO4dbi8Y83uwDIqcMDA
         xcik95fJevGntSS1pCRJ2t44VrALwn87WnyLzQU2Hw6cAU0ugSgWrJJuCo18chKq7es4
         W3MTTEys60rtQaQb/UDqL9c2BzcdexL90Jm+oqJHKpDjCkygU2KfC+ytFxSupmhST8tM
         XcOvC+2QISYSqu5/7MLGZbeqUvfbmHKPoZhow2VizaNhOqoS/8cgMGXOHVs/2vM/GtPF
         RD+V3LKgOhNMFmbA6GYlbnE7lbmCMULrM9Mj2SIQojOWJS+57h4Otzj4ce+PLfkvRVx1
         qDkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A6zArE+w;
       spf=pass (google.com: domain of 3jfxtaqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JfxtaQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e7914csi1559261fa.9.2026.01.19.01.40.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:40:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jfxtaqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-43102ac1da8so3450149f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:40:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2Wr8VYZdCQ4UvS1Gj2TOa4RcvW43NSiy05bPbfvE3xEGeGDk0kyk0+kLuYnJNBgki0DhdTjkkngI=@googlegroups.com
X-Received: from wrsz3.prod.google.com ([2002:a5d:4c83:0:b0:430:fcb8:38c0])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:64e9:0:b0:432:5bf9:cf22
 with SMTP id ffacd0b85a97d-435699709f8mr14538540f8f.3.1768815653726; Mon, 19
 Jan 2026 01:40:53 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:53 +0100
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Mime-Version: 1.0
References: <20260119094029.1344361-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-4-elver@google.com>
Subject: [PATCH tip/locking/core 3/6] kcov: Use scoped init guard
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>, 
	Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>, Bart Van Assche <bvanassche@acm.org>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=A6zArE+w;       spf=pass
 (google.com: domain of 3jfxtaqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JfxtaQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

Convert lock initialization to scoped guarded initialization where
lock-guarded members are initialized in the same scope.

This ensures the context analysis treats the context as active during
member initialization. This is required to avoid errors once implicit
context assertion is removed.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcov.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 6cbc6e2d8aee..5397d0c14127 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -530,7 +530,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
 	kcov = kzalloc(sizeof(*kcov), GFP_KERNEL);
 	if (!kcov)
 		return -ENOMEM;
-	spin_lock_init(&kcov->lock);
+	guard(spinlock_init)(&kcov->lock);
 	kcov->mode = KCOV_MODE_DISABLED;
 	kcov->sequence = 1;
 	refcount_set(&kcov->refcount, 1);
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-4-elver%40google.com.

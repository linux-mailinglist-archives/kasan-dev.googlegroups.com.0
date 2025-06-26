Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSU46XBAMGQE6JHUHEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 467C3AE9F35
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:36 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-451d5600a54sf8338085e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945355; cv=pass;
        d=google.com; s=arc-20240605;
        b=MvNh6Hx6j2hvHrgQ079hddaynByJykgJ/MSpX4FfTRs84VC9bxGLrZN0tcn5O8rgk8
         afHv7sJPOuX7vBOVeEUHT794kPWZiL3UxHZx2fn/ckvutfNEt7EJ+pZ3miMbaqTqZ4Z6
         PnBweeL1Bg2vEwyL1K8Kxwqa/K3drsJo5bPTFaT1Kl3jsZk3RRamB+Kkmcq7oEk7T//O
         GOXZNpVMwkKZzhIOvqtPqhhPeTf66mhpvXrPAwG4YPEPrCONJXQ0crKYSKZJxKtW49Ss
         yicxDQ7Exx/nAdHYRbCq7idFEza8VKAt8VS6ZqjxJyMteGUMENvpGYalu/7RDxhGn959
         skOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=asUs9mNTgWoLU1zKYxznPBv5lG/Qp7Uddle4HoAGTyQ=;
        fh=QC46lXqeDrrbjP2OK/NMf8Klaunr4L2pkOzEQZdKFMk=;
        b=MCJuYQ5wqjoMC/MWaI7jHhFA9RsjcWOk1NNWWr+3iQstbCpmIxfcdojs0u0UxZ8eaG
         yFQQ1rKxyVDkUnXzG1Dk7drGvZX/mG4gHgCdTV77PTL6nnTbXfeKpzneNnV9pGdKHfdz
         2S9KB2sAjWQsan0hHabkXu0UaSDodYZTU1DMxx26ci4cWVe4AkPZzZnf78OMJcd3bBv/
         jvWs9t3xjFUEtFDDhMLLk/9S9eFv7bUFOIBgntEoR2UgEVMQlT6HGfHy93rLXuDBLNsZ
         vQRB5Ll+7auztz1+2xONMvsNFQASXtdyajyOhid5E3tdNaMplnBHgRfitVw7D9acoEJe
         wz5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=angN+2oy;
       spf=pass (google.com: domain of 3se5daaykcamjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SE5daAYKCaMJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945355; x=1751550155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=asUs9mNTgWoLU1zKYxznPBv5lG/Qp7Uddle4HoAGTyQ=;
        b=s9BbfuTtAK2LcxumfuKKi6GZa904Y3RTMzCSYkGeWWAPwtM+7byoh6biWYGI6fe8V6
         UbxaXflcnlpUXaWwq2JnaU0zaR/p4Av76IE6AmhyNaNK7YQ9M0aeYjvZYFCirfWrFsaq
         62V8Bo/1GNTkdd1qhPlWZJ8tiKsVTpbHNfSNwPDXPDTaO/Ro7Ic2USReQOpwcy6qUx0v
         wDFy1BjIofLB6eewJb+MkaB1swDqxeMgxa+8KA6GUie8ASyIvL/Qi5p6JSPYBTp8PFk9
         WgVtDrBx2H4pd+FX2g3D6jrQAp9Q0tE6L8CmBxeBrtQhvDRmzoIaVELAUFPfuidxRIrQ
         zqBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945355; x=1751550155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=asUs9mNTgWoLU1zKYxznPBv5lG/Qp7Uddle4HoAGTyQ=;
        b=ibSecSLEJAAqh2VFWbo5ksIStskDdt3DlWGvwKnbII7563T9C7h4mt7yUuQ4ZLutfX
         iNPofc43HQUVy8u3/OZNyYoqITyFeBUTtIeD0+M+blb35fCpukcYKFE7LEZ2983uhlVe
         vFckRDr2rQXD8cxt6ADPN5JJMgoh/iG2onqoH3hNd9kY6ACEJb2EmDtpcCSnTLbBftrl
         u+2Ci4FvGTTRY+4a0WkIMjmhxRWDsUYe9VxR74n6Gq4Eu70MfMid25ditbJQfRmNXyBy
         a+EydSzOHyTHiPgGpqjLgD/zwoQXteONczR9mXjk7W3VNyXUF3xXqOIzDWJzzejYlxCE
         cnwA==
X-Forwarded-Encrypted: i=2; AJvYcCXLv7ufEO3GAshfWO6u3mO5FLJ1+ISw3hH5e1jr8sdZ8TJnQIKABxDhs5JBQQnmo1nWODof1w==@lfdr.de
X-Gm-Message-State: AOJu0YwbMZYKiY6oLtOwx66SApNOWwlnLoeG8porLit8iOseHGLUMe/J
	bBz2PAkEYJPAP97QQh0gccyeU/LmuCW/Odqn1NTsRclL92chfAe98FYA
X-Google-Smtp-Source: AGHT+IHouchhggkqiIIU4EviK1Jk65H4js4aQ895QfaBkcUt9JS0YR2Zpk4HmPpg889FdhkZDMyzSA==
X-Received: by 2002:a05:600c:a44:b0:453:9b7:c214 with SMTP id 5b1f17b1804b1-45381b2155cmr70501735e9.29.1750945355267;
        Thu, 26 Jun 2025 06:42:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhGOMdYgogTCKHhRl72Hzq5XG8Fbom7J7ow+e073XGwA==
Received: by 2002:a05:6000:2001:b0:3a3:719a:e30e with SMTP id
 ffacd0b85a97d-3a6f321d4f6ls508379f8f.0.-pod-prod-02-eu; Thu, 26 Jun 2025
 06:42:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+bTCDuB/F23Qac+3cxNGMcnHPa+rz070HaBGb2cgGQFnr/xc3fJyj/CDXs3bZNqHNc4Z0dnosUMQ=@googlegroups.com
X-Received: by 2002:a05:6000:2210:b0:3a6:d2ae:1503 with SMTP id ffacd0b85a97d-3a6ed637b3amr6257961f8f.34.1750945352958;
        Thu, 26 Jun 2025 06:42:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945352; cv=none;
        d=google.com; s=arc-20240605;
        b=LCSsUOB61NoHNIh47Sh0Kw1D6fYtJkNR6Bp1Z6PeDnKlvTplV3iVFj3vQrKdRKcyEx
         uBsladsaNTGoa7/7rvF1fwYn+H9izRIyYEkKmQAid9yCpPxgjzADHpa3fH3Ra8wtmjyz
         H4YzjlyeNhFgx3WnxM0FcxHrmn+iNt0Uqx/YtldiGWAM97naLKSXsrfcWpwLNxFAjUbM
         S2326nxuR5VEWN7jZ+QLZ6tAfTmMFYOG+V3/GvhsgbvAuZ6qn7K9dDC52OzlGiUIMf0u
         yqE0q8GAymcZZX0eRv+Jpbe+KbhZcPYfeu26tKluu7TZM/SiJLeR5xHn/3drVWb1Cbat
         Fh7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hl3fNVnAsDqURU0FpEqnT2FFnl4Elpb08ixBMdGUI4M=;
        fh=IfuHWGe9+En6AO9n9CKOK5+QgyEmjMA7QeDmv2yyGVQ=;
        b=V8GTcbA7VzIp2p6RMbGfdD3l5X4tLQAk24QRbQHtAtPsiArQEWwn7zlcmWo8YbVQ7O
         Qpn9Gjxir+1Z1wug08zhPYeQ2ZWsJEeOwCqjsolw+PMmsg1AG1jHAKH1dmRWoztHMcaT
         LM9B8C1O0/P8QJQsiX4Oe1R3nP2hlSts0MFsLvMWKZZCgA8mPIxe4pSMwzJKyaKngumH
         ps9fryorUuP5UIBhbVOnrTvG8dlQiDD/JyYcbbLyYrqvfuB+NthnBTITmZfrAP3NXz1J
         o1KiDCA6XGvp8Z0EeMi7TRdVz1OaIDYJe2eO6CFdlAcsC2/mn/ikWLcytkkAHyYLev2k
         ZMCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=angN+2oy;
       spf=pass (google.com: domain of 3se5daaykcamjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SE5daAYKCaMJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4538a3ca4desi340445e9.2.2025.06.26.06.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3se5daaykcamjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-450d6768d4dso5995515e9.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWB1uF9plb2fDLGgWmABPQOlawiuiJfsGNlq1k1RicEy8Sanzebesnf4JQOyzbxiPc1Uiylsn/q98k=@googlegroups.com
X-Received: from wmbej3.prod.google.com ([2002:a05:600c:3e83:b0:453:8ab1:7b7f])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3590:b0:453:6ca:16a6
 with SMTP id 5b1f17b1804b1-45381ab7e02mr85008665e9.10.1750945352580; Thu, 26
 Jun 2025 06:42:32 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:58 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-12-glider@google.com>
Subject: [PATCH v2 11/11] kcov: use enum kcov_mode in kcov_mode_enabled()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=angN+2oy;       spf=pass
 (google.com: domain of 3se5daaykcamjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SE5daAYKCaMJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Replace the remaining declarations of `unsigned int mode` with
`enum kcov_mode mode`. No functional change.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 kernel/kcov.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 1693004d89764..62ce4c65f79fa 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -951,7 +951,7 @@ static const struct file_operations kcov_fops = {
  * collecting coverage and copies all collected coverage into the kcov area.
  */
 
-static inline bool kcov_mode_enabled(unsigned int mode)
+static inline bool kcov_mode_enabled(enum kcov_mode mode)
 {
 	return (mode & ~KCOV_IN_CTXSW) != KCOV_MODE_DISABLED;
 }
@@ -959,7 +959,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
 static void kcov_remote_softirq_start(struct task_struct *t)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
-	unsigned int mode;
+	enum kcov_mode mode;
 
 	mode = READ_ONCE(t->kcov_mode);
 	barrier();
@@ -1135,7 +1135,7 @@ void kcov_remote_stop(void)
 {
 	struct task_struct *t = current;
 	struct kcov *kcov;
-	unsigned int mode;
+	enum kcov_mode mode;
 	void *area, *trace;
 	unsigned int size, trace_size;
 	int sequence;
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-12-glider%40google.com.

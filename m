Return-Path: <kasan-dev+bncBCCMH5WKTMGRB55RVXCAMGQEEOFGRAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 05561B170A7
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:25 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3b78aa2a113sf385810f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962744; cv=pass;
        d=google.com; s=arc-20240605;
        b=kAL4hPGIOZJvBkJrmPhlwYyixMXmcWjUlsMpLgplqUaL4qM053A+Q7Frz7rT9/hO8Q
         tqZz5tOHRD+ieAUJgGelZ7Q4026R1Fks5+YsSoVX25uMMZior7Akt50vneA3sXosrC3b
         VF4SL9l6wOihX8iUK1PMjUZEcq0DrC3wYXyVq+r7jT3FD2jvE1mXJR3Jots8NKZntO5h
         xrzDgCK7j31/ZLPZN5mn1mhEbJRxDnTppRt9QTBYmf7MBAXpo1dG+LljTR1K5byt8etu
         Xp7DvWdjLqZh4GwACHqhL+dcOfLCsfNEV06LFY32YgcuCHVJdNkHwWT0hKIcub+U6NDx
         YnRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XhOvLD3hpyJPoXUFqG+rY2n2A1y8AxZ7Cv52cIcLSFI=;
        fh=J21Q+NGIYNgLKv3PeV2X3AcHbZR5jDyuHZoc60a8AvM=;
        b=cYQ41m2aRiB+5PpdrIxwX/jrIXcUE/txNvcyJPG1yluJMRgiAebg6v7G61Fs55FYVp
         PNgFsb/FwWNAUXkkfcqAtoCn/gvEqSWaGpYjqWHs1q+qkn/F5wDLLb/FUwqOnAi7iXik
         8Z5jZeFjGrO1T5KmAEmUvGTQOPCO53RlnhJSyoYggV/6lwO4vrCrElHe2nImIpBC38M4
         c7h1hCTAfYn53SqHnW7J7haUqkw1iMTyMB6rSPm+WFuLYt6H3E9oTkIy5D+X411RZQlf
         WdDOWspMNxcf+zsNsuHWhROVpfz5wrmxixZx1af3X0vdZb/zPFLQcdXHv9vfQlq8g1KR
         w1lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cFmu6dqt;
       spf=pass (google.com: domain of 381ilaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=381iLaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962744; x=1754567544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XhOvLD3hpyJPoXUFqG+rY2n2A1y8AxZ7Cv52cIcLSFI=;
        b=mfMbAtgc4g+yBpoztG/AmOFjp2cCSChXkY5dHSUddNqctnVCCusiOPHWfAsVauiBzy
         oD1MNkXjMmz7+6QfXFTgoK+tpKzM/Ei+6eOqMZcUUEQzMT9QE64RhABj3UYgJeaL8pW5
         zEIghFlsbj7DXkalR8qs3su8a6Bl/PHMfYMtvBxolisTOrDMNgYYJPVACkrFTWd88uA8
         veAWGWM/ZgVXSzoTpr+N8wSLfP0NVs3hY8QpbaOr2OPUjZEmZuWyiAQzI1WxuuIp8Nx9
         Fc7HE6eGhpanNGnQAMNlzR5ShPUpHdb2xllukjoG1BREdeeo+TcuVatKDTUQmBSRWkPT
         KKPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962744; x=1754567544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XhOvLD3hpyJPoXUFqG+rY2n2A1y8AxZ7Cv52cIcLSFI=;
        b=PPwOZpd2Eyc+KY4+LjAKZGIIUztynVqE1yQ+9FaWoLEmEJW3HLexywF+EafRI+Tov3
         uYT0mxG77RxxAf8Ax4Fvfo2OWrpd3InWCCvTo0f83YlqhDNbUcwz1Vkk7DIsmj8v/OKq
         q11IzwJTiFBs8oPZCrAUvAOM7QZiTpC3errm+7zmpoTsNHBjsjFCPytHdoXE4Ejt50l5
         1h0vM7P3ZhH9OwXh90SZ9uEsDr9QvuEfwyxPt/MYcziBO9tndeosRi4HChNXdAMDbRas
         CkghjTYC82l8LCE2rX54TGyFxr5DX81g73HzBi1CD/EnwV/VVzTK28emS5ZabkvuuGFB
         3t8g==
X-Forwarded-Encrypted: i=2; AJvYcCWxIu+L1D/LOpFyFLXzGfNVgFPq84DQe1pgktn6XybxyDako/AXxnJVOpfdKw+b0BVfOYZXjQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPmIcWJz/VBc+kEY5h5TosJ8ZDXo7isCyjAorL+M+kx4NQ1GrG
	JQ3M3nnTtSD4uKCeTUwxybh13oU3RKKcEj8WaskijpZu5mR8vKe5AB2Z
X-Google-Smtp-Source: AGHT+IEzR2KZmJLSxy1vK4GO+Uh1pP7zKqreKvhSgPqQBaW3lm8xcKlW6lJxRUREBVTScnAlirxvGQ==
X-Received: by 2002:adf:f503:0:b0:3b7:99cb:16f6 with SMTP id ffacd0b85a97d-3b799cb195amr2916962f8f.53.1753962744456;
        Thu, 31 Jul 2025 04:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcobkho4kUPf0ongvvKsZC/hARkocaPqqPRLmIPgmXsgg==
Received: by 2002:a05:600c:4fd2:b0:456:11a9:85e0 with SMTP id
 5b1f17b1804b1-4589f39d967ls3466435e9.0.-pod-prod-03-eu; Thu, 31 Jul 2025
 04:52:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYTBSVaBYtSr3dZR1k/H+3crVfl/mEKgnc2+RVzz+glI08F21xshXvuMTwNPetfzfBq/IAUCPOr/A=@googlegroups.com
X-Received: by 2002:a05:600c:1d24:b0:456:1a41:f932 with SMTP id 5b1f17b1804b1-4589ddb66bdmr28317845e9.22.1753962739762;
        Thu, 31 Jul 2025 04:52:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962739; cv=none;
        d=google.com; s=arc-20240605;
        b=ISUX9v7aZrvJj0/dh6bLDkcaLIm8inCohYbh1CMohV+oNGtYeVX/ZXce5cg7lpvgEr
         Fm5c01Slt8sAt7mNkLZDdoUr0pYGNjALnObk0TlF6sKWlOYq12dK2eog/DOSbxddv+4i
         jUFeUXyZj5lNQjTFBIpAaeF4VNmrYURqh+4goRdQvM4b2vp0pKsjn53I4NPH4cBl8ve4
         e+a62xJPsAkfbz+daz1Uu9zMR5ljPOd5xbBsTz7h9i4hBDjCQxH5UGUk/YoDm5SzG/pc
         OO7iC6RV/Xg21Xb/Ji6ubTtUtmb9P6dl402catTfWa+y63GS0y3iKvd9+nx4qRYC9+UO
         1GXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3GI7pfDzbEZpzy7S8dcB3cJkLd1K2BcoBH+xtJGm4Rs=;
        fh=VbToQ9hjchrdWLeAFbzZRtkEfLInCa3SLsDroKtN87Q=;
        b=foQQ/wj4FFoTt3JjhGXo7z4iYji3N1AZ97n6p85ww91EElX2BYq+1MtaJtM0MuerYE
         giaGAgI6klbUyfQCtf0CIqpJRW2LJd9N5ec/qGtYBQOF5y8ewypAhSOp+/cprUEQqlYm
         egGjb2uYh44FqGHpY8Jhpa7n1kZx0GhY1ZFBil+tJjcbwDXQ+fl7C2rEVgR8XQ4tut6B
         nn5EUpE2dgizJnhzr/tUx2cyNKH5kDjlyBRalz3hCP9MKyyNVzhx2PAtGRBmHAcmBOUK
         P++mdbnvt4CbNls3KqVsG6L7veR6R5AS0zaozKzYsi3PYPAe79hkZad1+ZxhDVQZ5W1H
         s4OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cFmu6dqt;
       spf=pass (google.com: domain of 381ilaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=381iLaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4589ee09341si509235e9.2.2025.07.31.04.52.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:52:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 381ilaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b836f17b50so168933f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:52:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVH5ffSHZwNeSBnuvruwuAGJo/NIdCkYAKqFyr7WX83U4s3PKrFUsfhxg8JWNElV2HJ6xOqSPPe7Rw=@googlegroups.com
X-Received: from wmbgv7.prod.google.com ([2002:a05:600c:80c7:b0:458:a7ae:4acf])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2912:b0:3b3:9ca4:ac8e
 with SMTP id ffacd0b85a97d-3b794ff878amr5465479f8f.44.1753962739364; Thu, 31
 Jul 2025 04:52:19 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:39 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-11-glider@google.com>
Subject: [PATCH v4 10/10] kcov: use enum kcov_mode in kcov_mode_enabled()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cFmu6dqt;       spf=pass
 (google.com: domain of 381ilaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=381iLaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

---
v4:
 - Add Reviewed-by: Dmitry Vyukov

Change-Id: I739b293c1f689cc99ef4adbe38bdac5813802efe
---
 kernel/kcov.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 82ed4c6150c54..6b7c21280fcd5 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -949,7 +949,7 @@ static const struct file_operations kcov_fops = {
  * collecting coverage and copies all collected coverage into the kcov area.
  */
 
-static inline bool kcov_mode_enabled(unsigned int mode)
+static inline bool kcov_mode_enabled(enum kcov_mode mode)
 {
 	return (mode & ~KCOV_IN_CTXSW) != KCOV_MODE_DISABLED;
 }
@@ -957,7 +957,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
 static void kcov_remote_softirq_start(struct task_struct *t)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
-	unsigned int mode;
+	enum kcov_mode mode;
 
 	mode = READ_ONCE(t->kcov_mode);
 	barrier();
@@ -1134,7 +1134,7 @@ void kcov_remote_stop(void)
 {
 	struct task_struct *t = current;
 	struct kcov *kcov;
-	unsigned int mode;
+	enum kcov_mode mode;
 	void *area;
 	unsigned int size;
 	int sequence;
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-11-glider%40google.com.

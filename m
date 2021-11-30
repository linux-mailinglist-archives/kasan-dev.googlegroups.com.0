Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3U5TCGQMGQEZ7P2N2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E95794632F3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:50 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id b15-20020aa7c6cf000000b003e7cf0f73dasf16630868eds.22
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272750; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCzkSIobgtStW8kLIfNWGnuFPdiT9BNxqFQeBUj/ANJJTiC4Wc1Isi3xpVxSNDx8fU
         Cterq4A39P9c5bXdeKnNZHvu5YlgQS4sP4lacqH0p+jvlTYeihK05zcoF17VrkeWHRNb
         h8c7ZTxM3tuAkH2n1Zy6CgiP98MXJWP3encNVbYD0+0dSwilJdwuIJ8KMSUVV5Lx4YTR
         3g9F2ADWHYHv++6dFJ39EPPlqfBwtd0kdPASESbBk3SWDbTCrZLxjMsQuw+jBdOHEM6C
         cr1ikY9uNujhMNmBhv6IqOcxzm9LXgFtNWFfUE3uadtBLjcQpbqQE8HUoeAC07Aowtc1
         aoPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UwXIbos+lp8LXdPFS2nQs2/mk3cZhJ45m9iWiRxwWEY=;
        b=Cl8I8XGvg546sGB6RdP+xrsy9v52HSvmEaWWYB8JgopNzuPyyhWpk6U+McnSLd07Je
         yyrpdhUEh9GzhCnMGWylSQH2lG4rUm2cPU7R8vrvGM6IBP7KnBZIvSlr7904cT4FE0z4
         IjK8ZeSxjDpxfTCM/JeP1yvt6wathnRomlDQzVAI/x+IKShWjhk7FPVj4mCoU/DMa8i9
         skcjxD/qmeSbTS6RgfHVZhoyYf8BD/AaAfxjlFOYhX/C83Bpgow6A8o2gWbTcgJu2wm2
         Q6UrvqoVJL1aiMSEuVBigAP7QsfOiQrBESKvGCP9frZCL9+4t744A5Dwf/UkJ2SXx355
         Savg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UzkPOK44;
       spf=pass (google.com: domain of 37q6myqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37Q6mYQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UwXIbos+lp8LXdPFS2nQs2/mk3cZhJ45m9iWiRxwWEY=;
        b=c1S8WbGBat6lyf9pkzkf6f/BL3TEA+RG77oxE4o/z2D0dOQGjYufqObXKO96Crd4GD
         4FRajPIQT+E8VXr7/HLCcWgx/xvYfnRS/sKqrNIj1ImAj4eZNlvG2f47EZbBOZ/p2r5P
         cWHurDNSPSr2HZtkPJR3I7ecSZXqDfTh5yD4U0yk4Y+fXLFrx02bDsg2cyVjvQ/vcOFP
         EkaDY5CG8OnUgxFevzapK0yHf7Z80cA8CF85FEA8Y3PHSRroX04DzQNKYyCp2C/qiYN4
         /i377SSeabgUCqWcUoCYymkTUs7CTMBEZYChmeCG9iCfHcsOWm2n1CqNpXNydzoWVpsJ
         Ju7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UwXIbos+lp8LXdPFS2nQs2/mk3cZhJ45m9iWiRxwWEY=;
        b=FLNKTSK06Gd+SBZKrQmWr4MXilOwUIy7klAGCkwCPwf8lLgHjpeP5UTML82CQTVcUH
         qEH+12bsNE6NWIdFBUoRcF/L8V3H/abvOHq4qzB+3dZ+XZBvRGw4Dea/CTBrw2X8KJUz
         RVzCyEu4vAPVseRBseVW4BKxn5ykB1p7x6LepHV/KpFd6ONOguLboFRcxvO/fI+yTSfS
         d7Ys+yVtanpqBWyFNzeefnnQp26c6cdnqAqZ5+xrWR/+eRJDCPyL9Am4ZuTjMaS+rmqw
         nsqte944P1ayA0QqxuS7WwkIOyOiTHU9TCAJ86+VcZf/p8P8tfQbSzP3caIflx/VKI3O
         yRiA==
X-Gm-Message-State: AOAM532uQ4mIkdGGE8anOqiYQ5ONxfGhfTWfNOZAGDrwI7fU/5L8ZBjH
	A8S5iCZpwuuFTFmDnEZBXQo=
X-Google-Smtp-Source: ABdhPJyvYZmLNtKS8MSBtzYsI6DH1fB3EkUC605bqsTTULstYpgb/bA88iKjakNL5ylRqHYNvRCD5A==
X-Received: by 2002:aa7:c313:: with SMTP id l19mr81508626edq.209.1638272750776;
        Tue, 30 Nov 2021 03:45:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c517:: with SMTP id o23ls7556340edq.2.gmail; Tue, 30 Nov
 2021 03:45:49 -0800 (PST)
X-Received: by 2002:a05:6402:4382:: with SMTP id o2mr81838331edc.143.1638272749858;
        Tue, 30 Nov 2021 03:45:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272749; cv=none;
        d=google.com; s=arc-20160816;
        b=dPyNQ3xqwL/N49Cm2UWnYonFkO5wkH65U+hPBBUhAqViFZoRDlWeFsiZdbMyQc2s97
         6WFiWZXrMPgMXHeiFzfiy5lBrixGwdQ3rKhvC+ZqPkbfxRgbc/bRwZuMn5gmfWdmagTC
         gUEkcx1ILBgfk4IcuqVHwTeC7/Qhempd550SVTsfWBSJgA18JjXIgCkC3qjYm4UG0aLa
         UcCgSKU5upLMCNr92vZFbeH87IM0N/t1E9Gm0p4nNHYIUKE4stJQPveW2D9KPcWH0EnO
         OSBZpmcJ6/JA5TYNdfmeXw0y41ndV2xjZeM8Q7wgRA9eYPDDuyIqS/FnRMrx1hYfvtVx
         XGyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=TQFyZU0v42DaaTkISoD0OFzde9Hlzhfr9CYPS/61CiQ=;
        b=Es3u2ZBuhjnfO1L91MAw9rMvXqpADvKQp80jAVdnXrteoq9Jm5gaSVF8CnjE9wz+us
         5xfdj5EndJZugrbHnqj6ZKPwmAbiakcWq7VufCNTEfsV38FqykjCJjbmlJG0Qmy/r8yf
         PTa3nVio/L7CR6PcCxX0zLe9nQWv5L0s/EBLCUqwr290Vkaw2XBR7OTWG+84mgOgJdDs
         jxYHEFUcH91gsehqngTrptT+7dd6utGNJxHLHYC6870Y2AFsOLgw9ThecZAV2XGUP4oy
         rPcd+kkTUEWxzMZd5NFJ5sn7WAJf/3PdBsNbQW2q5ptiBcnrvYyVgqtsqQ+MM268Qfhg
         mMhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UzkPOK44;
       spf=pass (google.com: domain of 37q6myqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37Q6mYQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id eb8si1510002edb.0.2021.11.30.03.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 37q6myqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dso10297182wmc.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:49 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:19c8:: with SMTP id
 u8mr4203223wmq.155.1638272749477; Tue, 30 Nov 2021 03:45:49 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:27 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-20-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 19/25] x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UzkPOK44;       spf=pass
 (google.com: domain of 37q6myqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37Q6mYQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

If CONFIG_PARAVIRT_SPINLOCKS=y, queued_spin_unlock() is implemented
using pv_queued_spin_unlock() which is entirely inline asm based. As
such, we do not receive any KCSAN barrier instrumentation via regular
atomic operations.

Add the missing KCSAN barrier instrumentation for the
CONFIG_PARAVIRT_SPINLOCKS case.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/qspinlock.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/include/asm/qspinlock.h b/arch/x86/include/asm/qspinlock.h
index d86ab942219c..d87451df480b 100644
--- a/arch/x86/include/asm/qspinlock.h
+++ b/arch/x86/include/asm/qspinlock.h
@@ -53,6 +53,7 @@ static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
 
 static inline void queued_spin_unlock(struct qspinlock *lock)
 {
+	kcsan_release();
 	pv_queued_spin_unlock(lock);
 }
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-20-elver%40google.com.

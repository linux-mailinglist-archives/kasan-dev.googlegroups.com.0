Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4MDRSLAMGQEVPDUQRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D851D565944
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:25 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id c12-20020a2ebf0c000000b00258e5e6e125sf2865976ljr.17
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947185; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6S3HZhd7MpD2lDaMgBhRx0HA60PR/PR1gUn4jhfv/2ROsarU7kcO9n/tGkmdx9uVZ
         40sPAOviwzeiVJ5g3lFzXbwXfAOZirc6d9e2keU81PWH50HAMKo9VC88jfFg6EVHJfE/
         DuUHBk8aoNW7Cg8jdQdmOgqqhsk8du2eBuajvQffLkrw6QtBm/uuucaBVNwTo3IVTh5a
         trhfvm4HojB2pncp7aLvad3vai4S0eLUcoAw05ZOG5s4PRgNXVnQDQ5Mj9hN/Vr9AVje
         JDYW39oTdWm5SldACemfWp9VDhqE4moJPD8Rf3xSqnq/8uu4vAvpg8VT4ikHGFr/ei14
         Y7FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=L17W8U6nWlAsZ4bi6wD4G0q4Xupafbx/j0tbNmUtqn8=;
        b=ZU5k2P2RFamkm8XuSB2/QkvUSTuW/IhghPh8nGpSAdPdGG3BUChVA6v4FVQnjyO1G7
         jrDtJpHarstIzMI1f4pCJYEjk9o781wlIRhzEwNsdxIIx9qcAFinu+KORsyl1lAr6fA7
         rg9Fwhp2Kk3TgcZqP25wkYHutR2GzellAfrCyaM7Cy4Sso0t4uSAo2DqBSaXk8O5Dc46
         5Ht4OpCkBnw+b4b+5v4FLXEYFvoqPjnEg6WoM+2G9Uo71wSce2fcVjUTtohE67cKDJi7
         Roz0pCVEHIpmVXfotu9Mj0rqz21Ic02nFcfJBcgPR2sRL7Qsr/eTcQRNd8QVP5huE+Vn
         QYRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ph8b8+BR;
       spf=pass (google.com: domain of 37whdygukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=37wHDYgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L17W8U6nWlAsZ4bi6wD4G0q4Xupafbx/j0tbNmUtqn8=;
        b=RFZE2EsmodyB74Zv3rDlqrFQZrzN5DZO5GrOW0khdwxR2TiDnIrkQ2Q+TyUhNCu4o9
         0yiY2o78VL97vSYdSKFQ4MvkYN0vqZEwLdEq8AMRuvls/vAcboiyqWJuYgVoTGb0WzMz
         A96J8KLQ9qfuJpkhpRwyuEJlaEOiqauS+sB59X69crMQ5aB0Ku9txdx8hCmDzNRGejzm
         /suzKtWc+D9tp5qZDySHZuxkaomPK2s7LmBGlxqS7c88rIZqWEjecQR80uKAVMdodAyY
         KkwUQVLCogv3DJXsi1VPALkjtpwModifH93z+qDiLNpdk5niYBvyXRrF/DJD1TMfetRg
         7rhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L17W8U6nWlAsZ4bi6wD4G0q4Xupafbx/j0tbNmUtqn8=;
        b=MxipltrpB9BJFRwSPfluIAK2z5ddUTPd85P2T6OtPkul8g4IDwqbgvxYCk1jJJ/l2W
         gG1rvkdLu8qjJMw608awcUkDD3TXlAelDiUfzmSvalV9iLhOyasNm0GaRVcdY0A5ElMF
         hk+7ZKrRhC2gyWnbkB1fhf5lT6KfxZ4Gpi0FfVm3lZFbuPW5QiahNhoFrlYxCRZVywpx
         lXD6QQcHhib6vXNPOIHhcnME78+3+dHOGNi9xvvfnNisVW8UXu1xi8NeJxPQkzEhrL/P
         1HDtjJnvkVOUgyn3NBsQVIQ5ASrcXThBnZFdAe6Fusp4stoBshMSqbE0FBqma+pFCCuI
         dVjQ==
X-Gm-Message-State: AJIora+OndxFJHNZPDB/d0i9bWrzhLDMq0hqfZi/6puwCywblYAqzC7Q
	0b02iG1cJL5/0u/hGbh/pUY=
X-Google-Smtp-Source: AGRyM1sBQiJNxSWcoS0KBCffabFCZg+0T9nXfDWIdrfE15RNlVaspeR6S91wmkCjFwwp+N8Bg6wohA==
X-Received: by 2002:a05:6512:260b:b0:47f:b04e:3116 with SMTP id bt11-20020a056512260b00b0047fb04e3116mr19940412lfb.474.1656947185246;
        Mon, 04 Jul 2022 08:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b041:0:b0:25a:7050:86fb with SMTP id d1-20020a2eb041000000b0025a705086fbls6796714ljl.10.gmail;
 Mon, 04 Jul 2022 08:06:23 -0700 (PDT)
X-Received: by 2002:a2e:9a8f:0:b0:25a:7f54:a82e with SMTP id p15-20020a2e9a8f000000b0025a7f54a82emr17051072lji.8.1656947183842;
        Mon, 04 Jul 2022 08:06:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947183; cv=none;
        d=google.com; s=arc-20160816;
        b=GC5qUuw2Axeh3zfVmqIJpXHBPrRFvIRvSsC4EYTi4sKkJs7lusaAfp20VqpYrb0EFU
         JeH0Sk6y0yWdhGJUiMlobp2yxpP1Lj17ciBgEXmPYkFCGEPooZj62sCF2z/R9GTNO6K5
         y1iwmJPKWvz/2Y/z+0ouwK/0u4fNBNrFW7WEn+O41USbsufQ4sIVRItteuRKzNuYkNlA
         ks+vw3dXdPz2q++5+IFA79br/K+bJHOb9UjZWH6KZdUmvNy0+aIU4ZywKizUr1OMRbNN
         c1bN2gfFw71MqLOCdp6ruQjD25nv/eIyumh9u7DqJOf/+kr8/Ocj+7aSxfF82cRF1CdG
         WXoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yKHd4+xECY7NKN85fGWY0KF6Qb94v9CyhlLOvS2S1lk=;
        b=HuVVHSXThxn4YO8FW0ZtV0ElfsEjq4fpxOdBvmrH4VeteKB6OUHp6B4/+mJ1uylNH+
         JX1xz3M5yuupn9KCpUB6k69YlhMbaukdjsq2AzURC666ZJrSVl2PhDSgcRjYLXDz4VXc
         XxFcqFDPotC9GpMGXuKQELcSEM4frnjdtoGdaW2N3BxJ5JP9q3WEf6efl6gxwKyqIk/R
         KI9VpQ5ZbD0wR9EVtfHPHnfGBKOTGAtR0WvXJRdZPwVmrtVR/hBh09iKsfpybTxOfKm6
         mz0BRdbEUs24knGJZ9nq/+33JmBLy4BZHJW84BIBNcSuvgY8Xd/PjkvKOaAHrxlA3SXn
         q3QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ph8b8+BR;
       spf=pass (google.com: domain of 37whdygukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=37wHDYgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id h6-20020a05651c124600b0025a45f568e9si1121049ljh.0.2022.07.04.08.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37whdygukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hp8-20020a1709073e0800b0072629757566so2117644ejc.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:23 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a17:907:6ea7:b0:726:41de:78ac with SMTP id
 sh39-20020a1709076ea700b0072641de78acmr30061092ejc.452.1656947183301; Mon, 04
 Jul 2022 08:06:23 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:10 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-11-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 10/14] locking/percpu-rwsem: Add percpu_is_write_locked()
 and percpu_is_read_locked()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ph8b8+BR;       spf=pass
 (google.com: domain of 37whdygukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=37wHDYgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

Implement simple accessors to probe percpu-rwsem's locked state:
percpu_is_write_locked(), percpu_is_read_locked().

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* New patch.
---
 include/linux/percpu-rwsem.h  | 6 ++++++
 kernel/locking/percpu-rwsem.c | 6 ++++++
 2 files changed, 12 insertions(+)

diff --git a/include/linux/percpu-rwsem.h b/include/linux/percpu-rwsem.h
index 5fda40f97fe9..36b942b67b7d 100644
--- a/include/linux/percpu-rwsem.h
+++ b/include/linux/percpu-rwsem.h
@@ -121,9 +121,15 @@ static inline void percpu_up_read(struct percpu_rw_semaphore *sem)
 	preempt_enable();
 }
 
+extern bool percpu_is_read_locked(struct percpu_rw_semaphore *);
 extern void percpu_down_write(struct percpu_rw_semaphore *);
 extern void percpu_up_write(struct percpu_rw_semaphore *);
 
+static inline bool percpu_is_write_locked(struct percpu_rw_semaphore *sem)
+{
+	return atomic_read(&sem->block);
+}
+
 extern int __percpu_init_rwsem(struct percpu_rw_semaphore *,
 				const char *, struct lock_class_key *);
 
diff --git a/kernel/locking/percpu-rwsem.c b/kernel/locking/percpu-rwsem.c
index 5fe4c5495ba3..213d114fb025 100644
--- a/kernel/locking/percpu-rwsem.c
+++ b/kernel/locking/percpu-rwsem.c
@@ -192,6 +192,12 @@ EXPORT_SYMBOL_GPL(__percpu_down_read);
 	__sum;								\
 })
 
+bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
+{
+	return per_cpu_sum(*sem->read_count) != 0;
+}
+EXPORT_SYMBOL_GPL(percpu_is_read_locked);
+
 /*
  * Return true if the modular sum of the sem->read_count per-CPU variable is
  * zero.  If this sum is zero, then it is stable due to the fact that if any
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-11-elver%40google.com.

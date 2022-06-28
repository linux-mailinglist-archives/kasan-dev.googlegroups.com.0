Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FB5OKQMGQEJGZ5EXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AC3355BFFB
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:27 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id f13-20020a170902ce8d00b0016a408cbf3bsf6762547plg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410364; cv=pass;
        d=google.com; s=arc-20160816;
        b=BoofuaMjkw1YD+/OZR/gb6hMFqnPj6c7jB0VjNUXDv53vBV3gNFyVsDKlhVADQ/hKW
         AK9Juo/i0tESA8G2ynrw8ykMESSUlOGLl6IaWHtigVon9+iScxnhkPrJnay2m+cJ3Kil
         MgN821+BgQflXaFFcWp9Lfi1IMl3uwonSBoJgyUSGDm115Laa3TkKqrfWuLyF0DislEb
         UUEh9kSmHjwsmwbCEweDNulHf2n00rnf8e1unf+njK2Iqez0K13BOrTE/sRu2idUiP8t
         F/mAnBBrEYiGPHlQVWG5IvwtULY1zx0sgDk9eko0ZctAH5kGRjKcbUpgxqnl3bLsCWJV
         r1iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=pOpAMltBIwY7OkXIlEfK66erdgQAW+TjNrcFWmeLJK8=;
        b=qJDmDvpPVo+QyPyuVB3A3haSpA5jW+FlzOfYHtvJS+T8CHAOYeO+4tXV2i3PKzYf89
         +YiIbGsiF4gFzj4wWRUboAp41kvAifkXlK4E8pZ/ZjekXm2Z3VIe/jKKYmgZF3INhmgV
         NLXAyOMzfKW6XDSvJX+fwNhQTS2TY8j4Yz5Ut7O330jl31eh55Eu9tF2N137M7wCRGpS
         cHhuzFdVYtxdgvrK0AwMkf4bV6qTVQ7hjXrgB1PTJTTkHR5NxxeOIrJwf46qiab1Dc6D
         kj3v/VQ0DsgTdd4dNjv+YrSlobyYNWWUpxnPYPF+TiyRnuqUjxiOB6M+kS0Z/FU9xHrV
         tMyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d/0QyIe6";
       spf=pass (google.com: domain of 3-9c6ygukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-9C6YgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pOpAMltBIwY7OkXIlEfK66erdgQAW+TjNrcFWmeLJK8=;
        b=tCayq/F1C1F+qZV6IHdkW8w+O2sRpU7peOpIOLdejBXD2I6qolTXx2U6iIGANTJ+FG
         0ZwHJzvAF/mwRO9a5NkZSmS+dvCt7nmKoPfV4aM9Wbfwp/9p5Q6itnntve7RCNn6AacZ
         rIs1KDHBmzRrTIezP9NVbt51Y3ZozchnFsOP8AdqG4mXXxNPUB1oiEgeSq5JcfwEJw9L
         cUK3l59/DLP2K6D/wO9pE0t6KPAbuWldV/K2OS8tLv95ummegOPGpKIgFKudxi9BlETG
         FpTADrpx6ao8W9us5AjAs71iXEoSQfBGVSb+Dxx77T7PwpHvIGGHsxFR/Zhbyueco6az
         cO3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pOpAMltBIwY7OkXIlEfK66erdgQAW+TjNrcFWmeLJK8=;
        b=x7iF4pYEstTsVxDugNKEKWU67cofiobYExhJyjZOaPHUjO6Eqi5l0c33MWx27hdknO
         xcuysS/wDsKwkHOLebbc1hM2Ay6owccIVoBYal3kB8ewqnIEvMGFKCS/0hPdjnw6EMti
         AX28iyexEwl+CbZrpfJKsdqstvbbzprRyxetmV+BqlLRee1jr/11heUN6o5oD0IU6jJu
         UAwfOMBAUch4D0xFzxjBq4PyqiHYoYaVwbexm8WzgfLg4dbL21UB+RvFS4hF0UBJhuR5
         hrEi2dCzBwsonff8YXRZ3PKqAT3zGVIWCH5ObH66CeKEumTf+X8tzqGjwtRtb0fGDJnd
         g7uQ==
X-Gm-Message-State: AJIora865Tv+ZEGI5PmDxkmtb3kKdSfragjfHGegQehC3RDKrHYDHlp1
	Z2AT7oquwjHqYU2fnJ511F8=
X-Google-Smtp-Source: AGRyM1twjIRrMKJd5jkVmVijU2aL5S/nTNBGJ9ZibV1E4RdG1IcywlOgAQ7PLgtvLvJRXJ8p7nXMeQ==
X-Received: by 2002:a17:90b:4acb:b0:1ed:fef:5657 with SMTP id mh11-20020a17090b4acb00b001ed0fef5657mr25913388pjb.142.1656410364537;
        Tue, 28 Jun 2022 02:59:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2ccb:0:b0:411:51f1:84a8 with SMTP id s194-20020a632ccb000000b0041151f184a8ls1128515pgs.10.gmail;
 Tue, 28 Jun 2022 02:59:23 -0700 (PDT)
X-Received: by 2002:a63:ae03:0:b0:408:b78c:e284 with SMTP id q3-20020a63ae03000000b00408b78ce284mr16535916pgf.401.1656410363798;
        Tue, 28 Jun 2022 02:59:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410363; cv=none;
        d=google.com; s=arc-20160816;
        b=Taj7oz7ivQaQAnHG5Nf+TabPLu7LGtKf7Zjd+9zzAqOh0DefwnTpUunzNixQuXj0mU
         j5IOOfMNvXG/b5TYd/yO+/4ctzSv0it2tb+n+8giXT3h6ZuEWnPwFDDS2KOvquWjg/RQ
         zsJ3J+BUgDN3Etw5VcidmMBB5dGoICEVr8P807NlUkGzYAlWhZMxjIVjOPnwUtCUj3fW
         D1R/g+JeiHpD51cMez3pFlshhERSJWihrWUHb2+ukC8uj5vtZtJDKHj4QJOcnuIksn8r
         E9rD5CGpYMnXVIN6+ZbDP33aYUnssz2eJVjGYd1E3odVat+73Ai2l6V+vb+EiTE7j+AC
         D9MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=OJ712p3S1OHPRYNkQ5hzwMPKCksP3C27n0j33eqLkMg=;
        b=dF0UpaEFysSbH5IAXrv8nfddeUfD6DVp70D/SpZluTtjhE3ruD+on8nzJqfIeLJ4Tk
         5lYOMCDdCj7CyrXN/5aRXBrkVM99vttH84VxdZ+FOq5z+4QS7TB5Vm4ya1ovooofTS8S
         RfbXsDMrYKEbmaw+rH5RxfUTEe+rSd6c8iOIcQlin66uu54YqD7RuGpbSC80cjOGFaQg
         aF+Cyi9Nxt1pj3jqI1w6xzXQ2hCMHfinuDM8oLU/AK0LbwiuHoGiLo2NHhTZTxF9nwle
         P7YU+5o23AdqnINdCdkHZOT4qJzh7wSApYD8BV3Kbf1pNqDTlPLQCxbSXbLPjkN7WblX
         bL6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d/0QyIe6";
       spf=pass (google.com: domain of 3-9c6ygukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-9C6YgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id q3-20020a170902f78300b0016a11b71bfbsi483699pln.8.2022.06.28.02.59.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-9c6ygukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-31c095d07a8so3174167b3.18
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:23 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a25:1985:0:b0:66d:2027:1c7b with SMTP id
 127-20020a251985000000b0066d20271c7bmr3929985ybz.161.1656410363110; Tue, 28
 Jun 2022 02:59:23 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:29 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-10-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 09/13] locking/percpu-rwsem: Add percpu_is_write_locked()
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
 header.i=@google.com header.s=20210112 header.b="d/0QyIe6";       spf=pass
 (google.com: domain of 3-9c6ygukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-9C6YgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-10-elver%40google.com.

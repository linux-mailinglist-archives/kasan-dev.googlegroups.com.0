Return-Path: <kasan-dev+bncBC7OD3FKWUERBTMV36UQMGQETL7V42Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE8EB7D5221
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:54 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-581e74f7dd5sf6876963eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155213; cv=pass;
        d=google.com; s=arc-20160816;
        b=E75bFRn44PevrC7RfL8EydC6qPWSd8b/J6xDIVKaucW/6NMV2L3nmmqkeHM9KaN/h2
         4whJyfyCMW5N+fsG1EeOYNQoOvKCRCbJ5PBZ+9wOSmBfMCL8oTiO7HA3AiEGeO7aGfJC
         ONNBZWlwFIxhczzcNv8AIqk7f9tIWZPZbe+stP3fmyIGr8SdAQkq+qVteA/PN38WFaIw
         vaHquqn1nYgqSr94waawWMfeS7kkNoNUE/85vkFIFxWO240RT4hJfYndxIF205ayyIVs
         cdLM8TuQonuOExnvHqzI+IOjve4m7/VRAhSyr47pa/5v0RG29lgTVmArJQ55T7lQU07G
         oy3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kykdcuTTLy9JvcxcDY6iVrAVVquaiI7yUsapB9VraEA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=maclBMjG2pAsKZ4UyHfbWrkvhPndTDZ/rIXIQBWu9L3pJQzt9GQCox75RbER0o63CK
         wm38CpQg1jvkp4Xd1cOvykNjfEEVXmwGXnDYyI3Dg1Ch9c3UXZPR1ZWPnooYGVq/s4XN
         8VVhux9kgq8hgWwpmFRDsD645OI2WF65VVoHHgG9qSMqGXoN3yr+G9Cm5426RGGV4khN
         T0FJ4+Y/okirkem55riterQwQVoNi63KxhPAvNNNM0kFlakc1bR9RHf/779V3hnRhBJ3
         SIzHSp06Jfk69Wjm5/2PwdlAaXx53+eac7+pnttAaG/PBUULneMa1AssGQYYmumyqDah
         DmEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fU0z0HHK;
       spf=pass (google.com: domain of 3zmo3zqykcxehjgtcqvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zMo3ZQYKCXEhjgTcQVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155213; x=1698760013; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kykdcuTTLy9JvcxcDY6iVrAVVquaiI7yUsapB9VraEA=;
        b=IJkg7fjW7KBtSip5l9Qv/H9/6pAVxk15MGYwrGzKBtTznzFtukt+cAkqc+uPdQxCRo
         bAVfffgrCCV1IRtg9l7h3V+SLbm79CjOlUlTDrdC1dcaseMcRx+Sre2PjBg9+Iz6nLzF
         GHSjOCFnjJr+XrvlArDx0NHH0o14OJyT3rByk1+T9+wgZF/kheuu1luWq+zJ9kYlKID2
         lPx25Ahl77GqwWhs2mdsVD0eNiPrURgyMMTbANK7Cn3XqbhoL+j55alsqSn6d579mTjE
         QpZ0erLLfLVcZfXuWK1QKvBVa6Z1kWJVFSOfHxFTqtHWs84K4ED6tE86Q2luUpdVn5PH
         WZBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155213; x=1698760013;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kykdcuTTLy9JvcxcDY6iVrAVVquaiI7yUsapB9VraEA=;
        b=b8SJsXg25INGUhMxMCTRPNaRKwdrVTSDJxRMry6fnSxFo4ZrqMNEreNdMiSbclusYP
         nWnZsfkI1JbZpwgiypZrhz6L/ybFHhLojUOpcInUu7uEquK9V+JY7OTySaVyfGhNFGjV
         1Lr5GdVJUtlRaayDLhMf2G8MndiUaWs/xYboAMoSm/oT1lrDYu1IuVIGmdNiPTx/oUST
         pX4fyORzbF5S31KLK6Og6cQDS7js2enTWZcTzxNO5QkwBY+57hgjRJpw9j+R9uGls1zf
         fn5z+/UkLtyjyb55ABZ38aTLpjk+lDW41Q+gmNfx887L/+/jzYJzlLfKWVe7JwMhKpha
         yfOA==
X-Gm-Message-State: AOJu0YyaFVCSrOVnWUyk7YruPru6WLgxNr3n7bN3ewE8kjpwWNdCXweW
	vbcbXtqmsXy8uuYgHTcO4BQ=
X-Google-Smtp-Source: AGHT+IEyglukkhQeKlBQuYzz8YidGRjdX99I+1yHCmfAz16JLMFmOofFWqsSOGo6NjrcN5ZfE0Ac9g==
X-Received: by 2002:a05:6820:1c02:b0:584:1457:a52a with SMTP id cl2-20020a0568201c0200b005841457a52amr12196067oob.3.1698155213476;
        Tue, 24 Oct 2023 06:46:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:52d5:0:b0:581:daed:8418 with SMTP id d204-20020a4a52d5000000b00581daed8418ls1755009oob.2.-pod-prod-07-us;
 Tue, 24 Oct 2023 06:46:53 -0700 (PDT)
X-Received: by 2002:a9d:4d04:0:b0:6be:ffdd:efb9 with SMTP id n4-20020a9d4d04000000b006beffddefb9mr12509744otf.32.1698155212943;
        Tue, 24 Oct 2023 06:46:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155212; cv=none;
        d=google.com; s=arc-20160816;
        b=G9rPyZVEq0RBPRVCoPbOF+aoUXw0ratfoUZukHF5ebMEZM0MMYrO9e2sQinPhdoPEs
         xOQ78FzRh1QipFQ3IVwv6z2pEhCCWWuoW+P+vriqerW7yizaXu9jtUH6Zgcyzp0/0Nhx
         QRdjzjWO5FbHqbqNbN8xD8rqsVCVvGZCCqdDafe8xnIOdT5bTxKL7NPfD2DLq0uKpvZb
         f2rZKcimHRhnJYO9OOXGRcGO8CdyHp3SO4yFOEYCF8fU1xKQpBa+FtNUP/RdWOtxZFpJ
         3A6BllkU5J7HbYkkvMjY432pRZVVIo4SNiO+p5wDH7JNSozlQfKNPl6apEUYW2y/dS92
         Trpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r9ZaCKU38kmyhI7VEwX4KjtHXLgRMjapTHFgQ9SG6t0=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=EKwRjOxgiZ3NecFcFaj/nYemaRzISJ7cYGocllFmWc79vVHDqk2oZZqWVRfDdET6E5
         9GxVTUueEr2lD6aNJjoY+CSf8TVIbAKCcZgxBXyzaYBYQvt1IJDxS2+PqfLXfc0+Nfo/
         NrVjQv5B+RaBN/F1ro/BsET5ZZc+nqyALPu8ad5v5BOX5SNXS+DnUqedu1Gbg9S+HzpK
         1VKgT+O1osZvYYXFY1cwQpdrzfFwUGvcMTQ52Xy1Z6ydqyFIG5HI24qZBV6VrsL6Sf9c
         /8e1aEzRZo6O3D/UbAashMn9ijbhctIfGOcYVBFxy6Dwc0DXnG8FydswZM4J/znxdVhw
         7wGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fU0z0HHK;
       spf=pass (google.com: domain of 3zmo3zqykcxehjgtcqvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zMo3ZQYKCXEhjgTcQVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id dz26-20020a0568306d1a00b006c44affd0c6si775781otb.2.2023.10.24.06.46.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zmo3zqykcxehjgtcqvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a828bdcfbaso61798677b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:52 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:dfd0:0:b0:5a7:ad67:b4b6 with SMTP id
 i199-20020a0ddfd0000000b005a7ad67b4b6mr254303ywe.2.1698155212529; Tue, 24 Oct
 2023 06:46:52 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:02 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-6-surenb@google.com>
Subject: [PATCH v2 05/39] prandom: Remove unused include
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fU0z0HHK;       spf=pass
 (google.com: domain of 3zmo3zqykcxehjgtcqvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zMo3ZQYKCXEhjgTcQVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

prandom.h doesn't use percpu.h - this fixes some circular header issues.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/prandom.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/linux/prandom.h b/include/linux/prandom.h
index f2ed5b72b3d6..f7f1e5251c67 100644
--- a/include/linux/prandom.h
+++ b/include/linux/prandom.h
@@ -10,7 +10,6 @@
 
 #include <linux/types.h>
 #include <linux/once.h>
-#include <linux/percpu.h>
 #include <linux/random.h>
 
 struct rnd_state {
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-6-surenb%40google.com.

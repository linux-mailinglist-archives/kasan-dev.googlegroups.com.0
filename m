Return-Path: <kasan-dev+bncBC7OD3FKWUERBWWE6GXQMGQEE3A5HSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 46381885DB0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:47 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5a10683780dsf979068eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039066; cv=pass;
        d=google.com; s=arc-20160816;
        b=ESKwXVLyxp/SkAOwRMk70ypxWvwMe+2zzIG60jHzsNKdk5g+2fwB/G0MEcGX/6Ua1V
         zI+kP1z4LKIbDiVxXycA1Mmv3i7RhLI47sdYAtl+OjLrV6y6TWqbE08Y1Wd3mRiDq1dF
         Se7JP8Eg0BjXOOBn+aWGErk+yVlMMdrrECm466xjjiNF1WG/LmHfoHZhaaDhMxoTOnbI
         /UtX4cRFgHDvR1gp/qZjMN70HbgpBhQuqYZRacBsVdOEo1DuYKAx1D33gmiV6nZwsxSC
         805fPat2TkEw1EjRYnUMNEFCiAELL5QCe8OJd4DGGc85VGR+Jj3ULL6Ux2O+xc+qc3CN
         qDhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=uh608TVcIHIrWcKobnhplKzq6vM1o6A9c7llGIbsGsg=;
        fh=szvRRy2n9v9CfSSOosptphrgKIyfXEIuVvzEuZR/Dps=;
        b=XZ92XSnLWVBk+I7dZivwEklB/NDZnxUhKwOAm5vCzECzT2wEdQGxof+tK6r4Q1cFKQ
         b+Rl2/wXcPWbycD2erTMmhUlpTFZcnhYWdxA0kRSk1nm7/aL1cFDshEpjuNCQee1n+AF
         WyQYjzAPWW043ZSubl7ADT8KTl6i6QSxQKExO64U0mrT264ZhI+c50WZS+syetZQCAbq
         tZiCIJTZ08pTRzv8zgIOclXSybXI9ryFu7nfSRqGYSA0CPjq7cuH/EiEZkSKdOYiQCvr
         mA/VZ0UFfwuhZduuML62ThVOSlhgFssxDSHL1VHhT6Ea7YOdjy+HQ7FTLMJaSBDpNJFs
         +hwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DMWmFgZo;
       spf=pass (google.com: domain of 3wgl8zqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3WGL8ZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039066; x=1711643866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uh608TVcIHIrWcKobnhplKzq6vM1o6A9c7llGIbsGsg=;
        b=fT+JgqMV7A4wGxcsIw/98BZPDIF7JYyxmpu+99v98/aMRiXL38/muK1Oh6R9JPZd8Q
         Olbr4H/phyl+u5RySBcV1CDCEJdPSY4hnE7yVhC4HXzeNUr+xd4U8LR2FM6ZinRgfxNI
         WmHDPi/4zll4rAZOMQyCqIOy38NnoTyfdN5V4Qtfqeuj4B576QFFaE85EFrtYhc5fqNB
         p5PuS7Qgs75OMhRPce1l1/o4mNWsO3nuPKADcyQ0ukRJF6+p46S+RXhWE8ICCr39LSZs
         Ae/JglW/WUcdSQVgMbO4+aqMSApY/duTWMqV1ObLMiTdFVgctrFrDnbE9Eyrubv6FZsU
         Ujcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039066; x=1711643866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uh608TVcIHIrWcKobnhplKzq6vM1o6A9c7llGIbsGsg=;
        b=jDYkFJNxGaCbSqSujA9YIuiEIZECICGrm7Vmoj57+Gmd5+PB6vsOFV/9w2I5d9414o
         2qCLBLQTcAVsJ+l7TnPX+nVpQB/BLWtTXuXgT43280ptFtu2MF8yU1ZoA2k6dWuUHbfG
         p6C9ua3y3lFC59XUDlmdJLGnZCuuXZ+xZoB7uhEZtyQQvQZEUuaQhjqNsTFUo2/3FFu9
         U7mVR/BOek2kL+5b9eta8XrXE7jVU2eJgymISEw8h6bE0c5F3LaGrLPC7zLElF1svYek
         D+kWuCu3rUY9qlO3rqlAwuK4yGfsQNbSnqz8m0PHDUI9g1HlkqSSPz1VNAQTiZWhkk8Z
         98Wg==
X-Forwarded-Encrypted: i=2; AJvYcCX5JX3/oXISOIAcDZv+68GrMujkskRQHklD6lI5yL90XN5ny1I/3Uo5W4IzzxbroIT7ujan3ozwYTNKSRj2/G2FlLhqxECUkA==
X-Gm-Message-State: AOJu0YyCiAnDaIM0mJqTwTGmq4xYdYWq6R/fZ9cnFSZW7Yr1GZqXZ9h6
	QxY2UQk8SWyugUTmn+j6f5rdyrQkUvE6jo1YMQ4Di34AeU66Dhu6
X-Google-Smtp-Source: AGHT+IGcBc72BkfNe3Ukj/wVmdxmMoYQOM24jJ+s0vlNajMijPGqCSvtx+PC6DOukc2iKViLOBtMPw==
X-Received: by 2002:a05:6870:5251:b0:222:7217:f919 with SMTP id o17-20020a056870525100b002227217f919mr2893660oai.8.1711039066178;
        Thu, 21 Mar 2024 09:37:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5a94:b0:221:d814:2777 with SMTP id
 oo20-20020a0568715a9400b00221d8142777ls1611232oac.1.-pod-prod-04-us; Thu, 21
 Mar 2024 09:37:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX82FecRqd1bVxBU0sq3l1dQ3Yqc4SVZScChHHvyGBE7cGvQ62wTcZXrnXgM1r2gyh+Nvoe5aO/oYeEETFi3jNYCa8MQpmtHmAYig==
X-Received: by 2002:a05:6870:cd8c:b0:21f:aa57:4637 with SMTP id xb12-20020a056870cd8c00b0021faa574637mr2713376oab.58.1711039065286;
        Thu, 21 Mar 2024 09:37:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039065; cv=none;
        d=google.com; s=arc-20160816;
        b=NPWawO25AEyWDA/FQJ/vgVK+HXvNg0OfPzxMKjO7F/cb0T83dS3XAGzsE0Dk7GTDBP
         +LEyZzCxS/PaYA2lc2ZbdmrLEuRn3wP95l2Jb8aiCYSNEPiO+UpuayFrI/VpyO5Gtf1S
         XC1XtQDdAUHT5P5ZKIj54266hI1XQasp1EJI+Y69qg9wDtzd89NRBjfu2zN+xgbqLdTc
         tAyMZR8m2ohXgYWvTK44uZ6eUmh1Kax5WsTC31Mp3AjDl9mFG9gbDHRjzo10ZNo0Qqr6
         jp6DWsBiaYID0tVRX+tJ0/xZOyyG9wPGMxpQXwl7aFSiPx/0/NDbLlVMq9qGOyvVVR9r
         9ZdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=adETXft81L3mg8VeiLZhJ9Sn5YTIW37aD8rIZRQJCFY=;
        fh=IDEEIYn4v+TnMJzCL7ebHt18imYGYThGIYhojPmFMoA=;
        b=fvTW94PXU1YBJXk9SBYtjeoWK/r4i2YRY62oi648buIdj5hWipIO+XfK61zMrvyAMI
         JXVtzloJG2XaCb8urtE8WT9TEKxNllONXt0B10V7vXdMOnrpW6FsZJflmX0nUPJzWzsU
         DcSk4cryEes8Cg3d3/LV08WdlP9tNXW1Knkq6gnzAsPekIl8LdIphvAKPaqXvdUL5qSC
         ookn4G3LP9WZFASHX2vvGlIdB8Fn8V1gehsG3raXOJ9t5h+IKTfB8C2ivFgQ0g5i2s43
         hQPZyO6i8fnBkG09jbwl1qpGNkQO9G976AU/YF71CoHx5Ua/3h/vzVM2oJFVjq1sFMt2
         GXpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DMWmFgZo;
       spf=pass (google.com: domain of 3wgl8zqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3WGL8ZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id hm14-20020a0568701b8e00b00221d905d771si34653oab.2.2024.03.21.09.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wgl8zqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a605154d0so14619727b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3y8byREqJuLyRQQXMZo1BeQU015h69KPovZ4amqcJbttdYO2KVkUuSTQJBGcj7AKCRYXCNWHJN2klgrFoIu8ycMD5qT95qQJl9Q==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:690c:b06:b0:60c:cf91:53e0 with SMTP id
 cj6-20020a05690c0b0600b0060ccf9153e0mr3628ywb.1.1711039064823; Thu, 21 Mar
 2024 09:37:44 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:38 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-17-surenb@google.com>
Subject: [PATCH v6 16/37] mm: percpu: increase PERCPU_MODULE_RESERVE to
 accommodate allocation tags
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DMWmFgZo;       spf=pass
 (google.com: domain of 3wgl8zqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3WGL8ZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
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

As each allocation tag generates a per-cpu variable, more space is required
to store them. Increase PERCPU_MODULE_RESERVE to provide enough area. A
better long-term solution would be to allocate this memory dynamically.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Tejun Heo <tj@kernel.org>
---
 include/linux/percpu.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 8c677f185901..62b5eb45bd89 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -14,7 +14,11 @@
 
 /* enough to cover all DEFINE_PER_CPUs in modules */
 #ifdef CONFIG_MODULES
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+#define PERCPU_MODULE_RESERVE		(8 << 12)
+#else
 #define PERCPU_MODULE_RESERVE		(8 << 10)
+#endif
 #else
 #define PERCPU_MODULE_RESERVE		0
 #endif
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-17-surenb%40google.com.

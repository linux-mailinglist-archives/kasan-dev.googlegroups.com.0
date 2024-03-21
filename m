Return-Path: <kasan-dev+bncBC7OD3FKWUERBWGE6GXQMGQE4HKIFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C167B885DAF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:45 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5a4b916fd11sf1052663eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039064; cv=pass;
        d=google.com; s=arc-20160816;
        b=pWJFZa4mZigh1DDJqmT9H1iu8KFJ2gVCmDeBblJt1DlgSXgMfYBuLMVVFHPZ8lBC02
         7owslifoTOh/f0SxBqrpFT5ByJAK2lO0JBgLg6y12J+WiI2wlF50JNY/7AK2iX3c2931
         h9poc+5bEZV/tpNE7rgSFJpE4WCUSo80myTnSLbzycc/B1rVItUbIGxRxKVyDCQORnSf
         6uZ3DDaKKMQ7BSxELM0z3RQVGt9es8sDYcZZN32BAj1inu0KKFcwOjpJBkio5KH+s+yA
         7x0GYt7knK6h77LXQ4bKaZk+RrvxYJWzK9VTgUnJEBanYREsI/mV55UKODKslG3m35AU
         ewvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+VHtnrtH7uk7JY6t6G9s842ULNi49HdF/Ne/jqx1Vhc=;
        fh=BlTVIIe7U3MInL8MV2j/HvX61IwPrHdL07usXYRqjGA=;
        b=QkvCyO6YMgDt917qJgh2/Lr3jEXESsLOzwnor1rT5lXK2tDWMHPhhKqi9m+wWRHPqB
         b4c98w+IuXBLVJymRQ6N/h2zNAIhmQ3VBg4nES/lHsh2t3NnLRnGHJoTMMRdKsjnoG7B
         vfswdCjb+uP4ZkaDQv7yhVp6p77aB8U53kYJS99mja251zQYBykZ9pBTTg0k31J4kuA7
         FKIDCywMh4QmzoiJ3iPfkxJUJkCmqs8wYRbuISU07CVjcHjvuGwcYxuZFHODQ05NuDGz
         zInTyeaTwviu97EoSVSWE/AKq3oaT41o1KZBk+hjPGrgzYpPuyqx3pRi7m6qoGLbtAmC
         gRjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TfkXdYHw;
       spf=pass (google.com: domain of 3vml8zqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3VmL8ZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039064; x=1711643864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+VHtnrtH7uk7JY6t6G9s842ULNi49HdF/Ne/jqx1Vhc=;
        b=n/zt3dV4W9RDl+wnxdm1Xq2o4NTQ8lkAstFSRxcyVHfTlI2mF9pEagUfCB4LUTwtV8
         NhOXivCkTPrQytEvNxoZL+2JDpaZMN/iGNPfjwX2IyYOuOrDJcysAAmAFiKQ00brIJy5
         tqhUtYgFA3hYw+REXpQZ85vGLJj2Dre38bOyDEG4b8qPUB/n6CjVfaQKeSzsdEvPDU/t
         Q9RzZodIWtj8cglAIq1EVx/rN8sEuJGaRUzs+Ti2TIehdyO1/0jU9mBmRyjcJHIrjmpN
         s2B/P5lZ3MVPVJwfaToyDvZfHEG+vINODEqjGd5D5eJuEFFQ+niEh5k7h6pgYi8tSgmd
         tIyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039064; x=1711643864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+VHtnrtH7uk7JY6t6G9s842ULNi49HdF/Ne/jqx1Vhc=;
        b=jTRKZQQshnjLGbgW8cy04EmnCadhAOvZl+YdmO8BDGGGJivV5MxWyA0XnqF9Vywkv+
         WJShdDoYdjdC3kMdaaZjhOkteBz93cqOdBJhcRgP04wVEXeqSgPW3KqOlYcnQJjWZWyi
         BDPqEeu2e9x36xHDuGHHf4qbagMUuBoDmIyKnCIE66f9jVu1/uNu0Z1hbWwUYxlqgrn5
         I1gAc2+o+vGbhcBKvFFfxxqQ4L6Gn8BA0ZJ1B5vqmED1+2LNlrqXqUMiWmJhv50VgPUO
         TPaHB/I/xOSETRpWc+XVY/oV7ngnkG244uBXWHZla86UdidVrHr7h/KRzwA6tOkA5NHc
         u2vQ==
X-Forwarded-Encrypted: i=2; AJvYcCUQnyBqEEup6kFSJS5PwcXRh/f8YXIpWWuk4S928cOkkVGLrD5tB5Vo414Bjr74Hzec41GlS6Yq7eo/VQ3+C0UiyUy6h7mZdw==
X-Gm-Message-State: AOJu0YwReubL1hGdPsXMt70WeVcC9sZO3SWRsUDGYeXhqjV8kZlrghPu
	i20xFpU+ig5cKQYsXy+fdidQFvnyvIJUMMsBtSST3AEeGYQkW779
X-Google-Smtp-Source: AGHT+IH8U8ETODnGy1KirgSi8kX/BMvOFL8bxm4zKEf8wgasdH59gIlkMgbbTN1RoEFDWpFhGYmxSw==
X-Received: by 2002:a05:6820:200f:b0:5a4:55f5:e30d with SMTP id by15-20020a056820200f00b005a455f5e30dmr42385oob.3.1711039064421;
        Thu, 21 Mar 2024 09:37:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9b89:0:b0:5a5:119d:3afc with SMTP id x9-20020a4a9b89000000b005a5119d3afcls291185ooj.0.-pod-prod-06-us;
 Thu, 21 Mar 2024 09:37:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqrJc678cqsWVHN/neMOfPvej0BMNAHRuw+TZ2aM3VVPU0dxZ+AHI+9gkNfzAE+JGMW4k1xecxF+CWvSFs97A5X0z4pISKLKxoMg==
X-Received: by 2002:a9d:6188:0:b0:6e6:a6fb:7a0d with SMTP id g8-20020a9d6188000000b006e6a6fb7a0dmr5472808otk.24.1711039063415;
        Thu, 21 Mar 2024 09:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039063; cv=none;
        d=google.com; s=arc-20160816;
        b=Lmdx6oHpopmEi0LQ2abSss/5Rm7kb1M1vwNqH0jTTzNQbk13Fke6C+aVM0Yw7SW/Qd
         UKj3E3uHBAxSq3LrNyeVWWT0mTmnera2mjEYQEA3ALwgFTsTTIm5mSUZyDZK3c2SXhxb
         Hg4Jnu4WOrgxe4MtekvV0owGiy9rnA6Jzsc7PRPEF43v2/gwQnxWP1jXD+ODV1TGr518
         JwfA6g7MpU8mNMofp2nCxB7VaJArwRUKzbnpwRuJ8/pSyajjN6B/IQMjT4uuaaVrFqDt
         VCuVDqFc078E/y7d9+HqRjg+XDxHxyjRSUuyHxxmPfMY75ZO0k20T0s7/FrRZd2mjedK
         qaog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BfPuXrQNw6sP43MOvy7juBQZEF5XCZI3rVOwMSUBcyU=;
        fh=l5t0SMmJydTjsig78YNc7GHUG7GWlxsR3rKtxM893xk=;
        b=xWbb9WJs9wZOA5sDyOfYbYmkwbZlBgcKllWNvOPwAqrHkWaGwlTfGt668g6bUoVrVz
         5LV/5QTSbmB+4kpSt/j6ZcLlPOWfvT89CWDsTjqMoRYmA/s3hhk8hgk5XFGvuLUN77ve
         9wuCWAo/EmZHxe1DhLS1NbliU+ouIup6rGCUpW/ANuv53CQ2uJY4j3J/2uuEZv4e81pj
         xawiwaUhb3+mjO9ZG8yo7ol+x+KEuMO7MMaXNEKRzm5AhBPYUx54PWE6O6l2vsdSmc4i
         oEN5/B954fZXIGd16UK9vQXkEuI9ZIukfVI1ZkXt5miNdBMjma3VCvkbkfWux8zNKnFF
         8pXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TfkXdYHw;
       spf=pass (google.com: domain of 3vml8zqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3VmL8ZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id ee14-20020a0568306f0e00b006e6839fcce8si29152otb.0.2024.03.21.09.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vml8zqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60a0a5bf550so21840847b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAZ+HLNIFKf4aygWlkBhgAdpAUXRG6RB8DlaPsm/esU0MHPUxunZribRd7Cq4zGbNhci3msNXz7kGcgsRH5ErQwjbzyI8/TBRdXw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:690c:39b:b0:60c:d162:7abc with SMTP id
 bh27-20020a05690c039b00b0060cd1627abcmr2322702ywb.1.1711039062719; Thu, 21
 Mar 2024 09:37:42 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:37 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-16-surenb@google.com>
Subject: [PATCH v6 15/37] lib: introduce early boot parameter to avoid
 page_ext memory overhead
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
 header.i=@google.com header.s=20230601 header.b=TfkXdYHw;       spf=pass
 (google.com: domain of 3vml8zqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3VmL8ZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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

The highest memory overhead from memory allocation profiling comes from
page_ext objects. This overhead exists even if the feature is disabled
but compiled-in. To avoid it, introduce an early boot parameter that
prevents page_ext object creation. The new boot parameter is a tri-state
with possible values of 0|1|never. When it is set to "never" the
memory allocation profiling support is disabled, and overhead is minimized
(currently no page_ext objects are allocated, in the future more overhead
might be eliminated). As a result we also lose ability to enable memory
allocation profiling at runtime (because there is no space to store
alloctag references). Runtime sysctrl becomes read-only if the early boot
parameter was set to "never". Note that the default value of this boot
parameter depends on the CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
configuration. When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n
the boot parameter is set to "never", therefore eliminating any overhead.
CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y results in boot parameter
being set to 1 (enabled). This allows distributions to avoid any overhead
by setting CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n config and
with no changes to the kernel command line.
We reuse sysctl.vm.mem_profiling boot parameter name in order to avoid
introducing yet another control. This change turns it into a tri-state
early boot parameter.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 lib/alloc_tag.c | 41 ++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 40 insertions(+), 1 deletion(-)

diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index cb5adec4b2e2..617c2fbb6673 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -116,9 +116,46 @@ static bool alloc_tag_module_unload(struct codetag_type *cttype,
 	return module_unused;
 }
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+static bool mem_profiling_support __meminitdata = true;
+#else
+static bool mem_profiling_support __meminitdata;
+#endif
+
+static int __init setup_early_mem_profiling(char *str)
+{
+	bool enable;
+
+	if (!str || !str[0])
+		return -EINVAL;
+
+	if (!strncmp(str, "never", 5)) {
+		enable = false;
+		mem_profiling_support = false;
+	} else {
+		int res;
+
+		res = kstrtobool(str, &enable);
+		if (res)
+			return res;
+
+		mem_profiling_support = true;
+	}
+
+	if (enable != static_key_enabled(&mem_alloc_profiling_key)) {
+		if (enable)
+			static_branch_enable(&mem_alloc_profiling_key);
+		else
+			static_branch_disable(&mem_alloc_profiling_key);
+	}
+
+	return 0;
+}
+early_param("sysctl.vm.mem_profiling", setup_early_mem_profiling);
+
 static __init bool need_page_alloc_tagging(void)
 {
-	return true;
+	return mem_profiling_support;
 }
 
 static __init void init_page_alloc_tagging(void)
@@ -158,6 +195,8 @@ static int __init alloc_tag_init(void)
 	if (IS_ERR_OR_NULL(alloc_tag_cttype))
 		return PTR_ERR(alloc_tag_cttype);
 
+	if (!mem_profiling_support)
+		memory_allocation_profiling_sysctls[0].mode = 0444;
 	register_sysctl_init("vm", memory_allocation_profiling_sysctls);
 	procfs_init();
 
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-16-surenb%40google.com.

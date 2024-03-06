Return-Path: <kasan-dev+bncBC7OD3FKWUERBDXKUKXQMGQEIQFEVRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6721B873E85
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:20 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf122295ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749519; cv=pass;
        d=google.com; s=arc-20160816;
        b=udalbY6IVUv7AqjVCdaDOEh+dmv29BCSZTYhAM5nIQ6OJcd+tv7NLipDhwKEFbC46O
         ztS+vuVU/iaoGwUMZPH8OtrI121/9ELnN5+qzvCtMO6MPjA877R36di4MPreYUjjHeFQ
         IeEwnGKnQ6Nv/OsEzcGH45GdmmpxIa0txotQh24x8q/L7O96FrsRQ7xOYZGvLbwETA0H
         hQ+NtxCzbeczUdtxFcGdWHb5UGTRuztUVaFvEKoI0ge5qG8bNXFJ3bMrZel2VyHRWoPJ
         D+ugSITLYMpcwuwKNDf793pPmSbvx9BIPK6LgExSPgyaHsP7AjM3Hm0c9ZjhNA7cY/q0
         ZtAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nYDhUl0x3vy+nMxpBwEGnCl5Kj9HVE3wW1BnfBHv8hs=;
        fh=6yiApfzGrbwcfKDMDZh6WlpnJOjgjN+p6QN5Ps2nkPI=;
        b=Kj+GxUs/y9DhFsyic+g/PXZ2CLziqvrY/P+02EkDvQ2AyH0iALY7XICqb2cF9fRnj5
         fa9q4A0GP1k0GQF2GcSMjlD0jicXe6byNcCzdk6u3KTtxt9Ty4BqdzwQzLPP/vSWr4e2
         Y0kgW2vHh1ecaHIOqV73qvGks6PAjYWiz5sKLGObwcUihc3bhpTobRzb0cGGDECBPRWy
         KfFiHUFq2XIZWLulsCEb4CoA+BRnZDdjdBNPbgteuhgYFiwW1VPin3xFNrB844FyVHAd
         yR5HmMFl1G7DtqiuX4ajzAQq/chJaYvBNORqPxOT5uDWiJ4/kfyuxkzQXdwMkGQApuBM
         pZuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xeSoUiJF;
       spf=pass (google.com: domain of 3dlxozqykcu89b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DLXoZQYKCU89B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749519; x=1710354319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nYDhUl0x3vy+nMxpBwEGnCl5Kj9HVE3wW1BnfBHv8hs=;
        b=Q1TbSTLyB+A0+Yx5UmF7xjhNOQaOloOKtHhO/g4FHFBU9XQpEoD3U+DTVhijTDIYkZ
         xPYIO+shLf+s4az7iT/iJaqCyeqoZyKM7WX1DS5tD9MrjbIfHJImhF0cBLBRtIdXJEpa
         WYKuxw0uTD8Vn8oQzbk8aU0ZTLcBMs0mKPLJC0n1km+2g8UaHqSCnfzwar9/QDpEserN
         TuXNSoL4p9Dg5dsTGcgOegv/RJQTULeiD6pk23HN2zfmH0fdqjsZ8j/HeJKhJ14ATgX1
         jgccCsdozjnKCAkxj5lDNRigFM+Y2kiemqLmFXvOW9fp5pHAL9popRKCzk381bgiGk/E
         t9rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749519; x=1710354319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nYDhUl0x3vy+nMxpBwEGnCl5Kj9HVE3wW1BnfBHv8hs=;
        b=N0H/ZRGUU2P0IZqSKCCDIKXu375LZI398vRmKo3E8jVg9x22RLp0OzOJXOrLZ3hk1j
         y+++eTs5IoBWNT8KYQvBkpDKIPE7yf55bQrbyYY46xRrCOgJsajDLLdOoaxzlubf7zMJ
         QMCJUdq6OnApXpy2NI6DNbKyrym+OihtGU7IZR4qmBxM+sMpbrBUukSaf68fmzRG1eM9
         ICmvhfvWK3Go3MOrriOcTUu5B1QOkcU2etXgeI1rxdA6EaT/VKIGo2P5nxEoC7Oc0qHO
         GIJflp5ZioWaag9CcG2A6Co6UdORMNuBkSnCXOdGeS3RHsGchuvuSNqFcKCVtBMB0T9V
         aNEg==
X-Forwarded-Encrypted: i=2; AJvYcCV4wCPGW0LJTGMO8D+rxNhxhuHkLWS4ovPy6QZwooIx2kgPzx20UoZMyf3q5AKGbIKjYAoVusXm+r8ficewywUF9KQt9cIAzQ==
X-Gm-Message-State: AOJu0YytJPgrIZVHmaaDIgh4FTdy2NhsVAX4uQdWwyuJJVGtH1ARdC9w
	KCr63I5BYS1cdm+2i4iiSI+yGeOqiOg+rT+thnyYnWfFJVo0vzh5
X-Google-Smtp-Source: AGHT+IFjq6Fhgj3ovrLouxns6FEUsilvXLcqydjC/5Y3h/LHopt5NVzHuYKN2qI9wH8TQdDnAJggUQ==
X-Received: by 2002:a17:902:e744:b0:1dc:dfd0:f3da with SMTP id p4-20020a170902e74400b001dcdfd0f3damr46452plf.28.1709749519036;
        Wed, 06 Mar 2024 10:25:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1db:2ca9:b5b8 with SMTP id
 y17-20020a17090322d100b001db2ca9b5b8ls80963plg.1.-pod-prod-07-us; Wed, 06 Mar
 2024 10:25:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUmNyD0491NyglVhvRe6VLYeYdZ9QPyHZ8lL2SP9P9JnofTFLJhGLiFQWrbXrpSw41NkXilTiDj++JtsF109OOpk+OnKSQaspiMjA==
X-Received: by 2002:a17:902:e5d0:b0:1dc:fc86:2e7a with SMTP id u16-20020a170902e5d000b001dcfc862e7amr7146521plf.59.1709749517974;
        Wed, 06 Mar 2024 10:25:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749517; cv=none;
        d=google.com; s=arc-20160816;
        b=AYrstbKDP/VcIq02xE12VxatvEJ4sjaBhCPEw6hFPe2WwgJhNqj/XvVffDZ6LSUiTg
         zF8wauk2XtVL/gtnlchvueTx7/hqFtTaEEPH5dKKQJ5EMyII2fGv+dohVWT8sqLXBABI
         I+/mg8gOIvrlSpPx7GgitBOgeC+5/R2jIxS2UQ9T1ushK49InvdX57FwmOWFCwQTw29G
         cu5d+ISq5LyoASLJQiPwDvxHIH+z6zw14ti2z7G1YjNULo0Ah/+gH2y4jQgRwgMVHd5U
         1nf7+qo5ynGZfH7CbACPwwN0i76VrWV6Dw4VE3T3NiDB/mEqhmmVKcI86MW9IunikP70
         49eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bHZwja06se4PI5NvmXw6g0w6FqOSRgAaf+Zh29a7Axs=;
        fh=CzsyDPLNpE0KZKu8kJ5JP0coh8W7fWn4G7/mFw12QQ0=;
        b=OrY9d1cnaJLzo6Ih1+tHB8P9lDcbZAnQviDfREacfiKbn7jy3EuZ+m57l3CNZLNrs4
         zxq84vmCALxp8gmRaWbENB5Yq/mldwBZz8qZ6HL7G/vE91Cp+lufUMpV6HNinB5KAgog
         BKW7Ozq8Dqcfs5QjeUnokX8/afEy1ME7MkuJMYAvF0xcTdMMK88fMcrQltiqZ+xQRPV8
         xLQhD3qL9+ULTDpdUICngpYjKW/hXbpNjo8a7x73gHKIv99qja7HHUN+mIBAvdF14oVi
         s9sVoiMJF6YVvLGn7wAdNzmsIccbCaMeRTSv1vAAqpuHgy1TPgCq3mGKBIWSiM520Sbj
         eBPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xeSoUiJF;
       spf=pass (google.com: domain of 3dlxozqykcu89b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DLXoZQYKCU89B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id s3-20020a170903200300b001dd46c6d2d9si38483pla.3.2024.03.06.10.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dlxozqykcu89b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b2682870so11715696276.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWFnmpgSoG6kEcTgudQWXDxB3fyHUuhgh7VIHmirM6SzhAel6ijoPYWAzu/ut1sh8ZGEsHkg0Ki26RBHQThvaX8ceRR/FMBUbmbQg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:18c9:b0:dcd:5e5d:458b with SMTP id
 ck9-20020a05690218c900b00dcd5e5d458bmr4001383ybb.3.1709749516858; Wed, 06 Mar
 2024 10:25:16 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:13 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-16-surenb@google.com>
Subject: [PATCH v5 15/37] lib: introduce early boot parameter to avoid
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=xeSoUiJF;       spf=pass
 (google.com: domain of 3dlxozqykcu89b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DLXoZQYKCU89B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-16-surenb%40google.com.

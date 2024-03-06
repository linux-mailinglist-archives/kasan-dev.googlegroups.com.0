Return-Path: <kasan-dev+bncBC7OD3FKWUERBHPKUKXQMGQESQVKEQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EF2E873E92
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:35 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1dc8e1a6011sf75965ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749533; cv=pass;
        d=google.com; s=arc-20160816;
        b=X32JTTTgIsdapep9xxogNiWd+s/AR+9Z1BpVnpi8uCbAE8RdLnThx4Z92nHfqOLkKL
         OAbKLYaEqQocdhp4fZ2pTZxNIL87qeOfUJZDzP9Gab/C/f1//rmx1sPKc5xdA4i1Awbx
         tAok9C3DCEfWM8Hhy9s4QZFeLJ/s8Pr54G7nYfWwlqOSNm9aeX3OtJtRoNDl22oNdkbV
         UxyM9TlT5/pv9EY/FUfl4GSDk+7i2GXbMf5zgoTszJ56ysKCT+nt3i93PPLOjcjyviMF
         5Hb9zQ0La1sdEswjdBdVxwBKfrD14paU9UmYdKANNN8k383Ekd0rEjpRArs1NfiSP6vP
         PjOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lIBaxL/vc6+0ZQabyZtlFeIehw7sWZ/rAfF4szhyeDc=;
        fh=v3P0LWfYb+QnrQaukciu/LZxgEf6O/bDAdTBM+kd3aQ=;
        b=I4Dt/nvfNqnp19DtApMFvSLzXmVdfz1XzvIljir9IYmrcIapIWtR4f1mga8FQTOeg6
         0kMmI9stqjH4TtocLh3SSRCEUSmH6Edy/1qVMhGtEBw5XYAIaY8gu8cC1y61Pa4uaav8
         MvXnCmOEvw9q5ZPPI+9859gx+zJt6BnvM12nB8hjPq6r5V8V79x1lQTqn6s/DdxzDL70
         XE5b7H1y++HDKagM5oG5HhVKRWpXQJDO9iy6oY/ojO2U9e6WQepHqeNlKy71yYmbAn4M
         fmLNyvCKpyecZyxOaNWjS/bt66dzvOjs4FP8Sk4T5vJmpi4sCtyMX0FI4teO63XLMpgc
         YFxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JqRH0gfk;
       spf=pass (google.com: domain of 3hlxozqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HLXoZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749533; x=1710354333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lIBaxL/vc6+0ZQabyZtlFeIehw7sWZ/rAfF4szhyeDc=;
        b=RkutpPwMuWW4FIomNU6CKAqES/0oiMcH1UNCSBjMn0jnXCzEspcjRmsghYIz4mON+K
         kZSbFjP7Q1E+H6z80vqPzNQpkUhr0BM6bJIgf4U1ZlJX24tVoTNXVEmkSV7MnQItDL4F
         xdLuu0RsUwOssQaxQXb6EgKMAFavFOLDe8rLgkgbNFwaNY7J42J704ayDp1sernyPsAw
         aqTa4DlhGgULUJy3XsHE5+AcIW6x20TARfMkgQMwb90aP85bzreFwBhXLexJlYTkJdPY
         pYy9arGpC7TpKkTnAYmp77BmdzW5/s6vOHeab+UTexQz3ESwyV6MygKzZPEOrUe9/Pb1
         R8CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749533; x=1710354333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lIBaxL/vc6+0ZQabyZtlFeIehw7sWZ/rAfF4szhyeDc=;
        b=wIpJG7IgBZwdpcWYmYrNl1dMQkzmoemLF0K+n/ozbLuP5PZX6f2ZPgQOvP7H7dWYM4
         wOESYL6zy65Ej0ajGeuFGZX5aMeFuKut0GLM+A1Kro+3YxHcFsiHGfo6KpQ6lXF2TbUf
         +D72MUNHBkkHrlUafUizB7cRiaMPGOvFsIRGniinjKfLs5NTQtmSEUUjRWpLdc7ecYrV
         uUQI3/ZmdIawGYSu5uRNkSHl8zx0OEAXogfL8Ze8EP9sQZkURxydlgtVsqaZM3dJzVZP
         w3wreYSUvjO69ysp16OVVdeaO5Z2rF2tYQCg4HRQ19nRi3T5Y4Rd5h1QRqANAUC0hNRV
         1vUQ==
X-Forwarded-Encrypted: i=2; AJvYcCXx7Jzw/hsSdwn7EWXTVR2Zhkdf3S8p3/Puq+iNFuT+AZU2v1ouum07aN2OFbVxyk+g+4/uNXj8AiumLNEQs6JEGO5ChIJ8iQ==
X-Gm-Message-State: AOJu0YzW9BaBduC7GelZoxpXUlAr8kGPzqa1T4UC5zymgo2ucu8NRw5F
	fk4QyT4PqvQbQ09QzilIMZOexz7vEXkLipP70oeAiz6z3YfVaGm+
X-Google-Smtp-Source: AGHT+IG5qmJIkANBMbLwMO4y3IJHsDVm5Z+62MA/Gbh5DltW6ECagWBNVjMm+39sBaAPpya41GlJXw==
X-Received: by 2002:a17:902:edc2:b0:1dc:8e13:74ce with SMTP id q2-20020a170902edc200b001dc8e1374cemr5175008plk.17.1709749533656;
        Wed, 06 Mar 2024 10:25:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1d7:6a5d:5a9e with SMTP id
 d3-20020a170903230300b001d76a5d5a9els92531plh.1.-pod-prod-06-us; Wed, 06 Mar
 2024 10:25:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMGml51XohZVFo+SI0SF+cz/9uXxDjEvpwCmv3N3VN0WcSMnKHlm3UO3nN14XBlWsOI0yKmvnGMcW3aoccmeRS73B926g68ldp5g==
X-Received: by 2002:a17:902:ea0b:b0:1dc:8790:6824 with SMTP id s11-20020a170902ea0b00b001dc87906824mr7581858plg.15.1709749532578;
        Wed, 06 Mar 2024 10:25:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749532; cv=none;
        d=google.com; s=arc-20160816;
        b=DzY1hlHJO5s7GEwFzny9opM/T7TTtysSPdXmEoCeXUZCaFPSz+Y6MLEoIXfI5Hsz+D
         PI2Fh3X3Hmx3TbMTSKMgUTvhbpQCmB9iL8H1DAdruj/PZP89Ld133JxPh7PZMvBtmQyt
         1ocAGGOUMTrAbqj95MzQyXkTaVsqg7tC8lCMDQMDXVt/9I3o0DYP1sHGPUez54lkbMO7
         nv4I4n6WQr0gsGpjPGf7Ci4eX7MJbFUiDzd+PsMlOFTjQ/49wp0ZhQ6R0Ioau06M0g6i
         LTL3OVuanmo048dnUWXNs4UgaBpqp7zl9sCcfKxR1mnyHqnqu1pMNzywVbrd4RByid5w
         2egw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rg6IJ0Q4L7KBxRODnLb4yefimTum4BvWKaOTt5/YB2o=;
        fh=mEEaAzzl2DhYmxw3FHxlUAb8petEaw9M2vP7Vzplw8I=;
        b=FJBiVl+WI7NcNlhvlIqITlvIIsMpFUyyGFkyoRQf5cdLw1SxfG5fADjb9YYRMQF1Ng
         hgtMhvJw5tB7X8ofo30RR/LuN3phswv7dy+S2ou97+po+l9kMmnBVVtnl7otTba10siw
         +Sm17xOt1KQn5CpYNkC0e0yEWhpXFqLNjAFndchzLdHKRMiPisTHsh2UDu8p3uIBctKf
         gKKhNwwIZ5v+6aMKkv5gxEubT03Cup6eDG/bq75cEt05QKbna3eMskQPHXTVxK4bTg9W
         AZINlRLB6F0DJ+dGg2i+QtM1uDjbiZuPutVqbTub9Pae1fSwxNeWz6E7vrD7xw8s1nyx
         8khw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JqRH0gfk;
       spf=pass (google.com: domain of 3hlxozqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HLXoZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id lg11-20020a170902fb8b00b001db63388676si985672plb.8.2024.03.06.10.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hlxozqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60971264c48so593057b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXThpKqKPqXQh0Q9e5OS8ofsV5/862yD9b/U6DKMYO4oZdSPhnqog8GU002BcE8XJzAO1TyQ2/yefpGmOyDOzLdidbmVcxbeLwZ0A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a81:9945:0:b0:609:781f:a7ab with SMTP id
 q66-20020a819945000000b00609781fa7abmr3355582ywg.1.1709749532080; Wed, 06 Mar
 2024 10:25:32 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:20 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-23-surenb@google.com>
Subject: [PATCH v5 22/37] lib: add codetag reference into slabobj_ext
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
 header.i=@google.com header.s=20230601 header.b=JqRH0gfk;       spf=pass
 (google.com: domain of 3hlxozqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HLXoZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
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

To store code tag for every slab object, a codetag reference is embedded
into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 2 files changed, 6 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 7709fc3f8f5f..33cdb995751e 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1652,7 +1652,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 3e06320474d4..dfb5a03aa47b 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -979,6 +979,7 @@ config MEM_ALLOC_PROFILING
 	depends on !DEBUG_FORCE_WEAK_PER_CPU
 	select CODE_TAGGING
 	select PAGE_EXTENSION
+	select SLAB_OBJ_EXT
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-23-surenb%40google.com.

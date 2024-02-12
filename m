Return-Path: <kasan-dev+bncBC7OD3FKWUERBQNAVKXAMGQE6W5EV2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A6D69851FDE
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:18 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-3bd36b9fdafsf4657226b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774017; cv=pass;
        d=google.com; s=arc-20160816;
        b=x6M8p1paigeBWP293BJPlYq0D3cPr7C7T9nntwb7DfcoQvQCKG2XEMI7quvfMbCiYU
         tmKpHzZYjMnl3N0NMYaAnjLA1mGQdQErEqH6jXnNtLZiR1fgtAAg6Ti0ET67wghKN/Gk
         ecuW9LUVR+hwP2O0QsUOddJ46sY0rbGl7R+ut38dPB73vBI168j6mQHj79tJq4MDZ8nf
         fxyzNHZU69acCsY4e5LKkP4PFGh9XrfEMBkVtJAkIaVXIy3mBZ8UJotaZ+mx5d6XO4q5
         I3kluDgwUjBuXSZxzDRH2YXJHxauZtXCE3ZuAcocXRjSxDXReRZaMDk59S3Mmds/fZue
         TuXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TW28X5zkBKQ68UYSs186WxT2N4WRS+QYp+/kZp5xzb0=;
        fh=/y0oQwt19XYqS6+nNhAwFDeufa2cj/jFm5e6Sb3Kni4=;
        b=WexJS3OepnM94nAJupd6XoF3i4kEFCDjCTNgU7geyCQRJNgNinwkDE1BMBkxiGSfwl
         EVuwR6iQEoaLzIHomQIC8hid7R3ekAmOkZZDBNEeIkCb076qo/RnI81oxWNbznOFng5/
         R+d+ulpht0lY5iIwHeWQMDNged+nQUb0mOTaONFD6eRwezco/zO4sDsVk8GmEI+ec3ta
         tml72vCAgWC9pjDAufCuHDpxW4Hl4pnMApkeFu04SyG/P06YSxSlTWitD4wTHhah5iHc
         cttPaO2hTHtbWBoaRV/DrwevmUahOmiKNLMSiM80Ue6QV9I0qdVwcwiH5+8t5eJlbUgz
         Uk2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YT5Fdnp4;
       spf=pass (google.com: domain of 3qjdkzqykcb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QJDKZQYKCb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774017; x=1708378817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TW28X5zkBKQ68UYSs186WxT2N4WRS+QYp+/kZp5xzb0=;
        b=cBROhgKY2ZDRhsd13GwGddhbCDFcBDNQlfp6jH0J9DKrnYhwPID7mUXSxvsSyECsrl
         3TxYwI4B35eSrsZmOkDD2yQi0KJAoUEcHq3nf4pVSHjRXOe6Msh2yVpqqIhIn5mWGpqB
         CjvcTX0l+KE5q3gn7cp9431t2GN0uVcQh+EdtejDZ+swSgM8a8bcj4QmsWebU+8I676m
         Cg07lGLkK/NPIRCPFbSohtPKMBdax9j3WsdAo8x9XZB8I0e2QHCT8O1RNALJCTd7dOPf
         nShPJD+EEHYOoJKKP6UKGIEw5VtM0LfhOAIRILgTM575PhedJ81dzd0Q2KmzAG1djoM+
         +WjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774017; x=1708378817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TW28X5zkBKQ68UYSs186WxT2N4WRS+QYp+/kZp5xzb0=;
        b=K8LWqIeBsSufX1bFZr7pKSRNCBkCOulIXZQzLvdFr36YB4XvDr68uabdhua09PNzGV
         X4L1yXUYuB1esIYMqZhQYh6Gky6umOgNtS/FPk7/p+23UANvyeN2yh4Nkc/QA0iNM+v8
         sMjsLxndI1sJZdGbyeCleEuM+BN8UlR+LMqt1rkSCtA/f4ejgk6wVegmK0jpny0p2Ux5
         i4u57D87rvqfMrGw9rZD8T0MGt9+IYKzIzS1Yar+/w7dkjru3ucTr8K9GCytVuvVNCi8
         8zmSyh+ujNhPjBeiJiKQ7trCgyWt1MdhS1LFhKwzQrCoUEo+Rn6DxSnkrYHPPz5qLEIY
         +Y6g==
X-Forwarded-Encrypted: i=2; AJvYcCWhKsy3/nxN4KmuperhGkbVPTNvR/uTgo3Pe/5l6cvol4wgmg2WXIb23RmKY/Z/ilULbElTRKtPRtxaSXr69AmU4FbwrGqy1A==
X-Gm-Message-State: AOJu0Yxa+zaGtL0ui9McAM/am+BgtPJ8sGDMr2JkaURywH1jHlHKeoaq
	3Klfoththpbk15pgIqSlHthbonjbiMQ4T+yFU7KZMcyTDuA4z5k9
X-Google-Smtp-Source: AGHT+IHdcvrF4EhFN581xcbQ6tXA1IsUaYjm8QdJFZuaC53v60ZUjzy9cWxKx2z+PTFi4KOLS6DxDg==
X-Received: by 2002:a05:6870:514f:b0:21a:323e:f392 with SMTP id z15-20020a056870514f00b0021a323ef392mr8062422oak.27.1707774017497;
        Mon, 12 Feb 2024 13:40:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4406:b0:21a:c58:97b5 with SMTP id
 nd6-20020a056871440600b0021a0c5897b5ls850897oab.1.-pod-prod-03-us; Mon, 12
 Feb 2024 13:40:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWe2jJ9UPOMHz7Z92116j9KPZscd0nWs81k0uASwF79hFZovjKw/x0KKkCWhamrGi9lIIwfQezyRIgUg3Ii1NXtu2OzQKY5KETx+Q==
X-Received: by 2002:a05:6870:eca6:b0:219:27ff:ca86 with SMTP id eo38-20020a056870eca600b0021927ffca86mr7810495oab.40.1707774016835;
        Mon, 12 Feb 2024 13:40:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774016; cv=none;
        d=google.com; s=arc-20160816;
        b=YVApMMRNA5G8g8/u/8KtqDGC+l03oGgq1q3OprsPqDtiqmhlcAndjS/PL/KK/L8ysx
         5Z/z7fV7zq2woKoYqBYMiiP9ED5pV1aAVEGHvW8HQJ47L+ERbho/629E82wXxKPjrfx+
         01Bq7ovRY8De6+KO3zKDKy6Gt2feofs9SMi6cQt/ZkRRemXNYjOecjpERC5d98aBNEjI
         bDamq+JNHn1ZSXaUmxM+k7k4XpSNFDhDQbhZVuO6juCLXVspl+H8MDDwoEUoD4L62rzo
         NZEXdm/loF5Dr8KofdnFIp3WogSkZMY4JyMNBIk3IDlgG1OzKy8hZvPZpptY60FfElO3
         Roxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xFf/g8Eh9xc1yf0azF3fMp/AEmHqfeMm/yqsFpU3vIo=;
        fh=K85D8+z7iZK66L9y5o1ifew2dw0c+XAo/fsXspidA68=;
        b=lFrH/wYFtlpbrqn+BjYWNJ4jwh18usx4efZATchFB4ZUw25uuDNv0SmSlTfRHAqF1v
         IUby2dJT5SI8LZE++h7LJ0/5G62sTrJNwV3dsbvJtDO6ylV/+AYWSOZVFZlezQHPxROg
         +XEDk4np8udP7ARRNpOssJ0ABMPsQrN/2Rldf1rTJnIUIiqzSSZJs9HMEnpyqS9RgKRo
         eZPXC9n38k3o+Rua231I68U+Kx4+rlAQx4i47cDK0nwU6d5MdqY5XT2zgcjo9X5c320o
         YTYhVaMPiUtSP/bsrFFE6WT1emXuj6KYFp4bAqxTXtjkLioBDDwgwo3lSbJJN5tSFt5R
         uLJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YT5Fdnp4;
       spf=pass (google.com: domain of 3qjdkzqykcb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QJDKZQYKCb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWh08Dm1d5wKOJtmYzKyK+R7C+/vYTGo/cLZexmFz0OK3aXLYRpPRmbOu+ePQE8+6w//RNguws0idXeOvSRx2h4lGwbOiPGdcs6Bw==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cr11-20020a056870ebcb00b0021a0c4bd2edsi658033oab.4.2024.02.12.13.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qjdkzqykcb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6077ca422d2so6814877b3.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUU6LLDKGgLe8Z8J08PCuz3wsjq8cOfblzf0A9Zl9O2N6HS2tBu9opIa26YOieDx25D7z68S1QjAz1eANd4tSgcgcqo4F/Gp/RrLQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a25:8391:0:b0:dc2:1cd6:346e with SMTP id
 t17-20020a258391000000b00dc21cd6346emr2029085ybk.8.1707774016324; Mon, 12 Feb
 2024 13:40:16 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:06 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-21-surenb@google.com>
Subject: [PATCH v3 20/35] lib: add codetag reference into slabobj_ext
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=YT5Fdnp4;       spf=pass
 (google.com: domain of 3qjdkzqykcb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3QJDKZQYKCb8xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 mm/slab.h                  | 4 ++++
 3 files changed, 10 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index f3584e98b640..2b010316016c 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1653,7 +1653,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
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
index 7bbdb0ddb011..9ecfcdb54417 100644
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
diff --git a/mm/slab.h b/mm/slab.h
index 77cf7474fe46..224a4b2305fb 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -569,6 +569,10 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 
 static inline bool need_slab_obj_ext(void)
 {
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	if (mem_alloc_profiling_enabled())
+		return true;
+#endif
 	/*
 	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
 	 * inside memcg_slab_post_alloc_hook. No other users for now.
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-21-surenb%40google.com.

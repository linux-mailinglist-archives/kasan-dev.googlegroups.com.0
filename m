Return-Path: <kasan-dev+bncBC7OD3FKWUERBJVAVKXAMGQERG7FOPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1EF851FCA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:52 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-59922b09256sf3771340eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773991; cv=pass;
        d=google.com; s=arc-20160816;
        b=FvDnN3zwzpzuigRHwhKImWtPmE5httsZj7FR9XktfPZ8zermkHIPuOnaiZYLuucGYO
         w4LgLzFd17kmhFobg8YsjCcfyShna69VatL7l9HvKbDhzqSwNsv9rV/IrrywTVZZdCU8
         WjRAi1YQ+uD9Y/0x1+jcjMoMn/MT2ra0fn/Wk/O8OgNV5EIT0a5N/6toDuBGGGaAD4sr
         EtRGR3YtoV4NajukXnmii6GZs9XL5iUoL3gigRbKl1+7tOfYMNKaXWW6kW27mTf8kvW1
         tYEg/8/i26EB4tEyhqKZdil2QBijvMp3t5Ev0/oL1drISQpyDCT0+Dth5FErFICpfhXd
         SHCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bKr7Y+CvgiIH12qa6RTS00IDfacXk/JD+3fsnhl/rW0=;
        fh=/xn4CrpODciv+R0bUWLCrkp7ks6yFkUSZB5ll4sYGpU=;
        b=NTo7rJx7cfCdeP5CoP8Hpkf9/TvEjsn22M3n3SgWj3422wsC5w6wf72FMc1Xig8NfM
         D3h0nA2ppaCwZx7y+04hSNfgENr4cXlBAbfIjlrXs9LFVmlm1VELxR6onJ5QMd5HMvpJ
         g9SFJ55z25PHsKb/PvIZX8yWknYCQum1mHVGxUpVgtChP3YjKG4XLVkTHTdRbYRovG/m
         p4HOrnylaC7OStDWa2YbF56RYem5FMP6rGtQHI4oLTH742FlrzlIIVjzfBE54ixlHRPC
         f/gOxCJrOZZoL9lvjFqCvogq/virHtxDqYAKkawIEDe+oQKLdAks8qWnvbeJC/EFCPkl
         opqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B7cceBsF;
       spf=pass (google.com: domain of 3jzdkzqykcaqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JZDKZQYKCaQWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773991; x=1708378791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bKr7Y+CvgiIH12qa6RTS00IDfacXk/JD+3fsnhl/rW0=;
        b=EKi+wTn/x66GqQaBBbYWoWh25c8UKiQqCpLDCwbPcyQs4Xx1vvNjktvO+8ufZ/cl3w
         PNiSjJNo9KLNrGTqMMIUoG3WfwczYBApDqRTxtLTDUAlC2V1CmjmymxDWqcOUTxgjZoN
         SQIbioBkKWQoP+QuQ1KtNIz1X18YDY4INWAEZccZaFAtZBRnTEenLQ2r9mG9OJvcntJ9
         UZtn3TAkqd4gGDMp0B39Af06uDlMsEpX6LesVeoOqwaND1ShoiCCQlQptc7jj9S/LA6N
         2FRLgDzEEGnZWO0XhBgH1PLmnk4Ae6au1aGV/itxDMDQstMB4Wd26kdD3K6JHQ3c/Nls
         h2cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773991; x=1708378791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bKr7Y+CvgiIH12qa6RTS00IDfacXk/JD+3fsnhl/rW0=;
        b=cvWOZNC+FzdTgmyb/RU2S3xZ9Up3q1YRIAFFHaoD09jEK96i73krTzUiD6LoelSyE6
         afzhLAKdX80UFj/HgGRer+T8phJOi9Jk3hgyPAqiOtwsRD8P9xIRY2q3CRC17lrDgCO8
         0vmW6PKJcMrvJQlUvjxsItDTZD3IwELJ6SMKCgJEogG2XOZc82A0Lhn5aaxkc1BFn5nC
         Wlv9YYuqyP42VARMMGc3Bzjrdr19hRsOyL9MSFwGJfHW1u7nXmkZvh6Y5AG0qqHyzwJJ
         MahTqZDQywONNk1zOXTQeqOjyuBoMZeSTR2ZCLLNdR4bfIvRRN3QrFkrBk1Lgasp9U7U
         VNMA==
X-Forwarded-Encrypted: i=2; AJvYcCVtKJlFBdnojG74CvJYFJie3srDXAAZdYfD7AL2Y1Yhpbw/lsX6xWB4aBMB5xj7BNDUKdVt37Z5qEMejHThFwqKNTLHhHdjWw==
X-Gm-Message-State: AOJu0Yxg1rscdbgzi0QOdGEYluS3FkRzTm41pF0Ml8Fxcwmnqw4ZhMA/
	GhmjfIYLsHuiUwubPO0mxyaV+4We0tho8o7LeFK7swO1uGomW9lc
X-Google-Smtp-Source: AGHT+IGCYBagwMtbp76C+LjAWRcVy5pLLLubu2nXEQ2LzTybz6GLKVV0JsFzLxU3rf00QSFnIFD7xQ==
X-Received: by 2002:a05:6871:608:b0:21a:d38:9303 with SMTP id w8-20020a056871060800b0021a0d389303mr8132310oan.5.1707773991043;
        Mon, 12 Feb 2024 13:39:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a24:b0:42c:5dac:d843 with SMTP id
 f36-20020a05622a1a2400b0042c5dacd843ls3946085qtb.2.-pod-prod-08-us; Mon, 12
 Feb 2024 13:39:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/R/hQrvol/DGyS2HsJSHaDDM5xq2pUw5MwojlDa+WfpCe2dQrP6TJ2p7SCjgtNS2jQgQGv+qt3wlNk8FrTyI2PWwzEo3DXE08oQ==
X-Received: by 2002:a05:622a:18a:b0:42b:f47d:de47 with SMTP id s10-20020a05622a018a00b0042bf47dde47mr9066311qtw.55.1707773990385;
        Mon, 12 Feb 2024 13:39:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773990; cv=none;
        d=google.com; s=arc-20160816;
        b=cc+VNQk+CATzAavwGhUI2mJPNZFfUdqZg0ew5L87A2vT7u7Z2Ws7KU6Yvv7OOB1Vx1
         Jq2wZV25qaTFOMyqZw98MM95qmxuVh3On7wMu2RBNXERoFm73sIJrViVg6PJjq1iteP6
         oVsHn66Nqz6ZNCcLo1SVSUlrpe0MU73z4DVK9pVmx3v69AHqVL0AFc2uf1+MXPk1hb0l
         jWb6n9zfOWNuxaf3sbWUZI9DSyxDxZ2TnmhvsSZxiYgnaFU79aU4OTnuPra6I/pBiVGz
         a1Uy8F/bhxru8GaX5MjIrLeSzGu8Z+cNKsYcDUlwXLUdXvHP60TssnHNp6o5e6jB40nd
         9/xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MHmYMVX3pDUmg31UH8awuyUsQFI7ijlFGj9IhCGVNQw=;
        fh=g9T5CjVUiftXoBaf9sVtLTw5EGN70AQ5NBl0zzFHG34=;
        b=CZ+HxeOcqManMGJXVwzgye9fOI5kt8L8P/4wMTYEHxW2Ck0nJmKo/9fSpRRTpuOKCR
         2jOBGAUf76g28TusPv4mJ8h9/1NWwBAMLeNNU1VtQePffMSAiRgiz12Ar7NCphKKIyEe
         5kHmCzWItHm1F/nhKUz0ZwClOecV46Xr9CQC7Kn720z2gdsodxUIXrEUJNFJ/y2Ib2YR
         brLle8jtaHG79ix8+yA+8jx8udk8uXLaKrvw0mMIkyj+d3X2XdbifbMarLKbghyzgKYF
         bCo0l6VJO1eEfQ4Qw1vsP0YYED/on1sB/OUeWiGiOn9AfZsLhWBQAkchTqXTQWx5KENS
         Rmkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B7cceBsF;
       spf=pass (google.com: domain of 3jzdkzqykcaqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JZDKZQYKCaQWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWAyyiGU0GcjWT8swVMpEnMbg5g8YgwU3TROF1idze4BCL5Q/XZ/jFv7arafQ2jq7ZOwHDJGYGuNvg0hUGNTVNF/30DITjnAS+N0g==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id h11-20020ac8584b000000b0042daab50f18si71062qth.3.2024.02.12.13.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jzdkzqykcaqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6077e9dd249so4426897b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVTsmT7kR0jPISbR4cyM/5FnqBj4vWP9VJ6JZ1mnelMBCJnK7VRk90PnLMtqKhMfOt3WXPqinAlH1isO5GgMsBBB/1Kstg/26qEug==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:fd0:b0:602:cd1a:6708 with SMTP id
 dg16-20020a05690c0fd000b00602cd1a6708mr1449899ywb.0.1707773989875; Mon, 12
 Feb 2024 13:39:49 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:54 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-9-surenb@google.com>
Subject: [PATCH v3 08/35] mm: prevent slabobj_ext allocations for slabobj_ext
 and kmem_cache objects
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
 header.i=@google.com header.s=20230601 header.b=B7cceBsF;       spf=pass
 (google.com: domain of 3jzdkzqykcaqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JZDKZQYKCaQWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
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

Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
objects. Also prevent slabobj_ext allocations for kmem_cache objects.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/slab.h        | 6 ++++++
 mm/slab_common.c | 2 ++
 2 files changed, 8 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 436a126486b5..f4ff635091e4 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -589,6 +589,12 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 	if (!need_slab_obj_ext())
 		return NULL;
 
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
 	slab = virt_to_slab(p);
 	if (!slab_obj_exts(slab) &&
 	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 6bfa1810da5e..83fec2dd2e2d 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -218,6 +218,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-9-surenb%40google.com.

Return-Path: <kasan-dev+bncBC7OD3FKWUERBHNAVKXAMGQEJ4MW6DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id CB508851FC2
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:42 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5ce97b87716sf2559640a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773981; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZJAuUXGUDZSXw1JNZ+JC1oiGOXH1y5CFCqAYD+ECs7k2+b6eFPyS8VyhCy7QCTVto
         p/Zb+U32uPj3dfx48fF0fedhtSo2EPkm66Sl5ZMHZEstQmTmnsR9xY04ab3eydJOESva
         bUh+/cTX5BoxEqH0lKWa/SjFjV9wyjPN8gdL5JVayEy+24XRgak4ykknzJmQfWd0Xueu
         /WHY+Rb7yW4zZZ2sfQ+Y6r+hfg7fX4FJDlTnOFheV8Rfl1CvXDvZxvAecM41RZ932oVA
         SkxAs4tEzhTKp0FSjW3ZxlJomAo6dzkL1B6pVWkT5I0409IVUqgrXAJSC03EE1sh/SOO
         CrXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rM4IJ/h+kIb62UDPrbe0pXsIRKC74pChLcMYAtDS4NU=;
        fh=DjyFK15gvwJ55YysSnCIBBCryMpGHTa4s/wEkv2LNOE=;
        b=u3l8SoDrlzDPzCFQnX7sSsAkgrUOagsXQDL9oOgWNS0q4DgMYcYTTbdQ/9tk/fID/X
         ATchBaojZYJ2soPJ9rdVG0aSRoQXiHKKn9vrYOKVeGIkzOo2/aFPS/Oe/tO+8KTiqIjT
         DxVw/SU7iN88nBoJE/3OtHVsljYFOa7As9gPvtq6Q2XZ8LwYSPSER/e9n+po3EUGJxy4
         NTVGeAnNyWPCyAvo1c9GmVJQ8bnmyvvDtIt6AFtH+3+P+mtzp5M9EYCDFzsbXgPXYtNe
         6GXlBWybw20hBIbcPsZvwjXB9xQrHC/egkruJXqLRU/lFtN4/ydaHvSlM+xSQNbOZ99A
         9nQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zVx2XDrD;
       spf=pass (google.com: domain of 3gpdkzqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GpDKZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773981; x=1708378781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rM4IJ/h+kIb62UDPrbe0pXsIRKC74pChLcMYAtDS4NU=;
        b=OtVrPhMpCjXgQq6Bwi/OsC4O9WsFZhFQuiRsQw+9q8SkDUlpO+Mft328gDmd2yXYGU
         rv1OSQmVezsH6rkbCkIvkNOFSePB9I1PRMe2fsSU4cGU9ViQmVxCm/ObVfyXnEZyHi7p
         UWNsVlPvE6UD6mZlNLcLyCruUtgSqX8fCASMqmpu8u8ioqEBhoNDz5IxcaplnQqPyLK/
         dwFWVyDaokXoQWvkHNeSVQvIBCsHj+sOdEVfT6/kL9mGxCAbNfcezIB2oWEXYT+4HGSt
         rTJIS3nQ+WKequfbqRjpF3+ychipqRd0+zGK0lH+TNvlpXri1dS4xuL4xZUyovmyY6it
         KIMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773981; x=1708378781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rM4IJ/h+kIb62UDPrbe0pXsIRKC74pChLcMYAtDS4NU=;
        b=D6JqZfKfvQMJ2SPCiROVl6hME73qCNbaXQNP29+9S//C+4UO5ZCimOfKGKlPhiAJob
         LblpFECg2IGtXU4rMwyKta4jhROBL7Vaj4iVq+KPq3hembm0hMKgKqvbbDtGO5WI0T0t
         1OUNIOPOHLCYhaMkMcVjrtMMFAzbAU0No4OjQ3al/MbphwtE3ONkARVK34CQqy8jBM6O
         MpxeM0kyT8WKoieph9Gto1QESHIvSVPEf2qIzmGE7p/UfOGuVMlEf/AfW762nlkYw7O2
         C93GR2/K3BxRGa/6X0E8CIREKeZ2ZtYHM/riIEQF7jwlLwgjJW4s4TUdSPVsmu2o4EDC
         LJKg==
X-Gm-Message-State: AOJu0YygvRBjc0T5g/d0CC9yBepUvysepeJw8mq+tJZfxcW5kshL0n9l
	8FvTWSKBa2HYZxB61BkD5AdmtguEqnzsPsMzKFdeT5EiopUwmU1v
X-Google-Smtp-Source: AGHT+IFCpuhBzzVuwpzGZ5mCXZXOxhyp2/BsgJAR/nEnfxUpFW4b5ltl/aRC+PJn96Ob1uMcxSxt3A==
X-Received: by 2002:a17:90a:6fa1:b0:297:117f:7a6b with SMTP id e30-20020a17090a6fa100b00297117f7a6bmr5023677pjk.26.1707773981330;
        Mon, 12 Feb 2024 13:39:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:35ce:b0:297:2872:e9ee with SMTP id
 nb14-20020a17090b35ce00b002972872e9eels816073pjb.1.-pod-prod-01-us; Mon, 12
 Feb 2024 13:39:40 -0800 (PST)
X-Received: by 2002:a05:6a21:3a41:b0:19e:cc6e:fcc3 with SMTP id zu1-20020a056a213a4100b0019ecc6efcc3mr3801589pzb.46.1707773980046;
        Mon, 12 Feb 2024 13:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773980; cv=none;
        d=google.com; s=arc-20160816;
        b=vSqpY7Wpq2/+Kc1Rmw4McyXKBMrtC1h2VwHjypHVSSjoRtjyiDc4WwNrod2EdA1qcO
         5P04Xr58XuWEZoZWGNp9+35LCluHA6eZC9mFH9ixYBY4n0RsxEV1GLIz0z+qiAQXtyfh
         NhESnpSh27eqGf6taV3yB+eMGlv7KWBbaw7igOMTAbPRSIECkZbp2dFkIhAXN/NqkIMd
         wmD7f09VIQSWQMNnaTNsItOLAKQlafuM33666dCXP3ntzQiW06XPS0zoDpZLKnkln6Kn
         l1S601Y4Lgm/5dZp7f7SmvAd0WIzL2PpEft65Esin3HcBHWdaUyOiXwPJB4fYRabxfHI
         QzyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DoSimaxvysC1tsWvSL78khESKiClPBlBlt51p8Cfztk=;
        fh=DjyFK15gvwJ55YysSnCIBBCryMpGHTa4s/wEkv2LNOE=;
        b=ci4eusjhIKWgQarX9MLLt1EYSNN7ZSjPa5hXVy1Q5HfZTtSMreeYOrmyJbholot+qy
         A7i6w3lTsGWpESVS92RCqBJzTZNSS0PWnT+smP+dZXoBsi+FdswJlbcyreacb4YtNNOQ
         HBNINjTBDzegIMJ4ODH+0tpFWsDycuCRZ1tLQmbJBjFVGn46Go0Hh/GWGxLsEgCsol5s
         EYc3AKsJH0w0xxBluChupLHA9GbWJ6J9evtvbDxMqcPzsGWejJarAJmn65r+QExv5qbQ
         ymiqJ83I1FNEXcYM1g6TPCpCfHJQFlf/pdSwdR/oybnbhk2X+Gbhfd5yK4/6qklqO9K/
         GBLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zVx2XDrD;
       spf=pass (google.com: domain of 3gpdkzqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GpDKZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXnQGHOAEtNIAQMjOYIy0vJ4vu+QD7JQLPrhLJzyP+h3bnT5N7HUyFXMZJab2H9q0YaXl8jbc4/vtaP0h7WvZqmUzAZDzLN/ULZlw==
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ey13-20020a056a0038cd00b006e03dda48f5si504872pfb.6.2024.02.12.13.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gpdkzqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc74ac7d015so5030653276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:39 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:1005:b0:dcb:c2c0:b319 with SMTP id
 w5-20020a056902100500b00dcbc2c0b319mr80854ybt.9.1707773978951; Mon, 12 Feb
 2024 13:39:38 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:49 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-4-surenb@google.com>
Subject: [PATCH v3 03/35] fs: Convert alloc_inode_sb() to a macro
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
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zVx2XDrD;       spf=pass
 (google.com: domain of 3gpdkzqykczklnk7g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GpDKZQYKCZkLNK7G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--surenb.bounces.google.com;
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

We're introducing alloc tagging, which tracks memory allocations by
callsite. Converting alloc_inode_sb() to a macro means allocations will
be tracked by its caller, which is a bit more useful.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
---
 include/linux/fs.h | 6 +-----
 1 file changed, 1 insertion(+), 5 deletions(-)

diff --git a/include/linux/fs.h b/include/linux/fs.h
index ed5966a70495..7794b4182bac 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -3013,11 +3013,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
  * This must be used for allocating filesystems specific inodes to set
  * up the inode reclaim context correctly.
  */
-static inline void *
-alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
-{
-	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
-}
+#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
 
 extern void __insert_inode_hash(struct inode *, unsigned long hashval);
 static inline void insert_inode_hash(struct inode *inode)
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-4-surenb%40google.com.

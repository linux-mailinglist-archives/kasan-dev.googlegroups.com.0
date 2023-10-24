Return-Path: <kasan-dev+bncBC7OD3FKWUERBSMV36UQMGQEBTUUGTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 940E57D521D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:50 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-5abfa4c10c4sf26015067b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155209; cv=pass;
        d=google.com; s=arc-20160816;
        b=cPJzwHbcD0xAWkEmbPcSiKdS55173AuG2IHE2Z1f23o8ua1sKrd6bWBJVUl8VH7AUB
         eh5xncu4QSdhnPxXCSrP+HN3/3u3OuN9wE/RtfC/58z6IkR5aQzQt1zK+7eKO9hebUws
         5PMlNx2DOjfqwU076yWHT7zYrIWf9xB1tGWQAQrfDm7AG40Dty7le7i0lzK/2k5FhuAJ
         hP1cwK1LO1QJKm0f++XYMGFDJlVqA5vMzoyajzGv2CacYz4EHUKETctEywz9oLYoQ3XK
         ay/Mivqn/Jx2uMfTrnLMJ9KqoB+thay+8Qrm+42sqiDdAQdSbYRVHoj/9RLAnJpFIs6i
         UFlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UHysTmqNXTd0JW0rAuXAoDwqJpxNNt/dn4J4ZrSPSxc=;
        fh=RXOtFBdCfemqIzKgCT2IEWXkzD+vYXS6w3Ab8wzkuqk=;
        b=iQmt73dQRlRbFaeVMivjZ2yE0UvFR5s2l3gwjYk++Xjl2lgbZ/3qPaoTomlIyEksnC
         dB6fss9rWqfe/LDSa5jxb68O0KAGtAdWfcqdqkB/L9IxZb5FB+aCTeSS4SqRs2is0uYT
         QQBj+Wk4I0PMM3J603p+6Jof76+ytJGc5j9doFfsR/J+wi/ez+Tu+hiJapKGeF6or6KU
         F1p42AOz+Wt3AwcQVkjUVdHw35DPZVBuZPYMmqcXTLln/2nFR4u2bKAlr4HzCn4M1hRb
         BZEiGEGi+0WaU2qtML34gLq03AKgPqjL+aXE5c6iu46xjHF+sNRZeBp0gWF4ROMAWODh
         PC0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1SaWl6Q;
       spf=pass (google.com: domain of 3ymo3zqykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yMo3ZQYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155209; x=1698760009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UHysTmqNXTd0JW0rAuXAoDwqJpxNNt/dn4J4ZrSPSxc=;
        b=l7hY6gDkSh/F474CxDlTitM1FyyCUykmkckrjPwgW7PnfEmbCJXahBkpMh5sHSU9D7
         VZ2Fr215Jzwn3lJanB5eW778FmVojv1K0tmzhD5IrqIrwu3A8iPuUkWWsXGUHGWkuYLc
         NMw3Oz6EkO5oybToPaoB0rD7+cZnp78XK/D4mtyUpTSPDSwYrximo3UJqmj3o11imkAr
         x3RVjZAWyAX3bO5Vy9gPV/xN8hDvBJq1V1qWkzs8Z0dYDUZ5TfmjqGt0QSg4qWq7MFKP
         7wCyj/rxc7u75oWBrVWXBYj7uw/098hmx/OkqjkXGCP7lWoRpikxo24xT3zLQ/cnVdaV
         ZqMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155209; x=1698760009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UHysTmqNXTd0JW0rAuXAoDwqJpxNNt/dn4J4ZrSPSxc=;
        b=MqXxulvZPvNdx4gb5NdacaKUZBZgGIGs3du8W+puYMRu/BKnynpkfhoHuibBqTz1Au
         TC4GCjcGaMlLr+tN+AfvhbOzVu1cVTkhUC1YNCuXQR/76K2Eew9ToAQpUmsfrOpSW2oB
         JXyObbd71/1WU2c9TqyCMd0UPmwXLo+Y0nopBztKe6GSnUgoG0IlcmklxAD/4Sgsnppt
         DYofyeDNqW+kxUeoTh+AnRKu5Gi1AS6EzKXambmChhXwdnjIG7O3JCuHDuNaYZ5K0Htn
         L3CI5YCOdTGib/NL3Fvh5o0N1ojZq87daBkIi6zEcUcQ0IrXzCX1vvrd5pO3IEKzuOkh
         hGbw==
X-Gm-Message-State: AOJu0YyUFJ86NRvc9YlIwffSDdjB+4YV+ScjoocIylFbGEmH4kuz58Bv
	xqpc5qIrKDgaEVh2Q9SF8QQ=
X-Google-Smtp-Source: AGHT+IGayDtDnBfsIMfQuV5nc9FwavQ9RAT5vfrxIz5qiWLs7hHgwSkie2MICK1j8CNHfvzrWmNL6g==
X-Received: by 2002:a25:c742:0:b0:da0:51a0:11fe with SMTP id w63-20020a25c742000000b00da051a011femr1042947ybe.42.1698155209414;
        Tue, 24 Oct 2023 06:46:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d18c:0:b0:d9c:b193:bdf2 with SMTP id i134-20020a25d18c000000b00d9cb193bdf2ls1012431ybg.1.-pod-prod-05-us;
 Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
X-Received: by 2002:a25:bcca:0:b0:d9a:52ee:6080 with SMTP id l10-20020a25bcca000000b00d9a52ee6080mr10661653ybm.37.1698155208622;
        Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155208; cv=none;
        d=google.com; s=arc-20160816;
        b=bSkMk1TaTPXLUD+89PS2Ml95Yo5VWfrPGAHQpPSa2n5Ank3KbS4CA7sIub83ygPSV6
         OZlM/XA+ZHYu5pRuUOscKgPpwzKzxhHnloqO6dVgk5VxzO26JXQO6rnKM+OrSDzmYZj5
         N+A21xcNkRFwB+NmZrboLbsNsW1ooRolj3YmAKXaA2HN1RNalLJVPqsClm9vBTi7mpUz
         tO4ErumbTi+7CEN8noJsZchN1QepYJUocOz5pD/42P9MT4amQFItC01HgWemeJ+tfawp
         EPqO1ACI7tGR9RsgLZowe2ohGCiMfbIxS4FPoLBReVzGQntZhX32O28ABPpAUWZ20ycV
         dhjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MWOhaEKA8zMI+Iz0e6SkNPW5Kz551oWdhyAlPdtU984=;
        fh=RXOtFBdCfemqIzKgCT2IEWXkzD+vYXS6w3Ab8wzkuqk=;
        b=ybTD4oJxQSvDutyxNRrU7kLZa+YxPvEchMO62mjmeZDMiUnf9ncY6mrhAcggIZtcBq
         fv42INmdqp/T3AQAr31EHcwP0oRfgc7LiiKhwpeMMBsXycVoN3tOOheRqcnEV3vWSc+t
         yaGaqd+kBFHh6vcJ02AbITmyTw50XbDCZZiZ5mv+RhJhmNjlLTcMfJEBznzqrycxoYGp
         hgWMb2cg4Xa3AifDNDfWo1guojV5WsANOlN9Y9tZCryYU/qCBOB9kauMB0vk9W25pwup
         exyPLnk8FXIXfFmGOAuw249DWDrYXwUlRW/AjpQsRUyEXBD+6GmRKyzZBOeBpXVBXfDo
         sEaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1SaWl6Q;
       spf=pass (google.com: domain of 3ymo3zqykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yMo3ZQYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id a13-20020a25ca0d000000b00d9cb94608f1si1135511ybg.2.2023.10.24.06.46.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ymo3zqykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a8ead739c3so59301137b3.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:b951:0:b0:da0:1ba4:6fa2 with SMTP id
 s17-20020a25b951000000b00da01ba46fa2mr82321ybm.4.1698155208197; Tue, 24 Oct
 2023 06:46:48 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:00 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-4-surenb@google.com>
Subject: [PATCH v2 03/39] fs: Convert alloc_inode_sb() to a macro
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
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=b1SaWl6Q;       spf=pass
 (google.com: domain of 3ymo3zqykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yMo3ZQYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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
index 4a40823c3c67..c545b1839e96 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -2862,11 +2862,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-4-surenb%40google.com.

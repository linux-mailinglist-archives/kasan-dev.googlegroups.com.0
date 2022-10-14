Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBLGFUSNAMGQET2WAG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 370B95FEAF1
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:49 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id dm10-20020a170907948a00b00781fa5e140fsf1952815ejc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737389; cv=pass;
        d=google.com; s=arc-20160816;
        b=A7XRY0fkScRxIk+pHjV7VW1RoGPS1gh8D9dhoyjtRdKGdgqAybUQB2z2Wryd0pVYAu
         D7Hb3d2B14iNsEasWsRKZZ5CWoX57Ar8gM4kDX2h9Gc63VW+SLXb1D5NAP7PaZkCQvm9
         MJaETbf8eGUE9OuV0dGwBsWjilyYr9pFvpC38Q3gPpVShyZ0sXtjh43p8lzhwOtd6Iz6
         d5ApKQLR9wIC8Koaozy9lATDyZye+wecGpjW7/oHJteMHXYEXhbJ8ur5SQZkV6qjswhC
         MwpmctNZtzkVxmo08H9cCGSW5hQSNAswSeS6XIvxRb7QOTpZd7CdOb8K+jz08KaCdZlT
         tNcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=yiro5x1yrDqtjCnwfCjvePwybMisrflzZ3ZyMlpUhJk=;
        b=KlD/Stb7n29kzS+9MKCUZUcA0HMGUsfRlKbGPsfEbVHYZz2K4lhyQVSuAkL5Y9sKUQ
         uBG7abMNuB9kdOlH5CQAVuxZ1CrA+fLQr2SCQ2P0RcRxTw4S38I+LjJQoNBKB0zBlHDN
         8DQC3TneB56uFa+YomC3/p0UBfxbf8gxfWt9lucyAZBCCu4jEDvQ+zRExfhFGtknBcYP
         7a2Osn8T/8aQX3+T3mQf/NZCu4xqK+4zuDgOM1sWB+WcnJNVtlYjmRjxVhTkaFclkyMZ
         nqZqNc0k/HKkllW19lHnGLez6yanITXGB6sqZpD1Rc4/azts3lNa5UOsBX6zgRUGzI4x
         c/xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=p63rFDk+;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yiro5x1yrDqtjCnwfCjvePwybMisrflzZ3ZyMlpUhJk=;
        b=bX8ZyZqqYv8MeEBoHt1GuDtpIXrZD2OlqdmwXK+93XxFGqnSZh5Xy39NDuCkfTJspy
         XVUD0pJOHX5/JNcBXkHK2kufvMUO2sPH8hYTAdjSp2utXGOfS5ymbxJdYh4J/YoFn355
         3r406z91IfMYSeoaIYwRha6bndAN6WCck3H9gbhuLTvFYxQpLMQxxp/YnmCohVHDsMjL
         faxzd+OzcFWz2fU6k13Vs70GOlMd/B6VhaB6rwFviR8Ojir7e4Kx7fnKBjdcsLMylK2j
         w7CHyDEmX8df3D3MrTzl+BvpYrfcY61j0eI77MUw4HYJed3lnug8iHotVh50fpHaUjGi
         LH1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=yiro5x1yrDqtjCnwfCjvePwybMisrflzZ3ZyMlpUhJk=;
        b=fBqa68xh4oT7bJOem+bYbCquq9psXrU4i8ico3zsnGDH+/T5NS/HsNHmHPcJFTtWPL
         RrREyy1L93TP9UNS0QWqbZoI7Wl7NsKjbK7+RK+BZTFyWE1p0oYur9EgOnyS68uaMVXh
         3zGaKrFo0V1vl6TjMjfukAfC63IL8C/Uq2T990hinoU/V1iPJPHaraWkEQ2+C+nXkGt8
         vMGWOvVjlvaLyOr1O+zqEw7ESVSdvQ+j5qTXTFOZpAJB9Bx8QSDLT20wiSR/bsqh8pse
         1Hs33iua0AtPgt6W4eoowcNzihwN5WTHo86bPgsYT6WDKbZ5joF1y6kd1bvQIGgINVWR
         OtOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yiro5x1yrDqtjCnwfCjvePwybMisrflzZ3ZyMlpUhJk=;
        b=vvV3lgHmuP/NzgXUlxJTVFbXxMC1NaC1LbEqZv+pnydizepB8l7NBtFd8a8azlHRuq
         pRWsAa0efIvCfGunzPjq1dpx2fi3KHrzQqV3ZcejL4ndWwib1Kv06Xh7P1wxER8FDj/A
         vAQ9nPUUuo4h1cFRcm4mDRBpAhIcrVnLkuxCYQlMV99T8TduIGUt70l+GUbz/z67vjB8
         tKHGBfOEEci4RWLCipScjJPGfvtzCoY/AJFivoh/Qd48iiwnrE2y31Covn8+UPJ11XvQ
         B73grml6WdRiT6yLGiQCbiuq2iDtGbjbN2QDmJob0xlgfQo366hoFsn2+hBK8Z8ZoGkn
         rA7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0BIKEmzk0joatBn7cUqv4mu7PdmSY+eHgdhctqJ3YfflETEKP0
	VScpuo9aEzdRg26vsMlgOS4=
X-Google-Smtp-Source: AMsMyM5OrwoY7MLPQD78LsCH5Ag1/F/5zAv67eG5uYFsaVEkhWDi3lHIRcHEdLqMWS246mwMA7K5tw==
X-Received: by 2002:a05:6402:190f:b0:45d:2c25:3a1d with SMTP id e15-20020a056402190f00b0045d2c253a1dmr981827edz.175.1665737388715;
        Fri, 14 Oct 2022 01:49:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:45c:2675:8024 with SMTP id
 w12-20020a05640234cc00b0045c26758024ls4517073edc.1.-pod-prod-gmail; Fri, 14
 Oct 2022 01:49:47 -0700 (PDT)
X-Received: by 2002:a05:6402:298d:b0:451:5fc5:d423 with SMTP id eq13-20020a056402298d00b004515fc5d423mr3333288edb.102.1665737387670;
        Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737387; cv=none;
        d=google.com; s=arc-20160816;
        b=OlCrNmYpl/cp1qXo5NaEhYH+jU0ubVhokcXbd4xobYiRaz6AWYLoZBZz4hf1Dgvoot
         I+HFUOb/RkeX71Aj9545IM3XJibVlCMO0jPUPO3FqM20zXk0ZkDMGaivK1F3oks5x+nG
         R9VfF/Rb7Cc/s5Xx4rGixhkJ/J1NUWw2RLFRYMF7/WjVa1QtH1FA+Dl+Y/CfmMXpQvyf
         qDVJM8laGAYIMZMRRvXp7PX3I1ttqnv3u1DxzUJy8wnu0HaJ6C8rMynTPxHWEgR1qvtS
         mWI3zKaykSlzntoCRd3t5QIFGZDu9d7z/hMLmi8CJ2NxDqxw4qSHiT43QnUbTCKtWZid
         kSBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s+9yJ7ltRwZDViylHimzxt5trfp3/YyMYP1DALt6daQ=;
        b=AFj13bYPq2nWg+OOwNrqSOh6FDGVfubFVdI20nAgulRswcxgOoTZGonDl7fBW09Lu2
         MZIcVD8NSIp8amw0MDD1G23kEqkcSdanRp61qI/i7Qt9SX5vx0qbso5f38OMNVyrCi0T
         G8o0agcMpIaDGJkBoqO66HBJX45PXfGaYNzwiguukph3CpNukKNrNt1t4kaQboZJTuE7
         ECD6aGmvQfBMxIkJK9d1KmL/eukCkWZCG/Gl8iuwHOsQqTGAyDm4y1j1ELBTB9DVA7pS
         0Z8iEyIslx3fYK6PtJhkjw00M76xjruO6kpD6XJ6ZmWawWuSY6JbEjwiZEXMNQPUPdMQ
         nbVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=p63rFDk+;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id a16-20020aa7cf10000000b004595ce68e4asi70173edy.5.2022.10.14.01.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id l32so2684655wms.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
X-Received: by 2002:a05:600c:19ce:b0:3b9:c36f:f9e2 with SMTP id u14-20020a05600c19ce00b003b9c36ff9e2mr2761365wmq.110.1665737387337;
        Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:47 -0700 (PDT)
From: Hrutvik Kanabar <hrkanabar@gmail.com>
To: Hrutvik Kanabar <hrutvik@google.com>
Cc: Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org,
	Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>,
	linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>,
	linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: [PATCH RFC 2/7] fs/ext4: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:32 +0000
Message-Id: <20221014084837.1787196-3-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=p63rFDk+;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

From: Hrutvik Kanabar <hrutvik@google.com>

When `DISABLE_FS_CSUM_VERIFICATION` is enabled, bypass checks in key
checksum verification functions.

Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
---
 fs/ext4/bitmap.c  | 6 ++++--
 fs/ext4/extents.c | 3 ++-
 fs/ext4/inode.c   | 3 ++-
 fs/ext4/ioctl.c   | 3 ++-
 fs/ext4/mmp.c     | 3 ++-
 fs/ext4/namei.c   | 6 ++++--
 fs/ext4/orphan.c  | 3 ++-
 fs/ext4/super.c   | 6 ++++--
 fs/ext4/xattr.c   | 3 ++-
 9 files changed, 24 insertions(+), 12 deletions(-)

diff --git a/fs/ext4/bitmap.c b/fs/ext4/bitmap.c
index f63e028c638c..04ce8e4149ee 100644
--- a/fs/ext4/bitmap.c
+++ b/fs/ext4/bitmap.c
@@ -24,7 +24,8 @@ int ext4_inode_bitmap_csum_verify(struct super_block *sb, ext4_group_t group,
 	__u32 provided, calculated;
 	struct ext4_sb_info *sbi = EXT4_SB(sb);
 
-	if (!ext4_has_metadata_csum(sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(sb))
 		return 1;
 
 	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
@@ -63,7 +64,8 @@ int ext4_block_bitmap_csum_verify(struct super_block *sb, ext4_group_t group,
 	struct ext4_sb_info *sbi = EXT4_SB(sb);
 	int sz = EXT4_CLUSTERS_PER_GROUP(sb) / 8;
 
-	if (!ext4_has_metadata_csum(sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(sb))
 		return 1;
 
 	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
diff --git a/fs/ext4/extents.c b/fs/ext4/extents.c
index f1956288307f..c1b7c8f4862c 100644
--- a/fs/ext4/extents.c
+++ b/fs/ext4/extents.c
@@ -63,7 +63,8 @@ static int ext4_extent_block_csum_verify(struct inode *inode,
 {
 	struct ext4_extent_tail *et;
 
-	if (!ext4_has_metadata_csum(inode->i_sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(inode->i_sb))
 		return 1;
 
 	et = find_ext4_extent_tail(eh);
diff --git a/fs/ext4/inode.c b/fs/ext4/inode.c
index 2b5ef1b64249..8ec8214f1423 100644
--- a/fs/ext4/inode.c
+++ b/fs/ext4/inode.c
@@ -86,7 +86,8 @@ static int ext4_inode_csum_verify(struct inode *inode, struct ext4_inode *raw,
 {
 	__u32 provided, calculated;
 
-	if (EXT4_SB(inode->i_sb)->s_es->s_creator_os !=
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    EXT4_SB(inode->i_sb)->s_es->s_creator_os !=
 	    cpu_to_le32(EXT4_OS_LINUX) ||
 	    !ext4_has_metadata_csum(inode->i_sb))
 		return 1;
diff --git a/fs/ext4/ioctl.c b/fs/ext4/ioctl.c
index 4d49c5cfb690..bae33cd83d05 100644
--- a/fs/ext4/ioctl.c
+++ b/fs/ext4/ioctl.c
@@ -142,7 +142,8 @@ static int ext4_update_backup_sb(struct super_block *sb,
 
 	es = (struct ext4_super_block *) (bh->b_data + offset);
 	lock_buffer(bh);
-	if (ext4_has_metadata_csum(sb) &&
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    ext4_has_metadata_csum(sb) &&
 	    es->s_checksum != ext4_superblock_csum(sb, es)) {
 		ext4_msg(sb, KERN_ERR, "Invalid checksum for backup "
 		"superblock %llu\n", sb_block);
diff --git a/fs/ext4/mmp.c b/fs/ext4/mmp.c
index 9af68a7ecdcf..605f1867958d 100644
--- a/fs/ext4/mmp.c
+++ b/fs/ext4/mmp.c
@@ -21,7 +21,8 @@ static __le32 ext4_mmp_csum(struct super_block *sb, struct mmp_struct *mmp)
 
 static int ext4_mmp_csum_verify(struct super_block *sb, struct mmp_struct *mmp)
 {
-	if (!ext4_has_metadata_csum(sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(sb))
 		return 1;
 
 	return mmp->mmp_checksum == ext4_mmp_csum(sb, mmp);
diff --git a/fs/ext4/namei.c b/fs/ext4/namei.c
index d5daaf41e1fc..84a59052c51d 100644
--- a/fs/ext4/namei.c
+++ b/fs/ext4/namei.c
@@ -396,7 +396,8 @@ int ext4_dirblock_csum_verify(struct inode *inode, struct buffer_head *bh)
 {
 	struct ext4_dir_entry_tail *t;
 
-	if (!ext4_has_metadata_csum(inode->i_sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(inode->i_sb))
 		return 1;
 
 	t = get_dirent_tail(inode, bh);
@@ -491,7 +492,8 @@ static int ext4_dx_csum_verify(struct inode *inode,
 	struct dx_tail *t;
 	int count_offset, limit, count;
 
-	if (!ext4_has_metadata_csum(inode->i_sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(inode->i_sb))
 		return 1;
 
 	c = get_dx_countlimit(inode, dirent, &count_offset);
diff --git a/fs/ext4/orphan.c b/fs/ext4/orphan.c
index 69a9cf9137a6..8a488d5521cb 100644
--- a/fs/ext4/orphan.c
+++ b/fs/ext4/orphan.c
@@ -537,7 +537,8 @@ static int ext4_orphan_file_block_csum_verify(struct super_block *sb,
 	struct ext4_orphan_block_tail *ot;
 	__le64 dsk_block_nr = cpu_to_le64(bh->b_blocknr);
 
-	if (!ext4_has_metadata_csum(sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(sb))
 		return 1;
 
 	ot = ext4_orphan_block_tail(sb, bh);
diff --git a/fs/ext4/super.c b/fs/ext4/super.c
index d733db8a0b02..cb6e53163441 100644
--- a/fs/ext4/super.c
+++ b/fs/ext4/super.c
@@ -287,7 +287,8 @@ __le32 ext4_superblock_csum(struct super_block *sb,
 static int ext4_superblock_csum_verify(struct super_block *sb,
 				       struct ext4_super_block *es)
 {
-	if (!ext4_has_metadata_csum(sb))
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    !ext4_has_metadata_csum(sb))
 		return 1;
 
 	return es->s_checksum == ext4_superblock_csum(sb, es);
@@ -3198,7 +3199,8 @@ static __le16 ext4_group_desc_csum(struct super_block *sb, __u32 block_group,
 int ext4_group_desc_csum_verify(struct super_block *sb, __u32 block_group,
 				struct ext4_group_desc *gdp)
 {
-	if (ext4_has_group_desc_csum(sb) &&
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    ext4_has_group_desc_csum(sb) &&
 	    (gdp->bg_checksum != ext4_group_desc_csum(sb, block_group, gdp)))
 		return 0;
 
diff --git a/fs/ext4/xattr.c b/fs/ext4/xattr.c
index 36d6ba7190b6..b22a0f282474 100644
--- a/fs/ext4/xattr.c
+++ b/fs/ext4/xattr.c
@@ -154,7 +154,8 @@ static int ext4_xattr_block_csum_verify(struct inode *inode,
 	struct ext4_xattr_header *hdr = BHDR(bh);
 	int ret = 1;
 
-	if (ext4_has_metadata_csum(inode->i_sb)) {
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    ext4_has_metadata_csum(inode->i_sb)) {
 		lock_buffer(bh);
 		ret = (hdr->h_checksum == ext4_xattr_block_csum(inode,
 							bh->b_blocknr, hdr));
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-3-hrkanabar%40gmail.com.

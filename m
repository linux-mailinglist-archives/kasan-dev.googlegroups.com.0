Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBLWFUSNAMGQEI63DUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id AA92A5FEAF4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:50 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 2-20020a05600c268200b003c4290989e1sf1864873wmt.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737390; cv=pass;
        d=google.com; s=arc-20160816;
        b=uTDqNyGsXaDdHkUB/L9hlupQ3tDG4un0LmvCF599bRixJvrxvFMH2Sfe+7ZuxBsHhc
         1dKcMt739troSHV6E3f+pQb6B4R4mePo3ABge5yDH3xW/XXEwisxgILzr/DE4RZh5Yu+
         3ArkSWN2/dt4ZA1GKtw+hsL+Np3Jm6uKG63nhtnOTZfMkRZ/b6yYPsZO4PN48t6fEfbM
         KSGqKFTlWPTTDsV4bJAWFEl650OG1XQmPiEkVUiTA52bIUWONjkEcecMUPOQafPv3BZn
         GmVht9bHe06XqM74/QdSF2/KFhkdTExOPsVHt14kec6+KRmhCudjuTuw27Sc3h5R2Sx2
         wdOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=32LwMSL3CKWQFNfdzg/04dttx/IBRwGCnugaU7hnajU=;
        b=mPMWek0YH4+F7XRpirODynvywA6pd2LLfJ5ENyVt/s40qgNjX46WV3fHY2fGAHoenM
         BZ+3xipuNDrrs+fdjewS0nHA5oEntKRHPHNrjk0Jv/P7qOtOLOEH8pq3DCHdI0J8LYrL
         mou6JChkB+muIdy+5TJ488nAi9HJnXf0EWgeXHmXD1jNdBbwo1SlrWdyAkjpB9gjA/HI
         R91Y84U1GLBIJEzJjPc1qzjU63Co0+Oke3whxWNpIKONRjqm9UtxVk+7Xof11As6VvUb
         BZIcbT7AwgHwFz6tusRvhvGMDXu8ArTesyk30pPPwe3/aDLuNB4RHZjG/U/2Oa0cF+wl
         79QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FQxuL83N;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=32LwMSL3CKWQFNfdzg/04dttx/IBRwGCnugaU7hnajU=;
        b=jd2b2WIK+GJ9FUFh2lR5aA4M05DHEhSiJ8MIxqWfR5sLSxIpdpqVIW3CV04j5kpWyl
         jTUOg8iqJcaj5YIkdt132u2iOT5SnsrDhBMW6I0K8gQuaTHTjhtgV1tBQLDupr4djUDu
         54nZyLChJt1ZlgNXDBX7YQbGMPrMHdTxK0VJ+YRwqka2pCyWBvqFBpMBpgI5Ei7eRfZv
         1oe+hvzMZUpfOj9V7YKvk8f1uGIQ4GhHkE0Xl+PDK42lCfjji39YhPjK5hRtShMl9q1M
         SGM8MQL710RawyFRrPz1J7ZC9FmVZuAXeCYAFTT5JIEiP9mdNY+LpivaSPRUfcr4ntn0
         QPMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=32LwMSL3CKWQFNfdzg/04dttx/IBRwGCnugaU7hnajU=;
        b=l0Cxng48ofW3JWoGhNaFs8+WaDG9Fw1JTLFlinpFR8MqpTt92rHrzd7YjK1I1n1Kto
         D7o71J3F9P6xMYz9Srl/4bQYsHVOh6yA6jfZ6MgvaOdEHvYWdFsG/v9x7gN8LE1O7yTm
         DqKm6oSH6SLhk4ZY2vpQv4YP3hwYmGEF6gRrscQJ6NK7rre0xYPIakqXFfyZ0dFw2MbA
         pKp/lYglKRPCUPR0TjODVv/Na7xbjYnbcTIXWT/Ln0uSQCRtA0rcZ0avwODg2RVO3/mU
         TAZlVzPECzyMQpnTu6CC+6nX7sLG4qsdaBmT7Kuh5qf+LH90JUsimG1UT5+ytVcQm6fI
         4vrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=32LwMSL3CKWQFNfdzg/04dttx/IBRwGCnugaU7hnajU=;
        b=taf9gBkIJWlSyQ116Qulssw8eMfPoAgy11Zn2ezTsgcTeGxKXffGlUM98ArRKnyKcB
         wClio5S4ypPmoLYqA7ZFEB128Ted8kgk94pu3rkUaySTXtD8cGBlyG1FiHE6Fc91Vrxl
         4BAEWY/7BtaAgwOkFvTICAgYCIaph4ODOkdDaiYkuuDNajn2MkeWzG22svBwCcPT1vGg
         VpfVc6VbvdU8RwS4aZkQQ7VrsBz4lTcI/TbA7+bRdoyP0kgiNP8jmEmYSPnPQANAKrwk
         oiJDb0hQf2ugGZA5Pi3K60VzIcfSptLUl+SBDHySO4FLP/FRjuz+kpU40E4mhrEng67k
         3Oxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0W8o0QcJsC2WhBZorlJJXcL1nEWfRDQs1lecFvm2W96iIk74Xm
	rVAtSImfuIb6qFS/ingAAkE=
X-Google-Smtp-Source: AMsMyM5jVWMVSgU+hLnrQll+KF5h1RCs7MApjyNKJTu/AgcN5HfLpBbMeAN3cWI9ADqxtQXgVRDycg==
X-Received: by 2002:adf:e989:0:b0:22e:3370:dbdf with SMTP id h9-20020adfe989000000b0022e3370dbdfmr2613662wrm.316.1665737390379;
        Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2:b0:3c5:a439:23df with SMTP id g2-20020a05600c000200b003c5a43923dfls3950189wmc.0.-pod-canary-gmail;
 Fri, 14 Oct 2022 01:49:49 -0700 (PDT)
X-Received: by 2002:a05:600c:19d2:b0:3b4:a4cb:2416 with SMTP id u18-20020a05600c19d200b003b4a4cb2416mr2737623wmq.6.1665737389392;
        Fri, 14 Oct 2022 01:49:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737389; cv=none;
        d=google.com; s=arc-20160816;
        b=Q6BkNj8fujq2eUVPwuNApeho+uXx5GJA9nMPzaqHzDyjdksyriedIP7IAJGgBzAj4l
         NYLWNzCD8V+ODH2sB9kgjqakQxwrSokSnToQAnv3oUa5IXkMhdoaLTqOEQa6okvH8yJV
         PpE0UnxhlRlF6wBgaxemLj4yKhcOkno5haiLVujvBYEMMiqV1cyvs0Obl1KHW9ZVZZFe
         KTcnCqYkdEFIHb/caGI4OtWw9PQtb+XQK0jXPUK/X+z4rz7OK47Mljbp6V6oiZD2jm/8
         vodJjA+6+9nPIv6BLEzMbaBSGpfiEpHqBV/0jKK879L3K3ad+VL6PMhUugq5U5S2b+Ez
         vcqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=noZwzVYPpBsDl5CECnOrP5rsHRqU5K36GF5tioVqhvo=;
        b=c9ZWYRbQihYmvfMU8/yMrmVenfUv/CoaiwLX7TWsveNyqNh+5TCawghvzcQGcLvXKG
         XDfF21ITFLjFAunDTiCIq0KXwsv+Vjwvht7EgJaUbHzGY9T8rPEm6Ln1It0TU59gpwIN
         BEJxWeUh+Wj8r/Dk7UPKylhPBtryeoNJPUhHBVrVDZXajEeGZxZUpGZnx0kb62v0T0tL
         0f/lz/BDs1JGI8iRkWf4D5bFmUkbysG5d6qkxhpuOvGHgKUuKeVN9pgIP92/6e5r5Svs
         Uu/LuGQGbNc5xrfkO0CnPCLLzdQUTQxODZl6B+xsSiXEqkRQBVwB8CewJ87V0NOH2wqZ
         N2CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FQxuL83N;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id bn23-20020a056000061700b0022acdf547b9si79249wrb.5.2022.10.14.01.49.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id l16-20020a05600c4f1000b003c6c0d2a445so3058770wmq.4
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:49 -0700 (PDT)
X-Received: by 2002:a05:600c:288:b0:3c6:c44a:1d30 with SMTP id 8-20020a05600c028800b003c6c44a1d30mr9545255wmk.46.1665737388927;
        Fri, 14 Oct 2022 01:49:48 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:48 -0700 (PDT)
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
Subject: [PATCH RFC 3/7] fs/btrfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:33 +0000
Message-Id: <20221014084837.1787196-4-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=FQxuL83N;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32f
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

When `DISABLE_FS_CSUM_VERIFICATION` is enabled, bypass checksum
verification.

Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
---
 fs/btrfs/check-integrity.c  | 3 ++-
 fs/btrfs/disk-io.c          | 6 ++++--
 fs/btrfs/free-space-cache.c | 3 ++-
 fs/btrfs/inode.c            | 3 ++-
 fs/btrfs/scrub.c            | 9 ++++++---
 5 files changed, 16 insertions(+), 8 deletions(-)

diff --git a/fs/btrfs/check-integrity.c b/fs/btrfs/check-integrity.c
index 98c6e5feab19..eab82593a325 100644
--- a/fs/btrfs/check-integrity.c
+++ b/fs/btrfs/check-integrity.c
@@ -1671,7 +1671,8 @@ static noinline_for_stack int btrfsic_test_for_metadata(
 		crypto_shash_update(shash, data, sublen);
 	}
 	crypto_shash_final(shash, csum);
-	if (memcmp(csum, h->csum, fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(csum, h->csum, fs_info->csum_size))
 		return 1;
 
 	return 0; /* is metadata */
diff --git a/fs/btrfs/disk-io.c b/fs/btrfs/disk-io.c
index a2da9313c694..7cd909d44b24 100644
--- a/fs/btrfs/disk-io.c
+++ b/fs/btrfs/disk-io.c
@@ -184,7 +184,8 @@ static int btrfs_check_super_csum(struct btrfs_fs_info *fs_info,
 	crypto_shash_digest(shash, raw_disk_sb + BTRFS_CSUM_SIZE,
 			    BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, result);
 
-	if (memcmp(disk_sb->csum, result, fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(disk_sb->csum, result, fs_info->csum_size))
 		return 1;
 
 	return 0;
@@ -494,7 +495,8 @@ static int validate_extent_buffer(struct extent_buffer *eb)
 	header_csum = page_address(eb->pages[0]) +
 		get_eb_offset_in_page(eb, offsetof(struct btrfs_header, csum));
 
-	if (memcmp(result, header_csum, csum_size) != 0) {
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(result, header_csum, csum_size) != 0) {
 		btrfs_warn_rl(fs_info,
 "checksum verify failed on logical %llu mirror %u wanted " CSUM_FMT " found " CSUM_FMT " level %d",
 			      eb->start, eb->read_mirror,
diff --git a/fs/btrfs/free-space-cache.c b/fs/btrfs/free-space-cache.c
index f4023651dd68..203c8a9076a6 100644
--- a/fs/btrfs/free-space-cache.c
+++ b/fs/btrfs/free-space-cache.c
@@ -574,7 +574,8 @@ static int io_ctl_check_crc(struct btrfs_io_ctl *io_ctl, int index)
 	io_ctl_map_page(io_ctl, 0);
 	crc = btrfs_crc32c(crc, io_ctl->orig + offset, PAGE_SIZE - offset);
 	btrfs_crc32c_final(crc, (u8 *)&crc);
-	if (val != crc) {
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    val != crc) {
 		btrfs_err_rl(io_ctl->fs_info,
 			"csum mismatch on free space cache");
 		io_ctl_unmap_page(io_ctl);
diff --git a/fs/btrfs/inode.c b/fs/btrfs/inode.c
index b0807c59e321..1a49d897b5c1 100644
--- a/fs/btrfs/inode.c
+++ b/fs/btrfs/inode.c
@@ -3434,7 +3434,8 @@ int btrfs_check_sector_csum(struct btrfs_fs_info *fs_info, struct page *page,
 	crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
 	kunmap_local(kaddr);
 
-	if (memcmp(csum, csum_expected, fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(csum, csum_expected, fs_info->csum_size))
 		return -EIO;
 	return 0;
 }
diff --git a/fs/btrfs/scrub.c b/fs/btrfs/scrub.c
index f260c53829e5..a7607b492f47 100644
--- a/fs/btrfs/scrub.c
+++ b/fs/btrfs/scrub.c
@@ -1997,7 +1997,8 @@ static int scrub_checksum_data(struct scrub_block *sblock)
 
 	crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
 
-	if (memcmp(csum, sector->csum, fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(csum, sector->csum, fs_info->csum_size))
 		sblock->checksum_error = 1;
 	return sblock->checksum_error;
 }
@@ -2062,7 +2063,8 @@ static int scrub_checksum_tree_block(struct scrub_block *sblock)
 	}
 
 	crypto_shash_final(shash, calculated_csum);
-	if (memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
 		sblock->checksum_error = 1;
 
 	return sblock->header_error || sblock->checksum_error;
@@ -2099,7 +2101,8 @@ static int scrub_checksum_super(struct scrub_block *sblock)
 	crypto_shash_digest(shash, kaddr + BTRFS_CSUM_SIZE,
 			BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, calculated_csum);
 
-	if (memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
 		++fail_cor;
 
 	return fail_cor + fail_gen;
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-4-hrkanabar%40gmail.com.

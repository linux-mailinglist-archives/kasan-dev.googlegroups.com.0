Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBM6FUSNAMGQEF56AAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2425D5FEAFB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:56 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id r132-20020a1c448a000000b003c3a87d8abdsf2601953wma.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737396; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJiAd4JPndJu+9ox06NB133ZMhbMvzq5kdNqCTOSm0u0IMEnUNr7j7QfiXUoBQahuc
         2XDyUn1ybmaVp+77fBn88S1dtDdYLaKflfb38DFGtG0esyQtOlq0YTKP0mJRiq+0ZqKM
         AxYAf0dVnoJozHEcjDKs7ZguykwvMnyvG5nML5i5kpzPfkGZzTAOhSq7Y0a6lGABGu2D
         VgVALF4SHRZqqace07SvzP9WGsq5XDf16aKW0AuAMKGGEsadIlqYAUpgDqXyRzbBGz/U
         6YOGJbt3ZjRFVcCZ7ah0r0m0TjrRxixilWHDbI/LIIszzH8NrG1LDUZKxmnAgASKp4NY
         mnyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=TX8wiMJbStO8lCVwMruE1KYkf3hacMHRhaq+04gu96k=;
        b=sNeYG9BXWszStYmhbU1tlae9vCMhiPpbeTjKaRAyVPnzOKdjpTP2IiWtZPt0XinQ3b
         /KDJLLhlTaFzokT+ID7WhN1OdpFxyuNMEN3FrUaXBmCgkP1jLAGT0JMMKBwQp27n/Hdw
         0tPHpfBBFnTbpZl+aGaiBdMNfcn+2Q99cA/XfFDIV63IBGntq0f39afniwIghd9wpbKi
         pDPJGA1Q5l3mrvD5yrcf9WqLZKEaFyWhYU3F0reP4SgKYM+q1rTxAi3Kvt2kCUBUzm+w
         RSBEHaEjHF67L81zljzvbVHfGGlog0xXCjzXAiVcWF/LewAWEyShMY1cfdkVAr8XyaoK
         3xXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GfG0sfEg;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TX8wiMJbStO8lCVwMruE1KYkf3hacMHRhaq+04gu96k=;
        b=lr1ZW2L/2hmatoJ0foJ+bLw32E+yf2/B6+WERCB6J6kI4Ih6kXeBWectEdrV74FwfG
         7b6Jg2m41L9s/XzanDt3os8rNB+gcEP3fwjw/D9zGwniUNIOaBmi4FXNPeb0QSSfKYki
         i7TiDpwumLOfZa+sjiC3PS81M5L73lwkFtKaOSO11Ok3OdTRjHJqxVvyexWvWTBS6IGe
         sCOxoDytv+0Zwj0P1idqzboKVwaxCWt8PIhBfKDkUkISfA050X27gGH66kRFK3h24MEZ
         vYikL9vdaQNb3wt07pA/yYDH1Wvaxsi+mWppWWiiegPoHwf0YAIQpIjHeDZOb/9SP965
         mOOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=TX8wiMJbStO8lCVwMruE1KYkf3hacMHRhaq+04gu96k=;
        b=mGuh/U6ztUziN4eiv9mxUBRMDR/lcqJaT1NqlMHHH8ms8aXR4QLsioPy1CvPqioQ4D
         FvHYzSGNaW9H2uSGA9aCAZks6F/3tuc/96NiVNHu7J04Xl5shzxHqjSWCEVGXapf6rZg
         LAZBJ/QF4arXCaQl7uJrVohm6Qx0JdZ9r8azeiD78p4ZVq09ZtZWYj+Hb6ddUo0dBkO0
         eBbU/x2nALdXqg4+/ZCJ5Z0/kpsFjpDDEiM4J+1oGldHGIPCe5WtlTLO6PGP5zVvFnUG
         O7SXKQMiXaKjcd5Q4hWyYRcsupxMaZL7u9WoJ9Sm7eqmvL5emp9n673Kgc+3qlgYpPGL
         zp5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TX8wiMJbStO8lCVwMruE1KYkf3hacMHRhaq+04gu96k=;
        b=tBWUNZCrXtMhGFwbEMfwqU6rz9G/exyj7VSHMuIXfDBch6iGFGhCVLrmYSpopEkBL5
         0AQLQ+lB4HhQvzHcY9gnNs+WlqnJ1LuHz+oi8Obx9fXNSmVaiORh2E+Gl+zBSUb1ZJg6
         HwxcPEX1oqHvwd4ROIHxnXQEsjdXaZIoM8whxpj5PAH8epbKpiBaPV0pFpGxe3nzmuku
         3SA819PLb202Eyqp9tIj5SqG5mnirARM26IEJEyBg+FzBFEmeRJvEduwW4sFTsKVk5Jt
         UcKbmESHuuW2wsFmdojAlRtyKMsE5AsgHof9GtWiizt6npFFXy6o03N79MY2m00MzVr2
         PPLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0tmIdGzHVWdeebEhut0qanjyBmEwQ73cgIt8lvF5TDISuZhZ6G
	7qKzvOPIPKc+iIv9jQTIKbA=
X-Google-Smtp-Source: AMsMyM6zerrVu8V1i4T2z68oZFGMi5sFh5McEMLwkzQBuVkQLQYOJuNAKKjJQKaGNjQf4Z3kVzO6wA==
X-Received: by 2002:a5d:6547:0:b0:22e:465c:6d14 with SMTP id z7-20020a5d6547000000b0022e465c6d14mr2538718wrv.208.1665737395829;
        Fri, 14 Oct 2022 01:49:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:69e:b0:22e:5d8a:c92d with SMTP id
 bo30-20020a056000069e00b0022e5d8ac92dls6801533wrb.1.-pod-prod-gmail; Fri, 14
 Oct 2022 01:49:54 -0700 (PDT)
X-Received: by 2002:a5d:47cd:0:b0:22e:f98e:3b0b with SMTP id o13-20020a5d47cd000000b0022ef98e3b0bmr2573312wrc.556.1665737394862;
        Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737394; cv=none;
        d=google.com; s=arc-20160816;
        b=TCjKkpwVBO6CtaOMm5SAFjc1wFlC2h/bKqimNUL+8Pt0q+UgdtsCFDu4x0O10tN+xI
         LDR6ire+WaEz347Gi5eVIrlUxD9gjzD67f1WiUOrbD99X67TF2YHv02zSCWKTXww6Tbt
         3rrX1rxklkupdykr8QvOU3A+YfdUSLylSRgboPoYbImTbe8sG0zx/HxxNFJ/1JrEvOBT
         4+XUOF8uxcD2nRC4Enk5ynRKdgm8kTY8CXKx5AowuhEUt+x7q5l7HY84pBooZKdObwmw
         GFXdoLymAZFEz69Xc3dSQ+sGeNhpVK+0LxwilS+yaqUWy9E7bzh3dJE21Fzq0PPt/DjO
         ej+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gOV3h57ut5GHhGlnLsxkEHBnkvFbonX9ORLLuFusyi0=;
        b=Rko1HKAhnAQy9hPPDt1eyQwBUxc1NeWIrwm+7ECysn4yyJB7dKRoU5gsiE/DKBvAnT
         U+Zi7x3EzQilkj1ttgY2dJQamlYt2+TnvRV7EmFnz5etBQ75a53MF0sOHC+JB4z15jEx
         ZjXDcsdEOvkYxG0iMxWWvijrb3ouxfT4BLempmVfWSUgzbJkOkEgZJosBJ+WRZqZ5oE3
         +geJcnVHOGVlWGPDBreieYKS/BYsvzw2Uu11MDXnQ+iiUXmO759nFGk449brrCGLUG7o
         Ju5Dh/Z4qKVnBvATOsg3UA2TZ+dL3wKasGx9V/X4ajhSeYLuH/kuxKg7z9O3rWns07IN
         Sm3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GfG0sfEg;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id o12-20020a05600002cc00b0022a69378414si86259wry.0.2022.10.14.01.49.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id i10-20020a1c3b0a000000b003c6c154d528so122249wma.4
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
X-Received: by 2002:a05:600c:4f93:b0:3b4:c026:85a1 with SMTP id n19-20020a05600c4f9300b003b4c02685a1mr9583025wmq.39.1665737394358;
        Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
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
Subject: [PATCH RFC 7/7] fs/f2fs: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:37 +0000
Message-Id: <20221014084837.1787196-8-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GfG0sfEg;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::32b
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
 fs/f2fs/checkpoint.c | 3 ++-
 fs/f2fs/compress.c   | 3 ++-
 fs/f2fs/f2fs.h       | 2 ++
 fs/f2fs/inode.c      | 3 +++
 4 files changed, 9 insertions(+), 2 deletions(-)

diff --git a/fs/f2fs/checkpoint.c b/fs/f2fs/checkpoint.c
index 0c82dae082aa..cc5043fbffcb 100644
--- a/fs/f2fs/checkpoint.c
+++ b/fs/f2fs/checkpoint.c
@@ -864,7 +864,8 @@ static int get_checkpoint_version(struct f2fs_sb_info *sbi, block_t cp_addr,
 	}
 
 	crc = f2fs_checkpoint_chksum(sbi, *cp_block);
-	if (crc != cur_cp_crc(*cp_block)) {
+	if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+	    crc != cur_cp_crc(*cp_block)) {
 		f2fs_put_page(*cp_page, 1);
 		f2fs_warn(sbi, "invalid crc value");
 		return -EINVAL;
diff --git a/fs/f2fs/compress.c b/fs/f2fs/compress.c
index d315c2de136f..d0bce92dbf38 100644
--- a/fs/f2fs/compress.c
+++ b/fs/f2fs/compress.c
@@ -772,7 +772,8 @@ void f2fs_decompress_cluster(struct decompress_io_ctx *dic, bool in_task)
 		u32 provided = le32_to_cpu(dic->cbuf->chksum);
 		u32 calculated = f2fs_crc32(sbi, dic->cbuf->cdata, dic->clen);
 
-		if (provided != calculated) {
+		if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+		    provided != calculated) {
 			if (!is_inode_flag_set(dic->inode, FI_COMPRESS_CORRUPT)) {
 				set_inode_flag(dic->inode, FI_COMPRESS_CORRUPT);
 				printk_ratelimited(
diff --git a/fs/f2fs/f2fs.h b/fs/f2fs/f2fs.h
index e6355a5683b7..b27f1ec9b49f 100644
--- a/fs/f2fs/f2fs.h
+++ b/fs/f2fs/f2fs.h
@@ -1976,6 +1976,8 @@ static inline u32 f2fs_crc32(struct f2fs_sb_info *sbi, const void *address,
 static inline bool f2fs_crc_valid(struct f2fs_sb_info *sbi, __u32 blk_crc,
 				  void *buf, size_t buf_size)
 {
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
+		return true;
 	return f2fs_crc32(sbi, buf, buf_size) == blk_crc;
 }
 
diff --git a/fs/f2fs/inode.c b/fs/f2fs/inode.c
index 9f0d3864d9f1..239bb08e45b1 100644
--- a/fs/f2fs/inode.c
+++ b/fs/f2fs/inode.c
@@ -181,6 +181,9 @@ bool f2fs_inode_chksum_verify(struct f2fs_sb_info *sbi, struct page *page)
 #endif
 		return true;
 
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
+		return true;
+
 	ri = &F2FS_NODE(page)->i;
 	provided = le32_to_cpu(ri->i_inode_checksum);
 	calculated = f2fs_inode_chksum(sbi, page);
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-8-hrkanabar%40gmail.com.

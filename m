Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBL6FUSNAMGQEJFDAQUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 957995FEAF7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:52 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id z15-20020ac25def000000b004a060fcd1d5sf1348359lfq.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737392; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSbTWK9+yaamESLHHKETALOU89gHy+aoXCHwFFkPzbAQm4DcLAT/WtWyz2f81I/JZR
         YwP0/i13fmH8VXrdnDZaDYR6ah9z3snfombZnHWcz9Cd63MU3cbNq1JxfRqUjY7bV304
         IyY394lwY+M+aZzuUkX9uyUn4SjIB38GRuJ5Gw5z8CS8UaTG5FYN2XVRl3NaRX52dneD
         7qQzYLAMzpfTZf5P/B+3Mct3fxzARYo1pC6R1/WR9hjSUTCri8vRRg5pUuqOhZLrvHsi
         EZue/vOxUWt2TFMrlmLGYjNyM73eAExadcjGBGUtGk8ucFd0xol9QgoGDcIYz1oG/b5v
         LjUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=meyvSEnjE3YAppI/oBBhVAwBTLoyf3M1of4LvqoulGk=;
        b=uKnTv4wnS/Mx/nGtqecMgfZzYBIreTw19CMm8uOHWKLCNZn+RR+Hnl5oRua/X7h1DM
         XwEWtU6l07y6zzKdsDc3yHisjzU0Ls6I0XLVA/tybXqOOnRj8yL8KlEppNzX2lsNnUt1
         3oYAlL7khPbqD2E4UFAS/5WdLGSnLHSB/WccMIor3cYkPMO2ICaddFJS8srweUIu9cJM
         56zNFmgjrwjvcRy/LK2aPTzljE/V5qET16UKZbnWzgttS7lguIqY2leH4mGdDYji8A1a
         FsBNsEp+9+ba2UW4svw740JHES75tQjIq9z0cTDIKmsB1L1Ya6bwZSTYu9IDSoFdXcpk
         rjUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="jUVoj/7b";
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=meyvSEnjE3YAppI/oBBhVAwBTLoyf3M1of4LvqoulGk=;
        b=EMu80Tl5l/HQTIXLWauQfvOjp8GHO8j0KgaOqteO36AgqsLwcT8SBkdy60GpsVr7o7
         7glZveQTF4wegLXw0wbreZuHv4Bg9xUzvrvXpSjoi1Nv4RbapYGxsT1da/zc6B763R8e
         IHAWCLIN1v7po159fRYdg92MoaQscMhGXIkeId6TM977wYSj+Z6+NYPE26cuz2/nmWsP
         Rl0ZMHepRHkwAMMWpAEPTu/9U8I0uZHULSLt0N6TTK4VgnEmLT3vsa52CXwSiSqDPso1
         Z7qGrDuPz+c1xQxhsr1nKHbOOQa8r4v36gMKBqBTIkjd+VVPaBzQMfcwp2Vn6XxakgZQ
         Bm2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=meyvSEnjE3YAppI/oBBhVAwBTLoyf3M1of4LvqoulGk=;
        b=gyF56A1Hb7A10GjZczIGJ1T2ba+bmtE5o/0bQ12KM0Iu4HUtgafhe615PgkOjend7H
         nTMgyM1otQ//amzIl4+5Pfj/5DbgqJvcJjwfTr8lybzGsFzsSh9LEwZf8fl7Tc0mnoIo
         Vj+xxsJeTGac7zARHifUcV2R98+irF3f/6NfT52qFd63D3yY0vXpVsc4zZFTaWdUMVgJ
         HwfDZPycio38EHK7sYgPDw71rrpeKkIw4o0dTje51813LKujd6iHFrsu44oI8RgPHMlT
         lNv6hf9awuf6F/ePDqB1T+dBh0nvTQ0hMt7HV6K+X7oFTgdI2vAdb3ii6OKFEvggByRR
         7iaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=meyvSEnjE3YAppI/oBBhVAwBTLoyf3M1of4LvqoulGk=;
        b=ARQiSArL9Y5UWzyWmV+ILBDd+Kpnq3zlN4rtmrLul9L89kfvOk1jFpUZOsllzWsPUy
         pxB/Qtig6HImSFdU2OEmb0H2wEt33Dgb6VPNof/bPgdqJsKvpEcyIuh2P6vLRc+aqZGJ
         nzUtvIiDqgviMj6WUNPC/zgvzOxmZig+aQCV9CYBaNghTDlSx8BsJDo9w0qMfyE3u6JJ
         p85Wtf5+f7XtwJW3hsUq76DE19hx1NMuYoQBLZSWsx1ojiyLVtDdvJgvNkkWqvsE+gUt
         dX9X3rgtvSeaBpzJwahwtR89JE8gQxIcizer8Bg9pu7eISKtHx3bJyUq7KOSXVXyPKbf
         JopQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3+/Bym85f+sv4ModByJxpxMg2fAzhPq1/Um6o06r+0nque/azc
	iHB92vQYHbnt6fQmzh7cX5Y=
X-Google-Smtp-Source: AMsMyM4Wmnl4qeMLxneet0gLXGqXSsFpFVT5gNjW6gFohl9O4H7VUpEs3w9xWY5C/p4H68GGolnV/g==
X-Received: by 2002:a2e:a78d:0:b0:26f:ca62:f685 with SMTP id c13-20020a2ea78d000000b0026fca62f685mr1379131ljf.263.1665737392041;
        Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f5a:0:b0:48b:2227:7787 with SMTP id 26-20020ac25f5a000000b0048b22277787ls274341lfz.3.-pod-prod-gmail;
 Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
X-Received: by 2002:a05:6512:138e:b0:47f:77cc:327a with SMTP id p14-20020a056512138e00b0047f77cc327amr1415873lfa.277.1665737390831;
        Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737390; cv=none;
        d=google.com; s=arc-20160816;
        b=hLEzphWVZYYXI87kkpnVeqrs7S5nyDiy9ozDVhhS502AdJEEss6oCbUFLngkfeml8w
         QsfHqnWQ9ndWxoUdSQsyEHHNFgERushwGBDdMITGsz4XKNWIz9JKolmtYD3xaZDA1yYw
         x4PkSqWDqjjLyT4WT8D+0OoFMHGVdWMBuspVdfNe0JDvqg2MGuTOx6JFML2TFGDme9Ei
         IPKK5+2O43YbPfStIDdPXBaHRgA/z6dZa7mOB4UtdXV32Efxfce3DgxNBuP8pfmlQd9a
         UVQ621T69lTLYMkxDbVhNkcZXvGBCYd3T3IXkedVPP71cg6Tep0+QX21ZGpw7x71UIsh
         u7vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FSLibGjWy/nIs1Cd+IM0NiQuRQgBV8RHoXsPr1HGgA4=;
        b=aMaup04e+wGgJ/u99Xvh7Jv/M0ic1w5EmV1hA4UQ964sknzQfYBTlJ6wQWXdBqZLe3
         i8MS62RJFhFIgu1SlDQF2tByRws7HhwWQRHEsLBUQMzTcJDf1gjP4RT+MVbHvghXTt3W
         CKqkpXctWarywZ6PuLfusWPhD8swn3gpWQEm5ccjHxLNV25pt5ZOfvZP3WdBAYQJ6WOX
         VIBYE8ILrLxs6aIZj4coHIGIbjAAqaWsueurV+Zi2Z1LJPRTMdtCAySZwK1BAXN/xiQA
         xH0L4+s4v82F+qLpqkH8rYX0Hpkd1nrMUdNid2QFDBCcku5qvLtSVZHXTy8ELwk+Vg0t
         9nAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="jUVoj/7b";
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id v18-20020a05651203b200b00499b6fc70ecsi48699lfp.1.2022.10.14.01.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id n12so6488309wrp.10
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
X-Received: by 2002:a5d:5b1f:0:b0:22e:51b0:2837 with SMTP id bx31-20020a5d5b1f000000b0022e51b02837mr2605593wrb.132.1665737390355;
        Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:50 -0700 (PDT)
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
Subject: [PATCH RFC 4/7] fs/exfat: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:34 +0000
Message-Id: <20221014084837.1787196-5-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="jUVoj/7b";       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::431
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
 fs/exfat/nls.c   | 3 ++-
 fs/exfat/super.c | 3 +++
 2 files changed, 5 insertions(+), 1 deletion(-)

diff --git a/fs/exfat/nls.c b/fs/exfat/nls.c
index 705710f93e2d..f0f92eaf6ccc 100644
--- a/fs/exfat/nls.c
+++ b/fs/exfat/nls.c
@@ -696,7 +696,8 @@ static int exfat_load_upcase_table(struct super_block *sb,
 		brelse(bh);
 	}
 
-	if (index >= 0xFFFF && utbl_checksum == chksum)
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) ||
+	    (index >= 0xFFFF && utbl_checksum == chksum))
 		return 0;
 
 	exfat_err(sb, "failed to load upcase table (idx : 0x%08x, chksum : 0x%08x, utbl_chksum : 0x%08x)",
diff --git a/fs/exfat/super.c b/fs/exfat/super.c
index 35f0305cd493..7418858792b3 100644
--- a/fs/exfat/super.c
+++ b/fs/exfat/super.c
@@ -564,6 +564,9 @@ static int exfat_verify_boot_region(struct super_block *sb)
 	if (!bh)
 		return -EIO;
 
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
+		return 0;
+
 	for (i = 0; i < sb->s_blocksize; i += sizeof(u32)) {
 		p_chksum = (__le32 *)&bh->b_data[i];
 		if (le32_to_cpu(*p_chksum) != chksum) {
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-5-hrkanabar%40gmail.com.

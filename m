Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBMGFUSNAMGQE4UGQIKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6D25FEAF8
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:53 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id q11-20020a056402518b00b0045cf5a2348fsf2814943edd.16
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737393; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZMJVWYx9ZM4tnug5ShRMwUOFsoe3Qn0TcdmQXNHiucCgj6mCvk/Uc17nxMghseI/o
         9utoXyny2x65NmHkvpkiuB42nw2wHLJAwN/4G4ij8kI8Nk+wMMympFBQi4kKtM2/cDec
         RFH1hKSNwezZRSQ7OgneuS8DzeY7FjQtCySctsncgMsBLbsEpfZyDaEkMRIm+8FK0Du7
         eZehhSCmhHJZqbYCA21eUhBvLtXirfwqJEUNLkpPoUtG0o/t05Sdfjk227CmPOI5vkda
         g0W4qIZ1lHrN3CBHvtPSA4KeQb4fsoMiBr3sqr8Y+VI43syvES2Yqv1wKl2e3mvMg9M3
         +3Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=34YIhhkC3A1TUJyiTDlymRY179e2qV12p8F8t0QutLc=;
        b=s4Drgvdm8SLR1btscUzETtO7okOOgvRS3Q7nUZ0yZAmqZl4q9uh+SrCOkOPiLICGVh
         RNgU1rk66lmwNYfuXXd80tiAWsJebW5CtVLqazMHIdJhFmZcQ88Aj+Q8f7/bcn4J8Pxx
         dS9T9a6hV0+GbFw8EkZl3Kdp2v98pyfjpE901NUmuKeM9bWHY7oxHHTNUBCYs2UowAd8
         Q0mHVLdk3wtUbu/cdedhtoAi01WG81FhPN3JAK1/BcV00WqYnsrC9TaSfxD0WpO1CPMD
         fD/gkxzGTOj3Fr4mS8jy+WiChvOMVMsvEzR/P7MYZ0gpFTcLki9+si2F7prOZVcYYa8m
         wexQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UxT7gVP8;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=34YIhhkC3A1TUJyiTDlymRY179e2qV12p8F8t0QutLc=;
        b=W1ZxwNedzVZFxgkLmT/HSDJ72Afs3vuOw8wf5O3nUC8bb5iOlxfoKyY8f+ygvYT2da
         aH4emfeTP6jt3+rXnDOSIBiPtUrklTBmVKMCc7C+i+otcBUYLxYLU7QhMiE9TRqGETe6
         UaonQdrG02BsPMxX4047vROADd1k2ZXEDzNMNXUOoatS015t7k1ZbaAPPAi2i4dc5E2q
         oa7tGkEd1d59530DepUMQA41bgQUkBNkXrGIwUbxKco/VrROoQ8SPXVFiVYvl+5cbPZg
         fy/BCX6oapUGBdJqa43VL6XSpnfR4LFC69NKSp8Quw6cN/SSfKsCVanTUHRZNXM2aFZV
         iOng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=34YIhhkC3A1TUJyiTDlymRY179e2qV12p8F8t0QutLc=;
        b=amEtoYY16JemRgeQK4igShqADOVs6uZfrOhMTYblQlOJ9LjTUvwIQucPdjns8CB8Jq
         QHHEilxIJHO3lRHkBeviMHYHTN62LuVZlYNHfGrvd7cNho/Aez+D+yxlAmZVwhmQbYTt
         9aPTWK+w9awTHzOfaigNHTk84HxjtdxIpcjf4PVL+xemXCGcDSPIWSbW9KKVWAhCBO1D
         HFbwk51YdyAUSRLPUJFpc3aIJGUoHJjSYma1QSq8druQUS5tWiSdzcGhV28czBxZWbnl
         FELdvIWqSVe26+yIMT0QyV13zI7+skZDqa589sqjsCS12k5lINcZj4CCLMoJhnu/q+Yt
         lZ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=34YIhhkC3A1TUJyiTDlymRY179e2qV12p8F8t0QutLc=;
        b=PCnlxL0JlqeScOurPf57fWDmyapCW1FmdRH6FlnnSyySCt5ZvIaqW69VfA8CtvvpiE
         OEJwO8DCimK6uIKdJaNuQZ6Oma3nZ/T5+Q8Jxl46RtyxkQlFGTu8FamyGhuxz2WkPLj/
         3dt5c9GiDTzkCtVZBgIRteBiGgr6Xc1B06/S71bWFoPZrpcZP39laiaq5wZWdw4dakEE
         3pjDpLj3EFG8Ju5dKJyCtNixxzU60wkKl4vz2EvfPc5uAWfny7ZQBdJNoN1zDMko0fJj
         POEd0e4yj9x39JZrMSqZ8fzjQYtU2uaAp6bPNzMYJ4GHUQbPZqKPWXkARu4/5w7xVA1M
         FxEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2oMJXGK7hGlylzur6XriAF1iNBrQY6F11cEsu2OfhDuG4WiC7Z
	jTjFROKwD2BuRIWEp8W4JXM=
X-Google-Smtp-Source: AMsMyM7sdEj19OF4UKLgUmqiY7N6bHuaOBmRBeEZLM4wjFkl4AV4dhJlbt6qdPlxtnbio8hoY48PbQ==
X-Received: by 2002:a17:907:3e01:b0:730:a690:a211 with SMTP id hp1-20020a1709073e0100b00730a690a211mr2726302ejc.596.1665737393022;
        Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:45c:2675:8024 with SMTP id
 w12-20020a05640234cc00b0045c26758024ls4517207edc.1.-pod-prod-gmail; Fri, 14
 Oct 2022 01:49:52 -0700 (PDT)
X-Received: by 2002:a05:6402:2926:b0:459:675b:38a9 with SMTP id ee38-20020a056402292600b00459675b38a9mr3392269edb.60.1665737392101;
        Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737392; cv=none;
        d=google.com; s=arc-20160816;
        b=xQCFl3MRAS147EHgIraD4dW/Bf3ZnGj7CjttRk0OuZ8WYOh3BCKpObyAo2qiKW4CVL
         j2aoetmuIDKyyss7rF4PVCr5oC05Uu7RyfVIF1uiQDjVifJ6+euKrJMdxwJGkb57pyn0
         ljXYOlj4P6fFtw30qtjqYLvgEYhEcrT5lxiD9PyqjtYSeqPJqw/H5v9assVXlj6yfcaa
         CZJAsqSNAoJY1/m8TcUYfvdcgWBJ0Pd6ZblWOjoxXmvCObsOOP6MNdXcZ4bp99lkqK4U
         4jsAzeAp+K2iAedSOMGxE89shq3Rx4FhEG9fifBpooDavE+s0Nmw7gMp3h2pZPkA6be/
         pSAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Gi1PiA14Xvf0/+DfXuVtXD45G5BgebCQf9p57BfhR6s=;
        b=aEP5/RJQtWq7bBpi44HD9sSJ10cbqzUzC5wEDLWIWIdhWUq/dR7dhK6BfKJ/o2lIrh
         93QB+MKoSjcVrIAYugP5y7tkFlC7X90jXEDLhILhR8n5iU7uPIxAZV4vURZSJcCqa0uV
         8BJ8svDeC1DNYy8cRHyJ99VmYys5cVY0A+s4PGWjKqW2ffOV57I/hXII/esRvkFdF1Eg
         D27wE+ozHhkzUwDahGDS0/RhNO+ASeTuyfGRPIy7Sj5RWw7cBiPufsTykl4gpIdbQhux
         Mvzxtg0VB7Baezj+NBN5Yb9HcKlw3C7STkgn6PoXMQx3aN+qQJkqtdRLOXot43evoiVp
         hC3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UxT7gVP8;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id o13-20020aa7d3cd000000b004593fb0c160si78135edr.1.2022.10.14.01.49.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id t4so2662978wmj.5
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
X-Received: by 2002:a05:600c:3044:b0:3c4:8af4:ecc5 with SMTP id n4-20020a05600c304400b003c48af4ecc5mr2758757wmh.52.1665737391668;
        Fri, 14 Oct 2022 01:49:51 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:51 -0700 (PDT)
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
Subject: [PATCH RFC 5/7] fs/xfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:35 +0000
Message-Id: <20221014084837.1787196-6-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UxT7gVP8;       spf=pass
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

When `DISABLE_FS_CSUM_VERIFICATION` is enabled, return truthy value for
`xfs_verify_cksum`, which is the key function implementing checksum
verification for XFS.

Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
---
 fs/xfs/libxfs/xfs_cksum.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/fs/xfs/libxfs/xfs_cksum.h b/fs/xfs/libxfs/xfs_cksum.h
index 999a290cfd72..ba55b1afa382 100644
--- a/fs/xfs/libxfs/xfs_cksum.h
+++ b/fs/xfs/libxfs/xfs_cksum.h
@@ -76,7 +76,10 @@ xfs_verify_cksum(char *buffer, size_t length, unsigned long cksum_offset)
 {
 	uint32_t crc = xfs_start_cksum_safe(buffer, length, cksum_offset);
 
-	return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
+	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
+		return 1;
+	else
+		return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
 }
 
 #endif /* _XFS_CKSUM_H */
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-6-hrkanabar%40gmail.com.

Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBYFFV23QMGQE4LFUA3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E189097C2E2
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:33 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6c5acb84904sf6931576d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714592; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWnmEm8GYFUiaN7Kxl2Vflf/7OySdRaCkPBVvC36ZXyfAqnrMahVSN4PAogeAtLStW
         i4tL5WbBiODLdRtXVdnxnohHcmKcGQJPe1rCE58ozh+MufymLMfQtn51pV6J/jLEe2mX
         ekqL7+K/EKOPgJdfnzm04T1I3C0i6LDm1ebew/vLkjd8qAgvDzfG/ksoFwdrFTI6SxRk
         EWwfvPJKv2vdupSJOY6Kb44Z7KJ7VVJybhCwoTYitMO6W2JHcn5udmq9GcjQ1ueFyRjy
         75jPBx5kcNs0npESDJ1G4DZTUd07JKP5W4kxEX28y55pQ58nNUgNRglb2mw71EL6iWnN
         Da9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=hK4abJg1Bpy0gwFxfqt5ahx3rz0qwWoTScT0XY2K8NM=;
        fh=VELieG3fY7LBsU4B3JtLpmPFlqlKm5I2O6yv6/W2ea8=;
        b=b86bybnSaKzA/WjK/+kGCg58WUKs7zvMAQ7fdh3Y2jbilU07n7vnc0YsjrSpL0trY3
         WT99cgE+duDo5F4oX06sJKs39ZoYGENHG5EWzBV8x6zNxrob/0AWqAdMIYXjwOG4nPHh
         JzqvuvzeYsto4x7tXhQmiVseEgsCb9zrVde4QuuWL2TnRImydFgSbWamye8jYl0OMr6p
         sRHbGa1i3c4y9jX5KpeNVsP1K44NVubEQlQK/n+tNta45T8hNkR7HQvwPZNHq25b1FIp
         4ySB0OM5gmHWsdHfLyTQWqEdgqfX7zSz58R/zCRvfQqGki2jVCutMfRYui2VgUjdinp6
         LeMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQS68UPk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714592; x=1727319392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hK4abJg1Bpy0gwFxfqt5ahx3rz0qwWoTScT0XY2K8NM=;
        b=JlC3AhbAZFc6pXr9qlWsBAGex6r9Sr/Vepm0WcCKf2eh9YV9G34Khdpjj4xi5a3yGu
         pUdmD1lpaA+cLwTrHhRKi3EwKafbi/fwrsQt36OIGIn3Z74f9Rh1pJt5A6Ptje7tjYTo
         ETO661X2zO1hUp6T51nlc23Icrp4EWm5coNRDYbpL9r4OmizBczS/Fgfl9ZCBrQ4t96y
         1fvc1Yu7QJip7w1uBNAV1nShy+Bz9cHGgS+8Am1nkddJ4jCB+E0z8PIFXpCpRLn+3CaJ
         zSJ26QYg+q6FPUEpWfZ7IPbgMaOGn4V6Tk1QbJrDw0/k0FsEJqYSoLOc6EmJyHWAtowB
         +9Tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714592; x=1727319392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=hK4abJg1Bpy0gwFxfqt5ahx3rz0qwWoTScT0XY2K8NM=;
        b=gDTC85zC6w8rW2I4l/VS0F0m3msvoIrnGqaM28A+PL7rsx2ZGoHl5knGwMDsFQDx2V
         SAyGLIKB6R6X3GFtjI9yBTbs+DcRXPZi+EOywA/lV4cy7Hf5D7oND8rrtLVCC2QVKjO8
         XGoV0IlD9+WXzkz+pxTJiox7O5USknGtq7J7aDzP5NHN0Ur77fyofbajdNRalChSj7uk
         8VuYfiRE5uEUJ4rJWEG9LaCi7w7JBdj8FOx1wFEkA6aUdWs6FqdfS7F7tIU08f8T5QVW
         mEFCFIgifzEee2MAjVP/hXcYR0XW3hNFPW8Ff2FkmwXgKQSpq8LwWom8IUF/0+EJNyPJ
         Q2CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714592; x=1727319392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hK4abJg1Bpy0gwFxfqt5ahx3rz0qwWoTScT0XY2K8NM=;
        b=NCxT7UUGaZOTNzaAG+6mo+7DumYU4uU3spj7H07sC5hVepEISoKoxuBjv/H/zRrBnj
         c2A6JcGDlIUn37RpUTalesOK731AV4cDOrSJlfiswY1ipErM10TePr6X3kHWrvmdKJez
         YYdSuoAOW9WUaRMRLxRG7J0+RsRxEsFAI/nVRXKfbAPVRE+MHtu4GYO59S5mdLxBKT4g
         izCjS69HLhB2ASju+2VvNoLKs9551cAhsmBu2nlLtJh0VzEOGhSSCAXlsNWh5d5bmYXq
         Mb7GnuE849iEfUAhF9vMErNZFGsSIj1tcfAsb4tWEv2TPBIbv784OnBoKfVGEJkLA5lp
         WliA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbTSC3NmQRkwvMiVl/h6DUwKVClZf6DP1uleXAuOjVBmNoTf0ahT8IEzGj2BCBuFRHjtx9Ow==@lfdr.de
X-Gm-Message-State: AOJu0YxsQInHT1YtFX8v+QFS5CRpcG5nsxY0v/qD3v/3vj4djz97w41j
	3/UqXbGcsuxtg40bbBoiNfykfj3hKlcT4R8PEU6B/jkOWFLYnBsI
X-Google-Smtp-Source: AGHT+IENys98NKyjqQ33wF9F6UhCkp6ofrKSbmoBfJJ7c9paOYKJ5koL3pf39CjaO9fNm+zCmtuilw==
X-Received: by 2002:a05:6214:4b0e:b0:6c5:7138:d515 with SMTP id 6a1803df08f44-6c573582ee0mr419153136d6.46.1726714592230;
        Wed, 18 Sep 2024 19:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2308:b0:6b5:da50:ac19 with SMTP id
 6a1803df08f44-6c6b4847a52ls6827836d6.2.-pod-prod-07-us; Wed, 18 Sep 2024
 19:56:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlQTyRUUUZbQ0Y4+fEwWJY3OEjs85+tKVy9ee9Wr9IP3qjC38a77NgbhsxJ70amJDfLCtvvBN8fGk=@googlegroups.com
X-Received: by 2002:a05:6102:a51:b0:498:ccd9:5b1e with SMTP id ada2fe7eead31-49d4145a617mr17687762137.4.1726714591494;
        Wed, 18 Sep 2024 19:56:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714591; cv=none;
        d=google.com; s=arc-20240605;
        b=a8SFAQJPks0cogE0alYX81BhQX5mRgHoPQvnJt6bbKjcp8Ds1U/DZUzP0jWH9EyqQi
         K16LVK/lpPjR/lp6QvRN4nEqqvV0lMTob+8HdBOmtZ+JONTlF//k9Mcdnf0ABULSWM6z
         pxmJpNt2I9hzecvb2wQ4OB1DP0zAfzrAGvmKdvbgETLpjJNcSFKgNom+94E+N3KcxMMR
         mYo+C4fMAuusSkNbvdxVGGhrdcbXaMRG3QX7eEdnhhisvAxOO+4YtrY1QOZXtCx2gnz1
         VKFd1exPlquvesZAZ0yGji7puBdoLpvrjE15YDrCmiAD+tVpQNQejBr6OndlMCix9ajd
         IESg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L3z8aqN2PapGEchw6ngaiDWNeD417V3WkhQBwYXWFqM=;
        fh=AXuT9DkJ+EuoGZJFR+AUPphFf9gJQzppECxvryV4Oek=;
        b=fWUzlU4O8t9vi3TwDakyrsO/GGjHUqzog9NVQKaqhVtvOTu9u38pMyq0GFxfnZ+i6r
         m+aZ/ipYNT+1mtgVP/KM5JBeAvYMfdOrPHYh4vduYl4yb3tdG1lyzkukswwmGjreRgb1
         AJZRKS5Zi0REKYmMaRW2zpPQbF/eD2a3zX1nunlKBskAxbnFiGTrD9tBYA02ZleEFy2D
         U2hPTjyjfbIv00kU+NT0c/wNLDP/bJwxuXCrD098fUzqc2CbnuEUaKcxEs4vqHaxmRzT
         LQkTJhRkWIAKVthxCsDkmRRZEqtoWTimCr2LWFgkwWIyzT8CG8rbP4o3uuvgYQKEJgrv
         I59Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQS68UPk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-49e6b403ae2si516040137.1.2024.09.18.19.56.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-206f9b872b2so3366015ad.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYCuQsMVZaLc0NxydsQmDWpSB49wk1bv8CooQZjTGk9LrLg0sS1ou8CMP28LWqD/+8J8SlIBiypV4=@googlegroups.com
X-Received: by 2002:a17:902:da84:b0:206:c911:9d75 with SMTP id d9443c01a7336-2076e3b2654mr336649595ad.20.1726714590396;
        Wed, 18 Sep 2024 19:56:30 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:29 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	linux-mm@kvack.org
Subject: [RFC v2 01/13] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
Date: Thu, 19 Sep 2024 08:25:59 +0530
Message-ID: <a8ca8bd5eb4114304b34dd8bac7a6280d358c728.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RQS68UPk;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

From: Nirjhar Roy <nirjhar@linux.ibm.com>

Faults from copy_from_kernel_nofault() needs to be handled by fixup
table and should not be handled by kfence. Otherwise while reading
/proc/kcore which uses copy_from_kernel_nofault(), kfence can generate
false negatives. This can happen when /proc/kcore ends up reading an
unmapped address from kfence pool.

Let's add a testcase to cover this case.

Co-developed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
Cc: kasan-dev@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>
Cc: linux-mm@kvack.org
---
 mm/kfence/kfence_test.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00fd17285285..f65fb182466d 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -383,6 +383,22 @@ static void test_use_after_free_read(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }

+static void test_use_after_free_read_nofault(struct kunit *test)
+{
+	const size_t size = 32;
+	char *addr;
+	char dst;
+	int ret;
+
+	setup_test_cache(test, size, 0, NULL);
+	addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	test_free(addr);
+	/* Use after free with *_nofault() */
+	ret = copy_from_kernel_nofault(&dst, addr, 1);
+	KUNIT_EXPECT_EQ(test, ret, -EFAULT);
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
 static void test_double_free(struct kunit *test)
 {
 	const size_t size = 32;
@@ -780,6 +796,7 @@ static struct kunit_case kfence_test_cases[] = {
 	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
 	KFENCE_KUNIT_CASE(test_out_of_bounds_write),
 	KFENCE_KUNIT_CASE(test_use_after_free_read),
+	KFENCE_KUNIT_CASE(test_use_after_free_read_nofault),
 	KFENCE_KUNIT_CASE(test_double_free),
 	KFENCE_KUNIT_CASE(test_invalid_addr_free),
 	KFENCE_KUNIT_CASE(test_corruption),
--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a8ca8bd5eb4114304b34dd8bac7a6280d358c728.1726571179.git.ritesh.list%40gmail.com.

Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBZ55ZK4AMGQEZJQOKFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 135959A4544
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:46:17 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5eb7db06bf5sf1306794eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:46:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729273575; cv=pass;
        d=google.com; s=arc-20240605;
        b=N9NHzZJYyzsgIcMYKRZy48STZZkmDbgqqfmGuoLJkxGIWlKDUuUuVZftWq0SoPA5Bf
         Og2fLOYEXmyE9g4BGb31GX43+5euGaQXLE6jCtNf3gc8VJ0ThA5niJtT60CKGSvxzkXW
         l9rnzyyxHjODcycrP1GbBVu/Ud6Rs5Ym/rMaZTyqcaUYgXYvgS+1NRiTl9fDNdBUPnLi
         SUL6ahoWcSeA7wm2zzKddOqc3OQIyPTDqovsjGiQYszX2r9sGplVpk/d7cUUT2vhtRTH
         c0unKI/SmfIb+eluHS69r/VfOKrHtALYjf/J6JYs6Rj/trlsngUMGH/+cTXi/Vj2vYvU
         seaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=MhfKyiIhlXueIkiIFPvQ/ik+1+zwbH1bMYzFJUj8NiY=;
        fh=hMb8ylGYDKoqGpBx8RqeHlOBj3mzoLswB/I/AkDyzJM=;
        b=dYuIk73+B3gPYhWDXmxB82xBFb2R1jYeRXxygSIpz+OeH/Xak74ojTlncj5jYo4Xz9
         jPCBqIcXqtYrIM7g4NX5pZaDe3pV3q6NcqE4Xra7I3k7FaRmfg95LnVzQfxA762TcuIb
         55lw11bayeQvmw5M4K29EJygE9GkysB8y8o3E90qfDCjPeiMlCTdGn8OS6tkktH3cLfy
         yzPrzS0TBvuiptnJZ89KZPK/NHqSTs8YsLqftn6meswTkdROu6xo1+lQJaUtOXraPUq/
         wm6REvlLyN+8vKI19wUhIpvh8efojGBu6XVDrHvrA0A7Pzp4ejXcnZVPwxcrGJnsJuvY
         MFuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WdOTf2cF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729273575; x=1729878375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MhfKyiIhlXueIkiIFPvQ/ik+1+zwbH1bMYzFJUj8NiY=;
        b=HK5EO8d0bbUTuBOmcYI2Y8gaGk6Om7/AAbIy4SBMJJFcdJ2DhlSXm+/ftbqBNR5E9N
         QTQ9ZCkryhh5D//4oafE1yat9MU1dUcBufDsUVFCPa+lnXXcgE0gh6pkjIFt5Te8lSnF
         5evyaNm8UPYNj8x/TXRHDTnPuPEYgSeDLYh4LetuTOo5osgUvMTTqrHJfc2QdfwSb/ti
         3TK/llWQqhljdNawt6gfuzhculD8A9HQo01YT7iTE7nN34Q5nz4k7l0o1Clvrqry542r
         filWLhDTSWOd0IZjNpnjUvrrIXxtdVIaNCjKMoBordCUTwPhOjTU47uwGM6e8iRM4v+V
         LlBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729273575; x=1729878375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MhfKyiIhlXueIkiIFPvQ/ik+1+zwbH1bMYzFJUj8NiY=;
        b=jfWUmWHR85Rxy3NTjrSQL1IumnOT+ChLtJYRzSjLarnmyXelhWx7C31Zw5xJDL/D6g
         Xdmd3I5GqTSozMqfNfmaD0KQ4W++q6Jbrtac8hIJoOEgbxOS0jR+iYr8vzngO/uH2DOM
         VZdfz+hTC9vIqADtUNiretVIKAybgGf6buoPAqr+NK1vcPMCYgd9gnFrBnzobIzNaQtc
         K9dtZSYW3BBO6HKF6sJkiad5kdsniz3UMRcafw/JAz14vHPkGWxQetDE/dSrG5TSR2JS
         x+wrftiXGvC312C5B2eppptROtc6QgHgSfbnT2natWZUlNlDrGhh1/U84JYmFh/6cwcx
         iFNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729273575; x=1729878375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MhfKyiIhlXueIkiIFPvQ/ik+1+zwbH1bMYzFJUj8NiY=;
        b=s7wkxbyTRIW+9cE7EC0zFTYq8/56vDE5cWCoYBw+iKO9tqOSJovPxtCQvQBMQ2gRlm
         +mTK6Kbb5/xJUE/w7Te97Ge4kXTqvr7WpNAKsMC+haQoemijRWaBMWGiZDsZRIiXK96G
         bz66i8eGjhhRaPmwH+LlkbN9TIaxlW92EmtF7CBGlgGxelmoPY3pBr3RIULkhwBGmC+O
         1iBIyOwRbdVCPrYuiFxLIn8qcip3xezu0a9TqKCwScoXIzLFvfpnOH9PA+G2JtN0ZVKH
         aVgZiOW76k6qDFzTVIu9JA5wqY+DuNfxIvt4W/xrISeoQsTm9T5JQpFBgPtnCLh5mSxd
         MtFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzoibjnpQR9WLmO6zO6sCXd90/ktodMegopV0wMjGviS48heMD9Y3K4N39Z6u0DTEsTIhIng==@lfdr.de
X-Gm-Message-State: AOJu0YzF+b8MmcLHtUuZ5ugGOv4oY50zYjyXurLzmZpbSJAwhHRe+9u5
	7H1dTZAs87rpu45KLCGp8rDQMIzQfVQP81AeSYHW1A3l/r/Sj2WF
X-Google-Smtp-Source: AGHT+IG6gpZlepiIvr/Oq47VYyQobiGxCRljW4oM4tzFpApiIF8AGM+t1LIyBbYWogW9IEHy32Q7IA==
X-Received: by 2002:a05:6820:160d:b0:5eb:6da3:2760 with SMTP id 006d021491bc7-5eb8b0b05cdmr2716780eaf.0.1729273575340;
        Fri, 18 Oct 2024 10:46:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e8cd:0:b0:5eb:5d64:a13a with SMTP id 006d021491bc7-5eb6ba51504ls1311147eaf.1.-pod-prod-08-us;
 Fri, 18 Oct 2024 10:46:14 -0700 (PDT)
X-Received: by 2002:a05:6830:6f04:b0:718:116f:c8ce with SMTP id 46e09a7af769-7181a5c5407mr4541469a34.4.1729273574600;
        Fri, 18 Oct 2024 10:46:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729273574; cv=none;
        d=google.com; s=arc-20240605;
        b=XoZAhsYlXga0v/kAqS4CH+0H2oMcnyobbG/6GgIOUkJDIyZPXSOzx1+dDsM//gRW97
         hrtRpIRYM/UZ5edYE+2OWyX3f93H++7pNTB9p/6jQYHD+mBd/aznqXSMwyhQZt2KO/mD
         L6Cc7rZ321+o45a3Oes4N9qi5Iz3EwudvoKzLKXk/jMAnOR3hBkFQrPRVEUeBxRdtqRs
         sflAzrVTyuYQBLHpy4lx1GqWJU0KIPbUFejTAv1u4gBf+//jrT9/PIgmLoIfZdZgSA9K
         DDf6sdSYxBhLfrT5xnqpwVMrgmZyJyD7aBL1G+P5nmn6Op4qL8s/8fC9TbVc/Hr5WQd4
         uAxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=qaM5T4CJ19PBW8+xMVASp9taX+sewdJcY3azhiQ9zoE=;
        fh=eu2RHSqNx4BHkMcpFTPcX3+UhrLKnneomR6ocgamezw=;
        b=CSrMVq9ucVisvm/R820a3YWp/iDKiJUAps9D7Ie6VnrBoBO8rd49vlOUcmvKUBs3e7
         mjjvb25cGM3owxIZXAYCR/W6f4cFCnsUXD1VnXjrxbFDO+wLRs0x1bMmX8NHcOeX0ebO
         guE2y/1o3lHpWkh0EuLa37AI37NaMJL4T1CzbCf2rNu6S3Vj67npKltNqPaKBcSJrq6T
         2gy1q8RuQ3fJLzy4c6Doixf3Csw8jaqHuo0akRkim1CEQT1Oicff49xDLr9Tl5Ncyt7c
         QGdtpoFGxqobLvrMsktfnNOqX9AFR1VuvxnrSFQ5i25Oh7lEqzbJailRP7XMK7QdZsun
         QR+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WdOTf2cF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7181955d056si84484a34.1.2024.10.18.10.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-71e6cec7227so1939363b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:46:14 -0700 (PDT)
X-Received: by 2002:a05:6a00:18a2:b0:71e:1722:d02c with SMTP id d2e1a72fcca58-71ea3117050mr4572391b3a.3.1729273573297;
        Fri, 18 Oct 2024 10:46:13 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea333e939sm1731148b3a.82.2024.10.18.10.46.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:46:12 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-mm@kvack.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
Date: Fri, 18 Oct 2024 23:16:01 +0530
Message-ID: <210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WdOTf2cF;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42c
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
Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---

Will be nice if we can get some feedback on this.

v2 -> v3:
=========
1. Separated out this kfence kunit test from the larger powerpc+kfence+v3 series.
2. Dropped RFC tag

[v2]: https://lore.kernel.org/linuxppc-dev/cover.1728954719.git.ritesh.list@gmail.com
[powerpc+kfence+v3]: https://lore.kernel.org/linuxppc-dev/cover.1729271995.git.ritesh.list@gmail.com

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list%40gmail.com.

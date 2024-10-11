Return-Path: <kasan-dev+bncBCMPTDOCVYOBBHN4UK4AMGQENSXWIJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D65F0999B39
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 05:40:15 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-7ea07766e09sf1385447a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 20:40:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728618014; cv=pass;
        d=google.com; s=arc-20240605;
        b=arOwQO3Bvj5vQj6CRwo+SKswpYvboY6LO5VS59x8tk33JXUTg2doU6KHZaMtZZDhpN
         aa9LETdDAa4RrjqAUFJlHL1UhbV2eAt7AnIVyJYQbngbK6ePgwbHHuE59c0pWm+OOBhZ
         HxezTfJq1FwzB78YNv07Fch7OIFZ61TXW8mb9sYR9JAo39RelqNLIP46MCj8gaWMGCPd
         lyfPxpxfCOIe/h6srNyvjZUZ8wM1Kgv/3DZ2gCbmP/DxhNp1dRAIAlufkR+8QmziIDhf
         TxJ32mlt43jgO4j0kWOYvTWg/qKWkb+NrEKzpGiMSEOT3tpOjkmYhMbGjQwJeXSfFNQ5
         XPXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=tW+0GvIofNO3cmgtzDxscQ5unEZhnNbRsLAXy6jYumU=;
        fh=aaWvIeZEyJVh3FKcj86/ZKrTSBNf2m2yHbxHyAM9www=;
        b=eYFRkogvPpCKrI16mNMqsuITEUH9jTSMOpjHqjUAqqSLMvsiGu5jTSz/pMTasAzVyv
         aDp74C5bLZS53qxI6B1tlSx2/95frGFi6HCCc8JYSYAUmEdTp3cgVT5ca857jzHIr0uV
         fgEqKZ1bQyiolB3y/WqyAPLxpU88v2msNa9mEB99qQimInkFZ3xUpL8/8OXCpBybdVvV
         3/baLrf5p2v/TDOCIa+U3rDrw0XAqW0xJGdH9YFOVGuWcezXpt2AkZhLcwGXYCtniSER
         6ygtwbvq9eSl+Ldk+LGSWD2YN4SOlxtmxZlmGQZRQJ9QSUwzd2SRIfH7uwsK/CGOVguJ
         bo6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xx+3AJgV;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728618014; x=1729222814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tW+0GvIofNO3cmgtzDxscQ5unEZhnNbRsLAXy6jYumU=;
        b=dcpfD2LD7niCco27X+q3BLeRW4R75PiqHBLYXIZ9o+abWAxMjJTIU5DS8ukgNXRo40
         IWeuXmoB3hlmVTQbNpqvo6SY41/T3txy/ON8EWOpAqcHf2IOK9/2mwP7LggsgyHQvU/i
         mOu1uD3PNsqZUOGDAs9PADApTQt9PxeWxkEqInYHhuVOH7Lrxo/0AQZk+SmNV6ChlXoD
         2TerE1nOTWnxdKhM1xPC+c+VB3Y5bBfCZTKfu9H4xCrCKq/GiTa8bKuw58WZ8yKnSuIy
         83r0BBoUORJHXej7FTuTbCD9gdgxih2W7sOcUSULNuksbQw7/dWgNaOPsmjSSFppTm1R
         n63A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728618014; x=1729222814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tW+0GvIofNO3cmgtzDxscQ5unEZhnNbRsLAXy6jYumU=;
        b=IVmGfDuDVBCAYgyYZShHINy5coujtIYJswScPqImfLOGci/egU5W/2J91FG7tRoMts
         AssBvYG4yl/BZW2b21WPIWZ19XTSKG1FNyZsMqyDuJ8m0aV9rrJDc9tF3+oXrjayfND1
         tKwJBR9fmGyhEa87SX0r0dcDPxF4dwyL2yCiirt5fxHSu11Dtrf/vd/HZonsEFF3UoKN
         fFpSD7CuYA8Q0LS6gSkfSs96YrOXCSo+QLrrxsDA4Ercw7qV4OoPds8XQEp8KZ7Cm31t
         ajCyk9mdZwfOvtJHIzQXVPpoEX8Nkw4WT8iE9CyHTVzmvS/2dHDjO2T8NPaUDVNweGdB
         dGfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728618014; x=1729222814;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tW+0GvIofNO3cmgtzDxscQ5unEZhnNbRsLAXy6jYumU=;
        b=H7HDQ+iQRdEo/Q7pQz9X2bIlKfiChI4xsaKh+LqqNjZphrZC1TBx9dbLQ8wC2+0GOX
         4eaYqE8ayzM61eUMaDGawi5E6dBFNQBV9V0pgwxIQ2jdDIgEWjW/nxlN3Yk6+WwtY4fc
         F5S+l5auQlXZOjsYJj7ETv4RcK+5WLNiOoLbdNdRiKoxQchh2kz1rsDiYCsNBT+20rfL
         eXXjMWdNck1aPrrZgXoe57VBF76tMLLaLti4rfB+thMMwpbEPtJNFijIkDTpjEXycLAF
         TBnBunUTFG0RiSKIXqcRZCkdGcjnciKTdSWNprnEe+QKrHX+IiZwVX17B096+f/UjogR
         6JvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGNaXJnvLVZCTb/CXLJSUjxkZIsONOnOKDwRU564UKwVQAoW2aQvCmAqPrzhbvncySp/6ioQ==@lfdr.de
X-Gm-Message-State: AOJu0YzLyEY1fd2DkLu2WnLf9NT+8pJGoN+6neWI8b6U78AuyZtDrxA3
	ETSJSJqNnyNS1MNXvhEJiznMueduVL7JjKW7bNnL9lCQh3BFfVau
X-Google-Smtp-Source: AGHT+IFQOr4I7adBR85/9vChqdx3gcbi9QbudsY1TV+r28xv/w2jD8/oqQmWEhlziVOB/l6ubPqWUA==
X-Received: by 2002:a17:90b:fce:b0:2e2:effb:618b with SMTP id 98e67ed59e1d1-2e2f0a62d4bmr2021502a91.13.1728618013868;
        Thu, 10 Oct 2024 20:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1908:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2e2c81bcaf4ls1128517a91.0.-pod-prod-05-us; Thu, 10 Oct 2024
 20:40:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPFSbQXvhgKQ3E9jWUEekQHADUbcXoswHQjU09BIXgDksSu1zxQ8K2cUhr65zSxSsXHDR0PJxcCNo=@googlegroups.com
X-Received: by 2002:a17:90a:688f:b0:2e2:e937:7141 with SMTP id 98e67ed59e1d1-2e2f0ad1555mr1938124a91.20.1728618012638;
        Thu, 10 Oct 2024 20:40:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728618012; cv=none;
        d=google.com; s=arc-20240605;
        b=KCkefmRyukJdE31C42uyz+ZPuFDw4PoTRNuZABJ6kpzizCBzdVr8ppud4Rtx4k/cvr
         hM1nVBM91FaacudaPOe1XpQQoAHg5xymXxUG5K6OgTOHI2YrMz5nOx7IUAWeObiMCoto
         qNPYuaaFuewSHyUZ2zhb4xp1fnH6KxGwWfSb5PRBK9DWArC5x+kdzo+Yl/IPTFPAQkJ3
         klEgzuId7j1+hQWeHitMuJciley3NAxObHfxL3uMTArJXLNM2ArNcJ0YDmBDm0U55V6A
         uwjhMbwg+NroqJgCzbeCYDF89a8A4b+IerDgO6Y4OiNb65C3F/vpOFwrZ3aIwwxzYK5C
         bSgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=t0vNJQtq/0joVNg50nUAMn3bpfuOpVBsQDBObE5W4mI=;
        fh=qCOi0UXZhkEyC1jsWCPQ+spiRrDy4k5zFFskEDhoOaM=;
        b=dDdMKLAMD3dFEm2B0dDvOVkDT79q+no5RmeCXwFCfHQY6szlHEZwnv2tPKq4ytF2I9
         MaZGlycHQkASHsfFjLld5zR749iORQpsX0mF4Wf2ZurUbrivIVotKXnVOORcs+j1YBrM
         HQvT2UTvLAWL5jtoaRJsMY39AXkl6FeXy8hGvtnKCN+Qvp9nDSar21V14EZGBATRSDBy
         Fhi6firYz/2lguhGFtDeVzDN/P7ywDCWrxmUjeL0R+ULdlz5Aeir76k74wAIC0HFaGoN
         93OboZawdIQVcw+ME9yzj5A+P1K/cQHvbi5sKuIT0FdxlzZYVh5PceaZUIIDsaaC6l6G
         Wk9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xx+3AJgV;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2c08ade3esi312197a91.1.2024.10.10.20.40.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 20:40:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-71e408c57a3so1038b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 20:40:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCULdWVtXC1Bu5i9oNeoDWcmLHrU+ocvtxLz3HbyoxKY4Ff2ztXKjKQnqV2HRZVcFMlm+yR3ZirUF3Q=@googlegroups.com
X-Received: by 2002:a05:6a00:66c6:b0:717:9443:9c70 with SMTP id d2e1a72fcca58-71e37e4fa3fmr793355b3a.2.1728618012052;
        Thu, 10 Oct 2024 20:40:12 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e2aaba3a7sm1777651b3a.169.2024.10.10.20.40.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2024 20:40:11 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	skhan@linuxfoundation.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH] mm:kasan: fix sparse warnings: Should it be static?
Date: Fri, 11 Oct 2024 09:06:05 +0530
Message-Id: <20241011033604.266084-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Xx+3AJgV;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

The kernel test robot had found sparse warnings: Should it be static,
for the variables kasan_ptr_result and kasan_int_result. These were
declared globally and three functions in kasan_test_c.c use them currently.
Add them to be declared within these functions and remove the global
versions of these.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
---
 mm/kasan/kasan_test_c.c | 13 ++++++-------
 1 file changed, 6 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..d0d3a9eea80b 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -41,13 +41,6 @@ static struct {
 	bool async_fault;
 } test_status;
 
-/*
- * Some tests use these global variables to store return values from function
- * calls that could otherwise be eliminated by the compiler as dead code.
- */
-void *kasan_ptr_result;
-int kasan_int_result;
-
 /* Probe for console output: obtains test_status lines of interest. */
 static void probe_console(void *ignore, const char *buf, size_t len)
 {
@@ -1488,6 +1481,7 @@ static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 24;
+	void *kasan_ptr_result;
 
 	/*
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
@@ -1514,6 +1508,7 @@ static void kasan_memcmp(struct kunit *test)
 	char *ptr;
 	size_t size = 24;
 	int arr[9];
+	int kasan_int_result;
 
 	/*
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
@@ -1539,6 +1534,8 @@ static void kasan_strings(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 24;
+	void *kasan_ptr_result;
+	int kasan_int_result;
 
 	/*
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
@@ -1585,6 +1582,8 @@ static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
 
 static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
 {
+	int kasan_int_result;
+
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011033604.266084-1-niharchaithanya%40gmail.com.

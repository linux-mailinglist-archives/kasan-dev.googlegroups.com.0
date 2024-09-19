Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBZNFV23QMGQE4OK2DUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E6FBB97C2E4
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:38 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-2073498f269sf5522825ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714597; cv=pass;
        d=google.com; s=arc-20240605;
        b=IYKxj/WLm5TuXdKZjvxHDY1Dea11kGZ6uXLfT0YqqHsz+AUPs/VPFc2KIAF/t0YaEM
         W+/eVeLgReEKYfEPjeMfKTK3UrzKQ86OChiBwo9l60hlGgfV4r4voXaabCyWzYWmKe2R
         8GbDxo2EbF2iDIYEft27ty0MfFkmlzwM7wPo4L7SiHFddHt0KjlfarRiGcA8yl57GMRV
         fTPXxaImx5RSuiWFkgZZfDVUsoPRSGBRfDZCptloCem7/BsQ9tQC43D9guFdzAbYxc2F
         H8gNXjDoqzr9vIB6a5OeJ4ElE6porerXYDRS2VALiov9Lhq9pSOeerDjuiMa97vGqN88
         wS+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Knb5qh+IVB40jHCEZLoRsBD/AOc62Paq4Dy67w4Qy9o=;
        fh=ta5SQU09Ajb5SdQZS8DXeVPRhof2Gjt2+bDp+UJBbiw=;
        b=bB6gU5ueCldW1hVm9bfAZ8fPVIKGibuAwJdrBQMUS83qPfPB3l4cT0DI9nUjJXWjvN
         o8Y+EDwxd1LIpt3p71hVNNj+83Ri6BmB2iSfXVCiBdlzoCSXBJPOdiwX6PZrOKao/YI+
         8YTTRcUDZPIL3KzKtpikMgMKiQ5yLPUIILHFSqB4D5mEA2B3qWtvacm4NUUxTqOJ9WId
         cCYox/KwGzup+69qlMuH8JiG3mOnroz8n7ACgk3ZSa9DZdjX25l9k/JLp32qeTNH69jC
         6keRmTuOd1f6gcOdk0NIhXoRxCUCe0pEcOA7ZLNymI35wvsTCGnuECbJEbEjV8LpE0dW
         nMAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lQdEIiDF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714597; x=1727319397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Knb5qh+IVB40jHCEZLoRsBD/AOc62Paq4Dy67w4Qy9o=;
        b=QlForxmRZBbaFMBDK9yAT8n0ufHHZuRlcCVQNUdIn+aDh9hIu5Kst/nhP1FIxhu5eZ
         EEKssBEJAMPAuXvJrWMZI1R9UKjIx8SsTrVvo0dlrip9y9+Uvf6BZv88I+HX8ycUFW3w
         99kF2V6TzhAwjz1+J6ugoNCPcrLzMtHOkU9Qll9HIg6I4AjxufvyhOB44rr2fBUldB94
         hPjKKlFtHuS29G6rU6StiGZ1I+oHqzSnefANWYEJxXSdP3xa+yzBtu/omLXNLQ3W0ijv
         9bnzxaCCJ+3xU4IsoVeruf2SEqdJvYf4ADKiNR6KfsL1oNenBqt57UgwvIA4Us8zodDz
         heQw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714597; x=1727319397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Knb5qh+IVB40jHCEZLoRsBD/AOc62Paq4Dy67w4Qy9o=;
        b=dInYWto/rsYE0YbpSjHOJWABLRc5ELMAG7aatwSiB/yEfqyo0ZWUY8n2LgDlo8c0ct
         +fNr6683QHJdC8vgOlR83LF2ZqWuqN2YQjg8CLJ0dY+JjbpERuiZCi7OVYYj1TkVIQDd
         JVGdwpQ/ZbYftCXwqd7xpC3JJxxu5H2EWhtOkNPqIoESvoQtffENekACDuLZw3MUR2iY
         4JCxs1zQSqTPj0q7m5geKCrX3nq2dM2aRY9mIDkBgtXtpiwwha0w3S9O2rbENeTRaIgY
         5+iv2w2Spi7Zl6OlKc77FP/kaS34xNOSEuJHiEn8MlQQhUtg8rV0pE9HRwO/rb9ymS5D
         VlIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714597; x=1727319397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Knb5qh+IVB40jHCEZLoRsBD/AOc62Paq4Dy67w4Qy9o=;
        b=xM5GRjzhgdLgysdzJQZu0RNlXWIi8RDmo31Di+8M38+eNWpvkUiTru5z6jZP7HuKw5
         lR/pycilEoC5nYwXLfGE2eZGxzAtMFzPjnoRce5kMXqN1V+o+uzWftpL5sW9px269StM
         neZIKNOom7izWJw4iqC80Xa+NnbcF8Qrj6wM+WSe5kGsmknsxYAmCRlSmLh8h2zjeyz1
         xtJ5vCjM2raFe/N0KIWWZS+TjXKieaw+0bSrbnymLbIMzlJuXwervPEcVA67KTsOT0ef
         fl7CpUZM0HF3SPS6AZT+Hj0eJ9w04w/1Vz+B7zGtjDvXlb9UCfMy0t2ecSRLF22+UFNv
         /Ypw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsWqDDJHZVdccTbkjC9OWL4ebpWAByo3VZML9YU08lpj/O69sOaLvQJj1CkDv/dDnUy/uepQ==@lfdr.de
X-Gm-Message-State: AOJu0YzwdK5b9hKTPXDPj3gFKlhhSuTu38cEWtrH1R7ZfxmiAQyUoqAs
	S3l1Bss41Pd+qcDt3SDB3EjrdGCYDoBfQo2Nv8u0eVvvqe5tDKKA
X-Google-Smtp-Source: AGHT+IGJeVtF4DN1oUF4J/9m2m742fwd9cVd21DhHFXTePUypw6EqgG6a7EcL8Eq66+UBO77Q3CKvg==
X-Received: by 2002:a17:902:d4d1:b0:206:c776:4edb with SMTP id d9443c01a7336-2076e4876a9mr407538045ad.52.1726714597335;
        Wed, 18 Sep 2024 19:56:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32ca:b0:205:43b8:1aa7 with SMTP id
 d9443c01a7336-208cbd4a4b2ls3439355ad.0.-pod-prod-07-us; Wed, 18 Sep 2024
 19:56:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6xaSj5ToOysfwdoIA5Wx8P1vdCZHg9+e1Ttx8waL0+nSvN+VpgrxIrChRKoMSAy95W36JGzWX/zw=@googlegroups.com
X-Received: by 2002:a17:902:ea08:b0:207:13a3:a896 with SMTP id d9443c01a7336-2076e3c43dfmr453421535ad.23.1726714595924;
        Wed, 18 Sep 2024 19:56:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714595; cv=none;
        d=google.com; s=arc-20240605;
        b=h42NgAPCxRmiaApHnZKfXPDk0iwmWkyV/E68JOu8IuMIbw/4zgyws8RUrbuepISAHd
         y1VHfnAelhie17kvtRQqAScV3anTlSTSuqjvdwblHL2IBGj8gQy/niK/6tHM6wBsEHzO
         w/iFE3mxjGvMeD+c+NsK4MW2l6fYk/fPCJpNZxyiiUkgB3KA5kKA08H4kZXAJEgGcmST
         VQ9k/HWC4XSkIab6PoAaRD6bKYyPi/fQcQcoKqt02fjLR9skQpAqz3XbD9gsKcoDrf1X
         IGnldVbojet8UFAU4RaQC2//lGdM6e2lFOSAHC9/OQXRBcyc5Tq1ZyNh/F2S0P4L2/vZ
         /iFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2IOurK7ENej5lHHiP4d73lr8yQG82cdevQPBO00m0fo=;
        fh=He4jORfA9bm/Wj1XW4HI+OnymkSG5sR87ZMcWyUKPx8=;
        b=M8H9NQN2nKcgwhskUlU6H5MrPyi+3F+PV4oaeB/U5w/9pyPmvl4aZwwl/rTuw9NanK
         fqRBlZZaOt5+5ILhs0NRF1/U8x0BQqJgMimEHOyjreFNPLRtLf4dFibbxJxM6dbgT4of
         KhpRZhesd8T7p1wxqVkGXceWh3E4xLvRIPYn25y89DfIm3864n582zlmp36kBPKRwqKo
         6rUnCBBDsVbOyJOGeHGo96Kk6VyK5VoQ0VldSVcsY7HvnwQ1QFUcndGCAfE7l9XhEdzW
         jueVyBbafkQZx1aRDe4emmq1Ufet3vJ78Nj5ENN4CdASTGm4HOFJM+nrUBXxWMBhR0Hp
         vU5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lQdEIiDF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20794611769si4017855ad.5.2024.09.18.19.56.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-207115e3056so3701725ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwEOg7UmiLGOAGUWEDlmV7P3VozO40oCi1lXAdua6jJE+WDZphi151a4YaqPNVChRUq1ERjtyD8KE=@googlegroups.com
X-Received: by 2002:a17:902:dad0:b0:1fd:5eab:8c76 with SMTP id d9443c01a7336-2076e462c42mr369019805ad.41.1726714595450;
        Wed, 18 Sep 2024 19:56:35 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:34 -0700 (PDT)
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
	Disha Goel <disgoel@linux.ibm.com>
Subject: [RFC v2 02/13] powerpc: mm: Fix kfence page fault reporting
Date: Thu, 19 Sep 2024 08:26:00 +0530
Message-ID: <87095ffca1e3b932c495942defc598907bf955f6.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lQdEIiDF;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a
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

copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
/proc/kcore can have some unmapped kfence objects which when read via
copy_from_kernel_nofault() can cause page faults. Since *_nofault()
functions define their own fixup table for handling fault, use that
instead of asking kfence to handle such faults.

Hence we search the exception tables for the nip which generated the
fault. If there is an entry then we let the fixup table handler handle the
page fault by returning an error from within ___do_page_fault().

This can be easily triggered if someone tries to do dd from /proc/kcore.
dd if=/proc/kcore of=/dev/null bs=1M

<some example false negatives>
===============================
BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
Invalid read at 0x000000004f749d2e:
 copy_from_kernel_nofault+0xb0/0x1c8
 0xc0000000057f7950
 read_kcore_iter+0x41c/0x9ac
 proc_reg_read_iter+0xe4/0x16c
 vfs_read+0x2e4/0x3b0
 ksys_read+0x88/0x154
 system_call_exception+0x124/0x340
 system_call_common+0x160/0x2c4

BUG: KFENCE: use-after-free read in copy_from_kernel_nofault+0xb0/0x1c8
Use-after-free read at 0x000000008fbb08ad (in kfence-#0):
 copy_from_kernel_nofault+0xb0/0x1c8
 0xc0000000057f7950
 read_kcore_iter+0x41c/0x9ac
 proc_reg_read_iter+0xe4/0x16c
 vfs_read+0x2e4/0x3b0
 ksys_read+0x88/0x154
 system_call_exception+0x124/0x340
 system_call_common+0x160/0x2c4

Guessing the fix should go back to when we first got kfence on PPC32.

Fixes: 90cbac0e995d ("powerpc: Enable KFENCE for PPC32")
Reported-by: Disha Goel <disgoel@linux.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/fault.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
index 81c77ddce2e3..fa825198f29f 100644
--- a/arch/powerpc/mm/fault.c
+++ b/arch/powerpc/mm/fault.c
@@ -439,9 +439,17 @@ static int ___do_page_fault(struct pt_regs *regs, unsigned long address,
 	/*
 	 * The kernel should never take an execute fault nor should it
 	 * take a page fault to a kernel address or a page fault to a user
-	 * address outside of dedicated places
+	 * address outside of dedicated places.
+	 *
+	 * Rather than kfence reporting false negatives, let the fixup table
+	 * handler handle the page fault by returning SIGSEGV, if the fault
+	 * has come from functions like copy_from_kernel_nofault().
 	 */
 	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, is_write))) {
+
+		if (search_exception_tables(instruction_pointer(regs)))
+			return SIGSEGV;
+
 		if (kfence_handle_page_fault(address, is_write, regs))
 			return 0;
 
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87095ffca1e3b932c495942defc598907bf955f6.1726571179.git.ritesh.list%40gmail.com.

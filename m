Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBBUNW64AMGQEHARQKWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DF8299DB89
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:00 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2e18b6cd304sf4419382a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956039; cv=pass;
        d=google.com; s=arc-20240605;
        b=lF9RSYY6mpZ1Vjois/5DW3mmTCh822TiaCBzhS0GzAPmt3MktoTjqBOaKkQfukNGBZ
         vyZypAmye3RIb4FtDsTY45jn7XvuPq2oYwvGOAxe4lqZTvI1QIedp719N52IWLwcMtZJ
         o0IZm8BoECbdMdZo92ZJdtAGsWBOEvtpC6PwzY68F9sV02TgFZL7ef3HseKPKfJDsVR6
         r2Pu6gY9hoMBDAzTEkS3EllciAMLR//+LMKI9mQvgKOGpBxkaRm7hGwa4bXVnwOsOQ0B
         dmmyDVO/o+zhdjUefjzaL76n6GFtgmFdobJirQ9Cr0Sii3i7FTzD684/omO+7lOQYg+c
         jKxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=q/OE4gTzZxFrlTOYVIiMCX5Ai8CCTVmu8C8L5zIpeEc=;
        fh=2DdbdwYY+DjYcXBZXIfRGZwn/QEXDBftERMzwUK8di8=;
        b=lHXbCqj+tacq9rNd3SPE5vrcqA+vIU/E9SkQigHtUgg+XOvjjNfzniFDvNw98AVt/x
         alAyeIutSioA2G3kHLOXw2/iCbRM34cdkGYZGER0BPc2N0sYt3Lyp3Vd7Kxhbv+0kY5U
         9CyaklC9ILMzD5eZi0iUX+6/6AMiD6s+/70Kc1nyCdnJ9U+EcMltZNn3NdC6Iwauupky
         JS06B+jjejmpZuYyOtJpHn/4+iWVDY9HUkvTWPThphalTDdumBB3QoG1ZiWzhfdvpQu6
         E1yLpHkTwUxNEQq5lS7FFVSX6KznSLH0+J3EadsUwBxDzW7MCo1pFaRS7NZQWecJ1u3v
         Bh5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OF23yqKH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956039; x=1729560839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q/OE4gTzZxFrlTOYVIiMCX5Ai8CCTVmu8C8L5zIpeEc=;
        b=r9P5aoZ8PoaJISUlEN5VOnqFlUiaIubKarjrRaZYRDG+md+YS/4/PRnB3XVxFAVGzw
         XkrGy5XxknEF0OI+WJSWSvDFgQuhNEHyRHvBp18lmyHxCZTPTDqkiocJ7B0W72BRLnfe
         av0TCfEZ7CMATGkgtcg5i0TNdg+rmUzV7cFLqiQUQ4t1AU92IqoUBdJ/lunjl909zLnj
         mdtJrcxbFYLHA/AAZzQakBC6ArFnkz0b37S0zGWO614o42gIFRqHHhYeLJW3MZ7AFu1z
         aU4InpE7Gx0HFZDms9DvlIXF/JJNMGDrIdeNf9bExuZt2rzPYVM67cUVZYfKyKW6RJHU
         PTlA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956039; x=1729560839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=q/OE4gTzZxFrlTOYVIiMCX5Ai8CCTVmu8C8L5zIpeEc=;
        b=gwzpR9O29tBMaUhqXTxeQPMPQC96zDyl0oBoyD+shg+NoPejNKe8jLR1Qj/Ho1EcsQ
         Vex8CROh2a5WVQKD7b+BY7d9Xq/LULNp00NuYjwwdNjIzcYHhSCyY9ptjUn8KNr+r5/Z
         0xQbWeJryEQTQna8TuE9F4ZcYycUD4cow9nR7WxRI1XPuJELeJVl0NCAU5FwQrWTJ6yu
         kUl16sFzxfdjW0jTrGQJxy/fzNP9wS7HwzWxMEuRDgg/gJa2AKa3oLpPYAhsEXvqkfZB
         AIEUBLMbXNq0VrDZriavZBJp9SUZSahnIgeSsh1yW64pvNDhPUzK1WhgZU9wT1HdQR1e
         uZkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956039; x=1729560839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q/OE4gTzZxFrlTOYVIiMCX5Ai8CCTVmu8C8L5zIpeEc=;
        b=WKO/v0ZbdIsW/qAh+DscYKmSVDqTSBs+KxIWdYBaU4jG7npvsP21awBNmv7rgke6PZ
         d1l5LU8Dzq9FfEcJzkXQyF/XlsldtUqaml4NSDUMIUqI/lIhl9s85WhZiqmO3IpTOZ5X
         2J6CCKe4kFPO4A/TN98HYc+TdJ92ZppZj0VTKaegyrLtPiprtpc3m8+fZC4eTyyk5b6F
         BmUXXR4ClWqsPcdTiirQW1Kl2Uym43hSvNi1J+Q95uARWT8mv9tKZdtCqtGnRFfHYotA
         RUQZy4ZrY1XOgY4RQ1GPxsRK/5sQu1ia8xAX9R/De238fVvSdQCqsN/sViLHgnEeVfbC
         xENQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+ceB725N2w25aIr0tvT7WG9huASsKURkeruFEJ+nyed7zWS7jSEbtdxT9PvOhvseZ5ItRnA==@lfdr.de
X-Gm-Message-State: AOJu0YxpvhLXNNrjeHdF753q0J8+h//o0L/ejAQZdM2vcbcudjIodAC3
	NMnXuTWAagRW2Tq/9O6RLV4EKELqFLv0Kej3vgFeyuh+vjtIaLi9
X-Google-Smtp-Source: AGHT+IGL/P5yuREU+xw1K94yKUn5LE0UGS6B8WzFQ7jAgWpI50IOBzNrBIGmSq9GJE4butOGZCNADg==
X-Received: by 2002:a17:90b:1c08:b0:2e2:cd22:b083 with SMTP id 98e67ed59e1d1-2e3150bee4amr12315768a91.0.1728956038860;
        Mon, 14 Oct 2024 18:33:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7c9:b0:2e1:1d4a:962a with SMTP id
 98e67ed59e1d1-2e2c833665fls1105753a91.1.-pod-prod-04-us; Mon, 14 Oct 2024
 18:33:57 -0700 (PDT)
X-Received: by 2002:a17:90b:390a:b0:2e2:af0b:8f2d with SMTP id 98e67ed59e1d1-2e31536de5dmr12250900a91.26.1728956037282;
        Mon, 14 Oct 2024 18:33:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956037; cv=none;
        d=google.com; s=arc-20240605;
        b=JmckM0nlxl6RcpAo0FgTeyzzgnoRtqiE9zcKFvtYIKt9dMGoxWuQm/9CQ6+LP3EyXp
         qAVm4M9JQ4R6CXvwOxZNpih9YSpqaH1L9EOOztBB6grc6fWCGI+Ucg94MSwOK7UMx2kM
         sIF3sT1igW+d4K4jTIN3Ug3xheXtweA33TdNNK4/rFWAHNiIinvh9Vh7/hEpDHCPMCAz
         wZ9GEY7chLG0VR5ifHaiRtuI7/oyX0ouKEzQgTAloC5BsBcAM7j6bIdA6mpeYFMdWvkC
         mGvmOoE8bTsukr5KRGFOImn0O7TjdKZqdX58lvLDW0ZUVSxxTiCWKewzSTRCOAGmvH7x
         JO7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2IOurK7ENej5lHHiP4d73lr8yQG82cdevQPBO00m0fo=;
        fh=LbsfU9OIZC9T5pvBT9rrCWBYngVvNq6pmOpHR6dSp00=;
        b=Q7SXyKN6Cj/NH97hBOixmcKc7g3o0CQs4XWeVbrnW/WDntg9454QsGkNzgglO0PJjY
         7A6IcnM3Wr8Abv/UptHHYNljamxaA9V2s86lll12/7Gr5sfaWWkj2GNJ4PeGLP8/YpXo
         dnhoBx+62ijkCBpGAMcyS75PwPt03A5UP4Pei/jaBLTdqrDiIQtWbbfclyUBFnI1In0Y
         E9Wu3/ZjSh3bxXvyJghAaag9A7Ok8q8PYjwB/42UwNDKH7mLTLPro97SGWqfcQdvKo03
         pgUh87czL10MOX0KNc4iHVWT0C0qrklPf1yjhJ6rdV/jyC2yi7m+thanyYpOdRWNaOkI
         5l6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OF23yqKH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2ca44a71dsi1110183a91.0.2024.10.14.18.33.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:33:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-71e4244fdc6so2247658b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:33:57 -0700 (PDT)
X-Received: by 2002:a05:6a00:174b:b0:71e:148c:4611 with SMTP id d2e1a72fcca58-71e4c13a1d0mr15707237b3a.6.1728956036726;
        Mon, 14 Oct 2024 18:33:56 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.33.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:33:56 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	Disha Goel <disgoel@linux.ibm.com>
Subject: [RFC RESEND v2 02/13] powerpc: mm: Fix kfence page fault reporting
Date: Tue, 15 Oct 2024 07:03:25 +0530
Message-ID: <6bf523aa03e72d701d24aca49b51864331eed2d5.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OF23yqKH;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6bf523aa03e72d701d24aca49b51864331eed2d5.1728954719.git.ritesh.list%40gmail.com.

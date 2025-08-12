Return-Path: <kasan-dev+bncBCKPFB7SXUERBNHR5TCAMGQEZWLY3NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id DB151B22760
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:51:02 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-23ffd934201sf43696725ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:51:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003061; cv=pass;
        d=google.com; s=arc-20240605;
        b=hl6uA13WjMrVKCWp0WO+x+D6yd4hFc3sG+U5BoH7+7AjOCzEAuBaB7GB81QCdYUXIf
         peJ5+I9iL5NiGQoxudeHwUK4y4B0C4hRwtnUppDvnGDUibOrDb5JhZ26xK3SpznMZ3Q8
         m9hJ3dRZ+ndJkHwNZHgiPFm01N6lr/Q9qIuPQDwmUMwHtztMtH1AMhkQSM8BfPeCEIhD
         COWvmb87gF6J71Kjrf+cg788RwksH6e7daf1++EKTV3kBpyc/T1RlYzxBloHz/CHbLk6
         g2wWpFRaJU8JbzuiILRf0ahUVshPskJoi/39EOKBSVPQvdOhDt+OnGEjmuRXfsVLUXEq
         mSVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=RUnpxnuBsBAncGZ/OjxDAZHtI2eMMwtupJO2SieNPAA=;
        fh=s++ugO5I4KOKvYEvU9t1meb9kTr6B3p1/yl7fF8HVrM=;
        b=j9ZThYSRUeLDhLyZHInzn/67M4n7Etp6f7rlzZfaJ3U2W2R26zLRQSDMlcH3Z3Cs98
         IZdbZeWf6njEzXkKS+4LEodAt7lw5W1ocgkCdC+Gu+WnNwFNkLHvhO6/0pasYvKFBwje
         W0BLQhsDNjsZ25sXnzzuu+KHf0rIx2LQil4OfJ5SyCZB08cNw/1/PWfmS7TbnITHoofz
         icQvEcZnqzjjth3QxIB7Afivahua3d7Mc44zdFzaIcsAJ4y2EbfZLD1CSu3ok4SRiqEE
         MaToyT5YIkgtakTfZYcec2h7tKa0jjkzr12RzOmedYDCgmbFFXZ4TKluLJewWGcopmAV
         eQcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PWJprqUm;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003061; x=1755607861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RUnpxnuBsBAncGZ/OjxDAZHtI2eMMwtupJO2SieNPAA=;
        b=TD9eUzin8AneyWQ3XZpWVgaUhQoaYylHRpoOkPLPlc53lrPAI0sqLuQmIxqisNejhD
         j60LG3UUnUSrn9XqlxOt5sHhJBb8TEKF2FDARE/dkFkN/l1CyfkJtQqbJPSLER3kq/cb
         bWXuoDI0xw55pmXQKVuLWyzKJJDjYIAYCOnpFoW/lCv1H+v9r8SOOaudGyI1XAA2ZY/d
         UxJitoQul5wE5kBMhS8vjqkxAnc7PJS+VlMJvFOgaZ5yRKtPmJmP4XvksTRZBr7M9YyU
         uBi5icMWjYVJcC7+jqnZQyVQKMJxapeiQQkG1fJYoelEJI8kI1QP5LO8TlBA1O8nc3ms
         3gPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003061; x=1755607861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RUnpxnuBsBAncGZ/OjxDAZHtI2eMMwtupJO2SieNPAA=;
        b=hIkAnPMkXF5T+dzubLBq3GxjSr/Zeg+v5W5vO520qpyAXRx+v7liuL4EQCQ83o89Vo
         ItYskKzdThhhEyuBvzYpfaaQj7sEkRK+zRg6cZPWXJ6Dsgh6f3nwyhmBSw+24Rd2U3c7
         zkgB7bA6gu8CYiRIN5cBxiXaUSfMKR62CrWtgFi1x8+l84y9BZC/4XNhdnOc6TfcxPYn
         e+VCcxl+37Vg74kmE6dq08ReA57LoPICqYxm8sCrdFRhOBdXZ5ShFHvzrXKQyTCAaEEF
         gcUtcK+STfsKZgGAVPLOCxPorUFMQea37wzXU/uC/pzubu1FGnuNJfWxg/VSJaZfXeo3
         drMw==
X-Forwarded-Encrypted: i=2; AJvYcCVJCWQ/kIo/YOsk/BOS1VRqNKc6pW1hyM0HADWiThI6P7qHsk6Gc5sX4PDlnZ3n27tSbnH3rQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxz1walRJnpBUsD4YqPqDPgZ7Wq/yc7w0A7jlfU2XgGG/nrCZaY
	TkBJ/k9xv0RI1aVZEN0VdyjHWp2sS9H/j8awD37UQrA8o2JoWvs8vnV/
X-Google-Smtp-Source: AGHT+IGi2Xrh3E33WFr028R9Ge4cSwt02DWoJE7U2hnPHDZHpfF1TWIzb2Hp4ibo/nWDmLcVjGi1fQ==
X-Received: by 2002:a17:903:19cc:b0:242:a3fc:5900 with SMTP id d9443c01a7336-242c1ffce82mr221391725ad.8.1755003061151;
        Tue, 12 Aug 2025 05:51:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd4D6cnfuL2m26qXkOlXG6axAABYLshYyJukyld4RQjow==
Received: by 2002:a17:903:32d2:b0:231:e735:850a with SMTP id
 d9443c01a7336-242afcfff80ls66203625ad.1.-pod-prod-09-us; Tue, 12 Aug 2025
 05:51:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIgwaTSb6k2EF4D/y8oHKr2+K+sB3h/vqdKXpHEJ9OefxLkW8njSgt9xi2b/gwgVCw6RtQNj8TT0U=@googlegroups.com
X-Received: by 2002:a17:902:da83:b0:240:7753:3c07 with SMTP id d9443c01a7336-242c2209bf2mr238224045ad.33.1755003059920;
        Tue, 12 Aug 2025 05:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003059; cv=none;
        d=google.com; s=arc-20240605;
        b=aRwwmGURBEEorsybDFtfk5QWZWhofgjnqi6IAWHWWl9kRKnDzTQXvsTsVLTF4Gws89
         nezfIaSwaw5uVeruyi3WZN1CG/Im/SNc0dy1pNJDs46jvIdaoov9ratkL3OJjkqvVNST
         PGqpHn3Yv/RwJrBe9zHnr0DVeXhKMGQ4pLst2jjvAN/dtD0PUW+ykVO7SFYCsoWd5hxB
         KH3XS031PLTG4uW0s418iiYyeX18fs0ReMnX/kRSPih1+kg9C/oUul0hhVZxSNJYa4jM
         ZEPves7JU+3KRMbxelfiWYjcASdYCne9k+G9xVXITo2fjUeGUtorQ7Y0P5vDRX3w0CVA
         0nOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KrTt3YvXHtYUuoIddMbmkc8QXtgLzrL59sgxurx8fJw=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=iL8Wh+XvIyphgPsUyQocUdHhX5+mAJ6jDeTSSxWiSACg9KGFH66JALXdQzlGwACNJ3
         c5L5jKN5iltSwVLt0ezCOxt/urWplaH8M+XqLZrC77ntFlUxXxkg//wXpdndaJY5x6cJ
         FvlD6fKpbC8fxXSFsc4Q2nzjSfhUdPCzxJTwNs5DtHJ9gc6n5KtfdOuIzVF+kLOYlz2L
         +mq6ggdYp1o5eFC9wQ4q2lw6YF5uZEWyIgH7lziQO8c+yWdTy3Ch3668LmfMnzjUhtnS
         PAuPPB6Jyzrw1WU5CI6xrtegEN0fE4rc9hc/E3pj7fLjMUL15aOkfjfzvdqt02K9DIdb
         4/ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PWJprqUm;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si13855405ad.5.2025.08.12.05.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-9-IghP0uCBOV-OwVmnG3ieZQ-1; Tue,
 12 Aug 2025 08:50:53 -0400
X-MC-Unique: IghP0uCBOV-OwVmnG3ieZQ-1
X-Mimecast-MFC-AGG-ID: IghP0uCBOV-OwVmnG3ieZQ_1755003052
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E143219560A2;
	Tue, 12 Aug 2025 12:50:51 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 4F13630001A1;
	Tue, 12 Aug 2025 12:50:44 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 08/12] arch/riscv: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:37 +0800
Message-ID: <20250812124941.69508-9-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PWJprqUm;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/riscv/mm/kasan_init.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca4..ac3ac227c765 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -485,6 +485,9 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	create_tmp_mapping();
 	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);
 
@@ -531,6 +534,9 @@ void __init kasan_init(void)
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-9-bhe%40redhat.com.

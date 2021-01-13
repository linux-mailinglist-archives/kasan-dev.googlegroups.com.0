Return-Path: <kasan-dev+bncBAABB25T7H7QKGQEVHEIIKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 335FF2F41B8
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 03:24:44 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id m203sf905381ybf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 18:24:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610504683; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZhhPybBu20IHkT3xSKH3sVvz2IPaqjYoBaXNnt+/SrM0aTU1ybho11QrGTeuEdaRM
         Ho+hlAV/paVUCGEmSbHa8h2RABrSz2+DcsrjwXhi+MPkEBT9aP/PVsh/wVYdkXyME61e
         MRTu7FGcdM69Bcqytg2gIejw+Om4jlVumZFPLr/XPCa7s9jAqaFv9r1hXt7Q3fz9twhJ
         Uzi2Vl5Uf1n4aUlrkXjnM2forlaD4Meof5a4qn0gDMI1WZIHB+koM+8sBH/fvXcPJgVo
         ZQXmgOrt4wstCPRoduhpsjWQ3oelx0ADNdRjIr17GQKja0FNEJZVwIV9ZabTa9pXufRF
         CUWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=w+sbEU9ZVwWx1XdhloxL4Alk619mmHR+dDppdFPksVs=;
        b=n7cllilAtnwaUlJJNSMYt6ELpCqQELnfQ0pDPnDprgpUAZdxs+D424DHjbGZkHpwHn
         NuJZfTrJf4ckrbT7Rhd/9XyPPTzxg0eJGK4h5UhjHWphNwCA6WKOLnVhNuc/cm1yZlxO
         DVnzhpqW+bwqjmKhhhO5Qh5lYQJiZT5IW7rp+pnLNiqNR7IIocoz+ISEAZLV/OLNN7a3
         sW5OoGqoa45Y4MA8SXCGvir2Ns4vqXdLOl95Vn1pReQg1DMuYU5g4l4RzFF8dYq1Xeub
         CzkN6djEF3bP/BK+naXsb9tv/dZmxkPmM2qSL9fXak+iMK9gxMBIkeJFD23utBqG7qB7
         LdUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+sbEU9ZVwWx1XdhloxL4Alk619mmHR+dDppdFPksVs=;
        b=pFOh1lPG0d7Dzx2lMnm6YnrSCis5KBY4bx+pVoUdH7h1SaGhRrrBkYHRDUyDhKbPO6
         jtSJRkX0GqE4ZNFUwHtUU6lFt1EO/Fp1qqoOBTPXJd2IlJ7GpWS0PZmYZhPkkZjRQ/8t
         XYOxMZilUsJjsXRoGNxSlVFqnSNwVAu9KkGnzNYxfWt8IX/ERU4D4WIj+gZLmEqaFsRc
         0Zk7uoUMZmJRr8/jF/daNAZrT8yxlp+ML25Mtuj+feSY4eUVp3SCn/Fu2mOHv5WnDfg8
         YXpAYER2EFJos/LuNszxVjYN/aoOzrFolcoqzzZKXdHWjgjVG4kIqkSwF+Jx30PR/rGE
         cYmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w+sbEU9ZVwWx1XdhloxL4Alk619mmHR+dDppdFPksVs=;
        b=sb0z9bEEINVvJXqgLGW/t4/umIEh9d+r3+8DnJAgG8jAf7c1m4aRs/R8+MMBQWWkWL
         FV5l8avL6bh1J8pt9ORtwaZ2zuFRl6X+fi+x5U8MAl/W0+qTgPyBCU+AtRlcNTEd8x5c
         vDhRkZ1kIFCV7fYM4nZxCWrKJssJd0uqZSTwHQTFNgqDRnmD41Eb214W5eNfS8D8ZxTP
         A8sFB6Xi7a0fI/vyaiNcgifmqmFMBP0kbk0YIbhrx2jyZLYqnKgNoIjIHtJFRDKbH/kE
         Ko/IQzO+L0sakrZSab5wjQZdAyKi8B9od0L5VWcrNNah6occ6bzvbAP92beL7y1qZ5WQ
         Kt8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OzRU/D13LIo6kH9G+scF9UolUmwuqmE3z5fGbUFNC/JORHMGR
	eAz3ViGrn203/dsZPI9hgPs=
X-Google-Smtp-Source: ABdhPJwoLf9oX4ApEvOOiUeIYXfQhgMX095th8ESeu7AL4JmzYRD6XzD78iMUkY7qZ0/Yrp9nV0Q/A==
X-Received: by 2002:a25:94b:: with SMTP id u11mr193952ybm.518.1610504683218;
        Tue, 12 Jan 2021 18:24:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c594:: with SMTP id v142ls236967ybe.9.gmail; Tue, 12 Jan
 2021 18:24:42 -0800 (PST)
X-Received: by 2002:a25:da04:: with SMTP id n4mr192118ybf.300.1610504682695;
        Tue, 12 Jan 2021 18:24:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610504682; cv=none;
        d=google.com; s=arc-20160816;
        b=N+CLbCqoGNrmofHbz8xLw3bdyG7zoYAZnrPgox9yzatSK4wDeof8axhZKSUcQnPObE
         MrZukRjKzOdyfG+Jd+Yh3AjLjwYNnffavO9QeXlg9gO9uBH3Nm1d+nprm0ezW6fKg8ZV
         LQOzFT73kFOYDxUm1GnDXI9s1H0s4M7QedvlUy07ETFqFkJHgJspZCquwmGtg/1fXIkU
         hxSt3TfnqhHaoH94c8RvdM+i65FIeETYVWi44p2V9U/qvk3cJhltgC8cvbT6I73hSc8t
         RxsCu5wPAgvFJ1kmqo17+Fiq+tQvro7fCaenuu/fWqMsQLgzQUUSRH6IIf/yM13163HO
         L0rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=TYKiZ70QHlvmE3rgboyFD6zvGFIqO5v8pvVutSV877I=;
        b=I/TZO3iW6RmdoB98WxD+jHp71IrueAO7/yyhZRgK6dy2k371zswovjsNx0UE4zUM7C
         3xjjSLIY2SVh5XOJGn7/6yJR6MTW0eVMHn7PG1MK64MspHIMfssF5OPzsejRb7NYKc6v
         yxh3VfR8Z8SE21VqKQ9CsRoncF289F353cVTJz2AJgstHtTKjPkVg9yev1CJSW20KrW8
         yflAKx9rgW57MXVMj+DoWkjZj734+bqLUKxKX4B1/kgZJG8SP6ecFYB1F48HrXkQ9u2H
         9+qvPNiK7uq1cp0QFtU9aZ+5lI9ApJ0DZhbGF5ZP3ayYG4oyHWAbb9QhF4Zk3f3LnDLy
         N/mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (atcsqr.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id r12si45573ybc.3.2021.01.12.18.24.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jan 2021 18:24:42 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 10D2LWuX038877;
	Wed, 13 Jan 2021 10:21:32 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88.andestech.com (10.0.15.120) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Wed, 13 Jan 2021
 10:24:12 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <aou@eecs.berkeley.edu>,
        <palmer@dabbelt.com>, <paul.walmsley@sifive.com>, <dvyukov@google.com>,
        <glider@google.com>, <aryabinin@virtuozzo.com>,
        <alankao@andestech.com>, <nickhu@andestech.com>,
        <nylon7@andestech.com>
Subject: [PATCH 1/1] riscv: Fix KASAN memory mapping.
Date: Wed, 13 Jan 2021 10:24:10 +0800
Message-ID: <20210113022410.9057-1-nylon7@andestech.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 10D2LWuX038877
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

From: Nick Hu <nickhu@andestech.com>

Use virtual address instead of physical address when translating
the address to shadow memory by kasan_mem_to_shadow().

Signed-off-by: Nick Hu <nickhu@andestech.com>
Signed-off-by: Nylon Chen <nylon7@andestech.com>
---
 arch/riscv/mm/kasan_init.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 12ddd1f6bf70..a8a2ffd9114a 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -93,8 +93,8 @@ void __init kasan_init(void)
 								VMALLOC_END));
 
 	for_each_mem_range(i, &_start, &_end) {
-		void *start = (void *)_start;
-		void *end = (void *)_end;
+		void *start = (void *)__va(_start);
+		void *end = (void *)__va(_end);
 
 		if (start >= end)
 			break;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113022410.9057-1-nylon7%40andestech.com.

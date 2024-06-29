Return-Path: <kasan-dev+bncBCT4XGV33UIBBX7D7WZQMGQER23MXPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 65A7F91CA94
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:57 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-700d0020577sf1024093a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628256; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJyuko69FPZ9uekxtXOJdPB3Z1Uqssh7xHeS4EtG8BUBDOTpg3von5OeN3r6QzaQgl
         OCMtz7HZk9alWY2ca96SxioMxEsFDdwW1vTeWEHOa/y+AA3S+7CeK47tWg0++nDwEm9H
         djrq7vw3g2TKx94kd0WelKbecLqLIpJFDQAJzQPgwrFWo1r/3JgMJyb9qZgOUWzJraJE
         NGsA3O8Al6QvnzdheLynDQV+1b0OHIIc9qB8NZRUn8MyUS9DlJvYxh0G+WZdFRQjVUK4
         JB3dhL1iIrxiwJsREP39uMfujNIHI7MCglem+dabc8fB6FOV1Vx3sZSD2aq7Vw7nbNPc
         hTbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=lx4EatGu10go+hheAo116AT9qbyNraD3S5Q/MmHOB1o=;
        fh=hyTqr0Cu5wB31OLSeICH3F2rfilDjqPWNv/Sbd0cN7w=;
        b=tFHZB6Kj7dTwK1Iy1wGNGP0TMCoppRaqeva5c9tOWgVBGoUKo7HRnipnOVkk4yTG/V
         +DzDFxL7rGeQgxeOxyU8SENZ4/IYtRFFZEVuEu4ZGJcPHa+hjACU14Elwj9P6tvo54YX
         EOEXS4Q2oMOFxjFWFnQ4fCdjGz6pdkrrTkfKIROIX7GM8TWxyyE1MnkIhqof8BIuSZ64
         GUHdWurmgQ60vYGTfz4AB1+3sELO4UhG3rbY3BmeI+bpEaD7VMBmjZL40mfV4kxZIGtT
         00NciP3BTqSgXTwNmS6ulFqo8+FssAbTmFRWEq2Gw/7+WAtVdUUPcxVq6P9U0RF45n2P
         lLZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Nxg7+8kX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628256; x=1720233056; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lx4EatGu10go+hheAo116AT9qbyNraD3S5Q/MmHOB1o=;
        b=x0O5j/6R0kfHCNOH3R90EBh0UEiaR6NYYh2VnpcwcgUHNBlSNU/O8KfoO1RLGXeihc
         HzmEAhouMiu7Pq4bVn4yARxZXMpJT7534IiYoLeNxyUff1Us3D4vjEZMTR5foSlNjZEN
         jOYlSTN52zL9Gx6kyCJo+PS6jHFyaHao01xsBazFCVpm5aKVwx3qCEoZbyc63gsO5eQn
         eNR3srkK4Bo0Dpj+NurWt4SbToI+ppBkjdXr4D5uSzx7VujMq4tsB8fSEqbVrOjPMfF3
         kwwMgubLR8zHHmA4gAC9vdHz/h3J7Z280SqFiXwQngMsP/I9vwkpiBxQethNQaclXQD2
         nbfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628256; x=1720233056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lx4EatGu10go+hheAo116AT9qbyNraD3S5Q/MmHOB1o=;
        b=mbniz40QjiFHBy7lmmWfYbkp7ulNxjgC2m5Se7iY5cWFBtZe85tdmJ57IIMfMJ0lq+
         w15wSwDuMiCG9quFPbQhJAUDZxULNETgxOCLUI4H43ysl6v37isI8a6Xba/ueWCxsYnI
         RjKKoBcjILjN93qZ8YJPSYPkd54ue66EEHUmLqCUw3ECclMKzxaEDjmgQ+R8p/DMBrwH
         QEYOMwjIwqbQpzcoqkFCKen5W3jXAnlLl+9kfqUFbSIz8xbcBP7am3QKky+tIz7NHvlC
         ez2reBVJDIUcDMMDF9Q1UurN1L4Ch+5iwNqpDEnxAXFZb3ooklUCIO0l9qr7qq8sLeYx
         +YoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyHRokj7+84COkhPklXB4GRisxHAJyV6zF8iZtqQmBuUM0pYIU28jYBgpgyL4v/ECa1zrJXGi83vbn4y8QAlIaUWjBIV9G8Q==
X-Gm-Message-State: AOJu0YxeK2FzkhGtQDxua314IXGp+MNPGrxmISpB+0OtcZPgggXOakzF
	fW4PljelcDcjBQT+hgwvcNVzjFuwVVXcSNu0uzxaqFaMzc4G9Mtk
X-Google-Smtp-Source: AGHT+IFyrrXkO9nOHiu6FPIncGPFSBeZCIdxSss16Oi7dGZKf4xFyQT4hQn3Alpw1xnAVRnCexXFBw==
X-Received: by 2002:a05:6830:4423:b0:700:be1e:fb7e with SMTP id 46e09a7af769-700be1efc9amr19224368a34.31.1719628255778;
        Fri, 28 Jun 2024 19:30:55 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5ac5:0:b0:5c2:1c26:de10 with SMTP id 006d021491bc7-5c417ec24afls874623eaf.1.-pod-prod-04-us;
 Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUg1DQHVuXS7U5mAZ64qNw6n17JB2L6I/Uk+z6X+nmzJxL6yJFXsx5bA6rtynj7q/hSSkPnK5djxb+UhnTill1Dbv9gD7iyF7SjCw==
X-Received: by 2002:a9d:6c82:0:b0:701:ded9:209e with SMTP id 46e09a7af769-701ded92928mr8672878a34.26.1719628254790;
        Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628254; cv=none;
        d=google.com; s=arc-20160816;
        b=AX8hvCVRC+deiK/tpZaZROWpK3LG7cyFMY/PYA9K+CbeGTj9zbpncnqR7dKmKlINj3
         OvWhs8Dxk9x/1yv/qggKuGOLuZNb9/iZzKRziKtl5t8nOHWn638TdX5vkiJfTfzZs6Sk
         XJIsmLfAO6vv8tT9tCxorkmCA4EHDvKCB+OY9KMePCM3iHkpm4GPlR8A2f/ZtbFqjtBx
         dtWo7pJyei5bSZVQNGQdK/7OOIlIyqkSTzXBbXXUdYz2695Y9jZT9MDjEd1oFehPNF2/
         2/luroRjTgfx7tWDlorX6r0qjIZ0vT3Wc/PjUXiNQ19MdhUQ7iLOkg9SW4SOYP8KaEcm
         lw3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=KVQRjS9eMLCaL4adh8/K2k4cxMaxcM2pfk6gA0DxQFk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=UJiE5xHXEK7JnU6aGLA668J2AduvjsG7MbsV7kdPDLGZfxgiNMlqpcecFsetciPYje
         RLXP4J7aC0ftfKCrEZjDzJ3Y9marTld2S6cybNRiQp7l62WLlI62JovbnGoC/rgWjHvj
         sYiiEEdeXmJu+ZVUMkbL9GGHG1d4zrGlr2FiQ1r8tbCZPl3vHPA38hef4Uk5Coh6ZS/8
         zOwzZpUa0Jdggqs+Rj0HnlJDFw4zBYQmONbWtnDNBL75GkJNfn80v5xELvvcezKklHB+
         jw+p3a7X9clEzJnE5gjsQvraaybRnX54pxKBFrIT/S7eKM1tPVR4JYlcRJw3tOHpfoMh
         JD2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Nxg7+8kX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f79b46cbsi122807a34.0.2024.06.28.19.30.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8E20A622C2;
	Sat, 29 Jun 2024 02:30:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 37CE9C116B1;
	Sat, 29 Jun 2024 02:30:54 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:53 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-do-not-round-up-pg_data_t-size.patch removed from -mm tree
Message-Id: <20240629023054.37CE9C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Nxg7+8kX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kmsan: do not round up pg_data_t size
has been removed from the -mm tree.  Its filename was
     kmsan-do-not-round-up-pg_data_t-size.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: do not round up pg_data_t size
Date: Fri, 21 Jun 2024 13:34:59 +0200

x86's alloc_node_data() rounds up node data size to PAGE_SIZE.  It's not
explained why it's needed, but it's most likely for performance reasons,
since the padding bytes are not used anywhere.  Some other architectures
do it as well, e.g., mips rounds it up to the cache line size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures.  This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Link: https://lkml.kernel.org/r/20240621113706.315500-16-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/init.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/mm/kmsan/init.c~kmsan-do-not-round-up-pg_data_t-size
+++ a/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_s
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023054.37CE9C116B1%40smtp.kernel.org.

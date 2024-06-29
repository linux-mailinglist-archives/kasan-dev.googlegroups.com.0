Return-Path: <kasan-dev+bncBCT4XGV33UIBBT7D7WZQMGQEVWE5FKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B53D291CA87
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:40 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e035307b08csf2224398276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628239; cv=pass;
        d=google.com; s=arc-20160816;
        b=uYxgqDdAV03yPoPbUK6AwTOVnjyIRg5krYJlLrdsY6i0jLJZvWmkRf/+2/YO1aWeJ9
         7UKJIY1AwkdOaUUfjFE9sELI6jWQqWqdb7UUV2DTQXC3WLknkVFJnAM5BmdLKG2jfH+q
         kt3/JgLblaInWi3t2G0uy0F/sAHQr7f7RlRGMl6pQfrlnSsXHvaWZPtw4qMIMowW2Tkp
         sdzKBhsx0d7GGyZCRiS84Mii7vP0tfLbLpAHVgzq/JC9ni0JmmFMWqlYFfRfiNBKzlue
         Z6zAexWAsRwnfFm2JoYuiR5hVnOWq0e0dKqTP2r2yTr3hxfWCTFolGqV11LjkMBqfiRj
         K0QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=ZDr/3mC8FaBQSp25OLJasOMtXvNFsHpfXRbzWkVHbTs=;
        fh=h/EeX4haKRKeC43YgH/D+ruwvWBl0HfeNLYrN3IxPGU=;
        b=xKpGiFegQI1wH1HIgQNXoCmkWQfT3MXK3IW9g5Z+KdsQcfgiskdTBUJhWhkBH2zlCs
         raXUAWhCJFgyKYAsM1qlQlk1nc/RGdbmiB+YIFYDwe6ZsHqEIxvvsj3tuURL/ymsqKIG
         4vKIeVjDF2Z5Z+2qtc3YhsHX11VeOnFktTy0ffZTAgFj9uzyoOj5CLNqUkIyE6zr12A4
         xKNt2Z6lB64e3c1vAisk//kPvL/ajttVMTdxoqJLlF7nGi0I+HL5tW5RBcgCllGLbfDQ
         /epbkF+v2tZmy/d12rQIvpInQgFTrahTqZaAxznzODa1Dgz3NzdvbqU3lusiyIHY5RGU
         ulVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AZiLEGf1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628239; x=1720233039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZDr/3mC8FaBQSp25OLJasOMtXvNFsHpfXRbzWkVHbTs=;
        b=B3g9y9GC7sWVBPPa0mgPbTIa4MMDY8l9MXF5zWLtGG4iutHCToeTJlD8H1m219MY9R
         CoQkBfQOWcVZD6TAJRyZm0Y0XOc+w1tmcnT2f1LY6hlc9/cohODTkw2vJ5SIAYD0Q0xa
         k+BvvLkEAc41whnjHpbaQLoblxi3LQHxJMeBAmWcSC5B6DrpX6dKZ26kzCPI4Eoizf+6
         Jlq4qEZGV0L4J5MuPWKrY5jQ/OJGe/TztKDf2hBKotKGC9uiA2zI2qqA7a97xFH3ti2k
         lrCqJRAc7lPDqvUpT2g36v6eKnewnqvd4i2y6/U6AAcOuG16l1AiH1/bCzrfCLEMetVd
         /1Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628239; x=1720233039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZDr/3mC8FaBQSp25OLJasOMtXvNFsHpfXRbzWkVHbTs=;
        b=h4Z7IHdUGT3V1SJEuOU8c5+FJUwhsbk3MBQHP7O/kcM8Q+QmWNCD8wXUJdFuyDeSs4
         JKLqyM0e7TiNvwRvrANPbt1gTpC0zbBrN/UthLyAU2eZ5xeCsDKBHxMz2EH5qpitXOla
         4/7okJm3f+icspAVJGnKzmDm/A8XDc8TADfh44Myp6ofgyI6EApUpUd963jBERszmuzS
         wv1p9yQj/CfGFy7M8OlOllZ7kYvLJ5EdhBDwWIZT/IoonfR+QD32U83V2W0O2DMWvI36
         zKJhL3YUraGOA0D9+TY2XpS2UWwLhVOKsX2mYVk7WILLey/aZ1rQMwI8HZMVjyPHPq9C
         US7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfNVTDErSb74E0SBZU9yW1sVt48PzWQxW+GAfSroZzEK5Aqm2xEfCNHDo0b61vYcf2geFvhTEWOW8UoI6uNFxZPr3ghrfTiw==
X-Gm-Message-State: AOJu0YwTMs98RDAoPq92xc7+TR29VfaZWoReXqtVciIz2czev/truUqG
	GY9vmSt2bHV8FESUKgg2A+/W0574/Qr8407DrzH22w5W2qELDrd8
X-Google-Smtp-Source: AGHT+IHKSFTbHfkGeN8NF//dQ95bzqwX+8LFVOH1qO79UbKB3bdgYgAIfIwv4hCBtwwG/g6gNcL0qg==
X-Received: by 2002:a5b:c01:0:b0:df7:8f1b:3ea2 with SMTP id 3f1490d57ef6-e0303eb3a22mr18348145276.5.1719628239455;
        Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:18c5:b0:dff:3c7f:ea92 with SMTP id
 3f1490d57ef6-e035a023c7fls1777029276.0.-pod-prod-09-us; Fri, 28 Jun 2024
 19:30:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVU5B7PsQSrEuheIJ1ey2FwaECifcT1cAs8StzfuFgFHomh8eaLXvStwarcOhFQeWme0q+kX+2abSEVCyiPsl5qXw0Sq9EbGuPz6Q==
X-Received: by 2002:a81:e809:0:b0:64a:c3b0:3870 with SMTP id 00721157ae682-64c7277ca35mr52127b3.37.1719628238259;
        Fri, 28 Jun 2024 19:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628238; cv=none;
        d=google.com; s=arc-20160816;
        b=N49iUi2mgpTxhtknKL7x2PyzDKwxsCHg/F+zJvaQIWpbDQbd7Ns9cH5ojffr6lcmWX
         KKj//08eLCSEcwuBhfulK7zOdHd23TB8mRYgu4DBoGX/PJGkjAuYha1VyqZ6FXpdDXn9
         bdHX4He4fk/igdnINY824byuQxQiFCppmkVA+tbo73kXF6nHVAD+JMz2OPNBPftaJSWU
         mQCWrcKmy1YaStQpst4M66NkM+fYHVTIZsr9flTaZUdXGyKg8FyjqIm8wOCAnLLNBL3G
         lkTgI27gjmkF3P6ZLq9UyamGCDEEInupZLzqqBxcwJdCebFC7s5xGk99F+1vnipMduOO
         wthw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=MgtCHj1c5zpQRvN/6Yiu3hdgxGMozR5ucd3RQ/yR/OQ=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=jJnnXEzvt74w/iBGOmyyIRgqYVkfA9wXZCZxGOITjyLX6Z1dcXzPOmfAPzvb+cXLRD
         FGzkUWmmnkuK2XCS8nppyeG2mQSKSRiPCXVpkTl8JTpOd287ucGBC9596pxk8ui/55XJ
         KxcKhYwCc8KzqKkcBqGW3nxjbHdBSjoejtK5b6r+2hIcLEgsXHMtITrnNKZZu9WVT6KW
         ZltWPzG5CjxuLYpNzgeEYKkg4Yr1kjceL8WY7VpZRF5cwp6YEBCwoufBRBbte373lt5r
         q723M2JM8usMRq/EUyrLeZcuuDfbA7v96tumlGFO/XSp8zYwtZSEvENthwd73YYrNKRK
         UcXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AZiLEGf1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-72c72c6890csi139139a12.5.2024.06.28.19.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 95D38622B9;
	Sat, 29 Jun 2024 02:30:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EBDDC116B1;
	Sat, 29 Jun 2024 02:30:37 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:36 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch removed from -mm tree
Message-Id: <20240629023037.3EBDDC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=AZiLEGf1;
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
     Subject: kmsan: disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
has been removed from the -mm tree.  Its filename was
     kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Fri, 21 Jun 2024 13:34:47 +0200

KMSAN relies on memblock returning all available pages to it (see
kmsan_memblock_free_pages()).  It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages.  This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered an error.
DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as incompatible with
KMSAN.

Link: https://lkml.kernel.org/r/20240621113706.315500-4-iii@linux.ibm.com
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

 mm/Kconfig |    1 +
 1 file changed, 1 insertion(+)

--- a/mm/Kconfig~kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled
+++ a/mm/Kconfig
@@ -952,6 +952,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023037.3EBDDC116B1%40smtp.kernel.org.

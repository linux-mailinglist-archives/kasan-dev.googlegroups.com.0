Return-Path: <kasan-dev+bncBCT4XGV33UIBBXXD7WZQMGQEHVJEE7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 819C391CA91
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:55 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5c40a00d345sf2040608eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628254; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qkig32nq6Ej0sU/5QTo5cOl85hRov4KXbgR8TM37T2IYRKRMrjRuS9Cnsy9o58Yt//
         ANe9tfiD8luyg9yXopealW3HXZxvC6ykfh8CFCv9Bkuf3h5tmH0vBZUB8xV1u5fz+PQw
         QbWxAHTnG5bAa9ITF6J9FS869333GvuY1igKw4OeHDZvrK0rQ5ZLycqlGGgu72oSb05Y
         L9NJdpn3pbGX6jgFS32/k642bKoH33wN6zjw9sVabx9mJ8Ph7MbTe1MygY44/lxh/KhQ
         mvayhmMcwQFt9QpThQUPUMvRlxvZQojXzpwnZD3fqybdGOZJ2d2jOze3q1dVvZBx8TpX
         a4mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=LRizzsU3WMcNFjndwUK0zGfbQCYmmG+8KAzVNboamIc=;
        fh=idIr2QjomMWOGQKTqDylkmoKUZzNX7X17j0NgjfBS/E=;
        b=nIVVUQVWnuOHbkxB9DhFjJAKJj4atpXVEyA/wEiETzpKKbj2zHmEBjie3luVrkO22e
         tLGgekb9wCr6042+l41/9sELsUO7Nvmn/rmmYs/oo+MahTBZNK5jcMLe9BQYojq30bVL
         4WQrXuFsFHJbiu8bECJ+zezkJ6CVqZrfhT78w9XNBltlwuFYYJe8T7lJBVLphcB8wOll
         3GZLNnUETwZpHuFeRNbh6HjHA+1P0iMy2tFQ0GOyP7U09T1XSXOp/MjMxH6LzjxnwQgi
         nF1awmvTnfu2JjgT1Ek57l2PitO8W5j7FmFEeevKdHxiR/m27Pogl/E9Ifc9M/0aR6pY
         c5Jg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fsUmeexc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628254; x=1720233054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LRizzsU3WMcNFjndwUK0zGfbQCYmmG+8KAzVNboamIc=;
        b=AnYlyKyv5AjVOwMQLPScPwO4cXga4j+O9y7MxuQYZF1QjZWfp20umZ9/AxzlIsGbBi
         AvjHUYkERRPbngJHEgJWmzBwWdtgnkkdZlziYjJMAaB51R7L07IpV6RrQ5ySOh6/9n8K
         pWnOqLCkNXSY/JJLr9Mciv0OAkdPZU1U6dgAffzxGPDM6sPZVWD8xerSyLWC8HXE98AW
         7fK+Hk8b7WMlDbCi5XbDhCk7IZj7lab8XwE8fhq2VsGBcHfPdhBikvJj3RSwG33cfRkK
         ppT/kWxRfI6GtSPM1/6srHXycM9rvoYE9BLSEngUXd0ubfldjfVhE4DaTAHf/iueJuan
         VqfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628254; x=1720233054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LRizzsU3WMcNFjndwUK0zGfbQCYmmG+8KAzVNboamIc=;
        b=mCCjD00gEKa88k1yFLlKbIYla5i0ovxpGGT+NofSSjCfsSrXRrGTbJAIP5FDDkKbXI
         h8vm/bLBwcHOCawnqwI/bhq37oMFelqU7Rt3tn4wYHmR6PRJ+H9aV4XBQMDf/hP2xytn
         Y5ebTvs0rBE9VS+9UA3Ad7ziSyMD9ylUsQU5UGE8F77nfg/wFdYlVr5UfPuvU3DKiW7t
         FRIJbC53RuC+fa2CJoGBH4Aar14uAhHRnYOnU4Nc9j/o8ENzfxegzBIRYeo1Lw1ydHy7
         v9Y4yTTyDCuqqjyAtDqIFr4VObw16T2VV6Hqx5VvIfd6yp5itasmgxWtKNNQp0Go+NBp
         jPUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUY5ELxGhilcalCk5tiRC0RYttvC3E/RkR2QyOUGXladl6iLnq1+rStD5cMaMwSgdfnNJtPTKp2PcFvM5/2odT85UlVrkHalg==
X-Gm-Message-State: AOJu0YxJUgvPvavBQdWTz5ek/vaqwgpnE00eprqYdzABdAh/JWlYQ8t6
	S3pB8CllUlC+65X8abRIUVp6UjuPbTfYZi6oTmBsIag3KO3M0IUy
X-Google-Smtp-Source: AGHT+IEmyyserFOHOKywWGVbYVGLZZaPn4pcnt/OkxmuXRrJpClzh8fNvEIzZ6Wfcpf22lVZvqA6GA==
X-Received: by 2002:a05:6870:96a8:b0:254:a0e3:b2f5 with SMTP id 586e51a60fabf-25d97033d5dmr1642213fac.2.1719628254327;
        Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab1b:b0:25c:ac6e:8806 with SMTP id
 586e51a60fabf-25d92c64f33ls547909fac.1.-pod-prod-00-us; Fri, 28 Jun 2024
 19:30:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQgPYFqNcTN7jNwTelEC1k49XPI2Yi16SiHebdvIdz1X7ynBqXawNXTlXBnLOj8fFEmtEqlA9pfz720JOIbrWHYLiXtmGl8WnsUg==
X-Received: by 2002:a05:6870:8184:b0:250:3c9d:fd20 with SMTP id 586e51a60fabf-25db2187dd1mr32142fac.0.1719628253410;
        Fri, 28 Jun 2024 19:30:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628253; cv=none;
        d=google.com; s=arc-20160816;
        b=W7Vl9o9Y9mikPlOz/nS+E3u3GP1L9VbCMwxQu1R2z7FB8v7oMrUW3/FAvjxHwjjy4s
         KVyfV352ST2nWhOJClJPmaQYy8JDxAVdLeuN0CNq8XlFOtDhA3TtySbjtPCshrigsxLZ
         f8fCTfxDmMTpTF2TXmqwV/ojzWLW1LcpwdN96gbhCOXrZH4MOKpyXO/lJmZp2XdZteV+
         yKQ+kTv5DFIsn6Gr0uR2J5T3Hv2U3LHhLD1jGCirFR80HDzTjK+QhhHeiTVVc1+ZVSoE
         Q6h4xW9Suz7Pl5Ln9sO21VWAvXwdwxb9zreXCD2XOA0M80mMSyI+U04kC97IRkUuHCPu
         43IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=JusBrzIcyyD1TLuKGJHn0i0m2vHQ+6BDNaP+F+TCqi0=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=oBTL7QsLbzQv4v457m6d9idzBGS0l04o/OK8+Ttv05Zb/wyYj7LSfqYqeahqwN/jVj
         lRGGAiOGV1ED0gDoFstbaWfoyYEFb1TbAfoNYiUaTzWMi3aYxzpvEofJNGm+bIUAjh0p
         0tEhgEEt3qevEu2EAo90sr+Hk864pe1DFf5MZP2wInq7HX9aDaCefTAt6Qrx4Xh6XDLP
         YsIdJFHN5exPqTFtMpvMVuBBg6Fk0y9WTE8UF9aIpqts0ENfzU8X+CS2rsyyEOc62Vkk
         pFzjWw1M5HgPzuP/Y7Vit4lgqDtjFaWZmMi5oae/+MKvwlOtZY80w6Oc8x9yfavqVi9b
         4DHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fsUmeexc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7aaf0cfsi116132a34.2.2024.06.28.19.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2B672622B9;
	Sat, 29 Jun 2024 02:30:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C6BB9C116B1;
	Sat, 29 Jun 2024 02:30:52 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:52 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-use-align_down-in-kmsan_get_metadata.patch removed from -mm tree
Message-Id: <20240629023052.C6BB9C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fsUmeexc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: kmsan: use ALIGN_DOWN() in kmsan_get_metadata()
has been removed from the -mm tree.  Its filename was
     kmsan-use-align_down-in-kmsan_get_metadata.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: use ALIGN_DOWN() in kmsan_get_metadata()
Date: Fri, 21 Jun 2024 13:34:58 +0200

Improve the readability by replacing the custom aligning logic with
ALIGN_DOWN().  Unlike other places where a similar sequence is used, there
is no size parameter that needs to be adjusted, so the standard macro
fits.

Link: https://lkml.kernel.org/r/20240621113706.315500-15-iii@linux.ibm.com
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

 mm/kmsan/shadow.c |    8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

--- a/mm/kmsan/shadow.c~kmsan-use-align_down-in-kmsan_get_metadata
+++ a/mm/kmsan/shadow.c
@@ -123,14 +123,12 @@ return_dummy:
  */
 void *kmsan_get_metadata(void *address, bool is_origin)
 {
-	u64 addr = (u64)address, pad, off;
+	u64 addr = (u64)address, off;
 	struct page *page;
 	void *ret;
 
-	if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
-		pad = addr % KMSAN_ORIGIN_SIZE;
-		addr -= pad;
-	}
+	if (is_origin)
+		addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);
 	address = (void *)addr;
 	if (kmsan_internal_is_vmalloc_addr(address) ||
 	    kmsan_internal_is_module_addr(address))
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023052.C6BB9C116B1%40smtp.kernel.org.

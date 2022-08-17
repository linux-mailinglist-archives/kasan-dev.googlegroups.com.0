Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBN6I6SLQMGQE5NEK3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 478065974FE
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:24:08 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id y10-20020a2eb00a000000b0025e505fc2c4sf4473893ljk.11
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660757048; cv=pass;
        d=google.com; s=arc-20160816;
        b=HyU4bjURF8fZ3N+wv8wQjxVHcKCwy+t+noUK8FPpNS9aKY4k1Jx55cj4t+e70ROXcc
         samsB1k1JKHUtr97GPji9MJfe61sOSa96xSsTgKfg3K7UIS8KpKzjN2gp4hXU5tcAFAH
         aGn9T6+emBoeg3e+29nXdTeeGqZYbRG++xNnc5DY1ssV+WM2COkZWtUBnvRg6ThY0wa3
         anujjE5bV7tVzNHbjdJ/SthijNU4+Zh/Jbvfx2pQTra1FvPWEy7V5kEQ3UpLjtAfuPxg
         fEtR4BJaUo0GiCtoik1LqxZlNbpQRtcxV/T58vD8ex3QZw9pmvxQ9/zRJKByU6+0MyHs
         Et7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:in-reply-to:date:from:cc:to:subject:sender
         :dkim-signature;
        bh=8dZDOMM7WTuDm9kEE20aFZ7cS77qeao6OGSFG3Idbog=;
        b=o+MG5+oMyaLGYhoeer8xK/1ZicXNUrhrE0zk4O/Oq22rQrq8Hc2GGJaXDIKkbUN/S7
         IMCYWnxWJ3mvE/xRmt59tJLGLFSMZiAj1e6bs3mFLcz9rJUGTC6HcGhUaYSUFkum3Tf9
         CXiCC0GULD/yu3FvojtNFPR4QE35qQddW1vUf9GA98EMX+/rc8LRCJJf+HrzNMv7VYpf
         I/cVK9AW/tqcg8lFmxsTfDjI7kwRTeJzapY4xLp6G9UfrRzNwg0g1Oe3IU012I72OfIt
         Py8Gn2oChrjFPSuGtG93QJaidZL9XPnwOrYRs1MSGD2WTBCfozDRuXppYzn4FNc9QPfN
         PzcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=iIm9aMtJ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :in-reply-to:date:from:cc:to:subject:sender:from:to:cc;
        bh=8dZDOMM7WTuDm9kEE20aFZ7cS77qeao6OGSFG3Idbog=;
        b=CO3pt4Ii4FUcZy+Zse/DTmVRoQA0ik6nZHLo7QAb2EIpaTMdK9dx3mYPw/rKesHqlZ
         BQNWdY/pHrrHQPKKYQfJ/FyXv0ZNdKa1rAJpB7HpjIqLpK6M5BLRzIELsPNmnYw3H0Kb
         gI8AF4M5STdPJgtgaXEfCbv01rCwgdtWGxG4FKfzLhB6VMIsI9qgzm7yZmyaq+7c0rUF
         iryG2idgKdx+uuDFjprPP2yV7A692875JkZNolz6Tohx0z+mKqtyaRZ4gHEz7UENmWrp
         UYes94LQGPcAi1ifUnRFY1rGmsmgZK+/YZM6L4oI+t+x4znwHW3A/U9dq2Rxqg8KRJsi
         D/Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:x-gm-message-state:sender:from:to:cc;
        bh=8dZDOMM7WTuDm9kEE20aFZ7cS77qeao6OGSFG3Idbog=;
        b=LYYTMDqOeWBzMmo8/8dlP9caqqHNHk2aJNueVaeyLg9lh16vgeoJSAAb51ecDmpbmt
         Z4zx77buCq9qxScdtHOSa96pSZ2wamplsgNb7eSYau0IQ2v7PHK1aowNL/ql7KetixIR
         C7NFIIfxxnF8BRKZ0EDE2lLai9fhf0JLVFNhjNCzum7B0eJdf2Rlm8G5xn0w2hpidD1g
         jVcvHog6baYtzoSu6Gvw0vMoO7Hi3MPbGHI298coSlVYBSeC+sYCcXWQu0cvbJfQfMjl
         CCslCy/dU8d/IIDgb1sHNbazT1q76qmBQHVKy64iB0DjI6wUndWfo8Sneumj60g/Vugp
         qrEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0VGScfVMIeWoD8AQm6yq7rxNiRV1Cc0ZVp9j5pn7p7P5gZKqId
	OQlJuieVSzdAyDU3QhwV8ps=
X-Google-Smtp-Source: AA6agR5xBQ6WRrs/1DYafrBDWPBCyyb7FNNOptJPxIpdWSecN+L55MOwJR7T5luS0o9+1CHGfgWRVw==
X-Received: by 2002:a2e:b5b0:0:b0:25e:3440:9518 with SMTP id f16-20020a2eb5b0000000b0025e34409518mr8626257ljn.248.1660757048034;
        Wed, 17 Aug 2022 10:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c8b:0:b0:25e:58e5:b6d5 with SMTP id x11-20020a2e9c8b000000b0025e58e5b6d5ls2697382lji.1.-pod-prod-gmail;
 Wed, 17 Aug 2022 10:24:06 -0700 (PDT)
X-Received: by 2002:a2e:b522:0:b0:25e:75b9:3ed1 with SMTP id z2-20020a2eb522000000b0025e75b93ed1mr7825678ljm.505.1660757046852;
        Wed, 17 Aug 2022 10:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660757046; cv=none;
        d=google.com; s=arc-20160816;
        b=PWrBdIFaqEJPCmwkZShPWIXQ8ZFkYn0xB6OtFw1fT5VC3b48Sl8lVr3aKn5fePxu33
         ji+oYuxqIWo1AQvxr96N6zeMKNDcc9UFUNMtKUSUcFT96LxJOBoo9lLttgEHEDqiiLKL
         Q4UQzajYJlWh1/H51nVHgGI1I/z2G/+WER6c4/cmBp+2+QhZs7S+7BO73NwOmomYbHRS
         cyljAObict1vKCsi00NijLWmYEiAV+5fNuJWuPkADDgDOat7msPJmO4cKWmKJpu60Uu0
         Sj5QwsvTUeuLgXozIylj3oJFL2oY0srO9YHj3A0ZFUZDwAbyM4pRwW7mEUvdcDJ5xlI9
         9q6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:dkim-signature;
        bh=HEoNIlbqrQu8nJsTxhRPIAjN1F9b+gPXw1FAJpTsUZU=;
        b=wVOvUha58W5hf6D0f6WcqdBhsxlxKv73IbPig6hGhSfyF/oR8VKsdmbJGiBVGN/ByE
         nbG3rdud8TjXiiiVBWF0K30z641lX/LYQxAEf8RMFMuHvL+d8DT4jwSNlrwVEyYfsOhA
         6HGYiq+YfXbH9oKyd9ttxfk2WOHYMz/LsJwCarOEM1/1QUmDdmeH8iPUTHK9Lo+wGSvl
         CL6YcELkJTPVCjGOR4N4XY2ssCAaAZ44d8UeJ+IPc/IlJn98sdxEDeS8CruJFrDnGrsX
         TmRStYOftnNMpXJCnZW6TczckmJlM+tzsuqUKgham3ayTjxuCUcwWe8BLRChGs5YWssC
         XUpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=iIm9aMtJ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u22-20020a05651c131600b0025e5b685088si1056677lja.1.2022.08.17.10.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6E5C2B81DA0;
	Wed, 17 Aug 2022 17:24:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D310CC433C1;
	Wed, 17 Aug 2022 17:24:04 +0000 (UTC)
Subject: Patch "Revert "mm: kfence: apply kmemleak_ignore_phys on early allocated pool"" has been added to the 5.19-stable tree
To: akpm@linux-foundation.org,catalin.marinas@arm.com,dvyukov@google.com,elver@google.com,glider@google.com,gregkh@linuxfoundation.org,kasan-dev@googlegroups.com,linux-mm@kvack.org,max.schulze@online.de,will@kernel.org,yee.lee@mediatek.com
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Wed, 17 Aug 2022 19:24:02 +0200
In-Reply-To: <20220816163641.2359996-1-elver@google.com>
Message-ID: <166075704210791@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=iIm9aMtJ;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    Revert "mm: kfence: apply kmemleak_ignore_phys on early allocated pool"

to the 5.19-stable tree which can be found at:
    http://www.kernel.org/git/?p=3Dlinux/kernel/git/stable/stable-queue.git=
;a=3Dsummary

The filename of the patch is:
     revert-mm-kfence-apply-kmemleak_ignore_phys-on-early-allocated-pool.pa=
tch
and it can be found in the queue-5.19 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From elver@google.com  Wed Aug 17 19:23:19 2022
From: Marco Elver <elver@google.com>
Date: Tue, 16 Aug 2022 18:36:41 +0200
Subject: Revert "mm: kfence: apply kmemleak_ignore_phys on early allocated =
pool"
To: elver@google.com, stable@vger.kernel.org, Greg Kroah-Hartman <gregkh@li=
nuxfoundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.=
com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com=
, linux-mm@kvack.org, linux-kernel@vger.kernel.org, Will Deacon <will@kerne=
l.org>, Catalin Marinas <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediate=
k.com>, Max Schulze <max.schulze@online.de>
Message-ID: <20220816163641.2359996-1-elver@google.com>

From: Marco Elver <elver@google.com>

This reverts commit 07313a2b29ed1079eaa7722624544b97b3ead84b.

Commit 0c24e061196c21d5 ("mm: kmemleak: add rbtree and store physical
address for objects allocated with PA") is not yet in 5.19 (but appears
in 6.0). Without 0c24e061196c21d5, kmemleak still stores phys objects
and non-phys objects in the same tree, and ignoring (instead of freeing)
will cause insertions into the kmemleak object tree by the slab
post-alloc hook to conflict with the pool object (see comment).

Reports such as the following would appear on boot, and effectively
disable kmemleak:

 | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (=
overlaps existing)
 | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
 | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
 | Call trace:
 |  dump_backtrace.part.0+0x1dc/0x1ec
 |  show_stack+0x24/0x80
 |  dump_stack_lvl+0x8c/0xb8
 |  dump_stack+0x1c/0x38
 |  create_object.isra.0+0x490/0x4b0
 |  kmemleak_alloc+0x3c/0x50
 |  kmem_cache_alloc+0x2f8/0x450
 |  __proc_create+0x18c/0x400
 |  proc_create_reg+0x54/0xd0
 |  proc_create_seq_private+0x94/0x120
 |  init_mm_internals+0x1d8/0x248
 |  kernel_init_freeable+0x188/0x388
 |  kernel_init+0x30/0x150
 |  ret_from_fork+0x10/0x20
 | kmemleak: Kernel memory leak detector disabled
 | kmemleak: Object 0xffffff806e24d000 (size 2097152):
 | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
 | kmemleak:   min_count =3D -1
 | kmemleak:   count =3D 0
 | kmemleak:   flags =3D 0x5
 | kmemleak:   checksum =3D 0
 | kmemleak:   backtrace:
 |      kmemleak_alloc_phys+0x94/0xb0
 |      memblock_alloc_range_nid+0x1c0/0x20c
 |      memblock_alloc_internal+0x88/0x100
 |      memblock_alloc_try_nid+0x148/0x1ac
 |      kfence_alloc_pool+0x44/0x6c
 |      mm_init+0x28/0x98
 |      start_kernel+0x178/0x3e8
 |      __primary_switched+0xc4/0xcc

Reported-by: Max Schulze <max.schulze@online.de>
Signed-off-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/all/b33b33bc-2d06-1bcd-2df7-43678962b728@onli=
ne.de/
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 mm/kfence/core.c |   18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -603,6 +603,14 @@ static unsigned long kfence_init_pool(vo
 		addr +=3D 2 * PAGE_SIZE;
 	}
=20
+	/*
+	 * The pool is live and will never be deallocated from this point on.
+	 * Remove the pool object from the kmemleak object tree, as it would
+	 * otherwise overlap with allocations returned by kfence_alloc(), which
+	 * are registered with kmemleak through the slab post-alloc hook.
+	 */
+	kmemleak_free(__kfence_pool);
+
 	return 0;
 }
=20
@@ -615,16 +623,8 @@ static bool __init kfence_init_pool_earl
=20
 	addr =3D kfence_init_pool();
=20
-	if (!addr) {
-		/*
-		 * The pool is live and will never be deallocated from this point on.
-		 * Ignore the pool object from the kmemleak phys object tree, as it woul=
d
-		 * otherwise overlap with allocations returned by kfence_alloc(), which
-		 * are registered with kmemleak through the slab post-alloc hook.
-		 */
-		kmemleak_ignore_phys(__pa(__kfence_pool));
+	if (!addr)
 		return true;
-	}
=20
 	/*
 	 * Only release unprotected pages, and do not try to go back and change


Patches currently in stable-queue which might be from elver@google.com are

queue-5.19/revert-mm-kfence-apply-kmemleak_ignore_phys-on-early-allocated-p=
ool.patch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/166075704210791%40kroah.com.

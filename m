Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBK6I6SLQMGQEBFWKKEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 518DB5974FD
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:23:56 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id y10-20020a2eb00a000000b0025e505fc2c4sf4473546ljk.11
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:23:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660757035; cv=pass;
        d=google.com; s=arc-20160816;
        b=hB9ekWtGSX4tgxz9K6HAJZ3iM9hOPCWveuJ+xaF6WWeYtoFLLDDFuV+Ot65gHyuPLn
         gXtk7WmPiHtlJ0nUe6b4yn0DysDS/5Jdddjf+Y0JQYApHEGZoRTh+EE0mHP5ogalT6qL
         zXg/BGU33qghdQ1f0buzKUvsZBeQaVU2IqGysWzUIJWSFRc/xviah87U3hsnC30w2+Vv
         C/igbxctbZgwidRQnFB07IWv9uVc7fXYe4oKwgOowuRa9kLzpdR3KB55sLOoSO4q0sCh
         FQ6d3BkwkkTDTZnme51OUp0h+PJf8XalOytdl4KkUSNpZ3j9EDWVyWgPT/dS+SJJgc0X
         31Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:in-reply-to:date:from:cc:to:subject:sender
         :dkim-signature;
        bh=v85EJA4H4s3IpkxuLrNYgsUay44hkeOhriRYT1bjBlI=;
        b=eq2XtQIyKgteQRl+qd+/D5zul1dxvC9Que71GvKDZes8d2ucMhwfbRhAszaMNKMW/u
         k2c8266O3rJtxxs5AoM/LKJU9Kjiz2f01Gw1goU9kq0YO4ttzBg6p4fIGHO+WjsAbSi5
         H7/61bJevtvO9F1bqRDwemcBdH9R7ldRqDcAs72nPZdhhQISf1iR/NLlKhs5tOrEnbfB
         WB/Fsc+V9M9Wr31wgDNg5CWawKXz5zeGPTlzuJDP26ol1SQ5fw5c3sezY/jZvA11433M
         u4WoAoOnCnZPrv1wJEpzJvGYsPytx14azlLv6SRFXXULR9AG3LhHd3QSMWtnfykHUXFX
         5M3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=uZ7TjaiD;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :in-reply-to:date:from:cc:to:subject:sender:from:to:cc;
        bh=v85EJA4H4s3IpkxuLrNYgsUay44hkeOhriRYT1bjBlI=;
        b=ngCB3+BgX7ZWP6VmU7R4g0JrdOzrzgBAFiUHE+nxTW0VaDqruSO2jaTxkqk/qm3bq6
         1Xxs+86sax8ODerK/UUMb7nUQ7yy7y4D5Yt5+vFaHIK48fXmvfhgyWAkubpMLiEW2s0d
         BBqnE0K1hWRoF42Lvap7FOqi1Gv2WoFOPFRV24Z1Zt2Ryk4+d3FwumUlfTjSpeyZXSaO
         G3kLJnQoKuCrn9OCp/JPUbQy5R+mTO8mPlyY5CAzs3YjolMaUT8860hGre6o53KqMIWx
         vtpJ92HduxcP+CEfhCa2Blz7NNrKHMv+l2Zxn9EuV90t7rU+kTbqfoHb0XX6B87JINRO
         +TFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:x-gm-message-state:sender:from:to:cc;
        bh=v85EJA4H4s3IpkxuLrNYgsUay44hkeOhriRYT1bjBlI=;
        b=H1wyVjfIZzATwNdjyfmoil5fnJ1M5Hdh85XjMcKJViyGGfyDB/mJbN/2M2ik9HwxB+
         U/ILkVeQgBgNnGMW+DRMNyFnjDOR9ER6dhoxBZs8GX8s4M42krvlLekMCT1GZdb2P4IB
         hAmqYR88Lc5eqxXvAq28v3C26rZLYcz9ZcWCWNXhsYUMCig0cUeJO0bcchG8Q2h6eAI/
         u7ahB/lMqRhmbtcoCz9Z7depmQ2B7IljbG/ThJjs4nAGVNoIgVtlQwpzWuCaGgJoudhu
         BjFKjV1Cqcy4xU9VjDBtc3rsngtNIax6otsxJDXCfwDXWufOCOpiXEgkkVzW/JqkPGbo
         Jc9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3qKlgJkMKR3Eg4H2FcYVB8ZiV2uFu/TPvCRQ8iBE3tOOObYepw
	zmjl3zVelSNm/j7/6nIxDJE=
X-Google-Smtp-Source: AA6agR69qAGhdO2ysnhX2PbMqkoxV5UQ+gcm3uqSNWM3nSdA3Zw8SrAQgZXl8Nv/tYFGPSjRyPWpmA==
X-Received: by 2002:a05:651c:1208:b0:261:9d31:c07b with SMTP id i8-20020a05651c120800b002619d31c07bmr2066278lja.298.1660757035615;
        Wed, 17 Aug 2022 10:23:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8958:0:b0:25f:dcd4:53b4 with SMTP id b24-20020a2e8958000000b0025fdcd453b4ls2699891ljk.3.-pod-prod-gmail;
 Wed, 17 Aug 2022 10:23:54 -0700 (PDT)
X-Received: by 2002:a2e:8884:0:b0:261:8503:7e7f with SMTP id k4-20020a2e8884000000b0026185037e7fmr5203609lji.524.1660757034417;
        Wed, 17 Aug 2022 10:23:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660757034; cv=none;
        d=google.com; s=arc-20160816;
        b=vRwSMCYnmJ5NlEuXtPXs132Vh/UI2uD6APR2nGoUqzHZuYsH7U0oYgrOygrffXcTZG
         tPVSy8PLMa84OlmYGw7UrP8FqPlt1+FdFcUmkuq96BXeu7p+IqFnpggzTY5AZoClgLN7
         q8J6EJGqOCjaJQ2U9yENbE3R0Ev5m4/ForCm5u1HAugo1sPgE/zXXAf9pn9MC2HqVugx
         Qys8VEATdyrEDCY88U64GaMgz8kTBoWxnYke2fRUQU5nD80JACYtQljwmQRVi+lzGKU/
         yDav2CjA5z/NDaxM+e3Piv11Ap0WMf+aj0HTK+X/Xnqpd08T5IBMLCcyeCp/3pgKb+f6
         8Oew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:dkim-signature;
        bh=fClUHWUdGLGzh+1Baj8NJuKeSse+ratzEPtpVl9al14=;
        b=lCDSIQD7RsCVjqeYADkPcJX4IXgpx5cjP/aVtLWF4jZP/tQgNXF6Zy6kc2swxeI+p2
         i393JEYsL7JRitKxGIW2vi84TCFXDXkwrcmFjFjAQ0e/dNsMBSu/RsorJlMlvUGLF7iN
         LNdXdkeabacUxSn01EeOp3csIFaa5K+wD7Y+GKl6KC4f2VcOAZUnlkhJBI+Cdouh0Y7G
         RfH5rgULm+oWXsgRDjNIY/SAoP8UoX39wwIaWzTmwxv3oQsZXe28lLGPfIb3B14WOb8t
         Npiv7CaJRUJtN5nDxPOXKRdET6jCDmFw3JX8Mjlxhla2NihC2yawksJD7K6PA28bfFXL
         qhVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=uZ7TjaiD;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05651c231300b00261803548a7si719746ljb.4.2022.08.17.10.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:23:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id CF898B81E81;
	Wed, 17 Aug 2022 17:23:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 406D8C433D6;
	Wed, 17 Aug 2022 17:23:52 +0000 (UTC)
Subject: Patch "Revert "mm: kfence: apply kmemleak_ignore_phys on early allocated pool"" has been added to the 4.14-stable tree
To: akpm@linux-foundation.org,catalin.marinas@arm.com,dvyukov@google.com,elver@google.com,glider@google.com,gregkh@linuxfoundation.org,kasan-dev@googlegroups.com,linux-mm@kvack.org,max.schulze@online.de,will@kernel.org,yee.lee@mediatek.com
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Wed, 17 Aug 2022 19:23:49 +0200
In-Reply-To: <20220816163641.2359996-1-elver@google.com>
Message-ID: <1660757029198205@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=uZ7TjaiD;       spf=pass
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

to the 4.14-stable tree which can be found at:
    http://www.kernel.org/git/?p=3Dlinux/kernel/git/stable/stable-queue.git=
;a=3Dsummary

The filename of the patch is:
     revert-mm-kfence-apply-kmemleak_ignore_phys-on-early-allocated-pool.pa=
tch
and it can be found in the queue-4.14 subdirectory.

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
 mm/kfence/core.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 6aff49f6b79e..4b5e5a3d3a63 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -603,6 +603,14 @@ static unsigned long kfence_init_pool(void)
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
@@ -615,16 +623,8 @@ static bool __init kfence_init_pool_early(void)
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
--=20
2.37.1.595.g718a3a8f04-goog



Patches currently in stable-queue which might be from elver@google.com are

queue-4.14/revert-mm-kfence-apply-kmemleak_ignore_phys-on-early-allocated-p=
ool.patch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1660757029198205%40kroah.com.

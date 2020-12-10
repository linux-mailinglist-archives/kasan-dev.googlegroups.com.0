Return-Path: <kasan-dev+bncBCS37NMQ3YHBB6GVZH7AKGQE7TQ7PYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FAFC2D6530
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 19:37:45 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id h3sf3700675ljk.11
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 10:37:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607625464; cv=pass;
        d=google.com; s=arc-20160816;
        b=cei9HLgeB6XYk+C0EpGcI6vULFybl03NyCVDAW4/u0f4FVZ6TRU6WhkxUFxXDBd7Gm
         xNM7iYhIPlA1XAhFZbhvEbo2UMxhlTYkdD0QDYeMghG4O/+LCvyAJBq/kJB5323jAkdN
         90cq7ioihMzdhTcYSWVDj9RbnwJvZFTqsXVOuxzoxjjO4krxLt23RW7NaZI2sbSPLv50
         0jmwBBxuCkK+a/MUEKCEcc2WFDn/277v3s/u9f9pz4FzLYoON+t0xwfMrd2pZuQUtgQX
         32l6Llh1AxcuEb7AGwFheMbWI7OuJpwF1qJgpr/P0Co0DGOQH7vow7NM+7WrpnNHsiNU
         Vx0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=h1wZNbNKP0zdtWIyc9Ddhvy52VW7HNCQref86h627qk=;
        b=HEgQOD7o82yGHlQbT+cz6XsQDyOgRJlbcDIyjEnj8Xfy4l1xKeySdNqhp7tLW5jYWf
         8tWgTehdCCz7rDCB2McJKwGz+UfMYBtScGwKbGBAtdNDLYsPctjLT+jgZWlNsXL3JqKi
         h23c6LB3AwIzMIDGch60rzaVW4ZJ/1AePVg90obG8o1L8pqHnrUEz4e/oWDNJikC9pbf
         QZYpW4FqAcl9+bt3v/K2t08Xnmii9aBFxWkZXwgYuNaXQ0TeCboOSjyJaooXx/voZTcq
         QZP50q8bZoavLlEmK75ktlqtFRUDgA+I69nlo13kD0+j6q85GEbEy/l5jHe3cAytS3TP
         +Yag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h1wZNbNKP0zdtWIyc9Ddhvy52VW7HNCQref86h627qk=;
        b=ZjwvX+FiU8HGaf5ui0edwmEeC/IFDxxi8k9UBqUSEUb0CrthNQebvgDPM7HEXxd3/h
         XEId6YEbqplVDQ+/6UIY5+PPZAtOnlef00REBSDZzDanz3jsgUQfFqLcfxYNEzY+/b3U
         ztRtkBBJrYi95RwrYHg706Z4syHnvzpQlV2H9bRoA94sxKEFp/zy6yMY8ucrUuWnhIBp
         g/b4KDVg4yTZYOQrnyaAeKBJAMchcwIRanZKe/4fLgaxqNjGwaCblYb+qein69AnnamB
         Vl55r0+D905qssFnthAbQrFeAwYophC3Z76XC8bqOuXjOBPkmPGLtwSyf/G27KKGaLmP
         lUtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h1wZNbNKP0zdtWIyc9Ddhvy52VW7HNCQref86h627qk=;
        b=UF7HcT7ghILgR7DQ/pKSnoi5lOkD65CjgOEikG1ke9HMEc2I7s3Oa3pz24qsSKw7TN
         +Omb6VZ+ihrjjQxzLLkPWmT1fLy5KTmMQu7pbTSs1oCWSGhcNL2+8RPKeBtvt6Gsfnod
         ucTUlSKCeWcSTDmXGkY1SjOuhOBZUnoiZOAfMz9aj2NTOmWmT/Ho1hqiJzORQYQqBGTv
         o9q4XbnF6Xs42BL5qmY055Ryt9yKWiVf5/MDL8WjHK03QQOb91GW5hmLX47Nh/TCUfkR
         7uclvuJUmmf/UKQA2pTvwhbyVsApLhdO+hI/823axyfppSaEL+FtxVaR2v5hqnog/DX9
         3ekg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Re50jt5XYhL9uPTroYgk//w35uwEeKdRUGVm94iufFUpopDA8
	zHJNntNa8Qxtzi3bAEuOaEw=
X-Google-Smtp-Source: ABdhPJyTUzf40NoBTfZa3Ti2KWxXzNHdXWKM2LcDCKqgqRyVQTJ9MlMA3ovV82GzcLaImiyqfiLA0Q==
X-Received: by 2002:ac2:5b03:: with SMTP id v3mr3380498lfn.634.1607625464658;
        Thu, 10 Dec 2020 10:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1386:: with SMTP id k6ls1204556ljb.8.gmail; Thu, 10
 Dec 2020 10:37:43 -0800 (PST)
X-Received: by 2002:a2e:3210:: with SMTP id y16mr3615410ljy.395.1607625463562;
        Thu, 10 Dec 2020 10:37:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607625463; cv=none;
        d=google.com; s=arc-20160816;
        b=hIJyBjtglRE59emEhaXhGibZznS4ZLX/nyghtz1baEK7R1g4Gu4ID2+sJY9/RB9pTk
         32WUrxd+Kt4EP2RiJIhadOoGbTdLJEN1eibt2dY0oJqagKtfWnVeBclWqDGzpyuyoQCr
         nzN9xDJHgs0RLqKy+7n24EAZgczKOfs0Jv5uOrOK+LwiFRs8Mv4LwX9ksH6m9QbCKlH5
         42wgluxGIMFB/nBXeB1/o/dqAZ45nF2/sBYG5QDPUVccwncc5E+MF49gFyJQo7XHNg3d
         Ociq31CtL+iD+x8uP3dLO8HjMxROGOc0lpz3m+ErQIk86lZ7ebbEhtXh0fX6TQe0NaD6
         tX/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=qevJfY7dsLkmoNjN5cKll/uAr7AEc1whLJC/57i9ulU=;
        b=H0wSn7DYOJ9fS5qX/uvDXVeHFDDCU+skvEVy6NGOWTr1gf8ELibJq/vylqS6JF3/N0
         3tj0nobukgejIOf5S37Zo9w5hnUv+4vBAqf4BxaDjfCWtYv4FyPge7BD7FPDeaC3ybDk
         DFzg2w5rruwJLFX7T4hFhDMQq8xYEd86FrrU9eUgN+2Jpx1fq9AGFiPQqVh0nVmndZ5u
         y5F9DilZumDGIe/ySrvBLeemCZ84CbAUuF0e73HjVphsrG39Wu/tWXmg/hcz4jy+YTUA
         g08gT5S1giQyLk/hU4z7coLUn8NfdmPtZsjbD1AvQq7+hI1v8cc7GtSFFcZTrua5JCy4
         58RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f65.google.com (mail-wr1-f65.google.com. [209.85.221.65])
        by gmr-mx.google.com with ESMTPS id e18si186238lfn.6.2020.12.10.10.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 10:37:43 -0800 (PST)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as permitted sender) client-ip=209.85.221.65;
Received: by mail-wr1-f65.google.com with SMTP id 91so6521077wrj.7
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 10:37:43 -0800 (PST)
X-Received: by 2002:a5d:504d:: with SMTP id h13mr9905265wrt.246.1607625463189;
        Thu, 10 Dec 2020 10:37:43 -0800 (PST)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id z21sm10216699wmk.20.2020.12.10.10.37.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Dec 2020 10:37:40 -0800 (PST)
From: Alexander Popov <alex.popov@linux.com>
To: Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH] mm/slab: Perform init_on_free earlier
Date: Thu, 10 Dec 2020 21:37:29 +0300
Message-Id: <20201210183729.1261524-1-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.65 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Currently in CONFIG_SLAB init_on_free happens too late, and heap
objects go to the heap quarantine not being erased.

Lets move init_on_free clearing before calling kasan_slab_free().
In that case heap quarantine will store erased objects, similarly
to CONFIG_SLUB=y behavior.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/slab.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index b1113561b98b..344a101e37e0 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3416,6 +3416,9 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	if (unlikely(slab_want_init_on_free(cachep)))
+		memset(objp, 0, cachep->object_size);
+
 	/* Put the object into the quarantine, don't touch it for now. */
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
@@ -3434,8 +3437,6 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
 	struct array_cache *ac = cpu_cache_get(cachep);
 
 	check_irq_off();
-	if (unlikely(slab_want_init_on_free(cachep)))
-		memset(objp, 0, cachep->object_size);
 	kmemleak_free_recursive(objp, cachep->flags);
 	objp = cache_free_debugcheck(cachep, objp, caller);
 	memcg_slab_free_hook(cachep, &objp, 1);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201210183729.1261524-1-alex.popov%40linux.com.

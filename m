Return-Path: <kasan-dev+bncBCT4XGV33UIBB7HD7WZQMGQETWVUETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DDF91CAA7
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:25 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-25bfed6a3f5sf1486390fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628284; cv=pass;
        d=google.com; s=arc-20160816;
        b=iiaU9qXZ8jR0oSTBLAEs4QupNo/xhlc9+aAFTyLpnHC8zSv/ih6e65LHzq1RHd2R7A
         sP3oN2N1N7RkWa5zGAfOKNyvn7SQXbJG/oFf/6od7jbtQ4WgBj7P/+wvuAP9Xelds0nY
         3p9PR8WEvDU10T56zTBotlagAbwMzbb/gQ2wqWgSQ2xPuo1boYU6xdPVYNSaU5RKoUHf
         M4KASkOPG0hsB5tEra+TjjVqD3lOBDMiHSHAnYfbzBLM/yIVjcxFPs0GMbRBhv/h0wmk
         31vMSKSkkHf10IGxBI5irezI4mZcTY1gtwhu20HAjgmEML1UMACTdr/6uoUzQCmrayeK
         mo1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=QGphnu1zRA1zyrvCErMZKjTnbMQDB2gijmVKIXEmk7E=;
        fh=eTtoPNasuZ9i9B/lhKFLmszHnRyG0jV4OnK6pP2/JMc=;
        b=ca5h6cY2+9ytOq/7GwG1SeqVl02udJokzzNbw0g3iJMjhL0gveNs3vQvQGRPb5GmBG
         zGnex9mQAqHJa5spZhs445sHO6eHpBIRWrzXYfPR8OH4SSaNc5rKm4sfm1rTOHDx3SSr
         9bPA0eW0hC62LaTVpIrRmgFdcHbCw+ZVrwL5IxBcrRtD9f1booi7l9/Glocl2Z+mLkhe
         pjii1+n4fHVpRwJgfoRj0Rcb5o7Bet0sUjxqgLVtSotO01GI78ZY/ikgAGen7k34L8LN
         kOWEVYI3RoXRrHoL5h9YMfjN8MhE0HHYv0FTlNxagzHWxC5BpmHISFpU59z6KwsH45io
         CY3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="hC/D1x1X";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628284; x=1720233084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QGphnu1zRA1zyrvCErMZKjTnbMQDB2gijmVKIXEmk7E=;
        b=F51vauLqxsdA8t4RDGRY0nzlvUXQI+kmm7OvwOUtEcX1Mlp+PkXrDcx64fFkM/6sLt
         FZ7lqzNUJEY2PkCunVi88BuToctCV00PObstTjZ8RL5NRpXCXjKwYb0m84TbUi+AySSb
         OOsTleqYqJjj64Ap6mpvmZi435AYo1q9E9z0RRKtz5N6Y4vMxtHbN67COEisEjfX/Y31
         nZGPRiAcRslim3qqJPWVXEc/MLvnlqzFdar0ku567DOAHPPXWqIy9i4SSIBmwAUILk0e
         UEdFMYZJ5fhEDK7LbYj1s87f+wDof/jpV2fGqgKFuM/rhkUATwFvTydGnT5LC0NmHxUS
         JVKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628284; x=1720233084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QGphnu1zRA1zyrvCErMZKjTnbMQDB2gijmVKIXEmk7E=;
        b=s2y6haHQQCtA1uNpCuRq4BxxLKsmyJeJIj0YHP/OeyyliWbO7FFs+x2uv+tkcSV8wP
         nI8ENF1+u/oL2Wo/+s8X6yAhT7dSTvsQcR+R5kokNNm0K53FvuI3BNsUORiHyS1fNjoM
         6y9CgQoydotQWqhyWOAgch4yY1U6XEcyzH7f8jMfflMJNtGlBPkaSWktPrS144WsONeP
         y1NnmhwOJTAgO5TEjFo6+I26MrKxdqrYDgdc0GqRq+DliAazy3bsBwGR29nWuv754sE7
         nu0yGHhKqMkK4mf2THbFTCar8zpP8ul7Z2HGqwTZ1mZTR+GoGkubmyMUJz4LpivYIhh3
         dV7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXMsFn+TN5K48PwyHGvxLMmxz6VpsrEf1M5ilVpFhFNsirkijS9bou+C2p43+fjiOPrqz4jgV+ESXXTEP4SD8qJ69KQhopRCA==
X-Gm-Message-State: AOJu0YxTWpxr9HcinWH93q5BAd8V0ErqJfPiVURahT+6jolmS0cx/guZ
	Kp6jmsn3iIMAxGofPxaLSeU+JNT6T30gusJZXDlmU09wPBSXoTnj
X-Google-Smtp-Source: AGHT+IGyxM/4uuRlnp5j4ZrYyAoixdI4yeu47KhSLvvjh6F6a922M7CAuwRsvwlLlwM6hm2RaLsyEg==
X-Received: by 2002:a05:6870:b490:b0:24f:f282:241b with SMTP id 586e51a60fabf-25d06ce030amr18571795fac.33.1719628284329;
        Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e499:b0:24f:f0cd:4790 with SMTP id
 586e51a60fabf-25d92c3a9bfls961568fac.2.-pod-prod-04-us; Fri, 28 Jun 2024
 19:31:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz4Kir6WVGpQhIWUkZhpjEpMc7uVA3LnS364zJFN85Nh7C/EitIW8+RWp7Tlf385xAPdqN4Yf0Hrc0IEKdcyYUb6/y33thrZIg9w==
X-Received: by 2002:a05:6358:4425:b0:1a5:fdba:7f50 with SMTP id e5c5f4694b2df-1a6acc7ce47mr6256255d.12.1719628283504;
        Fri, 28 Jun 2024 19:31:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628283; cv=none;
        d=google.com; s=arc-20160816;
        b=CBsI1hKMagqNL6ppeEO6OX+6v4kzrysgL7Ugk9a61zoKnaGWNRGjqMGlT+2VXiRxeg
         /gzPZ06ZMnn8kHYDMmsXpAa0Bi+hOCWJUJ/p5Ol0CXvBVI/cShHAgmgUPhhLGXsOtgob
         1N3dBcRFkIfnKEKmUd4yx7QC6WxAcWO3AYMBurKQFSXG4uj1M5k91QSfQH27rVb2dzrx
         1RDQRoV9ITArlfXW1sFHYl6Xq/CLhYMMlfQBa2G+2dribP3qvWmphuremScU1+mZ2QhQ
         RX3o6/53NTL8rJJWunOTWT45gGHjCkXhHkQmxXgWZDZj7vOnCFi0fruswOUKL5+pjQyT
         GA5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=Bd2+bKpX+cgMiJyMf8HLYb0EGrCGX2+UkxhzRXYWeGc=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=PWxO20yag5Ro2fUS3CV18/KFGxuU2oFujnaPlK9AGV+qUOUD3HSVnmDCD5PyXwWVT5
         OqPA9y46vy0EY99WdlARuR1rFKym07+VOPCHJQVr0WnPukTiiKtYoNkoMvfLv37A4l6i
         yVP+XPnOf/20tqNSRTHkknV8RALvVaBP1AQv44x5316vPex5gm0E0fPFFcQaVeCkB1Om
         hSaWLMUqfQ5NbEaFlOwxxWnDvgFIClrc8ynt4lY7nZfD6ywBxdgMWus9/mFe2tHw7AF5
         dnqPviMXVxRg9iyGpBwAHai7Pjwh+JfWH+0MjQq/iaJSVv2hgIxxnc2BdwNxjVE6/J1d
         phVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="hC/D1x1X";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c93bb23c9asi17507a91.1.2024.06.28.19.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C3D15622BC;
	Sat, 29 Jun 2024 02:31:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6C392C116B1;
	Sat, 29 Jun 2024 02:31:22 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:21 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-uaccess-add-the-missing-linux-instrumentedh-include.patch removed from -mm tree
Message-Id: <20240629023122.6C392C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="hC/D1x1X";
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
     Subject: s390/uaccess: add the missing linux/instrumented.h #include
has been removed from the -mm tree.  Its filename was
     s390-uaccess-add-the-missing-linux-instrumentedh-include.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/uaccess: add the missing linux/instrumented.h #include
Date: Fri, 21 Jun 2024 13:35:19 +0200

uaccess.h uses instrument_get_user() and instrument_put_user(), which are
defined in linux/instrumented.h.  Currently we get this header from
somewhere else by accident; prefer to be explicit about it and include it
directly.

Link: https://lkml.kernel.org/r/20240621113706.315500-36-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/include/asm/uaccess.h |    1 +
 1 file changed, 1 insertion(+)

--- a/arch/s390/include/asm/uaccess.h~s390-uaccess-add-the-missing-linux-instrumentedh-include
+++ a/arch/s390/include/asm/uaccess.h
@@ -18,6 +18,7 @@
 #include <asm/extable.h>
 #include <asm/facility.h>
 #include <asm-generic/access_ok.h>
+#include <linux/instrumented.h>
 
 void debug_user_asce(int exit);
 
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023122.6C392C116B1%40smtp.kernel.org.

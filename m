Return-Path: <kasan-dev+bncBAABB2HQRWIQMGQES3OLLEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1010A4CE555
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 15:49:14 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id c23-20020a4ad217000000b0031bec3c46desf8069044oos.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Mar 2022 06:49:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646491753; cv=pass;
        d=google.com; s=arc-20160816;
        b=q+KOFMGiAJ3AbeV0W1+Y5pKe3HX5S40WdDIg1nvZK3aQgfMEoMF8grsPUGVg2uVC8R
         AKVbjwCE+VO9DELyxO1Rdco67cduUjPhfylu1Fgd/BnSRI41D7l061fusqNYdnAOPR8k
         7ZXhR40h8kpEwQYkJ35u4MJcr+4MJEQGOqB4/n9LDVr44cBARQ6GNofrsO9DwyBzPwmh
         eA2dnyftacdA04OJUDYGVQLO1bHWHghs+QKjL1PnqzHmKHw7d4ja/KwHH8/tLpfvn9kL
         APuit3vdMFyPwi4RpL9MJg5fnnj6u3drNPN3vAENPqiXSxGqKvnvmbSGEcEOK8wTI2ak
         qfFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7uB9Hqu1CNTJvKCFeZgOR0Mn6EufZEQuepbr621ABps=;
        b=Bi+z0yi8bxtOsOkihIa11McbBab2/XwmWdbeRKCAuwkk1PMhozz3PyVjLm97LMsSQn
         gTituJffbJmqYrjvo/B6YovPqJfWVsF41caDDAWGqEdWrziXWdhKliIX98ZEZPhYMme0
         8tFG+/y/ExXWT5DPpHBdbnVCyadQSNdsDXUKesNevtqNRcaE5Y88XejVte/wORdGSlDF
         SXKiXgoriVzaT/GzgGCsNretdVnsRmDgeb0g3PrbhG2n4fIdFKsBiCFV4URDuilrDkMB
         DnXTzj+047e2Ixl8xiL3j952bJ+JTEVA/QYSwATvfJwucVr261n6r+ozsbC8/38hirk1
         oZPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7uB9Hqu1CNTJvKCFeZgOR0Mn6EufZEQuepbr621ABps=;
        b=B8muvaguL2M1IzktdXvSF/6fzPc/XrV4bGQsp7yIhIBjs7ChgH4HG3RXebKchF4eMg
         JofMQTF8Lj8DSrEcn3r3jfsr9+uijiX6K7CmB4F0TE5+b5L3FQe9Uwzzc5W7uL3t31IG
         Krtatu+EnCoF8v5jiS1kGQgN0UPdFWoyNSN9dZgucQAq0HE/0rBJmR/uFuz8QNxbjveD
         ZHRdN9+0/E/LgnWLLD8eBztPH4LIANnBD0td3XxiB+w9NeiKEgGYhFhTYKiH6powIroi
         yrg3ktbPvWjZ8hCB1+NcUEfh4UCEJCj4yyRudafogQLVdGQRocp6lTvfphhhDj3oSXMG
         VTbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7uB9Hqu1CNTJvKCFeZgOR0Mn6EufZEQuepbr621ABps=;
        b=hbU3XbN3p//rbz/3W403AEpyS2fcMneufqIFX5bxt+jsefHfaAYDfN39Aw05xaOrS1
         Ir8YPK9ww55lAjPaV/JdW/JL89gqczT1C4Bk/DJZx8pBrvZspEKwp3l0335TkubYch4d
         G8OpYD7Vfb1rIK0+QE/FUxjcYaytmUS2JdsZhnegJ/4Xd7/doD1wmaqikujvheT2f/BN
         ckcCBq3Gzq/3qCjJ17BIuUM2uzcc4c7zULrmFO9DYaKK6MMmGdYl5KxyQ5GrqGcaFelD
         KI0qGTsuPD7FwwNHtJ+r3r/W7BcpKafKpkYsq0oKJglQOFy1II4n8eiIfCnmtQE2fspD
         DhnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PPsSVbNSSsg5cZqruCRKQsg5ZFTW7Mz7LMMqBDUD6yTYAAni1
	G0qJVczGqBb47urlSIohdbs=
X-Google-Smtp-Source: ABdhPJxP8LSuLVHHC4fOaQCSko0ZGIRaoDjsruk4L0mgxj/DeYyqjsCA7+uGyzbDH40MDBZ0HEFiRQ==
X-Received: by 2002:a05:6808:138b:b0:2d9:a01a:4bb7 with SMTP id c11-20020a056808138b00b002d9a01a4bb7mr2086261oiw.222.1646491752921;
        Sat, 05 Mar 2022 06:49:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2405:b0:d7:627b:b530 with SMTP id
 n5-20020a056870240500b000d7627bb530ls2722025oap.9.gmail; Sat, 05 Mar 2022
 06:49:12 -0800 (PST)
X-Received: by 2002:a05:6871:893:b0:da:b3f:2b1a with SMTP id r19-20020a056871089300b000da0b3f2b1amr1918146oaq.185.1646491752646;
        Sat, 05 Mar 2022 06:49:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646491752; cv=none;
        d=google.com; s=arc-20160816;
        b=mIqIu9oKcSVQHwNYqhIL3pPGTZlb0gfc+rYtR+l7sJySa8HCBoDXcuWFnBFx1miJtS
         /+TB+LhqudtrSEc8qbXYFlxO0jvGhlasAguB0lpbPtCA7wW7q7efEOzE9Vv9NMo+6dhU
         l8THo/Ruygutg/LjKAR/ZXMQ3l2seYQ0gEru+hs/12xa3C7276eYpX7UQS4AbTWmRLLB
         u1HKNtqmC9YXYT/ZFJxRa/t9YBc21obPAvPKIINyLWky7hB63bTv+N0gSgcgbOAHY1AU
         7xAVX1Z11NBdncfaAcAhVtMH3wUPKcSrXL0AzD0B0yWIfR3BkhBVO9mxPVMD6zI+PHSF
         xCSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9VcL551A3TxVykm0jE7KKo0qII6AHkQR38dlA/avbUE=;
        b=WifCoKlBOK+1KgH5Yr4qWo2HFH2yNE0+gjXFPIhSQIG8Xqt9bTsUqK4HYLSHAf/x9P
         yDyEOXMj4c+GpzxGF/Ckj6cTEwTyDY4Y73ujaojQ7CKPg93UNKpLIa5nHYAqBYgaBzSh
         0poeYRX0ZwpI8utbUZI/Npz/xnabU57ySrh5U6fpTWe6zLNefKzxigb0Q6gYiZnCoOuV
         jSiBiQY3kDMpK/EFWPz56nA5974GbDb2RR912G1g9fTBbdrJ9RJsnEV6rZTkgJsoasv5
         SoJSqeG+22k3zDmxLGgGL51dmRJPreg9xem28ShCyhFexxCxZaZICevIBt9qixnnAwnZ
         mcQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-133.freemail.mail.aliyun.com (out30-133.freemail.mail.aliyun.com. [115.124.30.133])
        by gmr-mx.google.com with ESMTPS id c6-20020a056808138600b002d560aa6678si1099388oiw.0.2022.03.05.06.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Mar 2022 06:49:12 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) client-ip=115.124.30.133;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R161e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04395;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6HF7hU_1646491739;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6HF7hU_1646491739)
          by smtp.aliyun-inc.com(127.0.0.1);
          Sat, 05 Mar 2022 22:49:08 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 0/2] provide the flexibility to enable KFENCE
Date: Sat,  5 Mar 2022 22:48:56 +0800
Message-Id: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

Hi, I'm sending v2 about (re-)enabling KFENCE.
I've removed description about use case and just focus on flexibility.

Thanks.

v2:
Take KFENCE_WARN_ON() into account. Do not allow re-enabling KFENCE
if it once disabled by warn.
Modify func names and comments.

RFC/v1: https://lore.kernel.org/all/20220303031505.28495-1-dtcccc@linux.alibaba.com/

Tianchen Ding (2):
  kfence: Allow re-enabling KFENCE after system startup
  kfence: Alloc kfence_pool after system startup

 mm/kfence/core.c | 114 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 93 insertions(+), 21 deletions(-)

-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220305144858.17040-1-dtcccc%40linux.alibaba.com.

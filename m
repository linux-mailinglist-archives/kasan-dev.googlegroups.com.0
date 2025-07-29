Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB5OFUTCAMGQEXL2HZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F54BB1538E
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:27 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-615bb7de238sf5644411eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817846; cv=pass;
        d=google.com; s=arc-20240605;
        b=UgDFqrMUvY/nJvrjZHCjPXaSG4lv6B74hwfyFwX/GRXlwngzp71f0gcsyzExJ8vL56
         xyjX0Gi+gZysjc1AuH3qygDq1e5Ndc0rAXgI+3thXNW37/Tm15tP3udDHhHDJfAANYem
         ytj9N7LT+PxTP+/7zYj+SUlYVy9VzuDO62gSsfVGEUT5Z4sxRY2eOk3xmiJiW2xqEHiM
         6+ayC8joH27XpxTEkDc1/9L8sym4osMV76eQiSkQ8mBeFX+cQk1s/jOmd+0ERg5s4HJi
         89BIv2WZqBjECNH8d9bCm+VJHt9N44tL6eEamMPpEf74wCnaOYq3W5IljRxLItu39Y4v
         ySUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZGGKd4ZBk8sC2vDJDVMTD5j5C9yghi0HplR7k2JDQgo=;
        fh=IPwe3Co7u6Mr8UP9ZuZOgSYeNG1m+mLunu+DupV6c1Y=;
        b=AWwH5mI19iVPadcdE8f2/58qphBU6rZQTH8tKgO3+B7bGeeTmm8P8Jt7CG6dLvLDh4
         g1co9c7pfadmGoidDAlFETqQljZyBeBf4Ug88QTWYRqqmrH1mE72ynzDgexrVtrnJx8e
         kNNSirQqR4+7Hzj7F3thHVBIkCORrSyCG4PG7dkIVfXJx5ruuYIq6tadhlbTbuLhyJG9
         5h3lh5FdYPvccK18eD+qL9gqVJOVwnE/aB2u+Aj3qOlPNKG1LiOh4xJj9w9bNQdshCtz
         G4/5AZtzHJtLAlG1OWGA+OFnxOnzQwE6UhO9ZUl5I/LnfNw7fJunQ1+9vT0CLu9P7rik
         Husw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=36yLl8hK;
       spf=pass (google.com: domain of 39ckjaagkcakvjarnerlpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=39CKJaAgKCakVJaRNeRLPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817846; x=1754422646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZGGKd4ZBk8sC2vDJDVMTD5j5C9yghi0HplR7k2JDQgo=;
        b=cTH5dig7tlwdf7W4xpMv4jCUOVxsQh62asFjB/f9JbYsJu5Y/zuu7FKZgdR+Sp32CK
         pd5p5U7HTAjqekCJpQca0TWMp/5Qnsh9NjzTSXjhJ+0RfTjomj7FhpNZvE4FVHT3R87W
         ro/zdgTzOZI8Qdw0O0hYGfhT71kI3fGcVlOdCWn/21qI96tTRVhjINLr953cza5k2PUA
         UHgIKgbrObBZiGKwYCfrCqsJdSEelropZVAgCSXlXvaf9rGBiZO3ihzcbeOWm5L1gge7
         +isXkHC08yZCAiuO0RLfG+W+ivwgi6v+nU5gC7S++DU4yYhzOIn/GkCXJ6fVebBDVEjO
         bHmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817846; x=1754422646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZGGKd4ZBk8sC2vDJDVMTD5j5C9yghi0HplR7k2JDQgo=;
        b=s/ZBMwv4Kz5SJmSPR/pLE4KWY9d7kukbee1V0EaFxi1IPyoj48vxV3uIP4RwdGpIEN
         d7Y7Qni+3V4qEw2UjEduUV/E5iLmt+foz9ZkrrMBpN0t3daU29cAEvsNygGNhUK6Vsjr
         ilMin0gCEbxALfj3sdgIFvOKKbQuqkGnbcBESni4VmVSqUyk3d/WnwbL54Y2crW/tg57
         rz7bEgrp7LLfvQnu7s1pSD4UD4bzwqbXtA12lZEEnOoN1bUGNVJHn17dXzQbrekAJi8i
         1co0RrGnVYTC+YW0n1oIlR7RkizrSGv7k/NQPtIbPpTDm03PLeiq5IF6VjAAo1SEe3/a
         XrDg==
X-Forwarded-Encrypted: i=2; AJvYcCVZrXeHX7ja2vvoMlp25x5G86WRaO0U/NbOZJWCQeiTiamCGhPRWeoFMXCbymqG7b6tj8hZdQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz4t0T9dGTG4dpKnNO0Zc3kppv9xpsQlMom4yQgQaBukEJUlZQh
	7dbGEbDJ3DtNmlZ6KEemWaVQffyWIzUiHmpumyHA0pk7NuDha+uMHAJD
X-Google-Smtp-Source: AGHT+IFNS/McgPEYXOjAGZ6O2KED9cDO/VboDw5QhPjaO5rebh8AdIrmNLjCQQ5EeuuzBgORcFTF3Q==
X-Received: by 2002:a05:6820:99a:b0:619:2ef:be06 with SMTP id 006d021491bc7-6195d2bcf0bmr634609eaf.6.1753817846065;
        Tue, 29 Jul 2025 12:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxYLE3JjGRfgARswRhgyp+xBe3I7avag6AXOOU3yu+Dg==
Received: by 2002:a05:6820:2407:b0:615:9e09:e4b0 with SMTP id
 006d021491bc7-618fa2665b0ls3060469eaf.1.-pod-prod-05-us; Tue, 29 Jul 2025
 12:37:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7n/X48y/k97SfJpXTiYbEBq3A0Fhw8mh6jsOfyOneW7Y2HNqU95rn1iz+F44jk/lFzEc07WGyteM=@googlegroups.com
X-Received: by 2002:a05:6830:7192:b0:73e:a1ed:7716 with SMTP id 46e09a7af769-7417784c287mr772754a34.0.1753817845243;
        Tue, 29 Jul 2025 12:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817845; cv=none;
        d=google.com; s=arc-20240605;
        b=SnCjKjuUalVXBak0uuL8SVoPsdaIP2wnNRm5tiRJoEpiAyscLQ1Kw/dw8EopopBUdI
         /pbwY9H2GJ7weuCTXW+dmcfWNBaJGdhS1uiueeEWqwU3pJX9mvn5+WL+D1eWmw15z+Wr
         jgl8ove6wQwphK0+HOXqw/qqKxt/ELeNfDwSHVARbZfQ8fiyoq7uaVbsc+SP5yQfJdQX
         FqJwFnNC/Ga82PRtZoTYvGcrCXzT64O6oRpyY1hGLlSAzzDGi+WrGs8+00/lIrCqsQCo
         ZfBLgzvFA1Q1TGYZb9VFSwsFY9Vkx+2S7Y1cRo95ezf5Ttrd+qLdIfd1vMHEwdi5QXqd
         GXEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=n1I9IAjE7arvoHRD2CPgQ4vbTvzkjQYYPvGX27voj8U=;
        fh=Z+xwtOiGQUau1M7J0+TWtz/ZdobQ/2v6OFdCgwtiH9k=;
        b=TfjpXN3W2IENJ12SsTzJnJHZPcExszvjaeqtVw91eUbb0AUVSIvTJITc06sWqMs7aR
         XqcFWshMpEHeiM9WlJrL3pJhrjj5Fr06ommUHZ4I+eaX35RQSKC9mt9qmAW/7Qz889CH
         Zk6ZuuqAJ2atW8I1q86LpRqakvjkX/gHpXyWHu3+yEPQCPFg9ay/omhfo0rbummQI6mj
         CMNxTQ4AcYEiYSRiOfDGZLZlG5AVRlVvY8htzy/IWDaN1q9C3cIU/BZelOus2XsWhOWT
         /6oKhxfgweu2Xd9g34lMPhKyH9QA9n/6opQSG3oXU29ZLAtojMSGXTjACPKinNan0uVN
         m2PA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=36yLl8hK;
       spf=pass (google.com: domain of 39ckjaagkcakvjarnerlpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=39CKJaAgKCakVJaRNeRLPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-741481ef779si442851a34.3.2025.07.29.12.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ckjaagkcakvjarnerlpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id 6a1803df08f44-7074bad04efso4106086d6.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSsoM8BSP0+cKgsQTMfIO5i2ZVIw3tLmL523Os0lOfDiM+KrCuySvFeg6zohhpjHbJi49j8LMG2rI=@googlegroups.com
X-Received: from qvsw1.prod.google.com ([2002:a05:6214:121:b0:6fd:5e45:e693])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ad4:5ecc:0:b0:707:5046:6a1e with SMTP id 6a1803df08f44-70766139e40mr11981946d6.10.1753817844434;
 Tue, 29 Jul 2025 12:37:24 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:42 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-5-marievic@google.com>
Subject: [PATCH 4/9] kcsan: test: Update parameter generator to new signature
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=36yLl8hK;       spf=pass
 (google.com: domain of 39ckjaagkcakvjarnerlpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=39CKJaAgKCakVJaRNeRLPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

This patch modifies `nthreads_gen_params` in kcsan_test.c
to accept an additional `struct kunit *test` argument.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index c2871180edcc..fc76648525ac 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
  * The thread counts are chosen to cover potentially interesting boundaries and
  * corner cases (2 to 5), and then stress the system with larger counts.
  */
-static const void *nthreads_gen_params(const void *prev, char *desc)
+static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
 {
 	long nthreads = (long)prev;
 
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-5-marievic%40google.com.

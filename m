Return-Path: <kasan-dev+bncBCMPTDOCVYOBB5HSUO4AMGQE2UT526Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 19D7799A0DA
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 12:09:58 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbe6ad0154sf28153126d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 03:09:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728641397; cv=pass;
        d=google.com; s=arc-20240605;
        b=UKe4bj6y2puzvzyCOo1ixHMZpcJvrQFuqpr5Vs2or5k06GQ1bUBqUnrBd6S+K2jRsy
         t6nkzuSE5gN4ejc1ud4xfn2tPZhVnMTHUgNB+ZoPT0Q/pBPLUpp+rZ3f/VQoEIIe1GB3
         nS0yZKN9eH7joLCmfOg/+Ror2oFmusgudqHEwM+vS1Xy0zovZ71QHuI1mFNnJmYK5G1X
         jTuUa9JGjXCL/JGsIRFxX4daKDsZfqsRTFf9ar7K2p+O61/qjNDB9E55wnJaecMMh74X
         r28a47hDaRgMdVBi9lNe9Ztl6H7SOmtnrqctT4WC2GG80t1edJUZFF4RpwmFy63TzFNo
         G1Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=pYkzGLd1VxObADxqP9gxU6dl9BYTqYY/yy2EwSXfNCI=;
        fh=C//L1XaasLtPxAjHgCq15gFAlsa7zfl6MYJR1i2Zl/I=;
        b=VTEK0iG2lEq1J++TGA7lDo+8tuLaWE1AlRL9FuGYSq9Yw8TbTJEbF5Ritzr3A88FBv
         v97gBWkh7p19ifNbZjI+Ib6BXSBNISa3mhndNImC0LpSaSGLb9EDSzgkogZtwUr5e2fL
         zoj03p8YS3RcT9Qk59Y7yM/cr4h6p9QqyA0l+g/rgEcZP7sVBIWy59a5ol/5CmkkOfQs
         JhMuii4oHIfj+UXfImW1Kqppd+LrENDJp/DLZin/Dq5LarqXhwQo2unlM7C4KK5P/wHl
         ctD55u8/PEJHyDEAsBR8LjBz0yj0VN1HIToXnhZUjwvq4soNL6TbOQHNAHQcqmouPQWU
         TJTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ArJ6qXvb;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728641397; x=1729246197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pYkzGLd1VxObADxqP9gxU6dl9BYTqYY/yy2EwSXfNCI=;
        b=COj+q9+7OINzQmRgYEu9GHClw3mgG7i5m4bh8hVy5TIj7fyHGwULcuyUhUCd6PLHAb
         4zNHWnRjQ+9iH9i0Yi4Ka34ToSvz+TBHp4I99BWhTvW4cWrMXUGhB+rsTOTDt6PB1n6I
         oNe1PZlG8+udoC0/Mq9XhBj/qsBUS+7WbQwwTbT/RNWH3xvJQO3Wq6cv2Al1YBL+ObML
         7NraVuF2BJQDNCrpOI77tRvdIWLZg3/JEdNVkO2ZGXyqQdDBlZOFQ4A31WFUsugI9XNf
         o8/FmnIkRoBANpu0s3WWaoiGn5hv2LSM2GAIbxLB5n/rhSowS+aynpuDuIuq9/D3CSBa
         pQNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728641397; x=1729246197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pYkzGLd1VxObADxqP9gxU6dl9BYTqYY/yy2EwSXfNCI=;
        b=HqZFUTxQX2UzHlqbP4weNrhTrX5oR2xSqdLeU1eAolzXE9KdfV3CrMWcC5IAsYXMLV
         RU6UQS9mx3Cf++gxQUF3knDOTSs7D4SPrE3URFov/vJBGGuSZl2oujsdlAR1bknU1DwN
         6Z4vKJ/iuYy6hQ7LEBaRBti3UfkK+Pppj+uu+x04CVRQGZAZUR6ImneZkvT+iQavegzr
         dccloporTUInNnCJZl8dP86LCecgOD2DX4YJPIKmFe8fvhC1vYKtSvYnVxsWH5eRMKvz
         wZMM/5PMV36aAZfFaUDjZspt1GPZ0kw/fLAQzFvJBjqYu4YZHZCNEnFB0+jqcfe4lQLj
         e5Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728641397; x=1729246197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pYkzGLd1VxObADxqP9gxU6dl9BYTqYY/yy2EwSXfNCI=;
        b=FCwK6O2Kw2SU5W1fPIBFat55jSXNIyKQEVzId+4MH33cj46kicF9GI2li+nRQdg75I
         v2/RTnP3xQyYmpGNJoBs3oycn6FrxPBCw/fTGA6jZOfgL5XJoHnDIiZ52f2cCHLXUMlB
         0GT3vVPmxnlgf1Ix4cE/JbhxeEw8ibJ6WaElNUo9o/euPyr3uP1FdiujbHSvygPrJWB6
         redHEQJrA15iNDg8IT/5qyNv8PR2Zdld4vhFoabTu4s2LoFzESgZqS5L9ZvE/sURb/V+
         01qWwuhIV3Di2SToCiTmDvsHfg0en0k81bi2dRW3i7cVyVbTZ47jtO3Cn2JL2f6txc+Q
         Ra5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkrdZzaCq8VLeB76+Na5uNsncEx6l22bUnh5rtUDSYYfu/skAjMFc5EZZk1jfOe4c7krtspw==@lfdr.de
X-Gm-Message-State: AOJu0YzFxKoO3AUQvuxRh+4bvrUFnZyJwUMr+xzWudHZWIUGWpz2qqgs
	jkNe+wRL5NH8QmUX7TVfVmuXfTCl8RsWY9LgVTqri+UEhN9AFxYV
X-Google-Smtp-Source: AGHT+IEot152XKJGac201GWNpQt04ptUmrk6nFOUrDDBO2bcyOQmm3C+Oo4VK7TiVIaBbr71ZoFwKQ==
X-Received: by 2002:a05:6214:3d85:b0:6cb:9bc9:e24b with SMTP id 6a1803df08f44-6cbf005c165mr35250156d6.43.1728641396637;
        Fri, 11 Oct 2024 03:09:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6d:0:b0:6c5:19d1:7aa8 with SMTP id 6a1803df08f44-6cbe5708578ls8943836d6.2.-pod-prod-06-us;
 Fri, 11 Oct 2024 03:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXa5Nvu76RHncDZRv8CR7d5rlx3dAt0MwkTgJbLbC6xAdXHOqDpR0B1mVMo1WE9dmh4Te+sfl73iBY=@googlegroups.com
X-Received: by 2002:a05:6214:3b8a:b0:6cb:e7eb:fcf0 with SMTP id 6a1803df08f44-6cbf0013e04mr27848906d6.33.1728641395574;
        Fri, 11 Oct 2024 03:09:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728641395; cv=none;
        d=google.com; s=arc-20240605;
        b=I5cdyQmxwffGldotWxD8dl8F07vpMuQhD68Ky2Sf2otVIU3DLr55iSQ2xaOD/0yUJZ
         XFO0S8Mx+7riVY3hMOAJS18QAbDd9HcnyNUNRaByJGV9Q4BZ9xqJJaiBHzFHRYJFSyyH
         MnVdbdfu3Hpo+fOpYnbHf9MbcJGY+ZQMZoels5VN/X/tGUSaqIpvusVklLa2fy8nsfC0
         mbkct34VnhvDkqsllzVMrdPtpopL250YWZs5Zax8X+mhot1WVgYYX5oQvHDFzhvS0aUy
         uJj5gKe3bO/oeqS30AmHcr61IwBaB9hsX0HqtxXvXJBwAwtst+4+a66h/iXJd47Uz1yN
         m5qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b/y3joT4t3IK13RKjZ6BzEDxAFTvU2c3jUZXESXkMEw=;
        fh=nuTmejWyRrg6dVtO6Gg5HIad0O8pqRff7F8pFWRN8KI=;
        b=dPuxpih1gWNSxM0wFiDkR4JXN4qYaE5nOE0ryOmJTBBrrvGPy0uYDNTfVpcDO/yYek
         XL2TlX7AtS03OQmKfSjMV/4kvj5GjeOqKuCpBZD8oKy0n0nkB/FSAArsbURy5TybcqtV
         tr3zzRKO5GEenkNsV8hnKZWuJii3AvLsr+lOncTdsPYNHs7ZJB6Y6nju4e9mAdywx+f0
         eHgHVy/Y+YyiD/ynvzJzVGwbMXRUmm6N9OltkJXgBlbFyROZjHM1qX0a2yiw5sggblUu
         18WI0hfZ+1WjrZco8z0GIjvEOtrncDYn7biHZ2+/CoRrMs8ltmBxiExv4/KP+ZxVdk9m
         c97w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ArJ6qXvb;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cbe86099f9si1295116d6.3.2024.10.11.03.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 03:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id 41be03b00d2f7-7ea59e3ba34so51692a12.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 03:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW2d2Uz1SYRkXte/A5G/pWgHHBWuAuihT6qHGVZm455knBo+DrERRxy1pHejP25VdCLdhlHZrt8cNE=@googlegroups.com
X-Received: by 2002:a17:903:1d0:b0:20b:bd8d:4281 with SMTP id d9443c01a7336-20ca130f7ccmr12094555ad.0.1728641394464;
        Fri, 11 Oct 2024 03:09:54 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-20c8bc0d34bsm20980575ad.97.2024.10.11.03.09.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 03:09:54 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	skhan@linuxfoundation.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH v2] mm:kasan: fix sparse warnings: Should it be static?
Date: Fri, 11 Oct 2024 15:23:00 +0530
Message-Id: <20241011095259.17345-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ArJ6qXvb;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Sorry about that, thank you for the pointing it out, I understand now that
compiler might optimize and remove the assignments in case of local
variables where the global variables would be helpful, and making them as
static would be correct approach.

Add a fix making the global variables as static and doesn't trigger
the sparse warnings:
mm/kasan/kasan_test.c:36:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?
mm/kasan/kasan_test.c:37:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
---
v1 -> v2: Used the aproach of making global variables static to resolve the
warnings instead of local declarations.

Link to v1: https://lore.kernel.org/all/20241011033604.266084-1-niharchaithanya@gmail.com/

 mm/kasan/kasan_test_c.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..4803a2c4d8a1 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -45,8 +45,8 @@ static struct {
  * Some tests use these global variables to store return values from function
  * calls that could otherwise be eliminated by the compiler as dead code.
  */
-void *kasan_ptr_result;
-int kasan_int_result;
+static void *kasan_ptr_result;
+static int kasan_int_result;
 
 /* Probe for console output: obtains test_status lines of interest. */
 static void probe_console(void *ignore, const char *buf, size_t len)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011095259.17345-1-niharchaithanya%40gmail.com.

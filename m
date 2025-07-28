Return-Path: <kasan-dev+bncBDXK3J6D5EHRB3FITXCAMGQECFNENGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07550B13927
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 12:43:59 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-23fd8c99dbfsf13725895ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 03:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753699437; cv=pass;
        d=google.com; s=arc-20240605;
        b=a9jpyVKiIu7maeaIPwWhe4Hgr9Rdc21XHsLUkjN+SB40C8gWMTa/vcUA/MdjRzgRtW
         1gQpl6dtnT7oLnfBG3DpVcpJtwqPAkXTUYFxcVoTF2FVLkNGQW/WPIUNlZAmkNEE3Tsn
         cG1VryCMyamByGPq366ST6gS59fNNXgADvUkH6QxZ7gvgUDciVBo3sJCk16fciKHMfk0
         bsb2DfNZe5UzE2AGHSy3TrlkTxAyn4eM7d0VZSj4baJRr4Fdy1GnD0zw1VxFgjBtWYFh
         nrMtCtH6CD2qIK+ljKlkGkO1VgMwR3xrYQZ9eSg9xB/1R+cT8uwAo7CkGQOeoQJzjeNA
         zelw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=ycJLagm9QD+3uInkdJe1xNVZVIo4GkR+A/t5chtLb08=;
        fh=e4i5LAWCAYINUxdp+Ame0miHFw2ha8BKj/Brii29nXE=;
        b=SPZ+Dx7lEuNrqmJdql1SWc+IBdQVu+gjV2zbzfYzm9pskhguW5MqeUm2VhZcLiWLwW
         Br2ey8+2EPoH4r8pZJgqlVXK89W3fSNs2n9gfCKoH2b6p0nVcCJdj8lT9UZcZuu6+HV2
         TYV5wakMgscErPq81H1hA9ac2g4hCLMZmXthzBUySR4nUX3l01ufGJjkLPxAV+CwzwCb
         xjx++P9a9bfLiYlTZRlWZTDUtv/b1W0vhYrVlbdD5XyiZqs4Nz+c1D370lPZaVpxjD/1
         R/K0jKk59lChK8qMJzNiQkpUCjzW06vVa4k3ZCLfo8QFLVs1SKbUs7b+ZdTNuC8m/yNC
         MS0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=On5TuiIE;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753699437; x=1754304237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ycJLagm9QD+3uInkdJe1xNVZVIo4GkR+A/t5chtLb08=;
        b=e8kwi4enT4P0N0wRnhiJC/y8mJ+wMVLl1d0PehRrC1yoZFclv8R99nVNXuxAkjou40
         hWOIUEhS6GxJolDXhwJIj26vQ7dRdHKpr+z3vv6iO4hwOJpvhEOpZd8/9fkejeXROS7R
         0zjRUyc3Cob40PZgEYidGgma8KnKnp+XiDhKRKGcAbOwV/cwEToT5IYP5c1sxAX/KQ0Q
         mLa745YzeWzLzzv8YYrwUy5f/npaQwMDw6KN5Y8GKRwSZndC9OGWPQK970VnPuKkknXL
         1Y60OCMF7Uo5BUr7wIuFofAIplPndA3u/VgfLixR2Yoj0KwAxVplfM7HMz8NQ2lHZike
         oO2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753699437; x=1754304237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ycJLagm9QD+3uInkdJe1xNVZVIo4GkR+A/t5chtLb08=;
        b=U9W6h98CJhS6JVaBZnxo3lrVii2YNW7dh1zj5pajTTuRDmk6inHZ+OmPHlXdT6hlnv
         oP4IN3+e6JN6TknLTRy7nKBlOAMxUpAtXAOW2CFWW+oxQLU8/3kQ644ns2nwxifmRV/4
         SQPRFQib2vyAdiiyjeI85x8Gwjqnv5JspuT5sugzpcwLmwtMQg0Ig48Hwd2Tx0ehWlxL
         ihNnouay/3WfUl2nOby62FojMnDtrqYU1mRwIlrHy3Bx5Pv9W14iskZIp+09fEg94kTU
         yfx5//3TaJjhPY6Ip4OFnqXTK48UwP/uIVBoYB4TCZv2DHD7K13098TiGSy4xU/ADEKn
         yufA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753699437; x=1754304237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ycJLagm9QD+3uInkdJe1xNVZVIo4GkR+A/t5chtLb08=;
        b=FHTbtltZy+9cixC1n2PV4KqsGmrbjYNh067bCh+SjpBUUCrUJ029VyNuhaJiW3oMhh
         Gn1l3UBKuLt3Nndm4wPxxveHIEWIG4f/KOy76aR199rgSoPcspB1g8MvijPsmbGr+yjD
         jNr65nRyUMX/P0T0OxPdKm9UTkiX+NfKvu5AmZo/Bop4T6teKTRVNrDbULyqe6aVNWtn
         ltGZfc5uphcAgya0r3xR4JRYrMB8w/MJHP+JOXDwR5/zQ+ifToSm+byL7tGpGLc+s/9K
         1sX+99mbSL2vQ/eMxe7zfcRfpjzsrZdFhCCfqfEmOiRI2A2BOa55c78mschbfUKY45ol
         e7EA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3Qkqt51m9K++E9UvkfdQOJALU4sGQ7H6ULxoywuurXPZDrfWVUBPFQOkfM9nZEWFjLgkO7w==@lfdr.de
X-Gm-Message-State: AOJu0YyJTVWrMj5/C/FJYd4t9MI6nzLzhPqBkbXb3W+HKQ/bPI1cYSSr
	VC9fsAreVkH6cxybsn+h3urt/lm00pU1+K2il63eqzsdY8l5DYhUnQ4y
X-Google-Smtp-Source: AGHT+IFe/c2Vj/xZJpCkDuvqxxDhTBrkIc2ok1CWvxuRfQQMb2qD5XMp0DbNjxJv4WxVDhuU5Ofg0Q==
X-Received: by 2002:a17:903:1111:b0:23d:dd04:28e2 with SMTP id d9443c01a7336-23fb30cd1f9mr164688275ad.35.1753699437088;
        Mon, 28 Jul 2025 03:43:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdjh/Zenuhm5iH4KiPdFNmLHxdZsTo7NfKghhhbteqIdg==
Received: by 2002:a17:90b:3b91:b0:31e:f3b1:2e6f with SMTP id
 98e67ed59e1d1-31ef3b12fb6ls957923a91.2.-pod-prod-05-us; Mon, 28 Jul 2025
 03:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFxAeTZKdwCASwLe8Ijj82bc2mDu9cLCKDZ17+L21DnDm6OUVCK+hVCZPmPAu6cu4SoAHLClDmY8A=@googlegroups.com
X-Received: by 2002:a05:6a21:6001:b0:220:2a64:bce1 with SMTP id adf61e73a8af0-23d70191a04mr20418597637.35.1753699435219;
        Mon, 28 Jul 2025 03:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753699435; cv=none;
        d=google.com; s=arc-20240605;
        b=KLRBvK5T2fBV53AI6v2ztbjZuTh4oeIigsj80uWDRfSeHM9I9bTdK+eH9CfmKbb2CO
         Ee6jTe1xdzFzb/mje0vXqQLEC/Ax5peacGfVnLGDPBUWqHGlK6Mc+KNARR4rq34Hqm+8
         B3v8Orrw+/BHHhloF4i1T3KYhmIvzGzsUJatG6KNYYrlPSOFc8+7TrfZoj58efNj0pJ0
         2HwYVygZmaiRBVvhClnms49You2I9QszeE2W79tXWEpzru46DJlWniAmKlyuwm1hnuww
         ui9ahT4pezlRCWgJeUvBC2VZs1ry/K9QcSUTxk5ACW+7fXctIaXaW3rnAqysz/RqQTCN
         H0Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=iewguF/RLCE9KJBwA51y3Hv7HH9nRTZkotwtc/bcctg=;
        fh=fL38g+xlFzTYuyPQtgbkpLnd8AygfdEzpHGMHCPKNIc=;
        b=g5vY8KS14Asx9Niq1Cfboopsk8HqD3i8SdKTDw2CM2r8VMebJruADll5yFTV9F1Spj
         AVBgs0QEZ7onfj7+AIijtlML7pDWSV33X5ykMac1AoFl5lyaMtphq5xeT9g2lwk+mfP6
         XSlHRgLwHfBHzlLKVc4f8PJpZHjVaGLWXCChDHt341ivuu/Nv3Izrms7YfkZVR6M1e2D
         hNyFoQIpVxwWl1s4t2jNQQhKSo9aYATiPkXh4JtSohm+q2eHe1DS6u+eQi35/HWStdwb
         Afef73dkGCnsGEey2NlZzR2Ril2SqV7g4r4Yjf7u7HwOOL8VVPDkYc264KCEn408ctDL
         VmTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=On5TuiIE;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-767275b465bsi122981b3a.1.2025.07.28.03.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 03:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-23fc5aedaf0so12298275ad.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 03:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUe3Sy4hTRnHD5GSFa23MghrtTZWSmYM1DgJ5qi9ywd6V1SXiRARwwtVccY9vq/ARtobhPxbGzfewc=@googlegroups.com
X-Gm-Gg: ASbGncvXNy09WfdJKh9AsBQz/28rQyjUqoKg49mmzAZgiJ7JaJR/sUATXdhbkIVvsJR
	rP0n3qEwmdT1tdkqw8ah/m2un4PEOtgFifXO5Hf4IYqlAerODFYdYID9vM77LKxZBNFS38Nwf9Y
	3xtU+iWGlFTUetV6+V9tRn3gF+TK14Rm1yHbBAhPhwVXZ8a4WLocD8ew3GDXad0RByp269e7Heh
	HS5UWQpGZR6Ej0dA+2XXGpjsRiNEsYfEsziq1gZjvM48K8VFzDdln7s5RwCOHnnG9tClX7ZoRLX
	mEAeC98dnTRuLTZDiXkv9PQlVC+fYUlvu2a4EaKQXI/HIsmSU/h7myPhMia/zkSNKsvYA/OFG2x
	HJ7tZagnNXl6RsJK4KRokM+h66xKMPzX7OFxl3dk=
X-Received: by 2002:a17:903:2f8a:b0:23f:8d03:c4ac with SMTP id d9443c01a7336-23fb2ff96ecmr167941025ad.2.1753699434632;
        Mon, 28 Jul 2025 03:43:54 -0700 (PDT)
Received: from localhost.localdomain ([49.36.70.111])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2403e6085e6sm10981475ad.129.2025.07.28.03.43.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 03:43:54 -0700 (PDT)
From: Dishank Jogi <jogidishank503@gmail.com>
To: elver@google.com
Cc: dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	rathod.darshan.0896@gmail.com,
	Dishank Jogi <jogidishank503@gmail.com>
Subject: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
Date: Mon, 28 Jul 2025 10:43:27 +0000
Message-ID: <20250728104327.48469-1-jogidishank503@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: jogidishank503@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=On5TuiIE;       spf=pass
 (google.com: domain of jogidishank503@gmail.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
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

---------------------------------------------------------

- Removed unnecessary trailing commas from DEFINE_TSAN_ATOMIC_RMW() macro
  calls within DEFINE_TSAN_ATOMIC_OPS() in kernel/kcsan/core.c

- It passes checkpatch.pl with no errors or warnings and
  introduces no functional changes.

---------------------------------------------------------

Signed-off-by: Dishank Jogi <jogidishank503@gmail.com>
---
 kernel/kcsan/core.c | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8a7baf4e332e..f2ec7fa4a44d 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -1257,12 +1257,12 @@ static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
 #define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
 	DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
 	DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );                                                 \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );                                                 \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );                                                 \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );                                                  \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );                                                 \
-	DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );                                                \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
 	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
 	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
 	DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728104327.48469-1-jogidishank503%40gmail.com.

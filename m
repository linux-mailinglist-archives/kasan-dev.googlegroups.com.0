Return-Path: <kasan-dev+bncBC447XVYUEMRBGXXWGBAMGQEP2XV4UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 247EA339D15
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 09:45:15 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id m71sf8820168lfa.5
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 00:45:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615625114; cv=pass;
        d=google.com; s=arc-20160816;
        b=prpVR8HAgeip2Oy4nuiYZokvliNmQsYytgobUsg4Xe2Bi+N6J9KnRP/K0wib6cu3Q2
         1c9yau5UQ+jL+2Q+BvGJ8MQgFQFVI/H5uceEVMxL6P2xD4gIUQfJebgd+2yM7owiqEZo
         5HUaq8JgVFh2aLNrO0w5CA1ARSG+NXNr1IgrDkEF1LxjpAhQSUHQTgNlJpT4H/c9gcS2
         G5POuKa4JRH6LRlu4uxgFAv4m0ZhBnWAoQqrGNNx43f0X5LXdVJIhZrK++WhOi52/nzu
         RF3iJr1ujXUItYxvKRUJ5sX6yOvfU7VWD3Yd1iOyVRQP/Mt12rW704M4FfIqyNxp+F/f
         P7cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pJW3zJ9u3dtx17e7QdZKh5fn0BJHF9LJXHadiw0H9UM=;
        b=FrO7RHQ296hAeev4Xv2dkLNwsS8EBS35YS1hVKO0QwXX5dQHtq/7oZ/F8JSB2OGlSi
         nuGk6SQxdbAni4VspTXVWsraS+luKce1Swwx+f0sMk43nv5wdqsM6yRm6xh6F4Z2B/Y3
         HN/yFz/5yJlFrPMyFErXKNhC1rgFBoVgVzScmedNNZK7iq00lTbAfC2gbuRi1a/NicEt
         ipAilnT00Olzav2Rtan6mSGwWrEh8Qrt3N7EssgsvNa4MWZGHROvAgBaY9QLiELfR68N
         UGNNpc9+oWPGANPFg4/OFF6dl20askq1xnRz5rAjD0nfpN1FhXioZBeZRwUzNxrWlSSS
         PA+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pJW3zJ9u3dtx17e7QdZKh5fn0BJHF9LJXHadiw0H9UM=;
        b=ZykoKnySQbMAf7UBLBPCSVI6ubC/m4ziqzW1FTI6BvHrov+KvpDWyW6yd4dRH2TKxb
         gBJdLibOu7V9CBzQAyt36nOra8Kfud12YneCYzPqcpRMb34IH4ftAcesEKp7WwIImH3m
         iunhax3VELpMbZxkp/uWhDndRE2ToHQ5C4BCaY8mDfIXihYl11T3LRHEHl5x9EEBxEQo
         aPLjq77Mrzi7MJSuOtg1pk8GjGczKvKIVk39o1KLt82qi05mR/uTgaMJArJXp7T3HGhH
         j/eFPxCqv78bfevEvMUuQHdWayJ2xoYbcirWNa/TXpHHhMb/XKcqrkJww5LjdgqTWcqq
         M5FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pJW3zJ9u3dtx17e7QdZKh5fn0BJHF9LJXHadiw0H9UM=;
        b=cl/+jl9Vp+MaK/lcG/Rp6OY3ZGbI+J3WqXSBLI7E8sye/4KpwuvyVEONBVwwhSxqmV
         /qe8CuzVZd0i3tsmqQ8gfoOD5JSFp62DDItkeFWU1wb0HAnmQijU1kvcZcm9U+WrxjIL
         HxSTZb6h5nqnAiZoT8s1gD0deuxv8vGljkGaGckrZ7JmdJhLt3LOQSdDcZsa0J5kSPhD
         NV9n1uROP1t+y2sRTbjW9i8Sm2+lW5kB354UATDnJCxnFOrucB8sOq/Auz8lt+iwWYy0
         TWPbp6UNFfXYykusJwR6rWRUh7sAqMGnRxqzPkQDj5dVsFsrltBRF7N6a3x7oBuTUGb2
         pSWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533UbZeNgtNFZSowbnVD/CDbcb6iKGsVbLMoI4xqD8d2hKtghWMv
	I4m6i7iz8SPch1k6qtCWbTM=
X-Google-Smtp-Source: ABdhPJwWuUPSDp03bc8YaEmCro/Z25ffx2AhnO7ccIKpnBuVwdonbcRQvUIp0MSbwanVUODub5bePw==
X-Received: by 2002:a19:3850:: with SMTP id d16mr2055998lfj.473.1615625114731;
        Sat, 13 Mar 2021 00:45:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:: with SMTP id b17ls2442592ljf.7.gmail; Sat, 13 Mar
 2021 00:45:13 -0800 (PST)
X-Received: by 2002:a2e:7807:: with SMTP id t7mr4715781ljc.313.1615625113757;
        Sat, 13 Mar 2021 00:45:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615625113; cv=none;
        d=google.com; s=arc-20160816;
        b=cQrP+bitdl0Mvp0EUzehUD7qa6TrfgHEI4scZ/sF6BslZtzLguGcLVAqpRrsn9FRm1
         FD4mOYc0CMCJrjQ4IwRrd3KbcrOAviMVBjHg0e+YgGGGeVwL9k582kBf1JUV7vjBRhuG
         87qXiC6BlIifCLn//cb1cnkr4UdF758z6BOCcPofRAZlsXG6eQADaLIwtf3caogSnLHQ
         Z7oJkUyoDGYNsnV872+0qgbmaNd/NMWWdFCsvZ0S9/bOfHFt2I129Cws3Ar1eAqhfbid
         zAjlS0WsHpiS9KKJcGUbu6LqIsdc4jGexYkfidwCAdWcn+jRfIWO1uJx9sK6MnJqaxmB
         N+Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=lr61uGNRcIHFtDXirFx9Psk102hpJFKn5JayyPk7WK4=;
        b=uI/KWI4x4vP2JE+gagynEUoJQ9gdLBHUSsTqEJqpGMSRF4vuwEhh/W+05P3CmCQ4NN
         u6Of56jGVSgstvzujVDTYcx2NK+S2BNByEC44cGxkUSS+PaBVh6mJiKSP/q4GvARMWW3
         JM5uZU7t2dLjSbDobAhiHDQbRh0V5BFmc0N504jbFtm+BAUF0rWCDMNq+h6Uon8/gQhC
         f1VwosYdNzsjtarA+pvrZuEev37l/njdQTMgDHw4zphUUb13lymdLqpfiezh40BHneeZ
         Yw+tPkarvRomVdvJgDF3TfaNT+xf9qQnzMSPovHmaFhRcGeaG4NSmyTVP2duxHpkv7KJ
         IM+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay13.mail.gandi.net (relay13.mail.gandi.net. [217.70.178.233])
        by gmr-mx.google.com with ESMTPS id o10si388703lfg.12.2021.03.13.00.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 00:45:13 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.233;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay13.mail.gandi.net (Postfix) with ESMTPSA id 736AF80003;
	Sat, 13 Mar 2021 08:45:10 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Nylon Chen <nylon7@andestech.com>,
	Nick Hu <nickhu@andestech.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v3 0/2] Improve KASAN_VMALLOC support
Date: Sat, 13 Mar 2021 03:45:03 -0500
Message-Id: <20210313084505.16132-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.233 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This patchset improves KASAN vmalloc implementation by fixing an
oversight where kernel page table was not flushed in patch 1 and by
reworking the kernel page table PGD level population in patch 2.

Changes in v3:
- Split into 2 patches
- Add reviewed-by

Changes in v2:
- Quiet kernel test robot warnings about missing prototypes by declaring
  the introduced functions as static.

Alexandre Ghiti (2):
  riscv: Ensure page table writes are flushed when initializing KASAN
    vmalloc
  riscv: Cleanup KASAN_VMALLOC support

 arch/riscv/mm/kasan_init.c | 61 +++++++++++++-------------------------
 1 file changed, 20 insertions(+), 41 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313084505.16132-1-alex%40ghiti.fr.

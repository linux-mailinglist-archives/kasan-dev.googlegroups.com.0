Return-Path: <kasan-dev+bncBDEKVJM7XAHRBXWR4LUQKGQE6GTLC6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB47736EE
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 20:52:14 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id f19sf30727337edv.16
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 11:52:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563994334; cv=pass;
        d=google.com; s=arc-20160816;
        b=mFw4KxSFKARdfOsydxTD4FYx71SMpMQi7ojE/mOlFA6sXA3cG15kkRHdvnGiKcDRtD
         FwYo5+48kVM2M704B8bYf3tv5bzVtRpdb4xeHQ0cPQZWbyBCqVYAbLyi7tT67WXeFNw6
         k67oo0Xz2uql0JaljPxbaozEEuWOyk9/j6uxqqhUbgmT9AzWE/rvD1pKKyERyK03e2Zq
         Byx6KxjSqbDg5AAyExxGutDCZrptRAMTL1fOLbe9JW6QwngUpALAJA+YqPRLCIMtul4C
         m9kgsS+XclBS5uqyWKlMhIVdw6EAEXa3NA3c51gWJ3S7B3O6WSJHa+LUcBXZ2nHSCcMe
         JwBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/sdihi65kk7CbCZ4wya8I9oUooNTjCO5GDOR2fLuqCo=;
        b=pAqGOqiL9t7pg2OwN924UArf9LM5cViUe8XYRkFteaXZciHQj+4Uq9iHzpp8FMIPvG
         WBsBH5ktppXWFE3Nxh1FiJFYtyK2oxkHXzWjAc2areO64psGc1qUcIZyojZ1ratZ+LEM
         gwtEPZrMTsA3iH/I7mF7wwtn+SW2UVGsgobsf6ZT3ytYh2eEX29vWkSVSqZEeUnivMw6
         fK7Bbe+BjFnbur547f2lKEJrzlC5eyLjAH3B1P0UII8iMhYqR7Eal76SlyUb1r6j33b8
         ZM94lbCFURKkf63+Kg+4DUl71bnhDD+RAceVspIQcSZ8TugbDMW+QSpQi7e1oJKfQg6w
         Vy2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sdihi65kk7CbCZ4wya8I9oUooNTjCO5GDOR2fLuqCo=;
        b=Hlyn2tHC0XpDFVfFfktij17adyliE/coFezXgle9YK97kyGZZTqNkaogHqVxH9/tcP
         e/YvfTLao9Nq9DQUmfLrqfs68Rc5be1e6M6roygW/wWMgL3027U6HPozpQZK8c5Zuyut
         UZL31PWHUvy2PAgWgCfMZlY3tz40zDkjEKXPOebSC3A2tX5rrLsq5HXf6ClDHX9MlNzC
         GVM8c7YeSCTM0B7MRWeU7OG+HvlTwnVNC683VU+thiMeondzGvHy+xk8KafzjYZRIRjg
         mkfho95532LVsdFYCv1Jwha8VwPYPT9OKln5SZgr7J+l/ZHYcZl1u3Cj5diMSPU4xtAO
         2Nmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/sdihi65kk7CbCZ4wya8I9oUooNTjCO5GDOR2fLuqCo=;
        b=Wd2IJDbrnmNKFqetMQ2/HH3DAsIdhhheWhQyz6zsbmLZ98oucmgFs0W+VhTXLzrfT5
         BbpP9PVy/XpglrMB4tDMjgbfphickIUBaKjeFcwyjHgZonOXTHVjkpZ4Oj86FtwJ97ra
         4HqBWVCB6uiT4FOvvhKKGbDJRYgiWLHeksWXG98PW9ZoMEm/Cxw3eCp+tHyQIq2M2jBK
         jMQ0ju6zCqfCwjo5qoZLhzBT4PYWAq0aDtJ3PmOiUwrLN/pLveS2d88dE5+ATEegZ3Kf
         s171bVAZ86r56QyUeC//ZNOgb/BGATy/M5RdFAsXMZMEmcCaCEGhctzFgh+2C1yBgAEt
         Rgig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVV3RBwq7Cw2VCmgo12Zem7PTkTP+F2mootz5Cxr69gbfMYEcCU
	Mcg6HuKlFudMUP0fWcX8heI=
X-Google-Smtp-Source: APXvYqzQz9gkXzqTqaSdUTSIGr4g8VrRhIiHFAgDapR6oxY3iUVjVF/5WnCq2tKGqNRhNpCzXm9/dA==
X-Received: by 2002:a50:b6c7:: with SMTP id f7mr71560418ede.275.1563994334192;
        Wed, 24 Jul 2019 11:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7345:: with SMTP id h5ls10003325ejl.16.gmail; Wed,
 24 Jul 2019 11:52:13 -0700 (PDT)
X-Received: by 2002:a17:906:e2c2:: with SMTP id gr2mr64462533ejb.284.1563994333790;
        Wed, 24 Jul 2019 11:52:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563994333; cv=none;
        d=google.com; s=arc-20160816;
        b=SuPrwbepO82xKwJloMj/iVUku16shcguj6dEdy+jLyi7pHaNVcdADS2BSpxsjKuEsY
         UKMMeqb1NxzY6IEg2elZBf1d1gM0Pr3le3JzhFfA32nnlzagZUE6Iva7/cR3v9Z/rGHB
         2+ojC6ZMSqSPvAbfi67zt5OibaJKT7F7TdNfc9fjaDmq6+FCnHAy4bhvNyM/luf9JeC9
         VHSfqDvSxdqlzttGIbhUO3J3qNQ5z0QIl1TdGsJHpuXcbdQ5cAYKcN3+WrntDlu6H7S+
         rZjIRtCykKhFoCLaRCCfPcFvjDme16E8STSekMqT8U9vLE7NYr9tUgyXCRb0M2lyvcTQ
         lVnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=AKqHgZgnAQlPpPhxatvb26g7h6hNtf8LoxfF8r523R0=;
        b=OPR3zHC49NT71EDnMn2pf2t5XrL6nYn/2uJYJOku227Cddij0HGmW29zwA88kObDCe
         om7ov+lAHwTz1gSpix1ilpLtv1Y6gQLUf1Vh5LbPJ5psSYbs1crE9h8J9Qs3uZzLTycJ
         bvjJnl0e0b4h8r+ius8h0DXqpqThsHjW1ePRvNZoVvEhA/kuX1JLMsqrpan2alfE9vLW
         itqLvKK5eK3w/XMURCNEMzfv/q7nwjJwtBNCIit+FvWslneKg/VF+/sjGO+auAG8YKR3
         ygpoHyMNiD9ogY30Q6kDUmGM1uVae3sVWkACc8Py+5QJuWL8DipucQiILLXgJ282fQ1W
         mtvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.73])
        by gmr-mx.google.com with ESMTPS id k51si2716815edd.0.2019.07.24.11.52.13
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 11:52:13 -0700 (PDT)
Received-SPF: neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.73;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue109 [212.227.15.145]) with ESMTPA (Nemesis) id
 1N4z2Y-1iZMDt3sXc-010r7i; Wed, 24 Jul 2019 20:52:10 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>
Cc: kasan-dev@googlegroups.com,
	=?UTF-8?q?Stephan=20M=C3=BCller?= <smueller@chronox.de>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Eric Biggers <ebiggers@google.com>,
	Vitaly Chikunov <vt@altlinux.org>,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] crypto: jitterentropy: build without sanitizer
Date: Wed, 24 Jul 2019 20:51:55 +0200
Message-Id: <20190724185207.4023459-1-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:2QZYaO519OJxYJsrSQIe/UzdE5AmrOwOkLjXT+CjRW8Dx1lg2Dy
 XV/NNUYdwM3vTfiFDwSD0F4fyLZmjd6jW+NV7AJpT+rAQ/sdhR4X1aKa+ZOReDYN8zdd2t/
 Ox2vDe5VdQRl1nHDLe+c38FlsGf4wYILrfhx66IL+1gIA7RT6JgkxFaiP7CwnYG/V2V5wfs
 fgvfUk/OsccuBGMrqhh/g==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:ZAZZZe+kadI=:rnEzG0t1GmceK0/lAFvYax
 Ex+XREoW3yNiDExdl9vfsXIjNkyvMdsCAn1FwWI7ElysOPL8L+Dx/4F9Ep3vW5LunKGgsyQQI
 yv00OJ6maRvK3LcMCmWUJIbWFUE8sskArxmHTlPGR7InwTiBMgZUHuRbnS8StCea9EgLWeL3r
 jy83jMfnVRvdKH7Jth/itcIV/WUhwQe2LDxJ3VuCreyugM/3bTF8MpMl0zcCN//tEyD0w8+xW
 Du4tJ4rFmi+sUNpeyvSGqSVK7gAn9NhOI3H/BVBkMnEhU9bB9J/ZVYxXIcKq+BMhlwE3Ra6k6
 f2Se4X678XzaJuT1ov055sLk0MnEFvD/inMo7rXZ9fDcJ7b1kQ0JLNX4NOapppsAkAxejmo7c
 9ke/cBlq2BAcDMkWdVfjbZzd+BPR3ORrzjnJu5WLtnJeB1u7q+rieUaCeJY36DgH0hqCNRysh
 69709d1BQlv3lfq+fXkple66lk7o126EGCSeuuhYxWrxN5PIazkrjeftVuZaUeS6pcCl7sSHd
 EdwAJHRSdgxtUWv6p92aNNsRhFJa0e8Hv43wSqKQrvPVq8xhELBOl5LvAKOcGQ/UKH+h5PJCu
 QYuanTrvsit0f4rxUE0kdYpNix8gPchck9Q8ZXw4Z2wXB/EF0wnfg27WTonImdt4nl/B/yR9b
 X4XrmEhr1kEVinpZHGB0gB/jOW6ftgC8qNgRmY8Ff6uL3Hs1ONFB6V1Ycbez4KvGP6w3j8rzz
 yhQXpQFLY+j8/q6KKgqbwrTRwUd6KVxz+18WNQ==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.73 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

Recent clang-9 snapshots double the kernel stack usage when building
this file with -O0 -fsanitize=kernel-hwaddress, compared to clang-8
and older snapshots, this changed between commits svn364966 and
svn366056:

crypto/jitterentropy.c:516:5: error: stack frame size of 2640 bytes in function 'jent_entropy_init' [-Werror,-Wframe-larger-than=]
int jent_entropy_init(void)
    ^
crypto/jitterentropy.c:185:14: error: stack frame size of 2224 bytes in function 'jent_lfsr_time' [-Werror,-Wframe-larger-than=]
static __u64 jent_lfsr_time(struct rand_data *ec, __u64 time, __u64 loop_cnt)
             ^

I prepared a reduced test case in case any clang developers want to
take a closer look, but from looking at the earlier output it seems
that even with clang-8, something was very wrong here.

Turn off any KASAN and UBSAN sanitizing for this file, as that likely
clashes with -O0 anyway.  Turning off just KASAN avoids the warning
already, but I suspect both of these have undesired side-effects
for jitterentropy.

Link: https://godbolt.org/z/fDcwZ5
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 crypto/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/crypto/Makefile b/crypto/Makefile
index 9479e1a45d8c..176b2623dd68 100644
--- a/crypto/Makefile
+++ b/crypto/Makefile
@@ -136,6 +136,8 @@ obj-$(CONFIG_CRYPTO_ANSI_CPRNG) += ansi_cprng.o
 obj-$(CONFIG_CRYPTO_DRBG) += drbg.o
 obj-$(CONFIG_CRYPTO_JITTERENTROPY) += jitterentropy_rng.o
 CFLAGS_jitterentropy.o = -O0
+KASAN_SANITIZE_jitterentropy.o = n
+UBSAN_SANITIZE_jitterentropy.o = n
 jitterentropy_rng-y := jitterentropy.o jitterentropy-kcapi.o
 obj-$(CONFIG_CRYPTO_TEST) += tcrypt.o
 obj-$(CONFIG_CRYPTO_GHASH) += ghash-generic.o
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190724185207.4023459-1-arnd%40arndb.de.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSFRST6QKGQELYNET2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 27A6D2A92D2
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 10:35:05 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id j1sf301069lfg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 01:35:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604655304; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bmy9896qwdiODomojNxapDvbJ7fX7h0W1DkIKw5k+s7EHcf3Pnh7DlM61D6KZsIdxn
         YGVS9LEbxeJWnyUcNyM91vUs56I1jDSH0Bfi926l2Ogji2sw6PrLtAAryChgVaZSByQ3
         7L8Q0qP25ON5X20S/mvY0wRcyqk9YLYTbRizWNSQ8b7mkckrP4DLdqUCJREIOgjHHrlJ
         pTiOKXUQHku0JLMUcX84EJOYLQIrITFpySh/Ayj1loBxg0rviw/gjsVvKnmjFttXnc19
         N1dRyeEOumR4Z6RPk89ssMr72GaPP3rjwdnLMSdj9WG3ipkF5ZovMFyT9y4X9258L9E5
         RXMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cklCJVmBKSHQF3rhTcXhdmmbmU+/EtLdxdUdjZygCpc=;
        b=jYE3PjeqyxJhdm+zRazmPdRsb/JzN6GRf4p/E6Tmbp5cUdEKhwqhcWe+7mBwLKi/ug
         3hvg2zpZyZCoGVtkdf5iWT7uEYpPQ1FubmaS7071hJATrzY7j1Ql3OJH7RulshMh5t4x
         QJFEQH87J5zkj/VPvsIjZpuzEuSRXGV0gYyrRIUrznnMEt3cDPyiUQHSHPUGWNU1IEka
         jsc1/9dunw2AjzkntZgabDw6YZZPwKPhdSixnsQHYTF2RX62T5ZYi8koJTZWVUzPLqix
         5vtUc/rPqRHqyAQKcXMdHPZiKeWdcf3dIrzB5fuJ309BID6xGlxxMpdktu2PVVkIYiO/
         EMEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aCr5QBrq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cklCJVmBKSHQF3rhTcXhdmmbmU+/EtLdxdUdjZygCpc=;
        b=lBCB4pclz9Sko9Evm7S9I5GJLcu9X2WW6wboLndekLaRDSWmlTpLHOLRT9OFrj7f3j
         BPvFve2WoZ+c1nH+wxJKw9FLJCNF1z3nGhmK72y8/lr0lC7lBIbtWoh3uitTxfUa53yH
         j9lTVPYtHVwVOw6z/b9I3lpwj4hOvKULW00Ucyi7HH0AZ0vjtQSJ146qtZ3dIH6imB74
         8UzYW0g5LkPsPioKahLxpxlbe4m24VOOYqMpyIhH6mXDQvAn+rz3KW9uAwdSOqHTZ9C7
         yRaJQGgQTMPeLRnn2URoGn0KlFd1J5XEAHGXdXt6gplV1VyJfefLPlFioNCkQL9FNzgR
         8QRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cklCJVmBKSHQF3rhTcXhdmmbmU+/EtLdxdUdjZygCpc=;
        b=Bl/pu6HMJPL5tFKUKqXaOlx7oXzc7tOBBunT0mJwGbz0P+hlPqS5T90liv1w214C4P
         AbNpsVGiPephWZZ+iewtD6wdE4bdEA8yinykpoLKOn3k0A8m6UWRLM1H6wqbNvae+tH/
         6nF1VGZGecx8/YYdE9K03kqrKc+NZuakgSDsBgDyC5SU5ysR4mCYG8ungU7PKUd6YP1t
         +lLY5vr14eTuEVkyNuL+AscN72CBM8Lavk9rkLnYCz91igjiqWZf9dx1n0mnOmCzCQ61
         oUu3mlMmG/cmcyxsv4usd/UjBdvo1uWPf+5/jkPKLpmXEeaERSnqlS9V42W5P4fJ5f6/
         Kfpw==
X-Gm-Message-State: AOAM533xJ2Ohv2vKyakhypsStMixkMUYhN6ZdM7cAiaEoC7Zkz1aUQYS
	y7lH9GM9hf9xvHjPOS2MOCg=
X-Google-Smtp-Source: ABdhPJxNLcYAUtbBNZkD1unjZOtNj9y/rWBzGdRGBTFi8Y2N5dwRF5qjX11tJ/twiWERKLrubkRR8g==
X-Received: by 2002:a2e:8143:: with SMTP id t3mr449046ljg.29.1604655304705;
        Fri, 06 Nov 2020 01:35:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls557365lfd.3.gmail; Fri, 06 Nov
 2020 01:35:03 -0800 (PST)
X-Received: by 2002:a05:6512:204:: with SMTP id a4mr501724lfo.310.1604655303523;
        Fri, 06 Nov 2020 01:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604655303; cv=none;
        d=google.com; s=arc-20160816;
        b=VZrfTibNaqPI+ASctYqR9AF+7HHWu2l69WwYECdDZ5KpkVTpH5RvEXKxVDvjJnbxwz
         ol5FM0c0GLTEz+9/GEIm7oGb6tftUgrIGNYx60X9YIdSdFcDS5lstYnUf1zJdtH3uPJ1
         RkL2l48EqAcCeOCgqS3jwQOUAhtDp6MqWOz4p9NcRsMV6dh6yTTLo9XXPt4lB0KDJWbC
         A5Cq/xN9qUYIlyT3jFFLbMwEthJhsdIYdGymo/j52HHhzttqcBn7FSevSevRIFJD4xCK
         W1BGXFa0Kg1UNLOvSWnLVuxORjKLFtHBPsOYW+G7fO8w+0syjlVDO/LT+2rW9VSA7dfZ
         lEyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Xbe1zafvLzFk0NBuZKfqZ6Cyl3GP1S5ka0zb2rUwC3Y=;
        b=qb4ua4XlDqLgFMemjjd9EjqV1DztEatWl2EVxbtHNY1UNUqF0bqJ6VdAS2s+UCy8s+
         tuUQh1T3kw6lPaP8lRkzGnmgPN1QcOmnvrEPYN8xi0UEg8gTSiLCVj4apEHqHl+gjCkP
         I/K/DkPE+qDL/DCK7/XAMZly4APxffQdfLC/Jpr/ZMK4bYJqF3gFFBlZ8a53WoXOymVE
         0pk6/DVVzW+rRWEgkye/AF1QlMKobp7RGZsetot9L34QA3ZLZz396oa64V9Z74H6tUuQ
         7CHR1UcLq2KJbC2aE0RS/h6Mv+0iqUYvXxA+PZ2AGXwypzmpY2CX6S4jf6gCLbUrncA5
         6q5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aCr5QBrq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l28si23964lfp.11.2020.11.06.01.35.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 01:35:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id 23so547511wmg.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 01:35:03 -0800 (PST)
X-Received: by 2002:a7b:c5c6:: with SMTP id n6mr1210948wmk.131.1604655302864;
        Fri, 06 Nov 2020 01:35:02 -0800 (PST)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id y185sm1395980wmb.29.2020.11.06.01.35.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 01:35:01 -0800 (PST)
Date: Fri, 6 Nov 2020 10:34:56 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: paulmck@kernel.org, boqun.feng@gmail.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, cai@lca.pw
Subject: [PATCH v2] kcsan: Fix encoding masks and regain address bit
Message-ID: <20201106093456.GB2851373@elver.google.com>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
 <20201105220324.15808-3-paulmck@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201105220324.15808-3-paulmck@kernel.org>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aCr5QBrq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The watchpoint encoding masks for size and address were off-by-one bit
each, with the size mask using 1 unnecessary bit and the address mask
missing 1 bit. However, due to the way the size is shifted into the
encoded watchpoint, we were effectively wasting and never using the
extra bit.

For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
bit, 14 bits for the size bits, and then 49 bits left for the address.
Prior to this fix we would end up with this usage:

	[ write<1> | size<14> | wasted<1> | address<48> ]

Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
size and address respectively. The added static_assert()s verify that
the masks are as expected. With the fixed version, we get the expected
usage:

	[ write<1> | size<14> |             address<49> ]

Functionally no change is expected, since that extra address bit is
insignificant for enabled architectures.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use WATCHPOINT_ADDR_BITS to avoid duplicating "BITS_PER_LONG-1 -
  WATCHPOINT_SIZE_BITS" per Boqun's suggestion.
---
 kernel/kcsan/encoding.h | 14 ++++++--------
 1 file changed, 6 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 4f73db6d1407..7ee405524904 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -37,14 +37,12 @@
  */
 #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
 
-/*
- * Masks to set/retrieve the encoded data.
- */
-#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
-#define WATCHPOINT_SIZE_MASK                                                   \
-	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
-#define WATCHPOINT_ADDR_MASK                                                   \
-	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
+/* Bitmasks for the encoded watchpoint access information. */
+#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
+#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)
+#define WATCHPOINT_ADDR_MASK	GENMASK(WATCHPOINT_ADDR_BITS-1, 0)
+static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
+static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106093456.GB2851373%40elver.google.com.

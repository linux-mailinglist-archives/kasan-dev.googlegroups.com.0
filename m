Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCGDTH3AKGQEQQ4IUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 086EF1DCBB6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:01 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id r18sf4892750ybg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059400; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWfjFBRzmEfv45JeHyoGBzFOR1vGOFPlfw+LZNFRy/BZOeYMZkrYaQi38VR7Fpk2k5
         4jQOojqTfJrX9tTSRg110TZpNKUW9XOF/pYRtOUnzjWHqPUbttkKfy/BMwPm1d51fZL+
         xfKJXm7RaXiPL62hedt5jtFEn1ZudEuRNqgUCsZQXyJM9KnlKnf+0vY0fyvu6wYRYYGp
         FgMFGdIM06uTFpP6XKaCBCtzOsaSEA99JaX0hBT4gA94oT5Ujb3E6qB3p/WFwmGtdONf
         a5kaw8XIzoNcoK959aGsSwb3Mj8Bp5zg4yh5ICbSVDgibj7qIyGej7IWB8Bu4fsHoGIM
         3v2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CG1fW878XiW1wyp2BZeCoWDvGjfXGHxcYUsBXTHUviM=;
        b=P/QoKk15Nukgsyrug1BF15bC/PchQ9cVgMZf1Bm/eSLVpGF4BLFJkqnf231pySH9xo
         lViWApEHeabJgJRo6wb8vMQAgTLlcYcsZML+qvGKdOPvVjn0iAl51L2Fa32e1E2mXo5A
         eAwrP1wNQsosW9rUdp87O0o9+VTrufcLXFyLout+s7Ufqadkvb2/4GhYJCHUSymSS3HV
         XeUpP4YDSNcAkc+4MI7lqKnTCUu3qrJy2zCNIhsQz5MX6fp1BOFnML7plhfl8QmP+eZn
         AEjD82scgKPCSuCnPSBp2bvG8w93rQCqCJlah22BpnoyN7TL3mLC2vukOVvt2yXoH2Jt
         nM5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YM6yTs41;
       spf=pass (google.com: domain of 3h2hgxgukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h2HGXgUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CG1fW878XiW1wyp2BZeCoWDvGjfXGHxcYUsBXTHUviM=;
        b=IB2CBB3ZxvHcWji87aJs9zBSGU3kN7QngM6Y+tYe5w+riBFrU7LOcew1XmodKB1IiR
         poq6sutALMXXy1jdE3dfVRAsv6PhlXH0/+uC7RxZyS8pE0N5/TE1J/EPmh2PDambLpFt
         50UuDgvrEHi30Mrmn8dyVU+RqW4pNI1PAMkL7BP6SQg8UiwruCgPMz74e0w6R+C+LAFF
         fT9AaK+Wu08dziRVtBmAUA+toK6GnDhj6Be4ipOxpxKR04Ify2OzDhX4eYlRCdTVWHCj
         tgB/LjmB64o/f3EcdayysE+Eqk/EzXii2+Dy3odHdmYRRK+7GbHkTd//r05jWC/NnKie
         +RDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CG1fW878XiW1wyp2BZeCoWDvGjfXGHxcYUsBXTHUviM=;
        b=shPVx+Hb0FA33OdSAGnYLzOpkXWkZ09s75ChSy8jBIDhO0A3T8ccvIVLeya/YfFARO
         oyXa3Cm3/SATIZuRlSem4Ve8TzjVr2YdfwA/zB9qROIz9HmMnXAsaPrDxxqmLODt6T8O
         dXPg45oNuPSkxXAjEW9izrbb2ZOeAsDnLCp9syy1esU5A4EGBJ/tST89Y+42PW4dyQcp
         lqi6JqlML6t8x05rbe3ZbqgYp3pzM69qp4rmm5WQ97gtFIJnHK7oEEeQjO9g8RpRVy/J
         miN2MbJZCg+2hj5y9W8MYJheidDV8greGT7AUQr82ielS48tf1GS1KETCgSon6etQ0QB
         63sQ==
X-Gm-Message-State: AOAM531auGbm2Abz7oh6+J8+Txwcui2Kxj9a1ARJnOJDY5vHMJwbzNUu
	3lQP3bWPxvD4Pvbd2uDn+VU=
X-Google-Smtp-Source: ABdhPJyyJXeF9ccsVFhRNVXg/SyLHzxOvrKo4AvxxSzffLKlOIEKXpV4IPQfNRmkhXbIVGHYMCNoyQ==
X-Received: by 2002:a25:2d02:: with SMTP id t2mr14342284ybt.163.1590059400099;
        Thu, 21 May 2020 04:10:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:75d6:: with SMTP id q205ls172989ybc.4.gmail; Thu, 21 May
 2020 04:09:59 -0700 (PDT)
X-Received: by 2002:a25:bb92:: with SMTP id y18mr15068199ybg.496.1590059399826;
        Thu, 21 May 2020 04:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059399; cv=none;
        d=google.com; s=arc-20160816;
        b=Ooc6LcEWVMASsGF8QBtfFywffoTMJa7kzueKAWsvO5QCQ9zbdAYn9zAwxqcB+1zWKK
         GMq0qtsI9oZzyZLZ13o5Om92T2fGtflrSBQhqGOUA8pm/uUuRXBpzu1C23xyORz89De3
         i8mfWNhaS+Fkr45Usddc+gviCqbvZ5/wOND4WPua/U01RgrfWaghc/YzF2I0MIcRceg1
         plbm3WZW8tu9qauyztdEm2qUHgadog/HuFDNnhX9N6Gf3ujQFylkOqF3vgR3xRofmT+X
         D+1ZMwAAPH+iS8FoXlE2WvIHwML7QS93oqsYuz9LqMhuEEWRQeQ1G4jic/n46YQw8pTl
         HkvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=maeQQXffB2UguUhgEnnewdiQJy0yPCx7FVOuZ5TWJ5k=;
        b=VA0Ti8FAwjhk5kah+Jw2ziulEOMrD14jRXaa27zwytQ2xUa9dOuT4VyRjaE+X6pzw/
         jHcWHNaN4P+TX8Uje417th/YIqgV0vvOyShHDTouybQTSPWxzTeK9LzfYkxjxVzX/CMO
         gkjg637CXoxrkWxyfTsDRXadCnIKOCEDq/xahg3V14CZnYuRX3zlcAt/WIht9NQBufPp
         L34zcKSTOBG+DwEiYtrEUg9itOIimaYRZKBduw1R+ald2MOd2Q+d4NTEbnhSoIu9Hq9h
         XUrB5FXrDmVYBSHDOOk7TTekgHATyPPbyJWQvvCmJyPULdlXxh0KWoJyymrlA96PGfkY
         lt8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YM6yTs41;
       spf=pass (google.com: domain of 3h2hgxgukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h2HGXgUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m9si344938ybc.3.2020.05.21.04.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h2hgxgukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 137so4907724ybf.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:09:59 -0700 (PDT)
X-Received: by 2002:a25:9010:: with SMTP id s16mr1833681ybl.2.1590059399495;
 Thu, 21 May 2020 04:09:59 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:47 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-5-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 04/11] kcsan: Pass option tsan-instrument-read-before-write
 to Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YM6yTs41;       spf=pass
 (google.com: domain of 3h2hgxgukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h2HGXgUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Clang (unlike GCC) removes reads before writes with matching addresses
in the same basic block. This is an optimization for TSAN, since writes
will always cause conflict if the preceding read would have.

However, for KCSAN we cannot rely on this option, because we apply
several special rules to writes, in particular when the
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC option is selected. To avoid missing
potential data races, pass the -tsan-instrument-read-before-write option
to Clang if it is available [1].

[1] https://github.com/llvm/llvm-project/commit/151ed6aa38a3ec6c01973b35f684586b6e1c0f7e

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 75d2942b9437..bd4da1af5953 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,7 @@ endif
 # of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
 	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-5-elver%40google.com.

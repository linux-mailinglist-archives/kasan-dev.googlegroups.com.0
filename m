Return-Path: <kasan-dev+bncBAABBGOIVSOAMGQECUPLZSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 85BBB6415C0
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Dec 2022 11:25:30 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id m62-20020a25d441000000b006f1ccc0feffsf7651202ybf.9
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Dec 2022 02:25:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670063129; cv=pass;
        d=google.com; s=arc-20160816;
        b=fJ8UCmOGs8qdcciBEyxaHIj/pAJ0LjaiqrJWWRUctNjqT0laK3SZHi/s0WL7uFIP4L
         yG2tL+Jt7nfP8IXnlwNez05DVKajHUMJ8887WLOWJe02UIM0/rzRpMVY5uUDwjzZzb5/
         gFN2kPXQn2EYhQTTsaQ2SFz8ZXvy0emqnbXM3jduZXco1BSYSqkpbe3XfrHenOr+45FH
         X2unysZw6Hdj4FH7E9mN1RbSnnFkM+qnuEe+dXH24SiN8wLXybpV+pMfRE8ZKW7WQgUh
         hYdSyOdjqNt1mXvRGzOxMcTxuigdSUkjDeeA+g9hFQB7W/se/IlByMqpc3LNAJy//CG2
         /9iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:subject:cc:to
         :from:message-id:sender:dkim-signature;
        bh=8C5/ntG9HyHZW9jkdlImrhwZreJxczIBKJrv+nn4Wrg=;
        b=Bkp79980joOQh12/kUVtxmdrICQj+DpLBC8JTZ8uzuCFMzzEKKOETBaCz/fuy1EZYK
         9C4yyefq9PLL96Z0XT7HyM+FgzrcTvV5NWpZOQNry6w7WJ/8dEMLH14oekZgnP7hyatb
         oVWc78Srucb9a210bx813s8o3N73JkbV6Dk47BT8C0lK5Ns/erk1psZk6BRnu3+cnG9q
         gsRmZN01BW0VCHg1SY4gFjYa9SMfFgmOhjnjQNVkVEK6NJfV+fnSKwnVF5ARlmlSk6RY
         aA7HiHOgk3vCIAZi40knHvCLHnHFQC22pJD6eTKp3MqCl1/vdrKCRlK3+AWriPQBdaoz
         j09A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=T8ZazCWM;
       spf=pass (google.com: domain of rtoax@foxmail.com designates 203.205.221.191 as permitted sender) smtp.mailfrom=rtoax@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:subject:cc:to:from:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8C5/ntG9HyHZW9jkdlImrhwZreJxczIBKJrv+nn4Wrg=;
        b=pNLrP7FKIn7LCvPaXcmR+dlA/lin/wn+TJS21bGDJEvQTk6mveZGhlXmNsOxzzyj7e
         curQnL/n2QeMpjrVoo7jGZeVr3H8Nw1J5iz2oOryN8GAq7x4lkMVu6bQaZj2iZJOdtYk
         7f4Fiwt+ebjMvFb7wN55cbjQbfNJGURhgQgxFm46tEBKXCLI5hbybp/sXCHrJ5LijHra
         LI1U6QYZ9ylQ1+xow0L6xgTSMcbmYJv3ZxySN2dNGZFMaXGJJ+grvowiVWw3vU/sXQUU
         yQfHHxER4JJfdxIRoNtiSpOXhx8XYD96Tqdvn+ZjriySWGEDtpd+/ke5UWBtLx0obf/p
         +SIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:subject:cc:to:from:message-id:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=8C5/ntG9HyHZW9jkdlImrhwZreJxczIBKJrv+nn4Wrg=;
        b=UCKbyRqmZ4RNT2BXpJyxca05mRrc+Do/j0Fn4xWqQ9GIHPn8vazSMD5BP427s6qnYs
         F1wydIuleoLekSr6JhPbmaoe3IPSU5VyWcPCDiaKoEFB4Z0b51n0lVesM+ZcLNqHLE7s
         7iOPu4kpICkZ0aSRQlJ96CRDp1f7IV5ewW5LY+zQLZ7CW0h5E7BTuUE81ai6s/mcV195
         dS0AaPS0xszPdhPeH42XpOwrl5NMUDqcx4FtXE9o+PqKG15Dsgej0iAt4zsMSWO8jwF7
         BxJ7HjaiTioE3zhYkybxI4YgUw+hHjQzVcFoGkxWLNlZpvgk5tstxN1PhiFfWEn8rzvU
         Q5kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plN0Gny5dH6J+w3x42wfGsWENs5khqsqdl5LiZWmsMBh8SXVHNu
	Em6asjKSNNlXPhav8dk9JsU=
X-Google-Smtp-Source: AA0mqf6tdOaRKzW1wO+WDbZqWYoGLsLVpA+A/uJkSD4L1sQXM3eYzWq7NuVmQdUEnBy5FdYUXwdgTg==
X-Received: by 2002:a0d:e6c4:0:b0:3bc:7270:cb70 with SMTP id p187-20020a0de6c4000000b003bc7270cb70mr36792106ywe.83.1670063129251;
        Sat, 03 Dec 2022 02:25:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc52:0:b0:6f0:36f1:bf78 with SMTP id y79-20020a25dc52000000b006f036f1bf78ls565745ybe.6.-pod-prod-gmail;
 Sat, 03 Dec 2022 02:25:28 -0800 (PST)
X-Received: by 2002:a25:d906:0:b0:6f9:bd14:f0b4 with SMTP id q6-20020a25d906000000b006f9bd14f0b4mr17711320ybg.408.1670063128754;
        Sat, 03 Dec 2022 02:25:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670063128; cv=none;
        d=google.com; s=arc-20160816;
        b=sB8ZdnWXbgDWiylTdZmzZYnagQT6cqySNSgTboPbGTp2dvpbG5+T3y7EEIgjU1BbvQ
         hzXUep/FtCbHzKgzLiylXaO2YzaEXIOdhvqcTFgywNwneQbSVS6JoPinWrSe1SKual07
         CpIj9RQlvgFtZv+WWBO5t5YGBc4X69doz5JngJk8KnUhJ4fOd+fETWLhk0+3v0tOpbcE
         UIQC5Oogl7lOgdHS5Vcz2YwzB2nO7zsJyBEVLoY1bkoks1+rEKMppxvw9uzGvCV8WGMB
         8BWHYfSy9aAw+73LCza5kApBlb2mCSSDd+ms5KW4dBWQQboUTiTTX1lwSmIijmIBYIDv
         laBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:subject:cc:to:from
         :message-id:dkim-signature;
        bh=kjhHL5Y9sg0vFwa2Ffv/y68ja0+Pkp5Gy+WmvouEaXs=;
        b=yW1EoACK8KXWI+eK2VsuB1/3nH1Y5bsVv2WC6GBUDxYpU+LgQcHFIQbT9bg8og0b2z
         tm+FBQGRrD1iPHlzgP+VEDsA1aa978i0Pws/dGuBcmVB4wawF3Mqn7+RaG7Hl8Qq0bpx
         FdMix9TtFMxUbiB/XTxaUdf7BroZcCYcEDXdW9RzxYkai3fFB6j93jZmhlK2gBWI+OZH
         DLOUFKGNPGpzvRw6z2W3hs7hq+dV646KzKaLmIdxvAMZuB6mcGWNehD+8g5WXnBFTnUg
         IkaUAU8OjclWugtiMcqr39irH+YBkzzUpwyWQeM4etCRCo8q8v/560wu1RGXy9+RROC2
         P+vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=T8ZazCWM;
       spf=pass (google.com: domain of rtoax@foxmail.com designates 203.205.221.191 as permitted sender) smtp.mailfrom=rtoax@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
Received: from out203-205-221-191.mail.qq.com (out203-205-221-191.mail.qq.com. [203.205.221.191])
        by gmr-mx.google.com with ESMTPS id bo19-20020a05690c059300b0035786664d22si20355ywb.1.2022.12.03.02.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 03 Dec 2022 02:25:28 -0800 (PST)
Received-SPF: pass (google.com: domain of rtoax@foxmail.com designates 203.205.221.191 as permitted sender) client-ip=203.205.221.191;
Received: from rtoax.. ([111.199.188.128])
	by newxmesmtplogicsvrszc1-0.qq.com (NewEsmtp) with SMTP
	id 657AD691; Sat, 03 Dec 2022 18:25:23 +0800
X-QQ-mid: xmsmtpt1670063123t00503lin
Message-ID: <tencent_922CA94B789587D79FD154445D035AA19E07@qq.com>
X-QQ-XMAILINFO: Mm/8i8/T4yne99HUiRiR+7VHSIfb9B6KG4/kMJ956O6iWoBr0lzjkRVw5BOQt8
	 lly3r7XEeO2nB4Ah1Ins8CUyyHCTwADPbYKsg4dLFLtuMZu3xo4xxhhzOVhrfBVCzufA2A3y8uHx
	 a3m4q/8AEcX/OXxx78c/5PVJTvntV0HVXbZuoI6e6jpPBSPDBmiOUB80HppIbjOuAhVym8akXpSu
	 JIW1whbTl1iPHaYuZitQmX4FSlbC60YJjyyOcv3FG4s/NLC09999Y94F0fHefpzYHjQg2cQ+Szb8
	 S+B/DZST0RZIS0ULdUaNREQWP4/Dg20NmnFzBoKfium47pkiW+eHFBcW2WaDHsBD5C2KbxnziL7Z
	 LWHJ9Q3Yl0F170d2LFTygeVKFP+lVt3zLzkjrU5s2nQ5sAZUQvFsfU9ul5ltKDeC/GrmGBgSknUB
	 229kOrpL4xyUa3kez6D9zKQLrZ+sFo6PEy5SQB1gncFqZIjGTPXTqv/w1zgQLiAOlRe1MC0v318M
	 Uez2pRvXlHb2yFwhlutf04IMYlpfqS2BCF+oEOHsETQucMoIwsyngmssS7uTCWVh4wDquA921qYU
	 UvBrC26CUdkj5R1Iz4zaTXcBilO5bDkkQjWvvwDW2oXST6Ex6z/WVMfyCH5pu/n5qblq+Cw2H3Vn
	 lZgZHQa31ZPeGsZITP8ubynwZZB605vnqHAIBTBjkUUQUJBx1qIwqJXvrMO4+HmHpx4OoodiHKC9
	 WVDprKp2yYh5ZR2CB4NtWcod1h2P3Q8L0ucZQohjyHOKLzQcKzvkXkVozyF6nZlPawdUJCi5QKN2
	 LeNe13LI6hjQbkc78pb7rVvhp4NUUzEBhpMoi05Qvq6WIg0ixvrBhiEd0/tkZcCrgVhVNPV843lS
	 hqsvPUk823GSzlUc6PblRmgPpIV1e8ebMXXpywwEsNidbkCtawTrNsx0p7nv+itpi94Ajlhi4LMh
	 2NiY6HDwoM3fBMARifsEJayMDhlDWAvJfIIU13FOo=
From: Rong Tao <rtoax@foxmail.com>
To: dvyukov@google.com
Cc: Rong Tao <rongtao@cestc.cn>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com (open list:KCOV),
	linux-kernel@vger.kernel.org (open list)
Subject: [PATCH] kcov: fix spelling typos in comments
Date: Sat,  3 Dec 2022 18:25:21 +0800
X-OQ-MSGID: <20221203102522.25347-1-rtoax@foxmail.com>
X-Mailer: git-send-email 2.38.1
MIME-Version: 1.0
X-Original-Sender: rtoax@foxmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foxmail.com header.s=s201512 header.b=T8ZazCWM;       spf=pass
 (google.com: domain of rtoax@foxmail.com designates 203.205.221.191 as
 permitted sender) smtp.mailfrom=rtoax@foxmail.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=foxmail.com
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

From: Rong Tao <rongtao@cestc.cn>

Fix the typo of 'suport' in kcov.h

Signed-off-by: Rong Tao <rongtao@cestc.cn>
---
 include/linux/kcov.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 55dc338f6bcd..ee04256f28af 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -56,7 +56,7 @@ static inline void kcov_remote_start_usb(u64 id)
 /*
  * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
  * work around for kcov's lack of nested remote coverage sections support in
- * task context. Adding suport for nested sections is tracked in:
+ * task context. Adding support for nested sections is tracked in:
  * https://bugzilla.kernel.org/show_bug.cgi?id=210337
  */
 
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/tencent_922CA94B789587D79FD154445D035AA19E07%40qq.com.

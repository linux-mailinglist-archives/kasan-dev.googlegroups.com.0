Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMGH7WPQMGQEGJL6VZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 27DCC6A6E98
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 15:39:45 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id e8-20020a05651c038800b002904f23836bsf4113251ljp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 06:39:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677681584; cv=pass;
        d=google.com; s=arc-20160816;
        b=g4/zUM9zWZsHMvdzg7v625Pe5W9HYDudwyEHXivF2WuJoNAleHU0WIfq99ef85THai
         DPq9VF+uKgNvMLFJx7HfV5KeV0bFOF26IMuu64ulQfYsE0RNRkBJBkqzL1XNr/DSevlM
         TMnS/qJarGx2vlEVfFjPcuBuuq5S5+03sqBWta6l3QqJs8deyfoTMdmh9kcT822J0do3
         eaK2tIkvGj+hZ2sz+WWv3r2ckHdu8ldBq1Avg5qEiz8pJETPn7uWPpZN0RkoduFJI2aC
         WxcNURwz/6E3ue6TA62275SjAy2ZfGf1y5Pn/9JzrpQb/yYGGYoypvq2t0gcztBOYcHm
         haFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=BDo94xyXqoAiaTAwHG4B0/TcpBaN4f9PaUCMVU/in1w=;
        b=V+QcglfqdIa5e77Y1EOPjoOWBO8dhzK6uEkgWkJ7bZ+2bv2Om1YLwgQnL+rkVXZUTS
         KEfyMCVyRZ5FZ6tAifxDSfzGiOt6hnsoW3BencTk+9zHHgpY1HysWBAojJDx6SFB0fwH
         5BswW8z+9TKDgtVBaY3dCSj3obQPc2et7SLQtJO5SRFIa1MDfGEiuLRkrdt/kqAEL72g
         s+7JRBeKSwvfrivTlKecgEtsv7oHR42GeP1SR7Peec5YrWCee1zn0sXhxriTACm0R9Q+
         WEy/96PT0x+9fYwiH+SitLosxaqeIKsZeeFZvpj4gqA5QJwdoMLC4xu8oG9QBAoOKzWL
         TUrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DcQhFeZ5;
       spf=pass (google.com: domain of 3rmp_ywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rmP_YwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BDo94xyXqoAiaTAwHG4B0/TcpBaN4f9PaUCMVU/in1w=;
        b=kf6w0os8UciV6jDadvoibIKaiSFPz+7ipFV2pre52WKBehat4DgmE7sD0z1iIsLUzd
         nMMSEVMt4Gl5Ya+6Ys9s5JSupMkv9b4V4httC7r/Wdbw7hc1AnQ55F5KSGRFDt64VVGB
         UNrwxxO2Y8INXjM8WXc/XLY4o5NvLrMiGJjRXE6hFujqpuL1NRn9l47ALz9mOjMo3foL
         Pe/t/BuwhqFEhPFBXpZL+M2yB1bQzntBi6lXNQVbeZCwyuwh/LNehiMZKkOa7cEhJXKT
         mnbSgAT+aXJynK+eOYPkuW3J6W/D0vVfqebyYxHjUQmlWli55zwM7JSxl/7eMQzliLc+
         nFPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BDo94xyXqoAiaTAwHG4B0/TcpBaN4f9PaUCMVU/in1w=;
        b=jKY7aAbuPBVVe5XZUltPG7legBVsc40vZhWPj2unk6ezJrNcLB3ZL38TYC2VEizzij
         xv+Dq+tJiu6B9mvvQPWi1dOX3Zfkdi9cQoFdzVRLXaJiLU9WSinWzgrajgI57jVW6Q17
         KI1TiXtsOpeOZqi5CAqISdFwsWy6MQ+zCQ5lqeRgoFbs6ZCk2Rmd8moNuREWU80tq/R7
         t2jCJoZxuusuBlTPychqDXgP7PRvOuAs3UeiFpbhEZ6aC5ICIW4mNsMyxMrKOnjv9bW9
         O0jRqkEzhTAe75LnyoZg+ouixac6uH+hPCI4iKwZWFS6TKQkvKTxWEq4v3XCAVuWrzhy
         tF/g==
X-Gm-Message-State: AO0yUKUTVs//60hxHpFJxN/K18qKYRnrK0vNYTyiwX6MqvnVr4zVT9NF
	xUpBQXtXNK8cw4S7t9KiQ7Y=
X-Google-Smtp-Source: AK7set+8ph+LQGV35zcvIR3mXgfWwvNrygc1dkPLjscC/rGyme1U1wfFykkBW8DiLTQ2B3ChnyDbhg==
X-Received: by 2002:a2e:aa1c:0:b0:293:5fb9:3c10 with SMTP id bf28-20020a2eaa1c000000b002935fb93c10mr2086581ljb.10.1677681584383;
        Wed, 01 Mar 2023 06:39:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e26:b0:4db:3331:2b29 with SMTP id
 i38-20020a0565123e2600b004db33312b29ls287747lfv.0.-pod-prod-gmail; Wed, 01
 Mar 2023 06:39:43 -0800 (PST)
X-Received: by 2002:a19:750c:0:b0:4d7:44c9:9f4b with SMTP id y12-20020a19750c000000b004d744c99f4bmr2082364lfe.1.1677681583181;
        Wed, 01 Mar 2023 06:39:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677681583; cv=none;
        d=google.com; s=arc-20160816;
        b=lCcxK7mdRBsmuiCkBuoxzNUMSglSMxThHbJZXekeCwn+Ia9Lvaxyl/o7aD+mnb1p7J
         n0BI29AkMPNrdYXfr4Fs6TUSXVwhmHWjx/qkXbQW/rqijbxFqceCwG3syx1k3iJ5WA4C
         9+25JUHeZNFG6f/oM+u9fDV+o1JyQrbzT2TXVjJG5vY50RzCNYPKGnKAZ9uIPtUVQvYn
         N23Trnmzxn7h5dlC1NNe7I89eXi+uuCxq2K5clJaOk4vu9WwUGOftCSMgusn1CDI6Cvp
         EIgQW/iGn6JI03hGhBsjF1WHtQB19HuzA2UwlzvkOcIoKFBKjSBk9F3WK4JVVPUYt2Cs
         jthA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=h2FIkUEqU6YxkmcIL1AtVszo9ZqqtqhQ8yghIzSXGmA=;
        b=YaMlXBFF/ctp2ENVBVj7kyoVeJN7pbVOJE6+ruyiMOYrGDmxa3b9Ng1TQXFSx5ImyF
         nRUS12qLSxsEKERu7TWgkPs7gDOApOtkEUGpTpCF29nabkGUXdzHo8GIShVpsz6PAJ6n
         mo54PEyXgHARxSHM2xvGCowUzCuyIrQ4yS6ZeoOYf0/VBwvY4XlR3qsEbDjrnTiuCYeZ
         /0g3CmyqRtSdtgs6MEWyFEbjnxUbFaMiWy/FTeA1b9FGO4CZN05gQhVjImjmLNr/73Il
         LQsRWgIrqJlgSMYsrL9qApuwpXRpE7364FXvRlUZL3TEPjRCZppHw27Cdgsia2r/isDM
         scWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DcQhFeZ5;
       spf=pass (google.com: domain of 3rmp_ywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rmP_YwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e19-20020ac25473000000b004dcbff74a12si579505lfn.8.2023.03.01.06.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 06:39:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rmp_ywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cf11-20020a0564020b8b00b0049ec3a108beso19362977edb.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 06:39:43 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:3c31:b0cf:1498:e916])
 (user=glider job=sendgmr) by 2002:a50:aa8b:0:b0:4ae:f648:950b with SMTP id
 q11-20020a50aa8b000000b004aef648950bmr3893580edc.7.1677681582665; Wed, 01 Mar
 2023 06:39:42 -0800 (PST)
Date: Wed,  1 Mar 2023 15:39:32 +0100
In-Reply-To: <20230301143933.2374658-1-glider@google.com>
Mime-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Message-ID: <20230301143933.2374658-3-glider@google.com>
Subject: [PATCH 3/4] x86: kmsan: use C versions of memset16/memset32/memset64
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DcQhFeZ5;       spf=pass
 (google.com: domain of 3rmp_ywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rmP_YwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN must see as many memory accesses as possible to prevent false
positive reports. Fall back to versions of
memset16()/memset32()/memset64() implemented in lib/string.c instead of
those written in assembly.

Cc: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Daniel Vetter <daniel@ffwll.ch>
Cc: Helge Deller <deller@gmx.de>
Suggested-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/include/asm/string_64.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 9be401d971a99..e9c736f4686f5 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -22,6 +22,11 @@ extern void *__memcpy(void *to, const void *from, size_t len);
 void *memset(void *s, int c, size_t n);
 void *__memset(void *s, int c, size_t n);
 
+/*
+ * KMSAN needs to instrument as much code as possible. Use C versions of
+ * memsetXX() from lib/string.c under KMSAN.
+ */
+#if !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_MEMSET16
 static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
 {
@@ -57,6 +62,7 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
 		     : "memory");
 	return s;
 }
+#endif
 
 #define __HAVE_ARCH_MEMMOVE
 void *memmove(void *dest, const void *src, size_t count);
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-3-glider%40google.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGEH53AAMGQEXWDCMKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A6E2BAAE5B8
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:00:25 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43d5ca7c86asf264465e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:00:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746633625; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y+mibHtOSOAMGaK6PRmRIgRNAsnqTlkcQ3xS8oFLj3mdvwy2bKe3KXtdZOJPFIQBl4
         iXgROqHk91XUUb++lazNDMuRWqcYlY/8eU8+OcGzgdiBD5YpTYzkVA9nN29r821RG1B/
         /Cw80ZwntNcytTAejP10cJGjBlEoIbXI+mTU8BK3/jhrl/QeaszkIIC6EQouEkOH5HII
         puieLsXdaOqDl7wLFLb+omiDyztunFlhXBMigB5K0lJVWLWcRB9YdDRVzniJ2yFGrd5/
         xV1MmDs3GNL0XNxuINhLS+Ae6zfqX3IYu81uLQrf4Y32j83GZAe+CK+dBiG8NY77r3Mk
         L39w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pTgwAHDIBvHCO9ZR3C5dohi9eVsacp9wq+LlJkGaaEs=;
        fh=660Gxb+ZgDreBFcJcfDMBJs7/ZphzrRvIlnuRS5vp4w=;
        b=YYtOJ8cIvqgkQKrRZnj4iR4uNSlfbsFO/6dlHiimZ9ZF6RM2Q6iOhKbifyIfE4uC9g
         r08ySWvW8KALGbDN35FCWX5BOKCyFsmVb2Ngy/kZ6OQeVasEe7iATZSni+PtAdhxECbQ
         9vXD9xBu5/sP22PuWZo0rNxnPxfSzApbUqxFTKJK31jMW3vb/0OUr97/2N8k6+RseKAa
         zQYFiyFDzStkDlzZ/KcnuFXjU4hDK7HE5UMRnKozmcWHeEIPxNy2BAc7XQJk3SUvDRL1
         h31XercxFASlxA4XuTs7+wFzWScuyv8DgIHSlzQJP7zZht+BxwXbcxdSPyDveXs6ecYu
         muBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="q0f/X1xE";
       spf=pass (google.com: domain of 3lymbaaykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3lYMbaAYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746633625; x=1747238425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pTgwAHDIBvHCO9ZR3C5dohi9eVsacp9wq+LlJkGaaEs=;
        b=VwRIZKSsafbzratXqBFtdpYlsdvJ6+9B8LV7FVyMwuXmmtkCyXzfo2g8/elPgZQlus
         V9ktojZcbzGQ1/pl1mzFX+K+k9afxkTHODMXPzzW4tpt0uZNTBuKbnPFzXkfyBMtwl5F
         00OqhqWqpnFrKlxq+vl9m6TPRQgRJjyokeztbTwTI0Ww5SjXpwMLQNpRacg+gKQf/nfP
         xRMM1pYsxBQ6nGXvMh7VYd+q6df1/jpIiMvsu9bjUPCrHp4iLneY9OP020W+uD//va2z
         Uaw1tOrJX2DpBPy383ijyK62Qcp6LJSw5h4eXVlPir8OPba+DBiAxHTW8kWpTd/psFlM
         j4Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746633625; x=1747238425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pTgwAHDIBvHCO9ZR3C5dohi9eVsacp9wq+LlJkGaaEs=;
        b=JSbQvCHIrI+pPrAQFGirbQyBr7mVj6/8Cp3uUk9e99XgvWoyLI++SHbYcZjMPRN7cc
         kPVsjoGkxWJYl2T7gh+VmgF5cEy28CxJ6y765Akd/guxGgEYacyKIZWiyjgnJaO2zVst
         DCgRK9eRuU2/kbUOo3D6um23W8ki9CeFmKB4nEthy9ItjAPVXuhnYIpuNfci5O1qoe75
         xwVZReR/REaAiwU3F9hlENqzmkchDTIWJelDijU+7MqeGz9HI+Y7FL8QdG0oIFxBDrJ3
         E1VNTfKHdn8Yg5yjfuwzuBBLM1B/4aGr/qhbJnQYbIPKMriIku8H8DUTvjeif9MCTnlw
         t7qQ==
X-Forwarded-Encrypted: i=2; AJvYcCUuUuhfzeAk4njA1ffXyqGIpimhiJJBYqqmMdS9wCO8/wqC1ljPBgjxVZniOhsB9QH7Zv3Dgw==@lfdr.de
X-Gm-Message-State: AOJu0Yyo1lcKeIYYh9udHxr+cPtdMfuxdTQhQ6YWr9tcLLJRNryzoBzn
	xFjXa9twWfnBaZ4MuuU4M9dw8cs9caeVElZM2uNeJvi/95UCc/kz
X-Google-Smtp-Source: AGHT+IGT4TVCp5HtKxZ5vZy7N7+weoCvGcswZZ4p2irt86kUu4BWqs+x+Ccnf0fKxw6ft7sd1D7fww==
X-Received: by 2002:a05:600c:4f4e:b0:43c:fe90:1282 with SMTP id 5b1f17b1804b1-441d44bc623mr33741415e9.7.1746633624729;
        Wed, 07 May 2025 09:00:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGbT90SUXNK108GTXtb93vzRtq11stE4sBdhNJEikekGA==
Received: by 2002:a05:600c:350e:b0:43c:ec03:5dc5 with SMTP id
 5b1f17b1804b1-442d034b8a7ls44095e9.2.-pod-prod-01-eu; Wed, 07 May 2025
 09:00:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwF7RaYP44voSmhaI3wXVvNcgKeG+HF5redJYDLf0AuPNUQMoHDMgg+8RFywwxdp57NLom33mzcDQ=@googlegroups.com
X-Received: by 2002:a05:600c:3d17:b0:43c:f4b3:b094 with SMTP id 5b1f17b1804b1-441d44bc6ddmr30684325e9.6.1746633622319;
        Wed, 07 May 2025 09:00:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746633622; cv=none;
        d=google.com; s=arc-20240605;
        b=E0C4giyQMDP4SESUR2AHieBqMNkpvrwZjgNf3DQFMvWLzn8VhiJRhCEXaPS/rjFD5U
         ljbcZeJ+nCcHuW+Zc4E+8xl2WwgFjkhsfFPoYDhklEZVd1hTF6XtVBDPPnCTpC4Hv1w8
         ND1hquJd1ru1XM8yXYJyyA0nmJIWkaCuJOo9ip8GkdaCJ+kYrG48mp5jCtmfymCrSU1I
         TmngYkQdjvrltEEjC5zfO5V2y+3C11DGaOlCGdwdfXEhdauP+qq4Bt0/qwUBUINDJBXe
         D4oDvWus3d6Y/cUaxuxnd1MbE0V/0IznOhQ8tDzX7HmWbvH6rxA1U7anYiE6f03DnwDs
         jApA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sPR0SEzdksw+QARijEF+8H2O/syRn+ur/NtvRkf+UuQ=;
        fh=WpB2CrbyskyN62t4452e9JB2LP5cA8b1rpaO5wD1rqw=;
        b=XntaT1RLH0CismJerp6XjMoWbn6p4eaV4DYVnOpXJ558t5ePez11PFYGFQG9o6GVdF
         93OS4S7T8gpptJeDPj4McwU4hMmr2noeguBzHY2FXQwVilCgXBkmJ4W9H7LtI3QNnQcz
         jfKEvTo4w4F2hJcFOgLa0GPCASam6qA/5Ndt/m8lKUauQsxjiOipJN5tM6gX5HpSRUgF
         mBPrIkjr6fYq2Z5uxXVwSl8MoeyocIl1e9tHFiWLt/tobOLtrk5mTezn4D4YgLyO6dvI
         jSuZ6DuAxTxm0oAgFnluV/JVtAt/l3/hmkMgMQFyGY04LLH8x5Ts059jni0DDxGgN+4B
         zsXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="q0f/X1xE";
       spf=pass (google.com: domain of 3lymbaaykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3lYMbaAYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d11a9570si2118355e9.0.2025.05.07.09.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:00:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lymbaaykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ac3e0c1336dso527334566b.3
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:00:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW4Jmv4+6xNIerHz1RILNdLvCcguP0jQa4qG12078w0iDKJ2ZgjKlcXwzGksvROyv5a7g8ynSuL1zY=@googlegroups.com
X-Received: from ejda5.prod.google.com ([2002:a17:906:2745:b0:ad1:83e8:4210])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:7fa8:b0:ad1:e587:9387
 with SMTP id a640c23a62f3a-ad1e8c50524mr400870066b.21.1746633621858; Wed, 07
 May 2025 09:00:21 -0700 (PDT)
Date: Wed,  7 May 2025 18:00:10 +0200
In-Reply-To: <20250507160012.3311104-1-glider@google.com>
Mime-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250507160012.3311104-3-glider@google.com>
Subject: [PATCH 3/5] kmsan: drop the declaration of kmsan_save_stack()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, bvanassche@acm.org, 
	kent.overstreet@linux.dev, iii@linux.ibm.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="q0f/X1xE";       spf=pass
 (google.com: domain of 3lymbaaykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3lYMbaAYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

This function is not defined anywhere.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index 29555a8bc3153..bc3d1810f352c 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -121,7 +121,6 @@ static __always_inline void kmsan_leave_runtime(void)
 	KMSAN_WARN_ON(--ctx->kmsan_in_runtime);
 }
 
-depot_stack_handle_t kmsan_save_stack(void);
 depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 						 unsigned int extra_bits);
 
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507160012.3311104-3-glider%40google.com.

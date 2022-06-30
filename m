Return-Path: <kasan-dev+bncBC6OLHHDVUOBBN5K6WKQMGQEAOOJ5ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E17356138F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 09:48:08 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id a83-20020a251a56000000b0066c354a19ccsf14771993yba.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 00:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656575287; cv=pass;
        d=google.com; s=arc-20160816;
        b=ljvt8F+WI52jUydbC+LztT0nuDsKTKt9YGZ503Z5iYbRlM0yjUAjeHLOPvphgyjtKY
         JQDVJkqchGHAhmNO6g8BnMMeZrGlOP3oLesAXue0z+Z+VRDZNhtHpL/WCu2CVs8K7iab
         Ve53fYk/Zuub01fosu8SNqmmoOfCEQK970MvKItNstRWT1N1TUDrwEINHkEbDbaR0Zdl
         boOoRPYKVXyPltXA+wxNTUWbgyHdFl0dwZUgyMEeuZI1lEUZ3pCh+gDEwOpFmw2fbilb
         cHFTFG5dCLzlsJv7O6KT9wx7+WhTanZMT60yzgX9KZ7g//4iMfe4FowCOQGSd8g2WK7n
         +Uhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=WznpgMGyfVgHU1Xo6gunIFuzXQqNMKqJu4sH8vzpOm0=;
        b=X6/6D61NrgEqFTVFYg9GQ7I+noSv+Zs9AdPo3ONZAFT1fWX3WN2zHxhdveRqQyNg7O
         P4riJdw8gs/aNdxpIV71IZOmylkjKOf4it8NWCaYv0H8h1uiuQ75pza5kRm/hQa/lGSf
         Riqk+s7Z9yTwgpTyq6AYB39x1jyOKN/0DjOT7pUZgi1ko+db97QC61d3uAGZJm7odoVa
         1maCjvhFOBwVvznGxDEnUBRY68wBLl7ei7g0mDAieHw3cuNEE5ISpRrZvHbtxdfVpBhW
         hRFRm5yI+fczujnRlgjrFdmzIozHVG89gmfKchlqcr8BYQMUlyA3SpDmG/IS9DDIeQWa
         Y/cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Cd/RaHs8";
       spf=pass (google.com: domain of 3nlw9yggkcfewtobwzhpzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NlW9YggKCfEWTobWZhpZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=WznpgMGyfVgHU1Xo6gunIFuzXQqNMKqJu4sH8vzpOm0=;
        b=Ht06u85v99jRu30RiqpO2lBWqQOkQFVoxzEBY4UTl4xBYApxtZHZZe6QbsOls721sH
         fBA49RlfdhUiqw0KzfqGSLiWaEagk0a0/XDrpBM2c3nLZuTKfsb90q2+FhJRbbB6eR7D
         CJ0fdyg2fdRkdL2Kbx0ofG3e31JXvkga0JTCdG3U+U7EQWHgvv7D0wUCG022uNA78or4
         t+M1ipJV9Ph6iZJ96i6X0tVvE9rXkAD8h+/+6i2oHWZWa+rw7mEipfW+yJ+SEAmpHb/J
         s2G1rBeHP/Uu6nkIO8GpPYZfIr+tQA4UJCzQITfAUlf4xCvuoPzFmMuxbQ75UpLcOiij
         8Bgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WznpgMGyfVgHU1Xo6gunIFuzXQqNMKqJu4sH8vzpOm0=;
        b=D+0/MT8XGrDq1KORhwYJLo9uYj9Btvg/non4x8HKJiOMS8kjaXrmmc2/dGfrAQBLca
         zXnNlb7dcjZZAozmYvzM15YfNP9TsxECirR6GgXPUDZ1EJLBL9s1dpQ6RAv3mgoSNGge
         wuQ3kgJMKWVQDaDprws74XharlecpLmA+TENIypMvKcLgRaRMdRsi2fPAzWUx7Jt2j+W
         tZNSsXP5OVsoVS9Xc75kHYq2/Km2AEgI1mlomy6OL36ToxZM81klpv9KPOINUvUGY12E
         cZYc3ShGqykFghDtTx4GyR2X3K8QwyK94PGSapUtwRBHWHJH0nv2ZnqHJwUFR+VNQ61x
         WsHg==
X-Gm-Message-State: AJIora+KSaukQOehwfv8+6NjIEPO7IWgTmuSTsjM7dWq1AvfeFQA2BO7
	euDWX6q16mdTaSVEj3+rB9M=
X-Google-Smtp-Source: AGRyM1tvjTrEi5cyjCfWvSDi9gFX1eLKzLClAY7+Ti9XB1Nz2laPahlT42+NSIwRKuMDwW9iBoBiEQ==
X-Received: by 2002:a5b:cca:0:b0:66c:e458:8882 with SMTP id e10-20020a5b0cca000000b0066ce4588882mr7815258ybr.465.1656575287196;
        Thu, 30 Jun 2022 00:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:721:b0:64a:b88e:63c8 with SMTP id
 l1-20020a056902072100b0064ab88e63c8ls25948511ybt.11.gmail; Thu, 30 Jun 2022
 00:48:06 -0700 (PDT)
X-Received: by 2002:a5b:3c3:0:b0:66c:82a5:c07e with SMTP id t3-20020a5b03c3000000b0066c82a5c07emr8232481ybp.201.1656575286546;
        Thu, 30 Jun 2022 00:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656575286; cv=none;
        d=google.com; s=arc-20160816;
        b=XQe7UxboHzcIP459ezt6P53SXli5VQYCARlnDI3SvLgOC4Qq9l7/qUuSw75zpihDo5
         uFZGcLKoD957J3Nf69cxbwzHxn2JoJvFLF4ijv8TagA+bvmWGn4nBCJkqQ8VesiT6D8K
         prnqQ5GOst5N+1A05glZLVecy5nh2PyHpto6O8tMJvCPzGxbPLNhg4oA7xQyMjGgzznM
         1J6tsx9kQTXO9u/KsevXMliSIlbsdJ78LDZMHU+ufrfw6qgrGF0sBw0TU4GPIVWsr1Wi
         T4jDT0a5yFCKqdfpcrEEj0hrEgix4UoMl4a487OSxxRbLkAs4sziTZTgBoN9iK/WZhUJ
         6uug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XzzQ2qeoRIHvL3OIKjNQCubCMmqjty1j1wRkBLGrTgU=;
        b=N2dMEneHOjAU3FEujyQNnQxm29z12i/kVmbbG3bBfEXrsqkE+/CY1TnaIWEtbcWqIw
         aXLW1PQS2UZTV0TSu68vNEHNbywCAJ/Mf1+QwHpVvpVuAUOkdPQR5IT0HlgcxzmQAvWC
         m9r3X5M/qMXBLuUPy3R5lIgHInjqMVTQpg/laAB7eKm2QZxTj1JvJyAiUEnLvrx0Pj4S
         92au3vZHOWZs+qQKB4kDXfIV7/Za8O7eN5JfItGdcV0C2EeEJlV09p9jUi3xjwvYlNQJ
         SapL3SWmKmiVTTRjiLKhaJpf3jUW+JD4jAtiY5bCaqJ7prFOjz4Ox5GnoU9VnGKEyAHK
         dR+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Cd/RaHs8";
       spf=pass (google.com: domain of 3nlw9yggkcfewtobwzhpzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NlW9YggKCfEWTobWZhpZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w67-20020a25df46000000b0066ccd85e4b8si460004ybg.1.2022.06.30.00.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 00:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nlw9yggkcfewtobwzhpzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-3178a95ec78so147625417b3.4
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 00:48:06 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a25:2f81:0:b0:66d:9a86:f6de with SMTP id
 v123-20020a252f81000000b0066d9a86f6demr3315237ybv.590.1656575286295; Thu, 30
 Jun 2022 00:48:06 -0700 (PDT)
Date: Thu, 30 Jun 2022 15:47:56 +0800
Message-Id: <20220630074757.2739000-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 1/2] mm: Add PAGE_ALIGN_DOWN macro
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: David Gow <davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Cd/RaHs8";       spf=pass
 (google.com: domain of 3nlw9yggkcfewtobwzhpzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NlW9YggKCfEWTobWZhpZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

This is just the same as PAGE_ALIGN(), but rounds the address down, not
up.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Acked-by: Andrew Morton <akpm@linux-foundation.org>
---

Please take this patch as part of the UML tree, along with patch #2,
thanks!

Changes since v2:
https://lore.kernel.org/lkml/20220527185600.1236769-1-davidgow@google.com/
- Add Andrew's Acked-by tag.

v2 was the first version of this patch (it having been introduced as
part of v2 of the UML/KASAN series).

There are almost certainly lots of places where this macro should be
used: just look for ALIGN_DOWN(..., PAGE_SIZE). I haven't gone through
to try to replace them all.

---
 include/linux/mm.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 9f44254af8ce..9abe5975ad11 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -221,6 +221,9 @@ int overcommit_policy_handler(struct ctl_table *, int, void *, size_t *,
 /* to align the pointer to the (next) page boundary */
 #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
 
+/* to align the pointer to the (prev) page boundary */
+#define PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, PAGE_SIZE)
+
 /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
 #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220630074757.2739000-1-davidgow%40google.com.

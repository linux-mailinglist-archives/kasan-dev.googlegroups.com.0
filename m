Return-Path: <kasan-dev+bncBDAOJ6534YNBBLFJZDCAMGQEEFUNCUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F2E50B1B66A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:53 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3b7806a620csf2497462f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404013; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZKjjQk1d2f4dl564ALgujSxWni77Aok4OFkr+RzfDTd9/vHXHzi5jvVtdr1yXAJQG7
         i5aAj1A4rIoJ+wI8DrrCXM/1I03nVvai98XQhFpZ83ZoN25EJNGGOhKmNZkMxng2EDf1
         NrCLi/mREYCBamEB9kfU2e51dRiAiOFzI397t61knY0qXImd9vA7r2BPO64BzccFkXQ3
         6Cfua0/4Or+ljJNidgj1YfJEBfDwtSvCmB8QQgM23F+DKYQgVYH617PWW3PQFIji9MDg
         pCHeIs33LnVjD8s62X/ioH9CcP7lPCevHi+hxIn3PdeFfxeMmZjo8m5A/eJbt54dk853
         LaKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NPbk6w01CXgrtTioMu4Jj3UGzKYzZowhcjTtuhOCdfU=;
        fh=35HxtzCZfnSCFyk+86FdthgLaQBUJBWqpDoGrrCQDwo=;
        b=eg9+l79z4AY6J4OxVRLBlmBr/BcgrFugVBu9BxsIaIFw+bshCOThSeM4nYrukK1gn5
         tBQjYoElA5VvQ+mlQYuTG4e2+4R9xvlXkulL0SPHzrcQOHQ0iBk6qWbQF/HRcKNwanHF
         MPyGDrYjx14MTID7ihtFAgA5GqlZp7ox5z9dIN7fQIP/bCWMuj0PuZT1Nh6gIjal3JvD
         KekWX6gNyrYkL0zUE60EjU1cAbp7RnvbclZkiYppnVv/iWXaLZHYBb7Mztu3X/5DhRcj
         2zK4Be66OMp6N5gobn+mpLE4KfvzERfzw90GT9KiMaPnTjsqJE9wyV313nLb/ew4BbUv
         0/gQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EBlsPxE2;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404013; x=1755008813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NPbk6w01CXgrtTioMu4Jj3UGzKYzZowhcjTtuhOCdfU=;
        b=O0mupA/oL575Q9DoOENuM95LkqwudkjlKAMQbrWmYiECDJfiV1jDvgKT4gptoZ3NzN
         gMCMFhtnrOxUtLmHlbO9ihEfZgBODUoAVxgd4Byh0Vfk4T/2pI2kXNzu+jSu4S2FXClx
         ds74EWZhcJOJPxx+M0ywGXa1wagvT7XzFw0CNIoMlnXRZl2w1IMBX+tiYhGCJbvgxW07
         DP9DEuKMcAu3Xp7naKsedxdI6LuL9NzAQHBl3Yahy6r5uayf7NLXj9hdRwoJSsyelo7i
         rNVBynnHynDRcElr6GlcKkYP6TVyzUZd+R6pdfWJuvXGBDY0XLvkXttH7SAeHUWFltM0
         w7BA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404013; x=1755008813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NPbk6w01CXgrtTioMu4Jj3UGzKYzZowhcjTtuhOCdfU=;
        b=A+YHdpY1b+q1NqYRTHro4uDsCAkYCDdGSibS3giKFrOzlusERICDYeoFoGHe332UCY
         0WOeN5rNYXgxMYHO9aJA/mdw6ptLU5GbSbO3YB6+ZLGOzJ9rrTU0lPAMSJu5IeyFPDl1
         ynfvVjSYu7D9+r8qMxbEtuLCsF/emIZN7ZoZop7wlX4VGPRXO9aPMGjl33sfB8jLK6c0
         QsotMN/zVWdJwk4g+evF8jd/NB9n+yFhr8eKS4tHX32JVUNzYvLTFtU0UytvRFk+d4J0
         QTOzVGwy+TSXNDoKc0SgLPZnh003qde0G1ttbyHYIz38FdUTkplMfqIrXTYA+kp/+kGX
         UyMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404013; x=1755008813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NPbk6w01CXgrtTioMu4Jj3UGzKYzZowhcjTtuhOCdfU=;
        b=N8uPyJkrGz/j9XANt1BFsER8MO95vN4A77su0+4Tev/hWtfvAiqkic49RYc7BCLFWo
         FB6c6Uws7s2lWpH6EwMXP6ZSy95D0BMbwf7nf+l/TES+8HpG5abAvwVwnI5E3h8yaNBc
         nH+EM5h95Ttxr3h8ceVjMX9dsbFsc4nQqk5QyVPojICA8sVyMqA6zMzQfupTtDcwvibP
         QDYJGeSwrxiI8/7q1Wtxn9u0w22DNvOwWozc0VqlvTE/FLzq6gD87KDY4FgDR7eS9xXi
         dIIWfkKoCnNXJTj1mTMZ/ZKnylflYt2ugDc7vi+FRvQ8ZeF+XLvEBKBNE4YJRiw78On8
         /1wg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAmZQLUBTfpPHpmjF0ByRuhD4BXAsI8k96n7xH9qHf/7xFAXvDjDYYLy7FB2WdTmVX+wvqeA==@lfdr.de
X-Gm-Message-State: AOJu0YyHLbK0MTpj9BrkGaDOHu5+W6jwaHRhvh7ezdZhsAUWzBroXc+J
	c2e3bkuWTDRjmKieU7bsctMAs5V+XsrkSJVQZosygVjzkewFlua/cCnV
X-Google-Smtp-Source: AGHT+IGgEv0XeyzOMxw9REYbhatlsK/cJwGg5GW0yEiZhi4c2G7ZAplxfqcqf1liCUBlzb9yyaCL0g==
X-Received: by 2002:a05:6000:2481:b0:3b5:f93a:bcc with SMTP id ffacd0b85a97d-3b8d94c1ceamr11424137f8f.35.1754404013266;
        Tue, 05 Aug 2025 07:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfkDYabbvwnJPkMowCkO+LTZQjYDzAG/3YPoZgyMXLDEQ==
Received: by 2002:a05:600c:c10d:b0:458:bc96:3b4d with SMTP id
 5b1f17b1804b1-458bc963eafls8494265e9.0.-pod-prod-01-eu; Tue, 05 Aug 2025
 07:26:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2AeU1ofimNIIAPl+tZtRJwPWhrP0CyxSsMlF8QPj4Q4mqUkao6c526x8+32AMtIHwifWEVlfUXiI=@googlegroups.com
X-Received: by 2002:a05:600c:1d05:b0:459:d709:e5c9 with SMTP id 5b1f17b1804b1-459d709e963mr75765175e9.6.1754404010689;
        Tue, 05 Aug 2025 07:26:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754404010; cv=none;
        d=google.com; s=arc-20240605;
        b=SsukgpIX4Oed8HF2tgtEn30pC0FjUT8fLiJ9W6Uj8VpUlzTZYIPhw0ioRg37EWq/cj
         sw4c5CQB+cQnxiqyMUm1WKTvFnNfzR3jUkaLXHfnqwxrgOlkBVC4wFFkl3q1LbXvrEbd
         V0n/wF01Si4PV4CkB35/ZycreFZO30+YpvtnYbgo2FVa/Op65fNaOIYsdi+rvJgREjB9
         Jt+HBkyhX4j9dWTFW+JAy8ABF4cGYwtFfe+EBQqX9jUPGvTYc3h+NPxqdMvZlG9HDDlO
         GDLeiSW0AOvhiSS1B4gaQxORL7MD59u/5mR+fRIoi5NvTVJTvA7vAQ046vQo0SYlS2bF
         sb1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=axtwyv1QW9Jl3sEVwduJUxW6lENRlEEn6jAlKX1Xswk=;
        fh=uI+KjqhBDeCO2nl4wo9/Cc8Y/pHHXQcMPHWNqpoXlaw=;
        b=Py8Ze2oIYSiK9W1wbc2vJFFEwuOcwllXDT77SqBbQKdNUDhO8XtM44OXaAk80cLEJX
         XEtI90RJCalRB+ceRKxkaauifRG2XA94pPSvo4wkDegUhD1c5gEHEs/zDLcL9Xxq/0Xa
         7ktXnyLYgKWEfEheUaRv1elwI/HesUoSUCVegatx1klTJWlSk7jtvWCTXAtLvid+SepN
         4hTcv1RNfTam7cOk/9LS5t67m7Z8k48kmXj4XG8+I+O/DNuLrQG136aIRoWpinNOw+98
         zy2nlnR1rRkXufJRb5ZPj+155ycLZHZsnt68XRfMAbGgNUzEoNfHxEByAvDRqZ2IKG4Z
         ABaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EBlsPxE2;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45910de589csi662175e9.0.2025.08.05.07.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-55b975b459aso4177220e87.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZIVZ/C4q+ZXOKEMzy9gi8gXHdf0v4MyfMtF6cPEDrpvnzExPiB6ta0Rn/tJIec+i0xQWlPoddsYw=@googlegroups.com
X-Gm-Gg: ASbGncs525YxNmwi3iuffT1QhPrAEoxvsTV+zXguo79e+dfafRwbSFOywgFlKDkYp58
	uXMrGcTnZ0OnVbdr3WvRnmiHp3tmvs7GhPcqZZsnUOmay1O5sW/E93gIVNXiiEl9nDOoPMoRs6R
	a42nbiTHmXhMychx/XyMMKnKiTEJ3PG7Htw0lRyA9L4oVlmxk+1+zdHp2BBSRYbi/6seDnJHThC
	IM7XFWlKWIyOD7AGVf7J+RJamWLC0HxIRHxvD4swowmBpqV+BlrLO+OrukKOyxRsBnFh3bFxyLQ
	ZS1CfjGXqWdyXXvasDrCgUVlIgQW1zOLcT+DjfzwB9hHP+WUFUN1vEnhVTp+Pkh4Qdsepg2q8o5
	CXzWhPLkRjTT5K1uLmlkNEnphs+A7VmZ2WZ1M27BwzHCbWVU32oR/jlVZzCyz9BgmvfW9Rw==
X-Received: by 2002:a05:6512:3e1d:b0:558:f694:a65e with SMTP id 2adb3069b0e04-55b97b41812mr3194986e87.34.1754404009682;
        Tue, 05 Aug 2025 07:26:49 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:49 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 9/9] kasan/riscv: call kasan_init_generic in kasan_init
Date: Tue,  5 Aug 2025 19:26:22 +0500
Message-Id: <20250805142622.560992-10-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EBlsPxE2;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since riscv doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/riscv/mm/kasan_init.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca..ba2709b1eec 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -530,6 +530,7 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-10-snovitoll%40gmail.com.

Return-Path: <kasan-dev+bncBDAOJ6534YNBBR4QWK4AMGQECZCYLII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5244B99BDE6
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 04:56:09 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5c94862c3adsf2208889a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 19:56:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728874569; cv=pass;
        d=google.com; s=arc-20240605;
        b=IcVmZJ+aMk8cqXg1+lo2pZcXetjjtnYEMes8YNAOwIHjN/z5dksiPiUqWtJqajfy+x
         NEJyc29/LOd6vVixVQWw+Zu4oOZZ+KWFAoT8Pzq4Fdl/8NNb4AYvbx5NoAUcZZaNpae7
         NGNFn/auoXXazcXL3ghwsdaOXO0dvJ9J/he0kESY1a5S4cA2GgEzCdS/LzeC12CexvOk
         7TrI8iOY98W5iu2lw7qJx1vgj5juF8G/SP747nQ+5XAFVmFDBQCacWI2n9lXqv7wsl+D
         0os9dQIN2ZJ1M8eRG5Ldb4rNyTViCnrtbNn/0RDbklLLzh82p91JXAJYii6a0dCnWd5r
         YNxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=EpDWpKhZdhOtwsmF3TYRIb4cOXZLGDKjZ1BlWmXQHcM=;
        fh=WK/jd1sAl7FpKSz3CiGdg697nFFh6m9u1DoVCntcNqI=;
        b=IZ/mxGQ7CKu/mc1mftCmWJQiDOQnGG/lTsLQwOrxKSpUoTtscAf+fibNcAuOewm7oB
         6PBPO1CHFn1h9tVrv1gXXyCD/3acLNd1AQSRunnMNunIA9yEUm215xn5XJMLbZWtf58T
         iWx5q71+cEfJxQB3vcD+0Xyq7nBzavn+c7n7gHKSDuDBGXBILGmYKtw8MDa22exKQezU
         v4wDWB5HtzrZAQ0A4Z+h9fOFT1yFH88V6j/s7r3/Xpr7N8o+81QVCQaPZ24EPtU3Sy2u
         hGcB/qbaCPNIPa3SAuq4nVZIKpwtnjtswXNh0OXVoFaZ1CTGRai+MIgBdUktIMtUD3BW
         dmGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MQ4LrpH8;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728874569; x=1729479369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EpDWpKhZdhOtwsmF3TYRIb4cOXZLGDKjZ1BlWmXQHcM=;
        b=CTV7/5eENRQUDSGeRqMAVBWmom71nw81PGVva8/MLJy0PlmjpMzxUgVn5tIZhs1HV5
         bx3yQx4lV+g/XgQjjeiAIz0hUnYU/gGa90iMt3+OYMHdl4MkfXZnPl/0DCCKWjODxtMS
         LJfvz5dP6XNl+xcbz1N+Z7f8IaK5+HhodbLqc9LpzkcwOA5Yr6vcTugRaNtbsrGqOFmH
         k3wa2zz8kO7dsvtzQ2Q+mvoQl4QhxbU+rRJMvwFrcnLBgAKLB4Jo4YvgUYlb+Y+PxVfn
         WbBITyun0N+JdmdkaagoW+QxtJGEwvwtUDyM+SJHN1hU3WwN/+s0weWEUK78+ACb8Rns
         Xnwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728874569; x=1729479369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=EpDWpKhZdhOtwsmF3TYRIb4cOXZLGDKjZ1BlWmXQHcM=;
        b=CcWd0ahiLNwckddzKX+mOrPpE+vyqeQlTEwbkCniE4WdRR2tlSKPNbtXjnLFxQ3skV
         8gH70ybdaVegnbMCELcKn53h2BZccLO/o/XoaMMD0kb4R0RWxe6z95nfocu2pLY5aIr/
         6+LbBmC5Zp1aks1SRf/vms380LL0sSw/gfNy3XwN+cumtS4AJECeAFpbK33GUbRkuSGY
         tMSzNAlB6MmFBsEJ2oz+qv7YFjYuZfLvVNECAHt+qpod2oExX1QSs6+H8vwc5/NKJX/S
         pUoiKXkGAmKIRUIxeUuY1Vc2N0bw7NsYbW+qEDrZCSAJjvMJ18BNoJTaWkTihc5XEovN
         eQjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728874569; x=1729479369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EpDWpKhZdhOtwsmF3TYRIb4cOXZLGDKjZ1BlWmXQHcM=;
        b=iZztW6npb/MlGp3rvxKrVy6FvnBkg3aL8cBLZ74mIqvdDYcSdYLY4l4DZW/PRHhktS
         IciYsxFJDemSHBlRNzN0zmujkwB7p4XqjCsiQjoRu8Bv02b5WZ25wKaiscUT0ctJ7GUk
         2a0b5aiVKTTzu1yYw6nsRWa38+59dfz+vrGNjohixr5uEQU3O07BbHBtZIdIr1LRpPuy
         Rn3C9h/Qfa3nzjBU1SH6vgtIYwmw1dbqVZ4JLcqBYgo+1zqN23xwuShn9/yz7Vt+8qjy
         NnptPTxaSkmMZC4x3pHYgZ7k2zTJz32WMwATXW5dp4luoIjPtHSMnWFTJd03ZRYiEEfo
         jB9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXodmHun/bYtX6IrVImv4g0BauLn3Ai8jjoC2B65TLsMB2aobTE57GKmbclc6DgsQwy/umNlw==@lfdr.de
X-Gm-Message-State: AOJu0YwqVW41zYv2ddz7rAyNNFlf2yMdPElzL+cP2kLlBoF58VHavgho
	ooAZ+Lw8fySaPDnjd+WsYbMbXay6jDmdNRb2FZ72yO1hUwzHdi/+
X-Google-Smtp-Source: AGHT+IGDnm45On43E9MwDaoBRY67ez0mdWdMMzw6LlFTTy/EcFAIBf3ObscUFECz2emvC7CIdJzQew==
X-Received: by 2002:a05:6402:4142:b0:5c9:60a:5bc2 with SMTP id 4fb4d7f45d1cf-5c948cd14c9mr7223638a12.17.1728874568096;
        Sun, 13 Oct 2024 19:56:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35cd:b0:5c9:29f3:fba8 with SMTP id
 4fb4d7f45d1cf-5c933b49212ls1184461a12.1.-pod-prod-01-eu; Sun, 13 Oct 2024
 19:56:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAAJeDHTMxFqi4cHQcKjHPoZZvaGPXnKOXpp2yqYhMPyw80jTEqEevPJdG3JFYpOCEcWdmYk1NaTQ=@googlegroups.com
X-Received: by 2002:a05:6402:3487:b0:5c8:aee5:9b05 with SMTP id 4fb4d7f45d1cf-5c948d4e43emr7776746a12.26.1728874566022;
        Sun, 13 Oct 2024 19:56:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728874566; cv=none;
        d=google.com; s=arc-20240605;
        b=DVLya1KvYJpAX7+l0hdUcQp99ptuWwm8NwWTFdConYWwNn9GfZDU6XJeVOlQ79Xgyg
         QksmBZ43VUfybrEDT14QmHwWtylVN2PPvDWtqACSFP4Uj1WIbz7u5QOdPCyjcB90rSEb
         tvs7YZiZxAlrWVYAQfMFE3GDLCrCKs+eT0lmjUJOveP/P9J5oMUvkJl4ccm6w2cdtVqs
         iJWdtIdy6O2/TMr4saelIvmmsRaRjwyfd+DK3+R1Zp87G3RdZaGtyHbLxig0ewJcrWpc
         /j1RoRjmG9UaS9Es9kY9nQXQiI0C5BQv5W3OjmhElo6ArP18d0tpskAmD7TUfqwlz8Yq
         YYmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fsia9jopa1EBGuIlree1T5OAe+wj8zghwoJWVSExaNA=;
        fh=qjbKoRrQm3DiQiHzWqdS27OxUedwfoIcr3eJjXvh/z8=;
        b=Snzwe8Ws4RrBEKmDW1gw8YyYVMS6lo8sYN9PURafCQ70scsL1NwDD1Fw/SphUmjBJK
         Hv3aacgfuDKeSQMN8GjM+iBzyBj9bfDyO5qMFYhU18bgdCMb3PjXuhylbc0OgN6RFhxy
         tJL5YZDf/XnBX7bUVtTDLk6v0tCqkB5saSQXRYJb82+MWeujOm79m9uGpeVTlXsbcD9m
         1h25Et6kVfhJHi5WtMGQdmpNxPIMnHWn0ZL7JXB6o2tmbZv5fTgY2KdScajwt5nw8Q9U
         lY/BfznEMHQCDRvC14/ldW9L1KoXcMm2B211iffS7Agybcf3SWmOVNMokyBLe/eY85Kh
         VisQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MQ4LrpH8;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c95ebccfd7si70332a12.2.2024.10.13.19.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 19:56:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-a9963e47b69so604666666b.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 19:56:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXODghN7l3m8LjDY3se2opOhYD5cUi7jY71VyIogEL8oP/N1JRezkfUZ28pZj6nfAlrPFBBa48wVoM=@googlegroups.com
X-Received: by 2002:a17:906:6a12:b0:a99:742c:5c7 with SMTP id a640c23a62f3a-a99b9305ed1mr791073066b.10.1728874565516;
        Sun, 13 Oct 2024 19:56:05 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a99ebdfbff1sm270501366b.39.2024.10.13.19.56.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 19:56:05 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: 2023002089@link.tyut.edu.cn,
	akpm@linux-foundation.org,
	alexs@kernel.org,
	corbet@lwn.net,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	siyanteng@loongson.cn,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	workflows@vger.kernel.org
Subject: [PATCH RESEND v3 1/3] kasan: move checks to do_strncpy_from_user
Date: Mon, 14 Oct 2024 07:56:59 +0500
Message-Id: <20241014025701.3096253-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241014025701.3096253-1-snovitoll@gmail.com>
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
 <20241014025701.3096253-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MQ4LrpH8;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::631
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

Since in the commit 2865baf54077("x86: support user address masking instead
of non-speculative conditional") do_strncpy_from_user() is called from
multiple places, we should sanitize the kernel *dst memory and size
which were done in strncpy_from_user() previously.

Fixes: 2865baf54077 ("x86: support user address masking instead of non-speculative conditional")
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 lib/strncpy_from_user.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
index 989a12a6787..f36ad821176 100644
--- a/lib/strncpy_from_user.c
+++ b/lib/strncpy_from_user.c
@@ -31,6 +31,9 @@ static __always_inline long do_strncpy_from_user(char *dst, const char __user *s
 	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
 	unsigned long res = 0;
 
+	kasan_check_write(dst, count);
+	check_object_size(dst, count, false);
+
 	if (IS_UNALIGNED(src, dst))
 		goto byte_at_a_time;
 
@@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 		if (max > count)
 			max = count;
 
-		kasan_check_write(dst, count);
-		check_object_size(dst, count, false);
 		if (user_read_access_begin(src, max)) {
 			retval = do_strncpy_from_user(dst, src, count, max);
 			user_read_access_end();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014025701.3096253-2-snovitoll%40gmail.com.

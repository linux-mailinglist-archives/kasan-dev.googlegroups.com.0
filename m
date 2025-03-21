Return-Path: <kasan-dev+bncBDKMZTOATIBRB6P26W7AMGQESMOTGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D163A6BDA2
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 15:53:49 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-391315098b2sf945971f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 07:53:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742568826; cv=pass;
        d=google.com; s=arc-20240605;
        b=gcdxwIZPceEtFtQn0YgE+e31sAZOFY3WwVNuexep7vabaQTgE+02TuQP5NEs9VGsbi
         4WTcqFLstxVv2QKHMubA4yModDSKGH5mwf7uQV45hoTSJsm781CFAijGL6OzNxgito3y
         +yZUZcgHjPJdKcR27G3wRCFs2EgRhhavp2yCqZ+iIuw/TjN7fY9IvYiaRbQqbry8iVo0
         1AoXCfdPAYJAbcYKlSzqqmLWiuNvraOmjwrcJy66+HP16pIPOa4EfHJJvv5u/Cw8QjMr
         Yi0WtuB0KyeJ2jbmlu8bBfkTmaH3v32ZBQkVjdzvIkNcNkWbuBfZ/QggoyUt4MzSImrM
         4k2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6Qts5wZv1tlLJG+95CKLLrbpM90l4NPTF33IyXtjtTg=;
        fh=3nCq+OyVLRdWc9vNLWrtXvAgddZvpB+A+XetfWFBCmA=;
        b=kHedzMMJ+s4e/1zf8V9Nqv1aMZJ8F99QsWaRR3MJNfPBhejNQNwjb80ivEwUw2K9p3
         bJUAQIjudmUU2+qyeKBIinxEy5RMclXibGLrh1b93sHUT5Mi8oXLeDsBGMwKH8is5wmj
         YIurXTynPtNFEagBHanICha7va9EyrTBIWfjPVd4ygNiYqhfhhChcn03VcD6BwAu5kai
         2diObe49xFUaFZqRis6k5JqM8a812hLXad8+/ow3p/7wlpFzhD0axUVKbLyUQlSLVHa9
         Tb295mfih6N98Qp/9gESe9vPoMsmtVRMT20zXgrWNbLfQEu+BbTPNAlKRj/q/zu9TCGq
         YOUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b0BM4AbX;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.186 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742568826; x=1743173626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6Qts5wZv1tlLJG+95CKLLrbpM90l4NPTF33IyXtjtTg=;
        b=pY0t+eRx18ibaIGtGVbc4nXztKLdAEyQifmtlGeFUMBXIoEpKcLAdGcHT+AIrOslRg
         5c/ZPunZZXSiO2s6J96bdBYxMyjM4tVR9FX3bbq+qbfQ6vKsKeMiD7h5FK2Syeva0yYd
         46GiHj6z1gE+cci8EjW+S/u5FTvdW1945VodRHeamkH5dlE8kSPSskILzzB3Xvv5W48Y
         5Y5d33qbJIw4vgo3HXhXWcO1OZyZGPxQy6+RtzZGHLN9/8xLX1iMr/9TtGJQP37C9CyB
         hlGj3Clv+G3V+N1z/IFL4y+zNUT+KIDXiaO+blp9FLl4fHGQypE3yJppLHOe8YAY1q0Q
         i7Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742568826; x=1743173626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6Qts5wZv1tlLJG+95CKLLrbpM90l4NPTF33IyXtjtTg=;
        b=oSRUslGAhImL5S6wgK54SWseRXnmVZZuZAD5GGWvowNqBKesiT7RiUcnIhMAY0w3sp
         7DwurF9eOq7dMkL73OxMC5L/wLNurznO+jfpFC6vZra624F7dchdKgM+kAPhfe3oLg3X
         SpGXS9pk/Li0chFnZVOPlF48ZfHU5OX1XYCz3wrMtX7wc6e7GvSjNlkjDl2kymLLtet5
         FLeXzMLaw5vwvyiPNAUk3fKj3kETz8O2BIiuEl5f0Y1nP8uq40GKcXCd0LZ2eE6dia/N
         mo6KSBJOgG3IRza15/xDpSPC2jZ454HsIFVdEHPuWLrJ93/nb3xD165WJO5q0SV6WR7R
         xkgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX62Ey414ByUG+ki2yy5jWU3qydOXliljMbzzh0CA473kHJotse0Rjyhn5W5y/2mhnDpyXdBg==@lfdr.de
X-Gm-Message-State: AOJu0YxQnGAOIe2dqVMeLWOIFmoOn9gWv6+x78MAtDjtk1Je/gE39Vw2
	9loGKD1mTj2DDehqp0hWH+535SWTA6vhEDhaID4Tj3j1YPFCotFu
X-Google-Smtp-Source: AGHT+IHVYGafXfScyPGsBKrRWP+xS3LYWoJpfpvK52G50r9HC6VCV5V5iDguBnf8UqDoEzt9I693Ow==
X-Received: by 2002:a05:6000:2107:b0:391:10c5:d1a9 with SMTP id ffacd0b85a97d-3997f90a3f9mr3473875f8f.31.1742568825590;
        Fri, 21 Mar 2025 07:53:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKGQl+USCxQnMA9yeHT1uX49xl2RhcRvRR+9OM1gfzoUA==
Received: by 2002:a05:600c:1d10:b0:43d:41a2:b75b with SMTP id
 5b1f17b1804b1-43d4926234fls2309775e9.1.-pod-prod-06-eu; Fri, 21 Mar 2025
 07:53:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvDHWFdqTyWOKajf6dg9r23Nrds4R2ff4g7mPLvE9tjbgbcYwlYMuVRSdBsFbkytZCHmNvXefmseQ=@googlegroups.com
X-Received: by 2002:a5d:584f:0:b0:391:487f:282a with SMTP id ffacd0b85a97d-3997f937456mr2843330f8f.50.1742568822654;
        Fri, 21 Mar 2025 07:53:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742568822; cv=none;
        d=google.com; s=arc-20240605;
        b=VVZuCyi3F4ZdJwj8+mf1pk68EK//Ib17X/LbyZkMwz1r9wW/Ngcqx3Vbm+IMlxwmwK
         JstttbnWXhmn3gZrSUQdhXOSEEL9zxHXXXahpPQ1wLtuL1ArfAFDJ+m73qH/t6mUUDds
         3BhxYB1ivj5l1fZ+riYcnj6w00Tw6ytx/Bqfx2z1cAN6eHAFO7LdAmNUhdRWagfJ39Ok
         tLP+WzoDJSx0PEP2on6yllXNAO4uNWR66FAqBNL1M54qQDaxf8G5+YTuOUDv/RlhKNHV
         JZTcYdP2FepDmzJlKq8tc3m7iK4SPyT4AgACAjeCgbeWMcVJmDpE8Wydt/HvXhVlNrzn
         rxJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lzd/7/JKU/c3Icezkw7Y1lUshd2vVlPciFxWV8Fe+Kc=;
        fh=eQVvRnaowjFhecodQw9rb17bJq8PyzUXPk4LtBZjfdA=;
        b=R7Gmg37MwWGCFZ2TW4HNoklMCHX/f+urfeXywygpGSm364XWQM35nUVHlLUy2dC5we
         HtHjz0x3RA39zXkgF6tbE35pUjXU34XPMXgkiZfFKpOXV9ryMTTWdWM5g03vQFRur5Zb
         0X6AtCCw/HvsZbnfYuA7Z1C3Y56JDfrbDGhs6JbrQUK4Wr+VhJFUTRJH/BgqZmu6USrE
         Ps1g0BnQjiK+wNmBSKAu0z5x8ZYwY0Jy8hgIokNT828EmrwjW3MkMfpJ6ySQ288kKmQb
         TSzQDgSyl+zrJCezgpckNLnrL8oovEJBIDIDEvMbFz4fnDAhiNDxIRohxWwgnIM+VGD+
         gBiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b0BM4AbX;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.186 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta0.migadu.com (out-186.mta0.migadu.com. [91.218.175.186])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3ad387dbsi4511325e9.0.2025.03.21.07.53.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Mar 2025 07:53:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.186 as permitted sender) client-ip=91.218.175.186;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: 
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH] kmsan: disable recursion in kmsan_handle_dma()
Date: Fri, 21 Mar 2025 10:53:31 -0400
Message-ID: <20250321145332.3481843-1-kent.overstreet@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b0BM4AbX;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.186 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

I'm not sure if this check was left out for some reason, maybe have a
look? But it does fix kmsan when run from ktest:

https://evilpiepirate.org/git/ktest.git/

-- >8 --

Without this reports via virtio console recurse, and nothing useful is
reported.

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 mm/kmsan/hooks.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3df45c25c1f6..5034cba1feab 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -341,6 +341,8 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 {
 	u64 page_offset, to_go, addr;
 
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
 	if (PageHighMem(page))
 		return;
 	addr = (u64)page_address(page) + offset;
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250321145332.3481843-1-kent.overstreet%40linux.dev.

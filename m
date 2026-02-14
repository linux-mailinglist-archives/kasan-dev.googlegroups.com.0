Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMESX7GAMGQEDMVDULI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wPlLBDPJj2mZTgEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBMESX7GAMGQEDMVDULI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Feb 2026 02:00:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A12EB13A3C3
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Feb 2026 02:00:34 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59e57bebcc7sf1060871e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 17:00:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771030834; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fiu64vdLPJU9im65UGuyAyeLD+R/d0aIzhjH0DBn5k1nZu8F9OjqK73YZBaOhjb1n+
         TrDk/hjMdtkLaO2OcIk70ZEq27agSft3U7rlxka39A4kdVorynkua1RjAhT0fDFb2R9E
         UXJ4ScgVYkjeMozww5k7t/1Bwt4IjyUcBCAyyL21p1P4rLE8PnXSmsM7YRTSK9KrOmPP
         7sIgrzI4Pedd52zVytczrI4xX4RBl9VLwFry1K8ilBw28kL+9Qw7Lt1QZMBrrEl8pE23
         krq9/O9nAcF40j5/sU97rIXVCx4nhEdRvVi64qQvzoAgWk0MfJUB33W4vvkkdTxFZTRO
         3IFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=8A2GbmgqyFJqFcZaAh/6ciGM/n/Dn2Qa/51rEGfx1S8=;
        fh=OTtCKy9HKmPu7SktpA3SjyC97zI2dLHCn+WvyZp31VI=;
        b=VhXcKppn0z7NHR++kdyOhqPDoSNw8LZEjLOnOtlPCmYmwEPeWqie4hCgO6cxfuNVfe
         8WpElqL/goIe7MdTArlgxZ8kyqEKHj+h3rm/X2gk+wA6XgnXYh7ZaIxnPFwH38nyeX1E
         kDOJ4MHJAGWbEXAKAUxBp60sABnJcLAImsw/zcjmAC6wD3LA5TsovUl8P6QR6jda09zC
         M+52+PrqNYNOiXySI5Xv5z73CT+++LDBveahik72h1ct0yjmulWscbE/m5B1IQ67JLfh
         C6y6pTUKJvp/TyWx0U/DBHQD4G1nZ1iTcikl8UMEfAW90xIG6XiNqlsjnu46USFJNDDN
         oDTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TO2hpxFb;
       spf=pass (google.com: domain of 3lcmpaqukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LcmPaQUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771030833; x=1771635633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8A2GbmgqyFJqFcZaAh/6ciGM/n/Dn2Qa/51rEGfx1S8=;
        b=HqDeBaFHpkJoAORyO921oFunL/31Qp9gzuDEMuVgBc4JU7CiZoW97IJ4hExeLRloeN
         DZiNIsRh8sHoLsN2dLpiaJCnphhJ6hGWEcOEsw7oGIJeJoiiJUzBa7oAyrBb952pQ9SU
         0dEmyM3e1EWFINkxSoRX+X226qNJ1hQBAVgHD4kolZ0CIi67wMVMJVkUE6SZz4Xo74qw
         34xr7hWIf4Bb6Nk4Qz5OnF2ywl/xOM6t3rRFxZRbFelCfkQhWC3xiEQRWTW3RgU/oEpc
         ogauNHK38t2yOKg9f8aIukHjMA9YW0QNtKVViC7h/PBq7fW3OCUzkS1MP/okT0W+zJnO
         H/ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771030833; x=1771635633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8A2GbmgqyFJqFcZaAh/6ciGM/n/Dn2Qa/51rEGfx1S8=;
        b=teHSD77lxmO2/19XTt9Hu4LJw8iPqBBj7N4PvxgKoyTgoEL3ZJ0lyYAO9J7owfIo+i
         nvVYoBLs9+87EkTEjnuHqtbAsQPYmYoN5fXlaAXJm+hli0fkTTaHoDiJ9Aeci1EQ4Xt3
         cWlSSnTovHwLIhk2QZ0GTWBoDS7FNMiCh6vxD0w2k1qR74uQfUmOUY1Bioh+czsvz+QI
         uRyyeYgCbCc18my7PkGIlADTGvBmfHX1l9cW28g1GDLycXoS3DTDHHM/g+G8JOxFBG+u
         3figJchimgqz8WhFL9bqA1hZgtYDMzySi8mqE/t8s5ilTerE7Yz80ToMOnJ/gOtiC5qx
         TPIw==
X-Forwarded-Encrypted: i=2; AJvYcCWWDmpYH+LgHCsQ/mS26nl5XYUuJg8uZSxw5FIwzq+3kRs/GtFl6ztHBMCs+73rQPFGUR3xTg==@lfdr.de
X-Gm-Message-State: AOJu0YyqdBbt5v05qyDRNF4KReIEjvol+BPGYt0Vb7LyeWE4anexO8ye
	WqCyFEuph33Vpue+z/ea+SP/QE4i9NDwLEHJoNF4oHDvGOFjjOMJHmfX
X-Received: by 2002:a05:6512:1592:b0:59e:62b4:a248 with SMTP id 2adb3069b0e04-59f69c5cb2bmr1209266e87.31.1771030833174;
        Fri, 13 Feb 2026 17:00:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G9aK+wYPKugrKrsUa1yuFzf0PmJM5FdFKrB1JwIjfrCQ=="
Received: by 2002:a05:6512:23a5:b0:59b:6d59:30f5 with SMTP id
 2adb3069b0e04-59e65223723ls798738e87.2.-pod-prod-02-eu; Fri, 13 Feb 2026
 17:00:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXzGxuRiu01E2R4MFy8RPK9qI7qz6naO5wxk9arcDcZFf2EEuDeLvlzDLeHKk4OLz/UbKbT7tjZ4eY=@googlegroups.com
X-Received: by 2002:a05:6512:2248:b0:59e:5d0c:e2 with SMTP id 2adb3069b0e04-59f69c5ce41mr1150899e87.30.1771030830339;
        Fri, 13 Feb 2026 17:00:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771030830; cv=none;
        d=google.com; s=arc-20240605;
        b=g7Eh2KIqQRcNFr4xYOrVefZ5jfsS+HV0DlDAHF6WcdvWYSJfPBHAiIJ/9vb1Cl9bFz
         1BVEaDVHBBVTuwPWaXuMCX8dTvxxWsp0jwzCSnssR17AIpDFZvLqBGEPM+X2Wl7PvnKH
         fn8206frYGb1h6L9i+2+nIBUy5tsQoehgMFtGTw2SPV7KPtbzFcgzIVh8k0lVMVHx5Oq
         wiEdzOrp5Yh03U5lx82ZGBo2rTgkAEt1fSGmELt49hE4hj4N5vtQTVsBjLlHD0T5VaPP
         z+zRDh5z7nJ5urqsbNj1F3s5GalviSehGSti4K5eweSeOhDfDqqeSw4QF/lAVoQc57sc
         Pqfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=N52x8JQ9Owt92Dd5wyBCJma3b4DEePYMVk8MRoPWKBM=;
        fh=P+s7snsVQIzbLkPLjlbWDhmJm1a+hdsQ7dqGe4fekE8=;
        b=YEOlAuKC29t6usVbd5frxfzzqrr8Nyg6IFf9Qh4Dyw5gKSkPTNYyaMYAsMBJlxILGT
         RXuTkqBz5tb97+RN1oHHn28PB7QU/LtaPKqgHKKPJ8DSbkfZzNm+6GNn/ec3Uk1lT8AF
         xsyNlxLWsYrA7iIIlhYpcZvU1P4Vz61bEMKKQBdt3cfz0xsEHCYzyD6uRYSNrXtvczIW
         ST3G7UFuI6EU+N0kbSbDC2My2E5KkYU79r/Ppaj8hbPmB1hsnWkJ2SnckEOWa2z+Qtdy
         oxpcU9w3SWKQERylysV9YmTpaN4bJIyJMdOptbkTNlKoAKdCtogTtL7fXhl1rRMsoBvy
         4cCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TO2hpxFb;
       spf=pass (google.com: domain of 3lcmpaqukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LcmPaQUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59e5f51fc74si209824e87.0.2026.02.13.17.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Feb 2026 17:00:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lcmpaqukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4832c4621c2so16183315e9.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Feb 2026 17:00:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVlFv1Kr+Y6rENLwdXpePbPjNw5mi/YjOEu3W4jZrqQ3dnj0rwhUKWaiH3cFPd3c+//GsbmbXLf8XI=@googlegroups.com
X-Received: from wmby28.prod.google.com ([2002:a05:600c:c05c:b0:480:3227:a124])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1c1c:b0:477:7b16:5fb1
 with SMTP id 5b1f17b1804b1-483739ff8damr66109275e9.7.1771030829456; Fri, 13
 Feb 2026 17:00:29 -0800 (PST)
Date: Sat, 14 Feb 2026 01:57:51 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.53.0.335.g19a08e0c02-goog
Message-ID: <20260214010013.3027519-1-elver@google.com>
Subject: [PATCH] kho: validate order in deserialize_bitmap()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Alexander Graf <graf@amazon.com>, Mike Rapoport <rppt@kernel.org>, 
	Pasha Tatashin <pasha.tatashin@soleen.com>, Pratyush Yadav <pratyush@kernel.org>, 
	kexec@lists.infradead.org, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TO2hpxFb;       spf=pass
 (google.com: domain of 3lcmpaqukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LcmPaQUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	MID_CONTAINS_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[9];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBMESX7GAMGQEDMVDULI];
	HAS_REPLYTO(0.00)[elver@google.com];
	RCVD_COUNT_THREE(0.00)[4];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: A12EB13A3C3
X-Rspamd-Action: no action

The function deserialize_bitmap() calculates the reservation size using:

    int sz = 1 << (order + PAGE_SHIFT);

If a corrupted KHO image provides an order >= 20 (on systems with 4KB
pages), the shift amount becomes >= 32, which overflows the 32-bit
integer. This results in a zero-size memory reservation.

Furthermore, the physical address calculation:

    phys_addr_t phys = elm->phys_start + (bit << (order + PAGE_SHIFT));

can also overflow and wrap around if the order is large. This allows a
corrupt KHO image to cause out-of-bounds updates to page->private of
arbitrary physical pages during early boot.

Fix this by adding a bounds check for the order field.

Fixes: fc33e4b44b27 ("kexec: enable KHO support for memory preservation")
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/liveupdate/kexec_handover.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/liveupdate/kexec_handover.c b/kernel/liveupdate/kexec_handover.c
index b851b09a8e99..ec353e4b68a6 100644
--- a/kernel/liveupdate/kexec_handover.c
+++ b/kernel/liveupdate/kexec_handover.c
@@ -463,6 +463,11 @@ static void __init deserialize_bitmap(unsigned int order,
 	struct kho_mem_phys_bits *bitmap = KHOSER_LOAD_PTR(elm->bitmap);
 	unsigned long bit;
 
+	if (order > MAX_PAGE_ORDER) {
+		pr_warn("invalid order %u for preserved bitmap\n", order);
+		return;
+	}
+
 	for_each_set_bit(bit, bitmap->preserve, PRESERVE_BITS) {
 		int sz = 1 << (order + PAGE_SHIFT);
 		phys_addr_t phys =
-- 
2.53.0.335.g19a08e0c02-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260214010013.3027519-1-elver%40google.com.

Return-Path: <kasan-dev+bncBDEZDPVRZMARBZ5SY7CQMGQE2DK7LXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EA4B8B3C11E
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 18:46:32 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61dc9b82764sf2457182eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:46:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756485992; cv=pass;
        d=google.com; s=arc-20240605;
        b=bR7/AVbCx1uXGHV6rULtrLcee4osdQLp80jIeMJJYKQsgSC5GDz1PSQ3avH5FEiswy
         /Boulo4neD0udjpt++A6ANkXs1eFPICWgqZJ1Fg7tNApVT3wu0RwBrbmNbkPbUmcDWjP
         ld9FhoNsyopz9o22QAGISDidyxPJxhXNQ9rNT3+JvcK00gZbm/b8yQZ9iTnR2YA3qfXK
         7lxaurtHG0cAIzCmGzh3Vjsz6HX9DJpfpCAz+vxclU/wJiSPdpc5nm8zYndAgiMr+Flf
         N/wX6QlgeV3u1vNqPXoJJpxHpn8XlKN1LCwxAOD+pjcFXSks8lyOMpje6q5hlZisFijU
         oQYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=48DZ2tzXjI2xYaSLks5D3XH9pwgzbJ5eJVa/N3xMMZA=;
        fh=14zXwIr7RaywgiwvQjjZKREX8iNw1/iWLBTd3z7YAZc=;
        b=TE4U0lQa+2tgqXxiL35wrhnOhvnh6lHcVQT48OUpupJaVrqVaxRvwSHDi2yC/+RxI8
         f1URQVUMKl8gLdz5L7TjDE8J0lpbGjYTvm9bMftwJEX8eb+Tz3uPvT82/MNENsdq8bfV
         blTJzL7FBLx54eL1+AmNp+jFMIPTpkycrRYq+4UrSavINW/JWhs1gjTG22YOZU3Kz5lx
         s8v+eJf3D6utbXBAEZJ7N+X2iie+dbXXXYdTGIB799sulh9nRpf+JuOdPpHfKTn9g/WQ
         UlyjZu8ToGsn5e0fmmQwi6kzrhcia4hpLKBw2DvasgfxzogfXbUsn2c6qHs8dV6YCH4K
         Yhnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D7s7Vq4s;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756485992; x=1757090792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=48DZ2tzXjI2xYaSLks5D3XH9pwgzbJ5eJVa/N3xMMZA=;
        b=Ai/4V++c9KXpwQhMihEkushBWXAl6+/nfpodkJxDxipkcFKrGt5kRH3B/S2+5dqKW2
         /j1VtMrPWRyuHjwm5T3HuMsP70cMkGCtdnfTb/HdS0ChlK6/UXRWlfqW8YfhTu0c2I4J
         vwLWHhFh7/5LR0eJIUAxFbT81j8UNAHi1tEvi+8QYVP+DdPrkPZQh23TXIgIeu+7IHJv
         C+CCWmjMBHnHCKbKZ/KyQXPx5cSZ0X6rX/3iZP2xatFzf4w+iHraPLtK2ST2fCqfe3G1
         CSrV6FahL3g73vrotBLOeg+W7aAnFEew37AJb06fIKjaXnhbGskdQ3zAvxORIoZ5le1X
         Q/WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756485992; x=1757090792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=48DZ2tzXjI2xYaSLks5D3XH9pwgzbJ5eJVa/N3xMMZA=;
        b=ah1+UcFLd2QuXfUOmc28o3h8wtCznWGsLunWXfc/xHWpQ8gJhTuL+yovU87eOC6meY
         XhtDJaCrRTmgsdrQ7EqJQfxYzAklq2A14EhefrtlWiL8ZdmILPJ/ueKkkufK+pmdw/A4
         HmVQlJGE5hb0+xbfH0VUEOn74/QuMAhW+WHMHHiq5kdn7oZGwf/gTKQ3++1mjnIApdwL
         LIEz7ajbMTVVW49kfi8moupzjAy23wACIQS3EIjq0zbcL1LcFGsl3Gk+a3qf6YaMDuYk
         GwjYkM4sno9f3XXwz+Qnwgl5BbibUrkps3idyLmV5cL/pXKmUYvLXDFluzmscs1lDvn1
         7DvA==
X-Forwarded-Encrypted: i=2; AJvYcCWu32XREXoRYEOln2g3OcUdjUclWihC8okrX4QO8zxsdJDCMEXpDlDSCVgzvNcgInQTGdDuqQ==@lfdr.de
X-Gm-Message-State: AOJu0Yya4Ay7JUXZpztFStqWgAMdlWhHFM9lHkKJ18sYBvqEHRYLqZZA
	FWWsKijLiCJ2FIbzsnq9dWzStxtx+um4QU7e0yiEHqNplBlY98um40DA
X-Google-Smtp-Source: AGHT+IF9veogmjZz3dMoS/E/sUWbm0gu5odOQJI7HO4+9+KqFWx3XnAIvurf0mXcpIY0zUVAVjfyJQ==
X-Received: by 2002:a05:6820:2304:b0:61e:16d0:9ea2 with SMTP id 006d021491bc7-61e16d09f7bmr3394043eaf.3.1756485991447;
        Fri, 29 Aug 2025 09:46:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1SFKoK6azMsffKtWvNKFnWRO3A2EfJPeGwPNZvnp0bw==
Received: by 2002:a05:6820:4408:b0:61d:9c62:11c3 with SMTP id
 006d021491bc7-61e124ea39els523436eaf.0.-pod-prod-00-us; Fri, 29 Aug 2025
 09:46:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWa5qZurKaFeBEm52QBzRzOn6QVIzS5O5JHtGGe0oYUuW87I2lJVnDz/jXvFOKSJwC/HLXDOcohhuQ=@googlegroups.com
X-Received: by 2002:a05:6820:4181:b0:61b:9bfa:593c with SMTP id 006d021491bc7-61df78900ddmr6069292eaf.3.1756485989871;
        Fri, 29 Aug 2025 09:46:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756485989; cv=none;
        d=google.com; s=arc-20240605;
        b=FmoxIW7ncU+/9pthCv/X6Afm3UKXxely5CeXacJ2N5JzJSAbE0OoDQ+bHmo50Samyy
         C4BeGj9zaLg8cQW6hLOLQ+26qHx+tZqQU2zXOrDsfttKmG3Q7wL7utP3bBcuujOa5yo6
         EBRk/g7eP0kd7wgiv/qXXAZhOs2rnvcq6GUYxdH9K8hJxUgtId/icmRdgQkOdbYnLFnb
         g8doEU7W1+N5n7FnvTX6yfNge+0e1EpXzQ2MOX76OVGfGEmv3t0DMlbWj4fPEmdHMAUk
         LQCJGZCrxY5q1WB78uwS2XLKRN5PoEXOcgAQZeFIZ81+QfLgnXajCGIemwC68reWgovP
         0rxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZncrKmkfYm0ifrU3KUl6vWqS0G4T0Q5iBTPG1MeBPms=;
        fh=oO4b7IAYxhiiXhWty/Cra9qYmXRSX03jv+l0QdgpWPA=;
        b=b3qb5ioLAMVJGii6hSD+m+7/pFm+JHIEER8OXgzqa70VSIElb2ypsz9QunrPxTBfTH
         imhM+pWQg/9TmzWX6RE1bLKR7pofv0S30VX8RXViygczd2ztmK3UtByFGXx1t2mHjgCF
         3adsHkycQX8Q9PJVHV77wprY8KCGNCjTbn+N+RWVJXrWI+11mAm3z7yDKnsiQSncKRjq
         NgQLcWIqejPwSWd3FAPMTePo8I4bekUdF7VCrdZcfjmVLldRsvGybbZA4JpXdAdN/6CW
         5tU5lAWx1MJ+GruDOoxEITBDIo563AncihCtibA6w6Fs9ye7errEsW624cYLz3cUHPYP
         e9ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D7s7Vq4s;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e2228d099si67051eaf.2.2025.08.29.09.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 09:46:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E2921601BC;
	Fri, 29 Aug 2025 16:46:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4098AC4CEF0;
	Fri, 29 Aug 2025 16:46:28 +0000 (UTC)
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Cc: Dmitry Vyukov <dvyukov@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	Eric Biggers <ebiggers@kernel.org>,
	stable@vger.kernel.org
Subject: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
Date: Fri, 29 Aug 2025 09:45:00 -0700
Message-ID: <20250829164500.324329-1-ebiggers@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D7s7Vq4s;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
kmsan_internal_set_shadow_origin():

    BUG: unable to handle page fault for address: ffffbc3840291000
    #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page
    PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
    Oops: 0000 [#1] SMP NOPTI
    CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G                 N  6.17.0-rc3 #10 PREEMPT(voluntary)
    Tainted: [N]=TEST
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
    RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
    [...]
    Call Trace:
    <TASK>
    __msan_memset+0xee/0x1a0
    sha224_final+0x9e/0x350
    test_hash_buffer_overruns+0x46f/0x5f0
    ? kmsan_get_shadow_origin_ptr+0x46/0xa0
    ? __pfx_test_hash_buffer_overruns+0x10/0x10
    kunit_try_run_case+0x198/0xa00

This occurs when memset() is called on a buffer that is not 4-byte
aligned and extends to the end of a guard page, i.e. the next page is
unmapped.

The bug is that the loop at the end of
kmsan_internal_set_shadow_origin() accesses the wrong shadow memory
bytes when the address is not 4-byte aligned.  Since each 4 bytes are
associated with an origin, it rounds the address and size so that it can
access all the origins that contain the buffer.  However, when it checks
the corresponding shadow bytes for a particular origin, it incorrectly
uses the original unrounded shadow address.  This results in reads from
shadow memory beyond the end of the buffer's shadow memory, which
crashes when that memory is not mapped.

To fix this, correctly align the shadow address before accessing the 4
shadow bytes corresponding to each origin.

Fixes: 2ef3cec44c60 ("kmsan: do not wipe out origin when doing partial unpoisoning")
Cc: stable@vger.kernel.org
Signed-off-by: Eric Biggers <ebiggers@kernel.org>
---
 mm/kmsan/core.c | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 1ea711786c522..8bca7fece47f0 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -193,11 +193,12 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 
 void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 				      u32 origin, bool checked)
 {
 	u64 address = (u64)addr;
-	u32 *shadow_start, *origin_start;
+	void *shadow_start;
+	u32 *aligned_shadow, *origin_start;
 	size_t pad = 0;
 
 	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(addr, size));
 	shadow_start = kmsan_get_metadata(addr, KMSAN_META_SHADOW);
 	if (!shadow_start) {
@@ -212,13 +213,16 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 		}
 		return;
 	}
 	__memset(shadow_start, b, size);
 
-	if (!IS_ALIGNED(address, KMSAN_ORIGIN_SIZE)) {
+	if (IS_ALIGNED(address, KMSAN_ORIGIN_SIZE)) {
+		aligned_shadow = shadow_start;
+	} else {
 		pad = address % KMSAN_ORIGIN_SIZE;
 		address -= pad;
+		aligned_shadow = shadow_start - pad;
 		size += pad;
 	}
 	size = ALIGN(size, KMSAN_ORIGIN_SIZE);
 	origin_start =
 		(u32 *)kmsan_get_metadata((void *)address, KMSAN_META_ORIGIN);
@@ -228,11 +232,11 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 	 * and unconditionally overwrite the old origin slot.
 	 * If the new origin is zero, overwrite the old origin slot iff the
 	 * corresponding shadow slot is zero.
 	 */
 	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++) {
-		if (origin || !shadow_start[i])
+		if (origin || !aligned_shadow[i])
 			origin_start[i] = origin;
 	}
 }
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr)

base-commit: 1b237f190eb3d36f52dffe07a40b5eb210280e00
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829164500.324329-1-ebiggers%40kernel.org.

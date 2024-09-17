Return-Path: <kasan-dev+bncBDGZVRMH6UCRBYXAUS3QMGQE3UAB4WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 395E697AC18
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:31:48 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6c5b440309asf3912046d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:31:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558307; cv=pass;
        d=google.com; s=arc-20240605;
        b=CpKgpvLqXbxm1IcsINxjtR7PjiO51V0El5cqg4sACs01uK9/V/eJd06ragqG/7kGje
         G02rWIcZ8zKpnc0h9kNNkopbll8J0ZOokMD2u6DACrgNHbsl6xDA1uHvtjWqfxleKlQg
         fBglXJ2I7Y7rIwBqrvOZZ0qtQrYhIMieK1EQcAs0xS+rOXVtdbkL16FSrr0zGxZb7rA8
         MLtgyUJYPaFmJ67oDQ2e8wR4GPsrwsCU3zwMtAiFsnH1cV6dbJjR41EF2gl9GXZXo2tj
         ogDprKn8gdMLgo5rkC6r7OiMPQzhvwZufzzYLwUl9TcbCYwgkwaof57hdJuCaEKUHzn2
         VOYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kumUFwoxlW7tb4iV+FpN7W88Z8likS2fV2P6+1HoE48=;
        fh=05DPpchg+7mGXaDietCDuDGc6eG/U/mgjvxHWxn7Fiw=;
        b=K0YG0VHPlSZSKLUOb+E6debFGHqzgg29IrKfLNlBvTziWyQ56kc0brz3LHyJyBGjsy
         HBotVbVLkRhiqllbIaIGLVMQRxaTsxD7myKHU/jtGmY/8d02FIxNSuxo8+GaUdzVmzAz
         UxvzKWJEWJdFDFGCb9F1SzgJIrANWNCRMNtuxzltZmXOHzY7meiM5W2xLbloQ1cptlKd
         rSqGMQuUZ901aVaiM69MK6fc3TyGdJjQV2FFwjxaX0hGFS9TQ6fJOjWoeWVX9Lcbcoq1
         hKIcmqD/mZBIZRTwDEhlVcKi+ibye2DOoj7vufh21YOOgjHJvsjKOLrUeZgfk7h4A2gm
         48QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558307; x=1727163107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kumUFwoxlW7tb4iV+FpN7W88Z8likS2fV2P6+1HoE48=;
        b=HguGPb6VHJ+Xn/DSWxnh5Pc7OdPRZYVrh8nnpOQX5D2y1h/BEOAgQndmEAd6OVEsN+
         HDuDTj579Pee6/+9VoQ+0lI5+cFkvATZq/ZkZmiwDctH/QVxM2BFG0eLqd7RTdSI9i6V
         a7i1JgV29vLvaYFSOBowtAO8eTdyINvHuXIv+74wMnYi6CMovqqiCdNFOu4sZAAW7bTk
         fOx6qiIJ4jC1OnNX8Z9UCwzSAQwJ2M6ZyJHcWYekNyOKqV3TLKUVwh7ldJCM1IgcWuFX
         uX3FtxDfzl7Ni5QgOtXCptYPgE9f03l/hz6JfrD9VqdXrL+rUVbtFdyBy8omdRlfvTwu
         AkLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558307; x=1727163107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kumUFwoxlW7tb4iV+FpN7W88Z8likS2fV2P6+1HoE48=;
        b=HtsqWt/arpCD71/5GBIy2mhvYDIJQ4Lpp3Dzqt/H0kOT9xjt06yl4ITyUAYqFbTEKC
         feSWSDzPb40mzK4sDpkZl2xRWpkmpdeAcanCVCFearKtkxwwUSJHDgSPPCczc1jHFZPk
         LLTh9iqPNRPn2cb8XjrWHzc0cIGtzSEQ1aSEjnrdkPbf4wNXCKQ3XSEvn8mqr4rHJ73/
         PxWfWNJmMUuhlfwRfVWllhqHcFaTxnKP6cx4sDc9mHFUQaoE52ZoE7PEvwOteyeuebR0
         +9l/8FXp5YJ0rnjdCTgWqOPjGbdtQwSmFk1rSlM6xWc3z5LdeenWxl5qxMYiIxMn6w/l
         2ErQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbW20MUVw8wWCYwRDdpgiEPRqa9JZwR1jmKxE5OkvdBxhiAr/Wg7dRuIy0qEX3ksEgxmdnYA==@lfdr.de
X-Gm-Message-State: AOJu0Yxrq4XVDRWzkx8Fk62IR5y9jAXVHrSG0KNd1mjJsthOJK/5/ski
	dyI0EwSTpg0ikbpzVF7ewoIS80+iM9Gd43FMg70CXJ3sNXVAKX5e
X-Google-Smtp-Source: AGHT+IGjp9s7GKum9eiuAsOrwOw5IPbMf41W2JbB5NaOhoVkH/oBRB8KoCrVTFL1B3MMU4nnayFV8g==
X-Received: by 2002:a05:6214:4806:b0:6c3:6560:af09 with SMTP id 6a1803df08f44-6c573a26148mr359587956d6.0.1726558306858;
        Tue, 17 Sep 2024 00:31:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5f4f:0:b0:6c5:1cfa:1e03 with SMTP id 6a1803df08f44-6c5734f142fls21796436d6.1.-pod-prod-00-us;
 Tue, 17 Sep 2024 00:31:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2lhyzuna+OmvbrMYyFyLxOK7hQ0xJiuPmF7rzjk60Wv88y9WSm+Ht2TgUxX+6YH5OUjunglXQmLk=@googlegroups.com
X-Received: by 2002:a05:6214:3c97:b0:6c3:6414:7172 with SMTP id 6a1803df08f44-6c573ac9044mr310450476d6.9.1726558306033;
        Tue, 17 Sep 2024 00:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558306; cv=none;
        d=google.com; s=arc-20240605;
        b=MXMVkKFifDWCRoTYfBE3XWBVCCAsTa8+HJiLfN04lemJWbtqjmHQZqLBJW8hjPZmzn
         yY266eUKPdJOAyRBK6gCfuPvriljFBDI9v3tUabDSz2AhVf4m4KyT/tuj+doUQ7Wg994
         LElcReLtrhvJOoG4kaPkUTvfYUbbCLQFzyTh0z0p6BSF9VJO3jWehFlnDPbyHvARAQJH
         Q6qeF7rHIjiHY9AcRwFwT4jNvmWaLKd9M/ZKqkNbgaVluQudOlv3rmF8+7Hb+oZ+wpYo
         5wfVBEPEXn0FaHtuMVHW6YGxS1btpV9vEWc/u64yckf7oQHg6bm/cAjfQgWF8OJIZip9
         Fwbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WBPoMFgWT2ZiqZhDgBB8E2TVvrfOMNhXDz2ju2nc0jk=;
        fh=UQNaMAYHGrpcz1A3KIVW4uNQRqY/Xs/Tgi5PZeMplwM=;
        b=Hoy1Nw9v2fYySwnZ5elg+0t1hmRCuH9k/sPwy+r9Z0UHJuZPBS9rSwyk6cHjapUpp1
         wbSdpJk5loTs1bNOXXRD4kFSJkew6ewQdE/17SbI+TDAmy39awpvfaOc744Pezm8uC6X
         97s/jlXk3/sFUDs0DjKhwtKglp688oW+F13r1HXIm8TSBTG3TrB7hlM7GBERGizdy7Yz
         e6THZEqXA+I36CqvGGcq0/NhsiuWy7gizClz3IYlv3Ws92ATa0r69Hcq+peeuV7L5T45
         2+ieHNbfaZWNeqRldlCtv19QHWZKNXBZHGDetRZs7px1yZSJ8dXbVLkyY2eC00Z43AOC
         eChg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-6c58c7f6e59si2696686d6.8.2024.09.17.00.31.45
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:31:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0434D106F;
	Tue, 17 Sep 2024 00:32:15 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 11DEC3F64C;
	Tue, 17 Sep 2024 00:31:40 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Subject: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
Date: Tue, 17 Sep 2024 13:01:13 +0530
Message-Id: <20240917073117.1531207-4-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240917073117.1531207-1-anshuman.khandual@arm.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
also provides the platform an opportunity to override when required. This
stores read page table entry value in a local variable which can be used in
multiple instances there after. This helps in avoiding multiple memory load
operations as well possible race conditions.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
Cc: linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 include/linux/pgtable.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 2a6a3cccfc36..547eeae8c43f 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
  */
 #define set_pte_safe(ptep, pte) \
 ({ \
-	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
+	pte_t __old = ptep_get(ptep); \
+	WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, pte)); \
 	set_pte(ptep, pte); \
 })
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-4-anshuman.khandual%40arm.com.

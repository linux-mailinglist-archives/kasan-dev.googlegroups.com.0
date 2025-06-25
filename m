Return-Path: <kasan-dev+bncBDAOJ6534YNBBGUO57BAMGQE4ZJ2PFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E12AE7E18
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:34 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32b3162348fsf5592791fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845211; cv=pass;
        d=google.com; s=arc-20240605;
        b=AoUtQQVMYqRsGFeM3DiFMogCGU4HHyKMCEY3ekmsYfnKG8SC2nvFsipxXL2iSz6sny
         BAL5j65tZI642lWTlQLRdqDJ/q2IUgPXYYEjP2uIEyJ8XBR9DDskOOeTmoDhB0GeU3m2
         X5LYhl5oB9P2epQyLGtHBjnrQqDU8UZHiKNWs3YLwlFRf1xQRs54BWf3pKsft8HxHogQ
         75Phd7/WEjPeNpGnxjX0yBx9YRgljjO5fUwwkptUITly/+itpRZQ4ym4j6MeA69oOMqf
         bJfqusblQ7sj1vXLXLpWCWBndCtXOC0Sie/UulKsv7LXURAXfc2sVNxpQz8Md96/9zuR
         MtTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=kLo/geESttIJ+aJXi2pDhJ8nIM9VOBWbNf6hL+U4nX0=;
        fh=wlKgyLTqfIRAJBKDrcaamn018FJXZtna9ABbo5+msPY=;
        b=YgRnkYO8CK62bhKn65lA66zHomZSafTn9jmLGuU4PMezpVq25cvleiyPQDGBMg/H1i
         GuPIYwdbPyfVQ8tpUQfosJSvIOTUHD5L2a06pLIaPPPiTIfHarn8QYjrCkkd+ENWDDFt
         tM6R2DZt0gnlrQfwOHSJprvku2/5P/EnrQmcMPv+alX0N4hqjP/m+/ZxWTSBuCbv/2c7
         923K/bZM/uK+HJ1yxTevuRSHwE2ZKp05ULv9Yx6600azb4+tgpaI3q4ovxDMGY1VMFmT
         7z5uRVlyHHx0TCvpMWzi1jhDn3haOeG56PKxrZ/JI0m6DhIFKUZH8K+78qUSu6sYIA7w
         yi6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UtHOEHWP;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845211; x=1751450011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kLo/geESttIJ+aJXi2pDhJ8nIM9VOBWbNf6hL+U4nX0=;
        b=Ck4+2qRBBqL/G/+PHlpkPk0A4MGMqc/TFY3vQ8/c9xUmTeVsJFgYqAZGxSk6yR5Ldg
         pj95XX9t+aG15X5wgioCfEgk2K9LCSBzurgPrE7KyxbBOUjBOVzRzyQQ8CmSsGnVVFgU
         Ch3JnbAnQYVLlUKnz8/36F+0ac+yMNgT/+GSUn//7A2NCjA+/WH1B0hkLoUKGsB1kT2b
         zrCklGcGPhDJ85/PUs7xQhmyvVLeRzYLso5N0RFx66qZ9u6tHSRri4vbjFN4Nnz0zRBV
         HmCCaFg1JjLZxnQDIMwe7c5ptyQSg2qau//z+y02U6Jf7DGrBQkMuCaQ53HpfrI6Xjz+
         oRSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845211; x=1751450011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=kLo/geESttIJ+aJXi2pDhJ8nIM9VOBWbNf6hL+U4nX0=;
        b=ZXAEofXCAaTIuADxq0/QGadXgjmb48i+BIMlkUwC3O6RpycMyJzibP/WYnLIx6Lvnu
         EshzCUf+3zOwJdW0rT36wLDHr1POYKhsi+9jjBEjXLhF5Tgm//Py1LnJo6qcMbmTFmwJ
         PkXQA3Ccg7l9RglBUcNIvs8FE2ijx2erApSSGJA3NyMlqz9CDgeiDooTiPqtE+YVIC9s
         k4UFUXASj6Rhn3Nb1UZg9T/6uK9QxRkfbHrHk5mvO+LVHCNE5R+KMuFbYvfJcI91Hs+n
         jjlXDFKkDMW+ohitvhmDKyZ5dRo/68w0qpMucRAOxVWWb/PgHORdHG2W9rnE4EDw1/9m
         4NDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845211; x=1751450011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kLo/geESttIJ+aJXi2pDhJ8nIM9VOBWbNf6hL+U4nX0=;
        b=Z7Vpl6uarVNkMxqGp9ohsGDUu+kOtyPkLj/2tMzS04LQQaKOhAByq+a9r4k0+w3g7n
         kiSWMjMavVPePdJDqg/l5Zm9S+uM7yFTRktju7PlWL9ndxlEWh1GqiBNsiREs4M2OWNR
         fwJlUH+PSMh/Ks5oMxTXXiMdRfjJGZgzMKZJdii1NTkpPl/O+8S6qtOaQTOhZEg3t8nb
         0x0vP9OVckDJmxYJmjW5QDPR0whBGqBbvl4r+6Sh8tfxdmRYzQimfbWFxLkzRoeKQ+kT
         X8KVQG0S8aCybVFE+4FXOJkGTruJpS2TwIRqGSANkntBmgsf54RRzK7botsD/A56zcci
         SPGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQHbjQWV46eJNUwEuucvERCX5zHvCha++/zV/Z8mmQ2kGZ5i1NensC1qIh5QBM55xSDEifBA==@lfdr.de
X-Gm-Message-State: AOJu0Yy3Js3001+25A89WqowWPZ4NAZCFimRoEmC9ZpBlXJ+VgYpntqt
	2CuFlTZKiQpBsDGI74sTpWYd6FHhKgHWtPhOFzrl25epfWI7cxXAIJ6k
X-Google-Smtp-Source: AGHT+IGNzkj/uPRyzZTSxC21UtyomGIuUybpbAN3aBBMKdxPOs9uoEXcxnJjWt4YpjZGiTgh6V8xDA==
X-Received: by 2002:a2e:a552:0:b0:32c:bc69:e921 with SMTP id 38308e7fff4ca-32cc649f481mr6550191fa.9.1750845211336;
        Wed, 25 Jun 2025 02:53:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdie0NT2L6gYREYTj50OS5INgY9UbM74vVxEu8KdqjYhA==
Received: by 2002:a2e:a9a9:0:b0:32a:646b:ac61 with SMTP id 38308e7fff4ca-32b896dccf1ls16978871fa.0.-pod-prod-04-eu;
 Wed, 25 Jun 2025 02:53:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV322Ma/fUsZJJCX2zbVBsx75W52msnP04nR2BaNw014xb1iFwE871e31uRCXfZ+5rHhEXJpO7OcWc=@googlegroups.com
X-Received: by 2002:a2e:850e:0:b0:32a:66f7:8a0d with SMTP id 38308e7fff4ca-32cc657ba25mr6733921fa.32.1750845208460;
        Wed, 25 Jun 2025 02:53:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845208; cv=none;
        d=google.com; s=arc-20240605;
        b=HpOdCDXQ7d1E5JtPJD1dmTOh6zHzv2Zc76glLN9DBtu+8WvUVpa0wOIVs17XQ47ru8
         Xj647nUWb2oIj1uwUjK4OowxKrC+i/G5Zwf0AjZXuY7G2irFQlUClmhuqWVaLNO6o/pz
         sTsMZ56LWnlvL1m4kZxxF0njVGa6azg2vV3kfn3TO1AKJ29Z1t1u9OzJ1918FqDPOIHQ
         JOni5MTuOpOatbboEL6GpJG3OVohRWC5msIZVjAQws7Acnqr8XCABYNB/n8I8VuyPwkq
         nynP2awlMeDn7+xK8waV4ghReIdc6ziZ99u8JZ7oH0XCiaKrH9w8Tpz1uFswr3n29m/q
         PEHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iNdRW1IbQwaJLK3IU9ZGilulsvtFwP6FJhql802bOZE=;
        fh=CMit9aqTl8roLx3VeWUKz9DCULyVnMNaiDICLyrFyYM=;
        b=B5BSNQZgdMuvV3PJFDBZYsJHsf3V92E6dtACYeKypthx2++mNh36DWE6D8Exs6oLoo
         0UoSw98wNlOAC98/VU5ErHx34MwXqJqRto36+Gi4gVw6c+aLoyi3/k80MC3jnwPxtokP
         MFvcAg/m1cpXAQD4kr83EI5kfnONPWnoC6+gddmiOOGLAqlbnYO374osMCWgqB27lve2
         gr82BPCULnLv13e5WlZ4JxAObodBtYWIvrnhZqGPIpBECoGZBB3uXmf5ouubTBa20diV
         hxFObHrqmTkcWc369EH5CW66t+taPxIMP36iMOwDwZH+jV1FxlmsucqcuY58HCZUX3kA
         CV1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UtHOEHWP;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b97f50b95si2683151fa.2.2025.06.25.02.53.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-32ac52f78c1so12765421fa.3
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXHLl51NtJtFTQCdDSpoDWDg4IVU5ipCknN4cKk/qQYp8WqoSmXwEZUU7J1QfD6UVVxFzyUNFHEl/4=@googlegroups.com
X-Gm-Gg: ASbGncuarFE2FmSGTkVKXVK6lCt/Ye32kTWqd/amH6IHF2A048hlJ7vvvZX87drsbDP
	v7z8cvbaVxHOlHTwmB7vEIbugJhoivINYQ2ZyGgsXABekQ6JOKHBixL9jv0BtxpUR3kZRpYL/+T
	vnyB2U3HYR7SUxtTnRadT7sqR+Z/UIODxU+8AIXCMyh/V9wKwMtJzWktjtONITgQhUZtCdKCZ1v
	Ut0NaBDngljGcGmkYkM9jFN1IlsOUnWx9c0Gm4Oel1COw2h1z9OB1VZPRgkcrnxVv0UeWiCuuYa
	qbxY3/Jgq5EldzQQJDn0GOrHl6HLySd8bdh6sudHiD2OtISCVvlHIcidfewpR1EsrvYE0e9C/LD
	v1MViQTHD1G8yQIsh9Jrvs+Bil0eLrQ==
X-Received: by 2002:a05:651c:31cf:b0:32b:33c7:e0c9 with SMTP id 38308e7fff4ca-32cc64b7c27mr7419481fa.16.1750845207836;
        Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 7/9] kasan/x86: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:22 +0500
Message-Id: <20250625095224.118679-8-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UtHOEHWP;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
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

Call kasan_init_generic() which enables the static flag
to mark generic KASAN initialized, otherwise it's an inline stub.
Also prints the banner from the single place.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/mm/kasan_init_64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d21..998b6010d6d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-8-snovitoll%40gmail.com.

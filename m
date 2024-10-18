Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBZVWZK4AMGQE5UQ5C3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CAE19A44B3
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:20 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3a3b7d1e8a0sf23054695ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272679; cv=pass;
        d=google.com; s=arc-20240605;
        b=dGtCIzQqXrw8nt6gVLQPk5dlNwI5xJ+epdlmNhSr7c8jWZ/S3WZ2ryZRw0rkfi0bub
         JJJ6qgj0gfpoxOOjlqG4EgvDHB6cpmP7PC9pxc5f45z5okkjH2n8paLpcOHqdwnlfK4i
         tkuqyHAHEEUdTG1gRpneFGrVRtM2nAnr4FdFA/Gc7iky0QETB4ejBKkx3Aqem10+5iMu
         zs1iMLKgcWjwWc3L+UtJMwpsPGVK960CdwGWTMSW9AmSxtRfff21p+FGRcbXcsD/Q4jn
         /dLacRwMZV+0E0bUgdRPrWIiJB+dBVKP/0xuKfr8oRjSiU9Rl4vIRqZOnMoesOZXbFD+
         czLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=EokyfGT45gsbej0uV3eJsEuUtaKMU9KwOjpqf2d0GOc=;
        fh=w5gxy1l/W8QHZhjv7zR+4osKuwpz+558GaDfYCfrlWc=;
        b=ikkJXhAfRgXqrQLgor5ewBKYr446a52Mn8gl3D1ZXDsm91e8RfATjvywyTGTxBJvyB
         y+LsYSwLyGBpuY1rPM3JCNE+otuEkJCWAXCaxiayzGllRKW4q8pJ2OEr1Ny7M22abVEe
         DOGTjXOKuxzwf4+VhXyLOcRDg+FQeg4r6Ae85u1xqRgxvl/U7YZ9iHTdZoLEpBuIDVEA
         p2wSv9URdzaoa5RxP1iWFN7PB9AzJBqwyVYKAmG/atnjK/EMK5luL46mZUq4Q9pgPwVc
         QBTJjLcc8wVuyfVoRwmSGix7JtWYKowa1MrEwhVbOvXsW18VezV8fHSUVLyr5dA6EyL2
         wqww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FsDnzZWD;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272679; x=1729877479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EokyfGT45gsbej0uV3eJsEuUtaKMU9KwOjpqf2d0GOc=;
        b=SILu4/5xyGislND/WDUERmUumuoxlVQkhpYpJu4d8xAA2xzObu+C0Un+uKrC0ZOwqO
         I3dNoAcpVeItmHhDPvtyFiPJ3gWAUsQ4nrbGjNPqVqYPZnXYFNkYxDT83hH5CPFeNzEL
         zBI0Fvyr24cluUvkRbPu6+eaQc+Vp0HpCViVurHOpNrWwTCXpFLKgtWF7JC+/Br1PFuP
         L0jSMxoN/xD47nZqb85SPbyTknxI0+NbPq0JobLJPIX7hGPsr9IiMzd/l+RlzxjtX2hA
         z4j6i5EYCKQdJgZuHEqREe7C1mhw+iMxUxIPR+uNolHQD+adwRvXszt6JaNB+9YLoT/N
         7/KQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272679; x=1729877479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=EokyfGT45gsbej0uV3eJsEuUtaKMU9KwOjpqf2d0GOc=;
        b=KYOB5I5PkIBP6SOB5wFkKmQSfPn8qkPp/RaQCdwGdDm+71aE01BFVGPQ3TQ6zG0AWj
         DEJW4sOt44EiY5QhHdUp50CgCXUbVFXbnERAHqLJ43b4pKqou46zD6Q5BqVL/4Q1skLN
         QcwTdNdM43AWQ7ApCmlE85wYLbfNp2OS2CILeUu/hUbgXwDXk6Bp5AS1zDU9Brz2PO4i
         E/QfkRVmgHzLM+KHB+BMWFC905Ap/s4TudKjVDvckeNK7iEj5Df/AkYzUnV4DDWShLW1
         PDFVNJcCZ8dtYr+x/8NHTzO0aCiDVFsSmrWedbH8nOXdtXHl+Lph+51w643A2tBwm0jt
         f8ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272679; x=1729877479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EokyfGT45gsbej0uV3eJsEuUtaKMU9KwOjpqf2d0GOc=;
        b=wRCFrweI+1sK5WqG5Pwur7ghBaRvH3HfWCC2b1w2pt4z4NERJs71ne4JyFWz2KA8+g
         T9KNws4gBt6zazNdYgZjwqKsu7bWI07Ru5WnntIpnmwHVoI4fETpqv2HitqOtjxVYhZo
         L/00K8ZRauWWfMazXaXmjCHQFiNION6NN37vDIk8Y7olkM+kwph/3ArgoxHqIj334FXI
         f3RvP6DmZipuiR44Txk3wwPaL1U6hdPHDqM+wY4ISIMu3ljAAu6+dVXnzl+VWpFKcBws
         xG5X+f1GtVzow2I2Bjukz+iGWcff2DzIHZng4P5Fvlvq1rdHvmjNf2+S3Ye7RliPgknp
         UbdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1+A3B8qjJ2QkkBhm83sUVaEAdXrIPgQTuHoA4uUwytLwxAwFFT5Y0gqyGOBBaR2Ria7nz9w==@lfdr.de
X-Gm-Message-State: AOJu0YzjziH4yNalgssj/gL1jJ7unLfKiMQoVnNDczyO8YxKbugtkqXS
	Sji1Y3czn+8tLBM/92K3T4cyOqqIOQVnDpdSDXETlSXdCqLykD1z
X-Google-Smtp-Source: AGHT+IFtbDsCgvbpwl2L3nR1hWAdyocI29F0gNvVLfe/1og9XK4Usje1eBfH6OgBXWyQsXtEn3863g==
X-Received: by 2002:a05:6e02:b4f:b0:3a3:449b:597b with SMTP id e9e14a558f8ab-3a3f40a7ea9mr31101275ab.18.1729272678972;
        Fri, 18 Oct 2024 10:31:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ec:b0:3a1:a1b8:cf6c with SMTP id
 e9e14a558f8ab-3a3e506622fls14309615ab.2.-pod-prod-04-us; Fri, 18 Oct 2024
 10:31:18 -0700 (PDT)
X-Received: by 2002:a05:6e02:1389:b0:3a1:a5dc:aa4e with SMTP id e9e14a558f8ab-3a3f4059c9dmr36432695ab.8.1729272678088;
        Fri, 18 Oct 2024 10:31:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272678; cv=none;
        d=google.com; s=arc-20240605;
        b=kygMenAYrEicD02fLO9wG2DwlLYdQdzK6xgh5bNuMjUUktFdhQlEcyebLFoUF9WAHO
         wrB+TnHC6whhkOKalNX5HCLusuv0btbUByAa4FNIjCOVCxdYBE7nT/7ijjqya4aE8FK+
         MLxINDcdwsX4psdfUzn7gkg2mzv0W2rqgMl7eCSm6smjwJK/GnMUWsKIBh27VaVHgxV1
         bjGzw6axSYSOHtBwDLLpCbOpi4q8VSmbqXhVtL244bhQCg2HRCMhHjByV2bv7yAt3U/Y
         hvAz2mlWmIEArdOVPObSZgpIHOPdm8YbtiBF4x++KFfozAszloe+U8ND/RRO2Acn3a2K
         FbTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=M+pQKseSbUwQ7nDgMGbwYxJsHyJez2ZBxycyN9iER7I=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=LnhekB3xOVgy/bz/9DIOjCWDSvjSpiX7DfhfuIf73ule5/KzcqvafGGIJZ54R9RoCS
         W0MvWi/mSE27nfKD7XKQmBuYa+dxi+Xq+lkX700PvqQfKZDR4Jz9Gq4dh9OGWR/aFjd9
         lnKeMuPK3BO8xEtWhJp3XjUqGCE4o5jDs6obfTwWYyi3zhhxV+3QlKlF9pESn8afvEPo
         bHPs1kpasMqgkxp0MGYO1wBq2f8XoXrj2pea7nna4DIg7jc3hLCeRJdSCr6FfTEzVZ3X
         iUiEYPWYXRmo2aa6ab2ChG3KLjESYhviAXAijClugQXK+HqoZqXOaCcjUe0px2wIcuYB
         9P8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FsDnzZWD;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cde110d170si776136d6.2.2024.10.18.10.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:31:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-71e5a62031aso1701731b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:31:18 -0700 (PDT)
X-Received: by 2002:a05:6a21:168d:b0:1d9:61b:9607 with SMTP id adf61e73a8af0-1d92c4a0231mr4271987637.6.1729272677039;
        Fri, 18 Oct 2024 10:31:17 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.31.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:31:16 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 11/12] book3s64/hash: Disable kfence if not early init
Date: Fri, 18 Oct 2024 22:59:52 +0530
Message-ID: <4a6eea8cfd1cd28fccfae067026bff30cbec1d4b.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FsDnzZWD;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
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

Enable kfence on book3s64 hash only when early init is enabled.
This is because, kfence could cause the kernel linear map to be mapped
at PAGE_SIZE level instead of 16M (which I guess we don't want).

Also currently there is no way to -
1. Make multiple page size entries for the SLB used for kernel linear
   map.
2. No easy way of getting the hash slot details after the page table
   mapping for kernel linear setup. So even if kfence allocate the
   pool in late init, we won't be able to get the hash slot details in
   kfence linear map.

Thus this patch disables kfence on hash if kfence early init is not
enabled.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 558d6f5202b9..2f5dd6310a8f 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -410,6 +410,8 @@ static phys_addr_t kfence_pool;
 
 static inline void hash_kfence_alloc_pool(void)
 {
+	if (!kfence_early_init_enabled())
+		goto err;
 
 	/* allocate linear map for kfence within RMA region */
 	linear_map_kf_hash_count = KFENCE_POOL_SIZE >> PAGE_SHIFT;
@@ -1074,7 +1076,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled_or_kfence()) {
+	if (!debug_pagealloc_enabled() && !kfence_early_init_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a6eea8cfd1cd28fccfae067026bff30cbec1d4b.1729271995.git.ritesh.list%40gmail.com.

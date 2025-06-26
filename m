Return-Path: <kasan-dev+bncBDAOJ6534YNBBPGQ6XBAMGQEX6IQRPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B8AAEA2AA
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:33:20 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3a523ce0bb2sf694874f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:33:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951997; cv=pass;
        d=google.com; s=arc-20240605;
        b=d3yX/mhWV2Fft/icdvBFYgTnnOCzxmVycWuAu16AZSDT0SF3GG9oeSCAQmCxD3ZbXt
         ET6VMlaRSTM9LJAQQEUjJ/BOw6b5iq+LOzLz6+Vw+cehEkjw0ZQe4euJJt0+rVWfavFI
         bfa8po7GEWJfWGP89T3lOexCB03upZdJZDO/I2gLNHdlYX2KwD0CJB0Qc2Xu+KPM+xF8
         rJwAfkpacU1IzQakpAHD2zMJAsNGpd/IveoVqB/BvNe7E4HT1KdQngwOTzz2uOxQXQ9h
         xHqXBOk4mPeMwk0i+eKzixffr0Id7u5b9sHxQX0N7luMpM3/RKjQw1wuK5kDePMzV51p
         xr5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KvwkjT9HpK3tvolUE6p3pVNZBKuhVCO0k/hJgbr5RPU=;
        fh=lOWVsNezNmReSmeGKM8waytj861ozvNM9r3Cc8O+/Ds=;
        b=cIWC2WLOPl6Jr8oegkSjN4C7gMcYKJTbJ2u8rWwi8v0anVxt1lmB4v7U9evPnsiiMG
         Ygsg6FWMZ+35x7ZriqOh33SOrUEflCpwcNS3Xl03CUVmpr6+vYlIIde7I1R+zLnyC4KN
         0RH9o6NIf+AiRtgavZpCn1egFCklIUvf35b5+dxnQmx4XF2V2ztyvNAL0pzsymhUNVm9
         WgUZn/+EDtjUC0ofGZn5BwxadCaKGwFIL4YOE/9JT+k64Ha2S7JUaTgX2O3GSsAQjMyJ
         vw0f5xUwREFudD0SLBVvhzD7FDxc4M90Xiud/UJlWY2P5jP2uXnlDCK20lZNpuooM13m
         LOzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Qe/bAqC+";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951997; x=1751556797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KvwkjT9HpK3tvolUE6p3pVNZBKuhVCO0k/hJgbr5RPU=;
        b=b5cQT4wKl9JefYJdG8wEUVLcFIUpjEhZsinfR5cp/LhcZjikxvMEvaVUXfB1tR4Q2w
         mFTidIpXPvhsckg2JhL2ZQ3/++10Qzl+yY1sta0RcZhnkYyWFESql2xOVgqkn6Gty6w1
         U4LJ7bgfUKjDcdyYUKAFE+2mDzdMUqlB9Fz6GzKT+jyOUqXMsbZmiRYqplUMfPAC9e2T
         7Sj6iZM0GJTgD6ApFqg3E1HI8sEO77RiydNHpMp+RjoWZyfbNpNzj3QnwOnRqXwnJP4m
         XLBFZA8dx/gbh8JW2ygj+ocBESg96gq3dLITNuSU2ECgNohZByMkCUwjtuzGgqJ/+cyW
         eiTA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951997; x=1751556797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KvwkjT9HpK3tvolUE6p3pVNZBKuhVCO0k/hJgbr5RPU=;
        b=DjMs/iGBAK21TtVUohkpEQ0fhazP/BVb6pauZPeNzko6wCds1UUq+PIMG/Kh0e3y0i
         o0zQBoZI1serJ3d5YlRF+cJmKbmBEr7z5IzgBNV2RuhQGmtT9UVNGTTi/9tV+v72nCDB
         q5YUypL9rUmrCaj1JuTHKYLGgnOSVk1heNbcXb3z0LQiJgsIc6aaeeA5P8J96fH+2YEU
         KP1DcDtviTpVcjDL7nuINs81Q6kupOb6TidaWiOum7BOn7eZZT2XwsHCa2c3Ko4H9MF3
         t0zuUmOAlNbbwyMXnkwbRqK17jNmyEvRg5la3Mvd5xle+tmHOwk2ECRRwjKjmrWUrdnZ
         dywg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951997; x=1751556797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KvwkjT9HpK3tvolUE6p3pVNZBKuhVCO0k/hJgbr5RPU=;
        b=X3KAbjARJYki+NHMs54iCjT4xOWH9HbZAkODCf0YwhAwxaz15j0GrQmixVh7sRB6tI
         QwF6N35yBXbB5AUPwvHg8e/E5SG+S7+a6LmUpSiIUPWVfQrGye2FNvc/lvNZsVRlk67i
         4htSSvdTnpqvQa2aG8MOHv+JuPlfSEnG4wPVuT0xHbwD/M/UVLRJ5PoVyszwUlu5ZoKK
         dpwQXJEw1aShtPhnph/5AWGZ5/edoe2kZ1J2xVYCssZV+wZ2aRxtgA0i0DEDqmPhyS1v
         z7VgqwYyS1AND9zrNzfWfAnZ4I7j//3LIUfOSgJxTaVSgKL1yRTtLb9si/kIhtZzEysN
         C26Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXO9WSEP8OmN4x7+johEyEJ40EJMC5OE/gU2TwAPRWg+Tp+apbdjlHH9JHzj9Uj8glyX1iZ9A==@lfdr.de
X-Gm-Message-State: AOJu0YwrvG+tAzyRO2UofyI8fOULi3e+wTn9SrrX6t3kqbl2ICWl3Q+D
	+i2X5pfbgnj+D2PdzXxMOZVqy2oYu4Sk1NDZ+BeZ60UKjZWYLLaDzQmz
X-Google-Smtp-Source: AGHT+IGGfOHHj12iPF+FfujS7jhoZUPex0WEhGZfQBpPQ+5G9XkP+5oLlRYD3gonSu1p7IZFj14Lvw==
X-Received: by 2002:a05:6000:4186:b0:3a5:39e9:7997 with SMTP id ffacd0b85a97d-3a6ed6450c6mr5312846f8f.34.1750951996842;
        Thu, 26 Jun 2025 08:33:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcm9Gr11Iin93Lyimf+OrS0UK9tcsV63/t1IpLYQnPHJQ==
Received: by 2002:a05:6000:2510:b0:3a5:89d7:cdff with SMTP id
 ffacd0b85a97d-3a6f321d45fls479658f8f.0.-pod-prod-07-eu; Thu, 26 Jun 2025
 08:33:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9CWJA/AOpUkih46NF88m+lyPNDk0TwGMUolRA2cijRTzgM/5B+aCU3QABiP06OOfHB6J9woyoSzw=@googlegroups.com
X-Received: by 2002:a5d:5e8d:0:b0:3a4:f661:c3e0 with SMTP id ffacd0b85a97d-3a6ed64ee00mr7176527f8f.45.1750951993200;
        Thu, 26 Jun 2025 08:33:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951993; cv=none;
        d=google.com; s=arc-20240605;
        b=SRhkvj08jJae+55NPqLNVSgAexQ+hBwYIaRK1HH1r+b4LccSo7VHY5OMGJ6e8vRO/z
         f/qgqNaTUnctz+cCdOqwleoBoKYnMm+EC6ME7PFX70mTZlP/PlmeGcbt0tZSQQIxEfXH
         QhlyTq2Fk7bn964ObMDOa/3V4CzYdMr7rydL6h1caYo5LHWZJ/ZzKGVJKiPuaHfY8I5p
         0pk15CBkZeZsQO6/zSPeXMjIU6DU1MBlPmz21ioqYSHQ7LbJU6lsXDC7ql7OOwGDoXqj
         16hFCIk04I0zsUlyCO1FLaza2VJZNPIET1whW7RZfmKX6uetmPCN5RVpG38A+sBiRsgR
         rCkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wSxJD4SCtsi5mR6YtVjdi0UPNRveg1OSTrY+9IeINk8=;
        fh=Ie1sxOo0nhXfdoQKTEcjSceelgdquuZA1+jzl2ZjnKA=;
        b=blZ6yE5Y9VN1ckm6YgH0bc/hl7NGGv+JQJqZYVFM+sPl+exDyovLfFJtWSSCkvW/5p
         wCAQgmCC0NLbOo4xkhODGHCguyiTHn3kEdWF47xTW5fgTbsha6TBdMefrWD92IbPyTGN
         AvYW19YH5R7JO7zeRj7EJpi7mwPAe2raDTf0R6OkSTph40F5lC7PQioORe3NbFBKHT/h
         9buX2K+3tk3o5PmuANlELP9E4KAaR5SxAyfyJmgYe33IcXZ5U79kTFvrGWamoI6oZF2O
         oL4Z55050+pGb/gpQp6Ebs9eLHZceHc4MTwBwKVeUhAVHSpU8jKJWxRnekLeMAkBExLL
         expg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Qe/bAqC+";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a892e6a2e2si3734f8f.8.2025.06.26.08.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:33:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-54b09cb06b0so1218839e87.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:33:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXiWXGOsnj31J6escliexwwMiG3rn3NxvUBMP1FFLN06rN4D5fT8o2uCc53r8bUMg1rZXX1kCoANbM=@googlegroups.com
X-Gm-Gg: ASbGncvT6SjJsIdgW9eHIf8ZsWIMp0xHVdyZrCm22H2+EyaSraEhzK+0UiO/pg0zmgi
	svh7fcnA8v4kq4HLseLWxn/jYTerIq6zCRSqcP4CuBJF8DpidlIR8XGiqCiZTcL3AXDX1SjpRJJ
	THzJKK5xxgGeNgRvISgW9ftMznnrCkIwNXVMMv7t01gRMaoo4khI/MgM++2T4C8lZyiatJXlBRu
	tG/pjAlFqraMj7acg7Q8p33/UqngXhbT65xoOL+kU7M22OVUS604HdLjetItXVxPJQhClPfGkgW
	trKCrBsG7k17LJtj5V2taL5uAGifev7vy4dSe2Id1ZbDBIXdXh4ehBzFuc3gA1wDe/uzw/2gqOV
	8OJtquxQ/JhotNdhXRsDd7GreLw9/9g==
X-Received: by 2002:a05:6512:15a1:b0:553:2882:d79b with SMTP id 2adb3069b0e04-554fdd1b90dmr3161154e87.32.1750951992214;
        Thu, 26 Jun 2025 08:33:12 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.33.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:33:10 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
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
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 10/11] kasan/riscv: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:46 +0500
Message-Id: <20250626153147.145312-11-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Qe/bAqC+";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-11-snovitoll%40gmail.com.

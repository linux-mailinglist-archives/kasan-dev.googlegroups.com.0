Return-Path: <kasan-dev+bncBDGZVRMH6UCRBV7AUS3QMGQEV3HIINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 96A0D97AC14
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:31:37 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3e05074e733sf4008800b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:31:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558296; cv=pass;
        d=google.com; s=arc-20240605;
        b=e8NpIIlTVJLUisrG64hkYRFf3M9++NARxwmbivhjiLEsBRgcQaPX3+97Wg24QQBsfv
         OTSIUuh2JRG4BCQJsiK0/ZY9R6TGk7WnhU3y2Gzy8T06fS3nFT6k7h540YedBPQa6zoZ
         sgQ0GsMgIZOTX9/oOJ2v9YstiD3gcd7OpnGbI3V0DIE21TJloK7pr6CFWMHMEctishcT
         ThIdf1mGbhypmSXeeYUnX/uHzFnDe/aHeTbi+sxt+31Z3DYcNIMESKzyvn0y+P315WyQ
         Qt8XiBY+g5T/Xf/G99V2JQyRjXxvl7xiZOzaL2GuvXQT3dzuUYFXtZGlja80i2pDrnnv
         S7/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ciILUeHiPx5O8hZ0jvPD1+dViBpToQl7/uvi31WNGuQ=;
        fh=QhQCw4SCwjTDDfjcQiM3PWZmuyfBlkCicEVGK47D3n4=;
        b=WQY7qVhtVi1elHpgB3GrQqdiseuTmbaShrmLDo2d5bvbFy+1LPMC56GbqZCb8DrBoT
         jJzRBg4Y9RPmvinD8gpwVa8id6ooGqFCtyq5ERkqREWsStXIpUL9YrSHK6kUTVlH7UGJ
         0on7gUgohfxNxeUr3Hx3PiJPFFIQ61JUv0YpFUsbFM6ajInsXhFI1Em+oxzqsTEIFIto
         i+hS9Ilm5DkVXrVZNki+XNuAE7eV+KV8ZdsJzebWegAoKLSZaiMa61CtokOr3EzQJRMe
         17ZvNlc398aZr3KAjunt84HyYK0dS8M/D1YG/vxTq1+sxN9RCTheq5SfFHNOVmmyqC7p
         lIBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558296; x=1727163096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ciILUeHiPx5O8hZ0jvPD1+dViBpToQl7/uvi31WNGuQ=;
        b=XoDXhUJhSOseHFTg0qElsMeo/Xb54Rok4AIfFusCYldi+0LEAlyQzaQsR1kXxFOj6R
         7q7EMOQ51A23JSJXBRUyRYiQVHrFF6Ub6xW+nwAIfzfijCzCUekaX1Q938YlfF/5R/cg
         oqSXaV9Ce1OAkrApZRvWPYirrsKMyhE4PWprDvjkbD5mCcLfUhXqO/3fPBbCLIZZ6sD2
         f/vA3VNtQk7v4a9nqdWms0jaHAjv0055tfQOehZAR0mqqp9PwtJDcSUcEOdKBQ5qb4b+
         BxTUR06zRY5BVnl7q00S34fwPiHCrQeHLIDi0hrFRNHZ/0KWrKxG6HygASV+hYlJKaHK
         WsNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558296; x=1727163096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ciILUeHiPx5O8hZ0jvPD1+dViBpToQl7/uvi31WNGuQ=;
        b=rAILcKY8z7uaEkKaLCv/Vic+ueWyNvv8w8GtBNxa4GpS4UXt0OejtNfR36aJ+Jy2kr
         24dL9t6EoxVYEd+tgLe1NQhwAT3PSZcbwfBpT/Ir/YOWsAcyNcmhEMv4c1J7/BABzEfM
         l2IGJmAfbNzOzDLmqkwXwgQ7uKUUl6seKKKF5YKkqoo3UWHU/bpB+Umd78sB+TerWDXe
         D2ogzajSf/D7ozYr39EIMtjEmSEY+fIUbTQmB9gzpOeqHg6ipziq6ql0ub0z4i6LPSIy
         rgZIPcEKC9XzLisMA28Te4KmOfcNiNMWrSQc7BiFNz2lqlsoCIBRH2Epd479pgWt+FYQ
         z66Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrA28wVagAw5WGu6jXArhf3S9Vjixo/1Zvo/kmaKSWryjN6TqAj/AeI1kuBSv1k7sQ8sHexg==@lfdr.de
X-Gm-Message-State: AOJu0YwdhuqzZDDPKwmf7DVfjlGA2H3ZkPv6FvOC3ozk3MajsEMwfGOA
	bxh0wAbaShFCS3GtH/HXIWs2Hl1/gG6JtFu0o2v7EcyfuC51l6q2
X-Google-Smtp-Source: AGHT+IHXN5FQLxU94/u3GrTjPEhcLs86Sgns/INO0gYfSTCUu0Qi9NIlflPLDfmR+KRfDmtnTudPUg==
X-Received: by 2002:a05:6808:1521:b0:3e0:456a:9f82 with SMTP id 5614622812f47-3e071b21d58mr11005571b6e.39.1726558296046;
        Tue, 17 Sep 2024 00:31:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d24a:0:b0:5dc:ad89:cd7b with SMTP id 006d021491bc7-5e200a80d4els2093185eaf.2.-pod-prod-07-us;
 Tue, 17 Sep 2024 00:31:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzB6YS8ozbAd78QHpqpmQpIF/cOkApfKE0q66YJ4jOvKKc0O4IRQ7jEOTvdP8GgQbsrqq7PBWwZdM=@googlegroups.com
X-Received: by 2002:a05:6820:80e:b0:5e1:dcbc:218c with SMTP id 006d021491bc7-5e20146ed62mr8822630eaf.7.1726558294853;
        Tue, 17 Sep 2024 00:31:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558294; cv=none;
        d=google.com; s=arc-20240605;
        b=Z4kml5MV+MIa4FIi7vTOS88xrWlNUvkgtIv0I1lUrmKU3fjj8KO7y6MJG/POjsKC5B
         sF3DWiI5PdLNrdsP0rR4gzvq3kcVHvxyPQyyPFT+5XP8XmLMWXLVNKKf0zKr18A3Uf1T
         J0uONo8eddg6f7lNvwFyVNHHjcjLl++XhMhNkCzJG4JWkvsvYuXPEL0QxN2ZVeqV5+Ss
         NbR3q3YRgHcNgg6XIxgRIUFpHuN/KcBm2IJt4AJPFSni6vcXgL8M+HJKO2B3C+IdnesU
         wkJlbQLibIgnDmwXZOs/S4Bn1kztBbNDR4ABcTubRnPVGm5D2oClXJzKQn6q6JdAkZ/T
         ehmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6lpxn0RtcL6Fkqv+YkOVwAEEKQgcrbZLeJiP74sUbcE=;
        fh=hcfUAbjVo1Onr/A6btw/6+DWx1lfMgdriCz1FYQJQQM=;
        b=g/e1RzG2sf3I94FPSVZB03eEg7mVRoH/PtmkRAuoyKcWVUJiKMq7KmKnAERhDnn1IC
         G4y2S6gAiUeH0AJAsncoyLcqRDF/vCX8L7vj3EWI3nj7Q3hzy9fqLSXdwVSd0fJDXve/
         wAXKbxdXtj+aqLm7WFfo6WoxcK7uDZtP5QeP/hVspj8gxMRIbCYSuKKZlNyQ63VGLd9w
         Z/7ZI3LQ9v+TPxq9M18J7IiWK3IFySF8//4CpT+cWPpcjwqlfZh6IHVE4dEy4ufV/Ecd
         rM5oDspPYdsPnzXFX7XpOAdAxArC5NLe/K9vh4jmSH3EyEvzRElUASlTQtm+jXd5uauK
         Fp1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 006d021491bc7-5e3b0e0f28esi268803eaf.2.2024.09.17.00.31.34
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:31:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 85F251063;
	Tue, 17 Sep 2024 00:32:03 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id E0D793F64C;
	Tue, 17 Sep 2024 00:31:28 -0700 (PDT)
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
	linux-perf-users@vger.kernel.org,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Guo Ren <guoren@kernel.org>
Subject: [PATCH V2 1/7] m68k/mm: Change pmd_val()
Date: Tue, 17 Sep 2024 13:01:11 +0530
Message-Id: <20240917073117.1531207-2-anshuman.khandual@arm.com>
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

This changes platform's pmd_val() to access the pmd_t element directly like
other architectures rather than current pointer address based dereferencing
that prevents transition into pmdp_get().

Cc: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Guo Ren <guoren@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: linux-m68k@lists.linux-m68k.org
Cc: linux-kernel@vger.kernel.org
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 arch/m68k/include/asm/page.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/m68k/include/asm/page.h b/arch/m68k/include/asm/page.h
index 8cfb84b49975..be3f2c2a656c 100644
--- a/arch/m68k/include/asm/page.h
+++ b/arch/m68k/include/asm/page.h
@@ -19,7 +19,7 @@
  */
 #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS == 3
 typedef struct { unsigned long pmd; } pmd_t;
-#define pmd_val(x)	((&x)->pmd)
+#define pmd_val(x)	((x).pmd)
 #define __pmd(x)	((pmd_t) { (x) } )
 #endif
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-2-anshuman.khandual%40arm.com.

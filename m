Return-Path: <kasan-dev+bncBDAOJ6534YNBBEOQ6XBAMGQEMH6RYGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC518AEA298
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:34 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-451d5600a54sf9417295e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951954; cv=pass;
        d=google.com; s=arc-20240605;
        b=fvpl6/pZ4uFPkrnYow8j4AIHGNpFjtLzcSv69AYxTN3xK2+/q/VzMF+o4lFIORLR/O
         xCoyum0hXI9Cf1y2T5GSfvQTL/HmAK7z+PAQ/FxGuqDDtxp4GOktVJQqWPr0ooZ0ojjK
         81hs8xOjKpRsV5ymx9jA2SLL8/pDn604GG59sSRvTlFEQQQ84MoNf8Aw+NYmeC58QMPr
         rZOU6E5q4m7X/gH2mFqNYn5lBWPyrw9IKn3SGlkDddgR8rxCpNlvAUCBs4x1ajYzUb96
         VfTbOPR4xFz/vQq3ek4cscisNe+Wg5nyIPozbTOGOtsSsCbzQqFARk0mYtzX9af7a5aT
         Ottw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6jPQ6O3uLG5tKkLdM5p0dDZ8D+UtfXICoSyit2M19Yo=;
        fh=GkxYO9Spa2LMFouSkyxlf0hU4d7YLTElnK0M1gVmBlk=;
        b=iIh+fPaGBIIRf5jopG3lBXJQqz+hF+JJYBipoNdPsv6UdwaWlYbw95//bk7hmAjTfm
         tCnC+uuayKr4sczl/0tCBjlWMaaroIylBbGRg1BI4TSWGCBAEDJvddLWoL6zDSSycRP2
         HYKewIH96Ad53G1IIvGdg7FAU3TIcmquOjndWnvewD2XZkdzWlyDEakol7IMQuXW90Ri
         raBXGzBuSxfjYr07+S0QIHMRsGaIcWQHSfG0KQJZKtzwTDZom4VdZnFYmweXyJisOt8k
         yNs9eTx2gW+ONO9zCNANiAbAgaPlTdvxb3CWHW8LS7lx09HqQ+43bFc+r/rqNVRUhshg
         3TLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fPVYQtS0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951954; x=1751556754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6jPQ6O3uLG5tKkLdM5p0dDZ8D+UtfXICoSyit2M19Yo=;
        b=F4AGpvSpkpxfayzZtBMEO2f18LdpSTMs4ulIA4IM3Lb7vSBjycG8LUfqD1VHqYOXdQ
         eDr9zjv/G1x2YG3SRR64Rit6Ry9r5feUoKtRhTqsX1SBRetzxT7VaYpU2MazpidS05en
         PuWD0kTFLwFlG1vu5KuadyuQhARFocB93ErWFlLw/+t32KEta7oaxT9b7XPFAI7IEKWu
         4JCUqQJjnxAXcTB1Ye6VHIHklN2mnUJRzYQXX9X9D+fvyD9twGqiIddnPFKVnGWg3eMT
         PcdPlbZZW8Hyt+zotw875ExEH/Fr6Zrgx0nWuDMp07qzjjO0dAfjOogigkLZU1TmIGoc
         srqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951954; x=1751556754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6jPQ6O3uLG5tKkLdM5p0dDZ8D+UtfXICoSyit2M19Yo=;
        b=JV636wurX8U3IG6NOhAq1aHN/bI91ZCl8drqecvffjaujtBdI8TAGWEkD+2phY9x/K
         gu2MSmXYcdMSLJSolTJVnKk6RujolAwVn7GvVc0DEF4qn5Pe53O68Psdo7kXlBXAhQjJ
         Q4INEYtpn1NyxQVR7jST6XDGVrSe4s/DsMnw1Dd46MwZxA6L1VqBojoOOwHQAGem4yiV
         GL4tKYuJosTuvaK3nRY09+3Prx5yOD+KQWkeEy+VsDWCH49ygOs/Fzj4oGHQ4qGP7fi5
         DdIqjFIh81GLeFQyl+cFdpKZhObR+zHBURBUcOYGXrYhgQS0KpIN/zBH7TTfv+Wq/151
         VhHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951954; x=1751556754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6jPQ6O3uLG5tKkLdM5p0dDZ8D+UtfXICoSyit2M19Yo=;
        b=uh920bIBCPx10AEQlW9IgTd39KWkxyRvtMHZRPo7/TD06HcYR/5ecvfy63tBELBLkc
         ISnZkdev7mapV26BFOBbpqsjtgk/MAOFmRgo6EMIQIjLIAMuLnHTs68Pl5RMBeAymlVK
         qna5TXBVS9jWXa5rVBcOt9kGAIUyfCUes/WxV2vH7m1uGOHsbjjo3pszP8jntFgJ38uj
         fhRNq88PeX0mW4RWlHm2DtaiRj/T6b7pr9J4SgOkEfqhP8cqBpxG++cwq/jc04pYg1FP
         NXfECDZldutOpn2aEexq/BhStmwJ8dd1CLY6PHwtS8JLGfXw91Ecc2s64ujf1HoAAw0u
         vA+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJrkDyqkljwhK/dTV4fndMnEc+razYsyQ4D8eFSUd/VOqeVTElYjCVSG5Qu7bKTRPtzilmPw==@lfdr.de
X-Gm-Message-State: AOJu0Yyj9b/j1AIzvOfOH5X4k/P1XUoMQXLMZnjEstFam1H8N8RwYyGh
	Q1ZoRW/V3qPhDn6gaVONDch76Xj0fgtloi29UwxrSfgwyUDdF4unEwve
X-Google-Smtp-Source: AGHT+IGSgjPH50p4dB3flXh7NXfUvEQerE5aPeM7egcG3To1Wz45qk7il1yf27SHNT6HkSXyS6aDJQ==
X-Received: by 2002:a05:6000:4104:b0:3a5:39a8:199c with SMTP id ffacd0b85a97d-3a6ed65070emr5925567f8f.53.1750951953890;
        Thu, 26 Jun 2025 08:32:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCMDxjDq3bPopsuZzCaJsVETItk73I1k9tDselLUIajg==
Received: by 2002:a05:6000:238a:b0:3a4:eed9:7527 with SMTP id
 ffacd0b85a97d-3a72be1997als365273f8f.1.-pod-prod-02-eu; Thu, 26 Jun 2025
 08:32:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNpAi3NIxAP1XtM23z130grSjk4pJTAuRE6bpyFu4maPLIDtkQR/Xtqqx2ZGVJWw9Ngkkc2d94PaI=@googlegroups.com
X-Received: by 2002:a5d:59ca:0:b0:39f:175b:a68d with SMTP id ffacd0b85a97d-3a8e90bc4bbmr15643f8f.11.1750951951198;
        Thu, 26 Jun 2025 08:32:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951951; cv=none;
        d=google.com; s=arc-20240605;
        b=JNMKOiBxFkveGRIZNvtkbzTHjxiHHjrsDrnrKEJw6/uoqqjmU7eopA0E495YpAcRdH
         0YhkjwJYicQnxaNogvgK/6m6wqlKQIUBinfzWA3mkHukxj3pQ3DCj6xkDlv7IhFQlj7Q
         ouRLYpNWVclhsX1Lcc2U5dXulcGLMe/IfNJk0+bjNf+ApRlkfI3A3QU4F1qu8BqPC4v8
         HJW4e6k0xBZF59xwu2SfK0FcF0kNVaTBlNetRPW/k+UAvKHa8+PNtwWvRTr/6igCNZ43
         tlnchwG8U4bYrSdLKH5WOEEOiLdXH/x9BRMw6tMQuHUimhiW/fodihCq1ASn9OxkhFbp
         hpLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Nxtugr6OI+iAiBoQ5DVdScoZ4wigsSWWp7UsuEUnh5g=;
        fh=eBvBAuTgp1xU689juxYEcNHQtoY6gcgcXgsHIEIwJ3U=;
        b=W7m5aLgkQA/f4xpAalk+U7DUZ1PsUUP+eB8ZwaNsO8oPRV9rPuS4MjiiZscXslx7mW
         /If+m6dtruZbZXjOYmzA+k3Amn2yz67Pf7QbFKcvg2DR4C4VssbhQ9Ej6407wWt3K7XY
         KNMeZNa3EY4CxIAPvRnPguFZn6qzjhC3VAztEGOjdszqar4uAMoFA8JoN270k6m2DAGW
         iGU0DjBvZ0uQVKRSbbr7aWuIEHLTULhPuHM3JUPaS1migXn0GF65I9sWj4r+SSr/957f
         REqYrQSrAYMTZz2vDkwAugnAar/pyGXcl8LNWH47G/iYnVP/PwPqVnWngC0WibZZg7ip
         8AwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fPVYQtS0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fced22si1160715e9.0.2025.06.26.08.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-553cf020383so1233113e87.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXu2zznlt0tpNzkIE/8DDNisyq+eVOTNB0j+YHwQOjF26EzQnffe5kU9lgqX6ol32wFPTiNLYzXY5w=@googlegroups.com
X-Gm-Gg: ASbGncv/zc/1DWRlaeDlbDxCGPpcPlAm+cpAYGMtnNeJ1IG+Btxz75WlEEtOvvJgAMP
	jjtNTF1cp6rsTBOG1Ywnm/5SF2O/7UA1tAGgtJKyhDVU57ytacCpyu++voNz0ACGBH4Kq12eZjB
	/2ECFC1LaQOZYb0/kBS6W3PGWnT3SuyKvJN81ee0mt6OXC90KZzY9Khmb3VLI6cn80D6RXSiiFC
	0SviVg7dd90oJ3G3n7uGPKEmDxSnHqUkRNRtJVhq75QV8FAf9FygpF7xqZKRG6/Zkbv0CcKJC4b
	f6X17NZJuo8w8Z2ozOg5xxvmo2uxywrbxGbvptqhXq04+YIDSnCVL+5ELllGY352DN7jQc5G6VB
	DvaDfgQYxm4Y4E0Xga4IXFHrP94a7NA==
X-Received: by 2002:a05:6512:1193:b0:553:ccef:e31f with SMTP id 2adb3069b0e04-5550b4749c2mr141485e87.13.1750951949806;
        Thu, 26 Jun 2025 08:32:29 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:29 -0700 (PDT)
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
Subject: [PATCH v2 04/11] kasan/xtensa: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:40 +0500
Message-Id: <20250626153147.145312-5-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fPVYQtS0;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135
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

Note that arch/xtensa still uses "current" instead of "init_task" pointer
in `current->kasan_depth = 0;` to enable error messages. I haven't changed
this because I can't test the change.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/xtensa/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173..0524b9ed5e6 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -94,5 +94,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-5-snovitoll%40gmail.com.

Return-Path: <kasan-dev+bncBDAOJ6534YNBBINJZDCAMGQEV4ABW7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CD188B1B662
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-3323287983bsf38039821fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404002; cv=pass;
        d=google.com; s=arc-20240605;
        b=N8kT/hiGl5Eul+GfXbMfSPuv6t4Xmwp2FjL07Vna/TifJ9NENE3FqSVFco5XOnfa/q
         a/BRfMADmHXuZj6vFGx+wIEE7CASS0YfH5pC7PsJ6Vnj5UpmVEWWHvomPa0SSjMhG8EP
         sIoBg1aNe6ApGAXO+IjVpR9lV09Re7jdSQe5rvn4OW5UJVOQbcSVVPWF6q53wi+z3r9y
         uWj8sl32sCgWESh8GzrndUm0KCO8CTwR8QDu/ok0h2PqnJO+B3Wiol3NeKqyAnXC5Cyz
         nGJQeWhafq31XyqjGlh8wLju9cmBP9Yu9VSheMJ94Gbd/sMO31icM67dITJbTwsCNC53
         Vfng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RyX1Ka5ErN63jWFZexw8lF20xkI5o+kwQ8eSlsGTqJs=;
        fh=jefb/cmoj7fP1xTPIsXaoFDTNa2Ij2bbtWZ+xvscig0=;
        b=YKI4NozlgTh7zenzA+IdwDQPXO5LFWFhWZ88IDOt7nT4St8BEU8N5ApqccyDU5nc5w
         F22+WkwD8CKv1EUY7Phij/gHRwMxq66wp7GR4RivE2lhfxriiSY0V5VKVFP2Lt8qUDm4
         Hpqu7Urqv2sctI62dhQmqFqFXiaXvl6Ba51u7pjt1wWZ2aZqNl2tRebKvaOqNx05LOx8
         HEp+4xOcKQ1GQIcypiRE5bSEK40d5nZ0e/EeyU1OkJlrXbFMJ7kFvEHjKJY2tU26axRr
         rYmO2MTxbJ3JzP8H56w8RtaTJxpntI2iQvw55LSKZqcoDLqnr4RTXoU+mZXGU0DCAra8
         o5SA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Usceg2pQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404002; x=1755008802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RyX1Ka5ErN63jWFZexw8lF20xkI5o+kwQ8eSlsGTqJs=;
        b=dfoDFqju/VmsQkVsYakuN2xa88oizZSnD39IQ1499AVmprF4ml8GFTn269hSLMv+yA
         Q6Txlow/6dv4G5buKyVmqzLH+ubT+j/uWqoRg2ZEvpOzV9T41pgRmEP1UIyyqSwnNvkN
         11QpfPz/jh5Z+ht3rcvENBlVurreC9KQii4iqDgG7bTXLGfG8r+SKbkeKRqUk+Jq1jCE
         lI+5uMOBWN/duUOFVsHkgfIf8Wxoq6zXodTrxvoSJuAC6ZunfLdEIqq7+WWnKUnbzUtf
         ilWEO+aDLC+VJjQVrkezYhhdr/N1blQignhSeOJURscb0GFDiZt+NJz0R1EwJIHpFERt
         TZlQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404002; x=1755008802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RyX1Ka5ErN63jWFZexw8lF20xkI5o+kwQ8eSlsGTqJs=;
        b=lCgL+OIzYKrxRi9nQnH3tG7R4HmU1IMKaPVDj+FQ533mi7K9N9S4mbMlhLSgBe90IC
         cTCMfKgGGKrcbb8Lj9zpDjEbUUW29RIb0GOXICxzHpMVVRUIFXdbqCuTejepMBUckUWc
         oulMuRJf7W2VUWoQEqvEG/axE6tNmlDNq+u+jT9QBdNRPceMWtFILPK72BigWjDankrA
         GT8U83NXB65Mb1XDooziIQwStFo3whyRzoANrFA+gN/6aOKmSR7STEURN9EpLA5WctgG
         1vzzNrkJ4KSJZ5qvZC0FHSbRbQyWtCzZW1F+etR0z2ZiV2WmCdY/bThIw8xZz4pRF2zc
         8cVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404002; x=1755008802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RyX1Ka5ErN63jWFZexw8lF20xkI5o+kwQ8eSlsGTqJs=;
        b=BgnYhW3wDj86sxW+aMPabK57X1HJmID//Ix48udSS/jhQJR36NuIZtQEMn9MhOKFd6
         kfBMJ7ApQt/sZR8yfhrbP8kYOr8s0KL8ULKrWPCPg2DvI2/SIssPzRVNzHLj4EFsJvZ4
         62u7YTYmGaIOndaB2iuc6FpIqVfi8s4THWmJ1pgoLD8gJmj+4A4nlZ4UA2tqPRVotzNj
         cm13XxD+8pJ1RiCvkbGmIXP9QP+FKD6/+9rHrT2Si6mwCVkkYaQsP8tAjNN+1UxtRzXX
         2bUgp1jsFrboJX6MIZvWgLyBU9KYwDOvY3W3ZDjypTIQ0dGdBmTEjTJt9+OAikBtTQFH
         7e5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9uvfRZyTHDiHVnAwAVKNLcNcR9Hzm9gDoGS/b7jTuJcZHgix3zigGXnnPXSwtZzqCcTjPzw==@lfdr.de
X-Gm-Message-State: AOJu0YyuEdL1cNsmXLu4I3cN0A9a3k+MIKddNqxqLc0WT3MV8rs9yp8h
	cEGmrT52Du12CXX4eCnUT8i9aeD56g58R7E/vlzoN4RmK13SvK4wq6j8
X-Google-Smtp-Source: AGHT+IEQRZizLAuSt3NX973N0m5Kjl8GkEjYEw+NhBE8N7ILdtdCADxMJiXYPHRG6wAZApOV/JuTlQ==
X-Received: by 2002:a05:651c:989:b0:32b:56b3:d35e with SMTP id 38308e7fff4ca-3325677b118mr28374071fa.20.1754404001955;
        Tue, 05 Aug 2025 07:26:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEzx7pT4OhJkldpMzPFlx0Jjtxu5xOefyRcXqtb1gtVg==
Received: by 2002:a05:651c:382:b0:32a:5c14:7f1e with SMTP id
 38308e7fff4ca-3323894547els13539481fa.2.-pod-prod-01-eu; Tue, 05 Aug 2025
 07:26:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNZH0PMeu6FpPr/0eHFV0EiGsx8aSqlv+EGjvZ8gQaiYL5PTd4lav7G2MWSP+ESjX19m5LrwloaiY=@googlegroups.com
X-Received: by 2002:a2e:a98b:0:b0:332:5fd5:e3c7 with SMTP id 38308e7fff4ca-3325fd5f754mr36398151fa.33.1754403999169;
        Tue, 05 Aug 2025 07:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754403999; cv=none;
        d=google.com; s=arc-20240605;
        b=i0Rv7zRzkIjYi/f+AUZOOipPIn5sD2yt3yBQS5tV1FtkE2HuC18CluPshob0lqQoaF
         Owmw2lpq+rgBFaHv7bgEaiYJybCzhOLm3ZPKwBe8CJENb/YzQvJWF7Y9igRP+QVt56O3
         Xv1Z+rmMGIF38GCx2T6ujkoAo9SMXViurqRhJeH6hAXSuZ0sQ/zlAdD8euNQX1vGuFqt
         0TZASA9PijZDC7bh883tlHDlHlXBGgRvIvKhHrgiPNJdd30namg82o65RT00I54So/Ey
         lnAitlBhWdXo02OQEFm7UbnbbNBuki/nz4rgK1j6vjKY+Dl1a5oizMDkp4sp+QqMXHvP
         S7rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fypRqRD7duJ7p6/XnMiehAY4t+I2qqoeS7XCKLtEaPI=;
        fh=fAB6DCUS241AIfWzg6LstF8iD/OLj88XxHCtipbBfj0=;
        b=FpreCFv8SXSw9jdHIy/XlQMvbnoP2mC0CBTFz/09ViZYAbVw08huTNWcha5aQwn6o4
         vhoXLVzRiMTevn9fEnG8HQ8JYHb1DLLtK4bRXYeN4vI3VnUD3Seva8fy+xgX0KuN1smG
         yPvGJxZCnJIMzpdSPWnPDqlUjtUtlJ8WE7dGWnp1i9FVwU3UJVBWpDwSlADCCZaGdGns
         RLroHaZgpGHsjvKkT2Wj2ZaU9dQEMG0SEx0Ol0gYx+MSC/wutZGdvGN9bo3GgG7evDJ/
         5Kefik4I2++gSSTu9CO6TWeOggQwPhmbR3/6eALMrXQSv0fFHgB7rUU7fD1SzVdCsaxS
         JApQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Usceg2pQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33250b8b9d2si2347051fa.5.2025.08.05.07.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-55b93104888so4472687e87.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWoe3ebCukqg/TGyIEIeos3TTMGjaQ4SpiWaNmEybKQCtbOXmASlHwZ5sQQyi2M1Y3+PD29YiM4k/4=@googlegroups.com
X-Gm-Gg: ASbGncs8owmG3GZkRDPYn4uPPFcZEJU0L1YLazUTAfBB7hD1V+Z+d1pG/F4o0VFMJJh
	xpdzyaxmg+2hWiN4ItwabAZb+3/91jOe8crSWMODFQFQDtKuybbGjiKwjGrENqr5wTAAm7d0Mns
	iQLDeNldhgWpz3DO8uBNPy3Th9jiC4zfkn76YBC3KAgoNPe3ZsK45jHsnxm1qHPLCE26b+i98LB
	szfUtb0q04sea6attlpRXVCc/Z0t5y7I1BnnFeCpAnEtABOv0tE/zGfMDUDM+k+rZQlX+lGcxH5
	RiG/SAFD8TSRF73O0ulmJQ9+oK9XTS/uFvHqiBRRl/oy61u4bJXHTxklCYLnvqehBpsuIgwWkaf
	LYdpWIPUAXtrlKGR8WZAfng2DipofiqHMoq8lS4XIuHEqsBYUCXTO2UwCTkgHDrjuhBDJnQ==
X-Received: by 2002:a05:6512:a8e:b0:55b:5b29:61ef with SMTP id 2adb3069b0e04-55b97b89544mr4329067e87.56.1754403997895;
        Tue, 05 Aug 2025 07:26:37 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:37 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 4/9] kasan/xtensa: call kasan_init_generic in kasan_init
Date: Tue,  5 Aug 2025 19:26:17 +0500
Message-Id: <20250805142622.560992-5-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Usceg2pQ;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since xtensa doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op.

Note that arch/xtensa still uses "current" instead of "init_task" pointer
in `current->kasan_depth = 0;` to enable error messages. This is left
unchanged as it cannot be tested.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-5-snovitoll%40gmail.com.

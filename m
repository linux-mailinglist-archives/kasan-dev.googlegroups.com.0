Return-Path: <kasan-dev+bncBDOY5FWKT4KRBEEO3CFAMGQEV6J2XMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 79B9A41E174
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 20:50:58 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id v5-20020a17090331c500b0013e32daaffcsf3819402ple.22
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 11:50:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633027857; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6WbM871k+rKBXivhhrn35TW0M1BXJG6Ckc9o3XO519Z8QEfFXxlIF7yjKFJ6vGoE5
         +EPq9U80A/x0ddhLBK+0H9smYs+EziaPCFJ64yuvV5LZo8PKpN6oO2gmw0IzX31DD9f7
         5jTkI5gVd+4/C0RgX2e8N6Q7ZSJslLZ1Eybw+xFWrlpQp8EiDrQaio2vLtK+ezqVpa34
         S2PFUntkcIz/+BMxPzmgZK8Tz6b+ix2f2wgE+x5Wp8nUArw96HCvU3zlv6pk7/dYGDqB
         o+FMD1NhJ03wIGJnJjPBbG6+skPGEIDXxTPOYz7COk6Xtfnw011M+9T6WQI5SH3jLbl0
         ylJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Zh4GcXTPIFXFlBDtELc/eOeTnoDhHHS1muwAg/NOCBo=;
        b=gWgvmu6Jinevir6AEC6RpQOx7Cb0MzUMmlSM3oIoPvr2/alGNUu3iBxbDV8HDxuWVo
         3spTYpkRUjSXSofHmkGxQXph4MTfI+xjpQ7LL7jHWjw967YZlilbQ/eZ5ZvL358sSqyK
         sJG+oOobEu2N8GC4jWox2jlijTHYY4jpLL8CwasRuhTKx1ry7PfHjZ3/MEr9cQZ2P88G
         OHx7O+rSRC9dZomRnTQbP+fstDfG/mOspwf0EzijH4+Rc8US6ZBf5UMj5qJ5MCxpqOFv
         hZYTb/SiJnhPMcfb7A9Ux8oOOMF1pbhaUNO2tfF9jKDSRn73tTyrgj5x8Osv1p/FXPPI
         kuMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c2tPiDJe;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zh4GcXTPIFXFlBDtELc/eOeTnoDhHHS1muwAg/NOCBo=;
        b=RP3udVju34H6S5osjRxusTt5zk/6L1X+OlxYD/iMVkZtgqBZuUSmBrWy2BZqP1RicZ
         /Gw1yftHpeFPSR4FoaExfvRm92yyjDaEOIB6EK12c9UCkTS63RO3v3TVUhoRjDHp1ET3
         RgN6ur/Pp5FF5nj55Sjn62xi7exExxwU9+9vzLUTsmQA1CG5kZ9XgreGW5pZ24V8qhXV
         M+EFvjfylVXqoAvKgFZG5/3VsydEdJQpT6OeSy0AQgUXWXxtVGUe8vY4qi4/PdB/PZm5
         9WBWqIEtp6PdEQB5kVOgWpN6kAE9y88EmfinSuwU/FHvDi0SWoDsxO3mJp+p7/50MeOa
         9y9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zh4GcXTPIFXFlBDtELc/eOeTnoDhHHS1muwAg/NOCBo=;
        b=o30qV49h+vcmq7KRf8NI/Xr0X/e/WcdGgZ8Eoiult+8LPBgDoXdInXM/taavRN6gdT
         CNaqRu4FUY4qAb5r/bItnQ1HYr+QgGKrmxwRTTTCtzGkWQSR6YpSIOpVluZBKv5i2WpZ
         SnMlarkHnOpjPSx691sAzcueK63c3s3KQi6mHqq3x9hFf5LrTLEsheNAjc8nXKa/qeZc
         MZb/uRIdBn7n39fYJb36H4IrGE41R1pBD+dQqTVApQiTVsUjnTxP2P8vAUZP+eFbht4m
         s9x1p2ZdaNQoM9t0/zJfuJjiDbSokZVpA5XruyN+RG8HTHOkVc7Y1WcERROEhCmQF96E
         E8Ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SWkf5vPoGugYTSK4fLVoZMPULyFL7WHm7iYN7aD30Bt6wmJAE
	F2ucBPllKQcoI5SEnqPu40M=
X-Google-Smtp-Source: ABdhPJwxvivaQF+MLmpr6FspyenU/UHQORAQ8Kq2hTsXolZkITC4qt1khuz3p2u3KV8G0NuIBItcSQ==
X-Received: by 2002:a17:902:b94b:b0:13d:b1af:f9d4 with SMTP id h11-20020a170902b94b00b0013db1aff9d4mr6995618pls.0.1633027856838;
        Thu, 30 Sep 2021 11:50:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c498:: with SMTP id n24ls3992645plx.0.gmail; Thu, 30
 Sep 2021 11:50:56 -0700 (PDT)
X-Received: by 2002:a17:90b:804:: with SMTP id bk4mr14974502pjb.107.1633027856264;
        Thu, 30 Sep 2021 11:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633027856; cv=none;
        d=google.com; s=arc-20160816;
        b=kB51XHdO6CsepJA59gEoeNnP+q8ocL0BuKhxv66SLBl7X/9NS4P7+6DMSbQ2GeFosF
         aMuTk9Q8l+MTt5GaeB3oWffy/3ZuCC6Hps/B987AMT6PeXbHWV92fOEz/jc788Qo+LQv
         mhsUsWfi4maOE/BTW7mYhb5phcJdIFcSJheYetUSc+aEdxRhpMQyNIv8h8Eg/wfOWbr1
         6iMIHqQw/lsYsGg16sqYWShHoQ727s1G1p8mt1js3gdlNkmbUTJqBB/zgEdmyNvBkHAP
         mNgwKEaJ1vQpfikZRAApsd0af0rE4RhlJDFBlKyHz/AaunjGlWIRXg4m0F+wb1jwMNBW
         gczQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Fz4hntkqtj0uLprSVyAtphfn7lMfcGkP921vZJ9TXLo=;
        b=PT61QGiO9qm0oUbllOZpj+mVguVgPWXkxH36yaoBknAK9eQDrXcOTJh2yMKLMxnwcv
         aUi//d/ywnTV9rOgYyDYdcfb73LLOzEXRd01Qiqv12+uPGZ3mBiwU3XNYjWGWPrnxk77
         G5MyP81bk4543iDxX6XxkeJNR134waR6ZMfpefH+NuIQq8AaknEZrKnnSatQzt7nHeXA
         YcBl8MSp/NoJvGlNa1Gd/mPnwawH4uyS+VAT39oCdBuvW2kCtOc4H+tRQHbu3LWOGn9b
         GVmK4lF8tKI6ddH2aubjp4f6Qx/paP2c43pqW1ktfWPowhh97wFug5yq1tX5LeNjdRcN
         iWUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c2tPiDJe;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u5si1207344pji.0.2021.09.30.11.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 11:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8841861209;
	Thu, 30 Sep 2021 18:50:49 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org,
	linux-snps-arc@lists.infradead.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	sparclinux@vger.kernel.org,
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 2/6] xen/x86: free_p2m_page: use memblock_free_ptr() to free a virtual pointer
Date: Thu, 30 Sep 2021 21:50:27 +0300
Message-Id: <20210930185031.18648-3-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210930185031.18648-1-rppt@kernel.org>
References: <20210930185031.18648-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=c2tPiDJe;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Mike Rapoport <rppt@linux.ibm.com>

free_p2m_page() wrongly passes a virtual pointer to memblock_free() that
treats it as a physical address.

Call memblock_free_ptr() instead that gets a virtual address to free the
memory.

Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
Reviewed-by: Juergen Gross <jgross@suse.com>
---
 arch/x86/xen/p2m.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/xen/p2m.c b/arch/x86/xen/p2m.c
index 5e6e236977c7..141bb9dbd2fb 100644
--- a/arch/x86/xen/p2m.c
+++ b/arch/x86/xen/p2m.c
@@ -197,7 +197,7 @@ static void * __ref alloc_p2m_page(void)
 static void __ref free_p2m_page(void *p)
 {
 	if (unlikely(!slab_is_available())) {
-		memblock_free((unsigned long)p, PAGE_SIZE);
+		memblock_free_ptr(p, PAGE_SIZE);
 		return;
 	}
 
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930185031.18648-3-rppt%40kernel.org.

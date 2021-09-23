Return-Path: <kasan-dev+bncBDOY5FWKT4KRBPXAWCFAMGQEW7XPJJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D5EC41594D
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:43:59 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id 108-20020ab00175000000b002c4ccc2d094sf1990067uak.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 00:43:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632383038; cv=pass;
        d=google.com; s=arc-20160816;
        b=sTx4cn9k7Rbg27BK2fyej3jDPvS1aNIyk5dCbwrV5dNu3qIo9exT8sQRJnPO0RH+Wm
         NcjpAlsINcQ0xhxPKp1oCRQ1SmK3bp06QO6wNgCHy2t+5tYT2yCzmrkMJ8ACWlq4TT1p
         SCjWC8CMP4tDtYNjtyYx4OXvXuTX7oL6AyyPVFWtqM0vo3HMTPREO3rC+H04VFJrFtbE
         JhAxuCwZ/VA2kfutEOfAyXwAabg+rtOH7HHKpu9r0eWauzkapiEl9YqD9Xz/ZdRJjSen
         ykNC4fbc7j+PjhxiyBzgysucaWIa0it2s0uHdFu+y3txcKR3+K4ydg3Qns/hTjpiyF0b
         4bHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0olBXSf6Dcb+ARKr4sYpYN8Yu99yRf1Tq/ghfG7MNsk=;
        b=b5kT69mYBSmlyNQ0cIY2b6b5aKtpKnd4PDVaE58DKrAJF1y4fALepP8N3sCQZOuua2
         fY+QKYBAgG86BrWamYnBhiue1L3oKVBRWjgp5+XJ/om0w7bcOBFSIkMlPXQq0FoRYk5b
         VVx/OZ8+5ruiBKE0slDrinlPeFP6oXNRapyQs6BudzFfmkwgERQB9M1zOsJqlCoHqp8U
         CmfW7VHkmAq15t9HKutcsYABhD9J9zxti/yUY0B96TcPNJ5ytz4ZWH0AsgHqika8FeeG
         lSHXedencUs9eus1XplVE71RIWQoVQBilzfPz7VciVemEA/YR96/lx7mSUVHMd81A1+E
         FSiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H1kaX42z;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0olBXSf6Dcb+ARKr4sYpYN8Yu99yRf1Tq/ghfG7MNsk=;
        b=sZzhwqqtPhi19c1A3+xRsvak9VcEtefdvvNlCqlxM8smNv9fVMBCcTxNyBC3FgGMM2
         PjFf3WdzEgD4lSlSH/ScIaFLHU8KV7OL6PBMzJt79zqLxWleQs2i07QlReTel+5LbF7v
         UedzxP1pB+KXEOXyw/+s0ZSmN40fkzsK8gytJZlg0RU7eUHIZI2EuDFYbJAEAUqAnNgK
         Z2WON/2LeXPH+lK9UzaD2thc1JsOj5PldP4kmJgz0bhJQ63wUme5LqNNn40BIiliR92/
         61kedDgvTnAkEYiySyizlOYCjEQQQ5pcR+MxhjoEoWe8KtEzw1/eeNoM02SPURtXJa6t
         lFFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0olBXSf6Dcb+ARKr4sYpYN8Yu99yRf1Tq/ghfG7MNsk=;
        b=ySxG/qZg5mQSePRbDwVIdtHe9G7j1kUPQ8JWCPRR2Y0y4+IF90DvB0GcLLlZEbxvDE
         4UgHz5w7C64E3lOiHmBrTetIcgNHsaOq5kWG9PILyfbLpVhU1io8yImA+OU6Aq0ZeKii
         HOZdXPxWQfm1wlzfZ5o4Rw1nDjtF+0LI7MrhQUmdbpLbKDLm2QKk18u7XkaL5aTmUY+r
         YhDrdMOiWwTDEsIvpGBSsSHgWGXR4Xlw6OcvzxGAQkemQXgTuQAScjdDbpvgdLc5/Gnr
         VOLwvnNUjIIcjjSseunn4AZaVNwkWxfZfoYgAtRH7I/qp9Q+PaNuqvD1JAXXdcVS0+Xc
         +w0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530m2qgCVvE2rk5Bl41wXhklf03C61WcaiH82mCYFZx0Uyu7TBNm
	mTjkesT+GcUOqGs2bnRUMAU=
X-Google-Smtp-Source: ABdhPJx1L0OYEI/Pwx0Kz5S1h+exV5QtKPpnGjWdBGHuqVDL62FFddhF2jtP2Nc1IUb9dJf85UEUXw==
X-Received: by 2002:ab0:3766:: with SMTP id o6mr2978051uat.102.1632383038177;
        Thu, 23 Sep 2021 00:43:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:aa0f:: with SMTP id t15ls449972vke.6.gmail; Thu, 23 Sep
 2021 00:43:57 -0700 (PDT)
X-Received: by 2002:a1f:2515:: with SMTP id l21mr2225619vkl.13.1632383037729;
        Thu, 23 Sep 2021 00:43:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632383037; cv=none;
        d=google.com; s=arc-20160816;
        b=fJ4MYUK19VRMEVYMoACq9l/vzLfIPrLtJPe0XTIf8CCw0OHvKHV2LeHvCvWLXqfgJN
         /LvH04it1kXd962jyByCkVee8C6vTdJSa42OiNR8sw0JV+823fGkUWBESanP6Xy+/lBy
         EG77C4V3x7V1CbLx9BTGcsDUw4S/t+LGws7JKJLRADer9ZKdtAggLRX/tXSMAjgGBQwq
         LTQhTUeY86zKBFpBZPuztoxbn3vbaVkFaCPP9HRVPJPJzO1mVUJthVtlZ1zrFMcdvowG
         ezD9gHvmuxsSsqrcYfnoPjawW8vWZIE+C8osympENf8n5kM+h/eccfJRX8diR3IXYi+S
         cKnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zm/tNj0cxpy2GqfNwAc+yogvQgneCPLM1LFTrhm13rw=;
        b=h4FN+lo+pLPjwBi1j5x+R5dz8+UM6JCy+1gxMS2MT0LStgUZlhl8cVpOiUZ1mZMX2y
         NDP8EiYEl/0k3gBAsTM1PMCvtRxXVZLK/iDPiWSEEvhs/EOUslL4SV9NvJ4aG5H7lJwQ
         vQ7xe2GmeJIP0wYoZYGS5Nr0bun5eeKL02K6BB83gQVzejMcqcWU4b1ysXY3Uob0U4st
         s8ZGzuRGeNf6VHVGZXv/21Jadk84J/8qdOmpFUq5xB0kZ+6CblUlDFwjuWCWhjhfd18o
         R9OGfn5qiw6N0Pfkh1o9xtxDO9Dl1gp/9gav5O149veePEsh5WINNqTVa6i5lXsX7A9I
         NK0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H1kaX42z;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f9si314528vsm.0.2021.09.23.00.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 00:43:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9933660EC0;
	Thu, 23 Sep 2021 07:43:51 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
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
	xen-devel@lists.xenproject.org,
	Mike Rapoport <rppt@linux.ibm.com>
Subject: [PATCH 2/3] xen/x86: free_p2m_page: use memblock_free_ptr() to free a virtual pointer
Date: Thu, 23 Sep 2021 10:43:34 +0300
Message-Id: <20210923074335.12583-3-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210923074335.12583-1-rppt@kernel.org>
References: <20210923074335.12583-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H1kaX42z;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923074335.12583-3-rppt%40kernel.org.

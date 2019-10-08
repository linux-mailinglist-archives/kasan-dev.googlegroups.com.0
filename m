Return-Path: <kasan-dev+bncBAABBTGR6DWAKGQE5MRVIRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 12708CF277
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 08:12:30 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id z12sf4516413qtn.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 23:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570515149; cv=pass;
        d=google.com; s=arc-20160816;
        b=LXSCuvDWmAqtpNVrCO9cp6v8G6CJDoSdam9GtvHC2c8PNqN7L2ggDadZ90D2xac4NI
         Zy0MImrjHCQhcjJd/nY3fNxZTBzRC3nXdmHB5JwtOA2X7zTZg7mHrxnttqDXLjQ8MfkF
         1UM34odf/90Eo0gJUC0SehJxpKPzSgiKZ9U8CILihSlKubWlIosdh7Cmzi4f80bUhUPl
         oagWXsftjWF/NFh4DMgsv3kvAWJJn3u6NOCCIpAU6lTNUK7+qiqlCA+JpoC4xx8MxPNi
         yehO6v2HRxhECIjnT9GmST4Hzaujz7xHlLhTYW5AMlSA12Tjesp3HoktIK67SQWKqWRe
         9M6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=X6i2bUir9s7w8s41RqGjJvzCivUivii5ljqyD7LZ9Ds=;
        b=TwKwL1I418/oB0p7rGGIs8xX75E3H1CiyPSsLB9Zbb+C9YFqse8FNwHp7R/kQPr0nQ
         jSWtMNixMWUukfm7fAj/1p3pWcmSqsa3zxgf019gO8AClVk/fLcvNq6PKGZKKBT9apbP
         ZUhV7tSblNw3ambAEQVByC55Xrf7VYs8jthZsSH3Ea6TxXqPnVZyxwCux7K1FdryX0U4
         cP3G9AlW/7bcc7ZJ6VVJFv/LovlOXey/QuQohFGVZRLdSiSmEREnl1vRkOKMaTlKh+qt
         lT6Tp3uWuAZGljCmJOrV4WzK0I/vnUZmuqWySBHniIcLQaCrMrQ1ke6wcp7/2tZmaQGI
         3iug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6i2bUir9s7w8s41RqGjJvzCivUivii5ljqyD7LZ9Ds=;
        b=HtGr1RAdYUXW+Ee4pNBTx3GD30eCcMIqJYqdLwcI7/woLoRLpK1joj/0V2Jx0VEOo2
         XsLSO2RpMZNJX6ii8X1UMfLWu2CFE2/8YW3yRjF6z8am51E+TVEL+TCn4btIgxmVJl/a
         7rfaYJ5zNNbULA0i+16DRFBE4jbwJbNPg1Ba3LHSwqT2MTwfX6UrhmtRTUUQUAlPmGv6
         IzmXN+0Olqgc9B7Xs5NqO4ECiqSKMgL6hqGXqeJsf+pVmDLDOVVsAhU+NZY3qZVBLocG
         l2+aGm78zIMq0QXQfnZfWa3yMzrf+2fBiJ76KwKMvftYyNzEiA5jF4PiKKZVLqFthLYo
         SMSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6i2bUir9s7w8s41RqGjJvzCivUivii5ljqyD7LZ9Ds=;
        b=AuFjtELAe6hE40gJQGtIYzRI5bi5S487crk5U3hlBV23W0IxpzEpr9GdM3OJmiosiD
         omdv1fn6kSiw6/fahg+nonE2nfvb8aMEYz1xJ0Ea+w0sn5p4kMChnbZCvPWLY0LhUw1p
         s5euO54bh5kTSYKTVxI4a4aZGCyCa6YL1dMunmb80pBjw6QxJYprXXlOUfcV0J8uw9pW
         Q8XYwW1oFCqxPFe82kGbFDIjGUxZvsv51AlEanohQhA18F5S4bTSggeoV2r2UuiAzSJW
         WU3BlIrpfAYItgsVr/R1WF9RkZODqHOd+9REBDVHIGOJ5oStkxbKCK9ifr7qb4rMxcSN
         0mCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7/zE4OuenM0GDEUV1aDMdG/TRjLkyfHa1s9S1FQ1ZeUyha1v8
	bR7tl68bCWupgl/AusK0LNA=
X-Google-Smtp-Source: APXvYqx6gNsZ9NUrF0JBH9GKRm03gMPJ5EWXVeX7aTfm69DlhZQ2dLj/3v9zAut8iKYOCY6vM8ibVA==
X-Received: by 2002:a37:4c16:: with SMTP id z22mr27688769qka.42.1570515148832;
        Mon, 07 Oct 2019 23:12:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d246:: with SMTP id o6ls417824qvh.9.gmail; Mon, 07 Oct
 2019 23:12:28 -0700 (PDT)
X-Received: by 2002:a0c:ae9a:: with SMTP id j26mr9874210qvd.163.1570515148360;
        Mon, 07 Oct 2019 23:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570515148; cv=none;
        d=google.com; s=arc-20160816;
        b=CDAXko25e6GGbuB60gXUdwoDVMwPcuq5XsCUxFkg9vteah8P8+luRUcJ9fW6e7HhQy
         3BxhosQZ/Cd4fLb5nDF6X7GaipJSv56GsBEcoqLkvXEWvqZUHb2hLZxvltzamtp5swuM
         fC7ekckdbbx4wEsVhVbq+mDNXpxJzdqPhiDhdyL++5eVGNQxIp0GQcvN2pAqBk9uKd5o
         UODwohSBu+BIGvXrl7Jrae32sVqhQp1ldMDRw33+cOOdMpIrYBKzT7TkeVYSfCnTdCu9
         LK5dNYtE1aCNnuZ49upJf1K86idqfPxSg0yy24acr6sQuQ7Crdw399hcgcw3ObnK0VG/
         CuCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=f+V57mIuxcU3eo1NssNNzU+w/awJb4VMkV0TFNU8Cyc=;
        b=MoEEcFTLKp+IDLugknUeOzwnGishKj5Vkb96Kq7lx370QwsMz4KhxN2YqDFzzTfIbl
         yCCZl9KOj7C7Y4TZh9C41Iym48yo6SLI0sXI0JNpy+dUYlXvshEvWbFimfyYDo4oIWZC
         pyKp9aQI+8AJ69fW0BsoCVYAJvfONuWFPBMHL/5zLAuVlu1W0+fVHm4tzc+TkiPDbPRf
         3IH5xEYkPsb19V3IwPOeomamFpqYctkW1wA8StL7mhleiIlgZ6npC7SCc9bmYmsuTOAL
         W+r37fiTfUcfYTdk7GpHUOCSH515iabuCYNOmU1X4ZGOlineMHoXt3WXZW4MWK5AuUXF
         y7LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id l4si788599qtl.1.2019.10.07.23.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 23:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x985uHCM075309;
	Tue, 8 Oct 2019 13:56:17 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 8 Oct 2019
 14:12:08 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
        <alexios.zavras@intel.com>, <allison@lohutok.net>,
        <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-doc@vger.kernel.org>,
        <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v3 1/3] kasan: Archs don't check memmove if not support it.
Date: Tue, 8 Oct 2019 14:11:51 +0800
Message-ID: <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <cover.1570514544.git.nickhu@andestech.com>
References: <cover.1570514544.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x985uHCM075309
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Skip the memmove checking for those archs who don't support it.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 mm/kasan/common.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..897f9520bab3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
 	return __memset(addr, c, len);
 }
 
+#ifdef __HAVE_ARCH_MEMMOVE
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
@@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
 
 	return __memmove(dest, src, len);
 }
+#endif
 
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu%40andestech.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEOW26MAMGQE7DD6QLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE8E35AD28E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:57 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id hr32-20020a1709073fa000b00730a39f36ddsf2249794ejc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380817; cv=pass;
        d=google.com; s=arc-20160816;
        b=KlP6v+42IuoLs5umsBk4nJOA8JKeTmykiv+qE5PmGKgondwpUIGE8YsiY27gKI5/JF
         P8WfwuS9VVtznj9CnqtatucGnS+R0tjUZxQppD5NfdD5rolkmnFHEiCHIoWTI6qO4GkV
         Qlhxizk9pcpzFGnHxS2SwpbLEYZiYQmkRg9CATM1XYCZqP5yhVD0zhtEaurLfTZBYCyi
         xvWHt+WDBteEv+FORj271t4CSFQDF9sPm9Yv5un3dzOdmICDsLKBPsCe5dYhpi6TWvzj
         /F3RDaLgJJgemWQmCmF1HXzhtjpCqsj9TNLtaLfsf0Vghog7+4QL87MRauJG1U5BaIMy
         TutA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UcvYLYJLJPGFn11uqcRRKMvVDmqmYC6p1hlGN7cNVzE=;
        b=qBAAwxMOAMK7DLYyXMmKMS3mGRjCkKKLWH7d11niHbz7gaK5NMyjmJZQDkoPV+LYVW
         wmPI3iMTTkAPKxp7Z/FRhVzSHb+PBiD4qjXxxzj+oJ+gzarOOA7lF/G9biLLxOROW5pk
         VxiZwo0nHWdrrjgOm++0KB3moRf7Yenftdp86rEQrod8OYxt+VYkEdwtmnLg9IXr3wPN
         /oSArfAAp4RD43IML8XpiolXuUhc4je4ly2MMoiY6+RLoYkGF39srMaEPIwBwVpTE1jj
         0BnlqgSFPj4y5joVd5W2ogiAZUy612PG0kEbCusd8f36j/rOfyh17dQPQFPKOPJ8ulAp
         gQxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UJpdtPzQ;
       spf=pass (google.com: domain of 3eosvywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EOsVYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=UcvYLYJLJPGFn11uqcRRKMvVDmqmYC6p1hlGN7cNVzE=;
        b=D1xEwDdCm4JoBVMMg0N/DBFnc47O0IO6m+fEewmEVcBZwF96cF5WBQBPBryMavH831
         Nov9yTO300mueq3/Gfz5rpFxbQqek6OLEEm0gGwNYaX1f1Ky1Zupyml/8lkX8BQWjN3C
         GUAOphAterXecoBhMBUoNO9XU5iTPNORjbitwwqDcHQk0AL2Cq/31bazVPwTTbHK/91M
         XVtsM253/qpJPDTEAUQGjmmtymPpOCuYNtEqn3RUiNZCcwRdYsbz624wYGcAIT2vZ4i2
         IJRhwu/Iooish2jzM1df9lDzA/tVqB6VX1d+598u7CURu0HSf5reM/lmyW/+DCtaJzoa
         j0oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=UcvYLYJLJPGFn11uqcRRKMvVDmqmYC6p1hlGN7cNVzE=;
        b=rX2ogXUVTRoCVYUnG7+HmPhTb9vvxEbxEHy5+nKISg7RIWnu258IIoUIBBu9LnI1sY
         VYsFEbeZ1nP1WWv8G02xgtvhkY2EEh5sHNRnhw+0h+UUmVKxXOEY02EhMNP6BT3fsvZA
         EQRStkpyXHGs/lpFfk7FrzKlBUeb8+C28yT+shd7a/6HZwERWS+erw4TyYKxFN1qwyZG
         8Z3jVAUF5Jz3Hvaymh/i51NfrqlVl9QjVJ/uO4o1iZV16GHlzvha8kuia4RcLNewUIM0
         IxcP1v7FZEueno3f0t5fdNwHUZCBD9jEDwh9ATpOZVlIspxxb0abMpyytFnYTw3/wTv+
         3kSA==
X-Gm-Message-State: ACgBeo3nUIcMeqQZLgw2ehogTdKiMM6zT1s6q3ishBUA/aTCtTyIf993
	yBMu6hluVxLMaDBCOAYwypY=
X-Google-Smtp-Source: AA6agR41ITumTvqGwuWzidP9uXApBW3EH2+Eaja43hbpZ2/Yy1Z2HwZibH/seVM45r9hg9yGYlgqug==
X-Received: by 2002:aa7:da83:0:b0:44e:69ba:81c7 with SMTP id q3-20020aa7da83000000b0044e69ba81c7mr5566198eds.323.1662380817565;
        Mon, 05 Sep 2022 05:26:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3f87:b0:726:2c39:8546 with SMTP id
 b7-20020a1709063f8700b007262c398546ls3422069ejj.8.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:56 -0700 (PDT)
X-Received: by 2002:a17:907:a426:b0:763:318c:c0c6 with SMTP id sg38-20020a170907a42600b00763318cc0c6mr5809795ejc.671.1662380816566;
        Mon, 05 Sep 2022 05:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380816; cv=none;
        d=google.com; s=arc-20160816;
        b=kBLcBDsOZeROkth2IsZvvEGnomNXjaavXPZ22Zqb6b7FrGtwDq90hW9atIIMm9zydm
         oVhQR1jkmWY36FTmqFcqOfatpuEmJGwVaBjOmh6gehJznAkWZF5zriJffTULaNSJc80U
         e7c3pu6kPDde6VwqvKnKAxvibmik9JF8+7d3E3WCC0pa21rPMmkZ/6xE7wieW3im3rHj
         nobRiGCbi51/bQJEZQKp+bfBzF3MbUuT/ypid6fsdd5WGfJ0+QF33OD7J9pczf7f7VZc
         L87j0R2H771NcRP7Fslcm15hYkcehJY/wFCGllYeaBT+uD0MNA6rYm/ZoiPFbDcCzA/M
         AfDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RV5QTvMygwcM31S/hyrs6MnTkve28DlweGTrQchhxXo=;
        b=hjQKZSGPzdPhqvceJOE7SsaMZ1ltuae5WBvLTOfgxzWXtqu8VFT8cuKC2SY86kSHfj
         BbhhBh+megm4T8njx9MtcDNUsEhGprD4DaYqWPh2ii+PaeMUcO7KnGz0/j/pCJ6O01/q
         myTC2LsuBWrpmEOIoJLn0IaJwM935U3OU/A2dsGlWxhyseOP0SNzHs1EziaMhRq5j/0X
         P4/95Xhgovzg3havNmPcxxsIaAeyWgMBPXE5hgDe66H44omIunHBtl/JousUR9EvEJyw
         HE1g+XuTDFkCa6BSdg3LhJk68qKSYweZDymbJXDyZS1DtahuRDLkgUMOrp+9QAoFdYp7
         fSJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UJpdtPzQ;
       spf=pass (google.com: domain of 3eosvywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EOsVYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y4-20020aa7ccc4000000b00443fc51752dsi450574edt.0.2022.09.05.05.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eosvywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f14-20020a0564021e8e00b00448da245f25so5687705edf.18
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:56 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:cb87:0:b0:43b:e650:6036 with SMTP id
 r7-20020aa7cb87000000b0043be6506036mr44092076edt.350.1662380816223; Mon, 05
 Sep 2022 05:26:56 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:51 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-44-glider@google.com>
Subject: [PATCH v6 43/44] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UJpdtPzQ;       spf=pass
 (google.com: domain of 3eosvywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EOsVYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Functions implementing the a_ops->write_end() interface accept the
`void *fsdata` parameter that is supposed to be initialized by the
corresponding a_ops->write_begin() (which accepts `void **fsdata`).

However not all a_ops->write_begin() implementations initialize `fsdata`
unconditionally, so it may get passed uninitialized to a_ops->write_end(),
resulting in undefined behavior.

Fix this by initializing fsdata with NULL before the call to
write_begin(), rather than doing so in all possible a_ops
implementations.

This patch covers only the following cases found by running x86 KMSAN
under syzkaller:

 - generic_perform_write()
 - cont_expand_zero() and generic_cont_expand_simple()
 - page_symlink()

Other cases of passing uninitialized fsdata may persist in the codebase.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ie300c21bbe9dea69a730745bd3c6d2720953bf41
---
 fs/buffer.c  | 4 ++--
 fs/namei.c   | 2 +-
 mm/filemap.c | 2 +-
 3 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/fs/buffer.c b/fs/buffer.c
index 55e762a58eb65..e1198f4b28c8f 100644
--- a/fs/buffer.c
+++ b/fs/buffer.c
@@ -2352,7 +2352,7 @@ int generic_cont_expand_simple(struct inode *inode, loff_t size)
 	struct address_space *mapping = inode->i_mapping;
 	const struct address_space_operations *aops = mapping->a_ops;
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	int err;
 
 	err = inode_newsize_ok(inode, size);
@@ -2378,7 +2378,7 @@ static int cont_expand_zero(struct file *file, struct address_space *mapping,
 	const struct address_space_operations *aops = mapping->a_ops;
 	unsigned int blocksize = i_blocksize(inode);
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	pgoff_t index, curidx;
 	loff_t curpos;
 	unsigned zerofrom, offset, len;
diff --git a/fs/namei.c b/fs/namei.c
index 53b4bc094db23..076ae96ca0b14 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -5088,7 +5088,7 @@ int page_symlink(struct inode *inode, const char *symname, int len)
 	const struct address_space_operations *aops = mapping->a_ops;
 	bool nofs = !mapping_gfp_constraint(mapping, __GFP_FS);
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	int err;
 	unsigned int flags;
 
diff --git a/mm/filemap.c b/mm/filemap.c
index 15800334147b3..ada25b9f45ad1 100644
--- a/mm/filemap.c
+++ b/mm/filemap.c
@@ -3712,7 +3712,7 @@ ssize_t generic_perform_write(struct kiocb *iocb, struct iov_iter *i)
 		unsigned long offset;	/* Offset into pagecache page */
 		unsigned long bytes;	/* Bytes to write to page */
 		size_t copied;		/* Bytes copied from user */
-		void *fsdata;
+		void *fsdata = NULL;
 
 		offset = (pos & (PAGE_SIZE - 1));
 		bytes = min_t(unsigned long, PAGE_SIZE - offset,
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-44-glider%40google.com.

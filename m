Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUEH7SKQMGQETSTGGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CAAAA563549
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:20 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id cf10-20020a056512280a00b0047f5a295656sf1180168lfb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685520; cv=pass;
        d=google.com; s=arc-20160816;
        b=QhDSP+gS7LDUIfa69SfOc4sVy01QgY48mlLAQ9jeOcOwgmjvgzXO+uOZSEIF4Io4BI
         GK4FkH8cEIbSS3cAOrVKeaxrbn0qGnV21zj1KuTxardlvetLi+yOjHkzqWhCw/TKDpc3
         5+4H9TsePGJerFWjJinrdowkH5PbR+m4qhstz6HqdJI+1WgP2zkoEfMz7q/elaWsmU34
         HZ1TIMLShDl1EHP6y9MEsQNoX0Mu6MFNg+0/cRaUBda0FeImShcZgKOH+nTwieh4K9Sf
         QhcB4qtnRUgxvOTUb9ije30QAw6hYQegcmeUq7s4tgGqtHE8jJTWIwhLEh1XL+Z59hln
         yGvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YNMH9zS/0kC65KJfWqKPZ0jAjNPv4JjA0hE5Oo/lf8s=;
        b=J0tt8yT8/UQc3+JaHohK9SqXBmQlaj86uitnhVYAqXsffVN+NXl2EhQRlsjIaZoGXe
         I9PdXnil62AScfMEfDrthtqDIy8zgAVP+6Ts3JYeUeoFChageVT6wGjbzsqPIJIfJtnn
         0OqlDEgeeQdiAyFdvEqsDy51zl0fphiRKFYGlGTDqLAqnIzUEDgxSsnAVf4b76bWbo5u
         1EOfjhmQPu7VGaHvMimT4YRS7VpZqFTypuuhPVJSlKKMLIcUPdbJN3Z3102cTWmKQOGV
         Do7zFOWF1quMs0orVPOE4XEr0nKXvC6D0E2YVy6jPFiRnf/YLPs+ydyy1IFN02ZRwJQ/
         9j3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P7QKDp3h;
       spf=pass (google.com: domain of 3zgo_ygykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3zgO_YgYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNMH9zS/0kC65KJfWqKPZ0jAjNPv4JjA0hE5Oo/lf8s=;
        b=G/Zj4G1TEVEce6c4LljOSGD5Vo1DuE+s4IEqddbFw3NER/Fjk3npVPEdwTx6jdLEUC
         3okOkMieoY/9ctXnk3BsgUt8CFAGDKCesnMuiU55QNgxV/dQF/yZ/WViANweZlQ+t94D
         lWM+m7KXKvHhPXF+gmgUWOAn1oT66ft/f3aNmqL+fRo9JC/ZFMsExSZ4XEZlWPuCLdpL
         v7zUJkDSZlUxrcEuyI4FO99RqDYG/fVgr4mK7I+7LUEnijdydzGYjPmU2YfiGYoVLTDm
         lkUPV4zt3hPnPZxg+Eh+VVWz/dpfkV3aHl7m/LYSZVm4CUckqzTAew/7XCuU3NuE3/7f
         wFOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNMH9zS/0kC65KJfWqKPZ0jAjNPv4JjA0hE5Oo/lf8s=;
        b=waVJL1UT3iDxRubOWXStFdxx/M+4AxO0NCklrcWAODcAjq5jiXCIf6I6Og7rYw0cp3
         Pcmd3VWkOGI1actI8AamuTaKwX9r8xNzyM9Ri+ujXAMQGvNU99alLrkfOdGAAoXQFquN
         1WiLp3YajAewRYABE8lFQbgP0Q/UL5amVI3HpF/9kkt9XI1xgR22vPnv36WMLm8PYfJ2
         N8eXYsJvXIookR3CLopWYW5w0tcqXNLomIXtJr8F+4MBmdcXU+hopOAAwv8LauiJy51e
         5B1jrcpzUco3AL7DdIseBQeKfjRXH/VwAtc9/BocfQzBUk8HBTc1uJmZ8ABUiRihxT6g
         UINQ==
X-Gm-Message-State: AJIora8W3ZpxbDdAM3H8mzkUp1ZHemGt20tVvCIzP8rkJ9htK2LJ6/8F
	j9gBYoqFOtG2Pvd/jRmGYAU=
X-Google-Smtp-Source: AGRyM1uJn90RJUNguOmOYTX6ZuKSHhP4Fx20d+NBYQEI1necYk+vnhRGFibvErM9SCyNgb9/sF9j/Q==
X-Received: by 2002:a05:6512:2524:b0:47f:b0d9:d096 with SMTP id be36-20020a056512252400b0047fb0d9d096mr9192436lfb.243.1656685520345;
        Fri, 01 Jul 2022 07:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls89669lfb.1.gmail; Fri, 01 Jul 2022
 07:25:18 -0700 (PDT)
X-Received: by 2002:ac2:47f2:0:b0:481:4e4c:ecf4 with SMTP id b18-20020ac247f2000000b004814e4cecf4mr6335338lfp.291.1656685518628;
        Fri, 01 Jul 2022 07:25:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685518; cv=none;
        d=google.com; s=arc-20160816;
        b=Rk15sdVffJAF5LAQ/yHrowmWQuWQPJoIbuI0YM7TAr1KunXSqOf5VbobK1cZSpfVVJ
         YNNM5PLHc5yf24HTKsL3xAU8aLdzXI9JMIcNQCDNZayEeNwZskfKMinbbPM5j2yQfr25
         K+a8iVdrSArf8TxDHFto4kaoBvCERB+ZStQ98WLRit6HnyNfbYTsdKYJiyagox8PxZEZ
         bQHgnDkKkbAauNulU6ZRESXRx0hlv6TAmJ2dwjTW92qtFeeKsgEvyupIQSxrpOmvFZjH
         VNoDnCL3AWA7SBG/7+2Lq0g2/7AxhvI2YbW3jhZFtDHdxfN8a2rI20BpemjZj+P1bmbw
         vzJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=iGvD4mfjvjSWX+nv6535woTSPAyHTTcU/sEMimyHpxI=;
        b=NsGIAgriguxzbY4a/hcz3VQMIH3f8B+/m+kVgMLi2O7E9nW58DMZEd/cUq6mM9Kow5
         J1N4npbDSYazqSKrZ+fMoXfxiRjVvYUBuPhiCSfsX82o8c6Aty48i/XXx1tQZYd9mXRn
         H2acwNBYNyozF+bEMvL/B37SgHSDIbjixftEfiPrXR3/6JOhOsG1G9e4rf49P77Mj0IW
         eKaYKtDdL1Kakc+o+Iqx+QpHweyIV2ahFDkR16/qvTWOAqfGwKrw5pTCdDW5Ib46Gajn
         QOPWYQS3jI57HyUNEeX+3DLhc5P8fDz4SM+EfLZcJdd6SyvWFlx5EVb90eB/23fxSX+Z
         rFSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P7QKDp3h;
       spf=pass (google.com: domain of 3zgo_ygykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3zgO_YgYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id c7-20020ac25f67000000b0047faa025f65si45277lfc.12.2022.07.01.07.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zgo_ygykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id f29-20020a19dc5d000000b004811c8d1918so1182758lfj.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:18 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:4c3:b0:47f:6f6e:a7e7 with SMTP id
 w3-20020a05651204c300b0047f6f6ea7e7mr9859006lfq.674.1656685518270; Fri, 01
 Jul 2022 07:25:18 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:09 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-45-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
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
 header.i=@google.com header.s=20210112 header.b=P7QKDp3h;       spf=pass
 (google.com: domain of 3zgo_ygykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3zgO_YgYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/I414f0ee3a164c9c335d91d82ce4558f6f2841471
---
 fs/buffer.c  | 4 ++--
 fs/namei.c   | 2 +-
 mm/filemap.c | 2 +-
 3 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/fs/buffer.c b/fs/buffer.c
index 898c7f301b1b9..d014009cff941 100644
--- a/fs/buffer.c
+++ b/fs/buffer.c
@@ -2349,7 +2349,7 @@ int generic_cont_expand_simple(struct inode *inode, loff_t size)
 	struct address_space *mapping = inode->i_mapping;
 	const struct address_space_operations *aops = mapping->a_ops;
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	int err;
 
 	err = inode_newsize_ok(inode, size);
@@ -2375,7 +2375,7 @@ static int cont_expand_zero(struct file *file, struct address_space *mapping,
 	const struct address_space_operations *aops = mapping->a_ops;
 	unsigned int blocksize = i_blocksize(inode);
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	pgoff_t index, curidx;
 	loff_t curpos;
 	unsigned zerofrom, offset, len;
diff --git a/fs/namei.c b/fs/namei.c
index 6b39dfd3b41bc..5e3ff9d65f502 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -5051,7 +5051,7 @@ int page_symlink(struct inode *inode, const char *symname, int len)
 	const struct address_space_operations *aops = mapping->a_ops;
 	bool nofs = !mapping_gfp_constraint(mapping, __GFP_FS);
 	struct page *page;
-	void *fsdata;
+	void *fsdata = NULL;
 	int err;
 	unsigned int flags;
 
diff --git a/mm/filemap.c b/mm/filemap.c
index ffdfbc8b0e3ca..72467f00f1916 100644
--- a/mm/filemap.c
+++ b/mm/filemap.c
@@ -3753,7 +3753,7 @@ ssize_t generic_perform_write(struct kiocb *iocb, struct iov_iter *i)
 		unsigned long offset;	/* Offset into pagecache page */
 		unsigned long bytes;	/* Bytes to write to page */
 		size_t copied;		/* Bytes copied from user */
-		void *fsdata;
+		void *fsdata = NULL;
 
 		offset = (pos & (PAGE_SIZE - 1));
 		bytes = min_t(unsigned long, PAGE_SIZE - offset,
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-45-glider%40google.com.

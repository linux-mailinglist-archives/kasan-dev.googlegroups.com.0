Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6X6RSMQMGQEPQAZCEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 02E7D5B9E35
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:35 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id oz30-20020a1709077d9e00b0077239b6a915sf7801287ejc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254394; cv=pass;
        d=google.com; s=arc-20160816;
        b=CjcRiUjNwZ1UQVgm8i+tksV6va6Lk4NSSfmSJnMJ70snp37Ts8GwvJmrBUaYkBs0wK
         OkB3KHqe9BiB0rPVOiLZ8WBPyILoGsviM5wLUsDIlzA5ii+deZw/yl1y2pnZjIwEytnP
         1lNMTwwyiH+qhQgfqWoPTbugEIdM4pbV+H7mQkWfvYpdll4gcQ7zRo3OUC6oW4tXpNrG
         K4IP4bn6JZSUm6L9+8QSmaGKAsip4cUHhcVfIW02bPvphvj3IHWGfiKMFTdIsiYPBsW4
         zBdMdG69qL1GB7WTtrjJkx9mlkDWXqerRQGsM/lPk4ANOtIo9W/HrbHuzyZmZBo+CKdr
         uUpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=arPLVPR1YLw04hOi+wJ7ZvxvXQFOhBWRkz8/E60P+vY=;
        b=GkyuddxrdlrekuY9PAzkzADowo81B4qSfPGwhHRedBgjDdUonk/FUFNm4KKd9L/hIX
         aTS6vpa5yMc9odWLOoJwz36Vb5BSZuVOiPPUe5qCWny1rST9s2y93i5JEF7GyQRTDNlP
         K/k0TNwnO3F607kAMFuHBX15piNJ5ss4kSUI45CxAcTvmQataH9fKFCPbZAHEMhJNG55
         2MtcsHOa0ZNSicBYBAFBRu1WyCh7UqUWgXJ340fqhJniW4ERJMk49FWIuZT1tKzJMQTU
         KddA43UDEDddkYvSpWLf8bBC+iGMcLYZ3xJcAaAnsdl/Wy/2JbTl6ryu7mh2axE1Ma00
         0Rpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXaNCvcx;
       spf=pass (google.com: domain of 3et8jywykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eT8jYwYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=arPLVPR1YLw04hOi+wJ7ZvxvXQFOhBWRkz8/E60P+vY=;
        b=qcXjSezS49gheMuNSw21nb2hByQCZVxkQ1YUjaBI7k4a3uHcR8ruTJYdtYlbFDi1tI
         D/NpU7iA74m/o/3hihePzcGHteROkrksYRLTW/FO3aASbMXadUBqWUgTGT/qwHeL0c4v
         Djy2aB8xPP2m5cJXF8HIzE4gcUPmv98GaewX5YNKsOurL4mtT5voZSt2QvXDz/4gsOk7
         ULvU1Bg84xpDFOu+qJkPoXvMJ6U+Uqeq8OlWDD+3bApX0qSIFztjkxF/8XXMtwrxKp19
         4PdO6cTifwFPdw0UMsGNPvUcN5wU4qKInf5Iw+aWqUxKKzWPaSg+nA93iatXDqTF0DeK
         cL2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=arPLVPR1YLw04hOi+wJ7ZvxvXQFOhBWRkz8/E60P+vY=;
        b=edRSzDoxaiY/Dr+mDrqTSrE9NmPBM4oh4fFFrP0PiMX7CQD9zRPcr71yJKtyIC/du4
         pS/YVBPRBnD2c/E1ZEfzcL1/yKNLCzuUIssnldJa7d8OTdfDQ6x2Q6VA85sKfnaTDuBk
         f1wPCuJk8q2jCrSi355KCAqSEAS5BQj+6fAR3w7egmVdk5H1MzeKev/dI+ru7zk2eP0k
         rjxnqPipqXJkjL6TAz32eROb9Y1FBAKCBrR+bRTABlObQYxIR8+85B/h9fRWh4AFKDgT
         A1GTE88O3my16pZ/pqVj2CQOdZRtYCVvmBUT69rctI4qdPwOfThpDAxZN38rE/oL+s3u
         8dBQ==
X-Gm-Message-State: ACrzQf2vTnAcxw5Teh+Bb0WCvac4HYgqMQCOrqltlMwThxdwSyz/mgGR
	9AY6mRR5ZO6X08P+IU3qN5w=
X-Google-Smtp-Source: AMsMyM7MhLgKf1BNj/m6bs6AuPc+G3Uo7RNaQmyBKigvvGEXb2hH5wckQz/YRfk36zb6W8nM3w5qvg==
X-Received: by 2002:a05:6402:2711:b0:451:327a:365f with SMTP id y17-20020a056402271100b00451327a365fmr244032edd.315.1663254394616;
        Thu, 15 Sep 2022 08:06:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:76ea:b0:73c:b61c:65e3 with SMTP id
 kg10-20020a17090776ea00b0073cb61c65e3ls2525889ejc.11.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:33 -0700 (PDT)
X-Received: by 2002:a17:907:1612:b0:780:34ac:befb with SMTP id hb18-20020a170907161200b0078034acbefbmr282640ejc.315.1663254393505;
        Thu, 15 Sep 2022 08:06:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254393; cv=none;
        d=google.com; s=arc-20160816;
        b=lywVILnBa8qE8Qwb5DGHToCL7w5vjDY4NOuISq6CeBZxBZGFe36ktZwdGoiFsIA6VO
         DJc2QE3iTsAOthuaJW8fcmiEoOhmT2bUE3KJE5A+/PGrOyAwRrD6zzopc6D7TZquLJ9E
         f1lXV05jjH/thQ64Nq/ZCzuXbHptb6VWZN//ZjiLd9nLe9cwJBcX4x+E/s3oBlUSdKy5
         69ttKm9vlwkxBnk66ynqD3+b+I5K3mgk/qcZFYCrLV5nPZFxfReu2AjEINsRLJJliU5i
         T62zwXoTNTdGsoOWaSAJxNj+7Zr0kqURROcg55K+cvAPDqnj1v5+qn3xfo6+mu5Rbr+e
         dp5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RV5QTvMygwcM31S/hyrs6MnTkve28DlweGTrQchhxXo=;
        b=C18JpVbzQ0HkGGOJEP62aNTfbUlzSoiNfShgEwgVBnDMENVNf9PK72rL82UgcTmUJx
         lWu5uJtbsbhIsb08o15VdogCR3s/J0BHSbKRD27cjWciJJWn1Td1SgkkPehEse5H0ahY
         Hb3WAxa+viWzidZdwgynz5i2NjB/Ie87OK3sSoguIJ9TCeRsfKd7Af8sgMNDJbf0zKvT
         oVybtkHRchcjpYVyXM0Kq3iRVpUkuwlRXtli2OwZB/5vhdbRhG7shBjEb9LYlP8YKpD9
         K/rJl6VcwyB6W0RNWupuidDozQuBsibOiUfZXT8ir2Ogenxxo/80JG8+rOwJPtOuGxo/
         vYjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXaNCvcx;
       spf=pass (google.com: domain of 3et8jywykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eT8jYwYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c12-20020a056402158c00b0044608a57fbesi551893edv.4.2022.09.15.08.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3et8jywykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r11-20020a05640251cb00b004516feb8c09so10387661edd.10
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:4306:b0:451:8034:bcb6 with SMTP id
 m6-20020a056402430600b004518034bcb6mr291044edc.198.1663254393224; Thu, 15 Sep
 2022 08:06:33 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:16 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-43-glider@google.com>
Subject: [PATCH v7 42/43] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iXaNCvcx;       spf=pass
 (google.com: domain of 3et8jywykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3eT8jYwYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-43-glider%40google.com.

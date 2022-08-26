Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVWEUOMAMGQE2ZSUK3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 32B6E5A2A95
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:15 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id y14-20020a2eb00e000000b00261caee404dsf664077ljk.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526614; cv=pass;
        d=google.com; s=arc-20160816;
        b=b7XuEqcTbXwkCmIxyr9g0kTN9wiXlXP3poki24J+2cqdaPP4aOzUM1C/2kuC0HGpIJ
         HMHJ9X9oBmR2q0yPrIAkTTa07lWyQDlpy1k0JPT+BmPYRKP2EgXoodYqlFzydWUInIR5
         3xhpNGOfRhByEwDbhXqMwZyEw/lCPQeSjZ4jJyMTqjVU9ERzE5JuGh0MmJfUsLaRI1vF
         TcL8QpUTHne59Pw6Qt1tb3B9lTUxbFBjUvOet61fsBjw8QjpuVSe+aw2vw7fnK80LXez
         MqlUsHFwtGfCPLeFeySs7n6uXjiYnWlmn9JV2GtfMu6pI+ZM7JhCHDFc6HWtWRCTkYmk
         VrBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Hl6QZk+1tTfaDRT2S6LOoglxc/oVNk6f7USm1LWJRjs=;
        b=OweVSGa7zmzlQsyLjkOdwf5atdeJYijmEQ6uxiiCmTb3AzMb4EyHpkA/mozhs0K7Ag
         F+QwcmD7Sh6iIV1usJFwudByOjo1yhX1nW8GNphXg2PAfkBA4/mUClUIvNzFHkWIvH4+
         fB3rUiJqVdLhzMIepA8w2S8GQcn9WJau00cV2H4PKx3TSxNLukeW1J2pL48LdsY0J4nO
         M7bCeIIfVlhG9q2iLQ2o7cuQmPwTgbP8rjYRN5I67vruh2cJgrFb4ZvBKGAPQiiKwinz
         D8DmDKIpA+rl0K/Il0d269PAmG4b0QeX9KPDeFlrk5F9JAtAyzp5Zq0PyG45AHnC5eU6
         ojeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DZGsI9l3;
       spf=pass (google.com: domain of 3veiiywykcvwafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VeIIYwYKCVwAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Hl6QZk+1tTfaDRT2S6LOoglxc/oVNk6f7USm1LWJRjs=;
        b=pvX4aLd+pQkeM8ciAGpCKw8tOQ8fNCcXN3DKCouwvu6QsQ+3AaEWidVDf3PjcKUCje
         owjih3sQMR1sWRLOCha4J41TDOjyRxr9NDTBplz9uyBk04SuPjyYD2Q+v7B9awcI9Q23
         7/X2I29KmbOuX9SADFYJbDRhi5vyVE4LSUIk+RuzNfQcGo36Cw56DYZ2QNLVpoKj6ySz
         RwaUVOhlwrdnJ0nNdmef2VnZGz9/TTCad3pU45fkZURo1jxaLeE269sjCdP11Cg8LBwL
         Vx3dLGpsRUqMa9zSC8LLf+zggArrqxp1v0Yz0BZ9ckaWi99ZUX9J7ERToiKXnXSUQdig
         Sf8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Hl6QZk+1tTfaDRT2S6LOoglxc/oVNk6f7USm1LWJRjs=;
        b=SONFdTmAUiBPYChijPwCCOZTEYkDdM10lshQymPSqfSiumPoDl2BUDUjh71we5Wvb+
         YfmUE+v4o33m2hHhvL0Twx/VQwtaNnooA1ynmKhJh4+dFd0r/0tj5oemvjRtnFc2wKpG
         U+Tdl8rdtnepSVrBBLq+7F4x26evmovjhgbtXgVfYWZtXZk3vcdxNcEDy14WGc80pvUn
         LUvY/Qmf2kCmt7iofb0jQ6wZCUr23b6VPHxjbgmkHz4tsS8vGCJfUjJ3ljR30dzF2MfM
         PNeiOdFwezpldThW+iDtLx3GOlQsfzjlhz8X1IU/o5ubuT+lYTfANIuT5px3vjGDw5GY
         yLNQ==
X-Gm-Message-State: ACgBeo0KAEciSDEImrMmWijBndkV/Q8lbNdUFtAovKncazZpLNc5Kv4t
	pGAGJE1ksNOUV+xvexpjqxk=
X-Google-Smtp-Source: AA6agR7v/ySlTQD+UMeY91ZDy7TH8K0Gnj0ZmAnaXigfZSyV+a1nPwa0uYZq7zCdqwSq8jDvUE44tQ==
X-Received: by 2002:a2e:9e43:0:b0:25d:d8e9:7b15 with SMTP id g3-20020a2e9e43000000b0025dd8e97b15mr2461122ljk.234.1661526614760;
        Fri, 26 Aug 2022 08:10:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc29:0:b0:261:d944:1ee6 with SMTP id b41-20020a2ebc29000000b00261d9441ee6ls716528ljf.0.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:10:13 -0700 (PDT)
X-Received: by 2002:a05:651c:210f:b0:261:ca0a:c319 with SMTP id a15-20020a05651c210f00b00261ca0ac319mr2340397ljq.19.1661526613561;
        Fri, 26 Aug 2022 08:10:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526613; cv=none;
        d=google.com; s=arc-20160816;
        b=Nu8Yurk44C3bmv0V50HmKx+gMZTarHnxt0aLgaDCskYwBNqD7U+Krpzf3igRYkAamc
         JspZR5PB//VO+6xdVWV9wXtkPPkckrQhWSbzJ9sJx8SJlE5Z8oumxYB0yrwiHS/rymGM
         QExmGUPdBRYcHRkkcTcAzKFLkGPkl82e33DB4nGB8pqsDv8E+RyELo/yuW9KcbbchibH
         m1O1UapRXcRQYtQnHLwK2+b4lgaJWOb5EX6PLgSo4c+DeedbOa0cBNFcXpQNh381hOIw
         n3xFL7ZJvvYYJGdTd65u1fCixACvJlx4UfHjxu/q2ET1sSWJldGN5OphAY2kwcBH9kKv
         5emQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dGjdyFKcPZ8AZlzw9ep1EXgYBHGgW0m7GguSz7kBI6Q=;
        b=XwnmY3FfYDQmrGPJ3fafZvadnCeLtO7dkVoFTDu9Kq8wyw4Pou4/9ff0CFdUzIS7fS
         bSrVpLDo4qUlpDU+tQ1MWv/mJQ5p159YUXvT10MzXyvwnZZVFAZCYzxXyFxgHNi3aRzC
         9tCuifQECXOqt8/jZxXXmXH3XSY7dH60yWGxgeIEPf12o1M0rp5lKkmwf5CRvNvdp1xj
         nv0joGUDY93cQ7SCU5F3L6R/fv+c3xaZi2e9pz7TXA1D3QrVQe/91VhrT0Y/MuYHI4fl
         4WkgpaMd7HYrkCUW5dQSGAFxFqikjJq36iq/zQUrhLDeHZR83UWAOeVmvEmNMQrVPegl
         vnvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DZGsI9l3;
       spf=pass (google.com: domain of 3veiiywykcvwafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VeIIYwYKCVwAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id v19-20020a2ea453000000b00261c5a3061csi85536ljn.3.2022.08.26.08.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3veiiywykcvwafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id d23-20020a2eb057000000b00261d195a07dso658160ljl.5
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:13 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6512:3054:b0:48a:f489:1d68 with SMTP id
 b20-20020a056512305400b0048af4891d68mr2401202lfb.260.1661526613226; Fri, 26
 Aug 2022 08:10:13 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:06 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-44-glider@google.com>
Subject: [PATCH v5 43/44] mm: fs: initialize fsdata passed to
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
 header.i=@google.com header.s=20210112 header.b=DZGsI9l3;       spf=pass
 (google.com: domain of 3veiiywykcvwafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VeIIYwYKCVwAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-44-glider%40google.com.

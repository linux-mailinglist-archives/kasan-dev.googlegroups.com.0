Return-Path: <kasan-dev+bncBCLI747UVAFRBKOLSKNAMGQENIY3XXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 203FB5FA803
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 01:07:23 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id r12-20020a92cd8c000000b002f9f5baaeeasf9790077ilb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:07:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665443242; cv=pass;
        d=google.com; s=arc-20160816;
        b=XqAyXkQ85gOfFz1jwoR4PJEwGKKrW25tynzZSIOUKrTDHwroUwxpZ55guj46KhzWp/
         vU4xuBKhSpO0mV7vKig9Wer7dOXbXxRzK395PLIMEill7pdbzhFXXtm+Q5cgzSsHHXLh
         O/is7n1qRA6fe6sOw1fzfL+XAgdjwDiO4vkGDTdib5KHw2V49si2t1j8EEw3bYtqVftY
         DYAzItvjLcp5m+75Emq1/V21BJvQWI7XF3X1QLc/BBq+u1AoVn6tOW7gcw0sigqVTAlm
         i8gDqrZGWN5uu7Dy86p1eZDhm9x99BtNd6bRChv1eBcvFDC8B9cZYhZV5vzqOJC6SxF4
         ZAvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eGJxJ898u0jIKpW9+q3VtMM5f6cc9QukwAYO/Xvn75o=;
        b=Vl+OnmeonTDDuidJe22jUr2Hn/StvAqc8GBNlr8O1/4UupIQQ6CV6D9KyI7cTih9Xs
         Kd4lfgicPHgaSROQ83WQizHnUqbMaX2gSK2bHRVKquuvUV1oBKwBPgBCG86CI+hGupD0
         oKG25OIDdRiUrqNquaq/LEfJ+PdpAIGZ3RyiVcitE+1iC9ofiOcaYQom6rF3sAmyUhRS
         bthLP9EuCEO+pJsECpvxGaeMZp9w8Na9rlJF66nKaTZGlDJDUOFX8DxFWvkhQmHNl6Qd
         r8KNRNKSK4AEs77bupw5UdQP/MPP4SFg8Q2yY38RIA9uvdQmjJ5nov+ibXpCZqIZ7X07
         JziQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=iCV0PUgs;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eGJxJ898u0jIKpW9+q3VtMM5f6cc9QukwAYO/Xvn75o=;
        b=QqTs5tXPapZgQM+ki7X6p+y3XCSZ0i9rbYxugCI2qu+mU92S16ouj9CRql/F80rp0K
         7Yd1RrTt88y3upoC+BnFsM+J/q+PcUu5meIrcrk4Mf3GB9mPGMMozBoLhY2dFbJTBJ4z
         BKLLuQHSRpc5xXSsPcEvenA7SZeMb6wX3SVfaqvdEF6h48w7lSNa72pMsNTkOCmirzbq
         if/HUwfcS+/o7NOVV4rQcy3xqTZl06AEPTae7orNcgaXO7OmHTwOOo4cXIJNbcpZqAx3
         crFdbf+C7F71wxEgo1PrrKHjRpN54uddq3oZOSx5mgz7/HXGiMSvpy0/fDtnVUvwfWcG
         ca3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=eGJxJ898u0jIKpW9+q3VtMM5f6cc9QukwAYO/Xvn75o=;
        b=o4dKx5VSWM0jX7HcNLOJiS9hX2d6IPWVmaNoz69tu4e3Rc0rhYscxFhse12VPplpe1
         +HIk8/6ABrA8G8wX7T/efCXjF0XYr2lJiStxGsSRhV6nVDrXmMRDqL6rKN7RhLpSTcC9
         cWs8YxdYCZcoBLu+v2VR4EKn3kBW2g7AIFhz8+Vdh1SB/fcH7ZPIfG9nKxLZryHf0Gnd
         3QpYWNPwpWmEkxC64AV/9a0/CTrtZdGGZJA+k0/DEZGiR4AvLGdGACVDqlOF6AzBdaPu
         VmO9yUzbzsg+RM5U2Pyh8FTgdXh7jk4R8pkXvcPcLFWwbob5TZJHslNq4lsO62L9fhOK
         o9mA==
X-Gm-Message-State: ACrzQf32xXKFVZ6ccWXnspR4V55H2mFIGW5/B9aSWSp3vbrRXkOP2uLZ
	7uzRY7a31gQv770DFbnXYxk=
X-Google-Smtp-Source: AMsMyM54UWlQSffBwb0/MbSbdS6UaamXImmC4aGKaMQSTVDU0SsbvuTGSvUCy6KK+Fs2v61IxnGWKg==
X-Received: by 2002:a05:6638:32a3:b0:35a:4987:233b with SMTP id f35-20020a05663832a300b0035a4987233bmr10676746jav.73.1665443241910;
        Mon, 10 Oct 2022 16:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2981:0:b0:362:d525:90ae with SMTP id p123-20020a022981000000b00362d52590aels2778304jap.5.-pod-prod-gmail;
 Mon, 10 Oct 2022 16:07:21 -0700 (PDT)
X-Received: by 2002:a05:6638:258c:b0:35a:7227:3e5c with SMTP id s12-20020a056638258c00b0035a72273e5cmr10971059jat.168.1665443241491;
        Mon, 10 Oct 2022 16:07:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665443241; cv=none;
        d=google.com; s=arc-20160816;
        b=DHoTd/tREqZzcnbHDPTW5Pp3JvUtxecD9s1TIrTtV1331757ngPMKjre4v4LlEX5yN
         7nw7XNO5Vfvet6ww6gxsG4xbeIXGrf9sNbW+FCYDcX0mEYxj8tmaYjgqQAwlAVWrloyg
         RO9G815e2DAm4t1Dfl2qJEpVrsJNmG17V1nNN351OIZZDIN/gtiqDZRKk5d8e9yHrm2s
         KcoE7ER9GunmfZS/mQ24Z50P71URyciPhE9tB6Tfwqn4mDqvgLaSesU4W7xwQJ/8YyY3
         +VbVJZgavH47VCZ8nuvDWjmW9apwuspNIKpWHPIsXhB+XHEog6JEJquQ8lCAp/YfHRYk
         qOTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/gaEwlFkPoVgdZQ7oNDn7xk98mXWF7hGEdKqEVicSg8=;
        b=nZaAWEdGcThQ1s/nieH+gZqEGu2QLTmLp8vQJ5qwtWAG7MKQRQuXtgnr1dctAyf2Su
         t/zCgV6SBNFVssiTv1cfAF4uIp4OmPd1Em78c+Nd+W3NaoQy6gRIV5osQBWZp2DLrBD7
         98HirBORhlbyzsiKBHxXjUvVq3oBRLoA3fpRZbvYwp2aWFiCB2ilIBjNuhwUl0dZ9IKz
         6s7wXzUIUZBeIWgt1fWEsRQpi/7zksBhc5FQ3RoC2dikGxTuQSCX28u90B3xKHf5c78A
         6Q2suRl/96WLeL8I3X00ZCIAyeNWm8S0mQQF5GoqU2VyO8UV+VeW+GVsf8ObrUD9mERb
         lljg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=iCV0PUgs;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id w3-20020a5d8443000000b006a128dbb6efsi382974ior.0.2022.10.10.16.07.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 16:07:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 156B961044;
	Mon, 10 Oct 2022 23:07:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 725E9C433C1;
	Mon, 10 Oct 2022 23:07:14 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id e346dd3e (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 10 Oct 2022 23:07:12 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev,
	netdev@vger.kernel.org,
	sparclinux@vger.kernel.org,
	x86@kernel.org,
	Jan Kara <jack@suse.cz>
Subject: [PATCH v6 2/7] treewide: use prandom_u32_max() when possible, part 2
Date: Mon, 10 Oct 2022 17:06:08 -0600
Message-Id: <20221010230613.1076905-3-Jason@zx2c4.com>
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=iCV0PUgs;       spf=pass
 (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Rather than incurring a division or requesting too many random bytes for
the given range, use the prandom_u32_max() function, which only takes
the minimum required bytes from the RNG and avoids divisions. This was
done by hand, covering things that coccinelle could not do on its own.

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Yury Norov <yury.norov@gmail.com>
Reviewed-by: Jan Kara <jack@suse.cz> # for ext2, ext4, and sbitmap
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 fs/ext2/ialloc.c   |  3 +--
 fs/ext4/ialloc.c   |  5 ++---
 lib/sbitmap.c      |  2 +-
 lib/test_vmalloc.c | 17 ++++-------------
 4 files changed, 8 insertions(+), 19 deletions(-)

diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
index 998dd2ac8008..f4944c4dee60 100644
--- a/fs/ext2/ialloc.c
+++ b/fs/ext2/ialloc.c
@@ -277,8 +277,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent)
 		int best_ndir = inodes_per_group;
 		int best_group = -1;
 
-		group = prandom_u32();
-		parent_group = (unsigned)group % ngroups;
+		parent_group = prandom_u32_max(ngroups);
 		for (i = 0; i < ngroups; i++) {
 			group = (parent_group + i) % ngroups;
 			desc = ext2_get_group_desc (sb, group, NULL);
diff --git a/fs/ext4/ialloc.c b/fs/ext4/ialloc.c
index 208b87ce8858..7575aa359675 100644
--- a/fs/ext4/ialloc.c
+++ b/fs/ext4/ialloc.c
@@ -463,10 +463,9 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent,
 			hinfo.hash_version = DX_HASH_HALF_MD4;
 			hinfo.seed = sbi->s_hash_seed;
 			ext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
-			grp = hinfo.hash;
+			parent_group = hinfo.hash % ngroups;
 		} else
-			grp = prandom_u32();
-		parent_group = (unsigned)grp % ngroups;
+			parent_group = prandom_u32_max(ngroups);
 		for (i = 0; i < ngroups; i++) {
 			g = (parent_group + i) % ngroups;
 			get_orlov_stats(sb, g, flex_size, &stats);
diff --git a/lib/sbitmap.c b/lib/sbitmap.c
index 055dac069afb..7280ae8ca88c 100644
--- a/lib/sbitmap.c
+++ b/lib/sbitmap.c
@@ -21,7 +21,7 @@ static int init_alloc_hint(struct sbitmap *sb, gfp_t flags)
 		int i;
 
 		for_each_possible_cpu(i)
-			*per_cpu_ptr(sb->alloc_hint, i) = prandom_u32() % depth;
+			*per_cpu_ptr(sb->alloc_hint, i) = prandom_u32_max(depth);
 	}
 	return 0;
 }
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index 4f2f2d1bac56..a26bbbf20e62 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -151,9 +151,7 @@ static int random_size_alloc_test(void)
 	int i;
 
 	for (i = 0; i < test_loop_count; i++) {
-		n = prandom_u32();
-		n = (n % 100) + 1;
-
+		n = prandom_u32_max(100) + 1;
 		p = vmalloc(n * PAGE_SIZE);
 
 		if (!p)
@@ -293,16 +291,12 @@ pcpu_alloc_test(void)
 		return -1;
 
 	for (i = 0; i < 35000; i++) {
-		unsigned int r;
-
-		r = prandom_u32();
-		size = (r % (PAGE_SIZE / 4)) + 1;
+		size = prandom_u32_max(PAGE_SIZE / 4) + 1;
 
 		/*
 		 * Maximum PAGE_SIZE
 		 */
-		r = prandom_u32();
-		align = 1 << ((r % 11) + 1);
+		align = 1 << (prandom_u32_max(11) + 1);
 
 		pcpu[i] = __alloc_percpu(size, align);
 		if (!pcpu[i])
@@ -393,14 +387,11 @@ static struct test_driver {
 
 static void shuffle_array(int *arr, int n)
 {
-	unsigned int rnd;
 	int i, j;
 
 	for (i = n - 1; i > 0; i--)  {
-		rnd = prandom_u32();
-
 		/* Cut the range. */
-		j = rnd % i;
+		j = prandom_u32_max(i);
 
 		/* Swap indexes. */
 		swap(arr[i], arr[j]);
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221010230613.1076905-3-Jason%40zx2c4.com.

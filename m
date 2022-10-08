Return-Path: <kasan-dev+bncBCLI747UVAFRBVFBQSNAMGQET54CXFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5119C5F833E
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 07:55:34 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id h185-20020a6383c2000000b0046063c710a1sf277881pge.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 22:55:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665208533; cv=pass;
        d=google.com; s=arc-20160816;
        b=BjcDhZRMihd/QpqV0k6ShsIL9yC2cQmnj8yUU37Yumq6upmN2kePiayrRuQKw+6r1V
         1x84mdaCGzoK/rUijo9ZumKeuQJAWNy5plhl2yKV+2ut+MBdSn8f9I69QeIVqnfu17DT
         6MoudI8jWBFs8zZutlzs+2Vlgb/PHigkEUhrNTVSuTj1raDjIQKYtEsMOPVFTeAoRM5b
         AFJ6JpjRQB7HEOTpkke2EcHrtz9LbEas21pdgDkK0/CdM5e7SPv/tf+A0775egEq9stR
         vCYZEJLxz247IHFkA64XJ9/59a0Ip+hsvzbYWvZ/J8R30E7Rt5sXkkeJLvnpVq0BrkPo
         /p/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BYJj0Xw+77jPO2+t43UHLWQuWB21Yl5DD2TxW2AYLo8=;
        b=tLN9A6ufHvTYUzMqyQwBXfOosiegrflpTAZXcOND5e2Tvaw2rXUGZjkMwqK/Rtf6kt
         dj49uyl9J2Fba8SY2mLdIIoMt+L8WAZ45q/iA62mJq0L8OMZ3ZGiSnJUgDfHaFVO98BG
         p2Wl4qGW/euMdF8/IpRoXG2hhNlykeNZPDHNH6jX2sMDTGtGELFcfDTiSpcI2uYM9J8+
         pUTY4j6Zh2xN/xcuT20D6qT2d8J0RhGUlXrqHVK2Ucsq0D9R0YEBUV+vLZtE/4mV5sKU
         l8KG39pxPT0fxfFf48bLgBHBramGEid95uVFVOZMWmKCXtSV4LNHhQ+kNgiPVwFihKUl
         tXoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=SPv34xoV;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BYJj0Xw+77jPO2+t43UHLWQuWB21Yl5DD2TxW2AYLo8=;
        b=HArMMrRER+hemCdwoo6scEKCucI7vScApjGuBOyAMk6K9W0JbqyXt00oGI8CL34TWz
         obnlWUFu5cZfaBSiADs0aVKx1ukfU/nk/zYKHXeaxquEaVVOjUqcn3nys9ZFbKB5dXr8
         EaKjb7aoDj+CrbPxXRGuVal3XYfSBbCKGlX7xex8R8iRsQw3NHlhefmrxj/xyphPCc02
         DhJZUKUX0LtAfgK6qkzvFXnHIOy3MVz1q6t8us0ihEXkekksW4xIhH5PAj42ihJd4K4F
         ZN+qSvAFdKJ9zdI/BiO2+i0dWW8cgb6YY+hXrau45BSpcuAUgSsn4cEkSOrsfAMu1etj
         2jcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BYJj0Xw+77jPO2+t43UHLWQuWB21Yl5DD2TxW2AYLo8=;
        b=HQ8GSkfCSYqsAAsdnGcSeGoMoETX8s6BtsZiQZ24NRO28GOyOf/NjZEoOdDwSY8wwB
         P6nCuyTcdnDz+B5cZr27ai/iMlEk+eW/PTSOMN0AjAZgov8+mW1DXOtzlC1Nihch8GTX
         RsHUUeRDoNoCsG/a2l5M4QuXrHveTeGj4+2EAL1floUMXqTRFFKCfU9JNI3KmgNLW9sH
         IKHUNNXQLpdYHD6sVDXUwgAzF9w4QUWSppVzqNG/C+89jYV9S8rCYcYqIcnZy7ltWgHd
         U1mg5w+Y9riYpqBgopAHvVkc82bVnjp68wImXFQqGsSADz40TU9FViluSawHWW4AAcdm
         ag4Q==
X-Gm-Message-State: ACrzQf2NSylrm9YYIPp+zdCRhzLTjP5OPYdY/lOjKPx92DfB+zVV7sy8
	a/JObnh0sUoBFOiuWNaAJnc=
X-Google-Smtp-Source: AMsMyM4CYTQcUHCPHaARhPMMHi/o9kCR4kJeQt3IJwupg+Dnm/8cYNqN4eb24WHGqX5i3bDvYf2qOQ==
X-Received: by 2002:a17:902:b194:b0:176:d229:83bd with SMTP id s20-20020a170902b19400b00176d22983bdmr8277421plr.174.1665208532937;
        Fri, 07 Oct 2022 22:55:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6949:0:b0:41a:63e8:2535 with SMTP id e70-20020a636949000000b0041a63e82535ls3518845pgc.2.-pod-prod-gmail;
 Fri, 07 Oct 2022 22:55:32 -0700 (PDT)
X-Received: by 2002:a05:6a00:1410:b0:528:5a5a:d846 with SMTP id l16-20020a056a00141000b005285a5ad846mr8822424pfu.9.1665208532235;
        Fri, 07 Oct 2022 22:55:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665208532; cv=none;
        d=google.com; s=arc-20160816;
        b=A+q1O+4oan3PfKxQEvcsnT7EHkA5+1B/Y+X3sZhA1rCkC8dDGwAr2VYdEmE6bNJ0Sd
         Q/nQRbM4BjuRXpK5YNs2R7baEBLxsfXsRc86m69TT8BZfjl/24ag6Nju2c/G4fnZQHo1
         O/fujUdCnKy689mr4ZQVpTI6Zs9TfNxW7bkMqaaaUPv9w6sjJaHWg0ocOmDOINPnW7+Z
         C4BDZLHNio3nd6v/hzhEoyWQSm9GuIwbzAicUv/JUzYD7jjB6EGqs3YSmwpmzCXGkh7+
         UyKvjGkNP8/cqNZ1THjV3Bfq5jCSIVlhwmktArxsJayONvqCvq+Q+35GUdMCT9g+1jTk
         o3Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HWsAhbEWo1B1ihEWGdt8Ri0s25HJf7SbB73HqwgSl1I=;
        b=HF7mIpAYB0lZrr1VuY+BnFx3wveP5X2WVcv62kpkNxScg85HtRCCpFuaMbtrEkpVIz
         ucKMnmUMn8LmTtVw8BD/nqvIwtKoK7INSXU7R35FBbDhK6q6OoMcyFWx/JRe3yi8hMd9
         MfrBZ6xTFfvCwckMpIpkgWaCrnRC9VSC4EKia3S3OCKXHQAc+vZtmcf5Q94wf8oFQzG9
         L96HczMU1Jo3QZFUTI83tyzDwik6cxgtYuaXHUFUC//kSHfPlzvEaeLzRtaS3f6DRTfP
         OCESM2X9sLXBpSD2Qli8nE81qQNepLV0C/57/AbStV9QjuXc+a5FQC7rTUp9we0AQKGV
         79zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=SPv34xoV;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h25-20020a633859000000b0043c54fa497dsi192243pgn.3.2022.10.07.22.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 22:55:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B7FBD6129D;
	Sat,  8 Oct 2022 05:55:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 10A48C43470;
	Sat,  8 Oct 2022 05:55:24 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 8b3beed3 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 05:55:24 +0000 (UTC)
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
Subject: [PATCH v5 2/7] treewide: use prandom_u32_max() when possible, part 2
Date: Fri,  7 Oct 2022 23:53:54 -0600
Message-Id: <20221008055359.286426-3-Jason@zx2c4.com>
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=SPv34xoV;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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

Reviewed-by: Kees Cook <keescook@chromium.org>
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
index f73e5eb43eae..36d5bc595cc2 100644
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
index c4f04edf3ee9..ef0661504561 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221008055359.286426-3-Jason%40zx2c4.com.

Return-Path: <kasan-dev+bncBCF5XGNWYQBRBA43X6OAMGQE4ZWKULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EEE8D644F71
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 00:17:24 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id g7-20020a056e021a2700b0030326ba44e4sf15449766ile.13
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 15:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670368643; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQhBsUPum2MlVdaNuRyO7bYq5sO70E8TY7H+eMvF4U85k9HpwHVIOE2pxO+zp2dyLT
         mYHKFJ7JfU+30//+6bjGCsfjOPa8h2RXes+iohnCoNJ1j89yYM7oMvyxJzZ1XhdUcRPD
         BMQO7aEHhBM5Ngi59NV8QhKmfmSAhKKeDe2EVTYbmSZ98sq+oiuNEijCs5PiUknG/4P6
         pK6ZQxXh7/RxKOWW999Y+GIx9SaGeym+ZyaYd3UldUvijny3iiJ1IqOGMmLXds88X2ie
         vyI7F4ZX7MgwUuDbPxkCEA/BHE+fc8ByoGk1Tj9EeZwJqgRFMVSQGIPuaL8Fz8QVGWoV
         /0Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=d0DfQQcquPcoxWETNCsEPHhF8jL7T1ZuB5RQ+e0TR0Y=;
        b=iUFaGfFuyJC6E4WpnB2UhTBQwccx4oJ1aTLrcfzOxv7Wa8AT7ZoEKyO0sOp//5mpiR
         j6sAO39NxUDm+CjtQuRsBV5gzvzPMlC/EYXAUg+H2DO84wPObcG8swh63WD89UcTD2Cf
         4rHcTeyjhiolenXTzH5Xo2BYsIL+r+3ago97n1CY10mdJX3zE+dVHPLfznkHdAn9ri++
         pcNqkeHaEJEYYAKmihtFNco+0QviP0jy5L7k3ZQULhXfeQU/W/7zYpQqDsVLgw+ndWAU
         zBWqMNclsig1BTVHlV8wH4u82CrxtpsK1D6EV6X+K19xsrqY9NlSoLkSBHTlvCtq8fyK
         wLVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RcfNgmVF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d0DfQQcquPcoxWETNCsEPHhF8jL7T1ZuB5RQ+e0TR0Y=;
        b=K8/bduDm8fvBGC2zfHMF3ULCSN8aTu4pPev9vfGGZoK+OgdQDUZIF/xdy5T649IdMA
         oPoeCXKITzZpKEYWZSvDplIJUnW3KF4jfzXmYxSDh16mKWSGdUtmNPE6K931yetAaei3
         io3fjZTSWn7kkn11d121ncx/SJbhGDfUtH5dvCQGfy0tvC6P+7OdckiALpKXAthNVZR5
         HMHMLwbzRO156DM5L2j1EX9qw4wVrUhSDswB27/iHtC/UTrKDVwdXz6snR20p+jrEmXw
         2SHJvttp+KrTeRpr95nreYgMjelzQ+q/Fl4iSo5aheVLO45YV9Ru+ny1znlDTExtLmv4
         K6IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=d0DfQQcquPcoxWETNCsEPHhF8jL7T1ZuB5RQ+e0TR0Y=;
        b=tVwJihCSNZlehmDfwKzefK5SHmXYRRrOrflPWZBf2H4WAT9tj1ExXvRt7/93wjPZap
         TI9qkFxrgm/PhY9MVkkPMGClpRNINR6SfIahc7cK3CKdtJ1CZqYoxhl/mLVPBQpR60Hb
         aZ+xSS40RhV73vuFCsWXvihexFJaGG2ts6cMYvA8tUgQSxNhupLFp5fSQraT/Ciw6LmD
         4+DPLC1bQGmLsr5n74kIDRKa0sp9HhzZvqilECKAK3b1jkyCOmPdvCByzJhRpcNOF20T
         KnZTwVEobtaklo6aZuWKk1gfmt7douS4WoLPxZqTGDxm09/0TS5+r1p55kHQjCysOZK0
         DYPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmXyh0rlOXw7eRquZnS/NuZdccpAvv3j2VM3cO3q4YY5mex6Bn7
	dn0nhJqihaZfiVsg5cqNxWA=
X-Google-Smtp-Source: AA0mqf75NqHiSMy+RXgdkfUjcT2NF5geoP4gtdd0L9n71qvKzZroZGwkDJWjVW2PgUCUWH4FdJWSXg==
X-Received: by 2002:a92:1903:0:b0:2ea:e57a:e589 with SMTP id 3-20020a921903000000b002eae57ae589mr34007760ilz.240.1670368643364;
        Tue, 06 Dec 2022 15:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:cd2:b0:302:c73d:ac0f with SMTP id
 c18-20020a056e020cd200b00302c73dac0fls143193ilj.0.-pod-prod-gmail; Tue, 06
 Dec 2022 15:17:22 -0800 (PST)
X-Received: by 2002:a92:db42:0:b0:303:26c0:e1fe with SMTP id w2-20020a92db42000000b0030326c0e1femr15317403ilq.102.1670368642854;
        Tue, 06 Dec 2022 15:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670368642; cv=none;
        d=google.com; s=arc-20160816;
        b=IeIbMeP0/sL4FK3Z5LO3WuSlCYf+t1lcR6aKYzHY2evcetR8qRvflutrZtSS1YW2kN
         crN9uW/xhzJ6s/1vIfN8GdEpPZwyIK4IcY0HcOu1cxgcpPFIO8NVuab+ax2vdS1xy6vA
         YBpsY65mCeA0QuDVeo5WA5sUeM6HaeaBDTaAoyyk/55IZEMaqfvMnuePYOIFgJWvIbCH
         4xUGaAx9l1MW0O1Dig6asjyHU4RbA888MjKeMM5vAbwvZd9VClTtDw0EYCzHQOGJVa9C
         4xivHZB+0NtaAxQyl7EV3/GZyHPa2zV4mBBQ/qdGnOlkFhntVNLpwKr/oi36DQFwMNCJ
         McVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3vbRaeuklEF43T7OpAaK1TLfMIWz7cNmPbZiH16DjEk=;
        b=LmGoQy9bO7IVaAo5c3NLLOQ3If86D9w9F5K9nRurv0wkka1SZ7CJGfYRwAaSvjeCPR
         oJJLRuNyWg6M7Fe4uj2Oi31HbkAeElpLD/hnzplzhDI8KGEJqFbejC4G4bsaHc/kW+nM
         utPVr0owx2mA1gfWHIuwVOAMWJknD0QdByjFLKGiZuejoXcHADc16bPiPxvnmIz5kdUN
         NONKFztKnIwecPcABqhKnktf5avLVbNlsZnFBqdaWcA67apDIYSlrRzH5MOPbcRd5bkn
         jrTskHogjq/ww52j6o364EE0lPmQm9G1lz/JIHx5zK8LMYQwiIk2xCwJ0R3XotNVwHJ/
         vbsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RcfNgmVF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id bc9-20020a056602360900b006e02ea7519csi191953iob.4.2022.12.06.15.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Dec 2022 15:17:22 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id g1so7923837pfk.2
        for <kasan-dev@googlegroups.com>; Tue, 06 Dec 2022 15:17:22 -0800 (PST)
X-Received: by 2002:a63:d149:0:b0:478:dfd4:fc2b with SMTP id c9-20020a63d149000000b00478dfd4fc2bmr4745390pgj.234.1670368642119;
        Tue, 06 Dec 2022 15:17:22 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id x14-20020a170902a38e00b0017f36638010sm13058718pla.276.2022.12.06.15.17.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Dec 2022 15:17:21 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: "David S. Miller" <davem@davemloft.net>
Cc: Kees Cook <keescook@chromium.org>,
	syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	pepsipu <soopthegoop@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	ast@kernel.org,
	bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Hao Luo <haoluo@google.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	jolsa@kernel.org,
	KP Singh <kpsingh@kernel.org>,
	martin.lau@linux.dev,
	Stanislav Fomichev <sdf@google.com>,
	song@kernel.org,
	Yonghong Song <yhs@fb.com>,
	netdev@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	Menglong Dong <imagedong@tencent.com>,
	David Ahern <dsahern@kernel.org>,
	Martin KaFai Lau <kafai@fb.com>,
	Luiz Augusto von Dentz <luiz.von.dentz@intel.com>,
	Richard Gobert <richardbgobert@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	David Rientjes <rientjes@google.com>,
	linux-hardening@vger.kernel.org
Subject: [PATCH] skbuff: Reallocate to ksize() in __build_skb_around()
Date: Tue,  6 Dec 2022 15:17:14 -0800
Message-Id: <20221206231659.never.929-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2831; h=from:subject:message-id; bh=SEGHsTZp5rUk6+r1FvL0rwY8bYvfT9UgLniC3mssO5w=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjj81513DL6A5/30d+E/4ZlSiL3Nec8HQn2RQ2kFzs 0hZX4L+JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY4/NeQAKCRCJcvTf3G3AJgEWEA CP3WJylXFSIh5ufMvAJQvK79bcfGQEV+CDUcSNcXTWdDEohBbp8tEFod5Nfj2l3fynK91HxFZsxogF kEnuK8O/7SyKs7X8L7bGXpX9pXLRMweVYccLF5Nwxh4ERV1DNDsQmjZH1uDF7SNi9blnULpHvzg34i Byw6v5p0mynHLS3alptN8Pw1n6DTuP2wYEVV8vkB1gcqBOJ6MRbcCbnshUxezF2lTqORLUeVAKvn1S HhI3U5ydjsp6VsIcFmzIau3s9l5lF+z2D/Hrb28myH81E9/ec8nEljNqB5nwlZHAupJnwLxlBhukCC ILfKn0kAdEZLXwhYqmxctrFDB5aNYK+lcNtF2RKXnZsy0Tr3q7ubILFHbQLBSvEKQ8QfpAvwH4Gby9 BS+ELN1eAQ6WQqraXDr/ox/ZzfOPEk3IjsSY2jJ3UcGtqjz7rE7UXCEaAxTO+CmY+eGit7U/Y1HinQ JwhD/C4H1lNNPpJilKLWGmqOLnOYKkDKGfKWdTmSFJa3sxIlzWz5RlTPRoXPmMamZINipZHKl8BjU+ Ee0qzhGS5qQ8uuefIru++zAjBvy3ww83P/5IaKBqSma+SQkucNI4OEa4nqnSAZGLIwfYXc4sit2pHB WMtK/l1bgCdHLPDCL8cHfNH7f64jUTfmdEtV/urQ91TRLv497uFJ/hH07ZUg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=RcfNgmVF;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

When build_skb() is passed a frag_size of 0, it means the buffer came
from kmalloc. In these cases, ksize() is used to find its actual size,
but since the allocation may not have been made to that size, actually
perform the krealloc() call so that all the associated buffer size
checking will be correctly notified. For example, syzkaller reported:

  BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
  Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295

For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
build_skb().

Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Cc: pepsipu <soopthegoop@gmail.com>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrii Nakryiko <andrii@kernel.org>
Cc: ast@kernel.org
Cc: bpf <bpf@vger.kernel.org>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Hao Luo <haoluo@google.com>
Cc: Jesper Dangaard Brouer <hawk@kernel.org>
Cc: John Fastabend <john.fastabend@gmail.com>
Cc: jolsa@kernel.org
Cc: KP Singh <kpsingh@kernel.org>
Cc: martin.lau@linux.dev
Cc: Stanislav Fomichev <sdf@google.com>
Cc: song@kernel.org
Cc: Yonghong Song <yhs@fb.com>
Cc: netdev@vger.kernel.org
Cc: LKML <linux-kernel@vger.kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 net/core/skbuff.c | 18 +++++++++++++++++-
 1 file changed, 17 insertions(+), 1 deletion(-)

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 1d9719e72f9d..b55d061ed8b4 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -274,7 +274,23 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
 			       unsigned int frag_size)
 {
 	struct skb_shared_info *shinfo;
-	unsigned int size = frag_size ? : ksize(data);
+	unsigned int size = frag_size;
+
+	/* When frag_size == 0, the buffer came from kmalloc, so we
+	 * must find its true allocation size (and grow it to match).
+	 */
+	if (unlikely(size == 0)) {
+		void *resized;
+
+		size = ksize(data);
+		/* krealloc() will immediate return "data" when
+		 * "ksize(data)" is requested: it is the existing upper
+		 * bounds. As a result, GFP_ATOMIC will be ignored.
+		 */
+		resized = krealloc(data, size, GFP_ATOMIC);
+		if (WARN_ON(resized != data))
+			data = resized;
+	}
 
 	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221206231659.never.929-kees%40kernel.org.

Return-Path: <kasan-dev+bncBC7OD3FKWUERB34LXKMAMGQERHWXVEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA99D5A6F7B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:36 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id j11-20020a05690212cb00b006454988d225sf722600ybu.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896175; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmRAO6so93cwO8Qpr3TrBJQhWigbbYjjuxTnnGbLeWOoPTFnMEZWEsdixEqXIbZWt0
         GRO13OVN9DggPJJidCRTKMGHE7cjy+7SruwP6TTvgwMOlaSjOK+nkKyG0dtj2Iu1Wh9d
         I3GCjaeSTWfmyhtZC8oDC4ALx2WYaqLRdJM6heRoLgl/e8GFDTXaxYPDsrM/6f0J3BCx
         RON419OZFs/Pn7yXQEZ+zazF5jv41V3uaqsRtrJMBseETECO4IKriLyfaeYBUIzWn9BE
         ZzPRkBoufm2GJ2ckWt77H7aw6uNVO3AzyReOInXKBXDWOHB4U8LNw6rIYqrSwduq6iLJ
         3KTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AgVoswJHTOc5yeu/dabVzRpYOumlNIk9VpInh1eCubg=;
        b=kRkJmxbuanqJFwxQkVMwU2Nebi+w5NMwxKIaPqhJf/F87xyeCYWh9OcikaQBuSoBv2
         b7iKhnviUf3r8q7sKliqxA0xeprg3b+c1tLa39IQTNv+spdqCM2qaCc+pBNDLZz57XcK
         hh5fePazUE4PDGmUqSZD1xiYVU7FLZYHZUzE1NoyAW8LENE3kSQDY3MWYit0HId7KHAP
         /BDKvUYcqwTBEwWIDpeyRJPFnPYy5zL0fz0E5P5f5uKdLt+A/TtnjMxN+oR7N3IikJXG
         bZbNckhV+OXh1mZJ6K4Bay4yWjJnxFciYPFT6lhRFwyZhX7FdBfVmfrOyoUJedr9Ui/3
         L9Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hlMw9ssX;
       spf=pass (google.com: domain of 37ouoywykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37oUOYwYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=AgVoswJHTOc5yeu/dabVzRpYOumlNIk9VpInh1eCubg=;
        b=sIIVgj0s5UyS/6M08yzEKT9YAhVF3MH4ypBl7X9vntEx6w4dePztPR3GIwrYlIdG/3
         9O6npifQANPQ/jBXflhhFLRKvPQspUDqURh43NrvTivJUeCg8DYHlHhtU1hlO5Vt/IRn
         G277h9ZsHGS3kVdCxuCa595ElzqwJij4GxSliEPF4J8N+TJt4P7bU3mGs7LF8t5e9UI7
         F6amc2IMLKCnkHTfH5ytIF0unDMgzLkqB4cfQ74A3U7OlChawecwhAWZO4xHwhDixS6N
         tpt+LVzNYbMD9aRpYeveRFdtLnP00Hz0LaIs7cRe5TJ4Bav/WNflkmyY5Fk0uK4EH9ni
         B2uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=AgVoswJHTOc5yeu/dabVzRpYOumlNIk9VpInh1eCubg=;
        b=DYipvBKXSSB7acZijqx4cAM/G2d7FWOPE4K5YbKny3VxhgfqjtoQ/9irvDP/ZVI/WP
         3wLTbPCWURShcGJNSrj0ojOIgAxOLqSPc+qXxqbInaRF2uA4DHobfc3B4Ryd2XeZFAKi
         JSQqK8RW+kW4UGWQgNMUSDNqZMUVX7sg5qSAHT9W6coKpDqZ6rlFmD8ivxj0nGgKhPyY
         K35gsnT5T+TqWaUVdXHjUUox4KxYJVyw0Ettuj7rcaVw0dkXRJWAbKPo/wBnytZlySUK
         yZx1uNcVYgMGJ5oSuUDTLHdyJfFw0JRiaP1VHToGK/mz3mRHza/KlBr4JPems2WigHSI
         Of7Q==
X-Gm-Message-State: ACgBeo3YqgVMSM1FRE+vnyW2rrSRWRCwUvZMqXPsQCejTIJtrylHEld9
	UiIycJ6x51MGFIKHBWDFNdg=
X-Google-Smtp-Source: AA6agR5xrJJUWqBAhj/NScoP87FKF1Mbmz9UYy0RTfIj3boLkUR9MQXJVCK6EqIerXBp9r32VuQPRg==
X-Received: by 2002:a25:3503:0:b0:672:adb4:a69f with SMTP id c3-20020a253503000000b00672adb4a69fmr12416012yba.41.1661896175592;
        Tue, 30 Aug 2022 14:49:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:83:b0:336:fb80:b482 with SMTP id
 be3-20020a05690c008300b00336fb80b482ls4380752ywb.2.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:35 -0700 (PDT)
X-Received: by 2002:a0d:e650:0:b0:341:85d:f480 with SMTP id p77-20020a0de650000000b00341085df480mr9713500ywe.161.1661896175069;
        Tue, 30 Aug 2022 14:49:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896175; cv=none;
        d=google.com; s=arc-20160816;
        b=xqAfeHWuvXwMZgL3PxOcjTlJKgzRu1TxFZubwJK0m1owyY0tZjpn892NCOeY987Nxt
         myFDHYvyUG7WhMpMxSBT1hUnqmYCItATEzWThsbwGVE2d36YLjbJelbzk0tITiEGO+Ha
         ECLteMz+8/WZjJkk0FKzpJz184u5IMgrakG/C7jIuwaYviGFrwaE9SDIavi4GdFg2e+L
         ffGzcKu9na4P3VzzC+OerCVS26SvDE7SvveHRAH7zdqu9K+64RTMiXLXhg3lylAQ2rcK
         kq34DlTlNZNP3BGPFlg5dH1BZe0h15+OoxEL9ts1tAk1fW2g6ajjj0XFT1QN3vAX8vfA
         MAMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ximx3byfJ7rLtdPEIh1Ra0raz9MzgSTr/ga3ge5UvWM=;
        b=y4/hcXEarrG9oYe3sRx1eCKQdh1Dz2hFSmRaJKCZn9xfPdtgwMK7Yh1JrW1f3/c+f6
         E3kd8JHgoqxexhIdtuFypySm4vRkvqxjm2BS4J7EDLVkAhcKA2Tab9LwJvozDrGf71Ak
         BbRa5fkZiBgN4OcO+k70SyLJmIeguomV5Xfm/6NpTKBT9SRy4OaMOFWB2tiDc2rM7ISw
         TtOS9dMWEg2OW9geKEYTg0tCfTZ69YHB2KJTuwdc78wwrobPC2ZFg5Qje53Fbr1uTA3t
         Lm8TnF+3Y2Ysj5P2cx5Us7GIU5Qcq61BQQ4KKVXdvHpLTZzfWJ6ffK2yTXoWfUH68K4s
         S+pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hlMw9ssX;
       spf=pass (google.com: domain of 37ouoywykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37oUOYwYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id d128-20020a816886000000b0032e923f3f95si717607ywc.2.2022.08.30.14.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ouoywykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id l9-20020a252509000000b00695eb4f1422so720896ybl.13
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:35 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a0d:d98c:0:b0:33d:c482:9714 with SMTP id
 b134-20020a0dd98c000000b0033dc4829714mr15776751ywe.415.1661896174717; Tue, 30
 Aug 2022 14:49:34 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:53 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-5-surenb@google.com>
Subject: [RFC PATCH 04/30] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hlMw9ssX;       spf=pass
 (google.com: domain of 37ouoywykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37oUOYwYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

These symbols are used to denote section boundaries: by always including
them we can unify loading sections from modules with loading built-in
sections, which leads to some significant cleanup.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 scripts/kallsyms.c | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/scripts/kallsyms.c b/scripts/kallsyms.c
index f18e6dfc68c5..3d51639a595d 100644
--- a/scripts/kallsyms.c
+++ b/scripts/kallsyms.c
@@ -263,6 +263,11 @@ static int symbol_in_range(const struct sym_entry *s,
 	return 0;
 }
 
+static bool string_starts_with(const char *s, const char *prefix)
+{
+	return strncmp(s, prefix, strlen(prefix)) == 0;
+}
+
 static int symbol_valid(const struct sym_entry *s)
 {
 	const char *name = sym_name(s);
@@ -270,6 +275,14 @@ static int symbol_valid(const struct sym_entry *s)
 	/* if --all-symbols is not specified, then symbols outside the text
 	 * and inittext sections are discarded */
 	if (!all_symbols) {
+		/*
+		 * Symbols starting with __start and __stop are used to denote
+		 * section boundaries, and should always be included:
+		 */
+		if (string_starts_with(name, "__start_") ||
+		    string_starts_with(name, "__stop_"))
+			return 1;
+
 		if (symbol_in_range(s, text_ranges,
 				    ARRAY_SIZE(text_ranges)) == 0)
 			return 0;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-5-surenb%40google.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK555WWQMGQEXMZB6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 05709845361
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 10:04:46 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5d396a57ea5sf653830a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 01:04:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706778284; cv=pass;
        d=google.com; s=arc-20160816;
        b=lFlZtubhsB1fSKAijTch9KUM1fyEH3dJ0P4rE+xxpNB1vGYVBUhOhOkWJ/iYSsSxwt
         ad/AKyzHO0YK63Q0uVh2ix8xvz+9olP16rwSZdwPp1S5ZCFcqZVtk+Q9su8mWAK7r2l9
         opGcWlW5AEmiqd4JRwS/TtkWobro+3vTYGojGTSVUE17PUvjctzxYLBKyqN6wtSzR7gb
         jgPYWP5MOp8zvaU5I3+J2JnAr6NC2cC1F9jZxpIx+ozsCpdkxvafVENkTJIZJ1U5vtSP
         Kwq2ylrLutwRyNI3wB93DUZ11IvX2X1HCx7xouBSgpD0RI0TktzsxytegxE6vMqLql8h
         vo0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=lP9llXL0QWYbVxJJUn1lnsLKg4Oy1CAuruWeDzNnNx8=;
        fh=Aq+ctp4Y5KWRHUlttQxE4b+5SBBZv0M1SYvJJ3k0UoA=;
        b=0oThF/kUsL8s4sak3ZJkxRy6+7MeD4NRHmctGfR9Pf8rpf+QdYV9f2CMAMLXDCfEU5
         Mg4a4ajJnzphe+baYJsC89MUqmUOls3JJYiRTXX3RjrBtvB5Oebbb8tAPi0gT/4dbU/C
         //nO7M2Gczb7vtQf5ByEVEaCzXe0NlrRP3OUhlRSXMMfek6rNxaM00yet5iyz615dccY
         2d+b580lhB65c3gbCNTX8DbqcqoDGp+GeMLhyGjd0Rfl/4e5wMxdeRK/vEUZ9HIEQUH1
         gtdJrYDafDJ4Z7C93XLPwn2nDSlQEX2u5Nj6R/kVolKSgjlSVgkXaWCN2W5/ISCY8671
         M+yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qb9H6qsI;
       spf=pass (google.com: domain of 3ql67zqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ql67ZQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706778284; x=1707383084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lP9llXL0QWYbVxJJUn1lnsLKg4Oy1CAuruWeDzNnNx8=;
        b=knU0YfuKTOevM/2bT8N11WND/fUEUK2gz8ghTL46svmL0tCmLBeTByncM3Zl2ollXq
         s3IaEBbtwUfn+GRTJbpfTUe/cmsV/jpiPbItW9hm8LSmwPkI2bPHCY8o9QYpgotr76u6
         8k8+zzdxf32jEYM1YIKANamuTjCQUiwMYaUSxtIijIdnSezQXS42uxG8OAmhdx+I3qkE
         XpIdkE5OkwL024WGByXxJo2OVOmg4B19uvT74hnF0jLCzYD9FpRKm7zECrsVEYfv576s
         l1SvCp5vVRtPnihcl/+z0UdLLHad8vF95SWTeeXQjpIpZEBjAaDhYmK3ak7GlQ7Zb5Ad
         0pDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706778284; x=1707383084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lP9llXL0QWYbVxJJUn1lnsLKg4Oy1CAuruWeDzNnNx8=;
        b=w8dQKJFJXmyGwwjA2iiYkN6CtPv04nHXoYANybt6VDs6qbx4AmD1XUIDKA9A5OViHC
         Gcq6ZGnW6i1IxH7yG3qxNvywbUQn6XaeR1NGZ5Q315nNnIBb6SxGB85OmBC9VSgCsrZm
         W+2j+c+pI8KO628vRdWiNRsDf7IRmzEh2Mchoyi41c6Feytsg/lBK52eyOTT8c8KaCVN
         0kAG8F8Nglb5lm2P/AOyC+tcweujvykJgxsxt1LTKlTpPi9wwTaDQ52bJQR7ZAXIOorg
         JgGEijrgk5SKj5w8c82DL6Sh6/eIAU0DmRfv17O7gKtsiAM1fGBrDYgMEXHT3sr7O4Ng
         pDVQ==
X-Gm-Message-State: AOJu0YzFskz6r6UlK6M9UOy4WE2XWjQuV69FTgpXC//DRbBYt7XpP4Ic
	BRTxV95mHajdjZ8w3Mp7cu1yGAsnirZFQcAbWorloitg9F0A7BAk
X-Google-Smtp-Source: AGHT+IF+B3RPWCS0VnKpMT9bQILzCDqNNlHn4/dwpqqqBda/jVOFd7d4HlC18xX43X3Y1mV8Ldo/2g==
X-Received: by 2002:a05:6a20:1930:b0:18b:902f:892 with SMTP id bv48-20020a056a20193000b0018b902f0892mr3616614pzb.40.1706778284097;
        Thu, 01 Feb 2024 01:04:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb11:b0:1d4:910f:f861 with SMTP id
 l17-20020a170902eb1100b001d4910ff861ls442642plb.0.-pod-prod-07-us; Thu, 01
 Feb 2024 01:04:43 -0800 (PST)
X-Received: by 2002:a17:902:ea08:b0:1d9:55b:6a4c with SMTP id s8-20020a170902ea0800b001d9055b6a4cmr5469612plg.32.1706778282768;
        Thu, 01 Feb 2024 01:04:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706778282; cv=none;
        d=google.com; s=arc-20160816;
        b=uZIcwBU8v/tM6rA+gpmMPOylMKjGmmPpDAmvupMz+Sv574EEC7Cay19a3XDXhj59zi
         /ytCmCJ/roTf8WJjcEwkjV7PgFkf8Bz+n2GaeqtIKhThd+QMynvIV1RLiURLpumkq7B5
         w++MFUgVfdWAhqPos8vo97ZTfQqy9jvbc1J/Jeki/Vejg5nid+7aV2piXh0VrrR94o38
         jmiMhJY6SOe74Nnly6Xn+eMerNAe3vmdOl+c4lx48ymAKcwIWJ7Tn1ljDsbNHZ/uvG4E
         zwqJHUSOSsdLIWWUp5Ml2QDrK6jJbw8tAsSc/bAJGVukiYWLMYUyr7c7Ap7HchJNqw7U
         ldUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=qvWvk4QvsQxB0P/BHzB26BqaiUYgtrBgA7rGlBoMg2M=;
        fh=Aq+ctp4Y5KWRHUlttQxE4b+5SBBZv0M1SYvJJ3k0UoA=;
        b=TTFlF39R1l/pPDA7Q5DMzRZMNmz5Yyqm6vLtuNbVOd8ugxJzsQo53xL0jV6zCdThHr
         SjBvI+4sREpES6KEbJ+UzSR1QUyyyx39u/9STdxkN+Bqacd+SbOVoDFnKSl4CH2/0sRD
         tlfWxdkxnd6uESWvA71ZLsVa4FoGtCFre8OevU4NgjfJ9z83L6KvaUuy6qmDT3CdNpp/
         OtogkO53qsCIg6RcIzNXsN9NwYVLYQ6DwDt7IS8tcg4fDf+t7L4na4feSAry0Xs32Fb/
         zgmaweMmaxIgSua/0/8QjP8HX1s8eaXH6BCfZQFCmVyC7heOAGhB5ymemJMhTrC4D81Z
         x1YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qb9H6qsI;
       spf=pass (google.com: domain of 3ql67zqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ql67ZQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCW0T6MpdiR2hi0WPWAwcIDvn+CagTsSzKKPFPYV93OHE1MOa2yZv7g/ZL/gubgfM2/rodWZZkASciUgkDG8jHppoflucRGEuCG7PA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id h12-20020a170902680c00b001d72000bbf8si1571485plk.5.2024.02.01.01.04.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Feb 2024 01:04:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ql67zqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60420dcb127so922437b3.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Feb 2024 01:04:42 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:c945:1806:ff53:36fa])
 (user=elver job=sendgmr) by 2002:a81:99d8:0:b0:5ff:6e82:ea31 with SMTP id
 q207-20020a8199d8000000b005ff6e82ea31mr849671ywg.3.1706778282041; Thu, 01 Feb
 2024 01:04:42 -0800 (PST)
Date: Thu,  1 Feb 2024 10:04:30 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240201090434.1762340-1-elver@google.com>
Subject: [PATCH -mm v2] stackdepot: fix -Wstringop-overflow warning
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Qb9H6qsI;       spf=pass
 (google.com: domain of 3ql67zqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ql67ZQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Since 113a61863ecb ("Makefile: Enable -Wstringop-overflow globally")
string overflow checking is enabled by default. Within stackdepot, the
compiler (GCC 13.2.0) assumes that a multiplication overflow may be
possible and flex_array_size() can return SIZE_MAX (4294967295 on
32-bit), resulting in this warning:

 In function 'depot_alloc_stack',
     inlined from 'stack_depot_save_flags' at lib/stackdepot.c:688:4:
 arch/x86/include/asm/string_32.h:150:25: error: '__builtin_memcpy' specified bound 4294967295 exceeds maximum object size 2147483647 [-Werror=stringop-overflow=]
   150 | #define memcpy(t, f, n) __builtin_memcpy(t, f, n)
       |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
 lib/stackdepot.c:459:9: note: in expansion of macro 'memcpy'
   459 |         memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
       |         ^~~~~~
 cc1: all warnings being treated as errors

This is due to depot_alloc_stack() accepting an 'int nr_entries' which
could be negative without deeper analysis of callers.

The call to depot_alloc_stack() from stack_depot_save_flags(), however,
only passes in its nr_entries which is unsigned int. Fix the warning by
switching depot_alloc_stack()'s nr_entries to also be unsigned.

Link: https://lore.kernel.org/all/20240201135747.18eca98e@canb.auug.org.au/
Fixes: d869d3fb362c ("stackdepot: use variable size records for non-evictable entries")
Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Just switch 'nr_entries' to unsigned int which is already the case
  elsewhere.
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 8f3b2c84ec2d..4a7055a63d9f 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -420,7 +420,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
 
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
+depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
 {
 	struct stack_record *stack = NULL;
 	size_t record_size;
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240201090434.1762340-1-elver%40google.com.

Return-Path: <kasan-dev+bncBDXYDPH3S4OBBR5U2OXAMGQEGQUX3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A8EF285C1E4
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 17:58:48 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-564cb5b2bc5sf541931a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708448328; cv=pass;
        d=google.com; s=arc-20160816;
        b=U57uUEUPkhS8nAj5Pgyxgc6WBzX1y16b7vwomcuspqSXnEl8p0k4DtetAPLV0PmC8Y
         O0iD88DtZrFomE40w1hCMB/UNXIwHnxjNDeGH20eMLvjlwUizBwKeGUp6Jm6Y43MDpnS
         DXsnubtjNNSBthqqSYzhoudK4R2tNvIh9ur0HNHydAwlWfxLbWWU6ofSMsieqman1+pi
         Mvqqi0UPdGCLQBmzuPbRlsk9Qsy2YDVwI7+qkQMBGXRQqbjQhdY20D2Nyik9ydyO9I8q
         HzOv0k2Ojr86tVk/ULi7a3kOFtFPhT1Y6JWbxbbLWshezdWQoAFjbzhuVKjQOKwDcGw+
         4MIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=ohmRFUSUD8vIbEc6IaFkHTrKKooErRlcWD22rBJqvqA=;
        fh=UuF3rSeHqtOQmuDskBIpJqPeQ86EzuU2RvT0tMUdm+I=;
        b=i7J27uYooe5bGl4jBBSn5q/U8Ntk0uN/S02Xi2vL98gUUpeJF2/u41uQOhKpcymJsW
         sG3WdEp9BFqCqjDdnwmVDdBfSn+yXRHcR45aWJNzGXeDki8FgEIT3pIjj/p+fKSet6+7
         KnXnDmwZoQuU78IcnLyFVqp/dxg0WJdMK5XycvMuZBpKg6yZBdruL9GWhLZ7B5ftdSrv
         jrmj0lYydd9VURreNQUrJ/L5CCM17TwBEcJXlCuK55OatyyrzaBPFJqyY2U3r2fGYynQ
         ujCNRrKCsKEWx3cZiIEpY1NSw73rkwytN8VCXgpTpflJUlTpaWj+VFcOZ59wRyHqERGX
         ngjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708448328; x=1709053128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ohmRFUSUD8vIbEc6IaFkHTrKKooErRlcWD22rBJqvqA=;
        b=gzAmHJk4SDrYUVg+EtUY/nfQhqe0zZb2M36lyj9r/yX+LvxhhsxWj0DozCZkPAktMV
         iy8+Nogp+XOtABCugZjE+FP84temjePJ/6YdVKpQEefpYi2l57Arqxl8xVSMbDKZkctX
         0i7hs0wsm4VbuuNay/NDQHvXp5c9O1Rm4Y1Yjmc1hlGqJufZIW7CffbFz/f+bdXg944C
         s9aM6IxuwIjGDhbL1jhu4I+aGKZ6wGJxLQ9o5Yutmz8fP2+x/ljOYajdsj2v1+oc5f4+
         LDo5e3ZIeO8JJhXFz3cdx5fdg0Y7Ng6AiztWPTqbMMIXS7EflIlxqn4blrYpxIhrRcwP
         mbMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708448328; x=1709053128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ohmRFUSUD8vIbEc6IaFkHTrKKooErRlcWD22rBJqvqA=;
        b=M3GCIhTvEC1FW3RAg/jXIKl8ldOHCcFXOrAAjtHNTiKKG4J6X5dS23alfjERXm1hrE
         1oqDmS90cBf7lhrdCjkCN8VSEx16jzv9Hu6drLEeVz4whdNBWCN9zo5NqNFABGXKgDaz
         YudbZNLhYasF2CiYZ+cjZ8defDGgqHX47Y1pD2aDlgeewdh33i7SWv41LYbiuQbQPO+M
         xPxAytGzG2tU/MzIygplClTsHFbWCyslnaPz7Y5TdFfNo48MnaO6N5CyYzu9s9AOA2Oo
         iKatB/j8b3sRTzf5vKlNE3z2SVMt9ZUT0W65SauUhLOroNRSxc8h+hT7aTyYoFrsiRHn
         cfEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWti3n/OO3M1vcNsfE4L1MqvoZuM5us38ZWMgvrpZP+mWRb+TZQjJkZLOwnXXos++qFTFftdJhGemd7COHowByTAjmM+5EJGw==
X-Gm-Message-State: AOJu0Yy7S6TMwSKjn7dx9g90QkjMXhN666LzWrD2d0rHWpbq5GTayszJ
	YFPvIr3vydgmOX4+XP7Cq5c9PUI/Umyq/PEWIMLvP9jeNMYoXzqq
X-Google-Smtp-Source: AGHT+IHbkxWZvbTovArAOE/aBREp9bdqmGEG4nLDyyv8xFGxrrXL3UOqkSkV+dNeCl8M6J8i/luOsA==
X-Received: by 2002:aa7:da18:0:b0:564:4109:b318 with SMTP id r24-20020aa7da18000000b005644109b318mr5626401eds.24.1708448327629;
        Tue, 20 Feb 2024 08:58:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3811:b0:563:94d1:8216 with SMTP id
 es17-20020a056402381100b0056394d18216ls738320edb.1.-pod-prod-07-eu; Tue, 20
 Feb 2024 08:58:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWwRI5aQCG6qpr5WWcBDt722V2MtIMH6ai4SvofYB4gypcKj1R+tTH57F4m+WClbJYexYpyIAl+gXkP3zUa/qP75zjnOBc3Go+eoQ==
X-Received: by 2002:aa7:c0d7:0:b0:564:3fe7:5843 with SMTP id j23-20020aa7c0d7000000b005643fe75843mr5388172edp.27.1708448325874;
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708448325; cv=none;
        d=google.com; s=arc-20160816;
        b=HyAw+hjeh4w2zLFqBli0r0C4B3MkpC0x+cE0JRNHqFsErNnxsyQxO1DSUpWBpkI7HB
         9hdaRKyg7KX9Qg0HEHjcwba7+cNRjN9fkk++mKnuAic7Z7FfejC3ejmZNT06kFPbAyPa
         O0PzWuSmBOW/nczcxdmCJPN072T0Hmt6rhN2tAhjqbhDwPrk0H0lVC1Yfn6bEezG5P/T
         QA9GZfy0QmLG7Ltb48kYNdS4hQzLIX3sH//WkjAWUM0nX9X+QZ5ytHB6vsD6V6fhKxKb
         BMigJpIPecRzBtL0o5+nJ64BilFzTgNkCiHivHRIyxYsHvlvl0/VM+vul7Yp3MJhQanx
         6kxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=c4OC2yNSKLqgnXzwwPex64d+kZgeSX8gpLykWcl/SKw=;
        fh=H+kigXjdCOVpCxcHPaVg6SgkIx4KR669HTfmciEICLo=;
        b=JYY478hYHXTlZvfxg0wGA7vyjGPKf2jPHrz2TL6R8ykqoqujIKBJXNXeEmkWlUx8M0
         7V4GGc5i2hB0CAlAyuUJDgcVE3U55fMD5ELn+lLcroSkKukPDQW8kDx1FK1cMw+X5538
         vt7OCPboSXUFAo77oudtOxYgSsXHic8b+LuQ9xO8LBfm0ynWzOzV5EFUj+7F1TJW6j2F
         QrsUtvA2sCQlr4yL+LusEdmbU3VZjnQAzf6XMShGSCrmd8eLMgVG3/eohJW2ndPDLw1P
         VgF2IRHkDKl3YlZ+0KKmMVmw0jNlGlFbQLcnYrDkgb+yo96VHUR3L4WohHt0QrQfjL7f
         jQjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id a11-20020a509b4b000000b00564caddf28bsi142843edj.3.2024.02.20.08.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 411FC21FBD;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1915E13A93;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GJHYBUXa1GVKXQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Feb 2024 16:58:45 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Tue, 20 Feb 2024 17:58:25 +0100
Subject: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>, 
 Xiongwei Song <xiongwei.song@windriver.com>, 
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>, Steven Rostedt <rostedt@goodmis.org>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1731; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=OddJ5DHeDgks/i1mqhLaA/c2lRjGQhZqtVTweHMQxDw=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl1No9wmY1D3tW/Cy64eGuViYQaGuyi/p0I9ZML
 1aOynVc32uJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdTaPQAKCRC74LB10kWI
 mgcCB/9ah3oEc1eVnw/8rJfS4V2CrkLLtkwjbxIk0QO1Y0hJK6fdAYScMioTiqBbFz2fYneiEib
 unIEdHVvpl+axQ6ErHTm8ti5I3TyU4MWWs83wr4c2KDwr6M1dl/PvpBvMynOrlEipojbhKdzBUG
 M7r0KCDPswYFY/bWZNDMSglmuV4rdwkzWpAlBnmUSK1ARpf/CL/dLuc8EoPraztYVvBTuVl7/sS
 yeaXUhG1SHr+j+ewEl+8Ng27ejIu7HOiappS80WyxN0awRxddapuB+uGZB7Oe88F1qMmz88+5/T
 Zwh17MejM5IUm/PPb+QCsLgpmJBon11M/C4qFpCzuDCoY2ct
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spam-Level: 
X-Spam-Score: -3.81
X-Spamd-Result: default: False [-3.81 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 BAYES_HAM(-0.01)[46.40%];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[20];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RjcBobBc;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
removed.  SLUB instead relies on the page allocator's NUMA policies.
Change the flag's value to 0 to free up the value it had, and mark it
for full removal once all users are gone.

Reported-by: Steven Rostedt <rostedt@goodmis.org>
Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 5 +++--
 mm/slab.h            | 1 -
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b5f5ee8308d0..6252f44115c2 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -96,8 +96,6 @@
  */
 /* Defer freeing slabs to RCU */
 #define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
-/* Spread some memory over cpuset */
-#define SLAB_MEM_SPREAD		((slab_flags_t __force)0x00100000U)
 /* Trace allocations and frees */
 #define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
 
@@ -164,6 +162,9 @@
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
+/* Obsolete unused flag, to be removed */
+#define SLAB_MEM_SPREAD		0
+
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
  *
diff --git a/mm/slab.h b/mm/slab.h
index 54deeb0428c6..f4534eefb35d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -469,7 +469,6 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
 			      SLAB_STORE_USER | \
 			      SLAB_TRACE | \
 			      SLAB_CONSISTENCY_CHECKS | \
-			      SLAB_MEM_SPREAD | \
 			      SLAB_NOLEAKTRACE | \
 			      SLAB_RECLAIM_ACCOUNT | \
 			      SLAB_TEMPORARY | \

-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220-slab-cleanup-flags-v1-1-e657e373944a%40suse.cz.

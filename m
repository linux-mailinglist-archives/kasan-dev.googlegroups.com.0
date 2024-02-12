Return-Path: <kasan-dev+bncBC7OD3FKWUERBP5AVKXAMGQEYTBRGXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DB1CE851FDD
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:16 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-219a73e6fccsf3167216fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774015; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xn76LFKOztSxivn9Ss3pcOpyWGIso8uJi4jHGck0V4HVwVHdX3+8xzN/lzoFZRhsr2
         ned2eGiulUWIfaWvQCunTknxKbbcu5mox2JLHbLbUWgP7GsgZh5UAhR8BWOujs3P9pEv
         fANMmHB3afTToQSlQcybHIu/6tIacUfoyHUHGazulWkGnWAZes6JJDkn91JWROhsX4fN
         MLbKmbW8zSq40Of8PoVEpIDw6D31XrBWFKi5H+qJS3ViBkGFzhqufsfGt90i7xF9NjqY
         +GVrm21fjwLHnsyKrN5F+d3f/f7tj5fS5A9huzdF/d7TxEpzVUY/HBR1vwPW1PQJ1/sC
         GPwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TjuVSZyHAyfvhk7ON3VNXHNJhmgV32ATqTxRAD1E2AI=;
        fh=OJfgCK3zecM7JrQv+BieB3fR92eOHqv4AGeU0OA7uuM=;
        b=b2LdXG1t/6yCmuNrjrGjjcdlUKzUOrygaHdVxjOB3HNCt0K3rIQI7Z08FvaKeqSxFy
         5+XJ0XEb3jXKOlxVxJdj+FuzloOpmMKqFmHq/eBJ92Eu/cIQ4qJ/thbRmHyc5gLP2bry
         DaenqBLRsD7DLOcNRRmm0Ue3Z++1U6fJ3Q0W23qvWPytHj9+9s+7eaKlrmt41mWheAPq
         l050pUmqVsL68YRcfjJG8z7r2Yfn/W7/pXf31TgnGk7JE37CepZt1TTHpyyoEaUFjhzQ
         KP8Ace5GUyRwC2UGv8MZJKd2hOaN2IU5n9qAdqFBe0JU/dWVb5puEi1TVLbsF30olPgE
         Ketw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ggJw5o6S;
       spf=pass (google.com: domain of 3ppdkzqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PpDKZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774015; x=1708378815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TjuVSZyHAyfvhk7ON3VNXHNJhmgV32ATqTxRAD1E2AI=;
        b=G7mubJR1SiZiod2uN8oK1qfFYAatUCrhdLTbzIdIhvaa5f30QBYYUIMJmLIdCrjjgP
         DmCtDxhcNt2y1UHxTFSMQgd7h32kcldjVC/MkipMD2eYpFMh+TORShyznfpdGlpgG9x5
         D6jLjf04OrVZmqPIwUsNBGC7z5NFjLrdYIkolaT9QJhiTY9iazUQqxi77HIFJlvrpRq1
         BMOwbdjnefePUom75n4lWT8yL7pnM6pisJ8Q4SIh01c9GchtKLo5bBMtf/Ayz+6op4L8
         FHVZAARrGYt5nWsACCPnaYXlhARMkrbJgbbdMRLDPpPOuNiX3VxPuoP/aK3/LoixcVBl
         m4ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774015; x=1708378815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TjuVSZyHAyfvhk7ON3VNXHNJhmgV32ATqTxRAD1E2AI=;
        b=b1i/i1aDAl7RacPdMLcXt19239+L9iRembEWMkHK0GFdsVNfnxIq13SW2obdlMhpav
         lDYk+kAjLJQj8zClxtv4POebs97tHu7C2jPF1KeN7bDkWwaOOuearO7BijHINh33y6fx
         PcGuvS9fiW158Qj2mn7oQn6ydryaCXRIZ6/KZeP6jDlJqadP09ubRIOkY78u5eMKZ/y1
         BjYPWx76CwvugyrKdMlpSv6Hi8cDMvgp3juqyytvVkZpdTYQNKR8AxoB+3gHyo3k5WbO
         Z7RCvML3mHLvPwWBn2KnBlM2bR8CgPihg6BskMfOABPrJzNY9/bBfRdtNax47R57B1Fs
         w/Lg==
X-Forwarded-Encrypted: i=2; AJvYcCUYatWcNujAeaUFHors6CddJ7KnK+GnPgyQ2PIsrLzIU0xJJx+hKcfCA3XCRBClE+YJwy6PT4/n3hZmoEgVUeg8TIxrwKwWNg==
X-Gm-Message-State: AOJu0YxRe1OpRQ0xPmPYvTaAZ3I96TYx5UPVjvTjqYXEJUbmgdFhyOU6
	ond+Hi0mecMA+Ay43Qt0SOfAbMnMLW2n3Musnfap7S/rPSGDQzIP
X-Google-Smtp-Source: AGHT+IEI2tYf3vMUSBg0RDuhqca6e/Lncqtcgia28FZFrYUhnRVhhMrZrKmMAIgyNEctgvCiuOIi7w==
X-Received: by 2002:a05:6870:3042:b0:219:4536:5ec3 with SMTP id u2-20020a056870304200b0021945365ec3mr7664840oau.24.1707774015762;
        Mon, 12 Feb 2024 13:40:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5827:b0:21a:3d0e:bd25 with SMTP id
 oj39-20020a056871582700b0021a3d0ebd25ls870373oac.0.-pod-prod-08-us; Mon, 12
 Feb 2024 13:40:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQCrp5N0O9fiWblHTFdjkHwEs0jYFg8pz61P3bFPUberwuSPzvnMcsqV3pgc92AgEMCFbTnzR4jt1BG7fU1oTcut0ITjdMCb0KSA==
X-Received: by 2002:a05:6808:319b:b0:3c0:2a95:d3c4 with SMTP id cd27-20020a056808319b00b003c02a95d3c4mr10463556oib.12.1707774014835;
        Mon, 12 Feb 2024 13:40:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774014; cv=none;
        d=google.com; s=arc-20160816;
        b=LjNE8xxHj7Rn4XKb3df0iV85WTLJfPnMTUCRVmtUGUlHS1cIFFbVoXUgcVD/ExOSI/
         0xeymW8rNqszdwMbVg/Q6uRLHot5cW6APwNKtewAF6oIQBc/TiUMwEhQgBz5FTc02h13
         DY5gbSuWfS8d7aQh2fpEFvJDnOXC1ovWa3HCPjeLw9pRK6pZJVt+qHwh9SD8V7Xc8/KA
         RJ9+z299eaN+WLuwHpwdAxOtuyd7nV4PZrPrnnrW64ATgtaAQAbnTWcVndjSTf/EnQO3
         nZBTS09tRtvCh5hlLUdA2Ul3f2ILZKkMY2nRJtMQl+4K6d4xrOELu9rJqb/SXPFUW/au
         VebA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=q3nAahWS0BuDAP/EiPEY1h7hxq9o0SR1xq9twkhL8Tk=;
        fh=grLXCPbcUSBSWC5ZXzxSbt9NxU/xR2Vm58EJDcHXjo8=;
        b=AZ5ZyQRN/t6+M9F6rp+grLPDkrTl95+vtJCS9VReofRje9F5Ght2CmUzG1om6Uvf1T
         n4rMOephCGL75vHaeV2vTZXrrx7pcrRta8CLR48xuOYAQdh53+PVbUuW9VImIbP7fRDw
         3oIffFw5q5H4LpLdi2ITz2LdopnmguHLDa6PK0PFwFD0Km9pT5BjL9vPx0Ig0y1OI5Sk
         b/JAlA5Rp7jfUmJdmceaZbd454uV1LLIY9W96CXikpMk4KDquKzeW6zKbXSQBn9v9EnL
         RMedRPrAGRA9zGFQUgec8EIhTXSTLG/mOIV3ANifzKo4QEekpziJwWULVadu0fH7GTi9
         xMDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ggJw5o6S;
       spf=pass (google.com: domain of 3ppdkzqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PpDKZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVJcQ+ZJL3oGf06j0hUQK3RfpfZ7f5jRw4iDkrci44H4bCzSBiFCqn62LN5lXR6Yo2kULafKaMHhrSaPYSlN52/OLDrSTJQLy1YFA==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id s15-20020a05680810cf00b003bff43c21dbsi133360ois.2.2024.02.12.13.40.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ppdkzqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-604ac3c75ebso68380887b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV4TPm0IoaevbNDIwTEP9WxQTrtfmr0Nhg4+bDL+mCsPwrdjvkFkDg29tb2EpeKf74AQahQk7D2B3W7m3DQzV8v5aRTyUnylTkq9g==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:70c:b0:dc6:fec4:1c26 with SMTP id
 k12-20020a056902070c00b00dc6fec41c26mr2112341ybt.1.1707774014153; Mon, 12 Feb
 2024 13:40:14 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:05 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-20-surenb@google.com>
Subject: [PATCH v3 19/35] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ggJw5o6S;       spf=pass
 (google.com: domain of 3ppdkzqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PpDKZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
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

For all page allocations to be tagged, page_ext has to be initialized
before the first page allocation. Early tasks allocate their stacks
using page allocator before alloc_node_page_ext() initializes page_ext
area, unless early_page_ext is enabled. Therefore these allocations will
generate a warning when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
Enable early_page_ext whenever CONFIG_MEM_ALLOC_PROFILING_DEBUG=y to
ensure page_ext initialization prior to any page allocation. This will
have all the negative effects associated with early_page_ext, such as
possible longer boot time, therefore we enable it only when debugging
with CONFIG_MEM_ALLOC_PROFILING_DEBUG enabled and not universally for
CONFIG_MEM_ALLOC_PROFILING.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/page_ext.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/mm/page_ext.c b/mm/page_ext.c
index 3c58fe8a24df..e7d8f1a5589e 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -95,7 +95,16 @@ unsigned long page_ext_size;
 
 static unsigned long total_usage;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+/*
+ * To ensure correct allocation tagging for pages, page_ext should be available
+ * before the first page allocation. Otherwise early task stacks will be
+ * allocated before page_ext initialization and missing tags will be flagged.
+ */
+bool early_page_ext __meminitdata = true;
+#else
 bool early_page_ext __meminitdata;
+#endif
 static int __init setup_early_page_ext(char *str)
 {
 	early_page_ext = true;
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-20-surenb%40google.com.

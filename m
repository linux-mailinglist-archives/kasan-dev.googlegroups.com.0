Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBHLZGVAMGQETC5UOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DC8B7EA360
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:14 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40856440f41sf8312835e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902854; cv=pass;
        d=google.com; s=arc-20160816;
        b=SMmfd3xRdw6M3jHA1zPg0ueyN0F+6zjhF7pNgIiSAs4AjfZxDXpYLks6kXPiDGGBaT
         c8AObVrvJ7LTF4a0zMj2to6r1/mzOyqeGZn97ML8jk1gfQNt4D5e2uSGNtH1evXxhXS6
         Pt0Uzbbr6LgqtY1tUmiutTVRa/cLNVcBwmZ8EcrCh9wTLvk+t4oUZXSz0iwKfYj78Wop
         vLffj8MvMpG0wjO32dx6RbjHweFmYPl6ygvI4z3y2vaimiXXNMekvl36pSEc7Ut6oY4g
         xX6JlJE91fhv1pipXgfd8vbckV/HxucTZYmF/fS3tyGUpystWX6KldyySIJt1kh2F4Aa
         VW6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=N4sk2E2/B5E569KhRdXT+j5oVqhgCIShYqg0USqzPtM=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=hJ4Gj/46QYrw/ffuw/zb9IlVjtNbqfScXdaM4HmzZtZiaiuR1mQep5IPpEZzZI3Oq3
         f+ikot0HShYeKIOfITVe8RRnRQJ3rkP595/VOQRkobLldyj9PboZgweDY2dyDsnD+TWl
         h6jOjbfOfFs3/k21pLmai8JFfoQq6Nlp2cL7D30Zg5Sym/xrTWefb/etLwqr1UPwAIau
         CmlygZra0XyKIzSTepU/CDts7JGu7RgVlvMoxc+o9/RP9TjTGWpVazkWzIpQknBen7wI
         S5nrckmmc0DKpYwh9/uZMR8FT2EH/QJbO7SHgNudtsYD23mNSn2KoGPkCHmCO8+3CT+C
         Djzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HHcoCLJz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902854; x=1700507654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N4sk2E2/B5E569KhRdXT+j5oVqhgCIShYqg0USqzPtM=;
        b=srOXc6e7Ae4EICIDBCCQZ2Ur6Gi1UFpcA3uxPO0j6PPrNJAhKS7vPrezImqXk9fYgJ
         B/CuO9dbBiVPaQdwqb+bGYTix1cubhf+mjWtD11AJZDQvpBCGCg6TTtzjchZ6RQZO5Ta
         G7clz+Wg+6wPYWdc7in/aLtLLzbNVX5tfd8KlwStTgkP8jaDyZLVX1VZKXkmVJL+eyRe
         UvkE1ozE1pnqZhMmUwGBwjojuy/lkD30bxxlxtxIeytlBjM3bw1wt4B1FB+98qBY4nJ8
         spqnp9par3rhaX6ZIcgEt6Tm+zZqtLq4ZgMEHfsZiMBxT26hYvLmVsbvMSuSsGjwYgqI
         ZGdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902854; x=1700507654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N4sk2E2/B5E569KhRdXT+j5oVqhgCIShYqg0USqzPtM=;
        b=Nj2bb7xkntS8mJhO6OjdDDD66A5YSkNsPiCoaYQn/3BtDdWAyFmFP0nADUN4exxuTp
         5w0AOBjiXHqFrm1Qw+wEMYmc9ZQmRn+r2PycUip/rpOZu+GuOWKE/+X2IYzkY9VFY69M
         CdEV4GgzZe/usKR1lTxe1ZF0axcovGiA+5k8ZpX2B7nwa5nIOekaM+dOqWxWUQOfUilc
         Dm4Mwg/IliCLOBpZ83Ws2jX1BOnSrZ2R5vnty8N1IjPH8JLqYZH6hua858sYEFTUbO6D
         HWbtH2bad5/WjkN95TNBe19yvOk3LuoO5TTdZokHv11faw/3IPbjUAFhCBZ6UNRYcXxk
         t+gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxF1w1PIS58B/YcDUNCykvdkbPd/U3eW8kdPAggv8hUt+oV3gAA
	pxJer8SiOJBVILWUXkQhKdQ=
X-Google-Smtp-Source: AGHT+IG87/iOROGGw7ojKbrMTwyohPrKCuIdiYzp7HEB7UimIO6PhvaOqUUcbJ2nAM7wJqSjJCskOA==
X-Received: by 2002:a05:600c:1c1e:b0:3fe:d637:7b25 with SMTP id j30-20020a05600c1c1e00b003fed6377b25mr6288924wms.0.1699902852704;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c05:b0:312:831e:ec96 with SMTP id
 ba5-20020a0560001c0500b00312831eec96ls1432677wrb.2.-pod-prod-09-eu; Mon, 13
 Nov 2023 11:14:11 -0800 (PST)
X-Received: by 2002:a05:6000:2c7:b0:331:3425:b84d with SMTP id o7-20020a05600002c700b003313425b84dmr7565215wry.12.1699902850991;
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902850; cv=none;
        d=google.com; s=arc-20160816;
        b=F8K9KIfxybxn7M78E3wPts+OPd3Hywna4fqXs63D4/hEn/Spdc74MxKwj8ksT92rhY
         qUWivT3fZcGszt26h/AITjI7LwRtytMaFH+iEelbHekPFy+BlzocrtOI71Ce8ZxO6xSQ
         t8xIoy+JrxmCf6ESizRqedr/Z8+if82TPjmimldZrDVU7415lS93kOQPb14Dre7KEP2F
         RXXFlQ6Gs3PKxb04n2KnqG/p0rk8XdwYI5q9nF7gZE0hjJsVzIivqMjQwJICbyCgK62z
         dGdhBQV7gQ2UtBp4sDaNrlKIQrzZ2S/GGId4W+OBQFtpeHtbKCYcn21Fo3htpfd1HNeq
         vtPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=mRge4tn8AOyKqllhp/LWhG7OC3rpWRAypfG4D7BFSes=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=orgSUoFdvpyvcLeBd6dvzjdM7gvZeos9j0k2nwzCB4V21IxpdYFgQEx1dvDvRC3RW1
         oW5HkusduN7AGIDJkXqZI2qAOUCGP0jeqOeU/ZQXVHAnf5Y96wUXF+VXen1+07OtH3Um
         cPfLvDm96OfRmFlN2nFlksWwi91VIjw8ZJckAFiXx5Kg6IF6vBD+wPpFfjyNF3QaTDz9
         KC4ws/9gELGkuPylkbqQAHPljTstPDO2Dm3zirGDwipnoIsGkYwITI22mhmUX2olixSK
         2wciII7hJsnUDsCXHwxvdjRk9CPwpVSvK3abCygv0OOJ16rh72Ed7GkQ7SERJjSo8GrN
         +aNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HHcoCLJz;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id h7-20020a056000000700b0031aef8a5defsi190385wrx.1.2023.11.13.11.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B38D31F855;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 63ACE13398;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id cICdF4J1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 04/20] mm/memcontrol: remove CONFIG_SLAB #ifdef guards
Date: Mon, 13 Nov 2023 20:13:45 +0100
Message-ID: <20231113191340.17482-26-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HHcoCLJz;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With SLAB removed, these are never true anymore so we can clean up.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/memcontrol.c | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 774bd6e21e27..947fb50eba31 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -5149,7 +5149,7 @@ static ssize_t memcg_write_event_control(struct kernfs_open_file *of,
 	return ret;
 }
 
-#if defined(CONFIG_MEMCG_KMEM) && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
+#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
 static int mem_cgroup_slab_show(struct seq_file *m, void *p)
 {
 	/*
@@ -5258,8 +5258,7 @@ static struct cftype mem_cgroup_legacy_files[] = {
 		.write = mem_cgroup_reset,
 		.read_u64 = mem_cgroup_read_u64,
 	},
-#if defined(CONFIG_MEMCG_KMEM) && \
-	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
+#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
 	{
 		.name = "kmem.slabinfo",
 		.seq_show = mem_cgroup_slab_show,
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-26-vbabka%40suse.cz.

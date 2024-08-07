Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM2ZW2QMGQE3T4SKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AAA194A584
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:39 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-52fc54c3f66sf24904e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026698; cv=pass;
        d=google.com; s=arc-20240605;
        b=iJSgZvYnP0tCln2N3Xhta6GRYbGslou8m+Eo2CSW9064xshAOTmIR+M9e9fnSba5sF
         ERmcKEmHa8F4NQDstKjE2vFzV5q0TXzTm7EiGxsz2sOlxztjFn7g6UMTxVCRc4tsQ3CI
         ssSfAJHAjcgN9jmMm2/n/n4AaB1AgswRq2yi9MMr3s3GOOxA5+z2OS7CPI+IWOWrazR1
         02RjzEguU2URtHSmFF0EwHo4Xou8ATtlEixtiVnhqzySg9v7Y3+FE6QuIt6Xuwko6qem
         y2GOkWfslOYCMOoNZPFEzbItDMD06UJbwr2UALXDdO9nS4JhdxmNCcL9CtQeCrX9zvMG
         J2Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=lCIYS1sM7DKCbyDsjXPQTQxvrAf8AWdq1ohHniePKNI=;
        fh=lzi6z3btj/49f/hPAbHfCn4/4IXjkz4Oe5h23f+wC7Q=;
        b=WkfmuqDjOU+aOP1bRLBQpSAOsCkDUKQtw6JVjlGVH/11bpxZGO84iGHDtDg0QVbt64
         SmNkTz+EOS6RKR/k00CjjS/R4H2JWxo/e3e5ufamtLBmSS8UsA2SnFDOvAwRXPnepF8m
         9b1UlKx+Sj2RYjNdvu2yFJII79fsuP8HUPTiI1rqIb3jVS4skN+m5zdn6/nAhSGzK0gV
         y0+qZFKnvQucFureRkRJKxoZOEZ0yXs+Th17HbRzV+3Hcps6UHj45ujXo+Mr+90oByKP
         19lExUO6Q5iyXoYQ+qL5HVFrbW7Ie2kRBs8BXb2qj8+TbULkheggh7h4kP3hdjGP8t/j
         /ciA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H+6QUiPp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=eEuKmuDB;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fOdhnuMq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026698; x=1723631498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lCIYS1sM7DKCbyDsjXPQTQxvrAf8AWdq1ohHniePKNI=;
        b=BKfyuDG5LV1dsqO+PIvzsZAaucBrtJqnSHCBuWnlbxCIpxpTdTMMZvnXWkBHeQU3VF
         +YSOiAu+7b5+GkDOZAo+YbmTM7dAqOM9L/9fT4iVjGb3FLHbBC9+M4AhkJRiKzo09yeA
         iUl6Ux5JayzAkNFZ82dCsrEzDa2V24+Wt3ybzMP3dS+lN4IJzwAaWcFeuyaPEzWI8IFK
         eIdpuIQdv3Gg2w7XKwQ+kw1rFMwpf40OrQW3GydIcx17mtQz4RkfSXLT+k9g03DFTT+1
         zS6ITrQUNxwWfk0BgvCf1sgM0ZTrXRhk++fjgmpM0kTaEt9bTIzmF9IivbVcCNOpC8TD
         2swQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026698; x=1723631498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lCIYS1sM7DKCbyDsjXPQTQxvrAf8AWdq1ohHniePKNI=;
        b=gt+57ZguEMnGd1Zlk1urbtj1YjRh1O/FIPCLWoYYHQ8yob5si3fHUK/HuUvWv0guW0
         XfhX5lNyHWEmxRo9Ukr0tAvXnmoECjjr6ZT4on3vxpdkFH+kXt2sOBrJxgYdKdJZ0Pf8
         TYLUHdKQEKLdgQP9NIsqm9SloUkuA4AOSwJGXt6hfMqr27+behNhl35TaY1hdad6R+WU
         8CW+73kDRIOHToOS3QfJWe5gywDg7lvFPy4Sr1KdYGR8pZ5WF23mVDjI3N52Y5Vy1XlV
         UM+G+IFy2P82Xy5zisgPt9t7WfYbGRTj2yyrBdAbVM9juphDbNHQznpSLJWjj1exCKud
         CicA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVt66jYkED0Eu0n34v2AbYP4w0Ze968sJZ//vWMNFdVTcmjs2To2Y9qbgOasUU+DI8btj4gjCa3XlwZIlrkUM7xTp5HM+1JHw==
X-Gm-Message-State: AOJu0YypmTe0TkdSD9VtWed54qslsEaJ1pAS4MYTf1IyOJvU9mMiEqTN
	4cYxcOkPCk/R5ymRuHch4GAmAbeyY1dp/m1R8B14r49Hkl9V8mh4
X-Google-Smtp-Source: AGHT+IFjrJNi+pP/Dh6NsVaii8yLoUjQy2SQIlkOMxR7MCWcohFtmyJvHElg4qraJ6VWKSXCSHjLVA==
X-Received: by 2002:a05:6512:224c:b0:530:baaa:ee10 with SMTP id 2adb3069b0e04-530dd7d391amr90510e87.3.1723026697790;
        Wed, 07 Aug 2024 03:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c8:b0:52e:9b66:4f8 with SMTP id
 2adb3069b0e04-530c31f24e7ls2267395e87.2.-pod-prod-05-eu; Wed, 07 Aug 2024
 03:31:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJFQ0XoVNcbJU23yjva4niriq3jrV1byjd7Un3XeuUlELPDG1d8BsYmjZTzWLhJYjpvwpiG3Ipfs/MjRaHASdiaOnudsKKkYyEHA==
X-Received: by 2002:a2e:9b03:0:b0:2ef:2422:dc21 with SMTP id 38308e7fff4ca-2f15ab5cd3amr140392591fa.43.1723026695677;
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=ogdF5ShGySVF7npv1oSMHq7qDy2coKeOYcCxOZZltbPpf+WSAzOvFpmhPemY7oOjno
         ZZyDoRnNXIuqDJRniUE0qnzQGhwHC7KOBhxLpgSBLWW4bhN2g5kjYBsflio35H2hBjC0
         jqklhMYHn20gEoBFVtl3rLxEJR4hUCeiuyxqEuS7ug1iZvscbghZkVVuGr2M8iuTf8Cx
         9ss1JBHga/JzShLxOE6QkpRmdHMfEOoFZKUypNp/NqPaxzVcD0XIRdwuA08wqpRtBuaf
         sqDSBh5U9UmNnODOsOqkAWsYvkb5O/hBaXQAYWPgU6C4P4q+/OvjqRmqDLr42j+Gprk2
         XB+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=2ZCscfrhLRUfMCCWf1VM+44Ik8h8Xr8RVOlGx1djGvg=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=l35GFuw8iRPzvQ1JF7o6RN1JBSWHHF+azyAzzE0+H5fbZZK5TBbDaKaz/FxDCACg8L
         kCfc5dluFCosVjPNunT4BKOhF+NOiovm4Uq6IA1p7J9amEJKVLXHMZnKHte5bAd+6XY8
         iYmuP+CEa0zsm9ssl1OzPuYNB30F6eLEDyjmU0fCaWWTc8biU7lNTAYbc8/i2P5ljFJ9
         ZScLLYzw9y//s7eyKrzBTgU4gAdbe1jiMFIKhXLXWZxOr8TIYFHpNbX3m7roJiEN7O24
         Ebe/H7QpTLHagziVr34E/3Cqjtr1zj9c3NF47iNJ84bQu9EWwBw/gS4e+I+OijgDvyUp
         Q9dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H+6QUiPp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=eEuKmuDB;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fOdhnuMq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e292214si2382761fa.8.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C1E7121B34;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 96CED13B03;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ePOIJAVNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:33 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:14 +0200
Subject: [PATCH v2 1/7] mm, slab: dissolve shutdown_cache() into its caller
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-1-ea79102f428c@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
To: "Paul E. McKenney" <paulmck@kernel.org>, 
 Joel Fernandes <joel@joelfernandes.org>, 
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, 
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>, 
 "Jason A. Donenfeld" <Jason@zx2c4.com>, 
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.1
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLtsk3gtac773whqka7ht6mdi4)]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=H+6QUiPp;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=eEuKmuDB;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fOdhnuMq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

There's only one caller of shutdown_cache() so move the code into it.
Preparatory patch for further changes, no functional change.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 40 ++++++++++++++++++----------------------
 1 file changed, 18 insertions(+), 22 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 40b582a014b8..b76d65d7fe33 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -540,27 +540,6 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 	}
 }
 
-static int shutdown_cache(struct kmem_cache *s)
-{
-	/* free asan quarantined objects */
-	kasan_cache_shutdown(s);
-
-	if (__kmem_cache_shutdown(s) != 0)
-		return -EBUSY;
-
-	list_del(&s->list);
-
-	if (s->flags & SLAB_TYPESAFE_BY_RCU) {
-		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
-		schedule_work(&slab_caches_to_rcu_destroy_work);
-	} else {
-		kfence_shutdown_cache(s);
-		debugfs_slab_release(s);
-	}
-
-	return 0;
-}
-
 void slab_kmem_cache_release(struct kmem_cache *s)
 {
 	__kmem_cache_release(s);
@@ -585,9 +564,26 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	if (s->refcount)
 		goto out_unlock;
 
-	err = shutdown_cache(s);
+	/* free asan quarantined objects */
+	kasan_cache_shutdown(s);
+
+	err = __kmem_cache_shutdown(s);
 	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
 	     __func__, s->name, (void *)_RET_IP_);
+
+	if (err)
+		goto out_unlock;
+
+	list_del(&s->list);
+
+	if (rcu_set) {
+		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
+		schedule_work(&slab_caches_to_rcu_destroy_work);
+	} else {
+		kfence_shutdown_cache(s);
+		debugfs_slab_release(s);
+	}
+
 out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-1-ea79102f428c%40suse.cz.

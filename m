Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D9C7F1C76
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:43 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-54366567af4sf6165372a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505283; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx1y++ASrvFXUHs9svL5FyzgcRER62XqqhC20e8i1itVUjD+wAhfW2RZuygk93XEOn
         PsrbEIeNUS2yNmE2iLqDe+0Y3Ru2VTQQr5iNCWKG/6d23sDP9byrsfP/b8SMkmQg7kHY
         2cTIbI39F8Sj2uJ+rzyz5ao08OM36JPhwgBPQlcU0+UwlBjo2CBG+dX4HESomnrVJ7TJ
         Gmd5v1umE3JBVk3UaX5fHgArE90GcKBpfof+HSwuYAjWqt8nasICwNeTpMj6UwnnbVxO
         UclN5HLvTYQG15BRk/Lbix1JZY0Q0d28gOFK1/nG5kuJzwnylNjC0yNx9Rs7ACgyZOLq
         bgJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=owiTewCNKwsgROjE2pmSGMfsWNLfK+Szev+CA08UnhQ=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=wvDvWap4LVBgaV3LqBndk162Rzx2suQ06wri1+EQEOsCrycKdNf0IfXZZQEpfCkD/9
         rKh7EQ0fWNH/JxTpV0IeSGDUExzixJJZH3BsRAGPInkZwyw+DPWcbSw44wIQcy3r1TrH
         fGExEJsXWEv/HfHsmgzGx4mVp+MxVTstbgnOA7GXo9ua0U863ee4PSXOiERJ7gyr9+Qa
         Ff+RuPUPLJxlizdA6jw+UeubNLH0pUJcPg0LAyxnxJKHeXzLnF1TykuoKB4KorOmwe6m
         4RgAtuEBjZcJMovXEpfNj72wExxC2ulsAsKbuBWWYz0fhzdgnenF7JRITAFZca2PJS72
         NhjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lskh8+Nj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JQZpJQ9Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505283; x=1701110083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=owiTewCNKwsgROjE2pmSGMfsWNLfK+Szev+CA08UnhQ=;
        b=pVp47uJOO0T5lnokakKN43YoIDQ0G7shWgwcX/Ipaz9CLvOkSh+xberCc2CHnRYPeK
         Y/EHAtyfPOMEADIs3N7nA5TsZxsABVbSqtR234gRrMGEiXCDVPzLj3sajiwfaIeoSjrk
         W5ExkeXfIkGIxrVtbk2Orp9wbwx1HDku2iLOikqtooIbq1h2sjJcEWb93vKDBL4rlQdd
         vDTdEKmljbbaTLs2Z9iCdG8kD488j1MGPNx9ZAp9ddW8xOufnLNINAxLTEl+xV0VZMge
         jINA+fQcyPnkNSQHPenMYBIYaaGCYs+1r7AZz4NiafA8BKrarrMQqZIJyml9gfNu2+51
         f7zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505283; x=1701110083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=owiTewCNKwsgROjE2pmSGMfsWNLfK+Szev+CA08UnhQ=;
        b=bOcVg0UOC3gKJnLYf/a3fiyIbsQGaz6jvpk0Lx4s2CEqs5RWeK73VAV9rL6LeDx9iQ
         QMAbfSeGjBSbUslbWjMjuExQ6aSKycJ0Cq4DnshLd+zM8W3cDQGZzMTeYaQymi2l2IHx
         fl9k/T/rcjno19BaFBzRZyeVrfS5PrARYqRDEIwN6MEo5JxHGtZu3FLUm/mE2ysDXS7o
         RGSFz+RPw1SoNCFkZqzJRnxyiWgHI5lfAbf6WL30zQyaHBPGZqnzDjFIW02vfv9CWbnc
         Y4JmEaD2Bam5KdfE5zD9j9WDPCCOQ6Omg6UxLda+xQHLHBdzeoqtUaalKWyCMHYg6SQ3
         IeSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwlN+RnLSsydMtR5867o9lCi22xbmagjydaeWZnrxHDU935P//B
	gPeVZr1GyGhwj4t4ie0TLRs=
X-Google-Smtp-Source: AGHT+IGkCuaD0oJIIMWToGCQ1rGu6M4oTjXsDH8l8W/MgB81sORmPKDPnItQYsMdS6gXo9d+fwhDLA==
X-Received: by 2002:a05:6402:5022:b0:546:d6e1:fbf3 with SMTP id p34-20020a056402502200b00546d6e1fbf3mr234649eda.1.1700505283359;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:374:b0:547:2571:d5ae with SMTP id
 s20-20020a056402037400b005472571d5aels122136edw.1.-pod-prod-00-eu; Mon, 20
 Nov 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a17:906:51c1:b0:9fa:caf4:f4a with SMTP id v1-20020a17090651c100b009facaf40f4amr286139ejk.32.1700505281311;
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505281; cv=none;
        d=google.com; s=arc-20160816;
        b=JbtlHOhkrixg8Gqz09gZhq7zdMGuE8/+xdcISZv+GFxFVCyGfW7XlpfnFXRWfDa749
         rtMjaiz9WcCgMN3oOLwRKoCuAme7bYp7SjHNOfbJDhISla93eqRbViBPPWlGX/1yS6nt
         zHdolSHCNnabEs/jleOZb7pfQkuIzvu75kUc6LW+9HUdRCX15REgmHX/bBuF7EbyqPOj
         /ebvtCHbsfHcPGi77fv5+IHmm2u94+cL7YCFzsLLQ4E7Bd5z1fvnb03uBuvnwjJB74Ps
         dPN1I0I6JfG5ndCS9NkE8yEONvSUrcr5alqi2Ev3Uxy2AVHY6zv57UTBvfd9aWX6Thii
         GU6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=Nuh5DWhwaSyo20acRrWx07FPXsn5IPuIhuzYTBlJYws=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=Dlxeo5MzA2hR0Mf3wJzTozEHa73hBH6+KB3NMLgJkYHYCnLvSfkrtqHb75g08b2Byc
         rhdbPrP2lRKr/gHBpHBoYPwgGSLk7aVW86+66VRAwknf2p3VEBsV4eaSvTe3yzwPDIMK
         x49UiEPJWcEB6u6aSAEotScnG2TH688Him9Y5Mvn3PZEm06IkKwj7n+MShGeHrzYz7mR
         mvS5qjWjGfcgIVYyVJAXIKCtQj5dtNpoOjUfgMtjrBm4c9wUY0QZ0lFhaof2ZaO4QckU
         jQBDLAbyFcASBnBax3LknyjL7rrR5cDbuemcrzzDY1xtjaThxF+ipb1x2PCHvTRuE1rn
         wOSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lskh8+Nj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JQZpJQ9Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id fi27-20020a056402551b00b0053e26876354si359839edb.5.2023.11.20.10.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E9DB51F8A6;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B55FE13912;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UAbTK8CmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:17 +0100
Subject: [PATCH v2 06/21] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-6-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Spam-Score: -3.80
X-Spamd-Result: default: False [-3.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 BAYES_HAM(-0.00)[15.84%];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lskh8+Nj;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JQZpJQ9Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
SLUB defines them as NULL, so we can remove those altogether.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/cpuhotplug.h | 1 -
 include/linux/slab.h       | 8 --------
 kernel/cpu.c               | 5 -----
 3 files changed, 14 deletions(-)

diff --git a/include/linux/cpuhotplug.h b/include/linux/cpuhotplug.h
index d305db70674b..07cb8f7030b6 100644
--- a/include/linux/cpuhotplug.h
+++ b/include/linux/cpuhotplug.h
@@ -108,7 +108,6 @@ enum cpuhp_state {
 	CPUHP_X2APIC_PREPARE,
 	CPUHP_SMPCFD_PREPARE,
 	CPUHP_RELAY_PREPARE,
-	CPUHP_SLAB_PREPARE,
 	CPUHP_MD_RAID5_PREPARE,
 	CPUHP_RCUTREE_PREP,
 	CPUHP_CPUIDLE_COUPLED_PREPARE,
diff --git a/include/linux/slab.h b/include/linux/slab.h
index d6d6ffeeb9a2..34e43cddc520 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -788,12 +788,4 @@ size_t kmalloc_size_roundup(size_t size);
 
 void __init kmem_cache_init_late(void);
 
-#if defined(CONFIG_SMP) && defined(CONFIG_SLAB)
-int slab_prepare_cpu(unsigned int cpu);
-int slab_dead_cpu(unsigned int cpu);
-#else
-#define slab_prepare_cpu	NULL
-#define slab_dead_cpu		NULL
-#endif
-
 #endif	/* _LINUX_SLAB_H */
diff --git a/kernel/cpu.c b/kernel/cpu.c
index 9e4c6780adde..530b026d95a1 100644
--- a/kernel/cpu.c
+++ b/kernel/cpu.c
@@ -2125,11 +2125,6 @@ static struct cpuhp_step cpuhp_hp_states[] = {
 		.startup.single		= relay_prepare_cpu,
 		.teardown.single	= NULL,
 	},
-	[CPUHP_SLAB_PREPARE] = {
-		.name			= "slab:prepare",
-		.startup.single		= slab_prepare_cpu,
-		.teardown.single	= slab_dead_cpu,
-	},
 	[CPUHP_RCUTREE_PREP] = {
 		.name			= "RCU/tree:prepare",
 		.startup.single		= rcutree_prepare_cpu,

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-6-9c9c70177183%40suse.cz.

Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3NASTFQMGQEQOXPONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AFD0D138C8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:03 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-382fbcb5033sf35614431fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231022; cv=pass;
        d=google.com; s=arc-20240605;
        b=VXEQSJ/LG1YSULYFcuJbrD6UoA/hVPGTW3hMImqFhB24Jp159XmWXxrFmO3TF6YJkq
         gXhB8lQ/qdwtoV2QbK22tnrLAgo3G55dCF6H+NsC8ggAqpQyznKPVS3eFulh1zJEG40g
         YbFVvJ0PLKjWw8gx6Yk1aDqkZpCMJPxAdwiXHDaVlQUUe0wWn6fFUin/qkZVma5M+QWc
         G457UA5tltRX0eheCi6xa2+3QqpWVEkm5dmHdbVmcfFRa+/1x+t0EW9tsJblsoBLr0Np
         8BruBWTapr4D+84tqL40/Ki3ZTMHuaj8vgmIJlt1t0rsbjZHjI1ekYam0dLRdUCXzm/Y
         oVAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=xb24EYZ2/8v8DAfw2fh+ivZuzSxwxMZTYSZtssdP/Bg=;
        fh=Pg1b00jlubsPKp6SwcjOyrgAz7T5W8IOyNje8HvJXK8=;
        b=LooyBAFxbYMxIFybOdjqJQIjm7XQqjRfrIt+amwf8nQ01ojd6ys04g0sCcP7c665Zo
         jgJpgYf6LrnaPsSv44ODUTRmpxCN5MmiWse45KtZ2l5kclK5JBuXQXmGv1k6OHLPX+Ni
         7rZYHshS6ZzwFy5EIoG6Uacj8AXnjS4s1IbmAZJqgIAISNUEfXjAc5JyrRirN7rxgtzy
         w1OKrpbAdui0NgqUp+L1t+rv0TNhuM09eh9+MpMtyyl9n/UFVDk0uxqlHVHqmXzJTNY/
         8mbIXnpHuzyt2yhwAyFEywXyXIagepCdk+uTsXTtbTzUj/FfR70sf/erWoxNB9SLkS6i
         M9Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=viR1PWyE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231022; x=1768835822; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xb24EYZ2/8v8DAfw2fh+ivZuzSxwxMZTYSZtssdP/Bg=;
        b=evKBbcuvG+13LNCLvDTXsDOMbAgvX9es6VcMl2UoiYxgy+HbgeF3vqaLBZHnSQUTTB
         mwhVP4dAhfxOzi3ZmZzEwK62Q32ZEAVY+eMCNVZe+BbHUkIlWEC4emgGXvmAYuaCzzox
         E7bsrVRl0IPJ4dd633tglANhmAgab1Tu7K4qcHSw8GC8xEkS4c8159FDx1aTkHbINa4Y
         Md6uc/MGhH788OPP0LOtqJKTmjkBtkTPsUVlLluYvYIpe8mj93vKMf3c0PPyK/0RPKJ4
         FQanZNcVmLfjaDcGgjAstm4LyAP3D02rI7OEWnVaArQkXwrtUv09BAY5r1kZTOeD1vKh
         SybA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231022; x=1768835822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xb24EYZ2/8v8DAfw2fh+ivZuzSxwxMZTYSZtssdP/Bg=;
        b=xLUgytMWF1i4v4nv27aG+l6MhuCrBT3MbtHcXlQkPREgbDITisUlBIEICjiC2BUJ5c
         MBTMTegx8OL+t8oY9ZdbCYDb+myWqaLJOkncGlyrgGASazfzLZwbDUdLxfXm961/nQ4k
         /noj/CsQ/jnSpWgjPqs0OQMEPo1TbesgR9NvRV+HeW0jXShCyIGzLhKQiNo1l/Jfe9Ev
         MF87cXzkS0sHr/V4esLDP4Iyz7fUIJhCF0S87L6PxFuJXRNFNSqkQNSCJyrJ6FHvo1ky
         J10w1Fec6e0dzaKcfhpwQsd8KIPJ8FijvAaNAWzgm9agVwi3bUHD7DFTmiJlN9USn4RO
         WXHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhOweljV8D102dLOa6Uv4VaiDrhs6g2tFrJAnkYBsK+CFBbWTx/S7vabEKsaSP7EeANMkbOQ==@lfdr.de
X-Gm-Message-State: AOJu0YwpdbBl6+hzvC7hAdwV3aGVdwyijd+mHjsiM7dCv3EaeodLN30b
	eLFfJ3b3nE51BvNtSFbHdhVWxktW5UNtLRJYp7f+ta7AXwVjxf7Lczkw
X-Google-Smtp-Source: AGHT+IE0cSYLtNSGFL5a+ASrxovOix0ed8swZoZxexAX1clusqHDukbvwIwqlHvtooSxkF26a6010g==
X-Received: by 2002:a05:651c:552:b0:37a:49d3:863e with SMTP id 38308e7fff4ca-382ff81f984mr51260251fa.20.1768231022116;
        Mon, 12 Jan 2026 07:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GteBA+jqrbSyRQnBkdNm1VeKuzS7LpvIMWnm6GvfhexA=="
Received: by 2002:a05:651c:434d:10b0:383:1839:2d09 with SMTP id
 38308e7fff4ca-38318392f86ls8258881fa.0.-pod-prod-06-eu; Mon, 12 Jan 2026
 07:16:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzuyWklmknlj3P0RcpfFv1wrUtX2kPUdDUxH2rikyQq3MLxkFWhikyLIpR0g9KXRsil1xc9lwx4OQ=@googlegroups.com
X-Received: by 2002:a2e:a993:0:b0:37f:c5ca:72f0 with SMTP id 38308e7fff4ca-382ff67eee1mr47191711fa.8.1768231019177;
        Mon, 12 Jan 2026 07:16:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231019; cv=none;
        d=google.com; s=arc-20240605;
        b=EQPudnPCdROc+Ikltxiq2nEpai8WSZFltifAHfCPWpC6f5+zXufePvfKj1NGw6M6H+
         PwZP/hTWGUl/lH2jkeSNYItTuL2InQFzeBW9LsKeFCOZ+fFbj52ZISIf6VwXU5L4YVBN
         oDFd4jynQVAeguZz7zVw9CcROtl4+gLzCBl+OJ3hWj3NePlMMrq1UjmPI8a4hThxOZCo
         OFLBldJf6ySYiTAMs7sRGggPofZ0dM+fFrVZIidIJ/7CbeLs06aiHujcDpoOzVdYZIUL
         SMYpPtoKCcCAOjlhL7r5nW4qevXMH1ckEA6qmypC7X77GIJXRGMdyMGMi4cm154wZwky
         t8zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=KrA6Fyw2WVDJmDZKCXu6ahFK/Dsl+EjYPaRIRf6Zix8=;
        fh=ZDxAv8XPBkZG++ei96Z+swcHRAJrJtblU7Ri5E43an0=;
        b=EBE35Df5M4CQ4Bwqxvv92CTh5R71ZLZrx0tnIC5o+zo5grMK4bow/yK91d5d9zf4lw
         djgHeVh7w7u6LOf7SrSlDCChGgx2UiLu36r1vB9TudoNg9TXSuCZJczAqW5Rx1zkXyt1
         7Y4PDibcqd4mxAg6jzNxape1fuyLRbYnn5e4N1tRhORthZ+yocg7Bh8Q8woEsvofFKJy
         JoWXZCa32ebfpLpPAMF3uPeU6hiiId0t7oSsLgRMhjocS7sJOHeAAOvMcQjEwUDKrLHB
         gD6CW+2mg65IAngq2wHCoJHsFapT+fg2iy1yYS5D0GE9sDrwH823wuEz/hbmY+LEE0dr
         f8kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=viR1PWyE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3831a5fadf5si1645041fa.5.2026.01.12.07.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:16:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 553755BCC4;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 306713EA65;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oEhwC2kQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:16:55 +0100
Subject: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>, kernel test robot <oliver.sang@intel.com>, 
 stable@vger.kernel.org
X-Mailer: b4 0.14.3
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Queue-Id: 553755BCC4
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=viR1PWyE;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

After we submit the rcu_free sheaves to call_rcu() we need to make sure
the rcu callbacks complete. kvfree_rcu_barrier() does that via
flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
that.

Reported-by: kernel test robot <oliver.sang@intel.com>
Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
Cc: stable@vger.kernel.org
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index eed7ea556cb1..ee994ec7f251 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
  */
 void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
 {
-	if (s->cpu_sheaves)
+	if (s->cpu_sheaves) {
 		flush_rcu_sheaves_on_cache(s);
+		rcu_barrier();
+	}
+
 	/*
 	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
 	 * on a specific slab cache.

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-1-98225cfb50cf%40suse.cz.

Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUW57OXAMGQEXMVIOJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DEF986A9EA
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 09:29:08 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5131796a4b7sf952638e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 00:29:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709108947; cv=pass;
        d=google.com; s=arc-20160816;
        b=SZbe6Txf7zYF3zkUgjni5qTAixi2+YBH/8luNsirGWBEdJTaZKIwFVJU0YCTKmcTkV
         nC9M2yBtuvCXv0ZXtpl5Nxv/Oqh2KWJ7r0vT4yB+vef6bQaQqDZJVRJQqcB2Xkcgs4Je
         mHmUOc/+5cUXpm4E6nVS8jOszL6WDim/UXWqlniMmKHHD4unKyOqIQPp69YvClcP1eKe
         S+qdbnVxMKxLoGOv4paevGi8uikHU7iMeil0llwlG07xiGnIHsCfosUgCJ64tA8pDVUG
         jQowsrC+LnfIwqs25diNgyfK9wQ05CqRxKbN1b7sDgMY2FVKObVYmArDyL9Z3eHt2glq
         WVdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=DkReFCm/t8Wy0CnY98S3yxGyZNfronfowY0K4LEderw=;
        fh=KYoVR8XMxLhJx/DUR7+9FwIQC4lG9nKP13GkTUggfI0=;
        b=iPKo0kOeeHr6HWXIjBC70cSV+tTJlDXhGJs6bMjTMekgruBq5DAPq+MRr+r9tJhFcE
         TtoelMNn7FvzoembgiZf+8HlCt+VsUvBe4x4Gf5IHdjCkW31ScQr3MNgYhlQ2/6LF2T0
         imE/rNWJegRzS6KssNvSO0Y5F95pmOWthmWm0GuPev42L/S0hw6UzEfJm7+FFMdVyJ5Z
         kWIJ5IwtXk1vfUe0UEBSqTSa/eYSwAtxZlV5Wg3Er3lAJCBsFOu9Cn64tekMZMFjTgPr
         AykhJBmQffFlYeCfgC/2TiuhiZfhIMHKUKwkLTv+XtyKZK2hlQ+5edmSo4oB0Vr4fb0/
         F1HQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709108947; x=1709713747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DkReFCm/t8Wy0CnY98S3yxGyZNfronfowY0K4LEderw=;
        b=DUefhSzAVqDpRCi2l4SPh1sLeii0dM5EzxqgPv/a1/lUa0SXQZHR8Yug+3gvV5yY/j
         NAif3NkUMu8SKIGWgw70xHvW4HDF9AEhiO4tKtwuf3BtvcCGT0EVPKk+/Q5JVjbaISkY
         /hhfMvxRcmMMeZZznsC5dP/JSJPYQ7ybA4jCll7Q37eUsGbHm18+KVtt0nvtScyQgKMn
         kF/gKeSL2yJmH4f2Upn60yk+rwCifzlKWLATwGpx5xUmGtZoPMPg2Aigj2sA4rCBVVKJ
         4cBNCrmavdIeR2aV28bmBuLGqqUSjcD54hvUIbDqREJ7ZtoZK/3hm5XU7U4VmxOWTNEb
         Yvaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709108947; x=1709713747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DkReFCm/t8Wy0CnY98S3yxGyZNfronfowY0K4LEderw=;
        b=MQPvuSl4pmHQLl7YI7JTWgWxUKVPRQodjglbnZjuFUDNg/PVgcy/B46iOzpG+iqLqT
         JggWNMXByno4nR9pS5WlvDn0weCyAZDR8ELwHaA1cqy2XbAl7gRY1p0UkesyHYTGmWNZ
         WQw2yA5Qgr3ydbpdEd7/NEw70Xd/NF8mlYXmpgQtMlvlNKak+ofwV02syic6QXVIGbmQ
         P+4aAW1XpHLXmIVGeGL5tojCm3TG9AIqfchyiOJeRklz3wJj9OG1/WCoYp2NGGzxpfEz
         8VTcFr6hxr+UtozPHnwT4FlKSraA3JuX1k7QUgwJ5J1M9I3FzqR45iWFqI35FTh5XJmK
         KA0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9xT0F5Ku08u5MJawaYendmni5yOyHkGTNU7qq77iB1W2pex0Ewpac4Jv9NhTKiTLzG5HAjrK0FuyAUltLg5HoP+W6ejG32w==
X-Gm-Message-State: AOJu0YydV8SCB+fwtPrf242DbewQgj+xLlazA8zNkaK+98eW/MCiWnoc
	wJLwZhtN/pfhCygzCNbgkFDJ0pHWnt+A35ajjqV+5bp3wOFWPY9C
X-Google-Smtp-Source: AGHT+IFXxhUxYipwgJJrCEgStAu978ygQ/UCr0NKsWL6NrFaYABxbvHBFlmjevbF+Fyhs6XSl8fOBg==
X-Received: by 2002:a05:6512:4859:b0:513:1cfb:a848 with SMTP id ep25-20020a056512485900b005131cfba848mr234233lfb.33.1709108947028;
        Wed, 28 Feb 2024 00:29:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d97:b0:412:a9c3:3ac1 with SMTP id
 p23-20020a05600c1d9700b00412a9c33ac1ls229824wms.2.-pod-prod-02-eu; Wed, 28
 Feb 2024 00:29:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnGg4g3HX019dSbJa2CXTB465Ibeqepl0bzFF8oc1gHMHjJL5+siAaE3hiFGmvHNbuR4HzzIPZQZocC02bcmf7QGNHIFvzRywCDQ==
X-Received: by 2002:a05:600c:3514:b0:412:268f:1fa4 with SMTP id h20-20020a05600c351400b00412268f1fa4mr9233914wmq.1.1709108945385;
        Wed, 28 Feb 2024 00:29:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709108945; cv=none;
        d=google.com; s=arc-20160816;
        b=qCybNoaddfLrCryKaOGt2LSIgmxq3sB5ut8p5mYF50x4s7jiaXpAxXjmU+5Rrrvs55
         atArjQe88F3BDJsqLdC5xH5FHd4QZ47VhKayHUYw5TRkz3kUF93y1A8cIYQIswq8o8D7
         Y3+ak2j0EOemB3/cVwPhBDjUmLwPhs964JFxekF2lSkyXFyL8ei5YbEySo1og+Zqaomz
         yA4yHzYHtWdpqBQnrLoFFvOyjxpSN4mMIT6nhkBPSySDpkTm5O6wroWqO+vx+4L/4GD+
         zdg/xB4AuoAbsryASpn+naaaL+kSofOmu3DRdlhySHOax2nVLQfT7GpSuJVWGtZSW+Z3
         p5lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=+HoIz2Qi98NBEh6aNkVpIyLsbtr/CQMlELkE74c1McU=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=uNNeHKRpyzij+oOuugOVCEpxMx7nkvL/cT5K9GICDkzGGFsmWyZL/WZu+O+TefMAzw
         y9tT3SZYHUnLsbnjOUDJgTEyMsjgm+XSG3AJYcrmgUJFDOkwFqUTENNvkXmDZofpFvjJ
         xCgG+u+++Ok0/+iBOu/fmF7/YvsCj8ob68Ehhe9FxUaQlCpwteDh9BNJOgZqRW4IcCGM
         RcezTpYuSZ7mi84jujmIaC1Nt8Q+4Z4h++0Vr4Ddxq+3KD7G7z14rq2JNvxGk4gst6WE
         uCyMO8gXl1FPcrta9+v7hscvoAhrKo1+nQlhEQcwm/cdBu4Bnl6rb6gK0cQ2jeCqpTuC
         LecQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id r13-20020a05600c35cd00b00412748b15fesi60072wmq.2.2024.02.28.00.29.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Feb 2024 00:29:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A012E1FD5F;
	Wed, 28 Feb 2024 08:29:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1430F13A58;
	Wed, 28 Feb 2024 08:29:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IqSSBNDu3mWDHQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 28 Feb 2024 08:29:04 +0000
Message-ID: <1287d17e-9f9e-49a4-8db7-cf3bbbb15d02@suse.cz>
Date: Wed, 28 Feb 2024 09:29:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
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
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-15-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.73 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-2.23)[96.38%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Spam-Score: -3.73
X-Rspamd-Queue-Id: A012E1FD5F
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NTHWxN9u;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> 
> +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> +{
> + __alloc_tag_sub(ref, bytes);
> +}
> +
> +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
> +{
> + __alloc_tag_sub(ref, bytes);
> +}
> +

Nit: just notice these are now the same and maybe you could just drop both
wrappers and rename __alloc_tag_sub to alloc_tag_sub?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1287d17e-9f9e-49a4-8db7-cf3bbbb15d02%40suse.cz.

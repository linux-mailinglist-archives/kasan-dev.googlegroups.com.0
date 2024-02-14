Return-Path: <kasan-dev+bncBCKMR55PYIGBBV6VWOXAMGQEERHHMCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CAA26854E6B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 17:31:20 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-511a142ed1bsf20331e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 08:31:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707928280; cv=pass;
        d=google.com; s=arc-20160816;
        b=EzaJyoVe4ar5Smq8O8oqpZB2x6tzoTMA01q1W9mv34xWgIZQgBU+++EupcrV8VnB6v
         edYpR5UpKD4V9U7SUflodr9kA7o2MUeLQTxLMngzZChSBYjnipE93W8lOf0ySwXxeQIA
         e8HcdjTgtsrOiJabBuG1P2L0Q0oAObaNt2J5/ERGA/G2/eyGfCQYFCZ7wiMc9RanvNE1
         rJpXh31IrIy29VzaXhenVjsDe5Mor9W4txaA7b10KKM4XZc48nvLLRWGiPkpaRj/m9Ap
         Cw2/rgjWOf8HyUt5ddX6tWIvCDMMJ8MKpJrMXEZDRHNP7tiCUDnKq5O0QNRP903aaZER
         mUWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=gF1KD6Hiqm2SZ+wjblyyqiHsWGuWA6I3bD5hCjfaMyI=;
        fh=lllESxqv/zOgggQOrA1SeRjdSPQByOLTmDT3DTecMLc=;
        b=E5RLM4imRnqoF9jowaeQza2dlRaKfBK/XMSVNzpEi+7u2bCN2V9ycZYrq4ha/4H1mD
         h0f//Wv3OMBrq4fLRcKE2Xy4/CaVJG38Hs4qCJjQk/RD96J41uWvoOX62AUcUdkaq0qy
         izR2nlAfLlDye2v4P1OwI+PT7sg2C+2GMRzlZ70QK5ipetYHDrg9Pn/3kC+1kAdTqCDz
         yb12gSLIbF2lqy4RklcI99cAgx8/Ohfg8tu6d/yZuVTdpfo0xrYxs4KLuRJHEcJW4NfT
         akbqLFbvikon+WqtBUX/WQ0gjiC4rouFihQkoBmkLEWeyUvymEkkWZVs26ytXGHMbmY8
         P77g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707928280; x=1708533080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=gF1KD6Hiqm2SZ+wjblyyqiHsWGuWA6I3bD5hCjfaMyI=;
        b=mbG9hNF1ypqTx+iFVlAFWGiP+hzWLNPN4Eag4rJGLKGIHSvQMk1irYwEFxcSFj7k98
         6RUeX7Ouou+yshSspihA05W8nEnpORcNixmIRHTU3EYrd8+1n+fbfW81e5TRUAxowEAt
         n6S3tLScuQ+xLuxDFc2SuDybxejLaBDi8nsUnqc6Ym6hJCUB+XbT14faWdl2N8RhLe0e
         O+bW3ffQS9qffzooev6g8dL2e51110CLb7/bRUPcRFjGqLfXoVmSjrhPo6AjhgziOtQa
         ZfFPuzxi3OC0l5EY44wysGVNluhFgSu5sOkZzBfMfn6cLZM/1qoxOma5s/8qxkjGFUCM
         6O1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707928280; x=1708533080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gF1KD6Hiqm2SZ+wjblyyqiHsWGuWA6I3bD5hCjfaMyI=;
        b=F2dz83zaU8MulU1kzPI+l6M7Wv2vqsyXl6OXIRcLK3HGsOpzz5p+kLt2WUnprMde7t
         XArLSH+ch2DVmBfuR7iajO/q9lh5RvdSzprA2OW3DKFWysa9BRREDDw4KSXS5s0SQjJs
         jcDvez2FKx4Za8qD2vhJOWyNj2VCMToMqjoVkczXZmwjbJKvE2wvWaOuwBINGI7i3dAX
         rHAsRPbg5co6qFcZcUEhEpiUxRacrvj8U7XAplNSqNsDHL6v+8VG/kiEzCxwzdC1wdYk
         sIDpR6O3hKjPkyj7z/kELhB6TLihGqCV/A6xMGHrwIUFeuYBr5XFCtehZ5tD+QCLbjJI
         8SiQ==
X-Forwarded-Encrypted: i=2; AJvYcCXw0i72wMtY2OZDOIrEoQ/N7NJM+BM8seRLPfbjzewLVZnDltiwhmUAjRdrLe3OUMxf4SJu+ATZ8OftRX11R/nrNAuTxTnuTQ==
X-Gm-Message-State: AOJu0Yxg3PyPJovq0cLuLzyZNKMgbvSNQY3/BZI9dpi/RvowcWDROO43
	PTbfTkCs95lxVxenrIwo6Jzq9DxiOoC2VZRrJcC91PIyfgEuKBma
X-Google-Smtp-Source: AGHT+IE3MhQdE3M5eR75NIbQxfU1hIxya9KwJie9W3qNEmVNQcEXloF0SbeFdqJWuLG8RlD9yHyxcA==
X-Received: by 2002:a05:6512:462:b0:511:9165:9e13 with SMTP id x2-20020a056512046200b0051191659e13mr137167lfd.5.1707928279775;
        Wed, 14 Feb 2024 08:31:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c89:b0:511:3755:63d with SMTP id
 h9-20020a0565123c8900b005113755063dls150287lfv.1.-pod-prod-01-eu; Wed, 14 Feb
 2024 08:31:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXlANs2uPb1NDfV8+tYBf/08zfmxVLlgs9ZufmrejBqyLU2EQDM0DluDB/XbClYHkhEqDFXNInfce3KoLngfmNbPbwqwrZW5PoPVA==
X-Received: by 2002:ac2:5dfb:0:b0:511:986e:671e with SMTP id z27-20020ac25dfb000000b00511986e671emr2612450lfq.10.1707928277336;
        Wed, 14 Feb 2024 08:31:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707928277; cv=none;
        d=google.com; s=arc-20160816;
        b=b+pr6LQtiEDVwFDgu6le84GQB38y9JWzk0gQgLDcClD4yGdijLwMeB3yU22TyqT5IK
         KuJot+QoYcTQfOdqJaLPgNuSLbMlW3gffAYQ70ecv5qwGSqpAOZh7zcj2fJe70Ua/K1A
         EE6ao9jNWt+3UrOA0lCcw2zqqsSyAOzD+5x+ezBVJZf4u/44ztJPjPlKA+6n/yorXWvf
         ie9O6MQ6as9IZx63/5tH3JCUcK/dzgKImWWvp5tMFSkIeRf3GKkVwC+UT7triaXETW9d
         rm8u6st8cghFQ0Gg+dGGMdxLeI3+uliXfgSrklhQqTuDX7xigv1uTeNm7EHo7BTTyyTZ
         IS4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=tQsQtF68aCcyiGlksJtNjaSfy5IyP2T46OHdmxlmiHQ=;
        fh=OgQ+cQA0nzo0tfaMW9ZOGjel4aq1crPQ1SYiuCamWZw=;
        b=LOROUS55U+uZxE4Bzr8ngj2tI5BqHpaqJtx6rjonuJ3rteGyHjGRTvJOzOJECbfpxB
         llaboLoxDo8U2svP7ycir9lx5yUhghq+sy/Btn8M0Y05zWJYCq//Yq0altpTU7wfUHfe
         oQH5qlK+p1buU384zS3leKD/0uS+CdvmG5IDJr06L3Xxk2QwlsMeXBoY09u7Y9kRmxAD
         4D5O+tq00QaGkBHB28PW+/QSjwivbCdOyQbaWq3s3C0tjViEnWOskFLK4xTIK+YrJ6qg
         PLPBQWi+lea4Xbb+i3NjSuh1qfNGLzIa0wwEhwy6WN/BlLc6gCu0NhZxnJ+18Ngzzxp4
         5rkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Forwarded-Encrypted: i=1; AJvYcCUy2gAIzCrgQhof3ymfSBrbqOlZyGEqe79tLYeRRVR10GUikWkjRLbAbPJthBEYsKZqkVSZ7JFTO+boNeTrr/vtu9NEZdcMNYOJVQ==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id dw18-20020a0565122c9200b00511ac70130csi41582lfb.2.2024.02.14.08.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 08:31:17 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4720C1FD2F;
	Wed, 14 Feb 2024 16:31:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1DE9C13A72;
	Wed, 14 Feb 2024 16:31:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id pcetBtTqzGW1OAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Wed, 14 Feb 2024 16:31:16 +0000
Date: Wed, 14 Feb 2024 17:31:15 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Johannes Weiner <hannes@cmpxchg.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <Zczq02jdZa9L0VKj@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240214062020.GA989328@cmpxchg.org>
 <ZczSSZOWMlqfvDg8@tiehlicka>
 <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
 <ZczkFH1dxUmx6TM3@tiehlicka>
 <udgv2gndh4leah734rfp7ydfy5dv65kbqutse6siaewizoooyw@pdd3tcji5yld>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <udgv2gndh4leah734rfp7ydfy5dv65kbqutse6siaewizoooyw@pdd3tcji5yld>
X-Spamd-Result: default: False [-0.39 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 BAYES_HAM(-2.08)[95.54%];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DKIM_TRACE(0.00)[suse.com:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 MX_GOOD(-0.01)[];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[cmpxchg.org,google.com,linux-foundation.org,suse.cz,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: -0.39
X-Rspamd-Queue-Id: 4720C1FD2F
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Bar: /
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="Y87E/4xC";       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.131 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 14-02-24 11:17:20, Kent Overstreet wrote:
[...]
> You gotta stop with this this derailing garbage.

It is always pleasure talking to you Kent, but let me give you advice
(free of charge of course). Let Suren talk, chances for civilized
and productive discussion are much higher!

I do not have much more to add to the discussion. My point stays, find a
support of the MM community if you want to proceed with this work.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zczq02jdZa9L0VKj%40tiehlicka.

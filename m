Return-Path: <kasan-dev+bncBCKMR55PYIGBB456VWXAMGQE4U2IILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B685853070
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 13:24:20 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-561623cf639sf1583911a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 04:24:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707827060; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYByeW9140oE2hjIDJpEjXDTbCMWtpFLQBLE6vhC8l1ryQ1pcswKnOc89noEvIwhNi
         6uxGX6P+t3Ro0Eemg1uJtzsLnwODvw7XHzZRJEBqRrgpdQFrS77pQDdg12rABS6/teUa
         q/wyOrgbvEyyT0wyhWDLAVTKCcOfJ44H0Lg1moRDHJX4YF2iyt4CAUsaRPHY+cquHvVY
         WixT7YXwRLueuwaoAqpAt0f9FN5FnwxKF3f4LIyLalQNw/5Qcp9abw2mkSPdoqTGXIJX
         hYDjzstM2LmobBsaWvVq4CKJkDiibCC1lafFdHexv7GVVmnjaow0yyVQpCxD4SkPmBVU
         Wlcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UoVFzJQ0G7nTDO7i5MB0wo5J8cgrvKrRj86m7SUW6BQ=;
        fh=gfi4bLFX8Vocnc7iPsliGTWC/O1VijuZjezcyPGzwH8=;
        b=zVMS3hzj4ZGRI4lrG7LO8yE8PDqmdKz0JC7hJiWhMoj3BdEOuy1orG4LJsCtskbyXg
         M+yv7s329etlr+/vAXbmQYFqR6LT4D38xkN1ZlpmPlBlWYwcAMras+lJpXoqlAmvEX8a
         TrwdEP65PTWLj6m2IGeV5pzwqN3GmL+Q0rOVPO7ZZfYpvHVnkcdwCnoW8mlCYZYcssY8
         OWyuYCgA7ZFi0gZcPZL9clDi3WtjMAhKqHdRCemIxarCHXu2E3m/4n58l1Ne7R1k0PhX
         c6G/wwSgK3/iAT+a7fzyOCZzUFqdrqS+FX6qzCvZHRI2x7u+azTGEgEcdl+Xq1aaK1tU
         N7vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707827060; x=1708431860; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UoVFzJQ0G7nTDO7i5MB0wo5J8cgrvKrRj86m7SUW6BQ=;
        b=PliSLx+DzSv23N2IlemLTvH/F5p2ZfEqYPISeOMK7+HZ0+HmuvXKs8QoIMshetMzYY
         DF3LcH4+XmkC4ClCyumg2ChZt+NTADNiFlq1euoyTgXDFwpIm9pODg7NkhOlbKf0tP71
         QDkibT1ZyUusSaIW2239ZMHgpDwKo2piHmddTgDb2Twdh3/pzWlwBl8Jk8p3dr5N8wYP
         2yyd5L0YgEU2rdXzhVI7sQYS/4DCblFjbKMofG9hVIEoJAd4UPHqJoxR/JlRyamLLUwm
         5IQx9ikJRbRxo0I+vnDAD79yldYyPlU2WULDmKegJqaSevxPObdET7QIrh/W1tzn+5nk
         pAfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707827060; x=1708431860;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UoVFzJQ0G7nTDO7i5MB0wo5J8cgrvKrRj86m7SUW6BQ=;
        b=hcnMGMAb2bhI7FhNB0KPIoqLCjNhU1yeNEXLP3QLIy51C2Jbk6tFbUS9K1kYmPg4/A
         0QA3y3Jwgm+RviRE22Lh4MbpEUC9fb2/B9JcOR6YBKw7EqNPObrIwgDIvqUKQS740NG5
         GHcwkSdxLAy5ggJo/7ytnvCOCqq44R5ejJOC0r0/GAs5Y49kW3lB4S/OddTstYrZXWrK
         Fju0zpWFMUGcXXeFrnCHM3hpiOryLgea4brxaWZUYvdqCxBr0W5cdYcWa2fDz6Jlac86
         QN71TR0kL9BM5iVJjlpmcaNjio9KF5JKTbOtSzyMjLoAq/RhTRIpzitCLKSW4gfgTYyp
         ZvSg==
X-Gm-Message-State: AOJu0YygfG8nQFXcUW5bKIW8x4qpQz4sDzuQtGjIfJFcIPmhvInsfcOv
	DVUOIxEtYljhIFTtbVBB4Bj9kfErgtOXu57t8Xo/SjmKltOvr2ix
X-Google-Smtp-Source: AGHT+IFPlfNRtSCOpydVa1r9uZ0QYKoLWMQ52iSIrZ8HDkeqieYhbYitJkJbV6nj3oCl89jakzcgmg==
X-Received: by 2002:aa7:cf05:0:b0:55f:1728:3b33 with SMTP id a5-20020aa7cf05000000b0055f17283b33mr5553892edy.40.1707827059245;
        Tue, 13 Feb 2024 04:24:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:321b:b0:562:7c0:2157 with SMTP id
 g27-20020a056402321b00b0056207c02157ls153357eda.2.-pod-prod-07-eu; Tue, 13
 Feb 2024 04:24:17 -0800 (PST)
X-Received: by 2002:a17:906:35c7:b0:a3d:765:7be2 with SMTP id p7-20020a17090635c700b00a3d07657be2mr1005936ejb.73.1707827057300;
        Tue, 13 Feb 2024 04:24:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707827057; cv=none;
        d=google.com; s=arc-20160816;
        b=OpXilvcuunm1YD3slYdmAUGUlPDjuMu5JEXI/eDQU6FXIlS6cS1+q1itbb/p9Smjir
         7bFJSEJ5Fe3JUqNUXaasCYYP5oXYIaTh1xAw3ENKHdRl9UbpHQ/npKZw8swQE8zzUrfC
         rIPvGB9mrGmO859E+4WUInf51Yivp4lMUxm/ZvX1dj50Ww26C5b5vBwYAVzc/384hY8N
         cVTqv33fjPtbu+NosJ6lf8OSqsg6J5upyCSD4uWdauEC1aSvYZQzvlmlmgiFw7mBLwXI
         j7czPh2WB2Hbdw8YWzHeY3Nyj2b2/uCOPHtDF/TjkGLmfctfIujmy5BHEy9mEufgF4S1
         Ln2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=zXbOiQIN7neMTyajtp5U/4Xc00nM1Z7564QKlnGLw3E=;
        fh=gfi4bLFX8Vocnc7iPsliGTWC/O1VijuZjezcyPGzwH8=;
        b=eFebqpY8s6/9ECo0TRKU5KKaDLTVBDOI3hZMOlOOfIZj40EoxDnYAMLbb20ERPoK6M
         fQ0+yKHMfsWzY8PJgTB3uUFAxMiJmMBFuiz7vW/WIYPg4oLSzGkXi8M2MykLdm/LM1FF
         WCSta2nei5NtNgrh6lztPXQvcB8uNZofixOaAau3b/IL+mNWNAiHvfPmcQ2LRHPlVXUW
         VV/i46bhHpvLCOvdE68OBM5MGnPenbo13045UOeJ63E/CTv2MhTAWW3nwPD9KWKHVqLu
         FMogvspbQEKAceZrUfI47cXTV1Dgi2Cy3A3iUYl4OiJtq8idLQSxt6vYvYlOfMbsgusx
         pfzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Forwarded-Encrypted: i=1; AJvYcCVYFbqH316MqthyflAWyFk9X0cqmn32r2hPsk0XRNIIPfahQouecBoT47u7/xvna3NjyyEPhlpAtGmZT6RCWIDeB2qq2erFE7lTAQ==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id gl5-20020a170906e0c500b00a353a6e9fe4si215346ejb.1.2024.02.13.04.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 04:24:17 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B00FC1FCA1;
	Tue, 13 Feb 2024 12:24:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8BA931370C;
	Tue, 13 Feb 2024 12:24:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 4rhuIXBfy2WUCAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Tue, 13 Feb 2024 12:24:16 +0000
Date: Tue, 13 Feb 2024 13:24:11 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
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
Message-ID: <Zctfa2DvmlTYSfe8@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
X-Spamd-Result: default: False [-1.83 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.com:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.02)[54.94%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 DWL_DNSWL_MED(-2.00)[suse.com:dkim];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.cz,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:104:10:150:64:97:from]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: B00FC1FCA1
X-Spam-Level: 
X-Spam-Score: -1.83
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="oPNMu0/3";       spf=pass
 (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
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

On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
[...]
> We're aiming to get this in the next merge window, for 6.9. The feedback
> we've gotten has been that even out of tree this patchset has already
> been useful, and there's a significant amount of other work gated on the
> code tagging functionality included in this patchset [2].

I suspect it will not come as a surprise that I really dislike the
implementation proposed here. I will not repeat my arguments, I have
done so on several occasions already. 

Anyway, I didn't go as far as to nak it even though I _strongly_ believe
this debugging feature will add a maintenance overhead for a very long
time. I can live with all the downsides of the proposed implementation
_as long as_ there is a wider agreement from the MM community as this is
where the maintenance cost will be payed. So far I have not seen (m)any
acks by MM developers so aiming into the next merge window is more than
little rushed. 

>  81 files changed, 2126 insertions(+), 695 deletions(-)
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zctfa2DvmlTYSfe8%40tiehlicka.

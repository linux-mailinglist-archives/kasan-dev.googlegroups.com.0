Return-Path: <kasan-dev+bncBCKMR55PYIGBBTNEWOXAMGQE3ZWFGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B2A4854BCB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 15:46:39 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d117db8fe6sf5683461fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 06:46:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707921998; cv=pass;
        d=google.com; s=arc-20160816;
        b=zzV1YPVX/iJy3Hler8CnK1/Gv84flzldKNnlSnihSq0mngljC45Ws9FrpICbgXmp95
         uWhjv5OsGqR/YghvwSnzF/cB6U/aHjhkddOHQhXZ/mRm8kgpRjZxazz4YSLbHsIDcbaS
         4UWt6uu25iCNSwG2SB8DChkII7v1ULirlaHv7YjIVu13XKKAzgTfjP3GNch/NKobJ1yj
         0H8KhMmB4vZiVOgPPmM4fQnAeWmZzBTBb/a4ERgJXx0OoU77za/W/hELs9rnuv9UwaNA
         US+17wQABppG3G2sgcIQTYhe880LlnqhcQRJEOEf5X1R47N9/HvteE0tZz32ZrfcCrR+
         fRhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yRM262nSU3QPUueEDEeg6mYL7epKK1nQbUFRI2Jh0WI=;
        fh=gwlGgX6MRG3Lx1br8fiZ/O6u2FF4tbpWvKrcaiIpgBI=;
        b=HvuD2l+tulspOQzc1pVgyrqzBHfKdgEXutHF/qk5F+97oDsEUsWMuXw8MAzGTfXJsu
         LNzVDKMRH/sTE6kF76J3dt6qubMRlW8CNHJoLefJDSO+qzw46uhlgE7z9staAjQqLk2a
         DSUyVNmPj8yyJkaVta6dPvpH8DQgJK+rULJNo0OIRsHa3kr33L6jimc6d96iMovq++cP
         irecEYplgb1U9jlfJb9FmrokcBkiA6S0PzToQHVE5lLZvY28wf72d/KuOmUgSVJAv79a
         5tM67ME2KCYLMdvruVib4/TbXKZYAM9sdJYmAPMUhO51czOXGqW2ay0r6/v9xBJipRaj
         T0Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707921998; x=1708526798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yRM262nSU3QPUueEDEeg6mYL7epKK1nQbUFRI2Jh0WI=;
        b=Zuj6TzRnnVMWZRHXqfkVtMhNiXBX6cisXV9wknv9ZZB0AHcuotnKlj8Hc/GIQ9uQJL
         ACsFmQGTDebLv5DQ9NzEFQMXW/qrqDXYFDparwn1Eym//oh3mRZJ+t53JGMsPOGeIv/o
         90n/GFcIeyJ3TTwZs83POxJ/XPONYsvafTZ3uhwCIKNjEGDce68Q3+7XN7S6n5eLHdXX
         eyL6qHDZqYqS3+WV48yySb0K1LhE2d8S11H8XKUUbeQ/IXO4S3yJZY6f/4+MT/xvJ+UZ
         sij5eTiHQcUoSbOHGkqB7AFE2YAvcgMrRNNRiYydQ8c3Ota8LYstbmdpIPaAkmqMB/9h
         OAwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707921998; x=1708526798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yRM262nSU3QPUueEDEeg6mYL7epKK1nQbUFRI2Jh0WI=;
        b=Vq3U4A57hcHRxITqnPiM5wQJgyemBPI7DTxd4gdVxJO17B6LUGlF1t84Hc9JTgULaL
         yR3uESjPVkD/e7a0zjOE4pSbw6Y/L0sGGcla+AJ2iTnsvCz5M0ZSlFU0KaPLWqDui9c1
         6X17QtHY1ZhhLN7c3Ui+T5iFfF6YtOsSS1HIsM9AMSOa0qbo+bATYSSKRigYXXQ/fZ0V
         hJqKsl2GSFweF4ymxHCk9lWiXFY4Qw2Rrpbfc17L7tH+cOCokTWmxWjEl+H2wZbVlIqZ
         N4RmSAitB5gUL99H6khWRKsEJAflAZT5lBvuz7uToZvfQPckc+exaC9DovHAy5s18Z6S
         Ym7g==
X-Forwarded-Encrypted: i=2; AJvYcCUEA/fM+R+GgaWP9DLvwyflXpAIitKP3nPVu2pcTDBp4h22/GX5BBK5nG8jGCyW6n1bsQJ8JD7VYQvNkDsxc0B9Q5o1PNPx2g==
X-Gm-Message-State: AOJu0Yy96z7H0n/aHwALm+TAulIAQGcTR1BPXGY3akj/lCERCOqtqGLm
	v3JKiA8LgISbcH0vU/5g3TE1wjHRNwjx7J8/F/hGd6EUsACl9HxU
X-Google-Smtp-Source: AGHT+IFQvsVlPoeyooh3sFUXpiGYRwvtmUI1dYyEJsZv0mprWWfFtgTFH9Hso3PLeZvd5zgFGh8Abg==
X-Received: by 2002:a05:651c:21b:b0:2d0:fa63:baad with SMTP id y27-20020a05651c021b00b002d0fa63baadmr2317637ljn.21.1707921997707;
        Wed, 14 Feb 2024 06:46:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10a3:b0:2d0:d976:e44a with SMTP id
 k3-20020a05651c10a300b002d0d976e44als836819ljn.2.-pod-prod-02-eu; Wed, 14 Feb
 2024 06:46:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWgqIiRRKc8H+Byo+aTsHBTICJjOQDBt23IBzKCXq38ZEiB24aASt19pek7wSMbPXiLJkMJcUryfRFTuVB2IR6VcpVUNia8lrCYg==
X-Received: by 2002:a2e:bc1c:0:b0:2d0:ec8b:2a2 with SMTP id b28-20020a2ebc1c000000b002d0ec8b02a2mr2675749ljf.18.1707921995505;
        Wed, 14 Feb 2024 06:46:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707921995; cv=none;
        d=google.com; s=arc-20160816;
        b=lBPx6yoTUM4Uuq1x9ZjVfvGD2Fd3hIJ0hrb4g5GvkNbgLCTOsg3SokFEDuuLx2yk3D
         rqDEXW1dRd3PEnpfCKUynAeSRJfEDt/m0ZS52EYccYs8A4z2UF3fmlB5pSESF53ES/U+
         hq0rxUsx2FvePbc2MMODW1jLR/JGi3YL0q7N/xW8LAuWBzibYnJ5PKn6o9DbN9nkuALY
         8QKbkYkw3UtZQ1mvtBuCidm7AXldJaHRwg1l2+iDl9kGQJdJ38msv1q+liw/lW2BIpf6
         MD0MLS41f0tGhWLNOFbwbExmJCmVxfTykH5VhLwYOEXv1kev052KitgZNWT37IkyTAwP
         HAIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=L7XYt0NyV1LLmmYXD5SRXg7RDztZSN4xXat2vk9BckU=;
        fh=9BWDj0I2D5ISGQy1JmWjP4ovdyRBeCLBMb0vctcsG3k=;
        b=mPCWyxVX9vE5Aagdr6TAfRrcLt1U6I7bkXxVaZCpCtvHgVBkmxgFvwc4yiycVkB6et
         DlJbJYSnuVEvckn1hZbzWeCdVzLE/CqkQT8XHpcyxysqy8iQ5TD0tE3RS/svRYtUBdRr
         Wz9s2UKLS5gznVnj3hXBv/XBVRlS1YmZQJsJPXyHdaLzYoM0GeDHNSedipbQ1iGeWPdd
         dqOWollhynEHuu+fNqCQYdVOkAFGMmfFS8IqPsnl/0Zi50aFfycOpP8Eewd+5CKRYXqr
         siEYMOJrlUHeD6H2ZqrM/wZIX4VdE7Ipi422DhVm27BoEO2Qux0g4/VgKWoKC1lNsmER
         s00A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Forwarded-Encrypted: i=1; AJvYcCWmxjSt7n5EVqe80SYcDt/2HZBehawH5putbqAhiW2OZVt+cAsYyNmZ+n3lOibzz6kCuLkVhnlxX7osXMxWbYs4HW61vIZ62JT4kQ==
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id p11-20020a2e740b000000b002d110eb34absi96010ljc.5.2024.02.14.06.46.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 06:46:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9E9BF220C8;
	Wed, 14 Feb 2024 14:46:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6C19613A72;
	Wed, 14 Feb 2024 14:46:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Hbm4GUrSzGUzGAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Wed, 14 Feb 2024 14:46:34 +0000
Date: Wed, 14 Feb 2024 15:46:33 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Johannes Weiner <hannes@cmpxchg.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	kent.overstreet@linux.dev, vbabka@suse.cz, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
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
Message-ID: <ZczSSZOWMlqfvDg8@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240214062020.GA989328@cmpxchg.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240214062020.GA989328@cmpxchg.org>
X-Spam-Level: 
X-Spam-Score: 0.70
X-Spamd-Result: default: False [0.70 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-0.00)[13.93%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLibijwhxa4crtso4io181jfzy)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[google.com,linux-foundation.org,linux.dev,suse.cz,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="G/fg/fXE";       spf=pass
 (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1
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

On Wed 14-02-24 01:20:20, Johannes Weiner wrote:
[...]
> I agree we should discuss how the annotations are implemented on a
> technical basis, but my take is that we need something like this.

I do not think there is any disagreement on usefulness of a better
memory allocation tracking. At least for me the primary problem is the
implementation. At LFSMM last year we have heard that existing tracing
infrastructure hasn't really been explored much. Cover letter doesn't
really talk much about those alternatives so it is really hard to
evaluate whether the proposed solution is indeed our best way to
approach this.

> In a codebase of our size, I don't think the allocator should be
> handing out memory without some basic implied tracking of where it's
> going. It's a liability for production environments, and it can hide
> bad memory management decisions in drivers and other subsystems for a
> very long time.

Fully agreed! It is quite common to see oom reports with a large portion
of memory unaccounted and this really presents additional cost on the
debugging side.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZczSSZOWMlqfvDg8%40tiehlicka.

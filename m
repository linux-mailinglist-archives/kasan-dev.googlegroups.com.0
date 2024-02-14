Return-Path: <kasan-dev+bncBCKMR55PYIGBBWX5WKXAMGQELU4BUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C1F0C854A66
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:23:46 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d0aafebedbsf45729361fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 05:23:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707917019; cv=pass;
        d=google.com; s=arc-20160816;
        b=MlgL8uACWuuwJMU7ij7lcty/tALGVkY7q+CdZRGPi0SbRN7Cay1b/kCdemqoD9l+n+
         AzzXmRPsfC3bDS8mVMp8i+N2szb2DmouFv37EMzNfiFJ4Ry/JVk+ZV7E40RujujG+pli
         Jyr0HAULYElTyyZYHzO2xQfQhvLhGJiO8Gyp7vjcVoUy3oInJu1dookFfWvhR+SumvGz
         vmMqfNn0q8YRM4sFckntTFPor8UEcTrRIvnW5aQti8RT6V67tHs4Hk3hPjnJmYvBl9RI
         QAWkUm8TkhFhc4mIKOIy0fGgUEK/J/GF2upYHcLAUzz5fLdo6x5Nwdsa9DQxd1zC7FWf
         2+Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WTDVGIskGoEVOkYsgkpWNGx94kkpt9LfKJCLOEymT84=;
        fh=sdXDgUOIWQ6ljnrWsSrgoelmfYed1YVLL905KsUYjzM=;
        b=xCGrAiExTDzSgS86RBau5nZM5tSJT6ZbJ9icWvXgliITwBYIK4zysOSBy6Z1QVFZF8
         IDh6vqhTVSXc5M1MSKft7XiIflDA0DEycRkTTb+qXLYAG7agKS13g8nz32cujWMUrH74
         VOPGjYEyi7Ig7weNt4JE0nDUOUq0OKfPBfT1t+eOOxAAIuoJr0KIpNmIOH9v6IocB8s+
         TXtW24jg7KhOvCVhY4Qla4A/0BmBDw+YCdpOytmMLlRb1xp1J5O1KpV2uGyOXHrU3Y8G
         sPBQJxfvuc6bQFamVBK/oD9DBzxiE4+isQ72elN/fcge/ub9udY57d8CzgCWUbazvWf1
         bx5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=QIjP+FW0;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=OBUSsdFQ;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707917019; x=1708521819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=WTDVGIskGoEVOkYsgkpWNGx94kkpt9LfKJCLOEymT84=;
        b=XSFRcOda9vwiOhU0cKlPfG0RTZvhKy3Wkq+/08zNxjAWpvoJYwxmh1wDfuzljYT9Qh
         VzVYnnXOP9CpxnPIqouBArhwO+KuKN28fu4t2NAbcRzEr+qIZ4POgUlkzu8tvkriXl09
         0SwYPdG60f5BgVpTrNZzJtMFib14KjKVKAjR2v66eZ4LsJPfUmm6fm5bPClcJSJTSGVt
         ZzM4ohLYQPoPtb7kab6+Z0eC1lCVotODUfGi536vUwGaCje7giRTUEW/QjcIrNsxDIjO
         rVSzyaHNdKGjeq6JqINQlp1s7CPZjS60MwV1R2EgSQVNetqTxfC2dnDhSMjZJ/BmV92W
         jd4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707917019; x=1708521819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WTDVGIskGoEVOkYsgkpWNGx94kkpt9LfKJCLOEymT84=;
        b=iIo0nxWyZi5RShv8Sm5rNd2HbMX5goq9iHg3eUBz+uVUNWi9hq8NDGxX7Yr/UpiVQG
         v3jDoKDoWgVYHKw6rMNc/d9YcqfBnndcbnRlOIQOU+599fRpLKBSkyu6QQO6uZEBHFGU
         TA9e880XmDKdAgozl5DldEjsnsg1S6MkMBaPp4SR9idbreSRG59n/B8GECQRM/cocVak
         /CwiydNOmdKk3vlROJuKj+Kd2wsDdQSABypgtS8Q8o94SgJ/5WLoaIVi459uzsb9/JDa
         jIwvjQiJeq7UnMimVWIFYYxJW5lhDk0fZm8xSVu/eiIjk2YNu9wbfm8DdlSEZjbpkwoB
         hpUQ==
X-Forwarded-Encrypted: i=2; AJvYcCVann7i2b1c/8Umchh5tuzJ3yhF7CrWnoxyG8X+n7yNC0eJuUh4gEJwEFnpviUBSAXOuTNerOE+H+GHUKFFB27bvefXzC4vng==
X-Gm-Message-State: AOJu0YyYAUxc6bPDKtv0/klt9AFXzIyE1KRuziy/vRavoSELIewH06gi
	8s/EodGV2rG1pnL2mOnHFqXl/I7ZVQS59G+OOCB5mrtJl0S1wFxg
X-Google-Smtp-Source: AGHT+IH/Ou3n3G2pwXnVf33S2AmRi8fxWjDcyXKDmdhoOPmXinhAlq3nrVZULpN9f39DO4ngIz2WPg==
X-Received: by 2002:a2e:9ad9:0:b0:2d1:1e0d:b1c8 with SMTP id p25-20020a2e9ad9000000b002d11e0db1c8mr838459ljj.24.1707917018391;
        Wed, 14 Feb 2024 05:23:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a497:0:b0:2d0:a7cd:36ff with SMTP id h23-20020a2ea497000000b002d0a7cd36ffls1507846lji.2.-pod-prod-06-eu;
 Wed, 14 Feb 2024 05:23:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVnymFsPhWGCJ2jaNBmVw+Vcst5sbaZEKE0J4n1AheCu20iqYMG3jKhOoIC1a+kwGHc1QWBBx7wODQ4aX8j9pquS3yBYbST7381lQ==
X-Received: by 2002:ac2:529b:0:b0:511:a0ff:a225 with SMTP id q27-20020ac2529b000000b00511a0ffa225mr1688209lfm.9.1707917015990;
        Wed, 14 Feb 2024 05:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707917015; cv=none;
        d=google.com; s=arc-20160816;
        b=iIHV7rQEDNhoEmSCu7efWvKlDskapyK4wPtBu/evAoxz0jFGQG6J789hhBMsJo38z8
         8Q3BptqHZ1fw+bmEAmhmSwhDJDoKQJRxLr+/TyxvFVFpIUwiDCF/vZi6azo23Y9i8qHA
         fIWeF3TqoCDXHLU463kStYdXcPdoUaXXDce5bB3nlYxxT6J86z8ZuuLVYCPh/iohKLJQ
         ZH552Xi/rMFLwWCSFtHtFEqJ6gXuw6Yqxqzh3nnW5zB1S4ye3FosqKULfzdJrBNwcpvG
         GN/i/QMGzAASUSyxV2Cj2E21yz7bC5OpsP6duBx1xKNxxi9Mjdkt4ghAHFFJAgK7IrFS
         4lTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=qRJr10qi9dh6XG3cKWhF0aOO8OAegvJYwUfC6v4k4/c=;
        fh=Uc18vUQCYfDOkCSzloONTRh/fFTOntvBC/Tmj9hWBXk=;
        b=BHYXtivDZVfiqQ0msqeYXXcPo0ZI8OSrOvAUJbN+fnfLf4x9kvET/V4Z+b575PJ2op
         unSqrYPTjUTwrnXwOe2aKnWMDU19X2RYOA88w9lcAIbBt4aoZ2PEIluJj+5Kt9mfkO19
         FZwbaDdpM8qD/UmmylRlhxOkyzfBB4GNE0YZ61Z784dZKOCnQ95xoo6nLxDVoVTDzWTQ
         togbcyfppfrFlBHgykVbTKx6K609mFKI/hBQ9be24Oz0jkeTsHpnoo/T1ueLGg8JYSM1
         hZSEnk123lL0HLZM8AQGgvubZ3eNapvIHmxMps3B8aKAd3LdckLdqPeiS2jp7avxYdCq
         u8AA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=QIjP+FW0;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=OBUSsdFQ;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Forwarded-Encrypted: i=1; AJvYcCXJL4AV2+pbUKYTOn6Z4SCGlDwkrCE3cj3/8bp+Q4x2NMlpGjfp9tzid8kZraizJYKnOUd78DEC9TpnXhsul+JM4hiJNR7MUPmltw==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id h33-20020a0565123ca100b0050e69030a77si615359lfv.6.2024.02.14.05.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 05:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D10D31F803;
	Wed, 14 Feb 2024 13:23:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9EEC513A6D;
	Wed, 14 Feb 2024 13:23:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 13hAJta+zGWQeAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Wed, 14 Feb 2024 13:23:34 +0000
Date: Wed, 14 Feb 2024 14:23:34 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	David Hildenbrand <david@redhat.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
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
Message-ID: <Zcy-1nScrEI_q0w7@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
X-Spamd-Result: default: False [-1.31 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 BAYES_HAM(-3.00)[100.00%];
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
	 FREEMAIL_CC(0.00)[linux.dev,redhat.com,linux-foundation.org,suse.cz,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: D10D31F803
X-Spam-Level: 
X-Spam-Score: -1.31
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=QIjP+FW0;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=OBUSsdFQ;       spf=pass
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

On Tue 13-02-24 14:59:11, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
[...]
> > > If you think you can easily achieve what Michal requested without all=
 that,
> > > good.
> >
> > He requested something?
>=20
> Yes, a cleaner instrumentation.

Nope, not really. You have indicated you want to target this version for th=
e
_next_ merge window without any acks, really. If you want to go
forward with this then you should gain a support from the MM community
at least. Why? Because the whole macro layering is adding maintenance
cost for MM people.

I have expressed why I absolutely hate the additional macro layer. We
have been through similar layers of macros in other areas (not to
mention page allocator interface itself) and it has _always_ turned out
a bad idea long term. I do not see why this case should be any
different.

The whole kernel is moving to a dynamic tracing realm and now we
are going to build a statically macro based tracing infrastructure which
will need tweaking anytime real memory consumers are one layer up the
existing macro infrastructure (do not forget quite a lot of allocations
are in library functions) and/or we need to modify the allocator API
in some way. Call me unimpressed!

Now, I fully recognize that the solution doesn't really have to be
perfect in order to be useful. Hence I never NAKed it even though I really
_dislike_ the approach. I have expected you will grow the community
support over time if this is indeed the only feasible approach but that
is not reflected in the series posted here. If you find a support I will
not stand in the way.

> Unfortunately the cleanest one is not
> possible until the compiler feature is developed and deployed. And it
> still would require changes to the headers, so don't think it's worth
> delaying the feature for years.

I am pretty sure you have invested a non-trivial time into evaluating
other ways, yet your cover letter is rather modest about any details:
:  - looked at alternate hooking methods.
:    There were suggestions on alternate methods (compiler attribute,
:    trampolines), but they wouldn't have made the patchset any cleaner
:    (we still need to have different function versions for accounting vs. =
no
:    accounting to control at which point in a call chain the accounting
:    happens), and they would have added a dependency on toolchain
:    support.

First immediate question would be: What about page_owner? I do remember
the runtime overhead being discussed but I do not really remember any
actual numbers outside of artificial workloads. Has this been
investigated? Is our stack unwinder the problem? Etc.

Also what are the biggest obstacles to efficiently track allocations via
our tracing infrastructure? Has this been investigated? What were conclusio=
ns?
--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zcy-1nScrEI_q0w7%40tiehlicka.

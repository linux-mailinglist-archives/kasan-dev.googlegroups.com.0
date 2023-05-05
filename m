Return-Path: <kasan-dev+bncBCKMR55PYIGBB5MB2ORAMGQENNHYKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E21B6F7F39
	for <lists+kasan-dev@lfdr.de>; Fri,  5 May 2023 10:40:22 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-30641258c9esf515490f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 May 2023 01:40:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683276022; cv=pass;
        d=google.com; s=arc-20160816;
        b=j8/0D7QVenYsogRNAsiWm1CE+JFYTkGtqx3VgddyfzR/Xm4Cj82ymHgLCaqq1Lqxj4
         kv7dVXWFKism3lIxgQpgEJzwVQCi/USSvt6YPwhpKkYdBSnbwTTYwJea1eOFo2eW1mz4
         1giyJXcV3dC1WwlAErnCnz7Otxz9CEdDDybzs64P+XqM7nHqUxi+GTx7rSWNPgDMhlxJ
         XDl26UQV9VJIZQ3Z0iBCjvyC2jSrnx9q/wJ9jx/i+GUNu85wtDSolo9sY/alpdSuE0gR
         akQpRhmmU4V6yeMJs71A/0gYVi3YR1DGiixN4Y67N729GdWPuYbPB+1XH/VhBnb1syx8
         k2Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rRVvclYfy/Wz5RpWif4x61UdymfDpK1qx7qf3jM+Di0=;
        b=VDdmBPAPPHk61b1ECanKyGLG+GrS5FL2vhTIdIcx4mw+Xdivg2Tw0BLvoEqjNkX31Z
         hzBvDWXWyX//aH9RLyz4jolPBLsCIfXNeF7AUinTkVrWTHwaHmtMkk+CHjlZC1U/xV+G
         vLlDt3PwtDzNsivFhQ8DbGiQuHsu+QFLkiTR/zKHDJ5or6kcE3GsBodbyRgOS3tt+jof
         zl9fpYrJlS1fiM6h5PQ0ZeFBNpjsVL9Q0AnggNoRbm4WwAnhIHM0EuNXk6dEX4y9QArQ
         BTp8CpUcWnp/V5VZdIAG19kbYfqlydp/Th0G/88PWBC3erEJregsRNSwzbKJRYHKKkEg
         AGwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=N7Hh14Vs;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683276022; x=1685868022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rRVvclYfy/Wz5RpWif4x61UdymfDpK1qx7qf3jM+Di0=;
        b=NZPz2BhiaPwZET16IWhyzEEOCie4akwj3wznKU8uENVH7S+7Rov7/1NJuZJvfd4MA0
         zKefkX7XExGqw8WbnnFvOpGn+YtTAdQT8m5YWkV2tyjqzNIVAXVz52J4e7fNXztjQ7z5
         XGCrikpzUxGn2CohlHytxOKicdtl5Mkd26YngtCiBz9N/kuCdc0UjpJv8NREYNxM/YTs
         ZtdRgUkBCefl/DGI3uWftRKbfLN+LRd5o7zZAedV4t2A12HNJhogOhf39X3s5/CfZpJU
         1yFt4mvr94ZVbIo25b07agIfdTJWsdb01oolsMWeWFp4k9KfbwmBv+3pqPNjdUzhXSbn
         qBmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683276022; x=1685868022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rRVvclYfy/Wz5RpWif4x61UdymfDpK1qx7qf3jM+Di0=;
        b=kcGXnDUcB3YeWtPh8fwVDqMvdomQPoYSiO9mpmQ7FbKcP6J076IRvE99q+bR5st82t
         6cUZavBtikP0j/WxC+QLYAA48jbio/psflnc/7ZL/nnKnAtVB5S3wtgYP6lyEV16sOO2
         KE9SavqXNUU9Oz9PcX/M1FpBhCjSIjI+Q1nKVg0VPPia1g8vTlyI1I5PvMySYLQSVQPU
         NNuF7SnW5fetBV8pW87rz1OTcTrmEuZ3ZTLuXWE+cjfbEm3rQTVumf4ByDQfeWew+3A5
         9/ZorIc7GJVyy6XEwii+x+CAdyZwcRZY9Ez98s3o8aFJ6DY3niU+jMdWzmoExPqCPk6p
         +yAA==
X-Gm-Message-State: AC+VfDzobDw9FFvXYZPpvAcVXD82MNbTFRkc0fY06Jjr6uxOPxw4rtEB
	vVHpkJEHUAalZFm7tvqae7Q=
X-Google-Smtp-Source: ACHHUZ5RTZ8SpqQ2dqoJjnEbxKpa+liEaDlfqKSd5iOlu+slZ48KGvDcN3BRMOugdCCt3TRuGdpYvg==
X-Received: by 2002:adf:ce89:0:b0:2cf:ec67:8f9f with SMTP id r9-20020adfce89000000b002cfec678f9fmr125989wrn.13.1683276021658;
        Fri, 05 May 2023 01:40:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a18:0:b0:306:35d:2f11 with SMTP id bq24-20020a5d5a18000000b00306035d2f11ls633786wrb.2.-pod-prod-gmail;
 Fri, 05 May 2023 01:40:20 -0700 (PDT)
X-Received: by 2002:adf:f703:0:b0:306:4060:f25 with SMTP id r3-20020adff703000000b0030640600f25mr723120wrp.23.1683276020220;
        Fri, 05 May 2023 01:40:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683276020; cv=none;
        d=google.com; s=arc-20160816;
        b=XkGiHDeg968BmgyltbQjgg15iAUz2/sywD6J94DHtaKXJvh10eHmMMuWxjSYNkTm1Z
         5tTt0DODn4w2KzWA66pMF/FZ8XUDWANz0CyZ+b1whKER8hafwvtPnjlduHvC1b8nqjZP
         sJ3d/3KlwxbvBSbGs80yW+Zpe9DRTmlm9ovA/A8g0QmKttKdo5rzAo+l3OqnXZnaQ91B
         MXfEfQOjI9VYz+McbXJgAIUFNs6EbC5YBOGTjzPFvXk+qTHN0Lsfa3NbTINR6JfO3fJ0
         kHKewP6amSGitMNM/iONTU2sOa5O82K3VZFWR3AQZuu2jFS9OS/urrhatjTr/LD3lx0I
         wYSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/0NvfINDngaX81zK/8XuAzfIOyZoSgVhu9auLhp95+8=;
        b=vgNBS/+G3VDnlCn0RFTJTuCRDEc0AscjDe6pmjZ22jbodGRYO3b+mjREseghPa2/IA
         jXrIlkPPOy6OvpKwPjASUOmf7XUVCDgUQclNNI3J7rjStj94rEdu+00U6Oq43tqG0gri
         VYD8vHqzJ9XpC7EMw236ma+0HrJ7xlnVqyZ0mJdYE6T2zXZEi3LjhNA+NRuNmBdJF/kY
         TVYrE9x2BZ6MnRQNs0S8+zAY/LOPn6ShTX5qGbmaVN5UoHRLvhul39jrgRjoHAmhnDtN
         Kh4VmDd+0oCf/MjcjBgI8XWHwJkEf2VtoCj6O41B8yatQnniNMiF1UaIy7fg6YiCE+Qe
         171A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=N7Hh14Vs;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id az26-20020adfe19a000000b003063a286483si86374wrb.0.2023.05.05.01.40.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 May 2023 01:40:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D93321FD81;
	Fri,  5 May 2023 08:40:19 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id AB98313488;
	Fri,  5 May 2023 08:40:19 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id VIvmKfPAVGSkQwAAMHmgww
	(envelope-from <mhocko@suse.com>); Fri, 05 May 2023 08:40:19 +0000
Date: Fri, 5 May 2023 10:40:19 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
Subject: Re: [PATCH 35/40] lib: implement context capture support for tagged
 allocations
Message-ID: <ZFTA8xVzxWc345Ug@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-36-surenb@google.com>
 <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz>
 <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
 <ZFNoVfb+1W4NAh74@dhcp22.suse.cz>
 <CAJuCfpGUtw6cbjLsksGJKATZfTV0FEYRXwXT0pZV83XqQydBgg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpGUtw6cbjLsksGJKATZfTV0FEYRXwXT0pZV83XqQydBgg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=N7Hh14Vs;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
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

On Thu 04-05-23 09:22:07, Suren Baghdasaryan wrote:
[...]
> > But even then I really detest an additional allocation from this context
> > for every single allocation request. There GFP_NOWAIT allocation for
> > steckdepot but that is at least cached and generally not allocating.
> > This will allocate for every single allocation.
> 
> A small correction here. alloc_tag_create_ctx() is used only for
> allocations which we requested to capture the context. So, this last
> sentence is true for allocations we specifically marked to capture the
> context, not in general.

Ohh, right. I have misunderstood that part. Slightly better, still
potentially a scalability issue because hard to debug memory leaks
usually use a generic caches (for kmalloc). So this might be still a lot
of objects to track.

> > There must be a better way.
> 
> Yeah, agree, it would be good to avoid allocations in this path. Any
> specific ideas on how to improve this? Pooling/caching perhaps? I
> think kmem_cache does some of that already but maybe something else?

The best I can come up with is a preallocated hash table to store
references to stack depots with some additional data associated. The
memory overhead could be still quite big but the hash tables could be
resized lazily.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFTA8xVzxWc345Ug%40dhcp22.suse.cz.

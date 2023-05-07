Return-Path: <kasan-dev+bncBCKMR55PYIGBBCH23WRAMGQEJHLFTYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D9C7A6F982F
	for <lists+kasan-dev@lfdr.de>; Sun,  7 May 2023 12:27:21 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id a640c23a62f3a-9662fbb79b3sf63390266b.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 May 2023 03:27:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683455241; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBUIkQ+gZsK9108odpaAG+Bl6d1bzA1Q91AB2zmavX4WKNY+JTkPwlpE9CLf7tDofu
         GphFYeibHqo9QQc+JXw+mJHW112z/yy/yyExf++cJW1mfgZ1U5qNlMyc3YxvyOoU8a89
         UYkE2v16k8CXUecRwKwBrVB8RfD3geSWrFCYTuWqQSIO+5uwFKCwFxZyRri42Afn7kyf
         nElm4T1zGIhFou4oE9cXe5TowYvCiUMGZePAkdHIpBl7oWUelScArBa2qHmrk4B4h0UI
         PJCMpp7uCoc/b9nVF/ONK9HDCqTQqmNAwy9qnH0+RNMi3ztVvv5iO+7UyecDY91d0uks
         Mamw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4igE0efpb7yNyiJ5kLLj7itYFdShTgsx26mCf1bW7pA=;
        b=JYYQLAOl9QxAxLNyvcyPnZ4rrdKRPBFcDM8T1E714HVPAAUNicfD6s3Rs00Hg0hRGp
         4Z0JDgayus+gVTeIS0BIbtjPK5vyIexWqA8aNyIueSbFf9NuW36Z0SmtSuBj9Hhmc3rC
         vMCi4oezrMMyEpQDIWw3UAdhVoNpiwye+uePk0O11aw72XyDTVG/r1e7qke2b1s/+NSl
         wT3tkMDLQ7LUppFrDZflEyAd/1P7OIPTMU1Ih2y9J4S9vyH4DEzYxSXu1p7VzxdqqOnH
         1O0Hl1g7JsP09m5srH8MTOvENCKxEW1Gvjrq1nJUhOlQ2Y/MAD6imrhqXaSoQEcQobve
         WV2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=c+QuWE6E;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683455241; x=1686047241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4igE0efpb7yNyiJ5kLLj7itYFdShTgsx26mCf1bW7pA=;
        b=jRRSzVHWyrXADnoWThbtvtEI/v9Re9o+sjC49+H4dJNq184fES8febXIyq/FIxZime
         rLAGCuwkia+zUOxoDWKSLwQ41ZZNEcCIt5z91G2gvdtUG8fVCGQpK5eBusU0V2AdMdGV
         1hEwaYeMz0IkJO6A8GVk82a9IwhCCU7rf1Isz4tCrKvNgJGEukpBkSNOzJtHFdLv9o5z
         AJHRx1zQ0G9RQ+G+6lkB7uq5FyuDXKpbtfE6A0vryHunxeXsAqyYN9E36fd6nPuWBQ5/
         FDhj319M2MUe1lXSQRDLnzE6/xkJOH3NxYnMJmLm4q42bb6LbUjROLox1GDBV3HhQa1I
         hUVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683455241; x=1686047241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4igE0efpb7yNyiJ5kLLj7itYFdShTgsx26mCf1bW7pA=;
        b=jYK21WCnicnZB63Qxp7J5sMB+qhaIaUuaWlJeCC5CEG29iHLQ5btLERoCLfzaEbZwr
         92anrh1kyfElXLagRjt9l3YZeiKKm9yXMExgHfoJuhjLxvfs7N1iudZGpHLkyqZw9L//
         0qPY0EyU+ALbiSrhh/YGwD3LwrRmWStG8p6+XeSNoim48Inderd32+/wuq3g5ekeP5PU
         LSDijLM0MNsutONwzdOiSuCQmH8LcfzuN9VBxQ7Amz0XMeg4fCg0lz6x4wcVYrWNbwHN
         dgL+U6o/ovulWFeGRbNsJEJPEGQPuqA7iRw6sdSPi9LrLSqNxwDglPI3ZvSe7Z3xWzK5
         os0A==
X-Gm-Message-State: AC+VfDwxx69VffF1DdXsjBr1qSwRpGV6PZxpC35LQVbQoTOyZJ7J1oyH
	2fgRnBYy92GLWXosr1CMWRE=
X-Google-Smtp-Source: ACHHUZ4VlQDKHEJYVqz2NmZ+6vNaoTsTNWQCKsfeRU/Fv+kIJhltvNpix8T+BRUJWCN9u2AdALYwUw==
X-Received: by 2002:a17:906:8a6e:b0:94f:2cba:b785 with SMTP id hy14-20020a1709068a6e00b0094f2cbab785mr2503551ejc.12.1683455241184;
        Sun, 07 May 2023 03:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1b0c:b0:50d:8979:572a with SMTP id
 by12-20020a0564021b0c00b0050d8979572als835726edb.1.-pod-prod-07-eu; Sun, 07
 May 2023 03:27:19 -0700 (PDT)
X-Received: by 2002:a17:906:db03:b0:965:4b43:11f1 with SMTP id xj3-20020a170906db0300b009654b4311f1mr5412757ejb.3.1683455239470;
        Sun, 07 May 2023 03:27:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683455239; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8la9B/4XGKOGYdPN+nXAxOU4MTvMwY+nVE1U8KNyxrpayJmkiXBCw+CrRPP23rc3R
         q1taBa6B6iuy0uSTmsagthy2hr3ddqbKKVNRtTTfNi6r+YF+QCKiED7F96V5zBvnmVi8
         ByQn3IOr6PpgFQLpVQLWYfgOpJZ3f5IBpN0533B68ReWlT8u5V/UTWJ0/fG/Uqypzy7V
         QeMaS0x8smD78ATgxLr79o0syWUIplz5gW4XdsVr2R1xRePHEpI7jAJJrcmVz3+8uTWF
         9E0HnN34igjAYO2+Fne/CSH2AExj7/vUcXPRveoR4W7hf1qpmxjr5PFKKp85oORCTdEN
         My6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=oav2A28KVKDaotNibkAokXcYPyLTU0ijj1klZnIOiRI=;
        b=e3Gpo3d5PmPzfTcyyLf2l6P7EbyXxLFgniozMfZdc98SnB74h8ysnz37hauFd91onr
         QF+Ty+h8KaQ9kNxIK2lJYtpROlM1ji7LmaPjOF97KzJ/2uG3gxf371BC50OW++Ra/D8T
         xY+Yf6fXsaDZ6malH1m0LcB8kNovxnO81coC6GlnexVgpi843QrXfd2hGuLWRX0ZV4y2
         9KPEi/fDf4wrqxtOI5W/UnzxZgUIZh+gbXdTfu9VweG+jyxCh8BnHd3Jl/j+/Cik0dGl
         DzdhQgamhN2Vhn+nEkaOn1KfI+/08o3xuS7IOx0lK+OQaMBD3aj/UGOoHLnYlyF5jW9U
         aOvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=c+QuWE6E;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id d12-20020a056402400c00b00506bc68cafasi686453eda.4.2023.05.07.03.27.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 May 2023 03:27:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0FBA61F459;
	Sun,  7 May 2023 10:27:19 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E9F17139C3;
	Sun,  7 May 2023 10:27:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Yy8TOQZ9V2RkOQAAMHmgww
	(envelope-from <mhocko@suse.com>); Sun, 07 May 2023 10:27:18 +0000
Date: Sun, 7 May 2023 12:27:18 +0200
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
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFd9BiSorMldWiff@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <CAJuCfpEkV_+pAjxyEpMqY+x7buZhSpj5qDF6KubsS=ObrQKUZg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpEkV_+pAjxyEpMqY+x7buZhSpj5qDF6KubsS=ObrQKUZg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=c+QuWE6E;       spf=pass
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

On Thu 04-05-23 08:08:13, Suren Baghdasaryan wrote:
> On Thu, May 4, 2023 at 2:07=E2=80=AFAM Michal Hocko <mhocko@suse.com> wro=
te:
[...]
> > e.g. is it really interesting to know that there is a likely memory
> > leak in seq_file proper doing and allocation? No as it is the specific
> > implementation using seq_file that is leaking most likely. There are
> > other examples like that See?
>=20
> Yes, I see that. One level tracking does not provide all the
> information needed to track such issues. Something more informative
> would cost more. That's why our proposal is to have a light-weight
> mechanism to get a high level picture and then be able to zoom into a
> specific area using context capture. If you have ideas to improve
> this, I'm open to suggestions.

Well, I think that a more scalable approach would be to not track in
callers but in the allocator itself. The full stack trace might not be
all that important or interesting and maybe even increase the overall
overhead but a partial one with a configurable depth would sound more
interesting to me. A per cache hastable indexed by stack trace reference
and extending slab metadata to store the reference for kfree path won't
be free but the overhead might be just acceptable.

If the stack unwinding is really too expensive for tracking another
option would be to add code tags dynamically to the compiled
kernel without any actual code changes. I can imagine the tracing
infrastructure could be used for that or maybe even consider compiler
plugins to inject code for functions marked as allocators. So the kernel
could be instrumented even without eny userspace tooling required by
users directly.

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFd9BiSorMldWiff%40dhcp22.suse.cz.

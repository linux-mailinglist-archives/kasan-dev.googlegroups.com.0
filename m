Return-Path: <kasan-dev+bncBC7OD3FKWUERBLX3UXFQMGQEOC2BUQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id B6237D2957D
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 00:52:16 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-5013c19b92dsf39579401cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 15:52:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768521135; cv=pass;
        d=google.com; s=arc-20240605;
        b=KlWJF0fSPCtNPCohsCP7OJtYsH9s751q4cdfzR44sU5zOk2BvTRhRtp3dDWM0vj2dN
         lC5USvD+Yc/Sue9nijRSpCfwFMpbWt/2YxBq9H+swMf4AWC48MUdjRqig3O8Hrr4I4Np
         HyJCDmQB8s9UVWW6sEx83Lq0FW17vUpMHqXLvN8MG5M3WDGzrALNkDnGoH9EpVZNxXNY
         oO+PZWVbbyyB9fSoJGn0Ku92sTdUBJNUfqWHr3h7uUKEV+5T+wIlVBJ4jWN5S5atF/Pi
         DHN7yW3xvrrHVJFFDNa2OHFT715ddK9/tkCDLnbG99+wI3CGdbjLukyLquCdd04NYQqo
         f1nA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8ZlByoEtHQOFnlSqt/XNXuDz7+mWXbxO1uFp8DFd9Kc=;
        fh=D45rDLspoPrJfiTDz31RBKoWVBITKPjnEHs7UytJryA=;
        b=VQH5xBtmlnC8S5MksdCu9b/J+t6n1XNPG4QRcXqrASWkvpqKdJ1sLbznIcjYh/aEFa
         OTVOWZNINScoUY8xddzMlPstHu9YEk0DSIVKzJ3LMqrsFNUfykH5Xk2MPNREvb/KZHpz
         bI4334d6ZU3+AUgc/nkImH00wA9+prR6EcYsxmNN9Ijq4prL8TU5LABec6ONqsQycLBE
         1L+NdIyh1bOMPEw1m6aBeLDHv90Ke5NOi+8OJSAl0xumMNStSFa4CFeHlMx0rzUy65TM
         v2GKKOgGEnj54dpXmQBJ1+DO9gmBUNfZ4wcSM4kpR3MbigR+k9WoPwP1vprWtaPD1M0H
         yuQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CjQbNihR;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768521135; x=1769125935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8ZlByoEtHQOFnlSqt/XNXuDz7+mWXbxO1uFp8DFd9Kc=;
        b=LNpL4kLmoXCHu095de0Z0H1F1cbOCCNwABMC2Vc8RkOT2VZg84yb9Pw3qYtl1iLZzv
         SdL94jEAGIcf8xZvRDe2G/wWmpuhsOk/1yH1puvb5m6fvRa/7F6RUvFgIQXMxNHbe9RQ
         nuU0KUQAHw+FSwkdJEzt+wUAIfnAebcWXaarBBl/op0CrUw6uxxyKw2OVvWC5OmmhZ1w
         4wa5ndyuf3erjSGFLdx12L7TY2rHJip0PaOHIF4YUtslzCfHRLPisWPsGIoOQ4rRfaCD
         6ozOu5H9kdq0vtr2GsfDwi+tRokdI8ZAITdl1LRYwnaK4hmDBia5qqAI9zUM9fteoc6J
         1wAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768521135; x=1769125935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8ZlByoEtHQOFnlSqt/XNXuDz7+mWXbxO1uFp8DFd9Kc=;
        b=LcWkcpQQKtMCbjX7+Mt9WYxAIBduC3nWbxeeNoXe0NkWx/rbW0uXSYpjdcF96k+Rg/
         Dp0/d0CmsJCrMupJ9cxCFUcc+4tR8QmNdoxcyNBcQ8oXsGyC0M+NM5J1UVO8AU9nc62J
         u6nWSjHty1K8jeYdI7UmbomcrGUCQOHcFLj3Zs0+e0gmOs9Bzt6gLQvRfvrWeCnNUBdy
         8tbROP7Y8Tko5fjILxQ5wDsRL4GGB+Ctuyp0xzFktSSeTCh7Ro2KybAru0ea2LPxzvLQ
         rwMVv6FRqy3STbrH+/p9yRzkmYCHXL8g9W6XrmeiLLOWlsc6b3uF+LIG1YRTTy2Og6bo
         eFSw==
X-Forwarded-Encrypted: i=3; AJvYcCXccigxTAw7yT2SRXYTKJ/LGC96ZBjIwyn/YGm03mTbbeW30lFUCZaty54+vr30sb7FpQSl2A==@lfdr.de
X-Gm-Message-State: AOJu0YyAAC4DcFk8zzALjtDgLybeEK7Gliwp1MsoyirxRyxFPdRRyL/G
	DKsJ7h2a4I8rPJZCwtyg7aONGAUbAwPcND+ITpij/4W1MNSsy4PG3NK9
X-Received: by 2002:a05:622a:19a0:b0:501:489d:f405 with SMTP id d75a77b69052e-502a168dd0amr18733711cf.30.1768521135109;
        Thu, 15 Jan 2026 15:52:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GXkWC8ZfK7NdtAzo+HgDgGx9WoOKozSpXpOT3vwnZ0cg=="
Received: by 2002:a05:622a:1496:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-50200b13f76ls23911481cf.0.-pod-prod-02-us; Thu, 15 Jan 2026
 15:52:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWD7PgSJcX8twfbWfnJFYIOZvleOiZ5pQNJj7D0FBg+gUSplym0G2vk1T5EEmhCQwHnezvP9O6Nfts=@googlegroups.com
X-Received: by 2002:a05:620a:191f:b0:8b2:e666:70d with SMTP id af79cd13be357-8c6a675aba1mr191167085a.43.1768521134170;
        Thu, 15 Jan 2026 15:52:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768521134; cv=pass;
        d=google.com; s=arc-20240605;
        b=amw6bWsl9/MsPevGr9YbS/ok6+2KPt2D7aYt4Dxct1KYMgz6m3x63zoiHNpx5j5dHa
         iRTMO8Su56mIYAOL4tHrK6OXcb15t5dh30cjOYZjD6QkAMsHbMPfinJXGSCcl3nfB7+8
         syzaesKqdNvZf/MckdJlNLr9SOVU+6eqknnkXB16k5kwht8Vc2a0tyj1GhmigYyDEtn5
         +3nBX/f96vdfchdJHnfUqqNlasB4FxY75MNrEzoBdILdmRoRL5RttkSfycmMtcnDyUws
         QRRtMk6CprKDf/F+8h/kEYIN2cIwhfnUJR+JuXtyb+atbyyx+x56A0Ka6JJaNB4xvuh/
         KqTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ziMDC0dlNmas6gHzjHH1+PeorxqM4k3ugul/XAfwuzw=;
        fh=1EoQSOzhXcYLLPbzFlAwDpUfvRFBuvCKA2E0x8AVhkA=;
        b=CLk8W7k8yXYAUXiLRmUOIOvgQUp8vHFHC5nD2LdSfnaeKp/MCwgIvf0qIWf3zrERKJ
         fEMw5PI8uqmDLfWruzvIySi0BiEtbe7ofV+NEOm1cW3zPlrbsx/EUH9mzdPoESphX+J/
         CzKGgrz8MsBowGr0pR/7CkNYm/GiWgHIvaw9L1fAhdlA7GeOH0wNdw4sXpPqnw+RtHQq
         ZACsJzfeNDWmBqyQJtPBRd4EOhZfqFmtrev7qUwc1590/rZFXTogmDfVcxftPGndRlDX
         wPepwi5uDkFyha2wWl782VWc3lrbS3+7uzdQfp/clZjoi8sRWR2Bvct598Z4hj5PEGKN
         LfTg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CjQbNihR;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6a72419b1si2780485a.7.2026.01.15.15.52.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 15:52:14 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-5014b5d8551so154561cf.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Jan 2026 15:52:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768521134; cv=none;
        d=google.com; s=arc-20240605;
        b=c3sXPWY8cZDcnTlAy4UfKNhrC560qYsqTmdeyjnXFcd5BFOA4RN3PnYAp9T39RT2+h
         I3Fo6RNvTB49VRwDML12aPalU+2R7a5jMedEankB3rTcDXah/QfbcmlxGB9ZZu3d67Wd
         v5vbRyqvYJzGcUhih1yHHmaR+MTGXmtd9htDFNmnOsK8qVzCKb7XalqU40M9YMlJUS00
         3HwW8PTljKS1HTAXVnI53RfciEMe2708z8eJCnDNBpNhCyAvShawXYCe0LeXibDjhzHe
         heL7Kerzahvxvq2w+6qtNApny2j4tR67rZVJf8g5WwhO/aTqDV5Z2/+7vwoTdq2XsUZO
         fsxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ziMDC0dlNmas6gHzjHH1+PeorxqM4k3ugul/XAfwuzw=;
        fh=1EoQSOzhXcYLLPbzFlAwDpUfvRFBuvCKA2E0x8AVhkA=;
        b=dPjPMSqGr3kbQTL3Acr+IjCzF7ZXzX/Klang0maWybHmUEwBNkybwlpzKZ79dJg0gQ
         YivMZHAdMWmk0SKyy0bLMlx4DDqVKT0AmVFQcd45wgUTRvPjOVhRC8NZcG72lPLUnl3I
         nPtz5B7zk2f0Y2037Yum0ti5eTXIUp9pkRHnDKQ/qGvupgyw0xdBaKJZwrGfDADdgW2v
         tAwPuOdqmJEWwKVLvOCe2VdJINo3ESUTCM/uxmHPcQjqAIUkqEDeRy5eWUqxq89xqcBQ
         N5DjbPsGDh+C4RGJkpDmylgdc5uKSmBCqeRxF4zQ0hOiG81dkSnRWBHkTXQu6Yq3Pt7K
         VZyw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXiWf43rmmPB+zWtqMdZ+uPEmch8s3YQWHyyZ+Mv5okjpMEsKRySSiwmUKwbZvAwSzDXazbvy/XmQ8=@googlegroups.com
X-Gm-Gg: AY/fxX6SfrQh7cQDeEzMImA6VCGfFhoS0CsL1/CEMqne+GSZnBO0Hd6CARQnQthgB/u
	vfFHOJhBKl9SiGvrE0UviuHA8+5KCF7RGt015KOlwbhGE4nsFUJY/73WxMS0s/1OD+cGkIPeSn1
	g9/F7Yj97bIVlS09H5DQjBjV6xiy46Ba6kINFEkAIdkPlAIXJ9f3PRP3QeNdtoe9XExGYuGng8i
	zqCKE3DGN/p29NMZuq7wxf7q3FM3GB0QOVpoDyVznIdBsiLyxQlZ+nNO+sah6ajPFSgHxVo6vO2
	udkqZUsNm5XcGa5aMmoAY/RZjSMXN4T6EA==
X-Received: by 2002:a05:622a:58b:b0:4ff:a98b:7fd3 with SMTP id
 d75a77b69052e-502a22cfe86mr4096151cf.2.1768521133130; Thu, 15 Jan 2026
 15:52:13 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz> <aWWpE-7R1eBF458i@hyeyoo>
 <6e1f4acd-23f3-4a92-9212-65e11c9a7d1a@suse.cz> <aWY7K0SmNsW1O3mv@hyeyoo>
 <342a2a8f-43ee-4eff-a062-6d325faa8899@suse.cz> <aWd6f3jERlrB5yeF@hyeyoo> <3d05c227-5a3b-44c7-8b1b-e7ac4a003b55@suse.cz>
In-Reply-To: <3d05c227-5a3b-44c7-8b1b-e7ac4a003b55@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Jan 2026 23:52:01 +0000
X-Gm-Features: AZwV_QjyQPPUtH5tGDbHEFhedU3kKqiqu-2QyYB5WPZJAwFL9F8l2hS-k58cSQU
Message-ID: <CAJuCfpHCgyKTiPOZ_p76hTLRrZfQrkNh7XHJkEM0omWWCK2WQA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to kvfree_rcu_barrier_on_cache()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com, kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CjQbNihR;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Jan 14, 2026 at 1:02=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 1/14/26 12:14, Harry Yoo wrote:
> > For the record, an accurate analysis of the problem (as discussed
> > off-list):
> >
> > It turns out the object freed by sheaf_flush_unused() was in KASAN
> > percpu quarantine list (confirmed by dumping the list) by the time
> > __kmem_cache_shutdown() returns an error.
> >
> > Quarantined objects are supposed to be flushed by kasan_cache_shutdown(=
),
> > but things go wrong if the rcu callback (rcu_free_sheaf_nobarn()) is
> > processed after kasan_cache_shutdown() finishes.
> >
> > That's why rcu_barrier() in __kmem_cache_shutdown() didn't help,
> > because it's called after kasan_cache_shutdown().
> >
> > Calling rcu_barrier() in kvfree_rcu_barrier_on_cache() guarantees
> > that it'll be added to the quarantine list before kasan_cache_shutdown(=
)
> > is called. So it's a valid fix!
>
> Thanks a lot! Will incorporate to commit log.
> This being KASAN-only means further reducing the urgency.

Thanks for the detailed explanation!

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHCgyKTiPOZ_p76hTLRrZfQrkNh7XHJkEM0omWWCK2WQA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC7OD3FKWUERBQU6YTFQMGQEH2BIQZI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4E+vFkQPcWlEcgAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBQU6YTFQMGQEH2BIQZI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:39:16 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id CF6825AA9B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 18:39:15 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-40837897c83sf311688fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 09:39:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769017154; cv=pass;
        d=google.com; s=arc-20240605;
        b=a6d6qOPxrOZD1KDPaSJ5wWRRoUMIfkCQtLVgJBT+cqUYWHqZdt6V+UA1VBc9rYnlzj
         Q10e5qkwNLVwBbKIWZjiy+QYovLQd68tt0h2YvynFdMPVYtAm9+kdchkQJ9duglT54zr
         iU8j23E+pKkxCiDhC1i/8GL/QOfZcMrctGsa6PbLF8buMzTk5qWHb+2vLzdEfWXOlN84
         4Za2Hr+FVT7TOAjPnHxeSQ5c31om7OyBuetlw4rnhRItG6NqGp2nzCzE+3oEwKCrOJRx
         STNGFeV0o0lx2jXr5vR+Kqfb3Z/6+tIaoqkualMDHpe0FMghoNakNgLtcxYPk4iMZMGi
         qwRg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0/dprQP6Vj7E4wT1f6jqBUKdt6j5+vaiqtX6knHiC4Y=;
        fh=BjOiHEb/YD+RY+0RW/45Ght8Kr06etMvteu0S2g3HO0=;
        b=WNTK9rBunUu8YPt/Gd4gRpFNYR4L1hQW/JvzoVXmpV5DtSL1imrrEsIcYoAxqFhtyn
         /LmgRz6R9CdrgPkM9Z/5Frxna7sWKYJbh0N02AL2j8WBjVCFs8et71sHUlLJcxYfWWAY
         zYW2S3FgLsYeec/WTzCEBBM73bCjng/OuoyLH8x3oHZdvIj5rCp1WrIQIpF02JnY5tOo
         Q6W2zfEJoVNeJb5jShYkcRJ+QjieKRnVIiqQmUkW8HY89xtAA4lsDZURu7qSFguKGhpr
         PUFBTeeaK+Fpru33ASd7QDkumD2a+VEDVikXlF1lVM0XPrtWclS6Y+Ped64sObOxpWrb
         L3vQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qG9EbowQ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769017154; x=1769621954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0/dprQP6Vj7E4wT1f6jqBUKdt6j5+vaiqtX6knHiC4Y=;
        b=qxeTT6cnIiWkn/kGHHJZOHwcnAIg7HKZdILoPcrjqmqtvaTUWTixw60x6JJq60h8qy
         q2cYbmYO7/QtjpSHIk/I861GA6OZr/2RFnN4ZsxiwAB4ocjCTjWmM2r+Ynox+Yz13s9/
         lQX+5apVbZz22VjOYrhP8oKPgKPnP9ISy6m418ZDdtakaxSqmaznbr2OWkYgQmFow1gR
         baBbDmhGyR6fZgZt8aHEaYeWb6NigCIGCsO74MsutcGHTuyxh89BlVUFtdO9BCZkbUYp
         U+uPrtd8gHOSqqT0U5oqDdnT4L49WaibMIHT0gLQhjeuqgl2EyLn/OL1TlrL4JdtRndg
         ZvRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769017154; x=1769621954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0/dprQP6Vj7E4wT1f6jqBUKdt6j5+vaiqtX6knHiC4Y=;
        b=ig4xzBGQfLwbF07BlskQfAdi4gnheojfeqVxxXrNGHaT99hUdi0kyB5wiSs52QYTfR
         wdxeiVVJfqYLj7XmbV29g1pV7dCm4WOn1tSg+qenXc1731useTPdudfJR3IpexD2TpEc
         1CM2ulWVjZDcRbNuZkwOR7ceoOUQmDBPrzWSE2lDQ390aV3tKcTowBr9KpN5lnAb9q4K
         mgeci3vJx41Y95C2+4W6Sy5wQkRYENDuymjEgVe4vWx3iXXQNLGEiFnknTkG+h9snRQ3
         fhdHVKdIHoVIDHYcXKeW3vW7KJhheQKglo1Y2dpk4wI/18LwWz/xWrSpj03mCfqn+7Xn
         1tQg==
X-Forwarded-Encrypted: i=3; AJvYcCW8DHnHeragYBfWjuDhjWnZeS/bOW55nOkgMyYRkQv9gGQWyry6WWKTesEb7PbFBUiCXXjIuQ==@lfdr.de
X-Gm-Message-State: AOJu0YytcI5ANmvPUtCtMbj0yK3pBtJGKvE9NFLKzn0JnE0hcndoz3h+
	n8gZ059muc3pKRBwcIzMb3PkuLhb/RLroODk3OHK5m0VXddvazH7XuE5
X-Received: by 2002:a05:6871:53c7:b0:3e8:8dcb:cdc7 with SMTP id 586e51a60fabf-40882d79627mr120099fac.20.1769017154297;
        Wed, 21 Jan 2026 09:39:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EWqSvY9s7kz9Yof0ZjbLMF6gS7QlXNVgfYO4yP93gFoQ=="
Received: by 2002:a05:6871:a805:10b0:3f5:cf8c:7f65 with SMTP id
 586e51a60fabf-4085b1545d5ls252355fac.2.-pod-prod-00-us-canary; Wed, 21 Jan
 2026 09:39:13 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWoOb7n0gKfNBy2hJ2uVYV+Le8ngMF596xRxHUUanMaylEivOWeCztZQvlOlPwzt/PacYLXsKR1Yfg=@googlegroups.com
X-Received: by 2002:a05:6808:10c7:b0:455:d474:7063 with SMTP id 5614622812f47-45ea3d47b6fmr124687b6e.14.1769017153445;
        Wed, 21 Jan 2026 09:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769017153; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y9xDcqbu8k/nOFe7MFTL4OY+FntUg4vEqlHEhQNChklnt37W8L6T1Tb8GcXqAPqDs9
         kXKY2MoAk2052q3LC0D7A7n/GbmACUQaFBRDbRGfFJEIk885jToo4gcCjQcbguy/kFII
         YGVxcCZGV+Bfl31I2s1KiWrkIIQA+EFnodkLE03tdj7O62WGYKZF8IKvtRuG2GbBi6AI
         n1/oWtW7SPqGDOQkwbSj+lcMHux+0wB2a2i+VOFtRN1aqIS3/ZNVVQOp7IE7XEaEUXrw
         xmre40PIbjyvUSjBkvlgqAyU1zE8oGdktZPinYVLrX1919L/yqz9BJRaL+UH3e/qccvT
         kZHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WZPB/nAuSxHMF8z7YKq4XwyLCyx1N2zE8w1NIox3Cbs=;
        fh=p2v1ZWruJQvnQnhHhC5RbVfTncgFJOfUC1dcGl7RjNU=;
        b=eUlSfEuakRRTBqIymv8eWXi6/xAH6g4zFt2WJckcAsSEYsYd1yxNpFPV1FQNSeg1ys
         qlgVLlucG/Fnwxnlv0Ws41YBPvNw+SIJGqHKBciKm0WUWEDHz3q2IQtr5JJJZb3kyZjn
         syXk3fDLgzU+tuizwf6z9WUvhBYZ8Mm47EfrPYjPc8nSsBOwrfaSX2dE0axVq3hGm4ZD
         mwcPQ6aJnCIVWe0NuU+pNXdVlZ8DMRaquRapTxfMwZTcC/BiY3kYMvV6x37hFOmec4N8
         na0zO3aKIuUxgiRumHVew4Pyns+OT+gr9FvUMhZ0Iae04iOhchlbaVWSveH7HoUhaAZn
         2WAw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qG9EbowQ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45c9e024593si575113b6e.6.2026.01.21.09.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 09:39:13 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-5014acad6f2so144411cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 09:39:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769017153; cv=none;
        d=google.com; s=arc-20240605;
        b=c8h6XiQI7hmmUAsUYmh521oCBmQl4YnG1GjBRWKxnQPu+sNFR7VQfQ9pW+hypSU7k4
         SK5qwKSeNoD8eXjKGZOKwpYiVedzqfMzh2o6mO0ei0usXEAEF36gEkKKzUuZ3Ab7UOdp
         OqMkQ3pz9eMU535bmPTmZFFZD2HbdPHkqHkcr5jOqtB1scSMbWv32zbAIWpSqj/FGkM4
         9kbY80yH9ESy3DuhtLKe/jVoFfkNWMdnwcvuvkIYOnzCTKWjh45DUcYzC8bf++vgnWJp
         grMMxkhK88VWpBXaFZW4xY3bpFmFnypDAvX2N+NqGNH7dDiS9/jt6qXmX94RgUR5JCuf
         jg7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WZPB/nAuSxHMF8z7YKq4XwyLCyx1N2zE8w1NIox3Cbs=;
        fh=p2v1ZWruJQvnQnhHhC5RbVfTncgFJOfUC1dcGl7RjNU=;
        b=iTmJJdVCwjMoDu1K1moG5dPBMzHPYH/VZENue5yHbyfAY4IoLfDOQ7VqLnpSQM7Uf2
         sR5skrL27031tNU1tPKWHxb62Pk85eEfT9JJZw23C+gnv02aUXCvDlgh1sLFxFddJ2b0
         ohtsHcAyGCilCJ+fm9zsqusoKz0HyC5VhSv6+bPPPzaCN8rhql5Nw8uBA76QeFt9m/Lf
         UMhHDGiCMYNmo8dvwfEOjNmPmACzjCnH7F+jtNub5/NfLsFbxsk2S7FuLR/qb+LRrHWt
         BE9rgLONuloUXWyO+0q4UGosaGKiOeYhg7hdQ1zBaGyzXv09amNRiGjsqRc7v2PJbC/+
         8MZw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUs+f2EkGj0O2ePHVTns3+UCNlbpTwPP3w1yoEtdWVRSG1d1u7cdCaHo9WffzjAopeDiIcWLTBReeU=@googlegroups.com
X-Gm-Gg: AZuq6aIVF4dWX5yPZSx+n8vlIdyl8pdJDQwQqeUEXIsNQ+2hTTv2HOKCuTYdTtGo2GB
	ZP3rC7JPq0DDmm8ycZ19f9NHhxYDpfaW2tY3zdd/3w63iemBfOyVuB8xg0in3e3fQgglYcqtQkx
	CLd0Nq0x/DnNmo93Lo/DDS1oRob6EnbW2xYvsWJlit1YcJWBUl/wKLaHmD9kwX35Ocg92kziVxn
	MHvH1uBFZ0TFFQLpIlaseX/SkcBqmNPux2KDoYJdzJ1JRzEAtKWjB6J/fTMLyrvwnvu87dt6bDk
	UbVe3D8uDRIITlL7zvKHuDM=
X-Received: by 2002:ac8:5994:0:b0:4ed:8103:8c37 with SMTP id
 d75a77b69052e-502e0c6494emr14807601cf.12.1769017152599; Wed, 21 Jan 2026
 09:39:12 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz> <2tvnelafuozzzfyvmxvflqmx2sepgy7ottnw4n2trkh33rrk6b@oewlapq3smvg>
In-Reply-To: <2tvnelafuozzzfyvmxvflqmx2sepgy7ottnw4n2trkh33rrk6b@oewlapq3smvg>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 17:39:00 +0000
X-Gm-Features: AZwV_Qi3Y2iex4LEenR-glhvYF5fdvLAgmEL3JsgkohqCrj2SiE002EgBpgOZDM
Message-ID: <CAJuCfpHGSxK99sSDmnh+xqJOaqLX6vVoH4oyPUS7J6J74RU=9A@mail.gmail.com>
Subject: Re: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
To: Hao Li <hao.li@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qG9EbowQ;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=surenb@google.com;
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBQU6YTFQMGQEH2BIQZI];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.cz,oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email,googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: CF6825AA9B
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 12:07=E2=80=AFPM Hao Li <hao.li@linux.dev> wrote:
>
> On Fri, Jan 16, 2026 at 03:40:34PM +0100, Vlastimil Babka wrote:
> > The kmalloc_nolock() implementation has several complications and
> > restrictions due to SLUB's cpu slab locking, lockless fastpath and
> > PREEMPT_RT differences. With cpu slab usage removed, we can simplify
> > things:
> >
> > - relax the PREEMPT_RT context checks as they were before commit
> >   a4ae75d1b6a2 ("slab: fix kmalloc_nolock() context check for
> >   PREEMPT_RT") and also reference the explanation comment in the page
> >   allocator
> >
> > - the local_lock_cpu_slab() macros became unused, remove them
> >
> > - we no longer need to set up lockdep classes on PREEMPT_RT
> >
> > - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
> >   since there's no lockless cpu freelist manipulation anymore
> >
> > - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
> >   unconditionally. It can also no longer return EBUSY. But trylock
> >   failures can still happen so retry with the larger bucket if the
> >   allocation fails for any reason.
> >
> > Note that we still need __CMPXCHG_DOUBLE, because while it was removed
> > we don't use cmpxchg16b on cpu freelist anymore, we still use it on
> > slab freelist, and the alternative is slab_lock() which can be
> > interrupted by a nmi. Clarify the comment to mention it specifically.
> >
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/slab.h |   1 -
> >  mm/slub.c | 144 +++++++++++++-----------------------------------------=
--------
> >  2 files changed, 29 insertions(+), 116 deletions(-)
> >
>
> Looks good to me.
> Reviewed-by: Hao Li <hao.li@linux.dev>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

>
> --
> Thanks,
> Hao

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHGSxK99sSDmnh%2BxqJOaqLX6vVoH4oyPUS7J6J74RU%3D9A%40mail.gmail.com.

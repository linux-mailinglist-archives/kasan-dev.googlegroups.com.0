Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVNZQK5AMGQE2KETUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 235099D6109
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 16:01:57 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2fb53ef3524sf16878501fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 07:01:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732287705; cv=pass;
        d=google.com; s=arc-20240605;
        b=V26Os4sJ0M4MP3WUOFIeg/B1wEOEbNYUHTacmCDYmx0jjJFdWAceE6UqphHTcEatHv
         DerDWOHhProUPZlmDlHGgBU52cbaXMUxOYAfR06PKx9SAKZaUDIROiFOAdD3TohW6HOk
         XnT2xX5rGK2a7rbp66OCmOKatUcxXiimruZU7n/0EtPi7Cup0VImj9X7vk3P++EtxWVp
         qUYmPdUOzt5wE24FxzLFtvfcb9YRLjZc7MGNbJVi0awvET++UB7g9JaslQ0S8+7csOmT
         yB3gHdlGu1+VxNgHZ9dTdJZ3WYYiGtK2pX3pRh+a1nvpzC/SJapHvJjuk+SY8hCaAQVt
         p/3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vTb4IVjc/VYlFkxnX5QWF1lgHqtFJzId4sFpiyn4AJ4=;
        fh=s7jyzYZHcDTErofPIhszfWuQ/mpaSv/uj6eul8PWyes=;
        b=gkeft79Mf0bnWU+JYCxN6u1MJ4RtA9gOgY/BAq7mqd3YeuNOSUEvk30e8Z9UC1bs+9
         UGso286kPqaELW53YpOzihV26+T2V/H9QH2GjCF9uX7eubHj/stqA+uHxYVyNGS2aNJT
         +jbNqAXz6VxD4+FYjieDgMZuONjXWKfT2swrjIlbLxj/KFoBkzCfOLB7Y6fkfxjAYDxk
         u92Dz6uBh5DUt96vBky65zmA/EML6qF6QJPuV8l7ddspmhusY2LbI9X/CUuW1qm6t15p
         c4wXfbN8rvw6R/5kbl5tFyeM2k4xZdB2QUX57OV7EH3YPQBBM6KoGgsULuapxI1rGgom
         w7NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H7z6x0xx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732287705; x=1732892505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vTb4IVjc/VYlFkxnX5QWF1lgHqtFJzId4sFpiyn4AJ4=;
        b=B1krHn3OfB5daqZxNB6yQcQBTMwZ3aY66QZH39XEdelsVjk/QihCRE5px6q0+/T693
         REqf01ipuC5WftI9FIz6XLab4y6kgT9iOlJkyHNnjMoIasr+e2W2+rWNXfF/J4N5E02P
         +3hJ4SaCXZmNV2Ztpe9/5JJ2+jLI1ufVmWDNuv7zIZA68PXGTE/7vTLazBzglrScR3+L
         5SjHmahM1Ez5Ju1OHTqAvJxGlg0ws+xxHtaqQTHnX/++DggG6NEj+PgAVp5HXJe68lpr
         qHxTxWW6F7yIBV6pSOABLu6peF1HPMx1rXBFokiNxpGpjT2qieaByAEO1+D9UjW5IZuz
         1rXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732287705; x=1732892505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vTb4IVjc/VYlFkxnX5QWF1lgHqtFJzId4sFpiyn4AJ4=;
        b=cnOWJY9MIWp96jpdH4plfCILTg0rRRz5fUUp6Uli3xo9SKx7sLHYEqFHPQ4u//SiMw
         yg2VwLda+hJ89R5sUDSfXJzVH8ImfwmnajuQxDAXHVqRFH/60gwRPiLojgeC8MYhAJxU
         /VTd99PoJjYq3Hts9mbwsEIbBvnKz+OxncBrOkxoZtqo8uJMG4xNokC/lQRu4slHuTut
         2YMxrfqCorMFnSGdfoAt7OJVmBdyyTaTVwdO59eeiBn4nIcXWLdr6ZwuXZFG64yvq5K6
         tjgiBcOoWVc0mCoAYCLAHhmBWKnZR90VCoMHIQc0424piMn4bUMwALok1n07fY76dIyp
         FmgA==
X-Forwarded-Encrypted: i=2; AJvYcCXZTE5DSi6aeYsJzwU4+YE68uogNPgJGPPwWrlTtxfkotTOsw4gwdZdtAURVfrxsgP8TSlRFw==@lfdr.de
X-Gm-Message-State: AOJu0Yzwbi9qiIulrRl58L02E2Q+WUAQGFpYRLEdCtgwwhyVApRcxipO
	px3OXvQhEvZd5Q4ijEBgue+flrZpOgzM/E8YpVvKioff8uCsmbuP
X-Google-Smtp-Source: AGHT+IHx4Jn16Cps2FYCwfX5OsQbyIfQBnkr0V2JcOPNHUHRT+1oST+glmxLE24xYmWHY3DGoCbZhA==
X-Received: by 2002:a05:651c:1145:b0:2fb:607b:4cde with SMTP id 38308e7fff4ca-2ffa7202d8emr19805181fa.39.1732287702185;
        Fri, 22 Nov 2024 07:01:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211:b0:2ff:5daa:13d with SMTP id
 38308e7fff4ca-2ff969718bals7684711fa.2.-pod-prod-07-eu; Fri, 22 Nov 2024
 07:01:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVT57zGboOc0w7nAnNzcD7n/d9JZBZM1DqJI9nK8fXAzeEwyFXWhwslm5oFxtVg/n0dVVUX4PGDJBw=@googlegroups.com
X-Received: by 2002:a2e:9e83:0:b0:2ff:a928:a234 with SMTP id 38308e7fff4ca-2ffa928a3demr12273751fa.20.1732287699077;
        Fri, 22 Nov 2024 07:01:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732287699; cv=none;
        d=google.com; s=arc-20240605;
        b=Q5A9oXPIFYj9VKk1VA4oejKnpOBMWZNA0N2xVgQh+uJWuLfRjnj1ypJuXCuZJtLipR
         ecjIDwU3jtcmf7Jx9gDYgOQeNz5DXciD5nP+FD9VtzG1SQfCQzlZZvlqqXNq5AkRqip/
         tFBmKTga0wjy5w5xz8tMmKxbTckgS/XrTJfzbZNArLBM2lAFA6RZXbCMQSWN2cqSMOBQ
         HlPle/Oi8a/YKNFxVkVixoXFip9ZPEfVoNq4iS89l604tVx/0xnNwB8PUsWnKZaoHdMK
         f2DPBj3oGrqJ6VtzO8sXz+hVyM2vevgCG3UIeGvW22ubxpScrbihodUakWOwS77ywcBc
         wHYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2CBrmR/4K5+pOzn9XzmrpMtqvst0Y6UbBDGLFW9ccDE=;
        fh=yudD2/ehLuwmsy7SlT1V8j7yonBZxqQX9UUOJ5LmcjY=;
        b=bJevFjbnK3oeBLDDk8m6HsZkDWeSbvYvy3lhes/0/1jVt+coCz9B/fv1lLbOITAmQ/
         AAM6Ua8zEX5RNia9FUc/qEs5GihR+H7fAaEMGNjU8A3wpUx8f5UY05jQYAcNwdSKAel3
         DQ+AFw16SmECKpNs5DUV3eboTEyzNxxaPldHLv9EZAPchSR7kn82mS/kKxvLDqHuZ+Ul
         kU7RiOyf3m8R+kAg1/N4V9ZjJfhHSaz8O9lzu3DrV18tU5gBACrTYGxezkyqG3A+mSly
         +Nnn8olko4t7OsDdWJYk6yIjIg4AuSl7E4wfucfyMQ2c01c4GV2p6yJ4sDzILUxj5hBY
         Vquw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H7z6x0xx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ffa4d16721si338591fa.2.2024.11.22.07.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2024 07:01:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-382456c6597so1600454f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2024 07:01:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVrG21OYDVLfzTcGe+YWoBJ5V3dNanvQTGdfdQundmLN2MlvNDu0T1XURf9MUYnm6xpRoX5w7nTOmY=@googlegroups.com
X-Gm-Gg: ASbGncsvTBiKvAlpjv8hmqy6wiGH1G+0bgg0XKNXkS9uLN1OaIx9dvlBCOD8VW3Cr21
	YMQgsZCoVdO7tbxAUwQG5Tkz1d8cbJfv46bQFxqmzvqyjbi5Ir0BJFWN2PSgzAIaqrD9WYa0fdP
	2VszFSDHNJlpcVKL45pK1O/1RVEP+FHCnjMijQi3swv1IZhvbAfwdeMZq+acICh/R4yueTtjFyR
	SlvSGyt3mJKkPORd5ASIrdJb722Rao/FwpGlXwzXoh0j5pt7Iw=
X-Received: by 2002:a5d:47aa:0:b0:382:3789:191c with SMTP id ffacd0b85a97d-38260b45584mr2567216f8f.7.1732287697197;
        Fri, 22 Nov 2024 07:01:37 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:e369:a6f7:a3ea:97bb])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3825fafe3cbsm2583014f8f.38.2024.11.22.07.01.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 07:01:36 -0800 (PST)
Date: Fri, 22 Nov 2024 16:01:29 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
	42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: Re: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
Message-ID: <Z0CcyfbPqmxJ9uJH@elver.google.com>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
 <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
 <20241122113210.QxE7YOwK@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20241122113210.QxE7YOwK@linutronix.de>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=H7z6x0xx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Nov 22, 2024 at 12:32PM +0100, Sebastian Andrzej Siewior wrote:
> On 2024-11-19 20:36:56 [+0100], Andrey Konovalov wrote:
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 6310a180278b6..b18b5944997f8 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cac=
he, bool in_object)
> > >                         sizeof(struct kasan_free_meta) : 0);
> > >  }
> > >
> > > -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot=
_flags)
> >=20
> > Could you add a comment here that notes the usage, something like:
> >=20
> > "This function avoids dynamic memory allocations and thus can be
> > called from contexts that do not allow allocating memory."
> >=20
> > > +void kasan_record_aux_stack(void *addr)
> > >  {
> =E2=80=A6
> Added but would prefer to add a pointer to stack_depot_save_flags()
> which has this Context: paragraph. Would that work?
> Now looking at it, it says:
> |  * Context: Any context, but setting STACK_DEPOT_FLAG_CAN_ALLOC is requ=
ired if
> |  *          alloc_pages() cannot be used from the current context. Curr=
ently
> |  *          this is the case for contexts where neither %GFP_ATOMIC nor
> |  *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
>=20
> If I understand this correctly then STACK_DEPOT_FLAG_CAN_ALLOC must not
> be specified if invoked from NMI. This will stop
> stack_depot_save_flags() from allocating memory the function will still
> acquire pool_lock, right?
> Do we need to update the comment saying that it must not be used from
> NMI or do we make it jump over the locked section in the NMI case?

Good point. It was meant to also be usable from NMI, because it's very
likely to succeed, and should just take the lock-less fast path once the
stack is in the depot.

But I think we need a fix like this for initial saving of a stack trace:


diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5ed34cc963fc..245d5b416699 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -630,7 +630,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned l=
ong *entries,
 			prealloc =3D page_address(page);
 	}
=20
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	if (in_nmi()) {
+		/* We can never allocate in NMI context. */
+		WARN_ON_ONCE(can_alloc);
+		/* Best effort; bail if we fail to take the lock. */
+		if (!raw_spin_trylock_irqsave(&pool_lock, flags))
+			goto exit;
+	} else {
+		raw_spin_lock_irqsave(&pool_lock, flags);
+	}
 	printk_deferred_enter();
=20
 	/* Try to find again, to avoid concurrently inserting duplicates. */


If that looks reasonable, I'll turn it into a patch.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
0CcyfbPqmxJ9uJH%40elver.google.com.

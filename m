Return-Path: <kasan-dev+bncBCKLNNXAXYFBBP6XQG5AMGQEXPU2CVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 749259D5E14
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 12:32:18 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-432d9bb0f19sf16109885e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 03:32:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732275138; cv=pass;
        d=google.com; s=arc-20240605;
        b=EUZOZg806TomUDQYtKTSCQBS2xQyozdiiwvbXhedLSRiTWHQqVZY19o/5OYKa34nkA
         L4sv5QcjUI8u/HL+5gcwARd03vO8wZ7Dtz4Pj+MNNEYpI95Y562LH5yBJteG4NRKUelN
         8HSS5Kr6DdDexARjiKHxpd7FRI36bfjvaMRc4skva0WREOOfM2yizySr2lwzsKZLf4w7
         /3ygrn/vyAu63uF/ME4CA5srvDzi7W0sEX2vUXeELNdKUrAvjA7zu2vlcP45KuGFolW9
         8CDbCZPpS99tzEGbty43D9KA3IR6Gfyl3wFn7Anm3oit7vousuF9bgumB7xUoqkbxA4Z
         1u/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=84iKyIZwzv8tpSeRe8Cgn2Thb56XitO1m7Je/AB7FeQ=;
        fh=Na0/QWt9sy6+PyhKInEF2eIuoJyMOyLPgJfWoe0WPJc=;
        b=erj+ZVPRVivIxblfjt8zUmKg4LnQv3tJyR/2ecZXX/v6EJeaojaWw3pbbXe47Y6ZnO
         IopHAA4WBjcZAbPiibSA3J2UJw6g6XVNco2pilfA4VcRjfGYIvDsWRrBegi+wb/sxVDd
         Vs4ehBm/DP618bEqkOSDHwg+ZpjISe64I77TG5oRDWuwkw3EboSUtGwU3MyAv920YyEM
         omqZqFyty6PNcoPl0YfRi22fKqY4K4jGLuPiVcij4jhyqN9AFO7+KB+qGwdLVQkprfqW
         VOXH9kkFtJWQh9KNPPlJupo/nRxjOS/r8btkZ71+6JcaVZqa6l2ml0Vu8Vz5EY8nCKak
         NxZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="k/c6S05b";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732275138; x=1732879938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=84iKyIZwzv8tpSeRe8Cgn2Thb56XitO1m7Je/AB7FeQ=;
        b=UDNDJ5b7CGdp4UqMefMGMLVjUU5gTVY+76W8yYY9o3wsdm8EK6RMvENZC4RZS2Y6cy
         7SWLGyT91cqCn8N1POvr8HKmvsl6Gi9xs3U4ligOQ/Yps9PPrUi3hkADT1Xneo94DQAV
         8EJgxhZczUfsHhawWIkFxF+xWaToc5libalEqGi40cu0stsEMvcDPJBgD2jqXAf+ki38
         BZhkYG6mC3o6d4BzlR5ZBFLLqOjPbD9nmIz+Lp4PGEOfhm8TeSnquQfQ1+OCcQiXrncU
         sWG9VzbSyDDjLLz9FQOS8lCuX7zEMwv+GHznNuZpaxcHHPCzqX8BZ/hoSORz2VIS+q8A
         ChAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732275138; x=1732879938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=84iKyIZwzv8tpSeRe8Cgn2Thb56XitO1m7Je/AB7FeQ=;
        b=Z1IAv/4clC8LcmRT5N18aEf77VNDmypfaROBcn1Az8s9WQfBCyYm971mNdtDE6kLKs
         5wPYOaByLQklpQmcP+ekdmPLcM07E8BdFLi+svq+LdJCpFBGOeHU9jPq+52WTWGVsycW
         R80GjJ5j20AY2DwAXjFb/N0AAfdE1Lm4MGmEixcjXleJ7egZTjFV+R6xNaIW1cMHjlCW
         AyuuRiiPaLmMMH/7G/AbotajoeNKzw6LsOaH5DMvrl/h2RQJ6QM+Hd+9UDwQYrj6U7YA
         jJDWjkktEniPAHfvnCqMhip1RGlMn9KoJCGzA+wRCKs0E+pFEukA+B6l5j4lD4l2vNfT
         WmBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAIHgy5eh5ch7+zGkocpHQYMcHCd7B7Kkw+xcPbPxaK2ODM7jHy98qnn9qd81tBH0T4H0l6g==@lfdr.de
X-Gm-Message-State: AOJu0Yz5R4hfGu8iRm43OkJIhDi3OAIOZQZ/ro7sP9FbQaAlBQu97oX/
	DRYkeIRnx5bsWAmCmGOrKj9pKmOVf011tKO5t1kE2cE2o/rrQqXl
X-Google-Smtp-Source: AGHT+IHDKYsTSaov0/vfLyvvGl6I1Ifs9Y/XVISOLavC0D5nsyFMmzNjknL3jLxJkZXQX57ZMs0aOA==
X-Received: by 2002:a05:600c:1e1e:b0:42c:b603:422 with SMTP id 5b1f17b1804b1-433cdb0b504mr22333525e9.8.1732275135758;
        Fri, 22 Nov 2024 03:32:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3acc:b0:42f:174:6add with SMTP id
 5b1f17b1804b1-43346e3da5cls8485445e9.1.-pod-prod-00-eu-canary; Fri, 22 Nov
 2024 03:32:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWSrrNUiTqqTiW7UnYO7RoqB9VKEujzOji8P0TY1Zu0ER4u4QNV+5FIWKU2mgsyeMm8CrCfEPKrPA=@googlegroups.com
X-Received: by 2002:a05:6000:1fa5:b0:37d:3b31:7a9d with SMTP id ffacd0b85a97d-38259d2c161mr6095946f8f.23.1732275133414;
        Fri, 22 Nov 2024 03:32:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732275133; cv=none;
        d=google.com; s=arc-20240605;
        b=edeMHmK8r10Fdaq7pVL0GO4dcOPBXHmUmtheo7Pfv0bkxxZQNuH4xYL2EUO6KJMQud
         NYn2bQ7POeGFjbBM1yrpgyNGjX27dWfQFMJr6Wyb117k3eNzh7wGzyhgyeVnqE3MJkqF
         GzCxhRXcmloEZPks7VZ30LZ8t/gYzUPvewIdGq6kZ8cpaPOng9NG39ao8LAao/5Ho95v
         CzO6HJ5g6Ei5ZAPIwplKLWCx5g8mYoHeVJxTS/BT7LBNUbz1M806+xOkZ+sOpEjyf0CD
         kER9WtuBEEbAHgOzb5f+1o2PVn14A+SzDkW5HxlEoSGCwcD756Zbu/cryld25fAden1a
         u18A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=qXjERXwGoyz9ImH0OMqUpjRgs/7YUUrAyzys/z/9r0k=;
        fh=Sy27l84g7ApLB4stBl/+5gX3Mk2fYSw44gFdqB9/Ok0=;
        b=jZ3owZhZwarkD2WnGM9cpw2UlIpE0mZOHLhZm+nGesp53dwjcAw8RR2B53tZorGOi8
         UNu5Qs+skIZV2W31ncjLUtHydfwL4X5TzfFS0NQbpl17otpnMJ5kMh75eNyNXsk/Ebmz
         FQRWrkc+RVIzLMDzLG6Rcd/QAES5I46auOjCpv8j0NHudKPdPZEdh/w8sdSrjfAWinXU
         8CGdesMIckdcWyfHodQ5MsBqpUFJHCoJjBx0fa702kwK2sG4wfaMBOgLcgKYJou8rjkV
         AtOYONDa+PnKHA9khFBJuFj6BkifHiSoLQaTlLjIYn9MMhQxlquG58H4zwEA1BJwQ7pA
         9/mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="k/c6S05b";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43366cba3e4si3054405e9.1.2024.11.22.03.32.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 03:32:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 22 Nov 2024 12:32:10 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <20241122113210.QxE7YOwK@linutronix.de>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
 <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="k/c6S05b";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2024-11-19 20:36:56 [+0100], Andrey Konovalov wrote:
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 6310a180278b6..b18b5944997f8 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache=
, bool in_object)
> >                         sizeof(struct kasan_free_meta) : 0);
> >  }
> >
> > -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_f=
lags)
>=20
> Could you add a comment here that notes the usage, something like:
>=20
> "This function avoids dynamic memory allocations and thus can be
> called from contexts that do not allow allocating memory."
>=20
> > +void kasan_record_aux_stack(void *addr)
> >  {
=E2=80=A6
Added but would prefer to add a pointer to stack_depot_save_flags()
which has this Context: paragraph. Would that work?
Now looking at it, it says:
|  * Context: Any context, but setting STACK_DEPOT_FLAG_CAN_ALLOC is requir=
ed if
|  *          alloc_pages() cannot be used from the current context. Curren=
tly
|  *          this is the case for contexts where neither %GFP_ATOMIC nor
|  *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).

If I understand this correctly then STACK_DEPOT_FLAG_CAN_ALLOC must not
be specified if invoked from NMI. This will stop
stack_depot_save_flags() from allocating memory the function will still
acquire pool_lock, right?
Do we need to update the comment saying that it must not be used from
NMI or do we make it jump over the locked section in the NMI case?

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241122113210.QxE7YOwK%40linutronix.de.

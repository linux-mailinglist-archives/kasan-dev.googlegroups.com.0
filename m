Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBIUOZ62QMGQEJHXE6JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D3C194B055
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 21:12:36 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-42808efc688sf1266685e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 12:12:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723057956; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEq1iqR7uGL0VaiYDT9zIJtDuquvo44Q8PAXJgKH7ibsW9hvFt0EATRLObnHU6WLbV
         022o54OeT7+N3LIzBYndmrekU4/4gwQcihHr0MDRNGSeXhp8OJ9CbLcxMSSkvL2/cdsz
         xfPabwlwPopMq/iLSzVuQZfoJfaYs7y1RMwxMTh7PDip0j4RnmnIPnChIl0BKIi9Ha6C
         AjUTN3MNUCzN8tmQ78JPo63m4KRmKUqi26ycTE+Yhgl7D/TzKA7PqDlmGojHa08hqIH0
         gcyuwrVNtJbfDmrnlSkPtC9/IqtxgdDb+/dX699eoomzQz8tfbgI+BGa3Sfnb2cRyIpH
         2a5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Oo1ELEQYf3y9FREST7A1ONOo+wD/1xZAtcmI85FTMJo=;
        fh=hcpMnLth3dbxTv5zLgP1s7I/pBbe5DRhDrY8QpbDFjo=;
        b=lB2gcq6PcBMQlS93Iu+UpPvFtH2j52A+yPCZgy55s+xzCvYyVf+DIjw6ULHiuiqiph
         QjKH0CCVrt4i6/8ozVU7O4VO2UaBC0RS/2pfvwDGoLuHwj6YmnIRTZyI0hQyoCosP6GR
         c+EjQb7GJltTLi4feStug+ZZ6rcn7Hwv5tf+pOwfmLmsupqKTNiQfArXbXLjI+4QNltJ
         IRZmxuUwlhiym7B2Mg6cW8a2kgS0qmCTNUlCyADKWwmjuxLd949ficPRmAe6k6cat5G/
         vkAisDGBysy8+pSnCqvQAILJ+/UsxNp74iwmBNoxNcgreaNVq2brnWGjfo5qyVwzNFbl
         /gXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kTUhv51Y;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723057956; x=1723662756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Oo1ELEQYf3y9FREST7A1ONOo+wD/1xZAtcmI85FTMJo=;
        b=NBJ2ytMQofBUAIg6r9ySCadBnyckf9Nm2Fs1tcYTkbbCYJBPYbIhWJaz8MkTOoKT1z
         VsVL01ekz31M2ISYboZ+UYOekuMbWVbXe7YvwXG4iFCaRoGaPBwmDcXo/OTUr6lF4NR5
         fvqPxpcWmOq2hScQwDVAhP9uyt5F6eHOqEInRCcojO5dW2l1C5BaFeSt43mKwqk7daNT
         lqkAMeeVUeb8sp3shQ4f1mZI1y8XNJ/+lx/jzl2fObQa1vDXCv/PwUOw7QOmLGwSjrxL
         Kp/U0qEHskYMwzNM9omYT0CFJOji7Y3dmwIj8PBUaWgeVyrAPXtouX9qDSUqUtGYsSIf
         mCug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723057956; x=1723662756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Oo1ELEQYf3y9FREST7A1ONOo+wD/1xZAtcmI85FTMJo=;
        b=ciothieWcKXoRKourlKNfo32FIJBsJ9J0Q+oT3P6ak75V5553pgV/N+dab9u67tWZH
         SZNq7sVedjQp8rE6/p0ZA1MBWdlQqLX4ycPglXY22NyAHmMretiFVNWxf3vjNR/hn85R
         1/RQkP9JDRhbTk8Mi4Z5LIDZIswTKDSlRlXkp8EWjy++wprBLLwdcq+v1BENqpLpiSXk
         nPI1vFuT9bC6R/vOAoMMZ42d/0zr1pvUXj4TmJ5dBldQ503bJLhNyLcRcVA6BgoDKUcu
         kMl11l4jsk7Nwh7Qm/0hpoqPAZ64ImmwFquHdhLC41FcigpLz2MFxEsgHkQf3bXOM2/v
         CVfw==
X-Forwarded-Encrypted: i=2; AJvYcCVLzrcJU3psxV3GQBpx30nsHLhrR80QSu9e8SJWGSM1ThQWvDl1AY0l7Xtp7LCQdCJQae8xy91QyyPX40dW5BogwPsmDlaUjQ==
X-Gm-Message-State: AOJu0YwgFoRPsgh25nQWWVh8kGOMbxXHRTMlUj1I6G2OYYP8y2z0anGU
	OQKiYHIC+goFCaaHXVnfuRDcG+ipsZ6DGnO/uRlG95FUFu5QhmEN
X-Google-Smtp-Source: AGHT+IFUuMboArKVsZNkTO5gJE/ELpY49Jwcgj1osPfRrwNdd7J9Sov3xJxE02GhnM1MlexkGMRsyA==
X-Received: by 2002:a05:600c:3549:b0:426:59fe:ac2e with SMTP id 5b1f17b1804b1-428e6b789acmr138762605e9.29.1723057955025;
        Wed, 07 Aug 2024 12:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1394:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-4290908de77ls786235e9.0.-pod-prod-02-eu; Wed, 07 Aug 2024
 12:12:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDue4v2HZiWAw0lg9KyoQRJQgsehGZEfXlhpeZPErrgg0gmVVVawK9Nt7ajnx7mf+KblVk3JtJoOYMDQaatG4cnzWr9g6vc8CJIw==
X-Received: by 2002:a05:6000:1883:b0:367:991f:4377 with SMTP id ffacd0b85a97d-36bbc1d2081mr17383092f8f.58.1723057953033;
        Wed, 07 Aug 2024 12:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723057953; cv=none;
        d=google.com; s=arc-20160816;
        b=EA1xPRRFkf5mCG8GymDGL0x6Bfyrubs7gId8p+RKVIE724thibEm1eNrY8tXg/sRNv
         BaP/QQWVtymCgbesscfg8bVvWfJvsR/aSY2A/rMTzxtsTy6LMtBnGciNe5naV9WfrUX2
         RK1XmpzyIQdN8OxeR/5XVBsw774wUeRYc6zbRoC9GzQjnIT6B0R3HDpVp7fG32yvF3YF
         3z7HAmtaR0pjGo1i8GDsL2CNjiCjKgI9On51GY+JoB4hEtkcWcrOm6Ilor6lB4f85C3A
         mNdPXyNKUlcLZV7XOW0TvcR9enc05DRvvwKQaGxlIuepcF4OA1NlydSN3+6LimIyjJM6
         vXKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TZmc//vzgWXo1JCuuQnsejz5TEP5eZApTnDweP28nSI=;
        fh=O2O8cAAH0vq9qKSVY1WLmBxfUgqZQE+Oz0XSXhyal0I=;
        b=hOJlgDo32A3WQp8vPyWEQ3VSDlAp1OCqZ28qrfWZDWs4nFVNLKqa9tXflSOHL8mMZy
         An7Q/r94zBE27OrpgtudSWpRp5L2w5uJTFIwynT8IJz7tHUpOb27HUNix87XUtHaQzqx
         ZT7onJbT48FhegdK/oq0vKpK5YQJ7u/Boq6kMTGjMtUjTeiBy+4ud9JrGF/AO/0Fsa7s
         vJ7ymXPQFaTH1o/2AYIkRoprCm3wN4v19B63vDgzRZ7rnHDwscTsm/ppISPEXGx8y2kZ
         iYEdcJS20ceFN5M6Dw3L02n5Y4u5BK3aVcJHSyydOrVxBMfoHn4c8AS6wEoWGVDiEPsK
         xAjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kTUhv51Y;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36bbcf04f7asi262013f8f.1.2024.08.07.12.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 12:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so101a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 12:12:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmCBPGzi4TNfdB0MFp56j8KVndrGHSUh1PBUr0teydqklEpt3LesOoAhGN7B/MNIWXclYFLMRWi6LHIeZJkWQ51QXzSwKprOawuQ==
X-Received: by 2002:a05:6402:254b:b0:59f:9f59:9b07 with SMTP id
 4fb4d7f45d1cf-5bbaff955fbmr27180a12.4.1723057951910; Wed, 07 Aug 2024
 12:12:31 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <20240807-b4-slab-kfree_rcu-destroy-v2-4-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-4-ea79102f428c@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 21:11:55 +0200
Message-ID: <CAG48ez2jKFXxkMhq-Q7-WNHp_FTYL7yOpCQa8e_yFDm05e3Few@mail.gmail.com>
Subject: Re: [PATCH v2 4/7] mm, slab: reintroduce rcu_barrier() into kmem_cache_destroy()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kTUhv51Y;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Aug 7, 2024 at 12:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> There used to be a rcu_barrier() for SLAB_TYPESAFE_BY_RCU caches in
> kmem_cache_destroy() until commit 657dc2f97220 ("slab: remove
> synchronous rcu_barrier() call in memcg cache release path") moved it to
> an asynchronous work that finishes the destroying of such caches.
>
> The motivation for that commit was the MEMCG_KMEM integration that at
> the time created and removed clones of the global slab caches together
> with their cgroups, and blocking cgroups removal was unwelcome. The
> implementation later changed to per-object memcg tracking using a single
> cache, so there should be no more need for a fast non-blocking
> kmem_cache_destroy(), which is typically only done when a module is
> unloaded etc.
>
> Going back to synchronous barrier has the following advantages:
>
> - simpler implementation
> - it's easier to test the result of kmem_cache_destroy() in a kunit test
>
> Thus effectively revert commit 657dc2f97220. It is not a 1:1 revert as
> the code has changed since. The main part is that kmem_cache_release(s)
> is always called from kmem_cache_destroy(), but for SLAB_TYPESAFE_BY_RCU
> caches there's a rcu_barrier() first.
>
> Suggested-by: Mateusz Guzik <mjguzik@gmail.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Jann Horn <jannh@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez2jKFXxkMhq-Q7-WNHp_FTYL7yOpCQa8e_yFDm05e3Few%40mail.gmail.=
com.
